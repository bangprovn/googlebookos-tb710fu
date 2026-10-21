/* SPDX-License-Identifier: Apache-2.0
 * Bounded Linux compute-shader qualification. Three arithmetic challenges write
 * a 4096-byte storage buffer; each fence and every word are checked. No WSI,
 * images, external FD import/export or firmware writes. An explicitly
 * supplied private Venus ICD still has to pass the hardware identity check.
 * Software control is explicit and can never establish Venus acceleration.
 */
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/resource.h>
#include "guest_vulkan_compute_spv.h"
#include "guest_vulkan_uniform_spv.h"

static int fail(const char *stage, int code) {
    printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"%s\",\"code\":%d,\"guest_vulkan_verified\":false}\n", stage, code);
    return 1;
}
#define CHECK(stage, call) do { fprintf(stderr, "GB_GUEST_VK_STAGE:%s\n", stage); VkResult r = (call); if (r != VK_SUCCESS) return fail(stage, r); } while (0)
#define INSTANCE(name) PFN_vk##name name = (PFN_vk##name)get(instance, "vk" #name); if (!name) return fail("entrypoint_" #name, -1)
#define DEVICE(name) PFN_vk##name name = (PFN_vk##name)GetDeviceProcAddr(device, "vk" #name); if (!name) return fail("entrypoint_" #name, -1)

int main(int argc, char **argv) {
    struct rlimit cores = {0, 0};
    if (setrlimit(RLIMIT_CORE, &cores)) return fail("core_limit", -1);
    alarm(20);
    bool control = argc == 2 && !strcmp(argv[1], "--lavapipe-control");
    bool custom_icd = argc == 3 && !strcmp(argv[1], "--venus-icd") &&
                      argv[2][0] == '/' && strlen(argv[2]) <= 4096;
    if (!control && !custom_icd && !(argc == 2 && !strcmp(argv[1], "--venus")))
        return fail("explicit_venus_or_software_control_required", -1);
    const char *coherent_mode = getenv("GB_GUEST_COMPUTE_COHERENT_V1");
    if (coherent_mode && strcmp(coherent_mode, "persistent") && strcmp(coherent_mode, "remap") &&
        strcmp(coherent_mode, "uniform-persistent") && strcmp(coherent_mode, "uniform-remap") &&
        strcmp(coherent_mode, "uniform-reused") && strcmp(coherent_mode, "uniform-reused-implicit"))
        return fail("unknown_coherent_input_profile", -1);
    bool cpu_input = coherent_mode != NULL;
    bool reuse_commands = coherent_mode && (!strcmp(coherent_mode, "uniform-reused") || !strcmp(coherent_mode, "uniform-reused-implicit"));
    bool implicit_host = coherent_mode && !strcmp(coherent_mode, "uniform-reused-implicit");
    bool persistent = reuse_commands || (coherent_mode && (!strcmp(coherent_mode, "persistent") || !strcmp(coherent_mode, "uniform-persistent")));
    bool uniform_input = reuse_commands || (coherent_mode && (!strcmp(coherent_mode, "uniform-persistent") || !strcmp(coherent_mode, "uniform-remap")));
    const char *icd = custom_icd ? argv[2] : control ? "/usr/share/vulkan/icd.d/lvp_icd.json" :
                               "/usr/share/vulkan/icd.d/virtio_icd.json";
    if (setenv("VK_DRIVER_FILES", icd, 1) || unsetenv("VK_ICD_FILENAMES") ||
        setenv("MESA_SHADER_CACHE_DISABLE", "true", 1)) return fail("process_env", -1);
    void *library = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) return fail("dlopen", -1);
    PFN_vkGetInstanceProcAddr get = (PFN_vkGetInstanceProcAddr)dlsym(library, "vkGetInstanceProcAddr");
    if (!get) return fail("get_instance_proc_addr", -1);
    PFN_vkCreateInstance create = (PFN_vkCreateInstance)get(VK_NULL_HANDLE, "vkCreateInstance");
    if (!create) return fail("create_entrypoint", -1);
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "gb-guest-vulkan-compute", .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo info = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app};
    VkInstance instance = VK_NULL_HANDLE;
    CHECK("create_instance", create(&info, NULL, &instance));
    INSTANCE(EnumeratePhysicalDevices); INSTANCE(GetPhysicalDeviceProperties);
    INSTANCE(GetPhysicalDeviceQueueFamilyProperties); INSTANCE(GetPhysicalDeviceMemoryProperties);
    INSTANCE(GetDeviceProcAddr);
    INSTANCE(CreateDevice); INSTANCE(DestroyInstance);
    uint32_t count = 0;
    CHECK("device_count", EnumeratePhysicalDevices(instance, &count, NULL));
    if (count != 1) return fail("one_physical_gpu_required", -1);
    VkPhysicalDevice physical;
    CHECK("device_enumeration", EnumeratePhysicalDevices(instance, &count, &physical));
    VkPhysicalDeviceProperties props;
    GetPhysicalDeviceProperties(physical, &props);
    props.deviceName[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE - 1] = 0;
    bool venus_adreno = strstr(props.deviceName, "Virtio-GPU Venus") &&
                        strstr(props.deviceName, "Adreno") && props.vendorID == 0x5143;
    bool software = props.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU &&
                    (strstr(props.deviceName, "llvmpipe") || strstr(props.deviceName, "lavapipe"));
    if ((control && !software) || (!control && !venus_adreno))
        return fail("selected_driver_identity_mismatch", -1);
    fprintf(stderr, "GB_GUEST_VK_IDENTITY:software_control=%d venus_adreno=%d vendor_id=%u\n",
            control, venus_adreno, props.vendorID);
    uint32_t families = 0;
    GetPhysicalDeviceQueueFamilyProperties(physical, &families, NULL);
    if (!families || families > 32) return fail("queue_family_count", -1);
    VkQueueFamilyProperties queues[32];
    GetPhysicalDeviceQueueFamilyProperties(physical, &families, queues);
    uint32_t family = families;
    for (uint32_t i = 0; i < families; ++i)
        if (queues[i].queueCount && (queues[i].queueFlags & (VK_QUEUE_COMPUTE_BIT))) {family = i; break;}
    if (family == families) return fail("compute_queue_required", -1);
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = family, .queueCount = 1, .pQueuePriorities = &priority};
    VkDeviceCreateInfo device_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = 1, .pQueueCreateInfos = &queue_info};
    VkDevice device;
    CHECK("create_device", CreateDevice(physical, &device_info, NULL, &device));
    DEVICE(CreateBuffer); DEVICE(GetBufferMemoryRequirements2); DEVICE(AllocateMemory);
    DEVICE(BindBufferMemory); DEVICE(MapMemory); DEVICE(UnmapMemory); DEVICE(GetDeviceQueue);
    DEVICE(CreateCommandPool); DEVICE(AllocateCommandBuffers); DEVICE(BeginCommandBuffer);
    DEVICE(CreateShaderModule); DEVICE(CreateDescriptorSetLayout); DEVICE(CreatePipelineLayout);
    DEVICE(CreateComputePipelines); DEVICE(CreateDescriptorPool); DEVICE(AllocateDescriptorSets);
    DEVICE(UpdateDescriptorSets); DEVICE(CmdBindPipeline); DEVICE(CmdBindDescriptorSets);
    DEVICE(CmdPushConstants); DEVICE(CmdDispatch); DEVICE(ResetCommandBuffer); DEVICE(ResetFences);
    DEVICE(DestroyDescriptorPool); DEVICE(DestroyPipeline); DEVICE(DestroyPipelineLayout);
    DEVICE(DestroyDescriptorSetLayout); DEVICE(DestroyShaderModule); DEVICE(CmdPipelineBarrier); DEVICE(EndCommandBuffer);
    DEVICE(CreateFence); DEVICE(GetFenceStatus); DEVICE(QueueSubmit); DEVICE(WaitForFences);
    DEVICE(DestroyFence);
    DEVICE(DestroyCommandPool); DEVICE(DestroyBuffer); DEVICE(FreeMemory); DEVICE(DestroyDevice);
    VkBufferCreateInfo buffer_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .size = 4096, .usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    VkBuffer buffer;
    CHECK("create_buffer", CreateBuffer(device, &buffer_info, NULL, &buffer));
    VkMemoryDedicatedRequirements dedicated = {.sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_REQUIREMENTS};
    VkMemoryRequirements2 requirements = {.sType = VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2, .pNext = &dedicated};
    VkBufferMemoryRequirementsInfo2 requirements_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_REQUIREMENTS_INFO_2, .buffer = buffer};
    fprintf(stderr, "GB_GUEST_VK_STAGE:buffer_memory_requirements\n");
    GetBufferMemoryRequirements2(device, &requirements_info, &requirements);
    VkMemoryRequirements req = requirements.memoryRequirements;
    if (dedicated.requiresDedicatedAllocation || req.size < 4096 || req.size > 1024 * 1024) return fail("allocation_budget_or_dedicated", -1);
    VkPhysicalDeviceMemoryProperties memory_props;
    GetPhysicalDeviceMemoryProperties(physical, &memory_props);
    if (!memory_props.memoryTypeCount || memory_props.memoryTypeCount > 32) return fail("memory_type_count", -1);
    uint32_t type = memory_props.memoryTypeCount;
    for (uint32_t i = 0; i < memory_props.memoryTypeCount; ++i)
        if ((req.memoryTypeBits & (1u << i)) &&
            (memory_props.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {type = i; break;}
    if (type == memory_props.memoryTypeCount) return fail("host_coherent_memory_required", -1);
    VkMemoryAllocateInfo allocation = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .allocationSize = req.size, .memoryTypeIndex = type};
    VkDeviceMemory memory;
    CHECK("allocate_memory", AllocateMemory(device, &allocation, NULL, &memory));
    CHECK("bind_memory", BindBufferMemory(device, buffer, memory, 0));
    void *mapped;
    CHECK("map_initial_memory", MapMemory(device, memory, 0, 4096, 0, &mapped));
    /* A recycled allocation must not pass from an earlier run's pattern if
     * submission silently does nothing. Coherent host writes precede submit. */
    memset(mapped, 0, 4096);
    if (!persistent) UnmapMemory(device, memory);
    VkBuffer uniform_buffer = VK_NULL_HANDLE;
    VkDeviceMemory uniform_memory = VK_NULL_HANDLE;
    void *uniform_mapped = NULL;
    if (uniform_input) {
        if (props.limits.maxUniformBufferRange < 4096 || !props.limits.maxPerStageDescriptorUniformBuffers)
            return fail("uniform_buffer_limits", -1);
        VkBufferCreateInfo uniform_info = buffer_info;
        uniform_info.usage = VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT;
        CHECK("create_uniform_buffer", CreateBuffer(device, &uniform_info, NULL, &uniform_buffer));
        VkMemoryDedicatedRequirements uniform_dedicated = {.sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_REQUIREMENTS};
        VkMemoryRequirements2 uniform_req = {.sType = VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2, .pNext = &uniform_dedicated};
        VkBufferMemoryRequirementsInfo2 uniform_req_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_REQUIREMENTS_INFO_2, .buffer = uniform_buffer};
        GetBufferMemoryRequirements2(device, &uniform_req_info, &uniform_req);
        if (uniform_dedicated.requiresDedicatedAllocation || uniform_req.memoryRequirements.size < 4096 ||
            uniform_req.memoryRequirements.size > 1024 * 1024) return fail("uniform_allocation_budget", -1);
        uint32_t uniform_type = memory_props.memoryTypeCount;
        for (uint32_t i = 0; i < memory_props.memoryTypeCount; i++)
            if ((uniform_req.memoryRequirements.memoryTypeBits & (1u << i)) &&
                (memory_props.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
                (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {uniform_type = i; break;}
        if (uniform_type == memory_props.memoryTypeCount) return fail("uniform_coherent_memory_required", -1);
        VkMemoryAllocateInfo uniform_allocation = allocation;
        uniform_allocation.allocationSize = uniform_req.memoryRequirements.size;
        uniform_allocation.memoryTypeIndex = uniform_type;
        CHECK("allocate_uniform_memory", AllocateMemory(device, &uniform_allocation, NULL, &uniform_memory));
        CHECK("bind_uniform_memory", BindBufferMemory(device, uniform_buffer, uniform_memory, 0));
        CHECK("map_uniform_initial", MapMemory(device, uniform_memory, 0, 4096, 0, &uniform_mapped));
        memset(uniform_mapped, 0, 4096);
        if (!persistent) UnmapMemory(device, uniform_memory);
    }
    VkCommandPoolCreateInfo pool_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT, .queueFamilyIndex = family};
    VkCommandPool pool;
    CHECK("create_command_pool", CreateCommandPool(device, &pool_info, NULL, &pool));
    VkCommandBufferAllocateInfo command_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = pool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1};
    VkCommandBuffer command;
    CHECK("allocate_command_buffer", AllocateCommandBuffers(device, &command_info, &command));
    if (props.limits.maxComputeWorkGroupCount[0] < 16 || props.limits.maxComputeWorkGroupInvocations < 64 ||
        props.limits.maxComputeWorkGroupSize[0] < 64) return fail("compute_limits", -1);
    VkShaderModuleCreateInfo module_info = {.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
        .codeSize = uniform_input ? sizeof(uniform_compute_shader) : sizeof(compute_shader),
        .pCode = uniform_input ? uniform_compute_shader : compute_shader};
    VkShaderModule shader;
    CHECK("create_shader_module", CreateShaderModule(device, &module_info, NULL, &shader));
    VkDescriptorSetLayoutBinding bindings[2] = {
        {.binding = 0, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
         .descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT},
        {.binding = 1, .descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
         .descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT}};
    VkDescriptorSetLayoutCreateInfo set_info = {.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
        .bindingCount = uniform_input ? 2u : 1u, .pBindings = bindings};
    VkDescriptorSetLayout set_layout;
    CHECK("create_descriptor_layout", CreateDescriptorSetLayout(device, &set_info, NULL, &set_layout));
    VkPushConstantRange push = {.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT, .offset = 0, .size = 2 * sizeof(uint32_t)};
    VkPipelineLayoutCreateInfo layout_info = {.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
        .setLayoutCount = 1, .pSetLayouts = &set_layout, .pushConstantRangeCount = 1, .pPushConstantRanges = &push};
    VkPipelineLayout layout;
    CHECK("create_pipeline_layout", CreatePipelineLayout(device, &layout_info, NULL, &layout));
    VkComputePipelineCreateInfo pipeline_info = {.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
        .stage = {.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, .stage = VK_SHADER_STAGE_COMPUTE_BIT,
                  .module = shader, .pName = "main"}, .layout = layout};
    VkPipeline pipeline;
    CHECK("create_compute_pipeline", CreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, NULL, &pipeline));
    VkDescriptorPoolSize descriptor_sizes[2] = {
        {.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 1},
        {.type = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, .descriptorCount = 1}};
    VkDescriptorPoolCreateInfo descriptors_info = {.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
        .maxSets = 1, .poolSizeCount = uniform_input ? 2u : 1u, .pPoolSizes = descriptor_sizes};
    VkDescriptorPool descriptors;
    CHECK("create_descriptor_pool", CreateDescriptorPool(device, &descriptors_info, NULL, &descriptors));
    VkDescriptorSetAllocateInfo set_alloc = {.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
        .descriptorPool = descriptors, .descriptorSetCount = 1, .pSetLayouts = &set_layout};
    VkDescriptorSet set;
    CHECK("allocate_descriptor_set", AllocateDescriptorSets(device, &set_alloc, &set));
    VkDescriptorBufferInfo descriptor_buffer = {.buffer = buffer, .offset = 0, .range = 4096};
    VkDescriptorBufferInfo uniform_descriptor = {.buffer = uniform_buffer, .offset = 0, .range = 4096};
    VkWriteDescriptorSet writes[2] = {
        {.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = set,
         .dstBinding = 0, .descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
         .pBufferInfo = &descriptor_buffer},
        {.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = set,
         .dstBinding = 1, .descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER,
         .pBufferInfo = &uniform_descriptor}};
    UpdateDescriptorSets(device, uniform_input ? 2u : 1u, writes, 0, NULL);
    VkFenceCreateInfo fence_info = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VkFence fence;
    CHECK("create_fence", CreateFence(device, &fence_info, NULL, &fence));
    VkQueue queue; GetDeviceQueue(device, family, 0, &queue);
    const uint32_t seeds[3] = {0x13579bdfu, 0xfedcba98u, 0x2468ace1u};
    for (unsigned pass = 0; pass < 3; pass++) {
        fprintf(stderr, "GB_COMPUTE_PASS:%u\n", pass);
        if (pass) {
            CHECK("reset_fence", ResetFences(device, 1, &fence));
            if (!reuse_commands) CHECK("reset_command_buffer", ResetCommandBuffer(command, 0));
        }
        if (GetFenceStatus(device, fence) != VK_NOT_READY) return fail("new_fence_unsignalled_required", -1);
        if (!persistent) {
            CHECK("map_initial_memory", MapMemory(device, memory, 0, 4096, 0, &mapped));
        }
        for (uint32_t i = 0; i < 1024; i++)
            ((volatile uint32_t *)mapped)[i] = cpu_input && !uniform_input ? ((seeds[pass] + i * 2246822519u) ^ 0x327a198du) : 0;
        if (!persistent) UnmapMemory(device, memory);
        if (uniform_input) {
            if (!persistent) {
                CHECK("map_uniform_update", MapMemory(device, uniform_memory, 0, 4096, 0, &uniform_mapped));
            }
            for (uint32_t i = 0; i < 1024; i++)
                ((volatile uint32_t *)uniform_mapped)[i] = (seeds[pass] + i * 2246822519u) ^ 0x327a198du;
            if (!persistent) UnmapMemory(device, uniform_memory);
        }
        if (!reuse_commands || pass == 0) {
            VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
                .flags = reuse_commands ? 0 : VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
            CHECK("begin_command_buffer", BeginCommandBuffer(command, &begin));
            VkBufferMemoryBarrier input = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
                .srcAccessMask = VK_ACCESS_HOST_WRITE_BIT, .dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT,
                .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED, .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                .buffer = buffer, .offset = 0, .size = 4096};
            if (!implicit_host) CmdPipelineBarrier(command, VK_PIPELINE_STAGE_HOST_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                0, 0, NULL, 1, &input, 0, NULL);
            if (uniform_input && !implicit_host) {
                VkBufferMemoryBarrier uniform_barrier = input;
                uniform_barrier.buffer = uniform_buffer;
                uniform_barrier.dstAccessMask = VK_ACCESS_UNIFORM_READ_BIT;
                CmdPipelineBarrier(command, VK_PIPELINE_STAGE_HOST_BIT, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                    0, 0, NULL, 1, &uniform_barrier, 0, NULL);
            }
            CmdBindPipeline(command, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
            CmdBindDescriptorSets(command, VK_PIPELINE_BIND_POINT_COMPUTE, layout, 0, 1, &set, 0, NULL);
            const uint32_t challenge[2] = {seeds[pass], cpu_input ? 1u : 0u};
            CmdPushConstants(command, layout, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(challenge), challenge);
            CmdDispatch(command, 16, 1, 1);
            VkBufferMemoryBarrier output = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
                .srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT, .dstAccessMask = VK_ACCESS_HOST_READ_BIT,
                .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED, .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                .buffer = buffer, .offset = 0, .size = 4096};
            CmdPipelineBarrier(command, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT,
                0, 0, NULL, 1, &output, 0, NULL);
            CHECK("end_command_buffer", EndCommandBuffer(command));
        }
        VkSubmitInfo submit = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &command};
        CHECK("queue_submit", QueueSubmit(queue, 1, &submit, fence));
        CHECK("fence_wait", WaitForFences(device, 1, &fence, VK_TRUE, 2000000000ULL));
        CHECK("fence_signalled", GetFenceStatus(device, fence));
        if (!persistent) {
            CHECK("map_shader_written_memory", MapMemory(device, memory, 0, 4096, 0, &mapped));
        }
        for (uint32_t i = 0; i < 1024; i++) {
            uint32_t input_word = cpu_input ? ((seeds[pass] + i * 2246822519u) ^ 0x327a198du) : i;
            uint32_t expected = ((input_word * 1664525u + seeds[reuse_commands ? 0 : pass]) ^ 0xa5c31f07u);
            if (((volatile uint32_t *)mapped)[i] != expected) return fail("shader_readback_mismatch", (int)i);
        }
        if (!persistent) UnmapMemory(device, memory);
    }
    if (persistent) UnmapMemory(device, memory);
    if (uniform_input && persistent) UnmapMemory(device, uniform_memory);
    DestroyDescriptorPool(device, descriptors, NULL);
    DestroyPipeline(device, pipeline, NULL);
    DestroyPipelineLayout(device, layout, NULL);
    DestroyDescriptorSetLayout(device, set_layout, NULL);
    DestroyShaderModule(device, shader, NULL);
    DestroyFence(device, fence, NULL);
    DestroyCommandPool(device, pool, NULL);
    DestroyBuffer(device, buffer, NULL);
    FreeMemory(device, memory, NULL);
    if (uniform_buffer) DestroyBuffer(device, uniform_buffer, NULL);
    if (uniform_memory) FreeMemory(device, uniform_memory, NULL);
    DestroyDevice(device, NULL);
    DestroyInstance(instance, NULL);
    dlclose(library);
    printf("{\"schema_version\":1,\"status\":\"shader_readback_verified\",\"software_control\":%s,"
           "\"venus_compute_verified\":%s,\"shader_execution_verified\":true,\"dispatches_verified\":3,"
           "\"words_verified_per_dispatch\":1024,\"fence_transitions_verified\":3,"
           "\"presentation_verified\":false,\"physical_gpu_performance_verified\":false,"
           "\"coherent_cpu_input_verified\":%s,\"persistent_mapping\":%s,"
           "\"uniform_cpu_input_verified\":%s,\"command_buffer_reused\":%s,\"explicit_host_input_barriers\":%s,"
           "\"custom_icd_explicit\":%s}\n", control ? "true" : "false", control ? "false" : "true",
           cpu_input ? "true" : "false", persistent ? "true" : "false", uniform_input ? "true" : "false",
           reuse_commands ? "true" : "false", implicit_host ? "false" : "true", custom_icd ? "true" : "false");

    return 0;
}
