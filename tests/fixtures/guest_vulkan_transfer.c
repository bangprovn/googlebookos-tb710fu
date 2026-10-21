/* SPDX-License-Identifier: Apache-2.0
 * Bounded Linux Vulkan transfer fixture, adapted from the existing private HAL
 * buffer test. One 4096-byte fill, host readback and fence transition; no WSI,
 * images, shaders, external FD import/export or firmware writes. An explicitly
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
        .pApplicationName = "gb-guest-vulkan-transfer", .apiVersion = VK_API_VERSION_1_1};
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
        if (queues[i].queueCount && (queues[i].queueFlags & (VK_QUEUE_TRANSFER_BIT | VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT))) {family = i; break;}
    if (family == families) return fail("transfer_queue_required", -1);
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
    DEVICE(CmdFillBuffer); DEVICE(CmdPipelineBarrier); DEVICE(EndCommandBuffer);
    DEVICE(CreateFence); DEVICE(GetFenceStatus); DEVICE(QueueSubmit); DEVICE(WaitForFences);
    DEVICE(DestroyFence);
    DEVICE(DestroyCommandPool); DEVICE(DestroyBuffer); DEVICE(FreeMemory); DEVICE(DestroyDevice);
    VkBufferCreateInfo buffer_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        .size = 4096, .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT, .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
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
    UnmapMemory(device, memory);
    VkCommandPoolCreateInfo pool_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = family};
    VkCommandPool pool;
    CHECK("create_command_pool", CreateCommandPool(device, &pool_info, NULL, &pool));
    VkCommandBufferAllocateInfo command_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = pool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1};
    VkCommandBuffer command;
    CHECK("allocate_command_buffer", AllocateCommandBuffers(device, &command_info, &command));
    VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
    CHECK("begin_command_buffer", BeginCommandBuffer(command, &begin));
    const uint32_t pattern = 0x6b475632;
    fprintf(stderr, "GB_GUEST_VK_STAGE:record_fill_buffer\n");
    CmdFillBuffer(command, buffer, 0, 4096, pattern);
    VkBufferMemoryBarrier barrier = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
        .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT, .dstAccessMask = VK_ACCESS_HOST_READ_BIT,
        .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED, .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
        .buffer = buffer, .offset = 0, .size = 4096};
    CmdPipelineBarrier(command, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 0, NULL, 1, &barrier, 0, NULL);
    CHECK("end_command_buffer", EndCommandBuffer(command));
    VkFenceCreateInfo fence_info = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VkFence fence;
    CHECK("create_fence", CreateFence(device, &fence_info, NULL, &fence));
    if (GetFenceStatus(device, fence) != VK_NOT_READY) return fail("new_fence_unsignalled_required", -1);
    VkQueue queue;
    GetDeviceQueue(device, family, 0, &queue);
    VkSubmitInfo submit = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &command};
    CHECK("queue_submit", QueueSubmit(queue, 1, &submit, fence));
    CHECK("fence_wait", WaitForFences(device, 1, &fence, VK_TRUE, 2000000000ULL));
    CHECK("fence_signalled", GetFenceStatus(device, fence));
    CHECK("map_gpu_written_memory", MapMemory(device, memory, 0, 4096, 0, &mapped));
    for (uint32_t i = 0; i < 1024; ++i) if (((volatile uint32_t *)mapped)[i] != pattern) return fail("gpu_fill_readback_mismatch", -1);
    UnmapMemory(device, memory);
    DestroyFence(device, fence, NULL);
    DestroyCommandPool(device, pool, NULL);
    DestroyBuffer(device, buffer, NULL);
    FreeMemory(device, memory, NULL);
    DestroyDevice(device, NULL);
    DestroyInstance(instance, NULL);
    dlclose(library);
    printf("{\"schema_version\":1,\"status\":\"transfer_readback_verified\",\"software_control\":%s,"
           "\"venus_transfer_verified\":%s,\"initial_contents_cleared\":true,\"fill_bytes_verified\":4096,"
           "\"fence_transition_verified\":true,\"queue_submission_verified\":true,"
           "\"shader_render_verified\":false,\"presentation_verified\":false,"
           "\"physical_gpu_acceleration_verified\":false,\"custom_icd_explicit\":%s}\n",
           control ? "true" : "false", control ? "false" : "true", custom_icd ? "true" : "false");

    return 0;
}
