/* SPDX-License-Identifier: Apache-2.0
 * Bounded private HAL / UDMABUF import control. One sealed 4096-byte memfd,
 * UDMABUF_CREATE, Vulkan import, GPU fill and independent memfd readback.
 * No shaders, images, presentation, guest mappings or VMM qualification.
 */
#define _GNU_SOURCE
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <hardware/hwvulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <linux/udmabuf.h>
#include <errno.h>

static VKAPI_ATTR VkBool32 VKAPI_CALL diagnostic(
    VkDebugUtilsMessageSeverityFlagBitsEXT severity,
    VkDebugUtilsMessageTypeFlagsEXT types,
    const VkDebugUtilsMessengerCallbackDataEXT *data, void *user) {
    (void)severity; (void)types; (void)user;
    /* Only the owned private driver's allocation/import diagnostic is useful. */
    if (data && data->pMessage && (strstr(data->pMessage, "dma-buf") ||
                                 strstr(data->pMessage, "VK_ERROR_OUT_OF_DEVICE_MEMORY")))
        fprintf(stderr, "GB_UDMABUF_DRIVER:%.1024s\n", data->pMessage);
    return VK_FALSE;
}
static int fail(const char *stage, int code) {
    printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"%s\",\"code\":%d,\"guest_vulkan_verified\":false}\n", stage, code);
    return 1;
}
#define CHECK(stage, call) do { VkResult r = (call); if (r != VK_SUCCESS) return fail(stage, r); } while (0)
#define INSTANCE(name) PFN_vk##name name = (PFN_vk##name)get(instance, "vk" #name); if (!name) return fail("entrypoint_" #name, -1)
#define DEVICE(name) PFN_vk##name name = (PFN_vk##name)GetDeviceProcAddr(device, "vk" #name); if (!name) return fail("entrypoint_" #name, -1)

int main(int argc, char **argv) {
    struct rlimit cores = {0, 0};
    if (setrlimit(RLIMIT_CORE, &cores)) return fail("core_limit", errno);
    alarm(20);
    if (argc != 2 || argv[1][0] != '/') return fail("explicit_absolute_driver_required", -1);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) return fail("dlopen", -1);
    hw_module_t *module = (hw_module_t *)dlsym(library, HAL_MODULE_INFO_SYM_AS_STR);
    if (!module || !module->id || strcmp(module->id, "vulkan") || !module->methods || !module->methods->open) return fail("vulkan_hal", -1);
    hw_device_t *common = NULL;
    int opened = module->methods->open(module, HWVULKAN_DEVICE_0, &common);
    if (opened || !common) return fail("hal_open", opened);
    PFN_vkGetInstanceProcAddr get = ((hwvulkan_device_t *)common)->GetInstanceProcAddr;
    if (!get) return fail("get_instance_proc_addr", -1);
    PFN_vkCreateInstance create = (PFN_vkCreateInstance)get(VK_NULL_HANDLE, "vkCreateInstance");
    if (!create) return fail("create_entrypoint", -1);
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "gb-private-vulkan-buffer", .apiVersion = VK_API_VERSION_1_1};
    const char *instance_extensions[] = {VK_EXT_DEBUG_UTILS_EXTENSION_NAME};
    VkDebugUtilsMessengerCreateInfoEXT diagnostics = {
        .sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT,
        .messageSeverity = VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT,
        .messageType = VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT | VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT,
        .pfnUserCallback = diagnostic};
    VkInstanceCreateInfo info = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pNext = &diagnostics,
        .pApplicationInfo = &app, .enabledExtensionCount = 1, .ppEnabledExtensionNames = instance_extensions};
    VkInstance instance = VK_NULL_HANDLE;
    CHECK("create_instance", create(&info, NULL, &instance));
    INSTANCE(CreateDebugUtilsMessengerEXT); INSTANCE(DestroyDebugUtilsMessengerEXT);
    VkDebugUtilsMessengerEXT messenger;
    CHECK("debug_callback", CreateDebugUtilsMessengerEXT(instance, &diagnostics, NULL, &messenger));
    INSTANCE(EnumeratePhysicalDevices); INSTANCE(GetPhysicalDeviceProperties);
    INSTANCE(GetPhysicalDeviceQueueFamilyProperties); INSTANCE(GetPhysicalDeviceMemoryProperties);
    INSTANCE(GetPhysicalDeviceExternalBufferProperties); INSTANCE(GetDeviceProcAddr);
    INSTANCE(CreateDevice); INSTANCE(DestroyInstance);
    uint32_t count = 0;
    CHECK("device_count", EnumeratePhysicalDevices(instance, &count, NULL));
    if (count != 1) return fail("one_physical_gpu_required", -1);
    VkPhysicalDevice physical;
    CHECK("device_enumeration", EnumeratePhysicalDevices(instance, &count, &physical));
    VkPhysicalDeviceProperties props;
    GetPhysicalDeviceProperties(physical, &props);
    if (props.deviceType != VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU &&
        props.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) return fail("hardware_device_required", -1);
    VkPhysicalDeviceExternalBufferInfo external = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_BUFFER_INFO,
        .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT, .handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkExternalBufferProperties external_props = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_BUFFER_PROPERTIES};
    GetPhysicalDeviceExternalBufferProperties(physical, &external, &external_props);
    VkExternalMemoryFeatureFlags features = external_props.externalMemoryProperties.externalMemoryFeatures;
    if ((features & (VK_EXTERNAL_MEMORY_FEATURE_EXPORTABLE_BIT | VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT)) !=
        (VK_EXTERNAL_MEMORY_FEATURE_EXPORTABLE_BIT | VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT) ||
        (features & VK_EXTERNAL_MEMORY_FEATURE_DEDICATED_ONLY_BIT)) return fail("non_dedicated_dma_buf_import_export_required", -1);
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
    const char *extensions[] = {VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME, VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME};
    VkDeviceCreateInfo device_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = 1, .pQueueCreateInfos = &queue_info,
        .enabledExtensionCount = 2, .ppEnabledExtensionNames = extensions};
    VkDevice device;
    CHECK("create_device", CreateDevice(physical, &device_info, NULL, &device));
    DEVICE(CreateBuffer); DEVICE(GetBufferMemoryRequirements2); DEVICE(AllocateMemory);
    DEVICE(BindBufferMemory); DEVICE(MapMemory); DEVICE(UnmapMemory); DEVICE(GetDeviceQueue);
    DEVICE(CreateCommandPool); DEVICE(AllocateCommandBuffers); DEVICE(BeginCommandBuffer);
    DEVICE(CmdFillBuffer); DEVICE(CmdPipelineBarrier); DEVICE(EndCommandBuffer);
    DEVICE(CreateFence); DEVICE(GetFenceStatus); DEVICE(QueueSubmit); DEVICE(WaitForFences);
    DEVICE(GetMemoryFdPropertiesKHR); DEVICE(DestroyFence);
    DEVICE(DestroyCommandPool); DEVICE(DestroyBuffer); DEVICE(FreeMemory); DEVICE(DestroyDevice);
    VkExternalMemoryBufferCreateInfo external_create = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO,
        .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkBufferCreateInfo buffer_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .pNext = &external_create,
        .size = 4096, .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT, .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    VkBuffer buffer;
    CHECK("create_external_buffer", CreateBuffer(device, &buffer_info, NULL, &buffer));
    VkMemoryDedicatedRequirements dedicated = {.sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_REQUIREMENTS};
    VkMemoryRequirements2 requirements = {.sType = VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2, .pNext = &dedicated};
    VkBufferMemoryRequirementsInfo2 requirements_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_REQUIREMENTS_INFO_2, .buffer = buffer};
    GetBufferMemoryRequirements2(device, &requirements_info, &requirements);
    VkMemoryRequirements req = requirements.memoryRequirements;
    if (dedicated.requiresDedicatedAllocation || req.size < 4096 || req.size > 16 * 1024 * 1024) return fail("allocation_budget_or_dedicated", -1);
    VkPhysicalDeviceMemoryProperties memory_props;
    GetPhysicalDeviceMemoryProperties(physical, &memory_props);
    if (!memory_props.memoryTypeCount || memory_props.memoryTypeCount > 32) return fail("memory_type_count", -1);
    uint32_t type = memory_props.memoryTypeCount;
    for (uint32_t i = 0; i < memory_props.memoryTypeCount; ++i)
        if ((req.memoryTypeBits & (1u << i)) &&
            (memory_props.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {type = i; break;}
    if (type == memory_props.memoryTypeCount) return fail("host_coherent_memory_required", -1);
    if (req.size != 4096) return fail("exact_4096_allocation_required", -1);
    int memfd = memfd_create("gb-udmabuf-control", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) return fail("memfd_create", errno);
    if (ftruncate(memfd, 4096)) return fail("memfd_size", errno);
    if (fcntl(memfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW)) return fail("memfd_seals", errno);
    int udmabuf_device = open("/dev/udmabuf", O_RDWR | O_CLOEXEC);
    if (udmabuf_device < 0) return fail("udmabuf_open", errno);
    struct udmabuf_create request = {.memfd = memfd, .flags = UDMABUF_FLAGS_CLOEXEC, .size = 4096};
    int dmabuf = ioctl(udmabuf_device, UDMABUF_CREATE, &request);
    if (dmabuf < 0) return fail("udmabuf_create", errno);
    close(udmabuf_device);
    VkMemoryFdPropertiesKHR fd_props = {.sType = VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR};
    CHECK("udmabuf_properties", GetMemoryFdPropertiesKHR(device, VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT, dmabuf, &fd_props));
    if (!(fd_props.memoryTypeBits & (1u << type))) return fail("udmabuf_memory_type_mismatch", -1);
    void *independent = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (independent == MAP_FAILED) return fail("independent_memfd_map", errno);
    memset(independent, 0, 4096);
    VkImportMemoryFdInfoKHR import_info = {.sType = VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR,
        .handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT, .fd = dmabuf};
    VkMemoryAllocateInfo allocation = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .pNext = &import_info, .allocationSize = req.size, .memoryTypeIndex = type};
    VkDeviceMemory memory;
    CHECK("import_udmabuf_memory", AllocateMemory(device, &allocation, NULL, &memory));
    CHECK("bind_imported_memory", BindBufferMemory(device, buffer, memory, 0));
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
    const uint32_t pattern = 0x6b475631;
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
    for (uint32_t i = 0; i < 1024; ++i)
        if (((volatile uint32_t *)independent)[i] != pattern) return fail("independent_memfd_readback_mismatch", -1);
    munmap(independent, 4096);
    close(memfd);
    DestroyFence(device, fence, NULL);
    DestroyCommandPool(device, pool, NULL);
    DestroyBuffer(device, buffer, NULL);
    FreeMemory(device, memory, NULL);
    DestroyDevice(device, NULL);
    DestroyDebugUtilsMessengerEXT(instance, messenger, NULL);
    DestroyInstance(instance, NULL);
    if (common->close) common->close(common);
    dlclose(library);
    printf("{\"schema_version\":1,\"status\":\"udmabuf_gpu_readback_verified\",\"verified_bytes\":4096,"
           "\"fence_verified\":true,\"independent_memfd_readback_verified\":true,\"guest_vulkan_verified\":false}\n");
    return 0;
}
