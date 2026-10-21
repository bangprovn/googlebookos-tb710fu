/* SPDX-License-Identifier: Apache-2.0
 * Bounded Venus DRM-modifier image -> DMA-BUF -> GLES consumer diagnostic.
 * A GPU fill and external ownership release precede a fence wait and FD export.
 * Only the exported owned buffer survives exec into the configured Python helper.
 * No WSI, desktop pixels, owner files, persistent installation or firmware writes.
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
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/socket.h>

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
    bool reuse = argc == 6 && !strcmp(argv[5], "--reuse");
    if ((argc != 5 && !reuse) || strcmp(argv[1], "--venus-icd") || argv[2][0] != '/' ||
        strcmp(argv[3], "--egl-consumer") || argv[4][0] != '/' ||
        strlen(argv[2]) > 4096 || strlen(argv[4]) > 4096)
        return fail("explicit_venus_icd_and_consumer_required", -1);
    const char *icd = argv[2];
    const char *format_profile = getenv("GB_GUEST_IMAGE_FORMAT_V1");
    uint32_t fourcc = 0x34324241u; /* ABGR8888, existing default */
    bool bgra = false, opaque = false;
    if (format_profile) {
        if (!strcmp(format_profile, "abgr8888")) fourcc = 0x34324241u;
        else if (!strcmp(format_profile, "argb8888")) {fourcc = 0x34325241u; bgra = true;}
        else if (!strcmp(format_profile, "xbgr8888")) {fourcc = 0x34324258u; opaque = true;}
        else if (!strcmp(format_profile, "xrgb8888")) {fourcc = 0x34325258u; bgra = opaque = true;}
        else return fail("unknown_image_format_profile", -1);
    }
    const char *neutral_profile = getenv("GB_GUEST_IMAGE_NEUTRAL_V1");
    bool with_neutral = neutral_profile != NULL;
    if (with_neutral && (strcmp(neutral_profile, "second-linear-xrgb") ||
                         !reuse || fourcc != 0x34325258u))
        return fail("unknown_neutral_image_profile", -1);
    const char *extent_profile = getenv("GB_GUEST_IMAGE_EXTENT_V1");
    if (extent_profile && (strcmp(extent_profile, "640x480") || !reuse || fourcc != 0x34325258u))
        return fail("unknown_image_extent_profile", -1);
    const uint32_t width = extent_profile ? 640u : 32u, height = extent_profile ? 480u : 32u;
    const char *render_profile = getenv("GB_GUEST_IMAGE_RENDER_V1");
    if (render_profile && (strcmp(render_profile, "renderpass-clear") ||
                           !reuse || !extent_profile || fourcc != 0x34325258u))
        return fail("unknown_image_render_profile", -1);
    bool render_clear = render_profile != NULL;
    const char *init_profile = getenv("GB_GUEST_IMAGE_INIT_V1");
    if (init_profile && (strcmp(init_profile, "gpu-only") || !reuse ||
                         !extent_profile || fourcc != 0x34325258u))
        return fail("unknown_image_init_profile", -1);
    bool gpu_only = init_profile != NULL;
    const VkPipelineStageFlags write_stage = render_clear ? VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT : VK_PIPELINE_STAGE_TRANSFER_BIT;
    const VkAccessFlags write_access = render_clear ? VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT : VK_ACCESS_TRANSFER_WRITE_BIT;
    const VkImageLayout write_layout = render_clear ? VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL : VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    const uint8_t source_alpha[3] = {opaque ? 0 : 255, opaque ? 73 : 255, opaque ? 127 : 255};
    if (setenv("VK_DRIVER_FILES", icd, 1) || unsetenv("VK_ICD_FILENAMES") ||
        setenv("MESA_SHADER_CACHE_DISABLE", "true", 1)) return fail("process_env", -1);
    void *library = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) return fail("dlopen", -1);
    PFN_vkGetInstanceProcAddr get = (PFN_vkGetInstanceProcAddr)dlsym(library, "vkGetInstanceProcAddr");
    if (!get) return fail("get_instance_proc_addr", -1);
    PFN_vkCreateInstance create = (PFN_vkCreateInstance)get(VK_NULL_HANDLE, "vkCreateInstance");
    if (!create) return fail("create_entrypoint", -1);
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "gb-guest-vulkan-egl-image", .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo info = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app};
    VkInstance instance = VK_NULL_HANDLE;
    CHECK("create_instance", create(&info, NULL, &instance));
    INSTANCE(EnumeratePhysicalDevices); INSTANCE(GetPhysicalDeviceProperties);
    INSTANCE(GetPhysicalDeviceQueueFamilyProperties); INSTANCE(GetPhysicalDeviceMemoryProperties);
    INSTANCE(GetDeviceProcAddr); INSTANCE(GetPhysicalDeviceFormatProperties2);
    INSTANCE(GetPhysicalDeviceImageFormatProperties2);
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
    if (!venus_adreno) return fail("selected_driver_identity_mismatch", -1);
    uint32_t families = 0;
    GetPhysicalDeviceQueueFamilyProperties(physical, &families, NULL);
    if (!families || families > 32) return fail("queue_family_count", -1);
    VkQueueFamilyProperties queues[32];
    GetPhysicalDeviceQueueFamilyProperties(physical, &families, queues);
    uint32_t family = families;
    for (uint32_t i = 0; i < families; ++i)
        if (queues[i].queueCount && (queues[i].queueFlags & (render_clear ? VK_QUEUE_GRAPHICS_BIT :
            (VK_QUEUE_TRANSFER_BIT | VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT)))) {family = i; break;}
    if (family == families) return fail("transfer_queue_required", -1);
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = family, .queueCount = 1, .pQueuePriorities = &priority};
    const VkFormat format = bgra ? VK_FORMAT_B8G8R8A8_UNORM : VK_FORMAT_R8G8B8A8_UNORM;
    const VkImageUsageFlags usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT |
        VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    const uint64_t modifier = 0; /* DRM_FORMAT_MOD_LINEAR, one plane only */
    VkDrmFormatModifierPropertiesListEXT modifiers = {.sType = VK_STRUCTURE_TYPE_DRM_FORMAT_MODIFIER_PROPERTIES_LIST_EXT};
    VkFormatProperties2 format_props = {.sType = VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2, .pNext = &modifiers};
    GetPhysicalDeviceFormatProperties2(physical, format, &format_props);
    if (!modifiers.drmFormatModifierCount || modifiers.drmFormatModifierCount > 128)
        return fail("modifier_count", -1);
    VkDrmFormatModifierPropertiesEXT mod_props[128];
    modifiers.pDrmFormatModifierProperties = mod_props;
    GetPhysicalDeviceFormatProperties2(physical, format, &format_props);
    bool linear_supported = false;
    for (uint32_t i = 0; i < modifiers.drmFormatModifierCount; ++i) {
        VkFormatFeatureFlags required = VK_FORMAT_FEATURE_TRANSFER_DST_BIT |
            VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT | VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT;
        if (mod_props[i].drmFormatModifier == modifier && mod_props[i].drmFormatModifierPlaneCount == 1 &&
            (mod_props[i].drmFormatModifierTilingFeatures & required) == required) linear_supported = true;
    }
    if (!linear_supported) return fail("single_plane_linear_modifier_required", -1);
    VkPhysicalDeviceImageDrmFormatModifierInfoEXT mod_query = {
        .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_DRM_FORMAT_MODIFIER_INFO_EXT,
        .drmFormatModifier = modifier, .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    VkPhysicalDeviceExternalImageFormatInfo external_query = {
        .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO,
        .pNext = &mod_query, .handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkPhysicalDeviceImageFormatInfo2 format_query = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_FORMAT_INFO_2,
        .pNext = &external_query, .format = format, .type = VK_IMAGE_TYPE_2D,
        .tiling = VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT, .usage = usage};
    VkExternalImageFormatProperties external_props = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES};
    VkImageFormatProperties2 image_props = {.sType = VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2, .pNext = &external_props};
    CHECK("external_image_format", GetPhysicalDeviceImageFormatProperties2(physical, &format_query, &image_props));
    if (!(external_props.externalMemoryProperties.externalMemoryFeatures & VK_EXTERNAL_MEMORY_FEATURE_EXPORTABLE_BIT) ||
        !(external_props.externalMemoryProperties.compatibleHandleTypes & VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT))
        return fail("exportable_image_required", -1);
    const char *extensions[] = {VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME,
        VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME, VK_EXT_QUEUE_FAMILY_FOREIGN_EXTENSION_NAME,
        VK_EXT_IMAGE_DRM_FORMAT_MODIFIER_EXTENSION_NAME};
    VkDeviceCreateInfo device_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .queueCreateInfoCount = 1, .pQueueCreateInfos = &queue_info,
        .enabledExtensionCount = 4, .ppEnabledExtensionNames = extensions};
    VkDevice device;
    CHECK("create_device", CreateDevice(physical, &device_info, NULL, &device));
    DEVICE(CreateImage); DEVICE(GetImageMemoryRequirements2); DEVICE(AllocateMemory);
    DEVICE(BindImageMemory); DEVICE(MapMemory); DEVICE(UnmapMemory); DEVICE(GetDeviceQueue);
    DEVICE(GetImageSubresourceLayout); DEVICE(GetImageDrmFormatModifierPropertiesEXT);
    DEVICE(CreateCommandPool); DEVICE(AllocateCommandBuffers); DEVICE(BeginCommandBuffer);
    DEVICE(CmdClearColorImage); DEVICE(CmdPipelineBarrier); DEVICE(EndCommandBuffer);
    DEVICE(CreateFence); DEVICE(ResetFences); DEVICE(ResetCommandBuffer); DEVICE(GetFenceStatus); DEVICE(QueueSubmit); DEVICE(WaitForFences);
    DEVICE(DestroyFence); DEVICE(GetMemoryFdKHR);
    DEVICE(DestroyCommandPool); DEVICE(DestroyImage); DEVICE(FreeMemory); DEVICE(DestroyDevice);
    DEVICE(CreateImageView); DEVICE(CreateRenderPass); DEVICE(CreateFramebuffer);
    DEVICE(CmdBeginRenderPass); DEVICE(CmdEndRenderPass);
    DEVICE(DestroyImageView); DEVICE(DestroyRenderPass); DEVICE(DestroyFramebuffer);
    VkImageDrmFormatModifierListCreateInfoEXT mod_list = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_LIST_CREATE_INFO_EXT,
        .drmFormatModifierCount = 1, .pDrmFormatModifiers = &modifier};
    VkExternalMemoryImageCreateInfo external = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO,
        .pNext = &mod_list, .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkImageCreateInfo image_info = {.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, .pNext = &external,
        .imageType = VK_IMAGE_TYPE_2D, .format = format, .extent = {width,height,1}, .mipLevels = 1,
        .arrayLayers = 1, .samples = VK_SAMPLE_COUNT_1_BIT, .tiling = VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT,
        .usage = usage, .sharingMode = VK_SHARING_MODE_EXCLUSIVE, .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED};
    VkImage image;
    CHECK("create_external_image", CreateImage(device, &image_info, NULL, &image));
    VkMemoryDedicatedRequirements dedicated = {.sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_REQUIREMENTS};
    VkMemoryRequirements2 requirements = {.sType = VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2, .pNext = &dedicated};
    VkImageMemoryRequirementsInfo2 requirements_info = {.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_REQUIREMENTS_INFO_2, .image = image};
    GetImageMemoryRequirements2(device, &requirements_info, &requirements);
    VkMemoryRequirements req = requirements.memoryRequirements;
    if (req.size < 4096 || req.size > (extent_profile ? 4u : 1u) * 1024 * 1024) return fail("image_allocation_budget", -1);
    VkPhysicalDeviceMemoryProperties memory_props;
    GetPhysicalDeviceMemoryProperties(physical, &memory_props);
    if (!memory_props.memoryTypeCount || memory_props.memoryTypeCount > 32) return fail("memory_type_count", -1);
    uint32_t type = memory_props.memoryTypeCount;
    for (uint32_t i = 0; i < memory_props.memoryTypeCount; ++i)
        if ((req.memoryTypeBits & (1u << i)) &&
            (memory_props.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) ==
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {type = i; break;}
    if (type == memory_props.memoryTypeCount) return fail("host_coherent_memory_required", -1);
    VkMemoryDedicatedAllocateInfo dedicated_alloc = {.sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO, .image = image};
    VkExportMemoryAllocateInfo export = {.sType = VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO, .pNext = &dedicated_alloc,
        .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkMemoryAllocateInfo allocation = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .pNext = &export,
        .allocationSize = req.size, .memoryTypeIndex = type};
    VkDeviceMemory memory;
    CHECK("allocate_memory", AllocateMemory(device, &allocation, NULL, &memory));
    CHECK("bind_image_memory", BindImageMemory(device, image, memory, 0));
    VkImageDrmFormatModifierPropertiesEXT selected = {.sType = VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_PROPERTIES_EXT};
    CHECK("selected_modifier", GetImageDrmFormatModifierPropertiesEXT(device, image, &selected));
    if (selected.drmFormatModifier != modifier) return fail("unexpected_modifier", -1);
    VkImageSubresource subresource = {.aspectMask = VK_IMAGE_ASPECT_MEMORY_PLANE_0_BIT_EXT};
    VkSubresourceLayout layout;
    GetImageSubresourceLayout(device, image, &subresource, &layout);
    if (layout.rowPitch < width * 4u || layout.rowPitch > 65536 || layout.offset > req.size ||
        layout.offset + (height - 1u) * layout.rowPitch + width * 4u > req.size)
        return fail("plane_layout_out_of_allocation", -1);
    char metadata[512];
    int metadata_size = snprintf(metadata, sizeof(metadata),
        "{\"width\":%u,\"height\":%u,\"stride\":%" PRIu64 ",\"offset\":%" PRIu64
        ",\"modifier\":0,\"allocation_bytes\":%" PRIu64 ",\"rgba\":[19,67,139,255]}",
        width, height, layout.rowPitch, layout.offset, req.size);
    if (metadata_size < 0 || (size_t)metadata_size >= sizeof(metadata)) return fail("metadata_budget", -1);
    if (format_profile) {
        /* rgba is the expected sampled value. RGBX must hide stored alpha,
         * which deliberately changes between zero and non-opaque values. */
        metadata_size = snprintf(metadata, sizeof(metadata),
            "{\"schema_version\":2,\"fourcc\":%u,\"source_alpha\":[%u,%u,%u],"
            "\"width\":%u,\"height\":%u,\"stride\":%" PRIu64 ",\"offset\":%" PRIu64
            ",\"modifier\":0,\"allocation_bytes\":%" PRIu64 ",\"rgba\":[19,67,139,255]}",
            fourcc, source_alpha[0], source_alpha[1], source_alpha[2],
            width, height, layout.rowPitch, layout.offset, req.size);
        if (metadata_size < 0 || (size_t)metadata_size >= sizeof(metadata)) return fail("metadata_budget", -1);
    }
    fprintf(stderr, "GB_GUEST_VK_IMAGE_LAYOUT:%s\n", metadata);
    void *mapped;
    /* A recycled allocation must not pass from an earlier run's pattern if
     * submission silently does nothing. Coherent host writes precede submit. */
    if (!gpu_only) {
        CHECK("map_initial_memory", MapMemory(device, memory, 0, req.size, 0, &mapped));
        memset(mapped, 0, (size_t)req.size);
        UnmapMemory(device, memory);
    }
    VkCommandPoolCreateInfo pool_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = family, .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT};
    VkCommandPool pool;
    CHECK("create_command_pool", CreateCommandPool(device, &pool_info, NULL, &pool));
    VkCommandBufferAllocateInfo command_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = pool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1};
    VkCommandBuffer command;
    CHECK("allocate_command_buffer", AllocateCommandBuffers(device, &command_info, &command));
    VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
    CHECK("begin_command_buffer", BeginCommandBuffer(command, &begin));
    VkImageSubresourceRange range = {.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT, .levelCount = 1, .layerCount = 1};
    VkImageView render_view = VK_NULL_HANDLE;
    VkRenderPass render_pass = VK_NULL_HANDLE;
    VkFramebuffer render_framebuffer = VK_NULL_HANDLE;
    VkClearValue render_value;
    VkRenderPassBeginInfo render_begin = {.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
        .renderArea = {.extent = {width, height}}, .clearValueCount = 1, .pClearValues = &render_value};
    if (render_clear) {
        VkImageViewCreateInfo view_info = {.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
            .image = image, .viewType = VK_IMAGE_VIEW_TYPE_2D, .format = format, .subresourceRange = range};
        CHECK("create_render_view", CreateImageView(device, &view_info, NULL, &render_view));
        VkAttachmentDescription attachment = {.format = format, .samples = VK_SAMPLE_COUNT_1_BIT,
            .loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR, .storeOp = VK_ATTACHMENT_STORE_OP_STORE,
            .stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE, .stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE,
            .initialLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL, .finalLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
        VkAttachmentReference reference = {.attachment = 0, .layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
        VkSubpassDescription subpass = {.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS,
            .colorAttachmentCount = 1, .pColorAttachments = &reference};
        VkRenderPassCreateInfo pass_info = {.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO,
            .attachmentCount = 1, .pAttachments = &attachment, .subpassCount = 1, .pSubpasses = &subpass};
        CHECK("create_render_pass", CreateRenderPass(device, &pass_info, NULL, &render_pass));
        VkFramebufferCreateInfo fb_info = {.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO,
            .renderPass = render_pass, .attachmentCount = 1, .pAttachments = &render_view,
            .width = width, .height = height, .layers = 1};
        CHECK("create_render_framebuffer", CreateFramebuffer(device, &fb_info, NULL, &render_framebuffer));
        render_begin.renderPass = render_pass; render_begin.framebuffer = render_framebuffer;
    }
    VkImageMemoryBarrier barrier = {.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .srcAccessMask = 0, .dstAccessMask = write_access,
        .oldLayout = VK_IMAGE_LAYOUT_UNDEFINED, .newLayout = write_layout,
        .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED, .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
        .image = image, .subresourceRange = range};
    CmdPipelineBarrier(command, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, write_stage,
        0, 0, NULL, 0, NULL, 1, &barrier);
    VkClearColorValue color = {.float32 = {19/255.0f,67/255.0f,139/255.0f,source_alpha[0]/255.0f}};
    if (render_clear) {
        render_value.color = color; CmdBeginRenderPass(command, &render_begin, VK_SUBPASS_CONTENTS_INLINE);
        CmdEndRenderPass(command);
    } else CmdClearColorImage(command, image, write_layout, &color, 1, &range);
    barrier.srcAccessMask = write_access; barrier.dstAccessMask = 0;
    barrier.oldLayout = write_layout; barrier.newLayout = VK_IMAGE_LAYOUT_GENERAL;
    barrier.srcQueueFamilyIndex = family; barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_FOREIGN_EXT;
    CmdPipelineBarrier(command, write_stage, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
        0, 0, NULL, 0, NULL, 1, &barrier);
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
    VkMemoryGetFdInfoKHR fd_info = {.sType = VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR,
        .memory = memory, .handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    int fd = -1;
    CHECK("export_dma_buf", GetMemoryFdKHR(device, &fd_info, &fd));
    if (fd < 0) return fail("exported_fd_absent", -1);
    VkImage neutral_image = VK_NULL_HANDLE;
    VkDeviceMemory neutral_memory = VK_NULL_HANDLE;
    int neutral_fd = -1;
    if (with_neutral) {
        CHECK("create_neutral_image", CreateImage(device, &image_info, NULL, &neutral_image));
        VkMemoryRequirements2 neutral_req = {.sType = VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2};
        VkImageMemoryRequirementsInfo2 neutral_req_info = {
            .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_REQUIREMENTS_INFO_2, .image = neutral_image};
        GetImageMemoryRequirements2(device, &neutral_req_info, &neutral_req);
        if (neutral_req.memoryRequirements.size != req.size ||
            !(neutral_req.memoryRequirements.memoryTypeBits & (1u << type)))
            return fail("neutral_memory_layout_mismatch", -1);
        VkMemoryDedicatedAllocateInfo neutral_dedicated = {
            .sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO, .image = neutral_image};
        VkExportMemoryAllocateInfo neutral_export = {
            .sType = VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO, .pNext = &neutral_dedicated,
            .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
        VkMemoryAllocateInfo neutral_allocation = allocation;
        neutral_allocation.pNext = &neutral_export;
        CHECK("allocate_neutral", AllocateMemory(device, &neutral_allocation, NULL, &neutral_memory));
        CHECK("bind_neutral", BindImageMemory(device, neutral_image, neutral_memory, 0));
        VkImageDrmFormatModifierPropertiesEXT neutral_modifier = {
            .sType = VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_PROPERTIES_EXT};
        CHECK("neutral_modifier", GetImageDrmFormatModifierPropertiesEXT(device, neutral_image, &neutral_modifier));
        VkSubresourceLayout neutral_layout;
        GetImageSubresourceLayout(device, neutral_image, &subresource, &neutral_layout);
        if (neutral_modifier.drmFormatModifier != 0 || neutral_layout.offset != layout.offset ||
            neutral_layout.rowPitch != layout.rowPitch)
            return fail("neutral_plane_layout_mismatch", -1);
        if (!gpu_only) {
            CHECK("map_neutral_initial", MapMemory(device, neutral_memory, 0, req.size, 0, &mapped));
            memset(mapped, 0, (size_t)req.size); UnmapMemory(device, neutral_memory);
        }
        CHECK("neutral_reset_fence", ResetFences(device, 1, &fence));
        CHECK("neutral_reset_command", ResetCommandBuffer(command, 0));
        CHECK("neutral_begin", BeginCommandBuffer(command, &begin));
        VkImageMemoryBarrier neutral_barrier = barrier;
        neutral_barrier.image = neutral_image;
        neutral_barrier.srcAccessMask = 0; neutral_barrier.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        neutral_barrier.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
        neutral_barrier.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        neutral_barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        neutral_barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        CmdPipelineBarrier(command, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
            0, 0, NULL, 0, NULL, 1, &neutral_barrier);
        VkClearColorValue neutral_color = {.float32 = {32/255.0f,32/255.0f,32/255.0f,1.0f}};
        CmdClearColorImage(command, neutral_image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &neutral_color, 1, &range);
        neutral_barrier.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT; neutral_barrier.dstAccessMask = 0;
        neutral_barrier.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL; neutral_barrier.newLayout = VK_IMAGE_LAYOUT_GENERAL;
        neutral_barrier.srcQueueFamilyIndex = family; neutral_barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_FOREIGN_EXT;
        CmdPipelineBarrier(command, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
            0, 0, NULL, 0, NULL, 1, &neutral_barrier);
        CHECK("neutral_end", EndCommandBuffer(command));
        CHECK("neutral_submit", QueueSubmit(queue, 1, &submit, fence));
        CHECK("neutral_wait", WaitForFences(device, 1, &fence, VK_TRUE, 2000000000ULL));
        VkMemoryGetFdInfoKHR neutral_fd_info = fd_info;
        neutral_fd_info.memory = neutral_memory;
        CHECK("export_neutral", GetMemoryFdKHR(device, &neutral_fd_info, &neutral_fd));
        if (neutral_fd < 0 || neutral_fd == fd) return fail("neutral_descriptor", -1);
    }
    int ipc[2] = {-1,-1};
    if (reuse && socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, ipc)) return fail("socketpair", errno);
    pid_t parent = getpid(), child = fork();
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
            fcntl(fd, F_SETFD, 0)) _exit(125);
        char number[32]; snprintf(number, sizeof(number), "%d", fd);
        if (with_neutral) {
            char neutral_number[32]; snprintf(neutral_number, sizeof(neutral_number), "%d", neutral_fd);
            if (fcntl(neutral_fd, F_SETFD, 0) ||
                setenv("GB_OWNED_NEUTRAL_DMA_FD", neutral_number, 1)) _exit(125);
        } else if (unsetenv("GB_OWNED_NEUTRAL_DMA_FD")) _exit(125);
        if (reuse) {
            close(ipc[0]);
            if (fcntl(ipc[1], F_SETFD, 0)) _exit(125);
            char channel[32]; snprintf(channel, sizeof(channel), "%d", ipc[1]);
            execl("/usr/bin/python3", "python3", argv[4], "--owned-dma-buf-fd", number,
                "--image-layout-json", metadata, "--roundtrip-fd", channel, (char *)NULL);
            _exit(126);
        }
        execl("/usr/bin/python3", "python3", argv[4], "--owned-dma-buf-fd", number, "--image-layout-json", metadata, (char *)NULL);
        _exit(126);
    }
    close(fd);
    if (neutral_fd >= 0) close(neutral_fd);
    if (child < 0) return fail("fork_consumer", errno);
    if (reuse) {
        close(ipc[1]);
        uint8_t colors[3][4] = {{19,67,139,255},{203,37,91,255},{47,181,113,255}};
        for (unsigned i = 0; i < 3; ++i) colors[i][3] = source_alpha[i];
        for (uint8_t phase = 0; phase < 3; ++phase) {
            if (phase) {
                CHECK("reset_fence", ResetFences(device, 1, &fence));
                CHECK("reset_command", ResetCommandBuffer(command, 0));
                CHECK("reuse_begin", BeginCommandBuffer(command, &begin));
                barrier.srcAccessMask = 0; barrier.dstAccessMask = write_access;
                barrier.oldLayout = VK_IMAGE_LAYOUT_GENERAL; barrier.newLayout = write_layout;
                barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_FOREIGN_EXT; barrier.dstQueueFamilyIndex = family;
                CmdPipelineBarrier(command, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, write_stage,
                    0, 0, NULL, 0, NULL, 1, &barrier);
                for (unsigned channel = 0; channel < 4; ++channel) color.float32[channel] = colors[phase][channel]/255.0f;
                if (render_clear) {
                    render_value.color = color; CmdBeginRenderPass(command, &render_begin, VK_SUBPASS_CONTENTS_INLINE);
                    CmdEndRenderPass(command);
                } else CmdClearColorImage(command, image, write_layout, &color, 1, &range);
                barrier.srcAccessMask = write_access; barrier.dstAccessMask = 0;
                barrier.oldLayout = write_layout; barrier.newLayout = VK_IMAGE_LAYOUT_GENERAL;
                barrier.srcQueueFamilyIndex = family; barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_FOREIGN_EXT;
                CmdPipelineBarrier(command, write_stage, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
                    0, 0, NULL, 0, NULL, 1, &barrier);
                CHECK("reuse_end", EndCommandBuffer(command));
                if (GetFenceStatus(device, fence) != VK_NOT_READY) return fail("reuse_unsignalled_fence", -1);
                CHECK("reuse_submit", QueueSubmit(queue, 1, &submit, fence));
                CHECK("reuse_fence_wait", WaitForFences(device, 1, &fence, VK_TRUE, 2000000000ULL));
                CHECK("reuse_fence_signalled", GetFenceStatus(device, fence));
            }
            fprintf(stderr, "GB_GUEST_VK_REUSE_PHASE:%u\n", phase);
            if (send(ipc[0], &phase, 1, MSG_NOSIGNAL) != 1) return fail("phase_send", errno);
            uint8_t ack = 0;
            ssize_t received = recv(ipc[0], &ack, 1, 0);
            if (received != 1 || ack != (uint8_t)(0x80 | phase)) return fail("phase_ack", (int)received);
        }
        close(ipc[0]);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return fail("wait_consumer", errno);
    bool consumer_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    DestroyFence(device, fence, NULL);
    DestroyCommandPool(device, pool, NULL);
    if (render_framebuffer) DestroyFramebuffer(device, render_framebuffer, NULL);
    if (render_view) DestroyImageView(device, render_view, NULL);
    if (render_pass) DestroyRenderPass(device, render_pass, NULL);
    if (neutral_image) DestroyImage(device, neutral_image, NULL);
    if (neutral_memory) FreeMemory(device, neutral_memory, NULL);
    DestroyImage(device, image, NULL);
    FreeMemory(device, memory, NULL);
    DestroyDevice(device, NULL);
    DestroyInstance(instance, NULL);
    dlclose(library);
    if (!consumer_ok) return fail("egl_consumer_failed", status);
    /* Only the consumer/host observer can verify sampled or displayed pixels.
     * A successful child exit alone is not image-readback evidence. */
    printf("{\"schema_version\":1,\"status\":\"external_image_producer_completed\",\"consumer_exit_code\":0,"
        "\"plane_layout\":%s,\"foreign_queue_release\":true,\"initial_contents_cleared\":%s,"
        "\"reuse_rounds\":%u,\"image_writes\":\"%s\",\"presentation_verified\":false,\"full_port_verified\":false}\n",
        metadata, gpu_only ? "false" : "true", reuse ? 3u : 1u, render_clear ? "renderpass_clear" : "transfer_clear");
    return 0;
}
