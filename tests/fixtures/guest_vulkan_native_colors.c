/* SPDX-License-Identifier: Apache-2.0
 * Owned Wayland/Vulkan swapchain attachment-clear diagnostic. No owner input
 * or framebuffer is read. Success means API completion, not verified pixels.
 * --swapchain-lifecycle opts into three bounded generations and requires
 * maintenance1 presentation fences before retiring old resources.
 */
#define _GNU_SOURCE
#define VK_USE_PLATFORM_WAYLAND_KHR
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <errno.h>
#include <poll.h>

static int fail(const char *stage, int code)
{
    printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"%s\",\"code\":%d,\"presentation_verified\":false}\n", stage, code);
    return 1;
}
#define CHECK(stage, call) do { VkResult r = (call); if (r != VK_SUCCESS) return fail(stage, r); } while (0)
#define INSTANCE(name) PFN_vk##name name = (PFN_vk##name)get(instance, "vk" #name); if (!name) return fail("entrypoint_" #name, -1)
#define DEVICE(name) PFN_vk##name name = (PFN_vk##name)GetDeviceProcAddr(device, "vk" #name); if (!name) return fail("entrypoint_" #name, -1)

struct window {
    struct wl_display *display;
    struct wl_compositor *compositor;
    struct xdg_wm_base *wm;
    bool configured, closed;
};
static int64_t monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}
static bool wait_configure(struct window *w)
{
    int64_t begin = monotonic_ms();
    if (begin < 0) return false;
    while (!w->configured && !w->closed) {
        int64_t now = monotonic_ms();
        if (now < 0 || now - begin >= 3000) return false;
        while (wl_display_prepare_read(w->display) != 0) {
            if (wl_display_dispatch_pending(w->display) < 0) return false;
            if (w->configured || w->closed) return w->configured && !w->closed;
            now = monotonic_ms();
            if (now < 0 || now - begin >= 3000) return false;
        }
        int flushed = wl_display_flush(w->display);
        if (flushed < 0 && errno != EAGAIN) {wl_display_cancel_read(w->display); return false;}
        struct pollfd fd = {.fd = wl_display_get_fd(w->display), .events = POLLIN | (flushed < 0 ? POLLOUT : 0)};
        int ready = poll(&fd, 1, (int)(3000 - (now - begin)));
        if (ready > 0 && (fd.revents & POLLIN)) {
            if (wl_display_read_events(w->display) < 0 || wl_display_dispatch_pending(w->display) < 0) return false;
        } else {
            wl_display_cancel_read(w->display);
            if (ready == 0 || (ready < 0 && errno != EINTR) || (ready > 0 && (fd.revents & (POLLERR | POLLHUP | POLLNVAL)))) return false;
        }
    }
    return w->configured && !w->closed;
}
static void global(void *data, struct wl_registry *registry, uint32_t name, const char *interface, uint32_t version)
{
    struct window *w = data;
    if (!strcmp(interface, "wl_compositor") && version >= 4 && !w->compositor)
        w->compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 4);
    if (!strcmp(interface, "xdg_wm_base") && version >= 1 && !w->wm)
        w->wm = wl_registry_bind(registry, name, &xdg_wm_base_interface, 1);
}
static void removed(void *data, struct wl_registry *registry, uint32_t name)
{ (void)registry; (void)name; ((struct window *)data)->closed = true; }
static void ping(void *data, struct xdg_wm_base *wm, uint32_t serial)
{ (void)data; xdg_wm_base_pong(wm, serial); }
static void configure(void *data, struct xdg_surface *surface, uint32_t serial)
{ xdg_surface_ack_configure(surface, serial); ((struct window *)data)->configured = true; }
static void size_hint(void *data, struct xdg_toplevel *top, int32_t width, int32_t height, struct wl_array *states)
{ (void)data; (void)top; (void)width; (void)height; (void)states; }
static void close_window(void *data, struct xdg_toplevel *top)
{ (void)top; ((struct window *)data)->closed = true; }

struct native_chain {
    VkSwapchainKHR handle;
    uint32_t count;
    VkImageView views[4];
    VkFramebuffer framebuffers[4];
    VkSemaphore done[4];
};
struct chain_destructors {
    PFN_vkDestroySemaphore semaphore;
    PFN_vkDestroyFramebuffer framebuffer;
    PFN_vkDestroyImageView view;
    PFN_vkDestroySwapchainKHR swapchain;
};
static void destroy_chain(VkDevice device, struct native_chain *chain, const struct chain_destructors *destroy)
{
    for (uint32_t i = 0; i < chain->count; i++) {
        destroy->semaphore(device, chain->done[i], NULL);
        destroy->framebuffer(device, chain->framebuffers[i], NULL);
        destroy->view(device, chain->views[i], NULL);
    }
    if (chain->handle) destroy->swapchain(device, chain->handle, NULL);
    memset(chain, 0, sizeof(*chain));
}

int main(int argc, char **argv)
{
    struct rlimit cores = {0, 0};
    if (setrlimit(RLIMIT_CORE, &cores)) return fail("core_limit", -1);
    alarm(30);
    bool lifecycle = argc == 4 && !strcmp(argv[3], "--swapchain-lifecycle");
    if ((argc != 3 && !lifecycle) || strcmp(argv[1], "--venus-icd") || argv[2][0] != '/' || strlen(argv[2]) > 4096)
        return fail("explicit_venus_icd_required", -1);
    const char *display_name = getenv("WAYLAND_DISPLAY"), *peer_text = getenv("GB_OWNED_COMPOSITOR_PID");
    if (!display_name || (strcmp(display_name, "wayland-0") && strcmp(display_name, "wayland-1") && strcmp(display_name, "wayland-2")) || !peer_text)
        return fail("owned_compositor_required", -1);
    char *end = NULL;
    long peer_pid = strtol(peer_text, &end, 10);
    if (!end || *end || peer_pid < 2 || peer_pid > 4194304 || getuid() != 1000)
        return fail("owned_compositor_identity", -1);
    if (setenv("VK_DRIVER_FILES", argv[2], 1) || unsetenv("VK_ICD_FILENAMES") || unsetenv("WAYLAND_SOCKET"))
        return fail("process_environment", -1);
    struct window w = {0};
    w.display = wl_display_connect(display_name);
    if (!w.display) return fail("wayland_connect", -1);
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(wl_display_get_fd(w.display), SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) ||
        peer.pid != peer_pid || peer.uid != getuid()) return fail("wayland_peer", -1);
    struct wl_registry *registry = wl_display_get_registry(w.display);
    if (!registry) return fail("create_registry", -1);
    static const struct wl_registry_listener registry_listener = {.global = global, .global_remove = removed};
    wl_registry_add_listener(registry, &registry_listener, &w);
    if (wl_display_roundtrip(w.display) < 0 || !w.compositor || !w.wm || w.closed)
        return fail("wayland_globals", -1);
    static const struct xdg_wm_base_listener wm_listener = {.ping = ping};
    xdg_wm_base_add_listener(w.wm, &wm_listener, &w);
    struct wl_surface *surface = wl_compositor_create_surface(w.compositor);
    if (!surface) return fail("create_wayland_surface", -1);
    struct xdg_surface *xdg = xdg_wm_base_get_xdg_surface(w.wm, surface);
    if (!xdg) return fail("create_xdg_surface", -1);
    static const struct xdg_surface_listener surface_listener = {.configure = configure};
    xdg_surface_add_listener(xdg, &surface_listener, &w);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xdg);
    if (!top) return fail("create_toplevel", -1);
    static const struct xdg_toplevel_listener top_listener = {.configure = size_hint, .close = close_window};
    xdg_toplevel_add_listener(top, &top_listener, &w);
    xdg_toplevel_set_title(top, "Googlebook owned native Vulkan colors");
    wl_surface_commit(surface);
    if (!wait_configure(&w))
        return fail("wayland_configure", -1);

    void *library = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) return fail("vulkan_loader", -1);
    PFN_vkGetInstanceProcAddr get = (PFN_vkGetInstanceProcAddr)dlsym(library, "vkGetInstanceProcAddr");
    if (!get) return fail("vulkan_entrypoint", -1);
    PFN_vkCreateInstance create_instance = (PFN_vkCreateInstance)get(VK_NULL_HANDLE, "vkCreateInstance");
    if (!create_instance) return fail("create_instance_entrypoint", -1);
    const char *instance_extensions[] = {VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_WAYLAND_SURFACE_EXTENSION_NAME,
        VK_KHR_GET_SURFACE_CAPABILITIES_2_EXTENSION_NAME, VK_EXT_SURFACE_MAINTENANCE_1_EXTENSION_NAME};
    if (lifecycle) {
        PFN_vkEnumerateInstanceExtensionProperties enumerate =
            (PFN_vkEnumerateInstanceExtensionProperties)get(VK_NULL_HANDLE, "vkEnumerateInstanceExtensionProperties");
        if (!enumerate) return fail("lifecycle_instance_extensions_entrypoint", -1);
        uint32_t extension_count = 0;
        CHECK("instance_extension_count", enumerate(NULL, &extension_count, NULL));
        if (!extension_count || extension_count > 256) return fail("instance_extension_budget", -1);
        VkExtensionProperties extensions[256];
        CHECK("instance_extensions", enumerate(NULL, &extension_count, extensions));
        for (uint32_t required = 2; required < 4; required++) {
            bool found = false;
            for (uint32_t i = 0; i < extension_count; i++)
                if (!strcmp(extensions[i].extensionName, instance_extensions[required])) found = true;
            if (!found) return fail("lifecycle_surface_maintenance_extensions_required", -1);
        }
    }
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "gb-owned-native-colors", .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo instance_info = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app, .enabledExtensionCount = lifecycle ? 4 : 2, .ppEnabledExtensionNames = instance_extensions};
    VkInstance instance;
    CHECK("create_instance", create_instance(&instance_info, NULL, &instance));
    INSTANCE(EnumeratePhysicalDevices); INSTANCE(GetPhysicalDeviceProperties); INSTANCE(GetPhysicalDeviceQueueFamilyProperties);
    INSTANCE(CreateWaylandSurfaceKHR); INSTANCE(GetPhysicalDeviceSurfaceSupportKHR);
    INSTANCE(GetPhysicalDeviceSurfaceCapabilitiesKHR); INSTANCE(GetPhysicalDeviceSurfaceFormatsKHR);
    INSTANCE(CreateDevice); INSTANCE(GetDeviceProcAddr); INSTANCE(DestroySurfaceKHR); INSTANCE(DestroyInstance);
    PFN_vkEnumerateDeviceExtensionProperties EnumerateDeviceExtensionProperties = NULL;
    PFN_vkGetPhysicalDeviceFeatures2 GetPhysicalDeviceFeatures2 = NULL;
    if (lifecycle) {
        EnumerateDeviceExtensionProperties = (PFN_vkEnumerateDeviceExtensionProperties)get(instance, "vkEnumerateDeviceExtensionProperties");
        GetPhysicalDeviceFeatures2 = (PFN_vkGetPhysicalDeviceFeatures2)get(instance, "vkGetPhysicalDeviceFeatures2");
        if (!EnumerateDeviceExtensionProperties || !GetPhysicalDeviceFeatures2) return fail("lifecycle_feature_entrypoints", -1);
    }
    uint32_t physical_count = 0;
    CHECK("physical_count", EnumeratePhysicalDevices(instance, &physical_count, NULL));
    if (physical_count != 1) return fail("one_physical_gpu_required", -1);
    VkPhysicalDevice physical;
    CHECK("physical_device", EnumeratePhysicalDevices(instance, &physical_count, &physical));
    VkPhysicalDeviceProperties props;
    GetPhysicalDeviceProperties(physical, &props);
    props.deviceName[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE - 1] = 0;
    if (!strstr(props.deviceName, "Virtio-GPU Venus") || !strstr(props.deviceName, "Adreno") || props.vendorID != 0x5143)
        return fail("venus_adreno_required", -1);
    VkWaylandSurfaceCreateInfoKHR surface_info = {.sType = VK_STRUCTURE_TYPE_WAYLAND_SURFACE_CREATE_INFO_KHR,
        .display = w.display, .surface = surface};
    VkSurfaceKHR vk_surface;
    CHECK("create_surface", CreateWaylandSurfaceKHR(instance, &surface_info, NULL, &vk_surface));
    uint32_t queue_count = 0;
    GetPhysicalDeviceQueueFamilyProperties(physical, &queue_count, NULL);
    if (!queue_count || queue_count > 32) return fail("queue_count", -1);
    VkQueueFamilyProperties families[32];
    GetPhysicalDeviceQueueFamilyProperties(physical, &queue_count, families);
    uint32_t family = queue_count;
    for (uint32_t i = 0; i < queue_count; i++) {
        VkBool32 present = VK_FALSE;
        CHECK("surface_queue", GetPhysicalDeviceSurfaceSupportKHR(physical, i, vk_surface, &present));
        if (present && families[i].queueCount && (families[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)) {family = i; break;}
    }
    if (family == queue_count) return fail("graphics_present_queue", -1);
    float priority = 1;
    VkDeviceQueueCreateInfo queue_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = family, .queueCount = 1, .pQueuePriorities = &priority};
    const char *device_extensions[] = {VK_KHR_SWAPCHAIN_EXTENSION_NAME, VK_EXT_SWAPCHAIN_MAINTENANCE_1_EXTENSION_NAME};
    VkPhysicalDeviceSwapchainMaintenance1FeaturesEXT maintenance = {
        .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SWAPCHAIN_MAINTENANCE_1_FEATURES_EXT};
    if (lifecycle) {
        uint32_t extension_count = 0;
        CHECK("device_extension_count", EnumerateDeviceExtensionProperties(physical, NULL, &extension_count, NULL));
        if (!extension_count || extension_count > 256) return fail("device_extension_budget", -1);
        VkExtensionProperties extensions[256];
        CHECK("device_extensions", EnumerateDeviceExtensionProperties(physical, NULL, &extension_count, extensions));
        bool present_fences = false;
        for (uint32_t i = 0; i < extension_count; i++)
            if (!strcmp(extensions[i].extensionName, VK_EXT_SWAPCHAIN_MAINTENANCE_1_EXTENSION_NAME)) present_fences = true;
        if (!present_fences) return fail("lifecycle_present_fence_extension_required", -1);
        VkPhysicalDeviceFeatures2 features = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, .pNext = &maintenance};
        GetPhysicalDeviceFeatures2(physical, &features);
        if (!maintenance.swapchainMaintenance1) return fail("lifecycle_present_fence_feature_required", -1);
    }
    VkDeviceCreateInfo device_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, .queueCreateInfoCount = 1,
        .pQueueCreateInfos = &queue_info, .enabledExtensionCount = lifecycle ? 2 : 1,
        .ppEnabledExtensionNames = device_extensions, .pNext = lifecycle ? &maintenance : NULL};
    VkDevice device;
    CHECK("create_device", CreateDevice(physical, &device_info, NULL, &device));
    DEVICE(CreateSwapchainKHR); DEVICE(GetSwapchainImagesKHR); DEVICE(AcquireNextImageKHR); DEVICE(QueuePresentKHR);
    DEVICE(CreateImageView); DEVICE(CreateRenderPass); DEVICE(CreateFramebuffer); DEVICE(GetDeviceQueue);
    DEVICE(CreateCommandPool); DEVICE(AllocateCommandBuffers); DEVICE(ResetCommandBuffer); DEVICE(BeginCommandBuffer);
    DEVICE(CmdBeginRenderPass); DEVICE(CmdEndRenderPass); DEVICE(EndCommandBuffer); DEVICE(QueueSubmit);
    DEVICE(CreateFence); DEVICE(WaitForFences); DEVICE(ResetFences); DEVICE(CreateSemaphore); DEVICE(DeviceWaitIdle);
    DEVICE(DestroySemaphore); DEVICE(DestroyFence); DEVICE(DestroyFramebuffer); DEVICE(DestroyImageView);
    DEVICE(DestroyRenderPass); DEVICE(DestroyCommandPool); DEVICE(DestroySwapchainKHR); DEVICE(DestroyDevice);
    VkSurfaceCapabilitiesKHR caps;
    CHECK("surface_capabilities", GetPhysicalDeviceSurfaceCapabilitiesKHR(physical, vk_surface, &caps));
    if (!(caps.supportedUsageFlags & VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT) ||
        !(caps.supportedCompositeAlpha & VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR)) return fail("surface_usage", -1);
    VkExtent2D extent = {640, 480};
    if ((caps.currentExtent.width != UINT32_MAX && (caps.currentExtent.width != 640 || caps.currentExtent.height != 480)) ||
        extent.width < caps.minImageExtent.width || extent.height < caps.minImageExtent.height ||
        extent.width > caps.maxImageExtent.width || extent.height > caps.maxImageExtent.height)
        return fail("qualified_extent_required", -1);
    uint32_t format_count = 0;
    CHECK("surface_format_count", GetPhysicalDeviceSurfaceFormatsKHR(physical, vk_surface, &format_count, NULL));
    if (!format_count || format_count > 64) return fail("surface_format_budget", -1);
    VkSurfaceFormatKHR formats[64], selected = {0};
    CHECK("surface_formats", GetPhysicalDeviceSurfaceFormatsKHR(physical, vk_surface, &format_count, formats));
    bool found = false;
    for (uint32_t i = 0; i < format_count; i++)
        if (formats[i].format == VK_FORMAT_B8G8R8A8_UNORM && formats[i].colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {selected = formats[i]; found = true; break;}
    if (!found) return fail("qualified_surface_format_required", -1);
    uint32_t requested = caps.minImageCount > 3 ? caps.minImageCount : 3;
    if ((caps.maxImageCount && requested > caps.maxImageCount) || requested > 4) return fail("qualified_swapchain_count", -1);
    VkAttachmentDescription attachment = {.format = selected.format, .samples = VK_SAMPLE_COUNT_1_BIT,
        .loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR, .storeOp = VK_ATTACHMENT_STORE_OP_STORE,
        .stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE, .stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE,
        .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED, .finalLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR};
    VkAttachmentReference reference = {.attachment = 0, .layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL};
    VkSubpassDescription subpass = {.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS, .colorAttachmentCount = 1, .pColorAttachments = &reference};
    VkSubpassDependency dependency = {.srcSubpass = VK_SUBPASS_EXTERNAL, .dstSubpass = 0,
        .srcStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT, .dstStageMask = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT,
        .dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT};
    VkRenderPassCreateInfo pass_info = {.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO,
        .attachmentCount = 1, .pAttachments = &attachment, .subpassCount = 1, .pSubpasses = &subpass,
        .dependencyCount = 1, .pDependencies = &dependency};
    VkRenderPass pass;
    CHECK("create_render_pass", CreateRenderPass(device, &pass_info, NULL, &pass));
    VkCommandPoolCreateInfo pool_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT, .queueFamilyIndex = family};
    VkCommandPool pool;
    CHECK("create_pool", CreateCommandPool(device, &pool_info, NULL, &pool));
    VkCommandBufferAllocateInfo cmd_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = pool, .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1};
    VkCommandBuffer command;
    CHECK("allocate_command", AllocateCommandBuffers(device, &cmd_info, &command));
    VkSemaphoreCreateInfo sem_info = {.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
    VkSemaphore available;
    CHECK("create_available_semaphore", CreateSemaphore(device, &sem_info, NULL, &available));
    VkFenceCreateInfo fence_info = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, .flags = VK_FENCE_CREATE_SIGNALED_BIT};
    VkFence fence;
    CHECK("create_fence", CreateFence(device, &fence_info, NULL, &fence));
    VkFence present_fence = VK_NULL_HANDLE;
    if (lifecycle) CHECK("create_present_fence", CreateFence(device, &fence_info, NULL, &present_fence));
    VkQueue queue;
    GetDeviceQueue(device, family, 0, &queue);
    const uint8_t colors[3][3] = {{19,67,139},{203,37,91},{47,181,113}};
    struct native_chain previous = {0}, active = {0};
    const struct chain_destructors destroy = {DestroySemaphore, DestroyFramebuffer, DestroyImageView, DestroySwapchainKHR};
    unsigned generations = lifecycle ? 3 : 1, total_frames = 0;
    unsigned present_fences_completed = 0, maximum_live_images = 0, recreated = 0;
    for (unsigned generation = 0; generation < generations; generation++) {
        extent = lifecycle && generation == 1 ? (VkExtent2D){480,360} : (VkExtent2D){640,480};
        CHECK("generation_surface_capabilities", GetPhysicalDeviceSurfaceCapabilitiesKHR(physical, vk_surface, &caps));
        if (!(caps.supportedUsageFlags & VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT) ||
            !(caps.supportedCompositeAlpha & VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR) ||
            (caps.currentExtent.width != UINT32_MAX && (caps.currentExtent.width != extent.width || caps.currentExtent.height != extent.height)) ||
            extent.width < caps.minImageExtent.width || extent.height < caps.minImageExtent.height ||
            extent.width > caps.maxImageExtent.width || extent.height > caps.maxImageExtent.height)
            return fail("generation_extent_required", -1);
        requested = caps.minImageCount > 3 ? caps.minImageCount : 3;
        if ((caps.maxImageCount && requested > caps.maxImageCount) || requested > 4) return fail("qualified_swapchain_count", -1);
        VkSwapchainCreateInfoKHR swap_info = {.sType = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR,
            .surface = vk_surface, .minImageCount = requested, .imageFormat = selected.format, .imageColorSpace = selected.colorSpace,
            .imageExtent = extent, .imageArrayLayers = 1, .imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
            .imageSharingMode = VK_SHARING_MODE_EXCLUSIVE, .preTransform = caps.currentTransform,
            .compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR, .presentMode = VK_PRESENT_MODE_FIFO_KHR,
            .clipped = VK_TRUE, .oldSwapchain = previous.handle};
        CHECK("create_swapchain", CreateSwapchainKHR(device, &swap_info, NULL, &active.handle));
        CHECK("swapchain_image_count", GetSwapchainImagesKHR(device, active.handle, &active.count, NULL));
        if (!active.count || active.count > 4) return fail("swapchain_image_budget", -1);
        VkImage images[4];
        CHECK("swapchain_images", GetSwapchainImagesKHR(device, active.handle, &active.count, images));
        if (!active.count || active.count > 4) return fail("swapchain_image_budget", -1);
        unsigned live_images = previous.count + active.count;
        if (live_images > 8) return fail("overlap_image_budget", -1);
        if (live_images > maximum_live_images) maximum_live_images = live_images;
        for (uint32_t i = 0; i < active.count; i++) {
            VkImageViewCreateInfo view_info = {.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
                .image = images[i], .viewType = VK_IMAGE_VIEW_TYPE_2D, .format = selected.format,
                .subresourceRange = {.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT, .levelCount = 1, .layerCount = 1}};
            CHECK("create_view", CreateImageView(device, &view_info, NULL, &active.views[i]));
            VkFramebufferCreateInfo fb_info = {.sType = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO,
                .renderPass = pass, .attachmentCount = 1, .pAttachments = &active.views[i],
                .width = extent.width, .height = extent.height, .layers = 1};
            CHECK("create_framebuffer", CreateFramebuffer(device, &fb_info, NULL, &active.framebuffers[i]));
            /* Default mode uses per-image presentation semaphores. Lifecycle
             * mode additionally waits explicit presentation-engine fences. */
            CHECK("create_done_semaphore", CreateSemaphore(device, &sem_info, NULL, &active.done[i]));
        }
        if (lifecycle) {
            printf("GB_NATIVE_LIFECYCLE_PHASE:{\"generation\":%u,\"width\":%u,\"height\":%u,\"images\":%u,\"previous_images\":%u,\"live_image_upper_bound\":%u,\"old_swapchain_supplied\":%s,\"present_fences_required\":true}\n",
                generation, extent.width, extent.height, active.count, previous.count, live_images, previous.handle ? "true" : "false");
            fflush(stdout);
        }
        if (previous.handle) {
            CHECK("retire_previous_idle", DeviceWaitIdle(device));
            destroy_chain(device, &previous, &destroy);recreated++;
            printf("GB_NATIVE_LIFECYCLE_RETIRED:{\"generation\":%u,\"remaining_image_upper_bound\":%u,\"present_fences_completed\":%u}\n",
                generation - 1, active.count, present_fences_completed);fflush(stdout);
        }
        unsigned frame_count = lifecycle ? 30 : 90;
        for (unsigned frame = 0; frame < frame_count; frame++) {
            if (w.closed || wl_display_dispatch_pending(w.display) < 0) return fail("owned_window_closed", -1);
            CHECK("wait_previous_frame", WaitForFences(device, 1, &fence, VK_TRUE, 2000000000ULL));
            CHECK("reset_fence", ResetFences(device, 1, &fence));
            uint32_t index = 0;
            VkResult acquired = AcquireNextImageKHR(device, active.handle, 2000000000ULL, available, VK_NULL_HANDLE, &index);
            if ((acquired != VK_SUCCESS && acquired != VK_SUBOPTIMAL_KHR) || index >= active.count) return fail("acquire_image", acquired);
            CHECK("reset_command", ResetCommandBuffer(command, 0));
            VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
            CHECK("begin_command", BeginCommandBuffer(command, &begin));
            unsigned phase = lifecycle ? generation : frame / 30;
            VkClearValue clear = {.color.float32 = {colors[phase][0]/255.0f, colors[phase][1]/255.0f, colors[phase][2]/255.0f, 1.0f}};
            VkRenderPassBeginInfo render_begin = {.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO,
                .renderPass = pass, .framebuffer = active.framebuffers[index], .renderArea = {.extent = extent}, .clearValueCount = 1, .pClearValues = &clear};
            CmdBeginRenderPass(command, &render_begin, VK_SUBPASS_CONTENTS_INLINE); CmdEndRenderPass(command);
            CHECK("end_command", EndCommandBuffer(command));
            VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
            VkSubmitInfo submit = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .waitSemaphoreCount = 1,
                .pWaitSemaphores = &available, .pWaitDstStageMask = &wait_stage, .commandBufferCount = 1,
                .pCommandBuffers = &command, .signalSemaphoreCount = 1, .pSignalSemaphores = &active.done[index]};
            CHECK("submit_frame", QueueSubmit(queue, 1, &submit, fence));
            CHECK("frame_fence", WaitForFences(device, 1, &fence, VK_TRUE, 2000000000ULL));
            VkSwapchainPresentFenceInfoEXT present_completion = {
                .sType = VK_STRUCTURE_TYPE_SWAPCHAIN_PRESENT_FENCE_INFO_EXT, .swapchainCount = 1, .pFences = &present_fence};
            if (lifecycle) CHECK("reset_present_fence", ResetFences(device, 1, &present_fence));
            VkPresentInfoKHR present = {.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR,
                .pNext = lifecycle ? &present_completion : NULL,
                .waitSemaphoreCount = 1, .pWaitSemaphores = &active.done[index], .swapchainCount = 1, .pSwapchains = &active.handle, .pImageIndices = &index};
            VkResult presented = QueuePresentKHR(queue, &present);
            if (presented != VK_SUCCESS && presented != VK_SUBOPTIMAL_KHR) return fail("present_frame", presented);
            if (lifecycle) {
                CHECK("present_fence", WaitForFences(device, 1, &present_fence, VK_TRUE, 2000000000ULL));
                present_fences_completed++;
            }
            total_frames++;
            if (frame % 30 == 5) {printf("GB_NATIVE_CLEAR_PHASE:%u\n", phase); fflush(stdout);}
            struct timespec pause = {.tv_nsec = 100000000}; nanosleep(&pause, NULL);
        }
        if (lifecycle) {
            printf("GB_NATIVE_LIFECYCLE_COMPLETED:{\"generation\":%u,\"frames_completed\":%u,\"present_fences_completed\":%u,\"presentation_verified\":false}\n",
                generation, frame_count, present_fences_completed);fflush(stdout);
        }
        previous = active;memset(&active, 0, sizeof(active));
    }
    CHECK("device_idle", DeviceWaitIdle(device));
    DestroySemaphore(device, available, NULL);
    if (lifecycle) DestroyFence(device, present_fence, NULL);
    DestroyFence(device, fence, NULL);
    DestroyCommandPool(device, pool, NULL);
    destroy_chain(device, &previous, &destroy);
    DestroyRenderPass(device, pass, NULL); DestroyDevice(device, NULL);
    DestroySurfaceKHR(instance, vk_surface, NULL); DestroyInstance(instance, NULL); dlclose(library);
    xdg_toplevel_destroy(top); xdg_surface_destroy(xdg); wl_surface_destroy(surface);
    xdg_wm_base_destroy(w.wm); wl_compositor_destroy(w.compositor); wl_registry_destroy(registry); wl_display_disconnect(w.display);
    if (lifecycle)
        printf("{\"schema_version\":1,\"status\":\"native_swapchain_lifecycle_api_completed\",\"frames\":%u,\"color_phases\":3,\"generations\":3,\"recreations\":%u,\"maximum_live_image_upper_bound\":%u,\"present_fences_completed\":%u,\"presentation_verified\":false,\"full_port_verified\":false}\n",
            total_frames, recreated, maximum_live_images, present_fences_completed);
    else puts("{\"schema_version\":1,\"status\":\"native_swapchain_api_completed\",\"frames\":90,\"color_phases\":3,\"presentation_verified\":false,\"full_port_verified\":false}");
    return 0;
}
