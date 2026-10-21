/* SPDX-License-Identifier: Apache-2.0
 * Owner diagnostic: load one explicit Android Vulkan HAL privately. No global
 * driver selection, UUID collection, queue submission, or firmware changes.
 * Exit 0 means enumeration only, never rendering or guest interoperability.
 */
#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>
#include <hardware/hwvulkan.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void json_string(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static int fail(const char *stage, int code) {
    printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":");
    json_string(stage);
    printf(",\"code\":%d,\"guest_vulkan_verified\":false}\n", code);
    return 1;
}
int main(int argc, char **argv) {
    alarm(20);
    if (argc != 2 || argv[1][0] != '/') return fail("explicit_absolute_driver_required", -1);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        const char *error = dlerror();
        fprintf(stderr, "GB_PRIVATE_VK_DLOPEN: %s\n", error ? error : "unknown");
        return fail("dlopen", -1);
    }
    hw_module_t *module = (hw_module_t *)dlsym(library, HAL_MODULE_INFO_SYM_AS_STR);
    if (!module || !module->id || strcmp(module->id, "vulkan") ||
        !module->methods || !module->methods->open) return fail("vulkan_hal", -1);
    hw_device_t *common = NULL;
    int status = module->methods->open(module, HWVULKAN_DEVICE_0, &common);
    if (status || !common) return fail("hal_open", status);
    hwvulkan_device_t *hal = (hwvulkan_device_t *)common;
    PFN_vkGetInstanceProcAddr get = hal->GetInstanceProcAddr;
    if (!get) return fail("get_instance_proc_addr", -1);
    PFN_vkCreateInstance create = (PFN_vkCreateInstance)get(VK_NULL_HANDLE, "vkCreateInstance");
    if (!create) return fail("create_entrypoint", -1);
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "gb-private-vulkan-enumeration", .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo info = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app};
    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = create(&info, NULL, &instance);
    if (result != VK_SUCCESS) return fail("create_instance", result);
    PFN_vkEnumeratePhysicalDevices enumerate = (PFN_vkEnumeratePhysicalDevices)get(instance, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties properties = (PFN_vkGetPhysicalDeviceProperties)get(instance, "vkGetPhysicalDeviceProperties");
    PFN_vkEnumerateDeviceExtensionProperties extensions = (PFN_vkEnumerateDeviceExtensionProperties)get(instance, "vkEnumerateDeviceExtensionProperties");
    PFN_vkDestroyInstance destroy = (PFN_vkDestroyInstance)get(instance, "vkDestroyInstance");
    if (!enumerate || !properties || !extensions || !destroy) return fail("instance_entrypoints", -1);
    uint32_t count = 0;
    result = enumerate(instance, &count, NULL);
    if (result != VK_SUCCESS || !count || count > 8) return fail("device_count", result);
    VkPhysicalDevice devices[8];
    result = enumerate(instance, &count, devices);
    if (result != VK_SUCCESS || !count || count > 8) return fail("device_enumeration", result);
    /* Use stdout only once all enumeration calls have succeeded. */
    VkPhysicalDeviceProperties props[8];
    VkExtensionProperties *exts[8] = {0};
    uint32_t lengths[8] = {0};
    for (uint32_t i = 0; i < count; ++i) {
        properties(devices[i], &props[i]);
        result = extensions(devices[i], NULL, &lengths[i], NULL);
        if (result != VK_SUCCESS || lengths[i] > 2048) return fail("extension_count", result);
        exts[i] = calloc(lengths[i] ? lengths[i] : 1, sizeof(**exts));
        if (!exts[i]) return fail("extension_allocation", -1);
        result = extensions(devices[i], NULL, &lengths[i], exts[i]);
        if (result != VK_SUCCESS || lengths[i] > 2048) return fail("extension_enumeration", result);
    }
    printf("{\"devices\":[");
    for (uint32_t i = 0; i < count; ++i) {
        if (i) putchar(',');
        printf("{\"properties\":{\"apiVersion\":%u,\"driverVersion\":%u,\"vendorID\":%u,\"deviceID\":%u,\"deviceType\":%u,\"deviceName\":",
               props[i].apiVersion, props[i].driverVersion, props[i].vendorID, props[i].deviceID, props[i].deviceType);
        props[i].deviceName[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE - 1] = 0;
        json_string(props[i].deviceName);
        printf("},\"extensions\":[");
        for (uint32_t j = 0; j < lengths[i]; ++j) {
            if (j) putchar(',');
            printf("{\"extensionName\":");
            exts[i][j].extensionName[VK_MAX_EXTENSION_NAME_SIZE - 1] = 0;
            json_string(exts[i][j].extensionName);
            putchar('}');
        }
        printf("]}");
        free(exts[i]);
    }
    printf("],\"scope\":\"private HAL enumeration only; no rendering, memory sharing or VMM namespace validation\"}\n");
    destroy(instance, NULL);
    if (common->close) common->close(common);
    dlclose(library);
    return 0;
}
