/* SPDX-License-Identifier: Apache-2.0
 * Bounded private Vulkan -> Android hardware buffer -> stock GLES diagnostic.
 * Only generated pixels, no CPU AHB mapping, owner content, VM access or writes
 * to installed drivers. A pass covers this allocation, not guest integration.
 */
#define _GNU_SOURCE
#define VK_NO_PROTOTYPES
#define VK_USE_PLATFORM_ANDROID_KHR
#include <android/hardware_buffer.h>
#include <vulkan/vulkan.h>
#include <hardware/hwvulkan.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/udmabuf.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <limits.h>

enum { SIDE = 32, PIXELS = SIDE * SIDE };
static const char *failed_stage;
static int failed_code;
static bool fail(const char *stage, int code) { failed_stage = stage; failed_code = code; return false; }
/* A diagnostic launched before the VMM must not retain AVF's inherited FDs or
 * capabilities. Read only this process's domain, never the parent's argv/FDs. */
static bool isolate_owned_probe(void) {
    if(close_range(3,UINT_MAX,0))return fail("close_inherited_descriptors",errno);
    struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    if(syscall(SYS_capset,&header,caps))return fail("drop_capabilities",errno);
    if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return fail("no_new_privileges",errno);
    FILE *file=fopen("/proc/self/attr/current","re");if(!file)return fail("own_context",errno);
    char context[256];size_t n=fread(context,1,sizeof(context)-1,file);bool bad=ferror(file)||!feof(file);fclose(file);context[n]=0;
    if(bad || strncmp(context,"u:r:",4))return fail("own_context_shape",-1);
    char *end=strchr(context+4,':');if(!end || end==context+4 || end-(context+4)>96)return fail("own_context_domain",-1);
    *end=0;for(const char *c=context+4;*c;c++)if(!((*c>='a' && *c<='z') || (*c>='0' && *c<='9') || *c=='_'))return fail("own_context_domain",-1);
    fprintf(stderr,"GB_AHB_CONTEXT uid=%u domain=%s fds_closed=1 caps_dropped=1 no_new_privs=1\n",(unsigned)getuid(),context+4);
    return true;
}
#define REQUIRE(ok, stage) do { if (!(ok)) return fail(stage, -1); } while (0)
#define VK_CHECK(stage, call) do { fprintf(stderr, "GB_AHB_STAGE:%s\n", stage); VkResult rc = (call); if (rc != VK_SUCCESS) return fail(stage, rc); } while (0)
#define LOAD_I(name) v->name = (PFN_vk##name)v->get(v->instance, "vk" #name); REQUIRE(v->name, "entrypoint_" #name)
#define LOAD_D(name) v->name = (PFN_vk##name)v->GetDeviceProcAddr(v->device, "vk" #name); REQUIRE(v->name, "entrypoint_" #name)
static bool has(const char *s, const char *name) {
    size_t n = strlen(name);
    for (const char *p = s; p && *p;) {
        const char *e = strchr(p, ' '); size_t length = e ? (size_t)(e-p) : strlen(p);
        if (length == n && !memcmp(p, name, n)) return true;
        if (!e) break; p = e+1;
    }
    return false;
}
struct vk_state {
    void *library; hw_device_t *hal;
    PFN_vkGetInstanceProcAddr get; PFN_vkGetDeviceProcAddr GetDeviceProcAddr;
    VkInstance instance; VkPhysicalDevice physical; VkDevice device;
    VkImage source_image, export_image; VkDeviceMemory source_memory, export_memory; int source_fd;
    VkDeviceSize source_bytes, source_stride; bool copy_mode, exported_mode;
    VkFormat source_format; /* Zero selects the original RGBA control. */
    PFN_vkGetMemoryFdKHR GetMemoryFdKHR;
    PFN_vkGetImageMemoryRequirements GetImageMemoryRequirements;
    PFN_vkGetMemoryFdPropertiesKHR GetMemoryFdPropertiesKHR;
    PFN_vkGetImageSubresourceLayout GetImageSubresourceLayout;
    PFN_vkCmdCopyImage CmdCopyImage;
    VkImage image; VkDeviceMemory memory; VkCommandPool pool; VkCommandBuffer command;
    VkQueue queue; VkFence fence; uint32_t family; uint64_t allocation_size, ahb_usage;
    PFN_vkEnumeratePhysicalDevices EnumeratePhysicalDevices;
    PFN_vkGetPhysicalDeviceProperties GetPhysicalDeviceProperties;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties GetPhysicalDeviceQueueFamilyProperties;
    PFN_vkGetPhysicalDeviceMemoryProperties GetPhysicalDeviceMemoryProperties;
    PFN_vkGetPhysicalDeviceImageFormatProperties2 GetPhysicalDeviceImageFormatProperties2;
    PFN_vkCreateDevice CreateDevice; PFN_vkDestroyInstance DestroyInstance;
    PFN_vkGetAndroidHardwareBufferPropertiesANDROID GetAndroidHardwareBufferPropertiesANDROID;
    PFN_vkCreateImage CreateImage; PFN_vkAllocateMemory AllocateMemory; PFN_vkBindImageMemory BindImageMemory;
    PFN_vkCreateCommandPool CreateCommandPool; PFN_vkAllocateCommandBuffers AllocateCommandBuffers;
    PFN_vkBeginCommandBuffer BeginCommandBuffer; PFN_vkEndCommandBuffer EndCommandBuffer;
    PFN_vkCmdPipelineBarrier CmdPipelineBarrier; PFN_vkCmdClearColorImage CmdClearColorImage;
    PFN_vkCreateFence CreateFence; PFN_vkGetFenceStatus GetFenceStatus; PFN_vkResetFences ResetFences;
    PFN_vkResetCommandBuffer ResetCommandBuffer; PFN_vkQueueSubmit QueueSubmit;
    PFN_vkWaitForFences WaitForFences; PFN_vkGetDeviceQueue GetDeviceQueue;
    PFN_vkDestroyFence DestroyFence; PFN_vkDestroyCommandPool DestroyCommandPool;
    PFN_vkDestroyImage DestroyImage; PFN_vkFreeMemory FreeMemory; PFN_vkDestroyDevice DestroyDevice;
};
static const VkImageUsageFlags image_usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT |
    VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
static bool vk_init(struct vk_state *v, const char *path) {
    v->library = dlopen(path, RTLD_NOW | RTLD_LOCAL); REQUIRE(v->library, "private_hal_load");
    hw_module_t *module = (hw_module_t *)dlsym(v->library, HAL_MODULE_INFO_SYM_AS_STR);
    REQUIRE(module && module->id && !strcmp(module->id,"vulkan") && module->methods && module->methods->open, "private_hal_module");
    REQUIRE(!module->methods->open(module, HWVULKAN_DEVICE_0, &v->hal) && v->hal, "private_hal_open");
    v->get = ((hwvulkan_device_t *)v->hal)->GetInstanceProcAddr; REQUIRE(v->get, "private_hal_proc");
    PFN_vkCreateInstance create = (PFN_vkCreateInstance)v->get(VK_NULL_HANDLE, "vkCreateInstance"); REQUIRE(create, "create_instance_entrypoint");
    VkApplicationInfo app = {.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,.pApplicationName="gb-ahb-vulkan-gles",.apiVersion=VK_API_VERSION_1_1};
    VkInstanceCreateInfo instance_info = {.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,.pApplicationInfo=&app};
    VK_CHECK("instance",create(&instance_info,NULL,&v->instance));
    LOAD_I(DestroyInstance); LOAD_I(EnumeratePhysicalDevices); LOAD_I(GetPhysicalDeviceProperties);
    LOAD_I(GetPhysicalDeviceQueueFamilyProperties); LOAD_I(GetPhysicalDeviceMemoryProperties);
    LOAD_I(GetPhysicalDeviceImageFormatProperties2); LOAD_I(GetDeviceProcAddr); LOAD_I(CreateDevice);
    uint32_t count=0; VK_CHECK("physical_count",v->EnumeratePhysicalDevices(v->instance,&count,NULL)); REQUIRE(count==1,"one_physical_gpu_required");
    VK_CHECK("physical",v->EnumeratePhysicalDevices(v->instance,&count,&v->physical));
    VkPhysicalDeviceProperties props; v->GetPhysicalDeviceProperties(v->physical,&props); props.deviceName[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE-1]=0;
    REQUIRE(props.vendorID==0x5143 && strstr(props.deviceName,"Turnip") && strstr(props.deviceName,"Adreno"),"private_turnip_adreno_required");
    uint32_t families=0; v->GetPhysicalDeviceQueueFamilyProperties(v->physical,&families,NULL); REQUIRE(families && families<=32,"queue_count");
    VkQueueFamilyProperties queues[32]; v->GetPhysicalDeviceQueueFamilyProperties(v->physical,&families,queues); v->family=families;
    for(uint32_t i=0;i<families;i++) if(queues[i].queueCount && (queues[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)){v->family=i;break;}
    REQUIRE(v->family<families,"graphics_queue"); float priority=1;
    VkDeviceQueueCreateInfo queue={.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,.queueFamilyIndex=v->family,.queueCount=1,.pQueuePriorities=&priority};
    const char *extensions[]={VK_ANDROID_EXTERNAL_MEMORY_ANDROID_HARDWARE_BUFFER_EXTENSION_NAME,VK_EXT_QUEUE_FAMILY_FOREIGN_EXTENSION_NAME,VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME,VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME,VK_EXT_IMAGE_DRM_FORMAT_MODIFIER_EXTENSION_NAME};
    VkDeviceCreateInfo device_info={.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,.queueCreateInfoCount=1,.pQueueCreateInfos=&queue,.enabledExtensionCount=v->copy_mode?5:2,.ppEnabledExtensionNames=extensions};
    VK_CHECK("device",v->CreateDevice(v->physical,&device_info,NULL,&v->device));
    LOAD_D(DestroyDevice); LOAD_D(DestroyImage); LOAD_D(FreeMemory); LOAD_D(DestroyCommandPool); LOAD_D(DestroyFence);
    LOAD_D(GetAndroidHardwareBufferPropertiesANDROID); LOAD_D(CreateImage); LOAD_D(AllocateMemory); LOAD_D(BindImageMemory);
    LOAD_D(CreateCommandPool); LOAD_D(AllocateCommandBuffers); LOAD_D(BeginCommandBuffer); LOAD_D(EndCommandBuffer);
    LOAD_D(CmdPipelineBarrier); LOAD_D(CmdClearColorImage); LOAD_D(CreateFence); LOAD_D(GetFenceStatus);
    LOAD_D(ResetFences); LOAD_D(ResetCommandBuffer); LOAD_D(QueueSubmit); LOAD_D(WaitForFences); LOAD_D(GetDeviceQueue);
    if(v->copy_mode){LOAD_D(GetImageMemoryRequirements);LOAD_D(GetMemoryFdPropertiesKHR);LOAD_D(GetImageSubresourceLayout);LOAD_D(CmdCopyImage);}
    if(v->exported_mode){LOAD_D(GetMemoryFdKHR);}
    VkPhysicalDeviceExternalImageFormatInfo external={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID};
    VkPhysicalDeviceImageFormatInfo2 query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_FORMAT_INFO_2,.pNext=&external,.format=VK_FORMAT_R8G8B8A8_UNORM,.type=VK_IMAGE_TYPE_2D,.tiling=VK_IMAGE_TILING_OPTIMAL,.usage=image_usage};
    VkAndroidHardwareBufferUsageANDROID usage={.sType=VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_USAGE_ANDROID};
    VkExternalImageFormatProperties external_props={.sType=VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES,.pNext=&usage};
    VkImageFormatProperties2 result={.sType=VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2,.pNext=&external_props};
    VK_CHECK("ahb_image_format",v->GetPhysicalDeviceImageFormatProperties2(v->physical,&query,&result));
    REQUIRE(external_props.externalMemoryProperties.externalMemoryFeatures&VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT,"ahb_image_importable");
    REQUIRE(result.imageFormatProperties.maxExtent.width>=SIDE && result.imageFormatProperties.maxExtent.height>=SIDE,"ahb_extent");
    v->ahb_usage=usage.androidHardwareBufferUsage|AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE|AHARDWAREBUFFER_USAGE_GPU_FRAMEBUFFER;
    REQUIRE(!(v->ahb_usage&AHARDWAREBUFFER_USAGE_PROTECTED_CONTENT),"unprotected_ahb_required");
    v->GetDeviceQueue(v->device,v->family,0,&v->queue); return true;
}
static bool vk_import_ahb(struct vk_state *v, AHardwareBuffer *buffer) {
    VkAndroidHardwareBufferFormatPropertiesANDROID format={.sType=VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_FORMAT_PROPERTIES_ANDROID};
    VkAndroidHardwareBufferPropertiesANDROID props={.sType=VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_PROPERTIES_ANDROID,.pNext=&format};
    VK_CHECK("ahb_properties",v->GetAndroidHardwareBufferPropertiesANDROID(v->device,buffer,&props));
    REQUIRE(format.format==VK_FORMAT_R8G8B8A8_UNORM && props.allocationSize && props.allocationSize<=1024*1024,"ahb_format_and_budget");
    v->allocation_size=props.allocationSize;
    VkExternalMemoryImageCreateInfo external={.sType=VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO,.handleTypes=VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID};
    VkImageCreateInfo image={.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,.pNext=&external,.imageType=VK_IMAGE_TYPE_2D,.format=VK_FORMAT_R8G8B8A8_UNORM,.extent={SIDE,SIDE,1},.mipLevels=1,.arrayLayers=1,.samples=VK_SAMPLE_COUNT_1_BIT,.tiling=VK_IMAGE_TILING_OPTIMAL,.usage=image_usage,.sharingMode=VK_SHARING_MODE_EXCLUSIVE,.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED};
    VK_CHECK("ahb_image",v->CreateImage(v->device,&image,NULL,&v->image));
    VkPhysicalDeviceMemoryProperties memory; v->GetPhysicalDeviceMemoryProperties(v->physical,&memory); REQUIRE(memory.memoryTypeCount && memory.memoryTypeCount<=32,"memory_type_count");
    uint32_t type=memory.memoryTypeCount;
    for(uint32_t i=0;i<memory.memoryTypeCount;i++) if((props.memoryTypeBits&(1u<<i)) && !(memory.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_PROTECTED_BIT)){type=i;break;}
    REQUIRE(type<memory.memoryTypeCount,"ahb_memory_type");
    VkImportAndroidHardwareBufferInfoANDROID import={.sType=VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID,.buffer=buffer};
    VkMemoryDedicatedAllocateInfo dedicated={.sType=VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO,.pNext=&import,.image=v->image};
    VkMemoryAllocateInfo allocation={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,.pNext=&dedicated,.allocationSize=props.allocationSize,.memoryTypeIndex=type};
    VK_CHECK("ahb_memory",v->AllocateMemory(v->device,&allocation,NULL,&v->memory));
    VK_CHECK("ahb_bind",v->BindImageMemory(v->device,v->image,v->memory,0));
    VkCommandPoolCreateInfo pool={.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,.flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,.queueFamilyIndex=v->family};
    VK_CHECK("command_pool",v->CreateCommandPool(v->device,&pool,NULL,&v->pool));
    VkCommandBufferAllocateInfo command={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,.commandPool=v->pool,.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,.commandBufferCount=1};
    VK_CHECK("command",v->AllocateCommandBuffers(v->device,&command,&v->command));
    VkFenceCreateInfo fence={.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO}; VK_CHECK("fence",v->CreateFence(v->device,&fence,NULL,&v->fence));
    return true;
}
/* This control uses a genuine Vulkan-exported DMA-BUF, not an opaque FD or
 * UDMABUF. It proves a separate source-allocation route, not guest memory. */
static bool vk_export_source(struct vk_state *v, const VkImageCreateInfo *image) {
    VK_CHECK("export_source_image",v->CreateImage(v->device,image,NULL,&v->export_image));
    VkMemoryRequirements req;v->GetImageMemoryRequirements(v->device,v->export_image,&req);
    REQUIRE(req.size && req.size<=v->source_bytes,"export_source_budget");
    VkPhysicalDeviceMemoryProperties memory;v->GetPhysicalDeviceMemoryProperties(v->physical,&memory);
    REQUIRE(memory.memoryTypeCount && memory.memoryTypeCount<=32,"export_memory_type_count");
    uint32_t type=memory.memoryTypeCount;
    for(uint32_t i=0;i<memory.memoryTypeCount;i++)if((req.memoryTypeBits&(1u<<i)) && !(memory.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_PROTECTED_BIT)){type=i;break;}
    REQUIRE(type<memory.memoryTypeCount,"export_source_memory_type");
    VkExportMemoryAllocateInfo export={.sType=VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO,.handleTypes=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkMemoryDedicatedAllocateInfo dedicated={.sType=VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO,.pNext=&export,.image=v->export_image};
    VkMemoryAllocateInfo allocation={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,.pNext=&dedicated,.allocationSize=v->source_bytes,.memoryTypeIndex=type};
    VK_CHECK("export_source_memory",v->AllocateMemory(v->device,&allocation,NULL,&v->export_memory));
    VK_CHECK("export_source_bind",v->BindImageMemory(v->device,v->export_image,v->export_memory,0));
    VkMemoryGetFdInfoKHR info={.sType=VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR,.memory=v->export_memory,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VK_CHECK("export_source_fd",v->GetMemoryFdKHR(v->device,&info,&v->source_fd));
    off_t bytes=lseek(v->source_fd,0,SEEK_END);
    REQUIRE(bytes>0 && (uint64_t)bytes>=v->source_bytes && bytes<=1024*1024,"export_source_fd_size");
    REQUIRE(lseek(v->source_fd,0,SEEK_SET)==0,"export_source_fd_rewind");
    return true;
}
static bool vk_source_dmabuf(struct vk_state *v) {
    const VkFormat source_format=v->source_format?v->source_format:VK_FORMAT_R8G8B8A8_UNORM;
    VkPhysicalDeviceImageDrmFormatModifierInfoEXT modifier_query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_DRM_FORMAT_MODIFIER_INFO_EXT,.drmFormatModifier=0,.sharingMode=VK_SHARING_MODE_EXCLUSIVE};
    VkPhysicalDeviceExternalImageFormatInfo external_query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO,.pNext=&modifier_query,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    const VkImageUsageFlags usage=VK_IMAGE_USAGE_TRANSFER_SRC_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    VkPhysicalDeviceImageFormatInfo2 query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_FORMAT_INFO_2,.pNext=&external_query,.format=source_format,.type=VK_IMAGE_TYPE_2D,.tiling=VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT,.usage=usage};
    VkExternalImageFormatProperties external_props={.sType=VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES};
    VkImageFormatProperties2 result={.sType=VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2,.pNext=&external_props};
    VK_CHECK("udmabuf_image_format",v->GetPhysicalDeviceImageFormatProperties2(v->physical,&query,&result));
    REQUIRE(external_props.externalMemoryProperties.externalMemoryFeatures&VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT,"linear_dma_image_importable");
    if(v->exported_mode)REQUIRE(external_props.externalMemoryProperties.externalMemoryFeatures&VK_EXTERNAL_MEMORY_FEATURE_EXPORTABLE_BIT,"linear_dma_image_exportable");
    const uint64_t modifier=0;
    VkImageDrmFormatModifierListCreateInfoEXT list={.sType=VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_LIST_CREATE_INFO_EXT,.drmFormatModifierCount=1,.pDrmFormatModifiers=&modifier};
    VkExternalMemoryImageCreateInfo external={.sType=VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO,.pNext=&list,.handleTypes=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkImageCreateInfo image={.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,.pNext=&external,.imageType=VK_IMAGE_TYPE_2D,.format=source_format,.extent={SIDE,SIDE,1},.mipLevels=1,.arrayLayers=1,.samples=VK_SAMPLE_COUNT_1_BIT,.tiling=VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT,.usage=usage,.sharingMode=VK_SHARING_MODE_EXCLUSIVE,.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED};
    VK_CHECK("udmabuf_image",v->CreateImage(v->device,&image,NULL,&v->source_image));
    VkMemoryRequirements req;v->GetImageMemoryRequirements(v->device,v->source_image,&req);
    long page=sysconf(_SC_PAGESIZE);REQUIRE(page>0 && page<=65536 && req.size && req.size<=1024*1024,"udmabuf_allocation_budget");
    v->source_bytes=(req.size+(VkDeviceSize)page-1)/(VkDeviceSize)page*(VkDeviceSize)page;
    if(v->exported_mode){if(!vk_export_source(v,&image))return false;}
    else {
    int mem=memfd_create("gb-owned-image-udmabuf",MFD_CLOEXEC|MFD_ALLOW_SEALING);if(mem<0)return fail("source_memfd",errno);
    if(ftruncate(mem,(off_t)v->source_bytes) || fcntl(mem,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW)){int err=errno;close(mem);return fail("source_memfd_size_seals",err);}
    int dev=open("/dev/udmabuf",O_RDWR|O_CLOEXEC);if(dev<0){int err=errno;close(mem);return fail("udmabuf_open",err);}
    struct udmabuf_create create={.memfd=(uint32_t)mem,.flags=UDMABUF_FLAGS_CLOEXEC,.offset=0,.size=v->source_bytes};
    v->source_fd=ioctl(dev,UDMABUF_CREATE,&create);int saved=errno;close(dev);close(mem);if(v->source_fd<0)return fail("source_udmabuf_create",saved);
    }
    VkMemoryFdPropertiesKHR fd={.sType=VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR};
    VK_CHECK("source_udmabuf_properties",v->GetMemoryFdPropertiesKHR(v->device,VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,v->source_fd,&fd));
    VkPhysicalDeviceMemoryProperties memory;v->GetPhysicalDeviceMemoryProperties(v->physical,&memory);REQUIRE(memory.memoryTypeCount && memory.memoryTypeCount<=32,"source_memory_type_count");
    uint32_t type=memory.memoryTypeCount;
    for(uint32_t i=0;i<memory.memoryTypeCount;i++)if((req.memoryTypeBits&fd.memoryTypeBits&(1u<<i)) && !(memory.memoryTypes[i].propertyFlags&VK_MEMORY_PROPERTY_PROTECTED_BIT)){type=i;break;}
    REQUIRE(type<memory.memoryTypeCount,"source_fd_memory_type");
    VkImportMemoryFdInfoKHR import={.sType=VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,.fd=v->source_fd};
    VkMemoryDedicatedAllocateInfo dedicated={.sType=VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO,.pNext=&import,.image=v->source_image};
    VkMemoryAllocateInfo allocation={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,.pNext=&dedicated,.allocationSize=v->source_bytes,.memoryTypeIndex=type};
    VK_CHECK("source_import_udmabuf",v->AllocateMemory(v->device,&allocation,NULL,&v->source_memory));v->source_fd=-1;
    VK_CHECK("source_bind",v->BindImageMemory(v->device,v->source_image,v->source_memory,0));
    VkImageSubresource subresource={.aspectMask=VK_IMAGE_ASPECT_MEMORY_PLANE_0_BIT_EXT};VkSubresourceLayout layout;
    v->GetImageSubresourceLayout(v->device,v->source_image,&subresource,&layout);
    REQUIRE(layout.offset==0 && layout.rowPitch>=SIDE*4 && layout.rowPitch<=65536 && layout.offset+(SIDE-1)*layout.rowPitch+SIDE*4<=v->source_bytes,"source_plane_layout");
    v->source_stride=layout.rowPitch;return true;
}
static bool vk_copy_clear(struct vk_state *v,const uint8_t rgba[4],bool reuse) {
    if(reuse){VK_CHECK("copy_reset_fence",v->ResetFences(v->device,1,&v->fence));VK_CHECK("copy_reset_command",v->ResetCommandBuffer(v->command,0));}
    REQUIRE(v->GetFenceStatus(v->device,v->fence)==VK_NOT_READY,"copy_unsignalled_fence");
    VkCommandBufferBeginInfo begin={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};VK_CHECK("copy_begin",v->BeginCommandBuffer(v->command,&begin));
    VkImageSubresourceRange range={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.levelCount=1,.layerCount=1};
    VkImageMemoryBarrier barriers[2];
    for(unsigned i=0;i<2;i++)barriers[i]=(VkImageMemoryBarrier){.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,.oldLayout=reuse?VK_IMAGE_LAYOUT_GENERAL:VK_IMAGE_LAYOUT_UNDEFINED,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,.srcQueueFamilyIndex=reuse?VK_QUEUE_FAMILY_FOREIGN_EXT:VK_QUEUE_FAMILY_IGNORED,.dstQueueFamilyIndex=reuse?v->family:VK_QUEUE_FAMILY_IGNORED,.image=i?v->image:v->source_image,.subresourceRange=range};
    v->CmdPipelineBarrier(v->command,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,NULL,0,NULL,2,barriers);
    VkClearColorValue color;for(unsigned i=0;i<4;i++)color.float32[i]=rgba[i]/255.0f;
    v->CmdClearColorImage(v->command,v->source_image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&color,1,&range);
    barriers[0].srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;barriers[0].dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT;barriers[0].oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;barriers[0].newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;barriers[0].srcQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;barriers[0].dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    v->CmdPipelineBarrier(v->command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,NULL,0,NULL,1,barriers);
    VkImageCopy region={.srcSubresource={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.layerCount=1},.dstSubresource={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.layerCount=1},.extent={SIDE,SIDE,1}};
    v->CmdCopyImage(v->command,v->source_image,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,v->image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&region);
    for(unsigned i=0;i<2;i++){barriers[i].srcAccessMask=i?VK_ACCESS_TRANSFER_WRITE_BIT:VK_ACCESS_TRANSFER_READ_BIT;barriers[i].dstAccessMask=0;barriers[i].oldLayout=i?VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL:VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;barriers[i].newLayout=VK_IMAGE_LAYOUT_GENERAL;barriers[i].srcQueueFamilyIndex=v->family;barriers[i].dstQueueFamilyIndex=VK_QUEUE_FAMILY_FOREIGN_EXT;}
    v->CmdPipelineBarrier(v->command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,0,0,NULL,0,NULL,2,barriers);
    VK_CHECK("copy_end",v->EndCommandBuffer(v->command));VkSubmitInfo submit={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,.commandBufferCount=1,.pCommandBuffers=&v->command};
    VK_CHECK("copy_submit",v->QueueSubmit(v->queue,1,&submit,v->fence));VK_CHECK("copy_wait",v->WaitForFences(v->device,1,&v->fence,VK_TRUE,2000000000ull));VK_CHECK("copy_signalled",v->GetFenceStatus(v->device,v->fence));return true;
}
static bool vk_clear(struct vk_state *v, const uint8_t rgba[4], bool reuse) {
    if(reuse){VK_CHECK("reset_fence",v->ResetFences(v->device,1,&v->fence));VK_CHECK("reset_command",v->ResetCommandBuffer(v->command,0));}
    REQUIRE(v->GetFenceStatus(v->device,v->fence)==VK_NOT_READY,"unsignalled_fence");
    VkCommandBufferBeginInfo begin={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT}; VK_CHECK("begin",v->BeginCommandBuffer(v->command,&begin));
    VkImageSubresourceRange range={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.levelCount=1,.layerCount=1};
    VkImageMemoryBarrier barrier={.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,.oldLayout=reuse?VK_IMAGE_LAYOUT_GENERAL:VK_IMAGE_LAYOUT_UNDEFINED,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,.srcQueueFamilyIndex=reuse?VK_QUEUE_FAMILY_FOREIGN_EXT:VK_QUEUE_FAMILY_IGNORED,.dstQueueFamilyIndex=reuse?v->family:VK_QUEUE_FAMILY_IGNORED,.image=v->image,.subresourceRange=range};
    v->CmdPipelineBarrier(v->command,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,NULL,0,NULL,1,&barrier);
    VkClearColorValue color;for(unsigned i=0;i<4;i++)color.float32[i]=rgba[i]/255.0f;
    v->CmdClearColorImage(v->command,v->image,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,&color,1,&range);
    barrier.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;barrier.dstAccessMask=0;barrier.oldLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;barrier.newLayout=VK_IMAGE_LAYOUT_GENERAL;barrier.srcQueueFamilyIndex=v->family;barrier.dstQueueFamilyIndex=VK_QUEUE_FAMILY_FOREIGN_EXT;
    v->CmdPipelineBarrier(v->command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,0,0,NULL,0,NULL,1,&barrier);
    VK_CHECK("end",v->EndCommandBuffer(v->command)); VkSubmitInfo submit={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,.commandBufferCount=1,.pCommandBuffers=&v->command};
    VK_CHECK("submit",v->QueueSubmit(v->queue,1,&submit,v->fence));VK_CHECK("wait",v->WaitForFences(v->device,1,&v->fence,VK_TRUE,2000000000ull));VK_CHECK("signalled",v->GetFenceStatus(v->device,v->fence));return true;
}
struct gl_state { EGLDisplay display; EGLContext context; EGLSurface surface; EGLImageKHR image; GLuint program,shaders[2],vbo,control,shared; unsigned maximum_error; PFNEGLCREATEIMAGEKHRPROC create_image; PFNEGLDESTROYIMAGEKHRPROC destroy_image; PFNEGLGETNATIVECLIENTBUFFERANDROIDPROC native_buffer; PFNGLEGLIMAGETARGETTEXTURE2DOESPROC target; };
static bool gl_init(struct gl_state *g) {
    g->display=eglGetDisplay(EGL_DEFAULT_DISPLAY); EGLint major,minor,count; EGLConfig config;
    REQUIRE(g->display && eglInitialize(g->display,&major,&minor),"egl_initialize");
    const char *extensions=eglQueryString(g->display,EGL_EXTENSIONS);
    REQUIRE(has(extensions,"EGL_ANDROID_image_native_buffer") && has(extensions,"EGL_KHR_gl_colorspace"),"native_buffer_and_linear_colorspace_extensions");
    REQUIRE(eglBindAPI(EGL_OPENGL_ES_API),"egl_bind_api");
    EGLint attrs[]={EGL_SURFACE_TYPE,EGL_PBUFFER_BIT,EGL_RENDERABLE_TYPE,EGL_OPENGL_ES2_BIT,EGL_RED_SIZE,8,EGL_GREEN_SIZE,8,EGL_BLUE_SIZE,8,EGL_ALPHA_SIZE,8,EGL_NONE};
    REQUIRE(eglChooseConfig(g->display,attrs,&config,1,&count)&&count==1,"egl_config");
    EGLint ctx[]={EGL_CONTEXT_CLIENT_VERSION,2,EGL_NONE},surface[]={EGL_WIDTH,SIDE,EGL_HEIGHT,SIDE,EGL_NONE};
    g->context=eglCreateContext(g->display,config,EGL_NO_CONTEXT,ctx);g->surface=eglCreatePbufferSurface(g->display,config,surface);
    REQUIRE(g->context && g->surface && eglMakeCurrent(g->display,g->surface,g->surface,g->context),"egl_current");
    const char *renderer=(const char *)glGetString(GL_RENDERER);REQUIRE(renderer && strstr(renderer,"Adreno"),"host_adreno_gles_required");
    g->create_image=(PFNEGLCREATEIMAGEKHRPROC)eglGetProcAddress("eglCreateImageKHR");g->destroy_image=(PFNEGLDESTROYIMAGEKHRPROC)eglGetProcAddress("eglDestroyImageKHR");g->native_buffer=(PFNEGLGETNATIVECLIENTBUFFERANDROIDPROC)eglGetProcAddress("eglGetNativeClientBufferANDROID");g->target=(PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)eglGetProcAddress("glEGLImageTargetTexture2DOES");
    REQUIRE(g->create_image && g->destroy_image && g->native_buffer && g->target,"native_image_entrypoints");
    const char *sources[]={"attribute vec2 pos;varying vec2 uv;void main(){gl_Position=vec4(pos,0.,1.);uv=pos*.5+.5;}","precision highp float;varying vec2 uv;uniform sampler2D image;void main(){gl_FragColor=texture2D(image,uv);}"};
    for(unsigned i=0;i<2;i++){g->shaders[i]=glCreateShader(i?GL_FRAGMENT_SHADER:GL_VERTEX_SHADER);glShaderSource(g->shaders[i],1,&sources[i],NULL);glCompileShader(g->shaders[i]);GLint ok;glGetShaderiv(g->shaders[i],GL_COMPILE_STATUS,&ok);REQUIRE(ok,"shader_compile");}
    g->program=glCreateProgram();for(unsigned i=0;i<2;i++)glAttachShader(g->program,g->shaders[i]);glLinkProgram(g->program);GLint ok;glGetProgramiv(g->program,GL_LINK_STATUS,&ok);REQUIRE(ok,"shader_link");glUseProgram(g->program);
    GLint pos=glGetAttribLocation(g->program,"pos"),image=glGetUniformLocation(g->program,"image");REQUIRE(pos>=0 && image>=0,"shader_inputs");
    const GLfloat vertices[]={-1,-1,3,-1,-1,3};glGenBuffers(1,&g->vbo);glBindBuffer(GL_ARRAY_BUFFER,g->vbo);glBufferData(GL_ARRAY_BUFFER,sizeof(vertices),vertices,GL_STATIC_DRAW);glEnableVertexAttribArray((GLuint)pos);glVertexAttribPointer((GLuint)pos,2,GL_FLOAT,GL_FALSE,0,NULL);glUniform1i(image,0);glActiveTexture(GL_TEXTURE0);glViewport(0,0,SIDE,SIDE);glDisable(GL_DITHER);
    uint8_t control[PIXELS*4];for(unsigned i=0;i<PIXELS;i++){control[i*4]=227;control[i*4+1]=43;control[i*4+2]=151;control[i*4+3]=255;}
    glGenTextures(1,&g->control);glBindTexture(GL_TEXTURE_2D,g->control);glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA,SIDE,SIDE,0,GL_RGBA,GL_UNSIGNED_BYTE,control);
    return glGetError()==GL_NO_ERROR || fail("gles_setup",-1);
}
static void texture_params(void) { glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE); }
static bool gl_sample(struct gl_state *g, GLuint texture, const uint8_t expected[4], const char *stage) {
    glBindTexture(GL_TEXTURE_2D,texture);texture_params();glClearColor(0,0,0,0);glClear(GL_COLOR_BUFFER_BIT);glDrawArrays(GL_TRIANGLES,0,3);glFinish();uint8_t pixels[PIXELS*4];glReadPixels(0,0,SIDE,SIDE,GL_RGBA,GL_UNSIGNED_BYTE,pixels);GLenum err=glGetError();if(err)return fail(stage,(int)err);
    for(unsigned i=0;i<sizeof(pixels);i++){unsigned delta=(unsigned)abs((int)pixels[i]-(int)expected[i%4]);if(delta>g->maximum_error)g->maximum_error=delta;if(delta>1)return fail(stage,(int)i);}
    return true;
}
static bool gl_import_ahb(struct gl_state *g, AHardwareBuffer *ahb) {
    EGLClientBuffer client=g->native_buffer(ahb);REQUIRE(client,"native_client_buffer");
    const EGLint attrs[]={EGL_IMAGE_PRESERVED_KHR,EGL_TRUE,EGL_GL_COLORSPACE_KHR,EGL_GL_COLORSPACE_LINEAR_KHR,EGL_NONE};
    g->image=g->create_image(g->display,EGL_NO_CONTEXT,EGL_NATIVE_BUFFER_ANDROID,client,attrs);if(!g->image)return fail("egl_import_native_ahb",(int)eglGetError());
    glGenTextures(1,&g->shared);glBindTexture(GL_TEXTURE_2D,g->shared);g->target(GL_TEXTURE_2D,g->image);GLenum err=glGetError();if(err)return fail("gles_target_native_ahb",(int)err);return true;
}
static void cleanup(struct vk_state *v,struct gl_state *g,AHardwareBuffer *ahb) {
    if(g->context){if(g->shared)glDeleteTextures(1,&g->shared);if(g->control)glDeleteTextures(1,&g->control);if(g->vbo)glDeleteBuffers(1,&g->vbo);if(g->program)glDeleteProgram(g->program);for(unsigned i=0;i<2;i++)if(g->shaders[i])glDeleteShader(g->shaders[i]);}
    if(g->image && g->destroy_image)g->destroy_image(g->display,g->image);
    if(g->display){eglMakeCurrent(g->display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT);if(g->surface)eglDestroySurface(g->display,g->surface);if(g->context)eglDestroyContext(g->display,g->context);eglTerminate(g->display);}
    if(v->device){if(v->fence&&v->DestroyFence)v->DestroyFence(v->device,v->fence,NULL);if(v->pool&&v->DestroyCommandPool)v->DestroyCommandPool(v->device,v->pool,NULL);if(v->source_image&&v->DestroyImage)v->DestroyImage(v->device,v->source_image,NULL);if(v->source_memory&&v->FreeMemory)v->FreeMemory(v->device,v->source_memory,NULL);if(v->export_image&&v->DestroyImage)v->DestroyImage(v->device,v->export_image,NULL);if(v->export_memory&&v->FreeMemory)v->FreeMemory(v->device,v->export_memory,NULL);if(v->image&&v->DestroyImage)v->DestroyImage(v->device,v->image,NULL);if(v->memory&&v->FreeMemory)v->FreeMemory(v->device,v->memory,NULL);if(v->DestroyDevice)v->DestroyDevice(v->device,NULL);}
    if(v->source_fd>=0)close(v->source_fd);
    if(ahb)AHardwareBuffer_release(ahb);if(v->instance&&v->DestroyInstance)v->DestroyInstance(v->instance,NULL);if(v->hal&&v->hal->close)v->hal->close(v->hal);if(v->library)dlclose(v->library);
}
int main(int argc,char **argv) {
    bool opaque=argc==4 && !strcmp(argv[3],"--opaque-ahb");
    bool exported=argc==4 && !strcmp(argv[3],"--exported-dmabuf-copy");
    bool copy=exported || (argc==4 && !strcmp(argv[3],"--udmabuf-copy"));
    if((argc!=3 && !copy && !opaque) || strcmp(argv[1],"--driver") || argv[2][0]!='/' || strlen(argv[2])>4096){printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"explicit_private_driver_required\"}\n");return 1;}
    alarm(25);struct rlimit core={0,0};if(setrlimit(RLIMIT_CORE,&core)){printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"core_limit\",\"code\":%d,\"rounds_verified\":0,\"ahb_sharing_verified\":false,\"guest_integration_verified\":false,\"full_port_verified\":false}\n",errno);return 1;}
    struct vk_state v={.source_fd=-1,.copy_mode=copy,.exported_mode=exported};struct gl_state g={0};AHardwareBuffer *ahb=NULL;AHardwareBuffer_Desc actual={0};bool ok=false;unsigned rounds=0;
    const uint8_t control[]={227,43,151,255};uint8_t colors[2][4]={{19,67,139,255},{203,37,91,255}};
    /* Deliberately write non-opaque source alpha. RGBX import must sample one,
     * independently of the stored fourth byte, with no CPU AHB access. */
    if(opaque){colors[0][3]=0;colors[1][3]=73;}
    if(!isolate_owned_probe())goto done;
    if(!gl_init(&g) || !gl_sample(&g,g.control,control,"baseline_cpu_texture") || !vk_init(&v,argv[2]))goto done;
    AHardwareBuffer_Desc desc={.width=SIDE,.height=SIDE,.layers=1,.format=opaque?AHARDWAREBUFFER_FORMAT_R8G8B8X8_UNORM:AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,.usage=v.ahb_usage};
    int allocated=AHardwareBuffer_allocate(&desc,&ahb);if(allocated || !ahb){fail("ahb_allocate",allocated);goto done;}
    AHardwareBuffer_describe(ahb,&actual);if(actual.width!=SIDE || actual.height!=SIDE || actual.layers!=1 || actual.format!=desc.format || (actual.usage&v.ahb_usage)!=v.ahb_usage){fail("ahb_description",-1);goto done;}
    if(!vk_import_ahb(&v,ahb))goto done;
    if(copy && !vk_source_dmabuf(&v))goto done;
    for(unsigned i=0;i<2;i++){
        if(!(copy?vk_copy_clear(&v,colors[i],i!=0):vk_clear(&v,colors[i],i!=0)))goto done;
        if(i==0 && !gl_import_ahb(&g,ahb))goto done;
        uint8_t expected[4];memcpy(expected,colors[i],sizeof(expected));if(opaque)expected[3]=255;
        if(!gl_sample(&g,g.control,control,"post_import_cpu_texture") || !gl_sample(&g,g.shared,expected,"vulkan_ahb_sample"))goto done;
        rounds++;
    }
    ok=true;
done:
    cleanup(&v,&g,ahb);
    if(!ok){printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"%s\",\"code\":%d,\"rounds_verified\":%u,\"ahb_sharing_verified\":false,\"guest_integration_verified\":false,\"full_port_verified\":false}\n",failed_stage?failed_stage:"unknown",failed_code,rounds);return 1;}
    printf("{\"source_udmabuf_gpu_copy\":%s,\"source_bytes\":%llu,\"source_stride\":%llu,\"cpu_frame_copy_used\":false,",(copy && !exported)?"true":"false",(unsigned long long)v.source_bytes,(unsigned long long)v.source_stride);
    if(exported)printf("\"source_vulkan_dmabuf_gpu_copy\":true,");
    if(opaque)printf("\"opaque_ahb_verified\":true,\"ahb_format\":%u,\"written_alpha\":[0,73],\"sampled_alpha\":255,",actual.format);
    printf("\"schema_version\":%u,\"status\":\"vulkan_ahb_gles_sampling_verified\",\"rounds_verified\":2,\"pixels_verified\":%u,\"maximum_channel_error\":%u,\"allocation_bytes\":%llu,\"ahb_stride_pixels\":%u,\"ahb_usage\":%llu,\"gpu_vulkan_clear\":true,\"cpu_ahb_mapping_used\":false,\"foreign_ownership_and_fence_wait\":true,\"egl_image_reused\":true,\"before_and_after_cpu_texture_controls\":true,\"ahb_sharing_verified\":true,\"guest_integration_verified\":false,\"original_vmm_namespace_verified\":false,\"owner_content_read\":false,\"full_port_verified\":false}\n",opaque?4u:(exported?2u:1u),2*PIXELS,g.maximum_error,(unsigned long long)v.allocation_size,actual.stride,(unsigned long long)actual.usage);return 0;
}
