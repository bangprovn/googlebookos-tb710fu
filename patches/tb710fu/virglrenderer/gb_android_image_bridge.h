/* SPDX-License-Identifier: MIT
 * Explicit opt-in Android image bridge. Incoming guest pixels stay on the GPU.
 * Included by vrend_winsys_egl.c; no new ELF dependency or global EGL selection.
 * ABI-only AHB declarations match Android API 26+ (verified against NDK r30).
 * The driver is the existing vkr_library selected by the pinned launch profile.
 */
#ifndef GB_ANDROID_IMAGE_BRIDGE_H
#define GB_ANDROID_IMAGE_BRIDGE_H
#if (defined(__ANDROID__) && defined(__aarch64__) && defined(ENABLE_VULKAN_DLOAD)) || defined(GB_ANDROID_IMAGE_BRIDGE_TEST)
#include <dlfcn.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <linux/dma-buf.h>
#include "venus/vkr_library.h"
#include "gb_vulkan_android.h"

struct gb_ahb_desc {
   uint32_t width, height, layers, format;
   uint64_t usage;
   uint32_t stride, rfu0;
   uint64_t rfu1;
};
_Static_assert(sizeof(struct gb_ahb_desc) == 40, "AHB descriptor ABI size");
_Static_assert(offsetof(struct gb_ahb_desc, usage) == 16, "AHB usage ABI");
_Static_assert(offsetof(struct gb_ahb_desc, stride) == 24, "AHB stride ABI");
#define GB_IMAGE_LIMIT (32u * 1024u * 1024u)
#define GB_IMAGE_SLOTS 4u
static atomic_uint gb_image_slots;
static atomic_uint gb_image_logs;

static void gb_image_log(const char *stage, int result, uint32_t width, uint32_t height)
{
   unsigned n = atomic_load(&gb_image_logs);
   while (n < 32) {
      if (atomic_compare_exchange_weak(&gb_image_logs, &n, n + 1)) {
         vrend_printf("GB-ANDROID-IMAGE: stage=%s result=%d width=%u height=%u\n", stage, result, width, height);
         break;
      }
   }
}
/* Pure admission rules, also exercised by the host mock harness. */
static bool gb_image_layout(uint32_t w, uint32_t h, uint32_t fourcc,
                            uint64_t modifier, uint32_t planes, uint32_t pitch,
                            uint32_t offset, uint64_t bytes)
{
   return w && h && w <= 8192 && h <= 8192 && planes == 1 && modifier == 0 &&
      (fourcc == 0x34324241u || fourcc == 0x34325241u) &&
      pitch >= (uint64_t)w * 4 && pitch <= 131072 && pitch % 4 == 0 &&
      bytes && bytes <= GB_IMAGE_LIMIT &&
      (uint64_t)offset + (uint64_t)(h - 1) * pitch + (uint64_t)w * 4 <= bytes;
}

struct gb_android_image {
   struct vulkan_library library;
   void *native_library;
   struct AHardwareBuffer *ahb;
   int (*allocate)(const struct gb_ahb_desc *, struct AHardwareBuffer **);
   void (*describe)(const struct AHardwareBuffer *, struct gb_ahb_desc *);
   void (*release)(struct AHardwareBuffer *);
   VkInstance instance;
   VkPhysicalDevice physical;
   VkDevice device;
   VkQueue queue;
   uint32_t family, width, height;
   VkImage source, destination;
   VkDeviceMemory source_memory, destination_memory;
   VkCommandPool pool;
   VkCommandBuffer command;
   VkFence fence;
   int sync_fd, import_fd;
   bool copied, pending, failed, blit;
   uint64_t destination_bytes;
   PFN_vkGetDeviceProcAddr GetDeviceProcAddr;
   PFN_vkDestroyInstance DestroyInstance;
   PFN_vkEnumeratePhysicalDevices EnumeratePhysicalDevices;
   PFN_vkGetPhysicalDeviceProperties GetPhysicalDeviceProperties;
   PFN_vkGetPhysicalDeviceMemoryProperties GetPhysicalDeviceMemoryProperties;
   PFN_vkGetPhysicalDeviceQueueFamilyProperties GetPhysicalDeviceQueueFamilyProperties;
   PFN_vkGetPhysicalDeviceImageFormatProperties2 GetPhysicalDeviceImageFormatProperties2;
   PFN_vkGetPhysicalDeviceFormatProperties2 GetPhysicalDeviceFormatProperties2;
   PFN_vkCreateDevice CreateDevice;
   PFN_vkDestroyDevice DestroyDevice;
   PFN_vkGetDeviceQueue GetDeviceQueue;
   PFN_vkCreateImage CreateImage;
   PFN_vkDestroyImage DestroyImage;
   PFN_vkGetImageMemoryRequirements GetImageMemoryRequirements;
   PFN_vkGetMemoryFdPropertiesKHR GetMemoryFdPropertiesKHR;
   PFN_vkGetImageSubresourceLayout GetImageSubresourceLayout;
   PFN_vkAllocateMemory AllocateMemory;
   PFN_vkFreeMemory FreeMemory;
   PFN_vkBindImageMemory BindImageMemory;
   PFN_vkGetAndroidHardwareBufferPropertiesANDROID GetAndroidHardwareBufferPropertiesANDROID;
   PFN_vkCreateCommandPool CreateCommandPool;
   PFN_vkDestroyCommandPool DestroyCommandPool;
   PFN_vkAllocateCommandBuffers AllocateCommandBuffers;
   PFN_vkResetCommandBuffer ResetCommandBuffer;
   PFN_vkBeginCommandBuffer BeginCommandBuffer;
   PFN_vkEndCommandBuffer EndCommandBuffer;
   PFN_vkCmdPipelineBarrier CmdPipelineBarrier;
   PFN_vkCmdCopyImage CmdCopyImage;
   PFN_vkCmdBlitImage CmdBlitImage;
   PFN_vkCreateFence CreateFence;
   PFN_vkDestroyFence DestroyFence;
   PFN_vkResetFences ResetFences;
   PFN_vkGetFenceStatus GetFenceStatus;
   PFN_vkWaitForFences WaitForFences;
   PFN_vkQueueSubmit QueueSubmit;
};
#define GB_I(name) do { g->name = (PFN_vk##name)g->library.GetInstanceProcAddr(g->instance, "vk" #name); if (!g->name) goto fail; } while (0)
#define GB_D(name) do { g->name = (PFN_vk##name)g->GetDeviceProcAddr(g->device, "vk" #name); if (!g->name) goto fail; } while (0)
#define GB_VK(stage, expression) do { VkResult r = (expression); if (r != VK_SUCCESS) { gb_image_log(stage, r, g->width, g->height); goto fail; } } while (0)

static void gb_android_image_destroy(struct gb_android_image *g)
{
   if (!g) return;
   /* Never free storage still referenced by an incomplete submission. Keep
    * its slot and <=64 MiB of bounded backing quarantined until process exit. */
   if (g->pending && (!g->GetFenceStatus || g->GetFenceStatus(g->device, g->fence) != VK_SUCCESS)) {
      gb_image_log("quarantine_pending", -1, g->width, g->height);
      return;
   }
   if (g->device) {
      if (g->fence && g->DestroyFence) g->DestroyFence(g->device,g->fence,NULL);
      if (g->pool && g->DestroyCommandPool) g->DestroyCommandPool(g->device,g->pool,NULL);
      if (g->source && g->DestroyImage) g->DestroyImage(g->device,g->source,NULL);
      if (g->destination && g->DestroyImage) g->DestroyImage(g->device,g->destination,NULL);
      if (g->source_memory && g->FreeMemory) g->FreeMemory(g->device,g->source_memory,NULL);
      if (g->destination_memory && g->FreeMemory) g->FreeMemory(g->device,g->destination_memory,NULL);
      if (g->DestroyDevice) g->DestroyDevice(g->device,NULL);
   }
   if (g->sync_fd >= 0) close(g->sync_fd);
   if (g->import_fd >= 0) close(g->import_fd);
   if (g->ahb && g->release) g->release(g->ahb);
   if (g->instance && g->DestroyInstance) g->DestroyInstance(g->instance,NULL);
   vkr_library_unload(&g->library);
   if (g->native_library) dlclose(g->native_library);
   free(g);
   atomic_fetch_sub(&gb_image_slots,1);
}

static uint32_t gb_image_memory_type(struct gb_android_image *g, uint32_t bits)
{
   VkPhysicalDeviceMemoryProperties memory;
   g->GetPhysicalDeviceMemoryProperties(g->physical,&memory);
   if (memory.memoryTypeCount > 32) return 32;
   for (uint32_t i=0;i<memory.memoryTypeCount;i++)
      if ((bits & (1u<<i)) && !(memory.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_PROTECTED_BIT)) return i;
   return 32;
}

static struct gb_android_image *gb_android_image_create(uint32_t w, uint32_t h,
   uint32_t fourcc, uint64_t modifier, uint32_t planes, int fd,
   uint32_t pitch, uint32_t offset)
{
   const char *selection=getenv("GB_ANDROID_IMAGE_BRIDGE_V1");
   if (!selection || strcmp(selection,"diagnostic-linear-v1") || fd < 0) return NULL;
   /* Reject an ordinary file masquerading as a DMA-BUF before driver work. */
   struct dma_buf_export_sync_file classified={.flags=DMA_BUF_SYNC_READ,.fd=-1};
   if (ioctl(fd,DMA_BUF_IOCTL_EXPORT_SYNC_FILE,&classified) || classified.fd<0) {
      gb_image_log("not_sync_exportable_dma_buf",EINVAL,w,h); return NULL;
   }
   close(classified.fd);
   off_t bytes=lseek(fd,0,SEEK_END);
   if (bytes<=0 || lseek(fd,0,SEEK_SET)!=0 || !gb_image_layout(w,h,fourcc,modifier,planes,pitch,offset,(uint64_t)bytes)) {
      gb_image_log("layout_refused",EINVAL,w,h); return NULL;
   }
   unsigned slots=atomic_load(&gb_image_slots);
   do { if (slots>=GB_IMAGE_SLOTS) { gb_image_log("slot_budget",ENOMEM,w,h); return NULL; } }
   while (!atomic_compare_exchange_weak(&gb_image_slots,&slots,slots+1));
   struct gb_android_image *g=calloc(1,sizeof(*g));
   if (!g) { atomic_fetch_sub(&gb_image_slots,1); return NULL; }
   g->width=w;g->height=h;g->import_fd=-1;g->sync_fd=-1;g->blit=fourcc==0x34325241u;
   g->sync_fd=fcntl(fd,F_DUPFD_CLOEXEC,3);
   g->import_fd=fcntl(fd,F_DUPFD_CLOEXEC,3);
   if (g->sync_fd<0 || g->import_fd<0) goto fail;
   g->native_library=dlopen("libnativewindow.so",RTLD_NOW|RTLD_LOCAL);
   if (!g->native_library) goto fail;
   g->allocate=(int (*)(const struct gb_ahb_desc *,struct AHardwareBuffer **))dlsym(g->native_library,"AHardwareBuffer_allocate");
   g->describe=(void (*)(const struct AHardwareBuffer *,struct gb_ahb_desc *))dlsym(g->native_library,"AHardwareBuffer_describe");
   g->release=(void (*)(struct AHardwareBuffer *))dlsym(g->native_library,"AHardwareBuffer_release");
   if (!g->allocate || !g->describe || !g->release || !vkr_library_load(&g->library)) goto fail;
   PFN_vkCreateInstance create=(PFN_vkCreateInstance)g->library.GetInstanceProcAddr(VK_NULL_HANDLE,"vkCreateInstance");
   if (!create) goto fail;
   VkApplicationInfo app={.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,.pApplicationName="gb-android-image-bridge",.apiVersion=VK_API_VERSION_1_1};
   VkInstanceCreateInfo ci={.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,.pApplicationInfo=&app};
   GB_VK("instance",create(&ci,NULL,&g->instance));
   GB_I(DestroyInstance);GB_I(GetDeviceProcAddr);GB_I(EnumeratePhysicalDevices);GB_I(GetPhysicalDeviceProperties);
   GB_I(GetPhysicalDeviceMemoryProperties);GB_I(GetPhysicalDeviceQueueFamilyProperties);GB_I(GetPhysicalDeviceImageFormatProperties2);GB_I(GetPhysicalDeviceFormatProperties2);GB_I(CreateDevice);
   uint32_t count=0;GB_VK("physical_count",g->EnumeratePhysicalDevices(g->instance,&count,NULL));if (count!=1) goto fail;
   GB_VK("physical",g->EnumeratePhysicalDevices(g->instance,&count,&g->physical));
   VkPhysicalDeviceProperties physical;g->GetPhysicalDeviceProperties(g->physical,&physical);
   if (physical.deviceType!=VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU && physical.deviceType!=VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) goto fail;
   count=0;g->GetPhysicalDeviceQueueFamilyProperties(g->physical,&count,NULL);if (!count || count>32) goto fail;
   VkQueueFamilyProperties queues[32];g->GetPhysicalDeviceQueueFamilyProperties(g->physical,&count,queues);g->family=count;
   for (uint32_t i=0;i<count;i++) if (queues[i].queueCount && (queues[i].queueFlags&VK_QUEUE_GRAPHICS_BIT)) {g->family=i;break;}
   if (g->family>=count) goto fail;
   float priority=1;VkDeviceQueueCreateInfo qi={.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,.queueFamilyIndex=g->family,.queueCount=1,.pQueuePriorities=&priority};
   const char *extensions[]={VK_ANDROID_EXTERNAL_MEMORY_ANDROID_HARDWARE_BUFFER_EXTENSION_NAME,VK_EXT_QUEUE_FAMILY_FOREIGN_EXTENSION_NAME,VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME,VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME,VK_EXT_IMAGE_DRM_FORMAT_MODIFIER_EXTENSION_NAME};
   VkDeviceCreateInfo di={.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,.queueCreateInfoCount=1,.pQueueCreateInfos=&qi,.enabledExtensionCount=5,.ppEnabledExtensionNames=extensions};
   GB_VK("device",g->CreateDevice(g->physical,&di,NULL,&g->device));
   GB_D(DestroyDevice);GB_D(GetDeviceQueue);GB_D(CreateImage);GB_D(DestroyImage);GB_D(GetImageMemoryRequirements);GB_D(GetImageSubresourceLayout);
   GB_D(GetMemoryFdPropertiesKHR);GB_D(AllocateMemory);GB_D(FreeMemory);GB_D(BindImageMemory);GB_D(GetAndroidHardwareBufferPropertiesANDROID);
   GB_D(CreateCommandPool);GB_D(DestroyCommandPool);GB_D(AllocateCommandBuffers);GB_D(ResetCommandBuffer);GB_D(BeginCommandBuffer);GB_D(EndCommandBuffer);
   GB_D(CmdPipelineBarrier);GB_D(CmdCopyImage);GB_D(CmdBlitImage);GB_D(CreateFence);GB_D(DestroyFence);GB_D(ResetFences);GB_D(GetFenceStatus);GB_D(WaitForFences);GB_D(QueueSubmit);
   g->GetDeviceQueue(g->device,g->family,0,&g->queue);
   VkFormat source_format=g->blit?VK_FORMAT_B8G8R8A8_UNORM:VK_FORMAT_R8G8B8A8_UNORM;
   VkDrmFormatModifierPropertiesEXT modifiers[128];
   VkDrmFormatModifierPropertiesListEXT modifier_list={.sType=VK_STRUCTURE_TYPE_DRM_FORMAT_MODIFIER_PROPERTIES_LIST_EXT};
   VkFormatProperties2 fp={.sType=VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2,.pNext=&modifier_list};
   g->GetPhysicalDeviceFormatProperties2(g->physical,source_format,&fp);
   if (!modifier_list.drmFormatModifierCount || modifier_list.drmFormatModifierCount>128) goto fail;
   modifier_list.pDrmFormatModifierProperties=modifiers;g->GetPhysicalDeviceFormatProperties2(g->physical,source_format,&fp);
   bool linear=false;
   for (uint32_t i=0;i<modifier_list.drmFormatModifierCount;i++) if (!modifiers[i].drmFormatModifier && modifiers[i].drmFormatModifierPlaneCount==1 && (!g->blit || (modifiers[i].drmFormatModifierTilingFeatures&VK_FORMAT_FEATURE_BLIT_SRC_BIT))) linear=true;
   if (!linear) goto fail;
   if (g->blit) { VkFormatProperties2 dest={.sType=VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2};g->GetPhysicalDeviceFormatProperties2(g->physical,VK_FORMAT_R8G8B8A8_UNORM,&dest);if (!(dest.formatProperties.optimalTilingFeatures&VK_FORMAT_FEATURE_BLIT_DST_BIT)) goto fail; }
   VkPhysicalDeviceImageDrmFormatModifierInfoEXT mod_query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_DRM_FORMAT_MODIFIER_INFO_EXT,.drmFormatModifier=0,.sharingMode=VK_SHARING_MODE_EXCLUSIVE};
   VkPhysicalDeviceExternalImageFormatInfo external_query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO,.pNext=&mod_query,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
   VkPhysicalDeviceImageFormatInfo2 query={.sType=VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_FORMAT_INFO_2,.pNext=&external_query,.format=source_format,.type=VK_IMAGE_TYPE_2D,.tiling=VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT,.usage=VK_IMAGE_USAGE_TRANSFER_SRC_BIT};
   VkExternalImageFormatProperties external_properties={.sType=VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES};
   VkImageFormatProperties2 result={.sType=VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2,.pNext=&external_properties};
   GB_VK("source_format",g->GetPhysicalDeviceImageFormatProperties2(g->physical,&query,&result));
   if (!(external_properties.externalMemoryProperties.externalMemoryFeatures&VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT) || result.imageFormatProperties.maxExtent.width<w || result.imageFormatProperties.maxExtent.height<h) goto fail;
   VkSubresourceLayout plane={.offset=offset,.rowPitch=pitch};
   VkImageDrmFormatModifierExplicitCreateInfoEXT explicit_layout={.sType=VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_EXPLICIT_CREATE_INFO_EXT,.drmFormatModifier=0,.drmFormatModifierPlaneCount=1,.pPlaneLayouts=&plane};
   VkExternalMemoryImageCreateInfo external={.sType=VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO,.pNext=&explicit_layout,.handleTypes=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
   VkImageCreateInfo image={.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,.pNext=&external,.imageType=VK_IMAGE_TYPE_2D,.format=source_format,.extent={w,h,1},.mipLevels=1,.arrayLayers=1,.samples=VK_SAMPLE_COUNT_1_BIT,.tiling=VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT,.usage=VK_IMAGE_USAGE_TRANSFER_SRC_BIT,.sharingMode=VK_SHARING_MODE_EXCLUSIVE,.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED};
   GB_VK("source_image",g->CreateImage(g->device,&image,NULL,&g->source));
   VkMemoryRequirements requirements;g->GetImageMemoryRequirements(g->device,g->source,&requirements);if (!requirements.size || requirements.size>(uint64_t)bytes) goto fail;
   VkImageSubresource subresource={.aspectMask=VK_IMAGE_ASPECT_MEMORY_PLANE_0_BIT_EXT};VkSubresourceLayout actual;
   g->GetImageSubresourceLayout(g->device,g->source,&subresource,&actual);if (actual.offset!=offset || actual.rowPitch!=pitch) goto fail;
   VkMemoryFdPropertiesKHR fd_props={.sType=VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR};
   GB_VK("source_fd_properties",g->GetMemoryFdPropertiesKHR(g->device,VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,g->import_fd,&fd_props));
   uint32_t type=gb_image_memory_type(g,requirements.memoryTypeBits&fd_props.memoryTypeBits);if (type==32) goto fail;
   VkImportMemoryFdInfoKHR import={.sType=VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,.fd=g->import_fd};
   VkMemoryDedicatedAllocateInfo dedicated={.sType=VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO,.pNext=&import,.image=g->source};
   VkMemoryAllocateInfo allocation={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,.pNext=&dedicated,.allocationSize=(uint64_t)bytes,.memoryTypeIndex=type};
   GB_VK("source_import",g->AllocateMemory(g->device,&allocation,NULL,&g->source_memory));g->import_fd=-1;
   GB_VK("source_bind",g->BindImageMemory(g->device,g->source,g->source_memory,0));
   const VkImageUsageFlags usage=VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_SAMPLED_BIT|VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
   VkAndroidHardwareBufferUsageANDROID ahb_usage={.sType=VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_USAGE_ANDROID};
   VkExternalImageFormatProperties ahb_external={.sType=VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES,.pNext=&ahb_usage};
   result=(VkImageFormatProperties2){.sType=VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2,.pNext=&ahb_external};
   external_query.pNext=NULL;external_query.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
   query.format=VK_FORMAT_R8G8B8A8_UNORM;query.tiling=VK_IMAGE_TILING_OPTIMAL;query.usage=usage;
   GB_VK("ahb_format",g->GetPhysicalDeviceImageFormatProperties2(g->physical,&query,&result));
   if (!(ahb_external.externalMemoryProperties.externalMemoryFeatures&VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT) || result.imageFormatProperties.maxExtent.width<w || result.imageFormatProperties.maxExtent.height<h) goto fail;
   struct gb_ahb_desc desc={.width=w,.height=h,.layers=1,.format=1,.usage=ahb_usage.androidHardwareBufferUsage|768u};
   if ((desc.usage&(1u<<14)) || g->allocate(&desc,&g->ahb) || !g->ahb) goto fail;
   struct gb_ahb_desc described={0};g->describe(g->ahb,&described);
   if (described.width!=w || described.height!=h || described.layers!=1 || described.format!=1 || (described.usage&768u)!=768u || (described.usage&(1u<<14)) || described.stride<w) goto fail;
   VkAndroidHardwareBufferFormatPropertiesANDROID af={.sType=VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_FORMAT_PROPERTIES_ANDROID};
   VkAndroidHardwareBufferPropertiesANDROID ap={.sType=VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_PROPERTIES_ANDROID,.pNext=&af};
   GB_VK("ahb_properties",g->GetAndroidHardwareBufferPropertiesANDROID(g->device,g->ahb,&ap));
   if (af.format!=VK_FORMAT_R8G8B8A8_UNORM || !ap.allocationSize || ap.allocationSize>GB_IMAGE_LIMIT || (uint64_t)(h-1)*described.stride*4+(uint64_t)w*4>ap.allocationSize) goto fail;
   g->destination_bytes=ap.allocationSize;
   external.pNext=NULL;external.handleTypes=VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID;
   image.format=VK_FORMAT_R8G8B8A8_UNORM;image.tiling=VK_IMAGE_TILING_OPTIMAL;image.usage=usage;
   GB_VK("ahb_image",g->CreateImage(g->device,&image,NULL,&g->destination));
   type=gb_image_memory_type(g,ap.memoryTypeBits);if (type==32) goto fail;
   VkImportAndroidHardwareBufferInfoANDROID ai={.sType=VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID,.buffer=g->ahb};
   dedicated.pNext=&ai;dedicated.image=g->destination;allocation.allocationSize=ap.allocationSize;allocation.memoryTypeIndex=type;
   GB_VK("ahb_import",g->AllocateMemory(g->device,&allocation,NULL,&g->destination_memory));
   GB_VK("ahb_bind",g->BindImageMemory(g->device,g->destination,g->destination_memory,0));
   VkCommandPoolCreateInfo pool={.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,.flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,.queueFamilyIndex=g->family};
   GB_VK("pool",g->CreateCommandPool(g->device,&pool,NULL,&g->pool));
   VkCommandBufferAllocateInfo command={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,.commandPool=g->pool,.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,.commandBufferCount=1};
   GB_VK("command",g->AllocateCommandBuffers(g->device,&command,&g->command));
   VkFenceCreateInfo fence={.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};GB_VK("fence",g->CreateFence(g->device,&fence,NULL,&g->fence));
   gb_image_log(g->blit?"created_bgra":"created_rgba",0,w,h);return g;
fail:
   gb_image_log("create_failed",EINVAL,w,h);gb_android_image_destroy(g);return NULL;
}

static bool gb_android_image_refresh(struct gb_android_image *g)
{
   if (!g || g->failed) return false;
   struct dma_buf_export_sync_file sync={.flags=DMA_BUF_SYNC_READ,.fd=-1};
   if (ioctl(g->sync_fd,DMA_BUF_IOCTL_EXPORT_SYNC_FILE,&sync) || sync.fd<0) goto fail;
   struct pollfd poll_fd={.fd=sync.fd,.events=POLLIN};
   int ready=poll(&poll_fd,1,2000);close(sync.fd);
   if (ready!=1 || !(poll_fd.revents&POLLIN) || (poll_fd.revents&(POLLERR|POLLNVAL))) goto fail;
   if (g->copied) {
      GB_VK("reset_fence",g->ResetFences(g->device,1,&g->fence));
      GB_VK("reset_command",g->ResetCommandBuffer(g->command,0));
   }
   if (g->GetFenceStatus(g->device,g->fence)!=VK_NOT_READY) goto fail;
   VkCommandBufferBeginInfo begin={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
   GB_VK("begin",g->BeginCommandBuffer(g->command,&begin));
   VkImageSubresourceRange range={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.levelCount=1,.layerCount=1};
   VkImageMemoryBarrier barriers[2]={
      {.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,.dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT,.oldLayout=VK_IMAGE_LAYOUT_GENERAL,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,.srcQueueFamilyIndex=VK_QUEUE_FAMILY_FOREIGN_EXT,.dstQueueFamilyIndex=g->family,.image=g->source,.subresourceRange=range},
      {.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,.dstAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT,.oldLayout=g->copied?VK_IMAGE_LAYOUT_GENERAL:VK_IMAGE_LAYOUT_UNDEFINED,.newLayout=VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,.srcQueueFamilyIndex=g->copied?VK_QUEUE_FAMILY_FOREIGN_EXT:VK_QUEUE_FAMILY_IGNORED,.dstQueueFamilyIndex=g->copied?g->family:VK_QUEUE_FAMILY_IGNORED,.image=g->destination,.subresourceRange=range}};
   g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,NULL,0,NULL,2,barriers);
   if (g->blit) {
      VkImageBlit region={.srcSubresource={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.layerCount=1},.srcOffsets={{0,0,0},{g->width,g->height,1}},.dstSubresource={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.layerCount=1},.dstOffsets={{0,0,0},{g->width,g->height,1}}};
      g->CmdBlitImage(g->command,g->source,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,g->destination,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&region,VK_FILTER_NEAREST);
   } else {
      VkImageCopy region={.srcSubresource={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.layerCount=1},.dstSubresource={.aspectMask=VK_IMAGE_ASPECT_COLOR_BIT,.layerCount=1},.extent={g->width,g->height,1}};
      g->CmdCopyImage(g->command,g->source,VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,g->destination,VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,1,&region);
   }
   for (unsigned i=0;i<2;i++) {barriers[i].srcAccessMask=i?VK_ACCESS_TRANSFER_WRITE_BIT:VK_ACCESS_TRANSFER_READ_BIT;barriers[i].dstAccessMask=0;barriers[i].oldLayout=i?VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL:VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;barriers[i].newLayout=VK_IMAGE_LAYOUT_GENERAL;barriers[i].srcQueueFamilyIndex=g->family;barriers[i].dstQueueFamilyIndex=VK_QUEUE_FAMILY_FOREIGN_EXT;}
   g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,0,0,NULL,0,NULL,2,barriers);
   GB_VK("end",g->EndCommandBuffer(g->command));VkSubmitInfo submit={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,.commandBufferCount=1,.pCommandBuffers=&g->command};
   g->pending=true;GB_VK("submit",g->QueueSubmit(g->queue,1,&submit,g->fence));
   GB_VK("wait",g->WaitForFences(g->device,1,&g->fence,VK_TRUE,2000000000ull));
   GB_VK("signalled",g->GetFenceStatus(g->device,g->fence));g->pending=false;g->copied=true;return true;
fail:
   g->failed=true;gb_image_log("refresh_failed",EIO,g->width,g->height);return false;
}
#undef GB_I
#undef GB_D
#undef GB_VK
#endif
#endif
