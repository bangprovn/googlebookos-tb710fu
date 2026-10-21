/* SPDX-License-Identifier: Apache-2.0
 * Runs actual bridge admission/ownership code with fake GPU calls and real
 * owned Linux descriptors. No image or hardware compatibility claim.
 */
#define _GNU_SOURCE
#define GB_ANDROID_IMAGE_BRIDGE_TEST 1
#define ENABLE_VULKAN_DLOAD 1
#define VK_NO_PROTOTYPES
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <dlfcn.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/dma-buf.h>
static int exported_sync=-1, ioctl_count, dl_count, dl_closed;
static bool dma_valid=true;
static int mock_ioctl(int fd, unsigned long request, ...)
{
   assert(fcntl(fd,F_GETFD)>=0);assert(request==DMA_BUF_IOCTL_EXPORT_SYNC_FILE);
   va_list ap;va_start(ap,request);struct dma_buf_export_sync_file *sync=va_arg(ap,void *);va_end(ap);
   assert(sync->flags==DMA_BUF_SYNC_READ && sync->fd==-1);ioctl_count++;
   if (!dma_valid) {errno=ENOTTY;return -1;}
   exported_sync=eventfd(1,EFD_CLOEXEC);assert(exported_sync>=0);sync->fd=exported_sync;return 0;
}
static int native_tag;
static void *mock_dlopen(const char *path,int flags)
{ assert(!strcmp(path,"libnativewindow.so"));assert(flags==(RTLD_NOW|RTLD_LOCAL));dl_count++;return &native_tag; }
static int mock_dlclose(void *handle) {assert(handle==&native_tag);dl_closed++;return 0;}
struct gb_ahb_desc;
struct AHardwareBuffer;
static bool successful_imports;
static int mock_allocate(const struct gb_ahb_desc *desc,struct AHardwareBuffer **out);
static void mock_describe(const struct AHardwareBuffer *b,struct gb_ahb_desc *desc);
static unsigned released;
static void mock_release(struct AHardwareBuffer *b) {assert(b);released++;if (successful_imports) free(b);}
static void *mock_dlsym(void *handle,const char *name)
{
   assert(handle==&native_tag);
   if (!strcmp(name,"AHardwareBuffer_allocate")) return (void *)mock_allocate;
   if (!strcmp(name,"AHardwareBuffer_describe")) return (void *)mock_describe;
   if (!strcmp(name,"AHardwareBuffer_release")) return (void *)mock_release;
   return NULL;
}
static unsigned log_calls;
static char last_log[1024],last_layout_log[1024];
static void mock_log(const char *format,...)
{
   va_list ap;va_start(ap,format);int n=vsnprintf(last_log,sizeof(last_log),format,ap);va_end(ap);
   assert(n>=0 && (size_t)n<sizeof(last_log));log_calls++;
   if (!strncmp(last_log,"GB-ANDROID-IMAGE-LAYOUT:",24))
      memcpy(last_layout_log,last_log,(size_t)n+1);
}
#define ioctl mock_ioctl
#define dlopen mock_dlopen
#define dlsym mock_dlsym
#define dlclose mock_dlclose
#define vrend_printf mock_log
#include "gb_android_image_bridge.h"
#undef ioctl
#undef dlopen
#undef dlsym
#undef dlclose
static unsigned unloads;
static VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL mock_get_instance_proc(VkInstance instance,const char *name);
bool vkr_library_load(struct vulkan_library *lib)
{if (!successful_imports) return false;lib->GetInstanceProcAddr=mock_get_instance_proc;return true;}
void vkr_library_unload(struct vulkan_library *lib) {(void)lib;unloads++;}

/* This dispatch is deliberately host-only. It lets the actual admission and
 * creation path finish with owned descriptors; no firmware driver is loaded. */
struct mock_ahb {struct gb_ahb_desc desc;};
static int mock_allocate(const struct gb_ahb_desc *desc,struct AHardwareBuffer **out)
{
   if (!successful_imports) return -1;
   struct mock_ahb *b=calloc(1,sizeof(*b));assert(b);b->desc=*desc;b->desc.stride=32;
   *out=(struct AHardwareBuffer *)b;return 0;
}
static void mock_describe(const struct AHardwareBuffer *b,struct gb_ahb_desc *desc)
{assert(successful_imports && b);*desc=((const struct mock_ahb *)b)->desc;}

static unsigned destroyed_images,freed_memory,destroyed_device,destroyed_pool,destroyed_fence,destroyed_instance;
static VkResult status=VK_NOT_READY,wait_result=VK_SUCCESS;
static unsigned copies,blits,barriers,submits,waits,begins,resets;
static VKAPI_ATTR VkResult VKAPI_CALL fence_status(VkDevice d,VkFence f) {(void)d;(void)f;return status;}
static VKAPI_ATTR void VKAPI_CALL destroy_image(VkDevice d,VkImage i,const VkAllocationCallbacks *a) {(void)d;assert(i);(void)a;destroyed_images++;}
static VKAPI_ATTR void VKAPI_CALL free_memory(VkDevice d,VkDeviceMemory m,const VkAllocationCallbacks *a) {(void)d;assert(m);(void)a;freed_memory++;}
static VKAPI_ATTR void VKAPI_CALL destroy_device(VkDevice d,const VkAllocationCallbacks *a) {assert(d);(void)a;destroyed_device++;}
static VKAPI_ATTR void VKAPI_CALL destroy_pool(VkDevice d,VkCommandPool p,const VkAllocationCallbacks *a) {(void)d;assert(p);(void)a;destroyed_pool++;}
static VKAPI_ATTR void VKAPI_CALL destroy_fence(VkDevice d,VkFence f,const VkAllocationCallbacks *a) {(void)d;assert(f);(void)a;destroyed_fence++;}
static VKAPI_ATTR void VKAPI_CALL destroy_instance(VkInstance i,const VkAllocationCallbacks *a) {assert(i);(void)a;destroyed_instance++;}
static VKAPI_ATTR VkResult VKAPI_CALL reset_fences(VkDevice d,uint32_t n,const VkFence *f) {(void)d;assert(n==1 && f);resets++;status=VK_NOT_READY;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL reset_command(VkCommandBuffer c,VkCommandBufferResetFlags f) {(void)c;assert(f==0);return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL begin(VkCommandBuffer c,const VkCommandBufferBeginInfo *b) {(void)c;assert(b->flags==VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT);begins++;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL end(VkCommandBuffer c) {(void)c;return VK_SUCCESS;}
static VKAPI_ATTR void VKAPI_CALL barrier(VkCommandBuffer c,VkPipelineStageFlags s,VkPipelineStageFlags d,VkDependencyFlags f,uint32_t nm,const VkMemoryBarrier *m,uint32_t nb,const VkBufferMemoryBarrier *b,uint32_t ni,const VkImageMemoryBarrier *i)
{
   (void)c;(void)f;(void)m;(void)b;assert(nm==0 && nb==0 && ni==2);assert(i[0].image!=i[1].image);
   if ((barriers++%2)==0) {
      assert(s==VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT && d==VK_PIPELINE_STAGE_TRANSFER_BIT);
      assert(i[0].oldLayout==VK_IMAGE_LAYOUT_GENERAL && i[0].newLayout==VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
      assert(i[0].srcQueueFamilyIndex==VK_QUEUE_FAMILY_FOREIGN_EXT && i[0].dstQueueFamilyIndex==0);
      assert(i[1].newLayout==VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
      if (begins==1) assert(i[1].oldLayout==VK_IMAGE_LAYOUT_UNDEFINED && i[1].srcQueueFamilyIndex==VK_QUEUE_FAMILY_IGNORED);
      else assert(i[1].oldLayout==VK_IMAGE_LAYOUT_GENERAL && i[1].srcQueueFamilyIndex==VK_QUEUE_FAMILY_FOREIGN_EXT);
   } else {
      assert(s==VK_PIPELINE_STAGE_TRANSFER_BIT && d==VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT);
      assert(i[0].newLayout==VK_IMAGE_LAYOUT_GENERAL && i[1].newLayout==VK_IMAGE_LAYOUT_GENERAL);
      assert(i[0].dstQueueFamilyIndex==VK_QUEUE_FAMILY_FOREIGN_EXT && i[1].dstQueueFamilyIndex==VK_QUEUE_FAMILY_FOREIGN_EXT);
   }
}
static VKAPI_ATTR void VKAPI_CALL copy(VkCommandBuffer c,VkImage s,VkImageLayout sl,VkImage d,VkImageLayout dl,uint32_t n,const VkImageCopy *r)
{ (void)c;assert(s && d && sl==VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL && dl==VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL && n==1 && r->extent.width==32 && r->extent.height==32);copies++; }
static VKAPI_ATTR void VKAPI_CALL blit(VkCommandBuffer c,VkImage s,VkImageLayout sl,VkImage d,VkImageLayout dl,uint32_t n,const VkImageBlit *r,VkFilter filter)
{ (void)c;assert(s && d && sl==VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL && dl==VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL && n==1 && r->srcOffsets[1].x==32 && r->dstOffsets[1].y==32 && filter==VK_FILTER_NEAREST);blits++; }
static VKAPI_ATTR VkResult VKAPI_CALL submit(VkQueue q,uint32_t n,const VkSubmitInfo *i,VkFence f) {(void)q;assert(n==1 && i->commandBufferCount==1 && f);submits++;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL wait_fences(VkDevice d,uint32_t n,const VkFence *f,VkBool32 all,uint64_t ns) {(void)d;assert(n==1 && f && all && ns==2000000000ull);waits++;if (wait_result==VK_SUCCESS) status=VK_SUCCESS;return wait_result;}
static uintptr_t next_handle=16;
static VKAPI_ATTR VkResult VKAPI_CALL create_instance(const VkInstanceCreateInfo *i,const VkAllocationCallbacks *a,VkInstance *out)
{assert(i && !a);*out=(VkInstance)++next_handle;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL physical_devices(VkInstance i,uint32_t *n,VkPhysicalDevice *out)
{assert(i && n);if (out) {*out=(VkPhysicalDevice)(uintptr_t)2;}*n=1;return VK_SUCCESS;}
static VKAPI_ATTR void VKAPI_CALL physical_properties(VkPhysicalDevice p,VkPhysicalDeviceProperties *out)
{assert(p);memset(out,0,sizeof(*out));out->deviceType=VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU;}
static VKAPI_ATTR void VKAPI_CALL memory_properties(VkPhysicalDevice p,VkPhysicalDeviceMemoryProperties *out)
{assert(p);memset(out,0,sizeof(*out));out->memoryTypeCount=1;}
static VKAPI_ATTR void VKAPI_CALL queue_properties(VkPhysicalDevice p,uint32_t *n,VkQueueFamilyProperties *out)
{assert(p && n);if (out) {*out=(VkQueueFamilyProperties){.queueCount=1,.queueFlags=VK_QUEUE_GRAPHICS_BIT};}*n=1;}
static VKAPI_ATTR VkResult VKAPI_CALL image_format_properties(VkPhysicalDevice p,const VkPhysicalDeviceImageFormatInfo2 *in,VkImageFormatProperties2 *out)
{
   assert(p && in && out);out->imageFormatProperties.maxExtent=(VkExtent3D){8192,8192,1};
   VkExternalImageFormatProperties *external=out->pNext;assert(external);
   external->externalMemoryProperties.externalMemoryFeatures=VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT;
   if (external->pNext) ((VkAndroidHardwareBufferUsageANDROID *)external->pNext)->androidHardwareBufferUsage=768u;
   return VK_SUCCESS;
}
static VKAPI_ATTR void VKAPI_CALL format_properties(VkPhysicalDevice p,VkFormat f,VkFormatProperties2 *out)
{
   assert(p && (f==VK_FORMAT_R8G8B8A8_UNORM || f==VK_FORMAT_B8G8R8A8_UNORM));
   out->formatProperties.optimalTilingFeatures=VK_FORMAT_FEATURE_BLIT_DST_BIT;
   if (out->pNext) {
      VkDrmFormatModifierPropertiesListEXT *list=out->pNext;
      if (list->pDrmFormatModifierProperties) *list->pDrmFormatModifierProperties=(VkDrmFormatModifierPropertiesEXT){.drmFormatModifier=0,.drmFormatModifierPlaneCount=1,.drmFormatModifierTilingFeatures=VK_FORMAT_FEATURE_BLIT_SRC_BIT};
      list->drmFormatModifierCount=1;
   }
}
static VKAPI_ATTR VkResult VKAPI_CALL create_device(VkPhysicalDevice p,const VkDeviceCreateInfo *i,const VkAllocationCallbacks *a,VkDevice *out)
{assert(p && i && !a);*out=(VkDevice)++next_handle;return VK_SUCCESS;}
static VKAPI_ATTR void VKAPI_CALL get_queue(VkDevice d,uint32_t family,uint32_t index,VkQueue *out)
{assert(d && family==0 && index==0);*out=(VkQueue)(uintptr_t)3;}
static VKAPI_ATTR VkResult VKAPI_CALL create_image(VkDevice d,const VkImageCreateInfo *i,const VkAllocationCallbacks *a,VkImage *out)
{assert(d && i && !a && i->extent.width==32 && i->extent.height==32);*out=(VkImage)++next_handle;return VK_SUCCESS;}
static VKAPI_ATTR void VKAPI_CALL memory_requirements(VkDevice d,VkImage i,VkMemoryRequirements *out)
{assert(d && i);*out=(VkMemoryRequirements){.size=8192,.alignment=1,.memoryTypeBits=1};}
static VKAPI_ATTR void VKAPI_CALL subresource_layout(VkDevice d,VkImage i,const VkImageSubresource *sub,VkSubresourceLayout *out)
{assert(d && i && sub);*out=(VkSubresourceLayout){.offset=0,.rowPitch=256,.size=8192};}
static VKAPI_ATTR VkResult VKAPI_CALL fd_properties(VkDevice d,VkExternalMemoryHandleTypeFlagBits type,int fd,VkMemoryFdPropertiesKHR *out)
{assert(d && type==VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT && fcntl(fd,F_GETFD)>=0);out->memoryTypeBits=1;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL allocate_memory(VkDevice d,const VkMemoryAllocateInfo *i,const VkAllocationCallbacks *a,VkDeviceMemory *out)
{
   assert(d && i && !a && i->allocationSize==8192);
   const VkMemoryDedicatedAllocateInfo *dedicated=i->pNext;assert(dedicated && dedicated->image);
   const VkBaseInStructure *import=dedicated->pNext;assert(import);
   if (import->sType==VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR) {
      int fd=((const VkImportMemoryFdInfoKHR *)import)->fd;assert(fcntl(fd,F_GETFD)>=0);assert(close(fd)==0);
   } else assert(import->sType==VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID);
   *out=(VkDeviceMemory)++next_handle;return VK_SUCCESS;
}
static VKAPI_ATTR VkResult VKAPI_CALL bind_memory(VkDevice d,VkImage i,VkDeviceMemory m,VkDeviceSize offset)
{assert(d && i && m && offset==0);return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL ahb_properties(VkDevice d,const struct AHardwareBuffer *b,VkAndroidHardwareBufferPropertiesANDROID *out)
{assert(d && b);out->allocationSize=8192;out->memoryTypeBits=1;((VkAndroidHardwareBufferFormatPropertiesANDROID *)out->pNext)->format=VK_FORMAT_R8G8B8A8_UNORM;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL create_pool(VkDevice d,const VkCommandPoolCreateInfo *i,const VkAllocationCallbacks *a,VkCommandPool *out)
{assert(d && i && !a);*out=(VkCommandPool)++next_handle;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL allocate_commands(VkDevice d,const VkCommandBufferAllocateInfo *i,VkCommandBuffer *out)
{assert(d && i && i->commandBufferCount==1);*out=(VkCommandBuffer)++next_handle;return VK_SUCCESS;}
static VKAPI_ATTR VkResult VKAPI_CALL create_fence(VkDevice d,const VkFenceCreateInfo *i,const VkAllocationCallbacks *a,VkFence *out)
{assert(d && i && !a);*out=(VkFence)++next_handle;return VK_SUCCESS;}
#define MOCK_PROC(name, function) if (!strcmp(name_string,"vk" #name)) return (PFN_vkVoidFunction)function
static VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL mock_get_device_proc(VkDevice device,const char *name_string)
{
   assert(device);
   MOCK_PROC(DestroyDevice,destroy_device);MOCK_PROC(GetDeviceQueue,get_queue);
   MOCK_PROC(CreateImage,create_image);MOCK_PROC(DestroyImage,destroy_image);
   MOCK_PROC(GetImageMemoryRequirements,memory_requirements);MOCK_PROC(GetImageSubresourceLayout,subresource_layout);
   MOCK_PROC(GetMemoryFdPropertiesKHR,fd_properties);MOCK_PROC(AllocateMemory,allocate_memory);
   MOCK_PROC(FreeMemory,free_memory);MOCK_PROC(BindImageMemory,bind_memory);
   MOCK_PROC(GetAndroidHardwareBufferPropertiesANDROID,ahb_properties);
   MOCK_PROC(CreateCommandPool,create_pool);MOCK_PROC(DestroyCommandPool,destroy_pool);
   MOCK_PROC(AllocateCommandBuffers,allocate_commands);MOCK_PROC(ResetCommandBuffer,reset_command);
   MOCK_PROC(BeginCommandBuffer,begin);MOCK_PROC(EndCommandBuffer,end);
   MOCK_PROC(CmdPipelineBarrier,barrier);MOCK_PROC(CmdCopyImage,copy);MOCK_PROC(CmdBlitImage,blit);
   MOCK_PROC(CreateFence,create_fence);MOCK_PROC(DestroyFence,destroy_fence);
   MOCK_PROC(ResetFences,reset_fences);MOCK_PROC(GetFenceStatus,fence_status);
   MOCK_PROC(WaitForFences,wait_fences);MOCK_PROC(QueueSubmit,submit);
   assert(!"unexpected device entry point");return NULL;
}
static VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL mock_get_instance_proc(VkInstance instance,const char *name_string)
{
   MOCK_PROC(CreateInstance,create_instance);assert(instance);
   MOCK_PROC(DestroyInstance,destroy_instance);MOCK_PROC(GetDeviceProcAddr,mock_get_device_proc);
   MOCK_PROC(EnumeratePhysicalDevices,physical_devices);MOCK_PROC(GetPhysicalDeviceProperties,physical_properties);
   MOCK_PROC(GetPhysicalDeviceMemoryProperties,memory_properties);MOCK_PROC(GetPhysicalDeviceQueueFamilyProperties,queue_properties);
   MOCK_PROC(GetPhysicalDeviceImageFormatProperties2,image_format_properties);MOCK_PROC(GetPhysicalDeviceFormatProperties2,format_properties);
   MOCK_PROC(CreateDevice,create_device);assert(!"unexpected instance entry point");return NULL;
}
#undef MOCK_PROC
static struct gb_android_image *owned(int source)
{
   struct gb_android_image *g=calloc(1,sizeof(*g));assert(g);atomic_fetch_add(&gb_image_slots,1);
   g->width=g->height=32;g->sync_fd=dup(source);g->import_fd=dup(source);assert(g->sync_fd>=0 && g->import_fd>=0);
   g->source=(VkImage)1;g->destination=(VkImage)2;g->source_memory=(VkDeviceMemory)3;g->destination_memory=(VkDeviceMemory)4;
   g->device=(VkDevice)(uintptr_t)1;g->instance=(VkInstance)(uintptr_t)1;g->pool=(VkCommandPool)1;g->fence=(VkFence)1;g->command=(VkCommandBuffer)(uintptr_t)1;g->ahb=(struct AHardwareBuffer *)(uintptr_t)1;
   g->DestroyImage=destroy_image;g->FreeMemory=free_memory;g->DestroyDevice=destroy_device;g->DestroyCommandPool=destroy_pool;g->DestroyFence=destroy_fence;g->DestroyInstance=destroy_instance;g->release=(void (*)(struct AHardwareBuffer *))mock_release;g->GetFenceStatus=fence_status;
   g->ResetFences=reset_fences;g->ResetCommandBuffer=reset_command;g->BeginCommandBuffer=begin;g->EndCommandBuffer=end;g->CmdPipelineBarrier=barrier;g->CmdCopyImage=copy;g->CmdBlitImage=blit;g->QueueSubmit=submit;g->WaitForFences=wait_fences;
   return g;
}
static unsigned fd_count(void) { unsigned count=0;for (int fd=0;fd<128;fd++) if (fcntl(fd,F_GETFD)>=0) count++;return count; }
static void successful_overlap_lifecycle(int source,int unrelated)
{
   assert(atomic_load(&gb_image_slots)==0);
   unsigned original_fds=fd_count(),prior_released=released,prior_images=destroyed_images;
   unsigned prior_memory=freed_memory,prior_devices=destroyed_device,prior_unloads=unloads;
   int prior_dl=dl_count,prior_closed=dl_closed;
   struct gb_android_image *live[GB_IMAGE_SLOTS]={0};
   successful_imports=true;atomic_store(&gb_image_logs,0);
   for (unsigned i=0;i<GB_IMAGE_SLOTS;i++) {
      live[i]=gb_android_image_create(32,32,0x34324241,0,1,source,256,0);
      assert(live[i] && atomic_load(&gb_image_slots)==i+1);
      assert(live[i]->sync_fd>=0 && live[i]->import_fd==-1 && live[i]->ahb);
      assert(fd_count()==original_fds+i+1);
   }
   int before=dl_count;
   assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
   assert(dl_count==before && atomic_load(&gb_image_slots)==GB_IMAGE_SLOTS);
   assert(fd_count()==original_fds+GB_IMAGE_SLOTS && strstr(last_log,"stage=slot_budget"));
   unsigned reclaimed=0;
   for (unsigned i=0;i<GB_IMAGE_SLOTS;i+=2) {
      gb_android_image_destroy(live[i]);live[i]=NULL;reclaimed++;
      assert(atomic_load(&gb_image_slots)==GB_IMAGE_SLOTS-reclaimed);
      assert(fd_count()==original_fds+GB_IMAGE_SLOTS-reclaimed);
   }
   for (unsigned i=0;i<GB_IMAGE_SLOTS;i+=2) {
      live[i]=gb_android_image_create(32,32,0x34324241,0,1,source,256,0);
      assert(live[i]);
   }
   assert(atomic_load(&gb_image_slots)==GB_IMAGE_SLOTS && fd_count()==original_fds+GB_IMAGE_SLOTS);
   for (unsigned i=0;i<GB_IMAGE_SLOTS;i++) {
      gb_android_image_destroy(live[i]);
      assert(atomic_load(&gb_image_slots)==GB_IMAGE_SLOTS-i-1);
   }
   unsigned total=GB_IMAGE_SLOTS+reclaimed;
   assert(released-prior_released==total && destroyed_images-prior_images==2*total);
   assert(freed_memory-prior_memory==2*total && destroyed_device-prior_devices==total);
   assert(unloads-prior_unloads==total && dl_count-prior_dl==(int)total && dl_closed-prior_closed==(int)total);
   assert(fd_count()==original_fds && fcntl(source,F_GETFD)>=0 && fcntl(unrelated,F_GETFD)>=0);
   successful_imports=false;
   printf("PASS: simultaneous_mock_imports=%u; excess_import_refused=1; released_slots_reclaimed=%u; final_slots=0; final_fd_delta=0 (mock GPU only)\n",GB_IMAGE_SLOTS,reclaimed);
}
int main(void)
{
#ifdef GB_IMAGE_LAYOUT_DIAGNOSTICS
   assert(gb_image_layout_refused(32,32,0x34324241,0,1,256,0,8192)==0);
   assert(gb_image_layout_refused(32,32,0x34324241,UINT64_MAX,1,256,0,8192)==GB_LAYOUT_MODIFIER);
   assert(gb_image_layout_refused(32,32,0x34324241,0,2,256,0,8192)==GB_LAYOUT_PLANES);
#ifdef GB_IMAGE_OPAQUE_FORMATS
   assert(gb_image_layout_refused(32,32,0x34324258,0,1,256,0,8192)==0);
   assert(gb_image_layout_refused(32,32,0x34325258,0,1,256,0,8192)==0);
   assert(gb_image_layout_refused(32,32,0x34325258,0x00ffffffffffffffull,1,256,0,8192)==GB_LAYOUT_MODIFIER);
#else
   assert(gb_image_layout_refused(32,32,0x34324258,0,1,256,0,8192)==GB_LAYOUT_FORMAT);
#endif
   assert(gb_image_layout_refused(32,32,0xffffffff,0,1,256,0,8192)==GB_LAYOUT_FORMAT);
   assert(gb_image_layout_refused(32,32,0x34324241,0,1,127,0,8192)==GB_LAYOUT_PITCH);
   assert(gb_image_layout_refused(32,32,0x34324241,0,1,256,0,GB_IMAGE_LIMIT+1ull)==GB_LAYOUT_BYTES);
   assert(gb_image_layout_refused(32,32,0x34324241,0,1,256,4096,8192)==GB_LAYOUT_RANGE);
   assert(gb_image_layout_refused(0,32,0x34324241,0,1,256,0,8192)&GB_LAYOUT_EXTENT);
   for (unsigned i=0;i<64;i++) {
      if (i%2) gb_image_layout_log(32,32,0x34324241,UINT64_MAX,1,256,0,-1,ESPIPE,-1,0,255);
      else gb_image_log("owned_budget_test",0,32,32);
   }
   assert(log_calls==32 && atomic_load(&gb_image_logs)==32);
   assert(strstr(last_log,"modifier=18446744073709551615") && strstr(last_log,"bytes=-1") && strstr(last_log,"refused=255"));
   assert(!strstr(last_log,"fd=") && !strstr(last_log,"0x"));
   atomic_store(&gb_image_logs,0);log_calls=0;
#endif
   assert(gb_image_layout(32,32,0x34324241,0,1,256,0,8192));
   assert(gb_image_layout(3840,2160,0x34325241,0,1,15360,0,33177600));
   assert(gb_image_layout(32,32,0x34324241,0,1,256,256,12288));
   assert(!gb_image_layout(0,32,0x34324241,0,1,256,0,8192));
   assert(!gb_image_layout(UINT32_MAX,UINT32_MAX,0x34324241,0,1,UINT32_MAX,UINT32_MAX,UINT64_MAX));
   assert(!gb_image_layout(32,32,0x34324241,1,1,256,0,8192));
   assert(!gb_image_layout(32,32,0x34324241,0,2,256,0,8192));
#ifdef GB_IMAGE_OPAQUE_FORMATS
   assert(gb_image_layout(32,32,0x34324258,0,1,256,0,8192));
   assert(gb_image_layout(32,32,0x34325258,0,1,256,0,8192));
   const uint32_t formats[]={0x34324241,0x34325241,0x34324258,0x34325258};
   for (unsigned i=0;i<4;i++) {
      bool blit=false;uint32_t ahb=0;
      assert(gb_image_format(formats[i],&blit,&ahb));
      assert(blit==(i%2==1) && ahb==(i<2?1u:2u));
      assert(gb_image_format(formats[i],NULL,NULL));
      assert(!gb_image_layout(32,32,formats[i],0x00ffffffffffffffull,1,256,0,8192));
   }
   bool untouched_blit=true;uint32_t untouched_ahb=123;
   assert(!gb_image_format(0xffffffff,&untouched_blit,&untouched_ahb));
   assert(untouched_blit && untouched_ahb==123);
#else
   assert(!gb_image_layout(32,32,0x34324258,0,1,256,0,8192));
#endif
   assert(!gb_image_layout(32,32,0xffffffff,0,1,256,0,8192));
   assert(!gb_image_layout(32,32,0x34324241,0,1,127,0,8192));
   assert(!gb_image_layout(32,32,0x34324241,0,1,256,4096,8192));
   assert(!gb_image_layout(8192,8192,0x34324241,0,1,32768,0,268435456));
   int source=memfd_create("gb-bridge-owned-source",MFD_CLOEXEC);assert(source>=0 && ftruncate(source,8192)==0);int unrelated=dup(source);assert(unrelated>=0);
   unsetenv("GB_ANDROID_IMAGE_BRIDGE_V1");assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));assert(ioctl_count==0 && dl_count==0);
   unsigned original_fds=fd_count();
   setenv("GB_ANDROID_IMAGE_BRIDGE_V1","diagnostic-linear-v1",1);dma_valid=false;
   assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));assert(dl_count==0 && atomic_load(&gb_image_slots)==0);dma_valid=true;
#ifdef GB_IMAGE_LAYOUT_DIAGNOSTICS
   int pipe_fds[2];assert(pipe(pipe_fds)==0);
   assert(!gb_android_image_create(32,32,0x34324241,0,1,pipe_fds[0],256,0));
   assert(dl_count==0 && atomic_load(&gb_image_slots)==0);
   assert(strstr(last_layout_log,"bytes=-1") && strstr(last_layout_log,"reset=-1") && strstr(last_layout_log,"reset_errno=0"));
   assert(fcntl(pipe_fds[0],F_GETFD)>=0 && fcntl(pipe_fds[1],F_GETFD)>=0);
   close(pipe_fds[0]);close(pipe_fds[1]);assert(fd_count()==original_fds);
#endif
   assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));assert(dl_count==1 && dl_closed==1 && atomic_load(&gb_image_slots)==0 && fd_count()==original_fds);assert(fcntl(source,F_GETFD)>=0 && fcntl(unrelated,F_GETFD)>=0);
   /* Admission must reach the loader below the configured ceiling, including
    * old/new swapchain overlap. The mock loader then fails and rolls back the
    * reserved slot without consuming the caller's descriptors. */
   for (unsigned slots=3; slots<GB_IMAGE_SLOTS; slots++) {
      atomic_store(&gb_image_slots,slots);int before=dl_count;
      assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
      assert(dl_count==before+1 && atomic_load(&gb_image_slots)==slots && fd_count()==original_fds);
   }
   atomic_store(&gb_image_slots,GB_IMAGE_SLOTS);int before=dl_count;
   assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
   assert(dl_count==before && atomic_load(&gb_image_slots)==GB_IMAGE_SLOTS);
   atomic_store(&gb_image_slots,0);
   struct gb_android_image *g=owned(source);int held=g->sync_fd,import=g->import_fd;
   assert(gb_android_image_refresh(g));assert(g->copied && !g->pending && !g->failed);assert(copies==1 && submits==1 && waits==1);assert(fcntl(exported_sync,F_GETFD)==-1 && errno==EBADF);
   assert(gb_android_image_refresh(g));assert(copies==2 && resets==1 && barriers==4);
   g->blit=true;assert(gb_android_image_refresh(g));assert(blits==1 && copies==2);
   wait_result=VK_TIMEOUT;status=VK_NOT_READY;assert(!gb_android_image_refresh(g));assert(g->failed && g->pending);unsigned prior=submits;assert(!gb_android_image_refresh(g) && submits==prior);
   gb_android_image_destroy(g);assert(atomic_load(&gb_image_slots)==1 && destroyed_images==0 && fcntl(held,F_GETFD)>=0 && fcntl(import,F_GETFD)>=0);
   status=VK_SUCCESS;gb_android_image_destroy(g);assert(atomic_load(&gb_image_slots)==0 && destroyed_images==2 && freed_memory==2 && destroyed_device==1 && destroyed_pool==1 && destroyed_fence==1 && destroyed_instance==1 && released==1);
   assert(fcntl(held,F_GETFD)==-1 && errno==EBADF);assert(fcntl(import,F_GETFD)==-1 && errno==EBADF);assert(fcntl(source,F_GETFD)>=0 && fcntl(unrelated,F_GETFD)>=0);g=owned(source);status=VK_SUCCESS;prior=submits;assert(!gb_android_image_refresh(g) && g->failed && !g->pending && submits==prior);gb_android_image_destroy(g);assert(atomic_load(&gb_image_slots)==0 && fd_count()==original_fds);
   successful_overlap_lifecycle(source,unrelated);close(source);close(unrelated);
   puts("PASS: admission, explicit opt-in, FD preservation/cleanup, budget, copy/blit barriers, reuse, fence deadline and pending quarantine (mock GPU only)");return 0;
}
