/* SPDX-License-Identifier: Apache-2.0
 * Run the actual candidate bridge on generated, explicitly LINEAR Vulkan
 * DMA-BUFs. Reuses owned-probe setup and independent GLES sampling controls.
 * No guest/VMM state, installed-driver writes, or CPU image mapping/copy.
 */
#define main gb_ahb_control_main
#include "android_ahb_vulkan_gles.c"
#undef main
#include <stddef.h>
#include <poll.h>
#include <stdarg.h>
#include <linux/dma-buf.h>
#define ENABLE_VULKAN_DLOAD 1
static void bridge_log(const char *format,...)
{
    va_list ap;va_start(ap,format);vfprintf(stderr,format,ap);va_end(ap);
}
#define vrend_printf bridge_log
#include "gb_android_image_bridge.h"

static const char *driver_path;
struct probe_loader {void *library;hw_device_t *hal;};
bool vkr_library_load(struct vulkan_library *lib)
{
    struct probe_loader *loader=calloc(1,sizeof(*loader));if(!loader)return false;
    loader->library=dlopen(driver_path,RTLD_NOW|RTLD_LOCAL);if(!loader->library)goto fail;
    hw_module_t *m=dlsym(loader->library,HAL_MODULE_INFO_SYM_AS_STR);
    if(!m || !m->id || strcmp(m->id,"vulkan") || !m->methods || !m->methods->open ||
       m->methods->open(m,HWVULKAN_DEVICE_0,&loader->hal) || !loader->hal)goto fail;
    lib->GetInstanceProcAddr=((hwvulkan_device_t *)loader->hal)->GetInstanceProcAddr;
    if(!lib->GetInstanceProcAddr)goto fail;
    lib->handle=loader;return true;
fail:
    if(loader->hal && loader->hal->close)loader->hal->close(loader->hal);
    if(loader->library)dlclose(loader->library);free(loader);return false;
}
void vkr_library_unload(struct vulkan_library *lib)
{
    struct probe_loader *loader=lib->handle;
    if(loader){if(loader->hal && loader->hal->close)loader->hal->close(loader->hal);
        if(loader->library)dlclose(loader->library);free(loader);}
    lib->handle=NULL;lib->GetInstanceProcAddr=NULL;
}

static bool exercise_format(uint32_t fourcc,unsigned *maximum_error)
{
    bool bgra=false;uint32_t ahb_format=0;
    REQUIRE(gb_image_format(fourcc,&bgra,&ahb_format),"format_admission");
    struct vk_state v={.source_fd=-1,.copy_mode=true,.exported_mode=true,
        .source_format=bgra?VK_FORMAT_B8G8R8A8_UNORM:VK_FORMAT_R8G8B8A8_UNORM};
    struct gl_state g={0};struct gb_android_image *bridge=NULL;
    AHardwareBuffer *scratch=NULL;bool ok=false;int fd=-1;unsigned rounds=0;
    const uint8_t control[]={227,43,151,255};
    /* Both opaque formats must sample one with non-opaque stored alpha.
     * Alpha-bearing formats must preserve exactly these same alpha values. */
    const uint8_t colors[2][4]={{19,67,139,0},{203,37,91,73}};
    if(!gl_init(&g) || !gl_sample(&g,g.control,control,"baseline_texture") ||
       !vk_init(&v,driver_path))goto done;
    /* Existing helper allocates its command pool/fence during AHB import.
     * This tiny scratch AHB is never rendered, sampled or used by the bridge. */
    AHardwareBuffer_Desc desc={.width=SIDE,.height=SIDE,.layers=1,
        .format=AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,.usage=v.ahb_usage};
    int allocated=AHardwareBuffer_allocate(&desc,&scratch);
    if(allocated || !scratch){fail("scratch_allocate",allocated);goto done;}
    if(!vk_import_ahb(&v,scratch) || !vk_source_dmabuf(&v))goto done;
    VkMemoryGetFdInfoKHR export={.sType=VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR,
        .memory=v.export_memory,.handleType=VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkResult rc=v.GetMemoryFdKHR(v.device,&export,&fd);
    if(rc!=VK_SUCCESS){fail("owned_source_export",rc);goto done;}
    for(unsigned i=0;i<2;i++){
        /* Clear the real source image on the GPU, not the scratch AHB. */
        VkImage saved=v.image;v.image=v.source_image;
        bool completed=vk_clear(&v,colors[i],i!=0);v.image=saved;
        if(!completed)goto done;
        glFinish();
        if(!bridge){
            bridge=gb_android_image_create(SIDE,SIDE,fourcc,0,1,fd,(uint32_t)v.source_stride,0);
            if(!bridge){fail("actual_bridge_create",-1);goto done;}
            struct gb_ahb_desc actual={0};bridge->describe(bridge->ahb,&actual);
            if(actual.format!=ahb_format){fail("actual_bridge_ahb_format",-1);goto done;}
        }
        if(!gb_android_image_refresh(bridge)){fail("actual_bridge_refresh",-1);goto done;}
        if(i==0 && !gl_import_ahb(&g,bridge->ahb))goto done;
        uint8_t expected[4];memcpy(expected,colors[i],4);if(ahb_format==2)expected[3]=255;
        if(!gl_sample(&g,g.control,control,"post_import_control") ||
           !gl_sample(&g,g.shared,expected,"actual_bridge_shader_sample"))goto done;
        rounds++;
    }
    if(fcntl(fd,F_GETFD)<0){fail("original_fd_ownership",errno);goto done;}
    ok=true;
done:
    fprintf(stderr,"GB_BRIDGE_PROBE fourcc=%u ahb_format=%u rounds=%u success=%u\n",
        fourcc,ahb_format,rounds,ok?1u:0u);
    if(g.maximum_error>*maximum_error)*maximum_error=g.maximum_error;
    /* In-flight bridge work must not outlive any source allocation cleanup. */
    if((bridge && bridge->pending) || (!ok && v.device && v.fence &&
       v.GetFenceStatus && v.GetFenceStatus(v.device,v.fence)!=VK_SUCCESS)){
        printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"gpu_completion_unproven\",\"full_port_verified\":false}\n");
        fflush(stdout);_Exit(1);
    }
    glFinish();cleanup(&v,&g,scratch);gb_android_image_destroy(bridge);
    if(fd>=0)close(fd);
    return ok;
}

int main(int argc,char **argv)
{
    if(argc!=3 || strcmp(argv[1],"--driver") || argv[2][0]!='/' || strlen(argv[2])>4096)return 2;
    driver_path=argv[2];alarm(25);struct rlimit core={0,0};
    if(setrlimit(RLIMIT_CORE,&core) || !isolate_owned_probe())return 2;
    if(setenv("GB_ANDROID_IMAGE_BRIDGE_V1","diagnostic-linear-v1",1))return 2;
    unsigned maximum_error=0,verified=0;
    const uint32_t formats[]={0x34324241,0x34325241,0x34324258,0x34325258};
    for(unsigned i=0;i<4;i++){
        if(!exercise_format(formats[i],&maximum_error)){
            printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":\"%s\",\"code\":%d,\"formats_verified\":%u,\"full_port_verified\":false}\n",
                failed_stage?failed_stage:"unknown",failed_code,verified);return 1;
        }
        verified++;
        if(atomic_load(&gb_image_slots)!=0)return 2;
    }
    printf("{\"schema_version\":1,\"status\":\"actual_bridge_sampling_verified\",\"formats_verified\":4,\"rounds_per_format\":2,\"pixels_verified\":8192,\"maximum_channel_error\":%u,\"opaque_sampled_alpha\":255,\"source_alpha\":[0,73],\"cpu_image_mapping_or_copy\":false,\"bridge_slots_after_cleanup\":0,\"original_fd_ownership_retained\":true,\"guest_integration_verified\":false,\"original_vmm_namespace_verified\":false,\"full_port_verified\":false}\n",maximum_error);
    return 0;
}
