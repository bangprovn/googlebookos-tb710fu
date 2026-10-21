/* SPDX-License-Identifier: Apache-2.0
 * Actual D91 bridge code with mocked GPU calls and real owned descriptors.
 * Retained quarantine is intentional D91 behavior, not reclamation proof.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
static char state_records[32][1024],renderer_records[16][1024];
static unsigned state_record_count,renderer_record_count;
static int diagnostic_vsnprintf(char *out,size_t size,const char *format,va_list args)
{
   int n=vsnprintf(out,size,format,args);
   if (n>=0 && (size_t)n<size) {
      if (!strncmp(out,"GB-ANDROID-IMAGE-STATE:",sizeof("GB-ANDROID-IMAGE-STATE:")-1) && state_record_count<32)
         memcpy(state_records[state_record_count++],out,(size_t)n+1);
      if (!strncmp(out,"GB-ANDROID-IMAGE-RENDERER:",sizeof("GB-ANDROID-IMAGE-RENDERER:")-1) && renderer_record_count<16)
         memcpy(renderer_records[renderer_record_count++],out,(size_t)n+1);
   }
   return n;
}
#define vsnprintf diagnostic_vsnprintf
#define main legacy_fixture_main
#include "android_image_bridge_mock.c"
#undef main
#undef vsnprintf

#define HAVE_EPOXY_EGL_H 1
#define VIRGL_ERROR_CTX_ILLEGAL_RESOURCE 1
struct vrend_context {void *sub;};
struct vrend_resource {void *gb_android_image;unsigned id;};
static bool switch_succeeds,refresh_succeeds;
static unsigned switch_calls,bridge_refresh_calls,context_errors;
static bool vrend_hw_switch_context(struct vrend_context *ctx,bool force)
{assert(ctx && force);switch_calls++;return switch_succeeds;}
static bool virgl_egl_android_bridge_refresh(void *bridge)
{assert(bridge);bridge_refresh_calls++;return refresh_succeeds;}
static void vrend_report_context_error(struct vrend_context *ctx,int error,unsigned id)
{assert(ctx && error==VIRGL_ERROR_CTX_ILLEGAL_RESOURCE && id==71);context_errors++;}
#include "renderer_diag_excerpt.h"

/* LeakSanitizer roots only. After destroy relinquishes ownership these pointers
 * are never read, retried or used to reclaim storage. The process-exit-only
 * retention of D91 remains visible in counters and real descriptor counts. */
static struct gb_android_image *intentional_d91_retention[8];
static unsigned fence_queries;
static VKAPI_ATTR VkResult VKAPI_CALL counted_status(VkDevice device,VkFence fence)
{assert(device && fence);fence_queries++;return status;}
static VKAPI_ATTR VkResult VKAPI_CALL fail_submit(VkQueue queue,uint32_t count,const VkSubmitInfo *info,VkFence fence)
{assert(queue && count==1 && info && fence);return VK_ERROR_DEVICE_LOST;}

static struct gb_android_image *create(int source)
{
   struct gb_android_image *g=gb_android_image_create(32,32,0x34324241,0,1,source,256,0);
   assert(g);return g;
}
static void dump(void)
{
   for(unsigned i=0;i<state_record_count;i++) fputs(state_records[i],stdout);
   for(unsigned i=0;i<renderer_record_count;i++) fputs(renderer_records[i],stdout);
}
int main(int argc,char **argv)
{
   assert(argc==2 && GB_IMAGE_SLOTS==8 && GB_IMAGE_LIMIT==32u*1024u*1024u);
   assert(setenv("GB_ANDROID_IMAGE_BRIDGE_V1","diagnostic-linear-v1",1)==0);
   int source=memfd_create("owned-state-source",MFD_CLOEXEC);assert(source>=0 && ftruncate(source,8192)==0);
   unsigned original_fds=fd_count();successful_imports=true;
   const char *mode=argv[1];
   if (!strcmp(mode,"capacity_after_generic_exhaustion")) {
      struct gb_android_image *live[8];for(unsigned i=0;i<8;i++) live[i]=create(source);
      while(atomic_load(&gb_image_logs)<32) gb_image_log("successful_import",0,32,32);
      assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
      assert(atomic_load(&gb_image_diag.active)==8 && atomic_load(&gb_image_diag.quarantined)==0);
      assert(atomic_load(&gb_image_diag.pending)==0 && atomic_load(&gb_image_diag.slot_refused)==1);
      assert(atomic_load(&gb_image_diag.created)==8 && state_record_count==1);
      for(unsigned i=0;i<8;i++) gb_android_image_destroy(live[i]);
      assert(atomic_load(&gb_image_slots)==0 && atomic_load(&gb_image_diag.active)==0 && atomic_load(&gb_image_diag.freed)==8);
      struct gb_android_image *fresh=create(source);gb_android_image_destroy(fresh);
      assert(atomic_load(&gb_image_diag.allocated)==9 && atomic_load(&gb_image_diag.freed)==9);
   } else if (!strcmp(mode,"successful_refresh_and_destroy")) {
      struct gb_android_image *g=create(source);g->GetFenceStatus=counted_status;
      assert(gb_android_image_refresh(g));
      assert(fence_queries==2 && submits==1 && waits==1);
      assert(atomic_load(&gb_image_diag.refresh_ok)==1 && atomic_load(&gb_image_diag.pending)==0);
      gb_android_image_destroy(g);
      assert(fence_queries==2 && atomic_load(&gb_image_diag.active)==0 && atomic_load(&gb_image_slots)==0);
      assert(!state_record_count && atomic_load(&gb_image_diag.created)==1 && atomic_load(&gb_image_diag.freed)==1);
   } else if (!strcmp(mode,"construction_failure")) {
      successful_imports=false;
      assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
      assert(atomic_load(&gb_image_diag.active)==0 && atomic_load(&gb_image_slots)==0);
      assert(atomic_load(&gb_image_diag.allocated)==1 && atomic_load(&gb_image_diag.created)==0);
      assert(atomic_load(&gb_image_diag.create_failed)==1 && atomic_load(&gb_image_diag.freed)==1);
      assert(state_record_count==1 && dl_closed==1);
   } else if (!strcmp(mode,"wait_failure_quarantine") || !strcmp(mode,"submit_failure_quarantine")) {
      struct gb_android_image *g=create(source);g->GetFenceStatus=counted_status;
      intentional_d91_retention[0]=g;
      bool submit_failure=!strcmp(mode,"submit_failure_quarantine");
      if (submit_failure) g->QueueSubmit=fail_submit;
      else wait_result=VK_TIMEOUT;
      atomic_store(&gb_image_logs,32); /* Successes cannot hide these failures. */
      assert(!gb_android_image_refresh(g) && g->failed && g->pending);
      assert(fence_queries==1 && atomic_load(&gb_image_diag.pending)==1);
      assert(!gb_android_image_refresh(g) && fence_queries==1);
      assert(atomic_load(&gb_image_diag.refresh_failed)==1 && atomic_load(&gb_image_diag.refresh_skipped)==1);
      gb_android_image_destroy(g);g=NULL; /* No retry or access after transfer. */
      assert(fence_queries==2 && atomic_load(&gb_image_slots)==1);
      assert(atomic_load(&gb_image_diag.active)==0 && atomic_load(&gb_image_diag.quarantined)==1);
      assert(atomic_load(&gb_image_diag.pending)==1 && atomic_load(&gb_image_diag.freed)==0);
      assert(state_record_count==3 && destroyed_images==0 && released==0 && fd_count()==original_fds+1);
      dump();close(source);return 0;
   } else if (!strcmp(mode,"all_quarantined_slot_refusal")) {
      atomic_store(&gb_image_logs,32);wait_result=VK_TIMEOUT;
      for(unsigned i=0;i<8;i++) {
         struct gb_android_image *g=create(source);intentional_d91_retention[i]=g;
         g->GetFenceStatus=counted_status;begins=barriers=0;
         assert(!gb_android_image_refresh(g));gb_android_image_destroy(g);g=NULL;
      }
      assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
      assert(atomic_load(&gb_image_slots)==8 && atomic_load(&gb_image_diag.active)==0);
      assert(atomic_load(&gb_image_diag.pending)==8 && atomic_load(&gb_image_diag.quarantined)==8);
      assert(atomic_load(&gb_image_diag.allocated)==8 && atomic_load(&gb_image_diag.freed)==0);
      assert(state_record_count==25 && fence_queries==16 && fd_count()==original_fds+8);
      dump();close(source);return 0;
   } else if (!strcmp(mode,"independent_bounded_counters")) {
      atomic_store(&gb_image_logs,32);
      atomic_store(&gb_image_diag.refresh_failed,UINT32_MAX-1);
      gb_image_diag_increment(&gb_image_diag.refresh_failed);gb_image_diag_increment(&gb_image_diag.refresh_failed);
      assert(atomic_load(&gb_image_diag.refresh_failed)==UINT32_MAX);
      for(unsigned i=0;i<100;i++) gb_image_diag_failure("test_failure","bounded",-4,true,32,32);
      assert(state_record_count==32 && atomic_load(&gb_image_diag.reports)==32);
      assert(atomic_load(&gb_image_logs)==32 && atomic_load(&gb_image_slots)==0);
   } else if (!strcmp(mode,"renderer_failures")) {
      struct vrend_context ctx={0};struct vrend_resource res={.gb_android_image=(void *)1,.id=71};
      assert(gb_android_resource_read(&ctx,NULL)==0 && !context_errors);
      assert(gb_android_resource_read(&ctx,&res)==EIO && !switch_calls && !bridge_refresh_calls);
      ctx.sub=(void *)1;
      assert(gb_android_resource_read(&ctx,&res)==EIO && switch_calls==1 && !bridge_refresh_calls);
      switch_succeeds=true;
      assert(gb_android_resource_read(&ctx,&res)==EIO && switch_calls==2 && bridge_refresh_calls==1);
      refresh_succeeds=true;
      assert(gb_android_resource_read(&ctx,&res)==0 && context_errors==3 && renderer_record_count==3);
      gb_android_renderer_failure("missing_egl_image",71,EINVAL,true,false);
      for(unsigned i=0;i<100;i++) gb_android_renderer_failure("bounded",71,EIO,true,false);
      assert(renderer_record_count==16 && atomic_load(&gb_android_renderer_diag_reports)==16);
      assert(!state_record_count);
   } else assert(!"unknown scenario");
   assert(fd_count()==original_fds && fcntl(source,F_GETFD)>=0);
   dump();close(source);return 0;
}
