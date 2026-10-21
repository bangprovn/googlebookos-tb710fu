/* SPDX-License-Identifier: Apache-2.0
 * Actual bridge ownership/reaper code with mocked GPU functions and real owned
 * Linux descriptors. ACTIVE calls stay serialized as required by virglrenderer.
 * Threads exercise registry reaper contention only, never the GL-owner API.
 */
#define main legacy_fixture_main
#include "android_image_bridge_mock.c"
#undef main
#include <pthread.h>
#include <time.h>

static atomic_int deferred_status=VK_NOT_READY;
static atomic_uint deferred_queries;
static pthread_mutex_t probe_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t probe_cond=PTHREAD_COND_INITIALIZER;
static bool gate_enabled,gate_entered,gate_released;

static VKAPI_ATTR VkResult VKAPI_CALL deferred_fence_status(VkDevice device,VkFence fence)
{
   assert(device && fence);atomic_fetch_add(&deferred_queries,1);
   pthread_mutex_lock(&probe_mutex);
   if (gate_enabled && !gate_entered) {
      gate_entered=true;pthread_cond_broadcast(&probe_cond);
      while (!gate_released) pthread_cond_wait(&probe_cond,&probe_mutex);
   }
   pthread_mutex_unlock(&probe_mutex);
   return atomic_load(&deferred_status);
}

static unsigned registry_count(enum gb_image_owner owner)
{
   unsigned count=0;
   pthread_mutex_lock(&gb_image_registry_lock);
   for (unsigned i=0;i<GB_IMAGE_SLOTS;i++) if (gb_image_registry[i].owner==owner) count++;
   pthread_mutex_unlock(&gb_image_registry_lock);
   return count;
}

static void verify_quarantined_backing(void)
{
   pthread_mutex_lock(&gb_image_registry_lock);
   for (unsigned i=0;i<GB_IMAGE_SLOTS;i++) {
      if (gb_image_registry[i].owner!=GB_IMAGE_QUARANTINED) continue;
      /* Read only the registry-owned pointer, never a relinquished caller's. */
      struct gb_android_image *g=gb_image_registry[i].image;
      assert(g && g->pending && g->failed);
      assert(g->instance && g->device && g->queue && g->fence && g->pool && g->command);
      assert(g->source && g->destination && g->source_memory && g->destination_memory);
      assert(g->ahb && g->native_library && g->release && g->DestroyDevice);
      assert(g->sync_fd>=0 && fcntl(g->sync_fd,F_GETFD)>=0 && g->import_fd==-1);
   }
   pthread_mutex_unlock(&gb_image_registry_lock);
}

/* After destroy, callers retain only numeric observations, never the pointer. */
static int submit_timeout_and_transfer(int source,bool missing_query)
{
   struct gb_android_image *g=gb_android_image_create(32,32,0x34324241,0,1,source,256,0);
   assert(g);g->GetFenceStatus=deferred_fence_status;
   int owned_fd=g->sync_fd;
   wait_result=VK_TIMEOUT;atomic_store(&deferred_status,VK_NOT_READY);
   begins=barriers=0; /* The reused base mock's barrier checks are per image. */
   assert(!gb_android_image_refresh(g) && g->failed && g->pending);
   if (missing_query) g->GetFenceStatus=NULL;
   gb_android_image_destroy(g);
   /* The complete object is now reachable only through its owning registry. */
   assert(fcntl(owned_fd,F_GETFD)>=0);
   verify_quarantined_backing();
   return owned_fd;
}

static void *reap_thread(void *value)
{
   unsigned *result=value;*result=gb_android_image_reap();return NULL;
}

static void wait_for_probe(void)
{
   struct timespec deadline;assert(clock_gettime(CLOCK_REALTIME,&deadline)==0);deadline.tv_sec+=3;
   pthread_mutex_lock(&probe_mutex);
   while (!gate_entered) assert(pthread_cond_timedwait(&probe_cond,&probe_mutex,&deadline)==0);
   pthread_mutex_unlock(&probe_mutex);
}

int main(int argc,char **argv)
{
   assert(argc==2 && GB_IMAGE_SLOTS==8);
   assert(setenv("GB_ANDROID_IMAGE_BRIDGE_V1","diagnostic-linear-v1",1)==0);
   int source=memfd_create("owned-quarantine-source",MFD_CLOEXEC);
   assert(source>=0 && ftruncate(source,8192)==0);
   int unrelated=dup(source);assert(unrelated>=0);
   unsigned original_fds=fd_count();successful_imports=true;
   const char *mode=argv[1];
   if (!strcmp(mode,"capacity_and_fd_cleanup")) {
      successful_imports=false;
      successful_overlap_lifecycle(source,unrelated);
      assert(atomic_load(&gb_image_slots)==0 && registry_count(GB_IMAGE_FREE)==8);
   } else if (!strcmp(mode,"loader_failure_rolls_back_registry")) {
      successful_imports=false;
      for(unsigned i=0;i<16;i++) {
         assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
         assert(atomic_load(&gb_image_slots)==0 && registry_count(GB_IMAGE_FREE)==8);
         assert(fd_count()==original_fds);
      }
      assert(unloads==16 && dl_count==16 && dl_closed==16 && released==0);
      assert(destroyed_images==0 && freed_memory==0 && destroyed_device==0);
   } else if (!strcmp(mode,"completed_after_owner_disappears")) {
      int owned_fd=submit_timeout_and_transfer(source,false);
      assert(registry_count(GB_IMAGE_QUARANTINED)==1 && atomic_load(&gb_image_slots)==1);
      unsigned before=atomic_load(&deferred_queries);
      assert(gb_android_image_reap()==0 && atomic_load(&deferred_queries)==before+1);
      assert(fcntl(owned_fd,F_GETFD)>=0 && registry_count(GB_IMAGE_QUARANTINED)==1);
      verify_quarantined_backing();
      atomic_store(&deferred_status,VK_SUCCESS);
      assert(gb_android_image_reap()==1 && atomic_load(&deferred_queries)==before+2);
      assert(atomic_load(&gb_image_slots)==0 && registry_count(GB_IMAGE_FREE)==8);
      assert(fcntl(owned_fd,F_GETFD)==-1 && errno==EBADF);
      assert(destroyed_images==2 && freed_memory==2 && released==1 && unloads==1 && dl_closed==1);
      assert(gb_android_image_reap()==0 && atomic_load(&deferred_queries)==before+2);
   } else if (!strcmp(mode,"admission_reaps_completed_quarantine")) {
      submit_timeout_and_transfer(source,false);
      atomic_store(&deferred_status,VK_SUCCESS);
      struct gb_android_image *fresh=gb_android_image_create(32,32,0x34324241,0,1,source,256,0);
      assert(fresh && registry_count(GB_IMAGE_QUARANTINED)==0 && registry_count(GB_IMAGE_ACTIVE)==1);
      assert(atomic_load(&gb_image_slots)==1 && released==1 && fd_count()==original_fds+1);
      gb_android_image_destroy(fresh);
      assert(atomic_load(&gb_image_slots)==0 && registry_count(GB_IMAGE_FREE)==8 && released==2);
   } else if (!strcmp(mode,"contended_reapers_claim_once")) {
      int owned[8];for(unsigned i=0;i<8;i++) owned[i]=submit_timeout_and_transfer(source,false);
      assert(registry_count(GB_IMAGE_QUARANTINED)==8 && atomic_load(&gb_image_slots)==8);
      verify_quarantined_backing();
      unsigned before=atomic_load(&deferred_queries);
      atomic_store(&deferred_status,VK_SUCCESS);gate_enabled=true;
      unsigned first=99;pthread_t owner;assert(pthread_create(&owner,NULL,reap_thread,&first)==0);
      wait_for_probe();assert(registry_count(GB_IMAGE_REAPING)==1);
      pthread_t contenders[15];unsigned results[15];
      for(unsigned i=0;i<15;i++) {results[i]=99;assert(pthread_create(&contenders[i],NULL,reap_thread,&results[i])==0);}
      for(unsigned i=0;i<15;i++) {assert(pthread_join(contenders[i],NULL)==0);assert(results[i]==0);}
      assert(atomic_load(&deferred_queries)==before+1 && atomic_load(&gb_image_slots)==8);
      pthread_mutex_lock(&probe_mutex);gate_released=true;pthread_cond_broadcast(&probe_cond);pthread_mutex_unlock(&probe_mutex);
      assert(pthread_join(owner,NULL)==0 && first==8);
      assert(atomic_load(&deferred_queries)==before+8 && atomic_load(&gb_image_slots)==0);
      assert(registry_count(GB_IMAGE_FREE)==8 && destroyed_images==16 && freed_memory==16 && released==8);
      for(unsigned i=0;i<8;i++) assert(fcntl(owned[i],F_GETFD)==-1 && errno==EBADF);
      assert(gb_android_image_reap()==0 && atomic_load(&deferred_queries)==before+8);
   } else if (!strcmp(mode,"device_lost_stays_bounded") || !strcmp(mode,"missing_query_stays_bounded")) {
      bool missing=!strcmp(mode,"missing_query_stays_bounded");
      for(unsigned i=0;i<8;i++) submit_timeout_and_transfer(source,missing);
      atomic_store(&deferred_status,VK_ERROR_DEVICE_LOST);
      unsigned before=atomic_load(&deferred_queries);
      assert(gb_android_image_reap()==0);
      assert(atomic_load(&deferred_queries)==before+(missing?0:8));
      assert(registry_count(GB_IMAGE_QUARANTINED)==8 && atomic_load(&gb_image_slots)==8);
      verify_quarantined_backing();
      assert(!gb_android_image_create(32,32,0x34324241,0,1,source,256,0));
      assert(atomic_load(&gb_image_slots)==8 && registry_count(GB_IMAGE_QUARANTINED)==8);
      assert(destroyed_images==0 && freed_memory==0 && released==0 && fd_count()==original_fds+8);
      /* Intentionally retained, globally reachable resources last to process
       * exit. Do not restore a function pointer or retry a relinquished g. */
      close(source);close(unrelated);
      puts("PASS: unresolved work retains eight complete registry-owned images (mock GPU only)");return 0;
   } else {assert(!"unknown scenario");}
   assert(fd_count()==original_fds && fcntl(source,F_GETFD)>=0 && fcntl(unrelated,F_GETFD)>=0);
   close(source);close(unrelated);
   puts("PASS: registry ownership, bounded nonwaiting reaping and FD cleanup (mock GPU only)");return 0;
}
