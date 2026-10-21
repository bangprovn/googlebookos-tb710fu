/* SPDX-License-Identifier: Apache-2.0
 * Actual patched bridge and budget helpers with mocked native/GPU functions.
 * Threads exercise the ledger only; active image calls remain serialized.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
static bool test_fail_calloc;
static unsigned test_fault,test_bind_calls;
static uint64_t test_destination_bytes=8192,test_source_bytes,test_before_create_bytes;
static uint64_t expected_teardown_bytes=UINT64_MAX;
static unsigned teardown_probes,allocation_probes;
static void budget_unlocked_probe(void);
static void budget_allocation_probe(uint64_t bytes,bool source_import);
static void budget_ahb_probe(void);
static char state_records[32][1024];static unsigned state_record_count;
static int budget_vsnprintf(char *out,size_t size,const char *format,va_list args)
{
   int n=vsnprintf(out,size,format,args);
   if(n>=0 && (size_t)n<size && !strncmp(out,"GB-ANDROID-IMAGE-STATE:",sizeof("GB-ANDROID-IMAGE-STATE:")-1) && state_record_count<32)
      memcpy(state_records[state_record_count++],out,(size_t)n+1);
   return n;
}
static void *budget_calloc(size_t count,size_t bytes)
{
   if(test_fail_calloc) {test_fail_calloc=false;return NULL;}
   return calloc(count,bytes);
}
#define calloc budget_calloc
#define vsnprintf budget_vsnprintf
#define main legacy_fixture_main
#include "android_image_bridge_mock.c"
#undef main
#undef calloc
#undef vsnprintf

static void budget_unlocked_probe(void)
{
   /* The mock is a driver boundary: accounting must remain charged while it
    * runs, without holding the accounting mutex across external code. */
   assert(pthread_mutex_trylock(&gb_image_budget_lock)==0);
   pthread_mutex_unlock(&gb_image_budget_lock);
   unsigned slots;uint64_t bytes;gb_image_budget_snapshot(&slots,&bytes);
   assert(slots>0 && bytes>0 && bytes<=GB_IMAGE_BACKING_LIMIT);
   if(expected_teardown_bytes!=UINT64_MAX) assert(bytes==expected_teardown_bytes);
   teardown_probes++;
}
static void budget_allocation_probe(uint64_t bytes,bool source_import)
{
   assert(pthread_mutex_trylock(&gb_image_budget_lock)==0);
   pthread_mutex_unlock(&gb_image_budget_lock);
   unsigned slots;uint64_t charged;gb_image_budget_snapshot(&slots,&charged);
   assert(slots>0);
   uint64_t expected=test_before_create_bytes+test_source_bytes+(source_import?GB_IMAGE_LIMIT:test_destination_bytes);
   assert(charged==expected && bytes==(source_import?test_source_bytes:test_destination_bytes));
   allocation_probes++;
}
static void budget_ahb_probe(void)
{
   assert(pthread_mutex_trylock(&gb_image_budget_lock)==0);
   pthread_mutex_unlock(&gb_image_budget_lock);
   unsigned slots;uint64_t bytes;gb_image_budget_snapshot(&slots,&bytes);
   assert(slots>0 && bytes==test_before_create_bytes+test_source_bytes+GB_IMAGE_LIMIT);
}
static uint64_t ledger(unsigned expected_slots)
{
   unsigned slots;uint64_t bytes;gb_image_budget_snapshot(&slots,&bytes);
   assert(slots==expected_slots && bytes<=GB_IMAGE_BACKING_LIMIT);return bytes;
}
static struct gb_android_image *create(int source)
{
   unsigned slots;gb_image_budget_snapshot(&slots,&test_before_create_bytes);
   struct stat info;assert(fstat(source,&info)==0);test_source_bytes=info.st_size;
   test_bind_calls=0;
   return gb_android_image_create(32,32,0x34324241,0,1,source,256,0);
}
static void destroy(struct gb_android_image *image)
{
   unsigned slots;gb_image_budget_snapshot(&slots,&expected_teardown_bytes);
   gb_android_image_destroy(image);expected_teardown_bytes=UINT64_MAX;
}
static void dump(void)
{for(unsigned i=0;i<state_record_count;i++) fputs(state_records[i],stdout);}
static struct gb_android_image *retained_until_exit[16]; /* LSan roots only, never retried. */

struct reserve_call {uint64_t charge;enum gb_image_budget_result result;};
static pthread_barrier_t reserved,release_gate;
static void *reserve_thread(void *opaque)
{
   struct reserve_call *call=opaque;call->result=gb_image_budget_acquire(call->charge);
   pthread_barrier_wait(&reserved);pthread_barrier_wait(&release_gate);
   if(call->result==GB_IMAGE_BUDGET_OK) assert(gb_image_budget_release(call->charge));
   return NULL;
}
static void contention(uint64_t charge,unsigned admitted,enum gb_image_budget_result refused)
{
   assert(pthread_barrier_init(&reserved,NULL,33)==0 && pthread_barrier_init(&release_gate,NULL,33)==0);
   struct reserve_call calls[32];pthread_t threads[32];
   for(unsigned i=0;i<32;i++) {calls[i]=(struct reserve_call){.charge=charge};assert(pthread_create(&threads[i],NULL,reserve_thread,&calls[i])==0);}
   pthread_barrier_wait(&reserved);
   unsigned success=0,failures=0;
   for(unsigned i=0;i<32;i++) {if(calls[i].result==GB_IMAGE_BUDGET_OK) success++;else {assert(calls[i].result==refused);failures++;}}
   assert(success==admitted && failures==32-admitted && ledger(admitted)==charge*admitted);
   pthread_barrier_wait(&release_gate);
   for(unsigned i=0;i<32;i++) assert(pthread_join(threads[i],NULL)==0);
   assert(ledger(0)==0);pthread_barrier_destroy(&reserved);pthread_barrier_destroy(&release_gate);
}
int main(int argc,char **argv)
{
   assert(argc==2 && GB_IMAGE_SLOTS==16 && GB_IMAGE_BACKING_LIMIT==536870912ull);
   assert(setenv("GB_ANDROID_IMAGE_BRIDGE_V1","diagnostic-linear-v1",1)==0);
   int source=memfd_create("owned-budget-source",MFD_CLOEXEC);assert(source>=0 && ftruncate(source,8192)==0);
   unsigned original_fds=fd_count();successful_imports=true;
   const char *mode=argv[1];
   if(!strcmp(mode,"sixteen_small")) {
      struct gb_android_image *live[16];
      for(unsigned i=0;i<16;i++) {live[i]=create(source);assert(live[i] && live[i]->backing_charge==16384 && ledger(i+1)==(i+1)*16384);}
      atomic_store(&gb_image_logs,32);
      assert(!create(source) && ledger(16)==16*16384 && atomic_load(&gb_image_diag.slot_refused)==1);
      assert(atomic_load(&gb_image_diag.backing_refused)==0 && fd_count()==original_fds+16);
      for(unsigned i=0;i<16;i+=2) {destroy(live[i]);live[i]=NULL;}
      for(unsigned i=0;i<16;i+=2) {live[i]=create(source);assert(live[i]);}
      for(unsigned i=0;i<16;i++) destroy(live[i]);
      assert(ledger(0)==0 && atomic_load(&gb_image_diag.active)==0);
      assert(atomic_load(&gb_image_diag.allocated)==24 && atomic_load(&gb_image_diag.freed)==24);
   } else if(!strcmp(mode,"eight_maximum")) {
      assert(ftruncate(source,GB_IMAGE_LIMIT)==0);test_destination_bytes=GB_IMAGE_LIMIT;
      struct gb_android_image *live[8];
      for(unsigned i=0;i<8;i++) {live[i]=create(source);assert(live[i] && live[i]->backing_charge==2ull*GB_IMAGE_LIMIT);}
      assert(ledger(8)==GB_IMAGE_BACKING_LIMIT);
      atomic_store(&gb_image_logs,32);
      assert(!create(source) && ledger(8)==GB_IMAGE_BACKING_LIMIT);
      assert(atomic_load(&gb_image_diag.backing_refused)==1 && atomic_load(&gb_image_diag.slot_refused)==0);
      destroy(live[0]);live[0]=create(source);assert(live[0] && ledger(8)==GB_IMAGE_BACKING_LIMIT);
      for(unsigned i=0;i<8;i++) destroy(live[i]);
      assert(ledger(0)==0);
   } else if(!strcmp(mode,"full_fd_not_requirements")) {
      assert(ftruncate(source,GB_IMAGE_LIMIT)==0);
      struct gb_android_image *image=create(source);assert(image);
      /* Mock vkGetImageMemoryRequirements remains8192 while imported FD is32MiB. */
      assert(image->backing_charge==GB_IMAGE_LIMIT+8192ull && ledger(1)==GB_IMAGE_LIMIT+8192ull);
      assert(allocation_probes==2);destroy(image);assert(ledger(0)==0);
   } else if(!strncmp(mode,"rollback_",9)) {
      if(!strcmp(mode,"rollback_calloc")) test_fail_calloc=true;
      else if(!strcmp(mode,"rollback_loader")) successful_imports=false;
      else test_fault=(unsigned)strtoul(mode+9,NULL,10);
      assert(!create(source) && ledger(0)==0);
      assert(atomic_load(&gb_image_diag.active)==0 && atomic_load(&gb_image_diag.pending)==0 && atomic_load(&gb_image_diag.quarantined)==0);
      assert(fd_count()==original_fds);
      if(strcmp(mode,"rollback_calloc")) assert(teardown_probes>0);
   } else if(!strcmp(mode,"quarantine_holds_both_quotas")) {
      struct gb_android_image *image=create(source);assert(image);retained_until_exit[0]=image;
      wait_result=VK_TIMEOUT;begins=barriers=0;
      assert(!gb_android_image_refresh(image) && image->pending && image->failed);
      destroy(image);image=NULL;
      assert(ledger(1)==16384 && atomic_load(&gb_image_diag.quarantined)==1 && atomic_load(&gb_image_diag.active)==0);
      assert(atomic_load(&gb_image_diag.pending)==1 && teardown_probes==0 && fd_count()==original_fds+1);
      dump();close(source);return 0;
   } else if(!strcmp(mode,"quarantined_maximum_prevents_new_admission")) {
      assert(ftruncate(source,GB_IMAGE_LIMIT)==0);test_destination_bytes=GB_IMAGE_LIMIT;
      for(unsigned i=0;i<8;i++) {
         struct gb_android_image *image=create(source);assert(image);
         retained_until_exit[i]=image;
         wait_result=VK_TIMEOUT;status=VK_NOT_READY;begins=barriers=0;
         assert(!gb_android_image_refresh(image) && image->pending && image->failed);
         destroy(image);image=NULL;
      }
      assert(ledger(8)==GB_IMAGE_BACKING_LIMIT && atomic_load(&gb_image_diag.quarantined)==8);
      assert(atomic_load(&gb_image_diag.active)==0 && atomic_load(&gb_image_diag.pending)==8);
      assert(teardown_probes==0 && fd_count()==original_fds+8);
      assert(!create(source) && ledger(8)==GB_IMAGE_BACKING_LIMIT);
      assert(atomic_load(&gb_image_diag.backing_refused)==1);
      dump();close(source);return 0;
   } else if(!strcmp(mode,"bounded_failure_records")) {
      struct gb_android_image *live[16];
      for(unsigned i=0;i<16;i++) {live[i]=create(source);assert(live[i]);}
      atomic_store(&gb_image_logs,32);
      for(unsigned i=0;i<40;i++) assert(!create(source));
      assert(atomic_load(&gb_image_diag.reports)==32 && atomic_load(&gb_image_diag.slot_refused)==40);
      assert(state_record_count==32 && ledger(16)==16*16384);
      for(unsigned i=0;i<16;i++) destroy(live[i]);
      assert(ledger(0)==0);
   } else if(!strcmp(mode,"reservation_shrink_and_invalid_operations")) {
      assert(gb_image_budget_acquire(64ull*1024*1024)==GB_IMAGE_BUDGET_OK);
      assert(!gb_image_budget_shrink(64ull*1024*1024,65ull*1024*1024));
      assert(!gb_image_budget_release(65ull*1024*1024) && ledger(1)==64ull*1024*1024);
      assert(gb_image_budget_shrink(64ull*1024*1024,16384) && ledger(1)==16384);
      assert(gb_image_budget_release(16384) && ledger(0)==0);
      assert(!gb_image_budget_release(16384) && ledger(0)==0);
   } else if(!strcmp(mode,"concurrent_pair_reservations")) {
      /* Scalar ledger helper stress only; no concurrent Vulkan/active APIs. */
      contention(16ull*1024*1024,16,GB_IMAGE_BUDGET_SLOTS);
      contention(64ull*1024*1024,8,GB_IMAGE_BUDGET_BYTES);
      assert(!allocation_probes && !teardown_probes);
   } else assert(!"unknown scenario");
   assert(ledger(0)==0 && fd_count()==original_fds && fcntl(source,F_GETFD)>=0);
   dump();close(source);puts("PASS backing ledger (mock GPU only)");return 0;
}
