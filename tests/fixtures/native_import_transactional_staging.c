/* SPDX-License-Identifier: Apache-2.0
 * Actual import/detach/resource lifetime functions are inserted by the host
 * harness. Native allocation, GL/EGL and hash tables are stand-ins. Owned real
 * Linux FDs exercise original-vs-duplicated ownership and FD-reuse safety.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "virgl_resource.h"

struct list_head {struct list_head *next,*prev;};
static unsigned list_removals;
static void list_inithead(struct list_head *h) {h->next=h->prev=h;}
static void list_add(struct list_head *n,struct list_head *h) {n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
static void list_del(struct list_head *n) {n->next->prev=n->prev;n->prev->next=n->next;list_removals++;}
#define LIST_FOR_EACH_ENTRY(p,h,m) for(struct list_head *node=(h)->next;node!=(h) && ((p)=(void *)((char *)node- offsetof(__typeof__(*(p)),m)),1);node=node->next)
#define LIST_FOR_EACH_ENTRY_SAFE(p,t,h,m) for(struct list_head *node=(h)->next,*next_node=node->next;node!=(h) && ((p)=(void *)((char *)node- offsetof(__typeof__(*(p)),m)),(t)=next_node!=(h)?(void *)((char *)next_node- offsetof(__typeof__(*(t)),m)):NULL,(void)(t),1);node=next_node,next_node=node->next)
enum pipe_error {PIPE_OK,PIPE_ERROR_OUT_OF_MEMORY};
struct util_hash_table {void *values[16];uintptr_t keys[16];unsigned n;bool fail;};
static struct util_hash_table globals;
static struct util_hash_table *virgl_resource_table=&globals;
static void *uintptr_to_pointer(uintptr_t p) {return (void *)p;}
static enum pipe_error util_hash_table_set(struct util_hash_table *h,void *key,void *value) {
 if(h->fail) return PIPE_ERROR_OUT_OF_MEMORY;
 for(unsigned i=0;i<h->n;i++) if(h->keys[i]==(uintptr_t)key) {h->values[i]=value;return PIPE_OK;}
 assert(h->n<16);h->keys[h->n]=(uintptr_t)key;h->values[h->n++]=value;return PIPE_OK;
}
struct pipe_resource {uint32_t format,width,height;};
struct virgl_context {uint32_t ctx_id;};
struct vrend_resource {struct pipe_resource base;void *egl_image,*gb_android_image;unsigned storage_bits,id;};
struct vrend_untyped_resource {struct list_head head;struct virgl_resource *resource;};
struct vrend_context {struct virgl_resource *untyped_resource_cache;struct list_head untyped_resources;struct util_hash_table *res_hash;void *sub;bool in_error;};
static unsigned close_counts[4096];
static int counted_close(int fd) {assert(fd>=0 && fd<4096);close_counts[fd]++;return close(fd);}
#define close counted_close
static unsigned context_errors,creates,bridge_calls,texture_calls,bridge_destroys,egl_destroys,gl_deleted,gl_finishes,unrefs;
static void vrend_printf(const char *f,...) {(void)f;}
static void gb_android_renderer_failure(const char *e,uint32_t id,int r,bool s,bool w) {(void)e;(void)id;(void)r;(void)s;(void)w;}
enum {VIRGL_ERROR_CTX_ILLEGAL_RESOURCE=1};
static void vrend_report_context_error(struct vrend_context *ctx,unsigned error,unsigned id) {assert(error==VIRGL_ERROR_CTX_ILLEGAL_RESOURCE);(void)id;context_errors++;ctx->in_error=true;}
static struct vrend_resource *vrend_renderer_ctx_res_lookup(struct vrend_context *ctx,int id) {
 for(unsigned i=0;i<ctx->res_hash->n;i++) {
  if(ctx->res_hash->keys[i]==(uintptr_t)id) return ctx->res_hash->values[i];
 }
 return NULL;
}
static void vrend_ctx_resource_insert(struct util_hash_table *h,uint32_t id,struct vrend_resource *r) {(void)util_hash_table_set(h,uintptr_to_pointer(id),r);}
static void vrend_ctx_resource_remove(struct util_hash_table *h,uint32_t id) {
 for(unsigned i=0;i<h->n;i++) if(h->keys[i]==id) {h->values[i]=NULL;return;}
}
#define PIPE_TEXTURE_2D 2
#define VIRGL_GBM_MAX_PLANES 4
#define VREND_STORAGE_EGL_IMAGE 1
#define VREND_STORAGE_GL_TEXTURE 2
#define VIRGL_FORMAT_R8G8B8A8_UNORM 1
#define VIRGL_FORMAT_B8G8R8A8_UNORM 2
#define VIRGL_FORMAT_R8G8B8X8_UNORM 3
#define VIRGL_FORMAT_B8G8R8X8_UNORM 4
#define FREE(p) free(p)
#define HAVE_EPOXY_EGL_H 1
struct vrend_renderer_resource_create_args {unsigned target,format,bind,width,height,depth,array_size,last_level,nr_samples,flags;};
struct vrend_renderer_resource_set_type_args {unsigned plane_count,format,bind,width,height;uint64_t modifier;uint32_t plane_strides[4],plane_offsets[4];};
enum fault {NONE,CONSTRUCTOR,FORMAT,OPAQUE_REFUSAL,PENDING_NULL,TEXTURE_RETIRED,TEXTURE_PENDING};
static enum fault fault;
static bool android_bridge=true;
struct native_backing {int duplicate_fd;};
static struct native_backing *quarantine; /* Root only: never retried or reclaimed. */
static int quarantine_fd=-1;
static int opaque_quarantine_fd=-1;
static void *egl=(void *)1;
static struct vrend_resource *vrend_resource_create(const struct vrend_renderer_resource_create_args *a) {
 creates++;if(fault==CONSTRUCTOR) return NULL;
 struct vrend_resource *r=calloc(1,sizeof(*r));assert(r);r->base.format=a->format;r->base.width=a->width;r->base.height=a->height;return r;
}
static int virgl_gbm_convert_format(uint32_t *v,uint32_t *d) {*d=*v;return fault==FORMAT;}
static bool virgl_egl_android_bridge_required(void *e) {assert(e==egl);return android_bridge;}
static void *virgl_egl_image_from_android_bridge(void *e,uint32_t w,uint32_t h,uint32_t format,uint64_t modifier,uint32_t planes,int fd,uint32_t stride,uint32_t offset,void **out) {
 assert(e==egl && w && h && format && !modifier && planes && stride && !offset);bridge_calls++;*out=NULL;
 if(fault==OPAQUE_REFUSAL) return NULL;
 if(fault==PENDING_NULL) {opaque_quarantine_fd=fcntl(fd,F_DUPFD_CLOEXEC,3);assert(opaque_quarantine_fd>=0);return NULL;}
 struct native_backing *b=calloc(1,sizeof(*b));assert(b);b->duplicate_fd=fcntl(fd,F_DUPFD_CLOEXEC,3);assert(b->duplicate_fd>=0);*out=b;return (void *)2;
}
static void *virgl_egl_image_from_dmabuf(void *e,uint32_t w,uint32_t h,uint32_t format,uint64_t modifier,uint32_t planes,int *fds,const uint32_t *strides,const uint32_t *offsets) {
 assert(e==egl && w && h && format && !modifier && planes && fds && strides && offsets);bridge_calls++;return (void *)2;
}
static int vrend_resource_alloc_texture(struct vrend_resource *r,uint32_t format,void *image) {
 assert(format && image);texture_calls++;r->storage_bits|=VREND_STORAGE_GL_TEXTURE;r->id=17;
 return fault==TEXTURE_RETIRED || fault==TEXTURE_PENDING?EIO:0;
}
static void glDeleteTextures(unsigned n,unsigned *id) {assert(n==1 && *id==17);gl_deleted++;}
static void virgl_egl_image_destroy(void *e,void *image) {assert(e==egl && image==(void *)2);egl_destroys++;}
static void virgl_egl_android_bridge_destroy(void *opaque) {
 struct native_backing *b=opaque;assert(b);bridge_destroys++;
 if(fault==TEXTURE_PENDING) {quarantine_fd=b->duplicate_fd;quarantine=b;return;}
 assert(close(b->duplicate_fd)==0);free(b);
}
static void glFinish(void) {gl_finishes++;}
static void unref_pipe(struct pipe_resource *p,void *unused) {
 (void)unused;struct vrend_resource *r=(void *)p;unrefs++;
 if(r->egl_image) virgl_egl_image_destroy(egl,r->egl_image);
 if(r->gb_android_image) virgl_egl_android_bridge_destroy(r->gb_android_image);
 free(r);
}
static struct virgl_resource_pipe_callbacks pipe_callbacks={.unref=unref_pipe};
// ACTUAL_RESOURCE_CONSTRUCTOR
// ACTUAL_RESOURCE_FROM_PIPE
// ACTUAL_RESOURCE_FROM_FD
// ACTUAL_RESOURCE_FROM_OPAQUE
// ACTUAL_RESOURCE_DESTRUCTOR
// ACTUAL_SET_TYPE
// ACTUAL_DETACH
static struct virgl_resource *resource(unsigned id) {
 int fd=memfd_create("owned-import-transaction",MFD_CLOEXEC);assert(fd>=0 && ftruncate(fd,8192)==0);
 struct virgl_resource *r=virgl_resource_create_from_fd(id,VIRGL_RESOURCE_FD_DMABUF,fd,NULL,0,NULL);
 assert(r && !r->vrend_native_import_blocked);return r;
}
static void attach(struct vrend_context *ctx,struct virgl_resource *r,bool listed) {
 if(listed) {struct vrend_untyped_resource *w=calloc(1,sizeof(*w));assert(w);w->resource=r;list_add(&w->head,&ctx->untyped_resources);}
 else ctx->untyped_resource_cache=r;
}
static bool retained(struct vrend_context *ctx,struct virgl_resource *r) {
 if(ctx->untyped_resource_cache==r) return true;
 struct vrend_untyped_resource *w;LIST_FOR_EACH_ENTRY(w,&ctx->untyped_resources,head) {if(w->resource==r) return true;}return false;
}
static int attempt(struct vrend_context *ctx,struct virgl_resource *r) {
 struct vrend_renderer_resource_set_type_args args={.plane_count=1,.format=1,.bind=1,.width=32,.height=32,.plane_strides={256}};
 return vrend_renderer_pipe_resource_set_type(ctx,r->res_id,&args);
}
static void init_context(struct vrend_context *ctx,struct util_hash_table *hash) {memset(ctx,0,sizeof(*ctx));ctx->res_hash=hash;ctx->sub=(void *)1;list_inithead(&ctx->untyped_resources);}
static void release_resource(struct vrend_context *ctx,struct virgl_resource *r) {vrend_renderer_detach_res_ctx(ctx,r);assert(!retained(ctx,r));virgl_resource_destroy_func(r);}
int main(int argc,char **argv) {
 assert(argc==3);bool listed=!strcmp(argv[2],"list");const char *scenario=argv[1];
 assert(setenv("GB_NATIVE_IMPORT_TXN_V1",!strcmp(scenario,"legacy")?"disabled":"retain-untyped-v1",1)==0);
 struct util_hash_table hash={0};struct vrend_context ctx;init_context(&ctx,&hash);
 struct virgl_resource *r=resource(59);int original=r->fd;attach(&ctx,r,listed);
 if(!strcmp(scenario,"success") || !strcmp(scenario,"dmabuf")) {
  if(!strcmp(scenario,"dmabuf")) android_bridge=false;
  assert(attempt(&ctx,r)==0 && !retained(&ctx,r) && r->pipe_resource && r->fd==-1 && !r->vrend_native_import_blocked);
  assert(close_counts[original]==1 && creates==1 && bridge_calls==1);
  assert(attempt(&ctx,r)==0 && creates==1 && bridge_calls==1);
  // Legacy already-typed attachment does not certify changed type metadata.
  struct vrend_renderer_resource_set_type_args changed={.plane_count=1,.format=2,.width=64,.height=64,.plane_strides={512}};
  assert(vrend_renderer_pipe_resource_set_type(&ctx,r->res_id,&changed)==0);
  assert(r->pipe_resource->format==1 && r->pipe_resource->width==32 && r->pipe_resource->height==32 && bridge_calls==1);
  int sentinel=memfd_create("owned-fd-reuse-sentinel",MFD_CLOEXEC);assert(sentinel>=0);
  release_resource(&ctx,r);assert(unrefs==1 && fcntl(sentinel,F_GETFD)>=0);assert(close(sentinel)==0);
 } else if(!strcmp(scenario,"constructor") || !strcmp(scenario,"format")) {
  fault=!strcmp(scenario,"constructor")?CONSTRUCTOR:FORMAT;
  assert(attempt(&ctx,r)!=0 && retained(&ctx,r) && !r->vrend_native_import_blocked && !r->pipe_resource);
  assert(bridge_calls==0 && fcntl(original,F_GETFD)>=0 && close_counts[original]==0);
  fault=NONE;assert(attempt(&ctx,r)==0 && creates==2);release_resource(&ctx,r);assert(close_counts[original]==1);
 } else if(!strcmp(scenario,"refusal") || !strcmp(scenario,"pending_null") || !strcmp(scenario,"texture") || !strcmp(scenario,"texture_pending") || !strcmp(scenario,"legacy")) {
  fault=(!strcmp(scenario,"pending_null"))?PENDING_NULL:(!strcmp(scenario,"texture"))?TEXTURE_RETIRED:(!strcmp(scenario,"texture_pending"))?TEXTURE_PENDING:OPAQUE_REFUSAL;
  assert(attempt(&ctx,r)!=0 && !r->pipe_resource && fcntl(original,F_GETFD)>=0);
  bool legacy=!strcmp(scenario,"legacy");assert(retained(&ctx,r)==!legacy);
  assert(r->vrend_native_import_blocked==!legacy);
  // Changing mode after failure cannot bypass the per-resource native guard.
  if(!legacy) {assert(attempt(&ctx,r)==EINVAL && bridge_calls==1);assert(setenv("GB_NATIVE_IMPORT_TXN_V1","disabled",1)==0);}
  assert(attempt(&ctx,r)==EINVAL && bridge_calls==1);
  release_resource(&ctx,r);assert(close_counts[original]==1);
  if(fault==PENDING_NULL) {assert(opaque_quarantine_fd>=0 && fcntl(opaque_quarantine_fd,F_GETFD)>=0);return 0;}
  if(fault==TEXTURE_PENDING) {assert(quarantine_fd>=0 && fcntl(quarantine_fd,F_GETFD)>=0 && bridge_destroys==1);return 0;}
  if(fault==TEXTURE_RETIRED) assert(bridge_destroys==1 && egl_destroys==1 && gl_deleted==1);
 } else if(!strcmp(scenario,"hash_retry_refused") || !strcmp(scenario,"hash_teardown")) {
  hash.fail=true;assert(attempt(&ctx,r)==ENOMEM && retained(&ctx,r) && r->pipe_resource && r->fd==-1);
  assert(creates==1 && bridge_calls==1 && close_counts[original]==1);
  if(!strcmp(scenario,"hash_retry_refused")) {
   hash.fail=false;assert(attempt(&ctx,r)==EINVAL && retained(&ctx,r) && r->vrend_native_import_blocked);
   struct vrend_renderer_resource_set_type_args changed={.plane_count=1,.format=2,.width=64,.height=64,.plane_strides={512}};
   assert(vrend_renderer_pipe_resource_set_type(&ctx,r->res_id,&changed)==EINVAL);
   assert(r->pipe_resource->format==1 && r->pipe_resource->width==32 && r->pipe_resource->height==32 && creates==1 && bridge_calls==1);
  }
  release_resource(&ctx,r);assert(unrefs==1 && close_counts[original]==1);
 } else if(!strcmp(scenario,"factory_initialization")) {
  struct vrend_resource *pipe=calloc(1,sizeof(*pipe));assert(pipe);pipe->base.format=1;
  struct virgl_resource *from_pipe=virgl_resource_create_from_pipe(60,&pipe->base,NULL,0);
  assert(from_pipe && !from_pipe->vrend_native_import_blocked && from_pipe->fd==-1);
  struct virgl_context owner={.ctx_id=9};
  struct virgl_resource *opaque=virgl_resource_create_from_opaque_handle(&owner,61,71);
  assert(opaque && !opaque->vrend_native_import_blocked && opaque->fd==-1 && opaque->opaque_handle_context_id==9);
  virgl_resource_destroy_func(from_pipe);virgl_resource_destroy_func(opaque);
  release_resource(&ctx,r);assert(unrefs==1 && close_counts[original]==1);
 } else if(!strcmp(scenario,"cross_context")) {
  struct util_hash_table other_hash={0};struct vrend_context other;init_context(&other,&other_hash);attach(&other,r,!listed);
  assert(attempt(&ctx,r)==0 && retained(&other,r));
  vrend_renderer_detach_res_ctx(&other,r);assert(!retained(&other,r));
  release_resource(&ctx,r);assert(unrefs==1 && close_counts[original]==1);
 } else if(!strcmp(scenario,"cross_context_hash_failure")) {
  struct util_hash_table other_hash={.fail=true};struct vrend_context other;init_context(&other,&other_hash);attach(&other,r,!listed);
  assert(attempt(&ctx,r)==0 && retained(&other,r) && !r->vrend_native_import_blocked);
  assert(attempt(&other,r)==ENOMEM && retained(&other,r) && r->vrend_native_import_blocked);
  other_hash.fail=false;assert(attempt(&other,r)==EINVAL);
  struct vrend_renderer_resource_set_type_args changed={.plane_count=1,.format=2,.width=64,.height=64,.plane_strides={512}};
  assert(vrend_renderer_pipe_resource_set_type(&other,r->res_id,&changed)==EINVAL);
  assert(r->pipe_resource->format==1 && r->pipe_resource->width==32 && r->pipe_resource->height==32 && creates==1 && bridge_calls==1);
  vrend_renderer_detach_res_ctx(&other,r);assert(!retained(&other,r));
  release_resource(&ctx,r);assert(unrefs==1 && close_counts[original]==1);
 } else if(!strcmp(scenario,"duplicate_attachments")) {
  attach(&ctx,r,true);attach(&ctx,r,true);
  assert(attempt(&ctx,r)==0);
  release_resource(&ctx,r);assert(unrefs==1 && close_counts[original]==1 && ctx.untyped_resources.next==&ctx.untyped_resources);
 } else if(!strcmp(scenario,"fd_type")) {
  r->fd_type=VIRGL_RESOURCE_FD_SHM;assert(attempt(&ctx,r)==EINVAL && retained(&ctx,r) && !r->vrend_native_import_blocked);
  assert(creates==0 && bridge_calls==0);release_resource(&ctx,r);assert(close_counts[original]==1);
 } else if(!strcmp(scenario,"unsupported_format")) {
  struct vrend_renderer_resource_set_type_args args={.plane_count=1,.format=999,.width=32,.height=32,.plane_strides={256}};
  assert(vrend_renderer_pipe_resource_set_type(&ctx,r->res_id,&args)==EINVAL && retained(&ctx,r) && !r->vrend_native_import_blocked);
  assert(creates==1 && bridge_calls==0);release_resource(&ctx,r);assert(close_counts[original]==1);
 } else if(!strcmp(scenario,"missing_and_bad_plane")) {
  struct vrend_renderer_resource_set_type_args args={.plane_count=0};
  assert(vrend_renderer_pipe_resource_set_type(&ctx,r->res_id,&args)==EINVAL && retained(&ctx,r));
  args.plane_count=1;assert(vrend_renderer_pipe_resource_set_type(&ctx,999,&args)==EINVAL && context_errors==1 && ctx.in_error);
  assert(creates==0 && bridge_calls==0);release_resource(&ctx,r);assert(close_counts[original]==1);
 } else assert(!"unknown scenario");
 puts("PASS actual import transaction (mock native/GL/hash only)");return 0;
}
