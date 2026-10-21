#!/usr/bin/env python3
"""Pinned current-source negative proofs plus an explicitly hypothetical ACK model.

No production patch, GPU, kernel module, VM, IPC, or device operation. Actual C
methods are extracted unmodified; generated stand-ins simulate asynchronous
dispatch and response completion, not a working acknowledgement protocol.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'docs/tb710fu-native-import-ack-feasibility-20261020.json'
MODEL = ROOT / 'tests/fixtures/native_import_ack_protocol.rs'


def function(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for end in range(opening + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1]
    raise AssertionError('unterminated function')


C_PREFIX = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "virgl_protocol.h"
#define VIRGL_MAX_PLANE_COUNT 4
#define DRM_IOCTL_VIRTGPU_EXECBUFFER 1
struct virgl_winsys { int unused; };
struct virgl_hw_res { bool maybe_untyped; uint32_t res_handle,bo_handle; };
struct virgl_drm_winsys { int fd,bo_handles_mutex; };
static struct virgl_drm_winsys dws;
static unsigned ioctls,guest_debugs,context_errors;
static uint32_t submitted[32];static size_t submitted_size;
static struct virgl_drm_winsys *virgl_drm_winsys(struct virgl_winsys *v) {(void)v;return &dws;}
static void mtx_lock(int *m) {(void)m;}
static void mtx_unlock(int *m) {(void)m;}
static void _debug_printf(const char *format,...) {(void)format;guest_debugs++;}
struct drm_virtgpu_execbuffer {uint64_t command,bo_handles;uint32_t size,num_bo_handles;};
static int drmIoctl(int fd,int request,struct drm_virtgpu_execbuffer *eb) {
 (void)fd;assert(request==DRM_IOCTL_VIRTGPU_EXECBUFFER && eb->size<=sizeof(submitted));
 memcpy(submitted,(void *)(uintptr_t)eb->command,eb->size);submitted_size=eb->size;ioctls++;return 0;
}
enum virgl_ctx_errors { VIRGL_ERROR_CTX_ILLEGAL_CMD_BUFFER };
struct vrend_context {bool in_error;enum virgl_ctx_errors last_error;unsigned ctx_id;const char *debug_name;};
struct virgl_context {unsigned ctx_id;};
struct vrend_decode_ctx {struct virgl_context base;struct vrend_context *grctx;};
static const char *vrend_ctx_error_strings[]={"illegal command"};
static void vrend_printf(const char *format,...) {(void)format;context_errors++;}
#define TRACE_FUNC() ((void)0)
#define TRACE_SCOPE_SLOW(x) ((void)0)
#define VREND_DEBUG(...) ((void)cur_offset)
static bool vrend_hw_switch_context(struct vrend_context *c,bool force) {(void)c;(void)force;return true;}
static bool vrend_check_no_error(struct vrend_context *c) {(void)c;return true;}
static int mock_dispatch_result;
static int decode_stub(struct vrend_context *c,const uint32_t *b,uint32_t n) {(void)c;(void)b;(void)n;return mock_dispatch_result;}
static int (*decode_table[256])(struct vrend_context *,const uint32_t *,uint32_t);
static const char *vrend_get_comand_name(unsigned cmd) {(void)cmd;return "mock import";}
// ACTUAL_CONTEXT_ERROR
#define vrend_report_buffer_error(ctx,cmd) vrend_report_context_error_internal(__func__,ctx,VIRGL_ERROR_CTX_ILLEGAL_CMD_BUFFER,cmd)
// ACTUAL_GUEST_SET_TYPE
// ACTUAL_HOST_DISPATCH
typedef uint64_t u64;
struct work_struct {int unused;};
struct list_head {int unused;};
struct virtio_gpu_ctrl_hdr {uint32_t type,flags;uint64_t fence_id;};
struct virtio_gpu_device;
struct virtio_gpu_vbuffer {struct list_head list;void *resp_buf;struct virtio_gpu_ctrl_hdr cmd;uint64_t seqno;void (*resp_cb)(struct virtio_gpu_device *,struct virtio_gpu_vbuffer *);void *objs;};
struct mock_ctrlq {struct work_struct dequeue_work;void *vq;int qlock;struct {int unused;} ack_queue;};
struct virtio_gpu_device {struct mock_ctrlq ctrlq;};
static struct virtio_gpu_vbuffer response_entry;
static unsigned logged_response_errors,completed_fences,freed_responses,callback_errors;
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define INIT_LIST_HEAD(h) ((void)(h))
#define spin_lock(p) ((void)(p))
#define spin_unlock(p) ((void)(p))
static void virtqueue_disable_cb(void *q) {(void)q;}
static bool virtqueue_enable_cb(void *q) {(void)q;return true;}
static void reclaim_vbufs(void *q,struct list_head *h) {(void)q;(void)h;}
#define list_for_each_entry(e,h,m) for(unsigned it=0;it<1 && ((void)(h),(e)=&response_entry,1);it++)
#define list_for_each_entry_safe(e,t,h,m) for(unsigned jt=0;jt<1 && ((void)(h),(e)=&response_entry,(t)=NULL,(void)(t),1);jt++)
#define trace_virtio_gpu_cmd_response(...) ((void)0)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define VIRTIO_GPU_RESP_OK_NODATA 0x1100u
#define VIRTIO_GPU_RESP_ERR_UNSPEC 0x1200u
#define VIRTIO_GPU_FLAG_FENCE 1u
#define DRM_ERROR_RATELIMITED(...) ((void)(cmd),logged_response_errors++)
#define DRM_DEBUG(...) ((void)0)
static struct virtio_gpu_ctrl_hdr *virtio_gpu_vbuf_ctrl_hdr(struct virtio_gpu_vbuffer *e) {return &e->cmd;}
static void virtio_gpu_fence_event_process(struct virtio_gpu_device *v,u64 id) {(void)v;assert(id==42);completed_fences++;}
#define wake_up(p) ((void)(p))
static void virtio_gpu_array_put_free_delayed(struct virtio_gpu_device *v,void *o) {(void)v;(void)o;}
static void list_del(struct list_head *h) {(void)h;}
static void free_vbuf(struct virtio_gpu_device *v,struct virtio_gpu_vbuffer *e) {(void)v;(void)e;freed_responses++;}
// ACTUAL_GUEST_RESPONSE_LOOP
static void inspect_response(struct virtio_gpu_device *v,struct virtio_gpu_vbuffer *e) {
 (void)v;struct virtio_gpu_ctrl_hdr *r=e->resp_buf;if(r->type>=VIRTIO_GPU_RESP_ERR_UNSPEC) callback_errors++;
}
static void submit_type(struct virgl_hw_res *resource) {
 struct virgl_winsys ws={0};uint32_t stride=2560,offset=0;
 virgl_drm_winsys_resource_set_type(&ws,resource,1,1,640,480,0,0,1,&stride,&offset);
}
int main(int argc,char **argv) {
 assert(argc==2);struct virgl_hw_res resource={.maybe_untyped=true,.res_handle=59,.bo_handle=1};
 submit_type(&resource);assert(ioctls==1 && !resource.maybe_untyped && guest_debugs==0);
 decode_table[VIRGL_CCMD_PIPE_RESOURCE_SET_TYPE]=decode_stub;
 struct vrend_context host={.ctx_id=9,.debug_name="mock-compositor"};
 struct vrend_decode_ctx decoder={.base={.ctx_id=9},.grctx=&host};
 if(!strcmp(argv[1],"late_einval")) {
  mock_dispatch_result=EINVAL;
  assert(vrend_decode_ctx_submit_cmd(&decoder.base,submitted,submitted_size)==EINVAL && host.in_error);
  // Actual guest method already consumed its untyped marker; another call doesn't retry.
  submit_type(&resource);assert(ioctls==1 && guest_debugs==0);
 } else if(!strcmp(argv[1],"errno_only")) {
  mock_dispatch_result=ENOMEM;
  assert(vrend_decode_ctx_submit_cmd(&decoder.base,submitted,submitted_size)==ENOMEM && !host.in_error);
  // A later missing-resource command returnsEINVAL; only changing import errno is insufficient.
  mock_dispatch_result=EINVAL;
  assert(vrend_decode_ctx_submit_cmd(&decoder.base,submitted,submitted_size)==EINVAL && host.in_error);
 } else {
  assert(!strcmp(argv[1],"response_loss") || !strcmp(argv[1],"callback_can_see_raw_status"));
  struct virtio_gpu_device device={0};struct virtio_gpu_ctrl_hdr response={.type=VIRTIO_GPU_RESP_ERR_UNSPEC,.flags=VIRTIO_GPU_FLAG_FENCE,.fence_id=42};
  response_entry.resp_buf=&response;
  if(!strcmp(argv[1],"callback_can_see_raw_status")) response_entry.resp_cb=inspect_response;
  virtio_gpu_dequeue_ctrl_func(&device.ctrlq.dequeue_work);
  assert(logged_response_errors==1 && completed_fences==1 && freed_responses==1);
  assert(callback_errors==(!strcmp(argv[1],"callback_can_see_raw_status")?1u:0u));
 }
 puts("PASS current-source negative proof (mock transport/renderer)");return 0;
}
'''


class ImportAckFeasibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(REPORT.read_text())
        cls.sources = {}
        for name, entry in cls.report['source_inputs'].items():
            data = (ROOT / entry['path']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry['sha256'], name
            cls.sources[name] = data.decode()

    def test_current_actual_functions_reproduce_async_failure_boundary(self):
        source = C_PREFIX
        for marker, name, signature in [
            ('// ACTUAL_CONTEXT_ERROR', 'renderer', 'void vrend_report_context_error_internal('),
            ('// ACTUAL_GUEST_SET_TYPE', 'guest_winsys', 'static void\nvirgl_drm_winsys_resource_set_type('),
            ('// ACTUAL_HOST_DISPATCH', 'decoder', 'static int vrend_decode_ctx_submit_cmd('),
            ('// ACTUAL_GUEST_RESPONSE_LOOP', 'guest_vq', 'void virtio_gpu_dequeue_ctrl_func('),
        ]:
            self.assertEqual(source.count(marker), 1)
            source = source.replace(marker, function(self.sources[name], signature))
        with tempfile.TemporaryDirectory(prefix='gb-import-source-proof-') as directory:
            root = Path(directory)
            (root / 'actual.c').write_text(source)
            (root / 'virgl_protocol.h').write_text(self.sources['guest_protocol'])
            binary = root / 'actual'
            built = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                                    '-I' + str(root), str(root / 'actual.c'), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for scenario in ['late_einval', 'errno_only', 'response_loss', 'callback_can_see_raw_status']:
                with self.subTest(scenario=scenario):
                    tested = subprocess.run([str(binary), scenario], capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
                    self.assertEqual(tested.stderr, '')

    def test_existing_completion_is_not_a_per_import_success_result(self):
        fence = function(self.sources['guest_fence'], 'void virtio_gpu_fence_event_process(')
        self.assertIn('dma_fence_signal_locked(&curr->f)', fence)
        self.assertNotIn('dma_fence_set_error', fence)
        self.assertIn('dma_fence_is_later', fence)
        submit = function(self.sources['guest_vq'], 'void virtio_gpu_cmd_submit(')
        self.assertIn('virtio_gpu_alloc_cmd(vgdev, &vbuf', submit)
        allocation = function(self.sources['guest_vq'], 'static void *virtio_gpu_alloc_cmd(')
        self.assertIn('virtio_gpu_alloc_cmd_resp(vgdev, NULL', allocation)
        importer = self.sources['renderer']
        self.assertIn('failed to create egl image', importer)
        self.assertIn('vrend_report_context_error(ctx, VIRGL_ERROR_CTX_ILLEGAL_RESOURCE, res_handle)', importer)

    def test_hypothetical_protocol_invariants_only(self):
        data = MODEL.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.report['protocol_model']['sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-import-model-') as directory:
            binary = Path(directory) / 'model'
            built = subprocess.run(['rustc', '--edition=2021', '--test', '-D', 'warnings',
                                    str(MODEL), '-o', str(binary)], capture_output=True,
                                   text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            tested = subprocess.run([str(binary), '--nocapture'], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            self.assertIn('8 passed; 0 failed', tested.stdout)


if __name__ == '__main__':
    unittest.main()
