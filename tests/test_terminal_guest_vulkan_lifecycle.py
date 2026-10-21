"""Generate a separately pinned lifecycle cube and test its actual owned C loop.
No Android/device, ARM execution or modification of an old source/artifact case.
"""
from pathlib import Path
import difflib, hashlib, json, os, selectors, shutil, subprocess, tempfile, unittest

ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/'tests/fixtures'
BASE=ROOT/'artifacts/device/first-boot-20261013/d95-owned-vulkan-pattern-20261021-v1/fullscreen-v1/cube.c'
BASE_SHA='261de4b2da9a5496c3cb6d3e0698588d981dc9c1f7295ffda3add4d3e07c815d'

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def replace_once(text,old,new):
    assert text.count(old)==1,old[:120]
    return text.replace(old,new,1)

def generate(folder):
    """Source transformation only; caller owns any separate sandbox build."""
    folder=Path(folder);assert digest(BASE)==BASE_SHA
    s=BASE.read_text()
    s=replace_once(s,'struct gb_owned_resize_state {','''#include "terminal_guest_vulkan_lifecycle_pattern.c"
static struct gb_lifecycle_pattern gb_lifecycle = {.awaiting_create=true};
struct demo;
static void gb_lifecycle_created(bool,uint32_t,uint32_t,uint32_t);
static void gb_lifecycle_present(struct demo *,VkResult);
struct gb_owned_resize_state {''')
    s=replace_once(s,'return gb_owned_fixed_enabled() ? width == 640 && height == 480 : gb_owned_resize_extent(width, height);',
                  'return gb_lifecycle_extent(gb_lifecycle.phase,(uint32_t)width,(uint32_t)height);')
    s=replace_once(s,'return gb_owned_fixed_enabled() ? frames >= 2400 && frames <= 3600 : frames >= 2200 && frames <= 2400;',
                  'return gb_owned_fixed_enabled() && frames == 3600;')
    s=replace_once(s,'if (width != 640 || height != 480) return false;',
                  'if (!gb_lifecycle_extent(gb_lifecycle.phase,(uint32_t)width,(uint32_t)height)) return false;')
    s=replace_once(s,'if (!gb_pattern_clear(cmd_buf, (uint32_t)demo->width, (uint32_t)demo->height))',
                  'if (!gb_lifecycle_clear(cmd_buf,gb_lifecycle.phase,(uint32_t)demo->width,(uint32_t)demo->height))')
    s=replace_once(s,'gb_pattern_present((uint32_t)demo->curFrame + 1, err);','gb_lifecycle_present(demo,err);')
    anchor='''        fflush(stdout);
    }
#endif

    VkImage *swapchainImages'''
    s=replace_once(s,anchor,'''        fflush(stdout);
        gb_lifecycle_created(oldSwapchain!=VK_NULL_HANDLE,swapchainExtent.width,swapchainExtent.height,demo->swapchainImageCount);
    }
#endif

    VkImage *swapchainImages''')
    begin=s.index('static void demo_run(struct demo *demo) {',s.index('#if defined(VK_USE_PLATFORM_WAYLAND_KHR)\nstatic void demo_run'))
    end=s.index('static void handle_surface_configure',begin)
    s=s[:begin]+'#include "terminal_guest_vulkan_lifecycle.c"\n\n'+s[end:]
    s=replace_once(s,'? gb_owned_fixed_configure(&demo->gb_owned_resize, 640, 480, maximized)',
                  '? gb_owned_fixed_configure(&demo->gb_owned_resize, gb_lifecycle.phase==1?480:640, gb_lifecycle.phase==1?360:480, maximized)')
    # The candidate fails on unexpected additional recreation, not on a guessed
    # stale generation; configure metadata still explicitly reports actual size.
    old='''        printf("GB_VULKAN_PATTERN_CONFIGURE:{\\"schema_version\\":1,\\"fullscreen\\":%s,\\"raw_max_width\\":%d,\\"raw_max_height\\":%d,\\"buffer_width\\":640,\\"buffer_height\\":480,\\"presentation_verified\\":false}\\n",
               fullscreen ? "true" : "false", width, height);'''
    new='''        printf("GB_VULKAN_LIFECYCLE_CONFIGURE:{\\"schema_version\\":2,\\"phase\\":%u,\\"fullscreen\\":%s,\\"raw_max_width\\":%d,\\"raw_max_height\\":%d,\\"buffer_width\\":%u,\\"buffer_height\\":%u,\\"presentation_verified\\":false}\\n",
               gb_lifecycle.phase, fullscreen ? "true" : "false", width, height,gb_lifecycle.phase==1?480u:640u,gb_lifecycle.phase==1?360u:480u);'''
    s=replace_once(s,old,new)
    s=replace_once(s,'if (!gb_pattern_selection_valid()) gb_owned_resize_refuse("pattern_selection");',
                  'if (!gb_pattern_selection_valid()) gb_owned_resize_refuse("pattern_selection");\n    (void)gb_pattern_clear;(void)gb_pattern_present;\n    (void)gb_owned_resize_action;(void)gb_owned_resize_sample;(void)gb_owned_resize_completed;\n    gb_lifecycle_stdin_init();')
    old='puts("GB_VULKAN_PATTERN_START:{\\"schema_version\\":1,\\"phase\\":0,\\"width\\":640,\\"height\\":480,\\"border_pixels\\":8,\\"fullscreen_requested\\":true,\\"presentation_verified\\":false}");'
    new='puts("GB_VULKAN_LIFECYCLE_START:{\\"schema_version\\":2,\\"phase_count\\":3,\\"frame_limit\\":3600,\\"ack_required\\":true,\\"presentation_verified\\":false}");'
    s=replace_once(s,old,new)
    old='''    printf("%s:{\\"schema_version\\":1,\\"status\\":\\"refused\\",\\"stage\\":\\"%s\\",\\"presentation_verified\\":false}\\n", gb_owned_fixed_enabled() ? "GB_OWNED_FIXED" : "GB_OWNED_RESIZE", stage);'''
    new='''    printf("GB_VULKAN_LIFECYCLE_REFUSED:{\\"schema_version\\":2,\\"status\\":\\"refused\\",\\"stage\\":\\"%s\\",\\"presentation_verified\\":false}\\n", stage);'''
    s=replace_once(s,old,new)
    s=replace_once(s,'    demo_cleanup(&demo);\n\n    return validation_error;',
                  '    demo_cleanup(&demo);\n    gb_lifecycle_completed(&demo);\n\n    return validation_error;')
    s=replace_once(s,'    vkWaitForFences(demo->device, 1, &demo->fences[demo->frame_index], VK_TRUE, UINT64_MAX);\n    vkResetFences(demo->device, 1, &demo->fences[demo->frame_index]);',
                  '    if (vkWaitForFences(demo->device,1,&demo->fences[demo->frame_index],VK_TRUE,UINT64_MAX)!=VK_SUCCESS ||\n        vkResetFences(demo->device,1,&demo->fences[demo->frame_index])!=VK_SUCCESS) gb_owned_resize_refuse("lifecycle_frame_fence");')
    s=replace_once(s,'        vkWaitForFences(demo->device, 1, &demo->fences[i], VK_TRUE, UINT64_MAX);',
                  '        if (vkWaitForFences(demo->device,1,&demo->fences[i],VK_TRUE,UINT64_MAX)!=VK_SUCCESS) gb_owned_resize_refuse("lifecycle_cleanup_fence");')
    # Every source idle call is still in the existing upstream lifecycle. Check
    # results in this dedicated binary; no default production function changes.
    s=s.replace('    vkDeviceWaitIdle(demo->device);','    if (vkDeviceWaitIdle(demo->device)!=VK_SUCCESS) gb_owned_resize_refuse("lifecycle_device_idle");')
    for name in ('terminal_guest_vulkan_pattern.c','terminal_guest_vulkan_lifecycle_pattern.c','terminal_guest_vulkan_lifecycle.c'):
        shutil.copy2(FIX/name,folder/name)
    (folder/'cube.c').write_text(s)
    patch=''.join(difflib.unified_diff(BASE.read_text().splitlines(True),s.splitlines(True),fromfile='a/cube.c',tofile='b/cube.c'))
    (folder/'source.patch').write_text(patch)
    assert digest(BASE)==BASE_SHA
    return dict(base_sha256=BASE_SHA,source_sha256=digest(folder/'cube.c'),patch_sha256=digest(folder/'source.patch'))

MOCK=r'''
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
typedef void *VkCommandBuffer;typedef int VkResult;
#define VK_SUCCESS 0
#define VK_IMAGE_ASPECT_COLOR_BIT 1
typedef struct {uint32_t aspectMask,colorAttachment;union {union {float float32[4];} color;} clearValue;} VkClearAttachment;
typedef struct {struct {struct {int32_t x,y;} offset;struct {uint32_t width,height;} extent;} rect;uint32_t baseArrayLayer,layerCount;} VkClearRect;
static unsigned clear_calls,draws,resizes;
static void vkCmdClearAttachments(VkCommandBuffer c,uint32_t ac,const VkClearAttachment*a,uint32_t rc,const VkClearRect*r){(void)c;(void)ac;(void)a;(void)rc;(void)r;clear_calls++;}
#include "terminal_guest_vulkan_lifecycle_pattern.c"
static struct gb_lifecycle_pattern gb_lifecycle={.awaiting_create=true};
struct wl_display {int unused;};static int eventpipe[2];
struct demo {void*wayland_library;struct wl_display*wayland_display;int width,height,curFrame,frameCount;bool quit,prepared,pause;struct{int width,height;}gb_owned_resize;};
static void gb_owned_resize_refuse(const char*stage){printf("GB_VULKAN_LIFECYCLE_REFUSED:{\"stage\":\"%s\"}\n",stage);fflush(stdout);exit(2);}
static int getfd(struct wl_display*d){(void)d;return eventpipe[0];}
static void cancel(struct wl_display*d){(void)d;}
static void*dlsym(void*l,const char*n){(void)l;if(!strcmp(n,"wl_display_get_fd"))return(void*)getfd;if(!strcmp(n,"wl_display_cancel_read"))return(void*)cancel;return NULL;}
static int wl_display_prepare_read(struct wl_display*d){(void)d;return 0;}
static int wl_display_dispatch_pending(struct wl_display*d){(void)d;return 0;}
static int wl_display_flush(struct wl_display*d){(void)d;return 0;}
static int wl_display_read_events(struct wl_display*d){(void)d;return 0;}
static void gb_lifecycle_created(bool,uint32_t,uint32_t,uint32_t);
static void gb_lifecycle_present(struct demo*,VkResult);
static void demo_draw(struct demo*d){draws++;assert(gb_lifecycle_clear((void*)1,gb_lifecycle.phase,d->width,d->height));gb_lifecycle_present(d,0);}
static void demo_resize(struct demo*d){resizes++;d->prepared=false;gb_lifecycle_created(true,d->width,d->height,4);d->prepared=true;}
#include "terminal_guest_vulkan_lifecycle.c"
int main(void){
 assert(pipe(eventpipe)==0);gb_lifecycle_stdin_init();struct wl_display display={0};struct demo d={.wayland_library=(void*)1,.wayland_display=&display,.width=640,.height=480,.frameCount=3600,.prepared=true};
 gb_lifecycle_created(false,640,480,4);demo_run(&d);
 assert(draws==3&&resizes==2&&clear_calls==15&&gb_lifecycle_acks==3);gb_lifecycle_completed(&d);close(eventpipe[0]);close(eventpipe[1]);return 0;
}
'''

class Tests(unittest.TestCase):
    def test_source_patch_roundtrip_and_real_upstream_recreation_integration(self):
        if not BASE.is_file():
            self.skipTest("cached Vulkan-Tools base source unavailable; host lifecycle mocks still run")
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);result=generate(b)
            text=(b/'cube.c').read_text()
            self.assertIn('gb_lifecycle_created(oldSwapchain!=VK_NULL_HANDLE',text)
            self.assertIn('gb_lifecycle_clear(cmd_buf,gb_lifecycle.phase',text)
            self.assertIn('demo_prepare(demo);',text[text.index('static void demo_resize(struct demo *demo) {'):])
            self.assertIn('vkFreeCommandBuffers',text[text.index('static void demo_resize(struct demo *demo) {'):])
            subprocess.run(['patch','--batch','--fuzz=0','-R','-p1','-i',str(b/'source.patch')],cwd=b,check=True,capture_output=True,timeout=5)
            self.assertEqual(digest(b/'cube.c'),BASE_SHA)
            subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(b/'source.patch')],cwd=b,check=True,capture_output=True,timeout=5)
            self.assertEqual(digest(b/'cube.c'),result['source_sha256'])

    def test_actual_owned_loop_ack_order_recreation_calls_and_failure_inputs(self):
        cc=shutil.which('cc')
        if not cc:self.skipTest('C compiler unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);(b/'mock.c').write_text(MOCK)
            subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                '-I'+str(FIX),str(b/'mock.c'),'-o',str(b/'mock')],check=True,capture_output=True,timeout=15)
            env=dict(os.environ,GB_VKCUBE_LIFECYCLE_V1='owned-three-phase-v1',ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
            for scenario in ('valid','wrong_phase','extra','eof'):
                proc=subprocess.Popen([str(b/'mock')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,bufsize=0)
                rows=[];sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ)
                try:
                    while True:
                        if not sel.select(4):self.fail('bounded host mock output timeout')
                        line=proc.stdout.readline()
                        if not line:break
                        prefix,payload=line.decode().strip().split(':',1);row=json.loads(payload);rows.append((prefix,row))
                        if prefix=='GB_VULKAN_LIFECYCLE_PRESENT':
                            phase=row['phase']
                            data=(f'ACK{phase}\n'.encode() if scenario=='valid' else b'ACK1\n' if scenario=='wrong_phase' else b'ACK0\nACK1\n')
                            if scenario=='eof':proc.stdin.close()
                            else:proc.stdin.write(data);proc.stdin.flush()
                    out,err=proc.communicate(timeout=3) if not proc.stdin.closed else (proc.stdout.read(),proc.stderr.read())
                    proc.wait(timeout=3);self.assertEqual(err,b'');self.assertEqual(out,b'')
                    if scenario=='valid':
                        self.assertEqual(proc.returncode,0)
                        self.assertEqual([r['phase'] for p,r in rows if p=='GB_VULKAN_LIFECYCLE_PRESENT'],[0,1,2])
                        self.assertEqual([r['swapchain_generation'] for p,r in rows if p=='GB_VULKAN_LIFECYCLE_CREATE'],[1,2,3])
                        self.assertEqual(rows[-1][0],'GB_VULKAN_LIFECYCLE_COMPLETED')
                    else:self.assertEqual(proc.returncode,2);self.assertEqual(rows[-1][0],'GB_VULKAN_LIFECYCLE_REFUSED')
                finally:
                    sel.close()
                    if proc.poll() is None:proc.kill();proc.wait(timeout=3)
                    for stream in (proc.stdin,proc.stdout,proc.stderr):
                        if stream and not stream.closed:stream.close()

if __name__=='__main__':unittest.main()
