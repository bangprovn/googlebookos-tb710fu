"""Versioned deferred-configure lifecycle candidate; actual owned wait helper.
Host mocks establish ordering/bounds only, not actual Wayland/GPU presentation.
"""
from pathlib import Path
import difflib,hashlib,importlib.util,json,os,selectors,shutil,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
FIX=ROOT/'tests/fixtures'
spec=importlib.util.spec_from_file_location('lifecycle_generation',ROOT/'tests/test_terminal_guest_vulkan_lifecycle.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)

def generate(folder):
    folder=Path(folder);old.generate(folder)
    s=(folder/'cube.c').read_text().replace('#include "terminal_guest_vulkan_lifecycle.c"','#include "terminal_guest_vulkan_lifecycle_configured.c"')
    needle='    demo_init_vk_swapchain(&demo);\n\n    demo_prepare(&demo);'
    offset=s.index('int main(int argc, char **argv) {');head=s[:offset];tail=s[offset:]
    assert tail.count(needle)==1
    s=head+tail.replace(needle,'    demo_init_vk_swapchain(&demo);\n\n    if (demo.wsi_platform == WSI_PLATFORM_WAYLAND) gb_lifecycle_wait_initial_configure(&demo);\n    demo_prepare(&demo);',1)
    s=old.replace_once(s,'    xdg_surface_ack_configure(xdg_surface, serial);','    xdg_surface_ack_configure(xdg_surface, serial);\n    gb_lifecycle_configure_surface_acked = gb_pattern_fullscreen_ready;')
    s=old.replace_once(s,'    if (gb_owned_window_enabled()) {\n        bool maximized = false, fullscreen = false;','    if (gb_owned_window_enabled()) {\n        gb_lifecycle_configure_surface_acked = false;\n        bool maximized = false, fullscreen = false;')
    shutil.copy2(FIX/'terminal_guest_vulkan_lifecycle_configured.c',folder/'terminal_guest_vulkan_lifecycle_configured.c')
    (folder/'cube.c').write_text(s)
    patch=''.join(difflib.unified_diff(old.BASE.read_text().splitlines(True),s.splitlines(True),fromfile='a/cube.c',tofile='b/cube.c'))
    (folder/'source.patch').write_text(patch)
    return dict(base_sha256=old.BASE_SHA,source_sha256=old.digest(folder/'cube.c'),patch_sha256=old.digest(folder/'source.patch'))

def mock():
    text=old.MOCK.replace('#include <errno.h>','#include <errno.h>\n#include <poll.h>')
    text=text.replace('static unsigned clear_calls,draws,resizes;','static unsigned clear_calls,draws,resizes;\nstatic bool gb_pattern_fullscreen_ready,gb_lifecycle_configure_surface_acked;static int setup_mode,reads;')
    text=text.replace('int width,height,curFrame,frameCount;', 'int xdg_surface_has_been_configured,width,height,curFrame,frameCount;')
    text=text.replace('static void gb_owned_resize_refuse(', 'static struct demo *active_demo;\nstatic void gb_owned_resize_refuse(',1)
    text=text.replace('static int wl_display_dispatch_pending(struct wl_display*d){(void)d;return 0;}', '''static int wl_display_dispatch_pending(struct wl_display*d){
 (void)d;assert(!draws&&!resizes);
 /* First event is an older nonfullscreen configure+ACK. Second is the
  * fullscreen toplevel configure, WITHOUT its surface ACK. Only third ACK
  * completes the matching pair; old ever-configured remains true throughout. */
 if(reads){gb_pattern_fullscreen_ready=setup_mode!=2&&reads>=2;active_demo->xdg_surface_has_been_configured=1;gb_lifecycle_configure_surface_acked=reads>=3;}
 return 0;
}''')
    text=text.replace('static int wl_display_read_events(struct wl_display*d){(void)d;return 0;}', '''static int wl_display_read_events(struct wl_display*d){(void)d;char c;assert(read(eventpipe[0],&c,1)==1);reads++;return 0;}
static int mock_poll(struct pollfd*f,nfds_t n,int ms){if(setup_mode==3){errno=EIO;return -1;}return poll(f,n,ms);}
#define poll mock_poll''')
    # ACK wait also dispatches after draws; only initial wait must be zero-GPU.
    text=text.replace('assert(!draws&&!resizes);','assert(gb_pattern_fullscreen_ready||(!draws&&!resizes));')
    text=text.replace('static void demo_draw(struct demo*d){draws++;','static void demo_draw(struct demo*d){assert(gb_pattern_fullscreen_ready&&d->xdg_surface_has_been_configured&&gb_lifecycle_configure_surface_acked);draws++;')
    text=text.replace('#include "terminal_guest_vulkan_lifecycle.c"','#include "terminal_guest_vulkan_lifecycle_configured.c"')
    text=text.replace('int main(void){','int main(int argc,char**argv){\n setup_mode=argc>1?atoi(argv[1]):0;')
    text=text.replace('.frameCount=3600,.prepared=true};','.frameCount=3600,.prepared=false};\n active_demo=&d;gb_lifecycle_deadline=gb_lifecycle_now()+.15;\n if(setup_mode!=1){size_t n=setup_mode==4?2:3;assert(write(eventpipe[1],"123",n)==(ssize_t)n);}\n gb_lifecycle_wait_initial_configure(&d);\n assert(reads==3&&gb_pattern_fullscreen_ready&&d.xdg_surface_has_been_configured&&gb_lifecycle_configure_surface_acked);\n assert(!draws&&!resizes&&!gb_lifecycle.creations);\n d.prepared=true;gb_lifecycle_deadline=gb_lifecycle_now()+5;')
    return text

class Tests(unittest.TestCase):
    def test_missing_cached_base_skips_only_roundtrips_both_actual_mocks_run(self):
        if not shutil.which('cc'):self.skipTest('C compiler unavailable for portable host-mock proof')
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp, patch.object(old,'BASE',Path(tmp)/'unavailable-cached-cube.c'):
            tests=unittest.TestSuite([
                old.Tests('test_source_patch_roundtrip_and_real_upstream_recreation_integration'),
                Tests('test_actual_generated_initial_wait_precedes_first_prepare_roundtrip'),
                old.Tests('test_actual_owned_loop_ack_order_recreation_calls_and_failure_inputs'),
                Tests('test_actual_deferred_configure_wait_and_fail_closed_errors')])
            result=unittest.TestResult();tests.run(result)
        self.assertEqual(result.testsRun,4)
        self.assertEqual(result.failures,[]);self.assertEqual(result.errors,[])
        self.assertEqual(len(result.skipped),2)
        self.assertTrue(all('cached Vulkan-Tools base source unavailable' in reason for _,reason in result.skipped))
    def test_actual_generated_initial_wait_precedes_first_prepare_roundtrip(self):
        if not old.BASE.is_file():
            self.skipTest("cached Vulkan-Tools base source unavailable; host configured lifecycle mocks still run")
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);r=generate(b);s=(b/'cube.c').read_text();main=s[s.index('int main(int argc, char **argv) {'):]
            self.assertLess(main.index('gb_lifecycle_wait_initial_configure(&demo)'),main.index('demo_prepare(&demo)'))
            self.assertIn('if (!gb_pattern_fullscreen_ready) gb_owned_resize_refuse("pattern_fullscreen_not_confirmed");',s)
            self.assertEqual(s.count('gb_lifecycle_created(oldSwapchain!=VK_NULL_HANDLE'),1)
            self.assertIn('gb_lifecycle_configure_surface_acked = false;',s)
            self.assertIn('xdg_surface_ack_configure(xdg_surface, serial);\n    gb_lifecycle_configure_surface_acked = gb_pattern_fullscreen_ready;',s)
            subprocess.run(['patch','--batch','--fuzz=0','-R','-p1','-i',str(b/'source.patch')],cwd=b,check=True,capture_output=True,timeout=5)
            self.assertEqual(old.digest(b/'cube.c'),old.BASE_SHA)
            subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(b/'source.patch')],cwd=b,check=True,capture_output=True,timeout=5)
            self.assertEqual(old.digest(b/'cube.c'),r['source_sha256'])
    def test_actual_deferred_configure_wait_and_fail_closed_errors(self):
        cc=shutil.which('cc')
        if not cc:self.skipTest('C compiler unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            b=Path(tmp);(b/'mock.c').write_text(mock())
            subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(FIX),str(b/'mock.c'),'-o',str(b/'mock')],check=True,capture_output=True,timeout=15)
            env=dict(os.environ,GB_VKCUBE_LIFECYCLE_V1='owned-three-phase-v1',ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
            for mode in range(5):
                proc=subprocess.Popen([str(b/'mock'),str(mode)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,bufsize=0)
                rows=[];sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ)
                try:
                    while True:
                        if not sel.select(3):self.fail('bounded configured mock output timeout')
                        line=proc.stdout.readline()
                        if not line:break
                        prefix,payload=line.decode().strip().split(':',1);value=json.loads(payload);rows.append((prefix,value))
                        if prefix=='GB_VULKAN_LIFECYCLE_PRESENT':
                            proc.stdin.write(('ACK%d\n'%value['phase']).encode());proc.stdin.flush()
                    out,err=proc.communicate(timeout=3);self.assertEqual(err,b'');self.assertEqual(out,b'')
                    if mode==0:
                        self.assertEqual(proc.returncode,0);self.assertEqual([v['phase'] for p,v in rows if p=='GB_VULKAN_LIFECYCLE_PRESENT'],[0,1,2])
                        self.assertEqual([v['swapchain_generation'] for p,v in rows if p=='GB_VULKAN_LIFECYCLE_CREATE'],[1,2,3])
                    else:
                        self.assertEqual(proc.returncode,2);self.assertEqual(len(rows),1)
                        self.assertEqual(rows[0][1]['stage'],'lifecycle_poll' if mode==3 else 'pattern_fullscreen_not_confirmed')
                finally:
                    sel.close()
                    if proc.poll() is None:proc.kill();proc.wait(timeout=3)
                    for stream in (proc.stdin,proc.stdout,proc.stderr):
                        if stream:stream.close()
if __name__=='__main__':unittest.main()
