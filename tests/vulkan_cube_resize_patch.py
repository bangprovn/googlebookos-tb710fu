#!/usr/bin/env python3
"""Verify the pinned diagnostic patch and its actual C bounds/event helpers.

Host helpers use ASan/UBSan. They do not open Wayland, load a GPU driver or
qualify presentation/retirement; the separate device observer is required.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'artifacts/source/vulkan-tools-1.4.304-cube-v1'
PAYLOAD = ROOT/'patches/tb710fu/vulkan-tools'


class OwnedResizePatch(unittest.TestCase):
    def stage(self, target):
        manifest = json.loads((PAYLOAD/'owned-resize-diagnostic.json').read_text())
        patch = PAYLOAD/'owned-resize-diagnostic.patch'
        digest = lambda data: hashlib.sha256(data).hexdigest()
        self.assertEqual(digest(patch.read_bytes()), manifest['patch_sha256'])
        entry, = manifest['files']
        data = (SOURCE/entry['path']).read_bytes()
        self.assertEqual(digest(data), entry['sha256'])
        path = target/entry['path']
        path.write_bytes(data)
        for reverse, expected in [(False, 'result_sha256'), (True, 'sha256'), (False, 'result_sha256')]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
            if reverse:
                command.append('--reverse')
            result = subprocess.run(command, cwd=target, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(digest(path.read_bytes()), entry[expected])
        return path.read_text()

    def test_exact_pinned_patch_round_trip_and_diagnostic_integration(self):
        with tempfile.TemporaryDirectory(prefix='gb-cube-resize-patch-') as directory:
            source = self.stage(Path(directory))
        self.assertIn('Licensed under the Apache License, Version 2.0', source)
        self.assertIn('strcmp(interface, wl_seat_interface.name) == 0 && !gb_owned_resize_enabled()', source)
        self.assertIn('.oldSwapchain = oldSwapchain,', source)
        self.assertIn('gb_owned_resize_action(&demo->gb_owned_resize, demo->curFrame)', source)
        self.assertIn('if (action == 1) xdg_toplevel_set_maximized(demo->xdg_toplevel);', source)
        self.assertIn('else xdg_toplevel_unset_maximized(demo->xdg_toplevel);', source)
        self.assertIn('peer.pid != pid || peer.uid != getuid()', source)
        self.assertIn('demo->frameCount < 2200 || demo->frameCount > 2400', source)
        self.assertIn('alarm(90);', source)
        for record in ['CREATE', 'REQUEST', 'CONFIGURE', 'SAMPLE', 'COMPLETED']:
            self.assertIn('GB_OWNED_RESIZE_'+record+':', source)
        run_start = source.index('#if defined(VK_USE_PLATFORM_WAYLAND_KHR)\nstatic void demo_run(struct demo *demo)')
        draw = source.index('            demo_draw(demo);', run_start)
        advanced = source.index('            demo->curFrame++;', draw)
        sample = source.index('gb_owned_resize_sample(&demo->gb_owned_resize, demo->curFrame)', advanced)
        self.assertLess(draw, advanced)
        self.assertLess(advanced, sample)

    def test_actual_helpers_bound_extents_images_events_and_require_observed_recreation(self):
        with tempfile.TemporaryDirectory(prefix='gb-cube-resize-helpers-') as directory:
            work = Path(directory)
            source = self.stage(work)
            start = source.index('struct gb_owned_resize_state {')
            end = source.index('/* GB_OWNED_RESIZE_HELPERS_END */', start)
            program = '''#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
''' + source[start:end] + '''
static struct gb_owned_resize_state initial(void) {
    return (struct gb_owned_resize_state){.width=640,.height=480};
}
int main(void) {
    unsetenv("GB_VKCUBE_OWNED_RESIZE_V1"); assert(!gb_owned_resize_enabled());
    setenv("GB_VKCUBE_OWNED_RESIZE_V1","1",1); assert(!gb_owned_resize_enabled());
    setenv("GB_VKCUBE_OWNED_RESIZE_V1","owned-maximize-v1-extra",1); assert(!gb_owned_resize_enabled());
    setenv("GB_VKCUBE_OWNED_RESIZE_V1","owned-maximize-v1",1); assert(gb_owned_resize_enabled());
    assert(gb_owned_resize_extent(32,32) && gb_owned_resize_extent(3200,2000));
    const int32_t bad[][2]={{0,480},{-1,480},{31,480},{640,31},{3201,480},{640,2001},{INT32_MAX,INT32_MAX}};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(!gb_owned_resize_extent(bad[i][0],bad[i][1]));
    struct gb_owned_resize_state s=initial();
    assert(gb_owned_resize_configure(&s,0,0,false) && s.width==640 && s.height==480);
    assert(!gb_owned_resize_completed(&s));
    assert(gb_owned_resize_action(&s,399)==0 && !s.request);
    assert(gb_owned_resize_action(&s,400)==1 && s.request==1);
    assert(gb_owned_resize_action(&s,400)==-1); /* No repeated requests. */
    assert(gb_owned_resize_action(&s,800)==-1); /* Request is not success. */
    assert(gb_owned_resize_configure(&s,1600,1000,false));
    assert(!s.maximized_seen && gb_owned_resize_action(&s,800)==-1);
    assert(gb_owned_resize_configure(&s,1600,1000,true) && s.maximized_seen && s.currently_maximized);
    assert(gb_owned_resize_recreated(&s,false,1600,1000,4));
    assert(!s.maximized_recreated && gb_owned_resize_action(&s,800)==-1); /* Must replace an old chain. */
    assert(gb_owned_resize_recreated(&s,true,640,480,4) && !s.maximized_recreated);
    assert(gb_owned_resize_recreated(&s,true,1600,1000,4) && s.maximized_recreated);
    assert(gb_owned_resize_action(&s,800)==0);
    assert(gb_owned_resize_action(&s,1400)==2 && s.request==2);
    assert(gb_owned_resize_action(&s,1400)==-1);
    assert(!gb_owned_resize_completed(&s) && gb_owned_resize_action(&s,1800)==-1);
    assert(gb_owned_resize_configure(&s,0,0,true) && s.width==1600 && s.height==1000 && !s.restored_seen);
    assert(gb_owned_resize_configure(&s,0,0,false) && s.width==640 && s.height==480 && s.restored_seen && !s.currently_maximized);
    assert(!gb_owned_resize_completed(&s));
    assert(gb_owned_resize_recreated(&s,true,640,480,4));
    assert(gb_owned_resize_action(&s,1800)==0 && gb_owned_resize_completed(&s));
    unsigned before=s.recreations;
    assert(!gb_owned_resize_recreated(&s,true,640,480,0));
    assert(!gb_owned_resize_recreated(&s,true,640,480,5));
    assert(!gb_owned_resize_recreated(&s,true,3201,480,4));
    assert(s.recreations==before);
    s.recreations=15;
    assert(gb_owned_resize_recreated(&s,true,640,480,4) && s.recreations==16);
    assert(!gb_owned_resize_recreated(&s,true,640,480,4) && s.recreations==16);
    s=initial(); s.configure_count=63;
    assert(gb_owned_resize_configure(&s,640,480,false) && s.configure_count==64);
    assert(!gb_owned_resize_configure(&s,640,480,false) && s.configure_count==64);
    s=initial();
    assert(!gb_owned_resize_configure(&s,-1,480,false) && !s.configure_count);
    assert(gb_owned_resize_action(&s,1400)==-1 && !s.request);
    const int32_t sample_frames[6]={100,250,900,1150,1900,2150};
    s=initial(); unsigned observed=0;
    for (int32_t frame=1;frame<=2400;frame++) {
        int sample=gb_owned_resize_sample(&s,frame);
        if (sample>=0) {
            assert(sample==(int)observed && frame==sample_frames[observed]);
            observed++;
            assert(gb_owned_resize_sample(&s,frame)==-1); /* No duplicate marker. */
        } else assert(sample==-1);
    }
    assert(observed==6 && s.samples_emitted==6);
    assert(gb_owned_resize_sample(&s,INT32_MAX)==-1 && s.samples_emitted==6);
    s=initial();
    assert(gb_owned_resize_sample(&s,101)==-2 && !s.samples_emitted); /* No retrospective/reused sample. */
    return 0;
}
'''
            path, binary = work/'helpers.c', work/'helpers'
            path.write_text(program)
            built = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                                    str(path), '-o', str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
