#!/usr/bin/env python3
"""Pinned additive fixed-window patch plus actual C helper ASan/UBSan checks.

No compositor, GPU driver, Android build, device, pixels or input are exercised.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'artifacts/source/vulkan-tools-1.4.304-cube-v1'
PATCHES = ROOT/'patches/tb710fu/vulkan-tools'


class OwnedFixedWindowPatch(unittest.TestCase):
    def stage(self, directory):
        digest = lambda data: hashlib.sha256(data).hexdigest()
        resize = json.loads((PATCHES/'owned-resize-diagnostic.json').read_text())
        fixed = json.loads((PATCHES/'owned-fixed-window.json').read_text())
        path = directory/'cube.c'
        data = (SOURCE/'cube.c').read_bytes()
        self.assertEqual(digest(data), resize['files'][0]['sha256'])
        path.write_bytes(data)
        patch = PATCHES/'owned-resize-diagnostic.patch'
        self.assertEqual(digest(patch.read_bytes()), resize['patch_sha256'])
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                       cwd=directory, check=True, capture_output=True, timeout=10)
        base = path.read_text()
        entry, = fixed['files']
        self.assertEqual(digest(path.read_bytes()), resize['files'][0]['result_sha256'])
        self.assertEqual(digest(path.read_bytes()), entry['sha256'])
        patch = PATCHES/'owned-fixed-window.patch'
        self.assertEqual(digest(patch.read_bytes()), fixed['patch_sha256'])
        for reverse, key in [(False, 'result_sha256'), (True, 'sha256'), (False, 'result_sha256')]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
            if reverse:
                command.append('--reverse')
            result = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(digest(path.read_bytes()), entry[key])
        return base, path.read_text()

    def test_round_trip_shared_guards_keep_resize_actions_separate(self):
        with tempfile.TemporaryDirectory(prefix='gb-cube-fixed-patch-') as directory:
            base, source = self.stage(Path(directory))
        self.assertIn('Licensed under the Apache License, Version 2.0', source)
        self.assertIn('strcmp(interface, wl_seat_interface.name) == 0 && !gb_owned_window_enabled()', source)
        self.assertIn('if (gb_owned_window_enabled()) {\n        const char *pid_text', source)
        self.assertIn('getenv("WAYLAND_SOCKET") || getuid() != 1000', source)
        self.assertIn('peer.pid != pid || peer.uid != getuid()', source)
        self.assertIn('if (gb_owned_window_enabled()) {\n        if (!gb_owned_window_arguments(', source)
        self.assertIn('alarm(90);', source)
        self.assertIn('!gb_owned_window_extent((int32_t)swapchainExtent.width, (int32_t)swapchainExtent.height)', source)
        self.assertIn('!desiredNumOfSwapchainImages || desiredNumOfSwapchainImages > 4', source)
        self.assertIn('if (gb_owned_window_enabled() && (err != VK_SUCCESS || !demo->swapchainImageCount || demo->swapchainImageCount > 4))', source)
        self.assertIn('states->size > 64 * sizeof(uint32_t)', source)
        self.assertIn('if (gb_owned_window_enabled()) {\n        bool maximized = false;', source)
        # The only maximization calls and phase markers remain in the original
        # resize-only branch; default/resize rendering and scheduling stay intact.
        start = source.index('            if (gb_owned_resize_enabled()) {\n                int action')
        end = source.index('            if (demo->frameCount != INT32_MAX', start)
        original_start = base.index('            if (gb_owned_resize_enabled()) {\n                int action')
        original_end = base.index('            if (demo->frameCount != INT32_MAX', original_start)
        self.assertEqual(source[start:end], base[original_start:original_end])
        for name in ['gb_owned_resize_action', 'gb_owned_resize_sample', 'gb_owned_resize_completed']:
            pattern = r'static (?:int|bool) '+name+r'\([^\n]*\) \{.*?\n\}'
            self.assertEqual(re.search(pattern, source, re.S).group(), re.search(pattern, base, re.S).group())
        self.assertEqual(source.count('xdg_toplevel_set_maximized(demo->xdg_toplevel)'), 1)
        self.assertEqual(source.count('xdg_toplevel_unset_maximized(demo->xdg_toplevel)'), 1)
        self.assertIn('GB_OWNED_FIXED_COMPLETED:', source)
        self.assertIn('demo->curFrame != demo->frameCount', source)
        # New diagnostics never assert presentation or retirement proof.
        self.assertNotIn('presentation_verified\\":true', source)

    def test_texture_failures_emit_exact_bounded_metadata_only_in_fixed_mode(self):
        with tempfile.TemporaryDirectory(prefix='gb-cube-fixed-api-') as directory:
            work = Path(directory)
            _, source = self.stage(work)
            start = source.index('static void demo_prepare_texture_image(')
            end = source.index('\nstatic void demo_destroy_texture', start)
            texture = source[start:end]
            for api in ['vkAllocateMemory', 'vkBindImageMemory', 'vkMapMemory']:
                call = 'gb_owned_fixed_texture_api_error(demo, tex_obj, "'+api+'", err, required_props, mem_reqs.memoryTypeBits);'
                self.assertEqual(source.count(call), 1)
                self.assertIn(call+'\n#endif\n'+('        ' if api == 'vkMapMemory' else '    ')+'assert(!err);', texture)
                self.assertLess(texture.index('err = '+api+'('), texture.index(call))
            enabled = re.search(r'static bool gb_owned_fixed_enabled\(void\) \{.*?\n\}', source, re.S).group()
            refuse_start = source.index('static void gb_owned_resize_refuse(')
            refuse_end = source.index('\n}', refuse_start)+2
            helper_start = source.index('static void gb_owned_fixed_texture_api_error(')
            helper_end = source.index('/* GB_OWNED_FIXED_API_HELPER_END */', helper_start)
            program = '''#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VK_MAX_MEMORY_TYPES 32u
#define VK_MEMORY_PROPERTY_HOST_COHERENT_BIT 4u
struct memory_type { uint32_t propertyFlags; };
struct memory_properties { uint32_t memoryTypeCount; struct memory_type memoryTypes[32]; };
struct demo { int curFrame; struct memory_properties memory_properties; };
struct texture_object { struct { uint64_t allocationSize; uint32_t memoryTypeIndex; } mem_alloc; };
''' + enabled + '\n' + source[refuse_start:refuse_end] + '\n' + source[helper_start:helper_end] + '''
int main(int argc,char **argv) {
    assert(argc==9);
    unsetenv("GB_VKCUBE_OWNED_FIXED_V1"); unsetenv("GB_VKCUBE_OWNED_RESIZE_V1");
    if (!strcmp(argv[1],"fixed")) setenv("GB_VKCUBE_OWNED_FIXED_V1","owned-fixed-v1",1);
    else if (!strcmp(argv[1],"resize")) setenv("GB_VKCUBE_OWNED_RESIZE_V1","owned-maximize-v1",1);
    struct demo demo={.curFrame=885};
    struct texture_object texture={.mem_alloc={.allocationSize=strtoull(argv[8],NULL,10),.memoryTypeIndex=strtoul(argv[4],NULL,10)}};
    demo.memory_properties.memoryTypeCount=strtoul(argv[5],NULL,10);
    demo.memory_properties.memoryTypes[1].propertyFlags=strtoul(argv[6],NULL,10);
    gb_owned_fixed_texture_api_error(&demo,&texture,argv[2],strtol(argv[3],NULL,10),6,strtoul(argv[7],NULL,10));
    puts("returned_without_diagnostic"); return 0;
}
'''
            path, binary = work/'api.c', work/'api'
            path.write_text(program)
            build = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(path), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            def run(mode, api, result, index=1, count=2, flags=6, bits=2, size=65536):
                return subprocess.run([str(binary),mode,api,str(result),str(index),str(count),str(flags),str(bits),str(size)],
                                      capture_output=True, text=True, timeout=10,
                                      env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
            for mode, result in [('default',-5), ('resize',-5), ('fixed',0)]:
                outcome = run(mode,'vkMapMemory',result)
                self.assertEqual(outcome.returncode, 0, outcome.stderr)
                self.assertEqual(outcome.stdout, 'returned_without_diagnostic\n')
                self.assertEqual(outcome.stderr, '')
            for api, code in [('vkAllocateMemory',-2), ('vkBindImageMemory',-4), ('vkMapMemory',-5)]:
                outcome = run('fixed',api,code)
                self.assertEqual(outcome.returncode, 2, outcome.stderr)
                self.assertLess(len(outcome.stderr), 1024)
                prefix = 'GB_OWNED_FIXED_API_ERROR:'
                self.assertTrue(outcome.stderr.startswith(prefix))
                record = json.loads(outcome.stderr[len(prefix):])
                self.assertEqual(record,dict(schema_version=1,api=api,vk_result=code,frame=885,
                    allocation_bytes=65536,memory_type_index=1,memory_type_bits=2,required_property_flags=6,
                    memory_properties_known=True,memory_property_flags=6,host_coherent=True,presentation_verified=False))
                refusal = json.loads(outcome.stdout.removeprefix('GB_OWNED_FIXED:'))
                self.assertEqual(refusal['stage'], 'texture_image_api_failure')
                self.assertFalse(refusal['presentation_verified'])
            for index, count, flags, known in [(1,1,6,False), (32,100,6,False), (2**32-1,2**32-1,6,False), (1,2,2,True)]:
                outcome = run('fixed','vkMapMemory',-5,index,count,flags,size=2**64-1)
                self.assertEqual(outcome.returncode, 2, outcome.stderr)
                self.assertLess(len(outcome.stderr), 1024)
                record = json.loads(outcome.stderr.removeprefix('GB_OWNED_FIXED_API_ERROR:'))
                self.assertEqual(record['allocation_bytes'], 2**64-1)
                self.assertEqual(record['memory_properties_known'], known)
                self.assertEqual(record['memory_property_flags'], flags if known else 0)
                self.assertFalse(record['host_coherent'])

    def test_actual_helpers_exact_tokens_fixed_bounds_and_configuration(self):
        with tempfile.TemporaryDirectory(prefix='gb-cube-fixed-helper-') as directory:
            work = Path(directory)
            _, source = self.stage(work)
            start = source.index('struct gb_owned_resize_state {')
            end = source.index('/* GB_OWNED_RESIZE_HELPERS_END */', start)
            program = '''#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
''' + source[start:end] + '''
int main(void) {
    unsetenv("GB_VKCUBE_OWNED_RESIZE_V1"); unsetenv("GB_VKCUBE_OWNED_FIXED_V1");
    assert(!gb_owned_window_enabled() && !gb_owned_fixed_enabled() && !gb_owned_resize_enabled());
    const char *bad[]={"", "1", "owned-fixed-v1-extra", " owned-fixed-v1", "owned-fixed-v1 "};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        setenv("GB_VKCUBE_OWNED_FIXED_V1",bad[i],1); assert(!gb_owned_fixed_enabled() && !gb_owned_window_enabled());
    }
    setenv("GB_VKCUBE_OWNED_FIXED_V1","owned-fixed-v1",1);
    assert(gb_owned_window_enabled() && gb_owned_fixed_enabled() && !gb_owned_resize_enabled());
    assert(gb_owned_window_arguments(true,640,480,2400));
    assert(gb_owned_window_arguments(true,640,480,3600));
    assert(!gb_owned_window_arguments(false,640,480,2400));
    assert(!gb_owned_window_arguments(true,641,480,2400));
    assert(!gb_owned_window_arguments(true,640,481,2400));
    const int32_t bad_frames[]={INT32_MIN,-1,0,2399,3601,INT32_MAX};
    for(unsigned i=0;i<sizeof(bad_frames)/sizeof(bad_frames[0]);i++) assert(!gb_owned_window_arguments(true,640,480,bad_frames[i]));
    assert(gb_owned_window_extent(640,480));
    const int32_t bad_sizes[][2]={{0,0},{639,480},{640,479},{641,480},{640,481},{-1,480},{INT32_MAX,INT32_MAX},{3200,2000}};
    for(unsigned i=0;i<sizeof(bad_sizes)/sizeof(bad_sizes[0]);i++) assert(!gb_owned_window_extent(bad_sizes[i][0],bad_sizes[i][1]));
    struct gb_owned_resize_state s={.width=640,.height=480};
    assert(gb_owned_fixed_configure(&s,0,0,false) && s.width==640 && s.height==480 && s.configure_count==1);
    assert(gb_owned_fixed_configure(&s,640,0,false) && gb_owned_fixed_configure(&s,0,480,false));
    struct gb_owned_resize_state saved=s;
    assert(!gb_owned_fixed_configure(&s,640,480,true));
    assert(!memcmp(&saved,&s,sizeof(s)));
    for(unsigned i=0;i<sizeof(bad_sizes)/sizeof(bad_sizes[0]);i++) {
        if (!bad_sizes[i][0] && !bad_sizes[i][1]) continue;
        assert(!gb_owned_fixed_configure(&s,bad_sizes[i][0],bad_sizes[i][1],false));
        assert(!memcmp(&saved,&s,sizeof(s)));
    }
    s.configure_count=63; assert(gb_owned_fixed_configure(&s,640,480,false) && s.configure_count==64);
    assert(!gb_owned_fixed_configure(&s,640,480,false) && s.configure_count==64);
    assert(gb_owned_resize_recreated(&s,false,640,480,4));
    assert(!gb_owned_resize_recreated(&s,false,640,480,0));
    assert(!gb_owned_resize_recreated(&s,false,640,480,5));
    setenv("GB_VKCUBE_OWNED_RESIZE_V1","owned-maximize-v1",1);
    assert(gb_owned_resize_enabled() && gb_owned_fixed_enabled());
    assert(!gb_owned_window_arguments(true,640,480,2400));
    unsetenv("GB_VKCUBE_OWNED_FIXED_V1");
    assert(gb_owned_window_enabled() && !gb_owned_fixed_enabled());
    assert(gb_owned_window_arguments(true,640,480,2200) && gb_owned_window_arguments(true,640,480,2400));
    assert(!gb_owned_window_arguments(true,640,480,3600));
    assert(gb_owned_window_extent(3200,2000));
    s=(struct gb_owned_resize_state){.width=640,.height=480};
    assert(gb_owned_resize_configure(&s,640,480,false));
    assert(gb_owned_resize_action(&s,400)==1 && !gb_owned_resize_completed(&s));
    assert(gb_owned_resize_sample(&s,100)==0);
    return 0;
}
'''
            path, binary = work/'helpers.c', work/'helpers'
            path.write_text(program)
            build = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(path), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10,
                                    env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
