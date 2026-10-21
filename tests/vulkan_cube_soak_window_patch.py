#!/usr/bin/env python3
"""Exact additive owned-soak source and actual C helper ASan/UBSan checks.

No Wayland/GPU/device/controller execution; old fixed/resize source stays pinned.
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
PATCHES = ROOT / 'patches/tb710fu/vulkan-tools'


class OwnedSoakWindow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-cube-soak-')
        cls.tree = Path(cls.work.name)
        manifest = json.loads((PATCHES / 'owned-soak-window.json').read_text())
        sha = lambda value: hashlib.sha256(value).hexdigest()
        for path, expected in manifest.get('host_inputs', {}).items():
            assert sha((ROOT / path).read_bytes()) == expected, path
        entry, = manifest['files']
        data = (ROOT / entry['base_path']).read_bytes()
        assert sha(data) == entry['sha256']
        cls.base = data.decode()
        path = cls.tree / 'cube.c'
        path.write_bytes(data)
        patch = PATCHES / 'owned-soak-window.patch'
        assert sha(patch.read_bytes()) == manifest['patch_sha256']
        for reverse, key in [(False, 'result_sha256'), (True, 'sha256'), (False, 'result_sha256')]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
            if reverse:
                command.append('--reverse')
            subprocess.run(command, cwd=cls.tree, check=True, capture_output=True, timeout=10)
            assert sha(path.read_bytes()) == entry[key]
        cls.source = path.read_text()

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def build(self, name, text):
        source = self.tree / (name + '.c')
        binary = self.tree / name
        source.write_text(text)
        q = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            str(source), '-o', str(binary)], capture_output=True, text=True, timeout=30)
        self.assertEqual(q.returncode, 0, q.stderr)
        return binary

    def run_binary(self, binary, *args):
        return subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=10,
                              env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                       UBSAN_OPTIONS='halt_on_error=1'))

    def test_round_trip_shared_peer_input_bounds_and_old_modes_preserved(self):
        source, base = self.source, self.base
        self.assertIn('Licensed under the Apache License, Version 2.0', source)
        for token in [
            'strcmp(interface, wl_seat_interface.name) == 0 && !gb_owned_window_enabled()',
            'getenv("WAYLAND_SOCKET") || getuid() != 1000',
            'peer.pid != pid || peer.uid != getuid()',
            'states->size > 64 * sizeof(uint32_t)',
            '!desiredNumOfSwapchainImages || desiredNumOfSwapchainImages > 4',
            'demo->swapchainImageCount > 4',
        ]:
            self.assertIn(token, source)
        self.assertIn('if (gb_owned_window_enabled()) {\n        const char *pid_text', source)
        self.assertIn('alarm(gb_owned_window_alarm_seconds());', source)
        self.assertIn('return gb_owned_soak_enabled() ? 660u : 90u;', source)
        self.assertEqual(source.count('alarm('), base.count('alarm('))
        self.assertNotRegex(source, r'\bsignal\s*\(|\bsigaction\s*\(')
        self.assertEqual(re.findall(r'\b(vk\w+)\(', source), re.findall(r'\b(vk\w+)\(', base))
        for name in ['gb_owned_resize_enabled', 'gb_owned_fixed_enabled', 'gb_owned_resize_extent',
                     'gb_owned_fixed_configure', 'gb_owned_resize_configure',
                     'gb_owned_resize_recreated', 'gb_owned_resize_action',
                     'gb_owned_resize_completed', 'gb_owned_resize_sample']:
            pattern = r'static (?:int|bool) ' + name + r'\([^\n]*(?:\n[^{}]*)?\) \{.*?\n\}'
            self.assertEqual(re.search(pattern, source, re.S).group(), re.search(pattern, base, re.S).group(), name)
        start = '            if (gb_owned_resize_enabled()) {\n                int action'
        end = '            if (demo->frameCount != INT32_MAX'
        self.assertEqual(source[source.index(start):source.index(end, source.index(start))],
                         base[base.index(start):base.index(end, base.index(start))])
        fixed = '    if (gb_owned_fixed_enabled()) {\n        if (demo->curFrame != demo->frameCount'
        self.assertEqual(source[source.index(fixed):source.index('\n}\n', source.index(fixed))],
                         base[base.index(fixed):base.index('\n}\n', base.index(fixed))])
        self.assertIn('if (gb_owned_soak_enabled()) gb_owned_resize_refuse("soak_requires_planned_owner_stop");', source)
        self.assertIn('GB_OWNED_SOAK_LIMITS:', source)
        self.assertNotIn('presentation_verified\\":true', source)

    def test_actual_helpers_exact_modes_finite_frames_alarm_and_early_exit(self):
        source = self.source
        start = source.index('struct gb_owned_resize_state {')
        end = source.index('/* GB_OWNED_RESIZE_HELPERS_END */', start)
        refusal_start = source.index('static void gb_owned_resize_refuse(')
        refusal_end = source.index('\n}', refusal_start) + 2
        early = 'if (gb_owned_soak_enabled()) gb_owned_resize_refuse("soak_requires_planned_owner_stop");'
        self.assertIn(early, source)
        program = '''#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
''' + source[start:end] + source[refusal_start:refusal_end] + '''
int main(int argc,char **argv) {
    (void)argv;
    const char *keys[]={"GB_VKCUBE_OWNED_RESIZE_V1","GB_VKCUBE_OWNED_FIXED_V1","GB_VKCUBE_OWNED_SOAK_V1"};
    const char *tokens[]={"owned-maximize-v1","owned-fixed-v1","owned-soak-v1"};
    for(unsigned i=0;i<3;i++) unsetenv(keys[i]);
    assert(!gb_owned_window_enabled() && gb_owned_window_alarm_seconds()==90);
    const char *bad[]={"", "1", "owned-soak-v1-extra", " owned-soak-v1", "owned-soak-v1 "};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        setenv(keys[2],bad[i],1); assert(!gb_owned_soak_enabled() && !gb_owned_window_enabled());
    }
    for(unsigned mask=1;mask<8;mask++) {
        for(unsigned i=0;i<3;i++) {unsetenv(keys[i]);if(mask&(1u<<i))setenv(keys[i],tokens[i],1);}
        assert(gb_owned_window_enabled());
        if(mask!=1 && mask!=2 && mask!=4) {
            assert(!gb_owned_window_arguments(true,640,480,2400));
            assert(!gb_owned_window_arguments(true,640,480,1000000)); continue;
        }
        int frames=mask==4?1000000:2400;
        assert(gb_owned_window_arguments(true,640,480,frames));
        assert(!gb_owned_window_arguments(false,640,480,frames));
        assert(!gb_owned_window_arguments(true,641,480,frames));
        assert(!gb_owned_window_arguments(true,640,481,frames));
        assert(gb_owned_window_alarm_seconds()==(mask==4?660u:90u));
        assert(gb_owned_window_extent(640,480));
        assert(gb_owned_window_extent(3200,2000)==(mask==1));
        if(mask==4) {
            const int32_t bad_frames[]={INT32_MIN,-1,0,2400,3600,999999,1000001,INT32_MAX};
            for(unsigned i=0;i<sizeof(bad_frames)/sizeof(bad_frames[0]);i++)assert(!gb_owned_window_arguments(true,640,480,bad_frames[i]));
        } else if(mask==2) {
            assert(gb_owned_window_arguments(true,640,480,3600));
            assert(!gb_owned_window_arguments(true,640,480,3601));
            assert(!gb_owned_window_arguments(true,640,480,1000000));
        } else {
            assert(gb_owned_window_arguments(true,640,480,2200));
            assert(!gb_owned_window_arguments(true,640,480,2401));
            assert(!gb_owned_window_arguments(true,640,480,1000000));
        }
    }
    for(unsigned i=0;i<3;i++)unsetenv(keys[i]);
    setenv(keys[2],tokens[2],1);
    struct gb_owned_resize_state s={.width=640,.height=480};
    assert(gb_owned_fixed_configure(&s,0,0,false));
    struct gb_owned_resize_state saved=s;
    assert(!gb_owned_fixed_configure(&s,1280,688,false) && !memcmp(&s,&saved,sizeof(s)));
    assert(!gb_owned_fixed_configure(&s,640,480,true));
    s.configure_count=63;assert(gb_owned_fixed_configure(&s,640,480,false));
    assert(!gb_owned_fixed_configure(&s,640,480,false));
    assert(gb_owned_resize_recreated(&s,false,640,480,4));
    assert(!gb_owned_resize_recreated(&s,false,640,480,5));
    s.recreations=16;assert(!gb_owned_resize_recreated(&s,true,640,480,4));
    s=(struct gb_owned_resize_state){.width=640,.height=480};
    assert(gb_owned_resize_configure(&s,640,480,false));
    assert(gb_owned_resize_action(&s,400)==1 && !gb_owned_resize_completed(&s));
    assert(gb_owned_resize_sample(&s,100)==0);
    if(argc==2) {''' + early + '''}
    puts("actual_soak_helpers_passed");return 0;
}
'''
        binary = self.build('helpers', program)
        q = self.run_binary(binary)
        self.assertEqual((q.returncode, q.stdout, q.stderr), (0, 'actual_soak_helpers_passed\n', ''))
        q = self.run_binary(binary, 'natural_loop_end')
        self.assertEqual(q.returncode, 2, q.stderr)
        self.assertEqual(q.stderr, '')
        value = json.loads(q.stdout.removeprefix('GB_OWNED_SOAK:'))
        self.assertEqual(value['stage'], 'soak_requires_planned_owner_stop')
        self.assertFalse(value['presentation_verified'])

    def test_texture_api_error_diagnostics_are_added_only_for_soak(self):
        source = self.source
        enabled = ''.join(re.search(r'static bool '+name+r'\(void\) \{.*?\n\}', source, re.S).group()+'\n'
                          for name in ['gb_owned_fixed_enabled','gb_owned_soak_enabled'])
        start = source.index('static void gb_owned_resize_refuse(')
        end = source.index('\n}', start)+2
        helper = source.index('static void gb_owned_fixed_texture_api_error(')
        helper_end = source.index('/* GB_OWNED_FIXED_API_HELPER_END */', helper)
        program = '''#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VK_MAX_MEMORY_TYPES 32u
#define VK_MEMORY_PROPERTY_HOST_COHERENT_BIT 4u
struct memory_type {uint32_t propertyFlags;};
struct demo {int curFrame;struct {uint32_t memoryTypeCount;struct memory_type memoryTypes[32];}memory_properties;};
struct texture_object {struct {uint64_t allocationSize;uint32_t memoryTypeIndex;}mem_alloc;};
''' + enabled + source[start:end] + source[helper:helper_end] + '''
int main(int argc,char **argv) {
    if(argc!=4)return 1;
    unsetenv("GB_VKCUBE_OWNED_FIXED_V1");unsetenv("GB_VKCUBE_OWNED_SOAK_V1");
    if(!strcmp(argv[1],"fixed"))setenv("GB_VKCUBE_OWNED_FIXED_V1","owned-fixed-v1",1);
    if(!strcmp(argv[1],"soak"))setenv("GB_VKCUBE_OWNED_SOAK_V1","owned-soak-v1",1);
    struct demo demo={.curFrame=50000,.memory_properties={.memoryTypeCount=2,.memoryTypes={[1]={.propertyFlags=6}}}};
    struct texture_object texture={.mem_alloc={.allocationSize=1228800,.memoryTypeIndex=1}};
    gb_owned_fixed_texture_api_error(&demo,&texture,argv[2],strtol(argv[3],NULL,10),6,2);
    puts("returned_without_diagnostic");return 0;
}
'''
        binary = self.build('api', program)
        for mode, result in [('default','-5'),('resize','-5'),('fixed','0'),('soak','0')]:
            q = self.run_binary(binary, mode, 'vkMapMemory', result)
            self.assertEqual((q.returncode,q.stdout,q.stderr),(0,'returned_without_diagnostic\n',''))
        for mode, api, code in [('soak','vkAllocateMemory',-2),('soak','vkBindImageMemory',-4),
                                ('soak','vkMapMemory',-5),('fixed','vkMapMemory',-5)]:
            q = self.run_binary(binary, mode, api, str(code))
            self.assertEqual(q.returncode,2,q.stderr)
            prefix = 'GB_OWNED_SOAK' if mode=='soak' else 'GB_OWNED_FIXED'
            self.assertLess(len(q.stderr),1024)
            value = json.loads(q.stderr.removeprefix(prefix+'_API_ERROR:'))
            self.assertEqual((value['api'],value['vk_result'],value['allocation_bytes']),(api,code,1228800))
            self.assertTrue(value['memory_properties_known'] and value['host_coherent'])
            refusal=json.loads(q.stdout.removeprefix(prefix+':'))
            self.assertEqual(refusal['stage'],'texture_image_api_failure')


if __name__ == '__main__':
    unittest.main()
