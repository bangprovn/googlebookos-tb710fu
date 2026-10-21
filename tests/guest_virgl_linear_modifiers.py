#!/usr/bin/env python3
"""Exercise actual patched modifier callbacks with mock Gallium capabilities."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'artifacts/source/mesa-25.0.7-debian-pool-v1/mesa-25.0.7'
PATCH = ROOT / 'patches/tb710fu/mesa/guest-virgl-linear-modifiers.patch'


class LinearModifiers(unittest.TestCase):
    def test_exact_patch_and_actual_callbacks_default_and_opt_in(self):
        manifest = json.loads(PATCH.with_suffix('.json').read_text())
        self.assertEqual(hashlib.sha256(PATCH.read_bytes()).hexdigest(), manifest['patch_sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-virgl-modifiers-') as temp:
            root = Path(temp)
            for entry in manifest['files']:
                data = (SOURCE / entry['path']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry['sha256'])
                target = root / entry['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            for reverse, digest in [(False, 'result_sha256'), (True, 'sha256'),
                                    (False, 'result_sha256')]:
                command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)]
                if reverse:
                    command.append('--reverse')
                subprocess.run(command, cwd=root, capture_output=True, check=True, timeout=10)
                for entry in manifest['files']:
                    self.assertEqual(hashlib.sha256((root / entry['path']).read_bytes()).hexdigest(), entry[digest])
            source = (root / manifest['files'][0]['path']).read_text()
            start = source.index('/* Process-only profile for the independently qualified')
            end = source.index('\nstatic void\nfixup_renderer(', start)
            callbacks = source[start:end]
            program = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#define UNUSED
enum pipe_format {PIPE_FORMAT_R8G8B8A8_UNORM,PIPE_FORMAT_B8G8R8A8_UNORM,
                  PIPE_FORMAT_R8G8B8X8_UNORM,PIPE_FORMAT_B8G8R8X8_UNORM,
                  PIPE_FORMAT_B8G8R8A8_SRGB,PIPE_FORMAT_OTHER};
enum {PIPE_TEXTURE_2D=2,PIPE_BIND_SAMPLER_VIEW=8};
struct pipe_screen {bool (*is_format_supported)(struct pipe_screen*,enum pipe_format,int,int,int,int);};
struct virgl_screen {struct pipe_screen base;bool gb_android_linear_import;};
static struct virgl_screen *virgl_screen(struct pipe_screen *p){return (struct virgl_screen*)p;}
static unsigned util_format_get_num_planes(enum pipe_format f){(void)f;return 2;}
static bool sample_support=true;
static bool supported(struct pipe_screen *p,enum pipe_format f,int target,int samples,int storage,int bind){
 (void)p;(void)f;assert(target==PIPE_TEXTURE_2D && !samples && !storage && bind==PIPE_BIND_SAMPLER_VIEW);return sample_support;
}
''' + callbacks + r'''
int main(void){
 unsetenv("GB_VIRGL_ANDROID_LINEAR_V1");assert(!gb_virgl_linear_profile_enabled());
 setenv("GB_VIRGL_ANDROID_LINEAR_V1","true",1);assert(!gb_virgl_linear_profile_enabled());
 setenv("GB_VIRGL_ANDROID_LINEAR_V1","qualified-linear-rgbx-v1-extra",1);assert(!gb_virgl_linear_profile_enabled());
 setenv("GB_VIRGL_ANDROID_LINEAR_V1","qualified-linear-rgbx-v1",1);assert(gb_virgl_linear_profile_enabled());
 struct virgl_screen s={.base={.is_format_supported=supported}};
 bool external=true;int count=77;uint64_t modifiers[2]={99,123};unsigned exts[2]={77,88};
 assert(virgl_is_dmabuf_modifier_supported(&s.base,UINT64_MAX,PIPE_FORMAT_OTHER,&external) && external);
 assert(virgl_get_dmabuf_modifier_planes(&s.base,UINT64_MAX,PIPE_FORMAT_OTHER)==2);
 gb_virgl_query_dmabuf_modifiers(&s.base,PIPE_FORMAT_R8G8B8A8_UNORM,1,modifiers,exts,&count);
 assert(count==0 && modifiers[0]==99 && exts[0]==77);
 s.gb_android_linear_import=true;
 for(int f=0;f<4;f++){
  assert(gb_virgl_linear_format((enum pipe_format)f));
  count=77;gb_virgl_query_dmabuf_modifiers(&s.base,f,0,NULL,NULL,&count);assert(count==1);
  count=77;gb_virgl_query_dmabuf_modifiers(&s.base,f,INT_MAX,modifiers,exts,&count);
  assert(count==1 && modifiers[0]==0 && modifiers[1]==123 && exts[0]==0 && exts[1]==88);
  gb_virgl_query_dmabuf_modifiers(&s.base,f,1,modifiers,NULL,&count);assert(count==1);
  external=true;assert(virgl_is_dmabuf_modifier_supported(&s.base,0,f,&external) && !external);
  assert(virgl_is_dmabuf_modifier_supported(&s.base,0,f,NULL));
  assert(!virgl_is_dmabuf_modifier_supported(&s.base,0x00ffffffffffffffull,f,NULL));
  assert(!virgl_is_dmabuf_modifier_supported(&s.base,1,f,NULL));
  assert(virgl_get_dmabuf_modifier_planes(&s.base,0,f)==1);
  assert(virgl_get_dmabuf_modifier_planes(&s.base,UINT64_MAX,f)==0);
 }
 for(int f=4;f<6;f++){
  assert(!gb_virgl_linear_format(f));assert(!virgl_is_dmabuf_modifier_supported(&s.base,0,f,NULL));
  count=77;gb_virgl_query_dmabuf_modifiers(&s.base,f,0,NULL,NULL,&count);assert(count==0);
  assert(virgl_get_dmabuf_modifier_planes(&s.base,0,f)==0);
 }
 sample_support=false;count=77;
 gb_virgl_query_dmabuf_modifiers(&s.base,0,0,NULL,NULL,&count);assert(count==0);
 sample_support=true;
 gb_virgl_query_dmabuf_modifiers(&s.base,0,-1,NULL,NULL,&count);assert(count==0);
 gb_virgl_query_dmabuf_modifiers(&s.base,0,1,NULL,NULL,&count);assert(count==0);
 gb_virgl_query_dmabuf_modifiers(&s.base,0,1,NULL,NULL,NULL);
}
'''
            cfile = root / 'callbacks.c'
            binary = root / 'callbacks'
            cfile.write_text(program)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            str(cfile), '-o', str(binary)], capture_output=True, check=True, timeout=30)
            subprocess.run([str(binary)], capture_output=True, check=True, timeout=10,
                           env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                    UBSAN_OPTIONS='halt_on_error=1'))
            self.assertIn('if (screen->gb_android_linear_import)\n      screen->base.query_dmabuf_modifiers = gb_virgl_query_dmabuf_modifiers;', source)


if __name__ == '__main__':
    unittest.main()
