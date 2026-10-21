#!/usr/bin/env python3
"""Test the real Android format converter against the project's GBM converter.

Compiles trusted source on the host; no firmware driver or allocator is loaded.
Requires the prepared, version-pinned virglrenderer checkout.
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
CHECKOUT = ROOT / 'artifacts/source/crosvm-android16qpr2-backend'
SOURCE = CHECKOUT / 'external/virglrenderer/src'
PAYLOAD = ROOT / 'patches/tb710fu/virglrenderer'


class FormatConversion(unittest.TestCase):
    def test_versioned_patch_reverses_and_reapplies(self):
        manifest = json.loads((PAYLOAD / 'android-gbm-format-conversion.json').read_text())
        patch = PAYLOAD / 'android-gbm-format-conversion.patch'
        entry = manifest['files'][0]
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), manifest['patch_sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-format-patch-') as temp:
            root = Path(temp)
            path = root / entry['path']
            path.parent.mkdir()
            path.write_bytes((SOURCE.parent / entry['path']).read_bytes())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry['result_sha256'])
            for reverse, digest in [(True, 'sha256'), (False, 'result_sha256')]:
                command = ['patch', '--batch', '--strip=1', '--input', str(patch)]
                if reverse:
                    command.append('--reverse')
                subprocess.run(command, cwd=root, capture_output=True, check=True, timeout=10)
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry[digest])

    def test_actual_android_converter_matches_real_gbm_without_loading_gbm(self):
        manifest = json.loads((PAYLOAD / 'android-gbm-format-conversion.json').read_text())
        reference = SOURCE.parent / manifest['reference_path']
        self.assertEqual(hashlib.sha256(reference.read_bytes()).hexdigest(), manifest['reference_sha256'])
        text = reference.read_text()
        start = text.index('static const struct format_conversion conversions[] = {')
        table = text[start:text.index('\n};', start) + 3]
        start = text.index('int virgl_gbm_convert_format(')
        function = text[start:text.index('\n}', start) + 2]
        function = function.replace('virgl_gbm_convert_format(', 'reference_convert_format(')
        names = sorted(set(re.findall(r'GBM_FORMAT_([A-Z0-9]+)', table)))
        self.assertEqual(len(names), manifest['format_count'])
        program = '''#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <drm_fourcc.h>
#include "virgl_hw.h"
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
struct format_conversion {uint32_t gbm_format,virgl_format;};
''' + ''.join('#define GBM_FORMAT_%s DRM_FORMAT_%s\n' % (n, n) for n in names)
        program += '#include "vrend_winsys_gbm.h"\n' + table + '\n' + function + '''
static void compare(uint32_t v,uint32_t d) {
 uint32_t rv=v,rd=d,av=v,ad=d;
 int expected=reference_convert_format(&rv,&rd);
 int actual=virgl_gbm_convert_format(&av,&ad);
 assert(actual==expected && av==rv && ad==rd);
 if (actual) assert(av==v && ad==d);
}
int main(void) {
 for (unsigned i=0;i<ARRAY_SIZE(conversions);i++) {
  uint32_t v=conversions[i].virgl_format,d=0;
  assert(virgl_gbm_convert_format(&v,&d)==0 && d==conversions[i].gbm_format);
  v=0;assert(virgl_gbm_convert_format(&v,&d)==0 && v==conversions[i].virgl_format);
  compare(conversions[i].virgl_format,0);
  compare(0,conversions[i].gbm_format);
  compare(conversions[i].virgl_format,conversions[i].gbm_format);
 }
 for (uint32_t v=0;v<1024;v++) compare(v,0);
 uint32_t random=0x73592a81;
 for (unsigned i=0;i<10000;i++) {
  random^=random<<13;random^=random>>17;random^=random<<5;
  compare(0,random);compare(random,random^0x17a3);
 }
 uint32_t value=67;
 assert(virgl_gbm_convert_format(NULL,&value)==-1 && value==67);
 assert(virgl_gbm_convert_format(&value,NULL)==-1 && value==67);
 assert(virgl_gbm_convert_format(NULL,NULL)==-1);
 puts("PASS: ten forward/reverse mappings, protocol sweep, unknown/ambiguous/null refusals; no allocator claim");
}
'''
        with tempfile.TemporaryDirectory(prefix='gb-format-actual-') as temp:
            root = Path(temp)
            path = root / 'test.c'
            path.write_text(program)
            binary = root / 'format-test'
            built = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-parameter', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-g', '-I' + str(SOURCE),
                            '-I' + str(SOURCE.parent / 'prebuilt-intermediates'),
                            '-I' + str(CHECKOUT / 'external/libdrm/include/drm'),
                            str(SOURCE / 'vrend_winsys_gbm_stubs.c'), str(path),
                            '-o', str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr[-8000:])
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(binary)], capture_output=True, text=True, env=env, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr[-8000:])
            self.assertIn('ten forward/reverse mappings', result.stdout)


if __name__ == '__main__':
    unittest.main()
