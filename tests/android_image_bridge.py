#!/usr/bin/env python3
"""Exercise actual bridge C with mock GPU calls and real owned descriptors.
Requires the prepared virglrenderer checkout; never loads a firmware driver.
"""
from pathlib import Path
import os
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'artifacts/source/crosvm-android16qpr2-backend/external/virglrenderer/src'
PAYLOAD = ROOT / 'patches/tb710fu/virglrenderer'


class Bridge(unittest.TestCase):
    def test_additive_layout_diagnostics_refusal_masks_and_shared_log_budget(self):
        manifest = json.loads((PAYLOAD / 'android-image-layout-diagnostics.json').read_text())
        patch = PAYLOAD / 'android-image-layout-diagnostics.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), manifest['patch_sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-layout-diagnostic-') as temp:
            root = Path(temp)
            header = root / 'src/gb_android_image_bridge.h'
            header.parent.mkdir()
            header.write_bytes((PAYLOAD / 'gb_android_image_bridge.h').read_bytes())
            self.assertEqual(hashlib.sha256(header.read_bytes()).hexdigest(), manifest['files'][0]['sha256'])
            subprocess.run(['patch', '--batch', '--strip=1', '--input', str(patch)],
                           cwd=root, capture_output=True, check=True, timeout=10)
            self.assertEqual(hashlib.sha256(header.read_bytes()).hexdigest(), manifest['files'][0]['result_sha256'])
            self.assertEqual(header.read_bytes(), (SOURCE / 'gb_android_image_bridge.h').read_bytes())
            binary = root / 'mock'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                            '-I' + str(header.parent), '-I' + str(PAYLOAD), '-I' + str(SOURCE),
                            str(ROOT / 'tests/fixtures/android_image_bridge_mock.c'), '-ldl', '-o', str(binary)],
                           capture_output=True, check=True, timeout=30)
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10, env=env)
            self.assertEqual(result.returncode, 0, result.stderr[-8000:])

    def test_pinned_patch_reverses_and_reapplies_exactly(self):
        manifest = json.loads((PAYLOAD / 'android-image-bridge.json').read_text())
        patch = PAYLOAD / 'android-image-bridge.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), manifest['patch_sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-bridge-patch-') as temp:
            root = Path(temp)
            for entry in manifest['files']:
                source = SOURCE.parent / entry['path']
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), entry['result_sha256'],
                                 'prepare the version-pinned bridge patch before this check')
                target = root / entry['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            for reverse, digest in [(True, 'sha256'), (False, 'result_sha256')]:
                command = ['patch', '--batch', '--strip=1', '--input', str(patch)]
                if reverse:
                    command.append('--reverse')
                result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for entry in manifest['files']:
                    self.assertEqual(hashlib.sha256((root / entry['path']).read_bytes()).hexdigest(), entry[digest])
            for entry in manifest['payloads']:
                self.assertEqual(hashlib.sha256((PAYLOAD / entry['input']).read_bytes()).hexdigest(), entry['sha256'])

    def test_gl_read_scope_finishes_normal_and_early_returns(self):
        source = (SOURCE / 'vrend_renderer.c').read_text()
        start = source.index('struct gb_android_read_scope {')
        end = source.index('\nstatic int gb_android_resource_read', start)
        scope = source[start:end]
        program = '''#include <stdbool.h>
#include <assert.h>
static int finishes;
static void glFinish(void) {finishes++;}
''' + scope + '''
static int operation(bool active, bool early) {
 GB_ANDROID_READ_SCOPE(read); read.active=active;
 if (early) return 7;
 return 0;
}
int main(void) {
 assert(operation(false,false)==0 && finishes==0);
 assert(operation(false,true)==7 && finishes==0);
 assert(operation(true,false)==0 && finishes==1);
 assert(operation(true,true)==7 && finishes==2);
}
'''
        with tempfile.TemporaryDirectory(prefix='gb-gl-read-scope-') as temp:
            path = Path(temp) / 'scope.c'
            path.write_text(program)
            binary = Path(temp) / 'scope'
            subprocess.run(['cc', '-std=gnu17', '-Wall', '-Wextra', '-Werror',
                            str(path), '-o', str(binary)], check=True, timeout=15)
            subprocess.run([str(binary)], check=True, timeout=5)

    def test_owned_fd_lifetime_admission_barriers_reuse_and_timeout(self):
        self.assertTrue((SOURCE / 'venus/vkr_library.h').is_file(),
                        'prepare the pinned virglrenderer source before this check')
        with tempfile.TemporaryDirectory(prefix='gb-image-bridge-') as temp:
            binary = Path(temp) / 'mock'
            command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                       '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                       '-I' + str(PAYLOAD), '-I' + str(SOURCE),
                       str(ROOT / 'tests/fixtures/android_image_bridge_mock.c'),
                       '-ldl', '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr[-8000:])
            env = os.environ.copy()
            env.update(ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    timeout=10, env=env)
            self.assertEqual(result.returncode, 0, result.stderr[-8000:])
            self.assertIn('pending quarantine (mock GPU only)', result.stdout)


if __name__ == '__main__':
    unittest.main()
