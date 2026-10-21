#!/usr/bin/env python3
"""Exercise the actual bounded bridge under the overlap-capacity patch.

Mock GPU calls qualify successful simultaneous imports, admission, rollback,
slot reclamation, FD and quarantine invariants only.
Actual native animation must be verified separately after installation.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'artifacts/source/crosvm-android16qpr2-backend/external/virglrenderer'
PATCHES = ROOT/'patches/tb710fu/virglrenderer'


class SwapchainBudget(unittest.TestCase):
    def test_exact_patch_and_actual_eight_slot_admission_cleanup(self):
        opaque = json.loads((PATCHES/'android-image-opaque-formats.json').read_text())
        manifest = json.loads((PATCHES/'android-image-swapchain-budget.json').read_text())
        patch = PATCHES/'android-image-swapchain-budget.patch'
        digest = lambda data: hashlib.sha256(data).hexdigest()
        self.assertEqual(digest(patch.read_bytes()), manifest['patch_sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-swapchain-capacity-') as work:
            tree = Path(work)
            for entry in opaque['files']:
                data = (SOURCE/entry['path']).read_bytes()
                self.assertEqual(digest(data), entry['sha256'])
                target = tree/entry['path']; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCHES/'android-image-opaque-formats.patch')],
                           cwd=tree, check=True, capture_output=True, timeout=10)
            header = tree/manifest['base_file']
            self.assertEqual(digest(header.read_bytes()), manifest['base_sha256'])
            for reverse, key in [(False, 'result_sha256'), (True, 'base_sha256'), (False, 'result_sha256')]:
                command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
                if reverse:
                    command.append('--reverse')
                subprocess.run(command, cwd=tree, check=True, capture_output=True, timeout=10)
                self.assertEqual(digest(header.read_bytes()), manifest[key])
            self.assertIn('#define GB_IMAGE_SLOTS 8u', header.read_text())
            self.assertIn('#define GB_IMAGE_LIMIT (32u * 1024u * 1024u)', header.read_text())
            executable = tree/'mock'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                            '-I'+str(tree/'src'), '-I'+str(PATCHES), '-I'+str(SOURCE/'src'),
                            str(ROOT/'tests/fixtures/android_image_bridge_mock.c'), '-ldl', '-o', str(executable)],
                           check=True, capture_output=True, timeout=30)
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=10,
                                    env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
            self.assertIn('pending quarantine (mock GPU only)', result.stdout)
            self.assertIn('simultaneous_mock_imports=8; excess_import_refused=1; '
                          'released_slots_reclaimed=4; final_slots=0; final_fd_delta=0 '
                          '(mock GPU only)', result.stdout)


if __name__ == '__main__':
    unittest.main()
