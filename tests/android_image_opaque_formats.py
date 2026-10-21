#!/usr/bin/env python3
"""Check the additive opaque-format patch against the pinned D89 source.

Compiles actual bridge C under ASan/UBSan with mock GPU calls. This validates
metadata, admission, ownership and bounded lifetime rules, not real rendering.
The separate RGBX physical control is required before guest qualification.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'artifacts/source/crosvm-android16qpr2-backend/external/virglrenderer'
PAYLOAD = ROOT / 'patches/tb710fu/virglrenderer'


class OpaqueFormats(unittest.TestCase):
    def test_exact_patch_round_trip_and_actual_bridge_rules(self):
        manifest = json.loads((PAYLOAD / 'android-image-opaque-formats.json').read_text())
        patch = PAYLOAD / 'android-image-opaque-formats.patch'
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), manifest['patch_sha256'])
        with tempfile.TemporaryDirectory(prefix='gb-opaque-formats-') as temp:
            root = Path(temp)
            for entry in manifest['files']:
                original = (SOURCE / entry['path']).read_bytes()
                self.assertEqual(hashlib.sha256(original).hexdigest(), entry['sha256'])
                target = root / entry['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original)
            for reverse, digest in [(False, 'result_sha256'), (True, 'sha256'),
                                    (False, 'result_sha256')]:
                command = ['patch', '--batch', '--fuzz=0', '--strip=1', '--input', str(patch)]
                if reverse:
                    command.append('--reverse')
                result = subprocess.run(command, cwd=root, capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for entry in manifest['files']:
                    actual = hashlib.sha256((root / entry['path']).read_bytes()).hexdigest()
                    self.assertEqual(actual, entry[digest])
            binary = root / 'mock'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                            '-I' + str(root / 'src'), '-I' + str(PAYLOAD),
                            '-I' + str(SOURCE / 'src'),
                            str(ROOT / 'tests/fixtures/android_image_bridge_mock.c'),
                            '-ldl', '-o', str(binary)],
                           capture_output=True, check=True, timeout=30)
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    timeout=10, env=env)
            self.assertEqual(result.returncode, 0, result.stderr[-8000:])
            self.assertIn('pending quarantine (mock GPU only)', result.stdout)


if __name__ == '__main__':
    unittest.main()
