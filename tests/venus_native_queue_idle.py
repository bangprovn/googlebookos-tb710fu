#!/usr/bin/env python3
"""Check actual diagnostic guard functions and reversible pinned source patch."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'patches/tb710fu/mesa'


class QueueIdle(unittest.TestCase):
    def test_guard_and_error_propagation_with_sanitizers(self):
        with tempfile.TemporaryDirectory() as work:
            executable = Path(work) / 'guard'
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(PATCHES), str(ROOT/'tests/venus_native_queue_idle.c'),
                            '-o', str(executable)], check=True, capture_output=True, timeout=30)
            subprocess.run([str(executable)], check=True, capture_output=True, timeout=3,
                           env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                    UBSAN_OPTIONS='halt_on_error=1'))

    def test_patch_round_trip_and_exact_source_pins(self):
        manifest = json.loads((PATCHES/'guest-native-queue-idle.json').read_text())
        source = ROOT/'artifacts/device/first-boot-20261013/image-wsi-diagnostic-20261020-v1/acquire-syncfd-v1/vn_wsi.c'
        digest = lambda data: hashlib.sha256(data).hexdigest()
        self.assertEqual(digest(source.read_bytes()), manifest['base_sha256'])
        patch = PATCHES/'guest-native-queue-idle.patch'
        self.assertEqual(digest(patch.read_bytes()), manifest['patch_sha256'])
        self.assertEqual(digest((PATCHES/'gb-native-queue-idle.h').read_bytes()), manifest['helper_sha256'])
        with tempfile.TemporaryDirectory() as work:
            file = Path(work)/manifest['base_file']; file.parent.mkdir(parents=True)
            file.write_bytes(source.read_bytes())
            for reverse, expected in [(False, 'result_sha256'), (True, 'base_sha256')]:
                command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
                if reverse:
                    command.append('--reverse')
                subprocess.run(command, cwd=work, check=True, capture_output=True, timeout=3)
                self.assertEqual(digest(file.read_bytes()), manifest[expected])


if __name__ == '__main__':
    unittest.main()
