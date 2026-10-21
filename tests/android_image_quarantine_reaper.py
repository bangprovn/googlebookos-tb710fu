#!/usr/bin/env python3
"""Actual patched C ownership/reaper under mocked GPU calls and ASan/UBSan.

The active-resource caller remains serialized, matching virglrenderer. Only
registry reaper passes contend concurrently. No GPU/driver/build/device proof.
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


class QuarantineReaper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-quarantine-reaper-')
        tree = Path(cls.work.name)
        cls.manifest = json.loads((PATCHES/'android-image-quarantine-reaper.json').read_text())
        opaque = json.loads((PATCHES/'android-image-opaque-formats.json').read_text())
        digest = lambda data: hashlib.sha256(data).hexdigest()
        for entry in opaque['files']:
            data = (SOURCE/entry['path']).read_bytes()
            assert digest(data) == entry['sha256']
            target = tree/entry['path']; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        for name in ['android-image-opaque-formats', 'android-image-swapchain-budget']:
            manifest = json.loads((PATCHES/(name+'.json')).read_text())
            patch = PATCHES/(name+'.patch')
            assert digest(patch.read_bytes()) == manifest['patch_sha256']
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)],
                           cwd=tree, check=True, capture_output=True, timeout=10)
        header = tree/cls.manifest['base_file']
        assert digest(header.read_bytes()) == cls.manifest['base_sha256']
        patch = PATCHES/'android-image-quarantine-reaper.patch'
        assert digest(patch.read_bytes()) == cls.manifest['patch_sha256']
        for reverse, key in [(False,'result_sha256'), (True,'base_sha256'), (False,'result_sha256')]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
            if reverse:
                command.append('--reverse')
            subprocess.run(command, cwd=tree, check=True, capture_output=True, timeout=10)
            assert digest(header.read_bytes()) == cls.manifest[key]
        cls.patched = header.read_text()
        cls.binary = tree/'quarantine-mock'
        built = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g', '-pthread',
                                '-I'+str(tree/'src'), '-I'+str(PATCHES), '-I'+str(SOURCE/'src'),
                                str(ROOT/'tests/fixtures/android_image_quarantine_mock.c'), '-ldl', '-o', str(cls.binary)],
                               capture_output=True, text=True, timeout=30)
        if built.returncode:
            cls.work.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self, name, expected):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=12,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertIn(expected, result.stdout)

    def test_exact_base_reversible_patch_preserves_eight_slots_and_guards(self):
        self.assertIn('#define GB_IMAGE_SLOTS 8u', self.patched)
        self.assertIn('#define GB_IMAGE_LIMIT (32u * 1024u * 1024u)', self.patched)
        reaper = self.patched.split('static unsigned gb_android_image_reap(void)',1)[1].split('static void gb_android_image_destroy',1)[0]
        self.assertNotIn('WaitForFences', reaper)
        self.assertNotIn('DeviceWaitIdle', reaper)
        self.assertIn('==VK_SUCCESS', reaper)
        self.scenario('capacity_and_fd_cleanup', 'simultaneous_mock_imports=8; excess_import_refused=1')

    def test_reclaims_completed_submission_after_original_owner_disappears(self):
        self.scenario('completed_after_owner_disappears', 'bounded nonwaiting reaping and FD cleanup')

    def test_partial_creation_failure_returns_registry_and_slot_reservation(self):
        self.scenario('loader_failure_rolls_back_registry', 'bounded nonwaiting reaping and FD cleanup')

    def test_admission_opportunistically_reuses_completed_quarantine(self):
        self.scenario('admission_reaps_completed_quarantine', 'bounded nonwaiting reaping and FD cleanup')

    def test_contended_reapers_exclusively_claim_each_entry_once(self):
        self.scenario('contended_reapers_claim_once', 'bounded nonwaiting reaping and FD cleanup')

    def test_errors_and_missing_query_retain_all_eight_complete_objects(self):
        for name in ['device_lost_stays_bounded', 'missing_query_stays_bounded']:
            with self.subTest(name=name):
                self.scenario(name, 'unresolved work retains eight complete registry-owned images')


if __name__ == '__main__':
    unittest.main()
