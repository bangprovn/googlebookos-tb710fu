#!/usr/bin/env python3
"""Actual patched bridge + bounded backing ledger, with host GPU stand-ins.

Real owned FDs, ASan/UBSan, and mutex contention exercise admission/cleanup.
This does not prove GPU allocation, physical memory usage, or presentation.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / 'patches/tb710fu/virglrenderer'
SOURCE = ROOT / 'artifacts/source/crosvm-android16qpr2-backend/external/virglrenderer'
BASE_MOCK = ROOT / 'tests/fixtures/android_image_bridge_mock.c'
FIXTURE = ROOT / 'tests/fixtures/android_image_backing_budget_mock.c'
digest = lambda data: hashlib.sha256(data).hexdigest()


def replace_once(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)


def controlled_mock(source):
    """Only the staged mock changes: fault injection and driver-boundary probes.

    Allocation sizes come from the actual bridge; the mock never invents a
    budget or changes a production helper. FD consumption follows Vulkan's
    successful-import-only ownership rule.
    """
    source = replace_once(source, 'i->allocationSize==8192',
                          'i->allocationSize>0 && i->allocationSize<=GB_IMAGE_LIMIT')
    source = replace_once(source,
        'const VkBaseInStructure *import=dedicated->pNext;assert(import);',
        '''const VkBaseInStructure *import=dedicated->pNext;assert(import);
   bool source_import=import->sType==VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR;
   budget_allocation_probe(i->allocationSize,source_import);
   if ((test_fault==1 && source_import) || (test_fault==6 && !source_import))
      return VK_ERROR_OUT_OF_DEVICE_MEMORY;''')
    source = replace_once(source,
        '   if (!successful_imports) return -1;',
        '   budget_ahb_probe();\n   if (test_fault==2 || !successful_imports) return -1;')
    source = replace_once(source,
        '{assert(d && b);out->allocationSize=8192;',
        '''{assert(d && b);if(test_fault==3) return VK_ERROR_OUT_OF_DEVICE_MEMORY;
   out->allocationSize=test_fault==4?GB_IMAGE_LIMIT+4096ull:
      test_fault==7?0:test_fault==8?1024:test_destination_bytes;''')
    source = replace_once(source,
        '{assert(d && i && m && offset==0);return VK_SUCCESS;}',
        '''{assert(d && i && m && offset==0);test_bind_calls++;
   if(test_fault==5 && test_bind_calls==2) return VK_ERROR_DEVICE_LOST;
   return VK_SUCCESS;}''')
    for old, new in [
        ('{assert(d);(void)a;destroyed_device++;}',
         '{assert(d);budget_unlocked_probe();(void)a;destroyed_device++;}'),
        ('{assert(b);released++;if (successful_imports) free(b);}',
         '{assert(b);budget_unlocked_probe();released++;if (successful_imports) free(b);}'),
        ('{(void)lib;unloads++;}', '{(void)lib;budget_unlocked_probe();unloads++;}'),
        ('{assert(handle==&native_tag);dl_closed++;return 0;}',
         '{assert(handle==&native_tag);budget_unlocked_probe();dl_closed++;return 0;}'),
    ]:
        source = replace_once(source, old, new)
    return source


class ImageBackingBudget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-image-budget-')
        tree = Path(cls.work.name)
        cls.manifest = json.loads((PATCHES / 'android-image-backing-budget.json').read_text())
        for path, expected in cls.manifest.get('host_inputs', {}).items():
            assert digest((ROOT / path).read_bytes()) == expected, path
        cls.base = {}
        for entry in cls.manifest['files']:
            data = (ROOT / entry['base_path']).read_bytes()
            assert digest(data) == entry['sha256'], entry['path']
            path = tree / entry['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            cls.base[entry['path']] = data.decode()
        patch = PATCHES / 'android-image-backing-budget.patch'
        assert digest(patch.read_bytes()) == cls.manifest['patch_sha256']
        for reverse, key in [(False, 'result_sha256'), (True, 'sha256'), (False, 'result_sha256')]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
            if reverse:
                command.append('--reverse')
            subprocess.run(command, cwd=tree, check=True, capture_output=True, timeout=10)
            for entry in cls.manifest['files']:
                assert digest((tree / entry['path']).read_bytes()) == entry[key]
        cls.patched = {entry['path']: (tree / entry['path']).read_text()
                       for entry in cls.manifest['files']}
        # Keep the existing shared fixture immutable and pin its content.
        assert digest(BASE_MOCK.read_bytes()) == 'dccaf525b89011360e8169eef00baea4e39b8217f3324808cb47a02b3d0020d5'
        assert digest((SOURCE / 'src/gb_vulkan_android.h').read_bytes()) == '298808a42c18f61a43d9c74beb91815c52f1808b41e4881c0a448f32ff6aa5cc'
        (tree / BASE_MOCK.name).write_text(controlled_mock(BASE_MOCK.read_text()))
        (tree / FIXTURE.name).write_bytes(FIXTURE.read_bytes())
        cls.binary = tree / 'mock'
        build = subprocess.run([
            'cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g', '-pthread',
            '-I' + str(tree / 'src'), '-I' + str(PATCHES), '-I' + str(SOURCE / 'src'),
            str(tree / FIXTURE.name), '-ldl', '-o', str(cls.binary),
        ], capture_output=True, text=True, timeout=30)
        if build.returncode:
            cls.work.cleanup()
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self, name):
        run = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=12,
                             env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                      UBSAN_OPTIONS='halt_on_error=1'))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(run.stderr, '')
        records = []
        for line in run.stdout.splitlines():
            if line == 'PASS backing ledger (mock GPU only)':
                continue
            self.assertTrue(line.startswith('GB-ANDROID-IMAGE-STATE:'), line)
            self.assertLess(len(line), 1024)
            record = json.loads(line.split(':', 1)[1])
            self.assertFalse(record['snapshot_transactional'])
            self.assertEqual(record['backing_limit_bytes'], 536870912)
            self.assertLessEqual(record['backing_bytes'], 536870912)
            self.assertLessEqual(record['charged'], 16)
            self.assertNotEqual(record['event'], 'accounting_failure')
            records.append(record)
        self.assertLessEqual(len(records), 32)
        return records

    def test_exact_round_trip_and_unchanged_gpu_operations_and_renderer(self):
        source = self.patched['src/gb_android_image_bridge.h']
        base = self.base['src/gb_android_image_bridge.h']
        self.assertIn('#define GB_IMAGE_SLOTS 16u', source)
        self.assertIn('#define GB_IMAGE_LIMIT (32u * 1024u * 1024u)', source)
        self.assertIn('#define GB_IMAGE_BACKING_LIMIT (512ull * 1024ull * 1024ull)', source)
        for call in ['GetFenceStatus(', 'WaitForFences(', 'QueueSubmit(', 'poll(',
                     'DestroyDevice(', 'dup(', 'close(', 'dlopen(', 'allocate(&desc']:
            self.assertEqual(source.count(call), base.count(call), call)
        self.assertNotIn('gb_android_image_reap', source)
        self.assertEqual(self.patched['src/vrend_renderer.c'], self.base['src/vrend_renderer.c'])
        # All untrusted input/FD/layout checks before admission stay verbatim.
        create = 'static struct gb_android_image *gb_android_image_create('
        old_guards = base[base.index(create):base.index('   unsigned slots=atomic_load(&gb_image_slots);', base.index(create))]
        new_guards = source[source.index(create):source.index('   /* Charge the complete imported FD,', source.index(create))]
        self.assertEqual(new_guards, old_guards)

    def test_sixteen_small_images_then_seventeenth_refused_released_and_reused(self):
        record, = self.scenario('sixteen_small')
        self.assertEqual((record['event'], record['charged'], record['active']), ('slot_refused', 16, 16))
        self.assertEqual(record['backing_bytes'], 16 * 16384)
        self.assertEqual(record['requested_backing_bytes'], 33554432 + 8192)
        self.assertEqual((record['slot_refused'], record['backing_refused']), (1, 0))

    def test_eight_maximum_images_exhaust_same_512mib_despite_free_slots(self):
        record, = self.scenario('eight_maximum')
        self.assertEqual((record['event'], record['charged'], record['active']), ('backing_refused', 8, 8))
        self.assertEqual(record['backing_bytes'], 536870912)
        self.assertEqual(record['requested_backing_bytes'], 67108864)
        self.assertEqual((record['slot_refused'], record['backing_refused']), (0, 1))

    def test_complete_source_fd_not_smaller_vk_image_requirements_is_charged(self):
        self.assertEqual(self.scenario('full_fd_not_requirements'), [])

    def test_constructor_faults_rollback_only_after_native_cleanup(self):
        for mode in ['calloc', 'loader', '1', '2', '3', '4', '5', '6', '7', '8']:
            with self.subTest(fault=mode):
                records = self.scenario('rollback_' + mode)
                self.assertTrue(any(record['event'] == 'create_failed' for record in records))
                self.assertFalse(any(record['event'] in ['backing_refused', 'slot_refused'] for record in records))

    def test_pending_quarantine_keeps_slot_and_bytes_without_raw_pointer_retry(self):
        records = self.scenario('quarantine_holds_both_quotas')
        record = records[-1]
        self.assertEqual(record['event'], 'destroy_quarantine')
        self.assertEqual((record['charged'], record['active'], record['pending'], record['quarantined']), (1, 0, 1, 1))
        self.assertEqual(record['backing_bytes'], 16384)

    def test_quarantined_maximum_backing_blocks_new_image_with_free_slots(self):
        records = self.scenario('quarantined_maximum_prevents_new_admission')
        record = records[-1]
        self.assertEqual(record['event'], 'backing_refused')
        self.assertEqual((record['charged'], record['active'], record['pending'], record['quarantined']), (8, 0, 8, 8))
        self.assertEqual(record['backing_bytes'], 536870912)
        self.assertEqual(record['requested_backing_bytes'], 67108864)

    def test_failure_records_remain_independently_bounded_with_byte_metadata(self):
        records = self.scenario('bounded_failure_records')
        self.assertEqual(len(records), 32)
        self.assertTrue(all(record['event'] == 'slot_refused' for record in records))
        self.assertEqual([record['slot_refused'] for record in records], list(range(1, 33)))

    def test_shrink_and_invalid_operations_do_not_underflow_accounting(self):
        self.assertEqual(self.scenario('reservation_shrink_and_invalid_operations'), [])

    def test_concurrent_helpers_reserve_slots_and_bytes_as_one_pair(self):
        # No concurrent native image calls: test scope is the actual mutex ledger.
        self.assertEqual(self.scenario('concurrent_pair_reservations'), [])


if __name__ == '__main__':
    unittest.main()
