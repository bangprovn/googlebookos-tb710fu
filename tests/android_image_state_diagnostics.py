#!/usr/bin/env python3
"""Exact D91 failure diagnostics and actual bridge/read helper host mocks.

ASan/UBSan exercise GPU stand-ins and real owned FDs. No GPU/build/device proof.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT/'patches/tb710fu/virglrenderer'
SOURCE = ROOT/'artifacts/source/crosvm-android16qpr2-backend/external/virglrenderer'


class ImageStateDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-image-state-')
        tree = Path(cls.work.name)
        manifest = json.loads((PATCHES/'android-image-state-diagnostics.json').read_text())
        digest = lambda value: hashlib.sha256(value).hexdigest()
        for path,expected in manifest['host_inputs'].items():
            assert digest((ROOT/path).read_bytes()) == expected,path
        cls.base = {}
        for entry in manifest['files']:
            data = (ROOT/entry['base_path']).read_bytes()
            assert digest(data) == entry['sha256']
            destination = tree/entry['path'];destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data)
            cls.base[entry['path']] = data.decode()
        patch = PATCHES/'android-image-state-diagnostics.patch'
        assert digest(patch.read_bytes()) == manifest['patch_sha256']
        for reverse,key in [(False,'result_sha256'),(True,'sha256'),(False,'result_sha256')]:
            command = ['patch','--batch','--fuzz=0','-p1','-i',str(patch)]
            if reverse:
                command.append('--reverse')
            subprocess.run(command,cwd=tree,check=True,capture_output=True,timeout=10)
            for entry in manifest['files']:
                assert digest((tree/entry['path']).read_bytes()) == entry[key]
        cls.patched = {entry['path']:(tree/entry['path']).read_text() for entry in manifest['files']}
        renderer = cls.patched['src/vrend_renderer.c']
        start = renderer.index('static atomic_uint gb_android_renderer_diag_reports;')
        end = renderer.index('static bool gb_android_framebuffer_writable',start)
        (tree/'src/renderer_diag_excerpt.h').write_text(renderer[start:end])
        cls.binary = tree/'mock'
        build = subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                                '-fsanitize=address,undefined','-fno-omit-frame-pointer','-g',
                                '-I'+str(tree/'src'),'-I'+str(PATCHES),'-I'+str(SOURCE/'src'),
                                str(ROOT/'tests/fixtures/android_image_state_diagnostics_mock.c'),'-ldl','-o',str(cls.binary)],
                               capture_output=True,text=True,timeout=30)
        if build.returncode:
            cls.work.cleanup()
            raise AssertionError(build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self,name):
        run = subprocess.run([str(self.binary),name],capture_output=True,text=True,timeout=10,
                             env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(run.stderr,'')
        records = []
        for line in run.stdout.splitlines():
            prefix,data = line.split(':',1)
            self.assertIn(prefix,['GB-ANDROID-IMAGE-STATE','GB-ANDROID-IMAGE-RENDERER'])
            self.assertLess(len(line),1024)
            record = json.loads(data)
            self.assertEqual(record['schema_version'],1)
            if prefix == 'GB-ANDROID-IMAGE-STATE':
                self.assertFalse(record['snapshot_transactional'])
                for key in ['charged','active','pending','quarantined']:
                    self.assertLessEqual(record[key],8)
                self.assertEqual(record['allocated'],record['active']+record['quarantined']+record['freed'])
            records.append(record)
        return records

    def test_exact_round_trip_and_existing_resource_policy_preserved(self):
        source = self.patched['src/gb_android_image_bridge.h']
        base = self.base['src/gb_android_image_bridge.h']
        self.assertIn('#define GB_IMAGE_SLOTS 8u',source)
        self.assertIn('#define GB_IMAGE_LIMIT (32u * 1024u * 1024u)',source)
        # Reuse existing calls/results; do not add a poll, fence query or GPU wait.
        for token in ['GetFenceStatus(', 'WaitForFences(', 'QueueSubmit(', 'poll(', 'DestroyDevice(']:
            self.assertEqual(source.count(token),base.count(token),token)
        self.assertNotIn('gb_android_image_reap',source)
        renderer = self.patched['src/vrend_renderer.c']
        self.assertIn('if (android_bridge) gb_android_renderer_failure("missing_egl_image",res_id,EINVAL,ctx->sub!=NULL,false);',renderer)
        self.assertIn('if (gr->gb_android_image) gb_android_renderer_failure("texture_import_failed",res_id,ret,ctx->sub!=NULL,false);',renderer)
        self.assertIn('gb_android_renderer_failure("resource_read_failed",res->id,EIO,ctx->sub!=NULL,switched);',renderer)
        self.assertEqual(renderer.count('virgl_egl_android_bridge_required(egl)'),self.base['src/vrend_renderer.c'].count('virgl_egl_android_bridge_required(egl)'))

    def test_slot_refusal_survives_exhausted_original_log_budget_and_reclaims_normally(self):
        records = self.scenario('capacity_after_generic_exhaustion')
        self.assertEqual(len(records),1)
        record = records[0]
        self.assertEqual(record['event'],'slot_refused')
        self.assertEqual((record['charged'],record['active'],record['pending'],record['quarantined']),(8,8,0,0))
        self.assertEqual(record['slot_refused'],1)
        self.assertFalse(record['vk_result_valid'])

    def test_successful_refresh_is_counted_without_logging_or_extra_queries(self):
        self.assertEqual(self.scenario('successful_refresh_and_destroy'),[])

    def test_failed_construction_returns_slots_and_diagnostic_ownership(self):
        records = self.scenario('construction_failure')
        self.assertEqual(records[0]['event'],'create_failed')
        self.assertEqual(records[0]['create_failed'],1)

    def test_exact_vulkan_failures_and_retained_quarantine_without_raw_pointer_retry(self):
        for mode,stage,result in [('wait_failure_quarantine','wait',2),('submit_failure_quarantine','submit',-4)]:
            with self.subTest(mode=mode):
                records = self.scenario(mode)
                self.assertEqual(len(records),3)
                self.assertEqual((records[0]['event'],records[0]['stage'],records[0]['result']),('vulkan_failure',stage,result))
                self.assertTrue(records[0]['vk_result_valid'])
                record = records[-1]
                self.assertEqual(record['event'],'destroy_quarantine')
                self.assertEqual((record['charged'],record['active'],record['pending'],record['quarantined']),(1,0,1,1))
                self.assertEqual(record['result'],1)  # Existing fence query returns VK_NOT_READY.
                self.assertEqual((record['refresh_failed'],record['refresh_skipped']),(1,1))

    def test_failure_cap_independent_of_success_budget_and_cumulative_saturation(self):
        records = self.scenario('independent_bounded_counters')
        self.assertEqual(len(records),32)
        self.assertTrue(all(record['refresh_failed']==2**32-1 for record in records))

    def test_all_quarantined_slot_refusal_is_distinct_from_eight_active_objects(self):
        records = self.scenario('all_quarantined_slot_refusal')
        self.assertEqual(len(records),25)
        record = records[-1]
        self.assertEqual(record['event'],'slot_refused')
        self.assertEqual((record['charged'],record['active'],record['pending'],record['quarantined']),(8,0,8,8))
        self.assertEqual((record['allocated'],record['created'],record['freed']),(8,8,0))

    def test_actual_renderer_read_failures_are_capped_and_preserve_short_circuit_calls(self):
        records = self.scenario('renderer_failures')
        self.assertEqual(len(records),16)
        self.assertEqual([r['event'] for r in records[:4]],['resource_read_failed']*3+['missing_egl_image'])
        self.assertEqual([(r['has_sub'],r['context_switch_succeeded']) for r in records[:3]],[(False,False),(True,False),(True,True)])
        self.assertTrue(all(record['resource_id']==71 for record in records))


if __name__ == '__main__':
    unittest.main()
