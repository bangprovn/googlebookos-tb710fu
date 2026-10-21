#!/usr/bin/env python3
"""Pinned insertion-only native GPU instrumentation; host actual-helper tests only.

No renderer/native Android build, device, workload performance or CPU-fix claim.
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
PATCH = ROOT / 'patches/tb710fu/crosvm/gpu-idle-worker-counters.patch'
MANIFEST = PATCH.with_suffix('.json')

class WorkerCounters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-gpu-idle-counter-test-')
        cls.tree = Path(cls.work.name)
        cls.manifest = json.loads(MANIFEST.read_text())
        entry, = cls.manifest['files']
        cls.base = (ROOT / entry['base_path']).read_bytes()
        sha = lambda data: hashlib.sha256(data).hexdigest()
        assert sha(cls.base) == entry['sha256']
        assert sha(PATCH.read_bytes()) == cls.manifest['patch_sha256']
        for path, expected in (cls.manifest.get('host_inputs', {}) | cls.manifest.get('support_inputs', {})).items():
            assert sha((ROOT / path).read_bytes()) == expected, path
        path = cls.tree / entry['path']
        path.parent.mkdir(parents=True)
        path.write_bytes(cls.base)
        for reverse, expected in [(False, entry['result_sha256']), (True, entry['sha256']), (False, entry['result_sha256'])]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)]
            if reverse:
                command.append('--reverse')
            subprocess.run(command, cwd=cls.tree, check=True, capture_output=True, timeout=10)
            assert sha(path.read_bytes()) == expected
        cls.source = path.read_text()
        helper = re.search(r'/\* GB_GPU_IDLE_COUNTERS_BEGIN.*?/\* GB_GPU_IDLE_COUNTERS_END \*/\n\n', cls.source, re.S).group()
        enum = re.search(r'enum WorkerToken \{.*?\n\}', cls.source, re.S).group()
        fixture = (ROOT / 'tests/fixtures/gpu_idle_worker_counters.rs').read_text()
        assert (ROOT / 'artifacts/source/crosvm-android16qpr2-backend/external/crosvm/LICENSE').read_text() in fixture
        assert fixture.count('// ACTUAL_WORKER_TOKEN') == fixture.count('// ACTUAL_GPU_IDLE_COUNTERS') == 1
        fixture = fixture.replace('// ACTUAL_WORKER_TOKEN', '#[derive(Clone, Copy, Debug)]\n' + enum).replace('// ACTUAL_GPU_IDLE_COUNTERS', helper)
        cls.program = cls.tree / 'fixture.rs'
        cls.program.write_text(fixture)
        cls.binary = cls.tree / 'fixture'
        q = subprocess.run(['rustc', '--edition=2021', '-Dwarnings', '-Coverflow-checks=yes',
                            str(cls.program), '-o', str(cls.binary)], capture_output=True, text=True, timeout=30)
        assert q.returncode == 0, q.stdout + q.stderr

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def run_case(self, scenario):
        q = subprocess.run([str(self.binary), scenario], capture_output=True, text=True, timeout=10,
                           cwd=self.tree, env=dict(os.environ, RUST_BACKTRACE='0'))
        self.assertEqual((q.returncode, q.stderr), (0, ''), q.stdout + q.stderr)
        return q.stdout

    def records(self, scenario):
        values = []
        for line in self.run_case(scenario).splitlines():
            self.assertTrue(line.startswith('GB-GPU-IDLE-TRACE:'))
            self.assertLessEqual(len(line), 2048)
            value = json.loads(line.removeprefix('GB-GPU-IDLE-TRACE:'))
            self.assertEqual(value['schema_version'], 1)
            self.assertEqual(value['scope'], 'worker_event_counters')
            self.assertFalse(value['cpu_usage_measured'])
            values.append(value)
        return values

    def test_insertion_only_actual_worker_policy_and_hooks(self):
        source = re.sub(r'/\* GB_GPU_IDLE_COUNTERS_BEGIN.*?/\* GB_GPU_IDLE_COUNTERS_END \*/\n\n', '', self.source, flags=re.S)
        source = re.sub(r'^[ \t]*// GB_GPU_IDLE_HOOK_BEGIN\n.*?^[ \t]*// GB_GPU_IDLE_HOOK_END\n', '', source, flags=re.S | re.M)
        self.assertEqual(source.encode(), self.base)
        self.assertEqual(self.source.count('GB_GPU_IDLE_HOOK_BEGIN'), 11)
        self.assertIn('std::env::var("GB_GPU_IDLE_TRACE_V1")', self.source)
        helper = re.search(r'/\* GB_GPU_IDLE_COUNTERS_BEGIN.*?/\* GB_GPU_IDLE_COUNTERS_END \*/', self.source, re.S).group()
        self.assertNotRegex(helper, r'\b(?:sleep|spawn|wait_timeout|wait|poll)\s*\(')
        self.assertNotIn('resource_id', helper)
        self.assertNotIn('process::', helper)
        self.assertIn('trace.queue_progress(true)', self.source)
        self.assertIn('trace.queue_progress(false)', self.source)
        self.assertIn('trace.flip_sweep(gpu_idle_flip_before, self.state.pending_flip_fences.len())', self.source)
        # Native compilation is a separately pinned build result. These host
        # fixtures still cannot establish Android execution or an idle repair.
        self.assertFalse(self.manifest['runtime_verified'])
        self.assertFalse(self.manifest['idle_cpu_fixed'])

    def test_exact_token_no_output_and_time_global_budget(self):
        self.assertEqual(self.run_case('tokens'), 'HOST_PASS\n')
        self.assertEqual(self.run_case('time_and_budget'), 'HOST_PASS\n')
        values = self.records('concurrent_budget')
        self.assertEqual(len(values), 16)
        self.assertEqual(sorted(value['record'] for value in values), list(range(1, 17)))

    def test_actual_event_progress_flip_and_duration_semantics(self):
        value, = self.records('events')
        self.assertEqual((value['waits'], value['empty_waits'], value['quick_waits_le_100us']), (2, 1, 1))
        self.assertEqual(value['wait_ns'], 1_000_100_000)
        self.assertEqual(value['work_ns'], 2_000_000)
        for name, count in value['readable_tokens'].items():
            self.assertEqual(count, 2 if name == 'resource_bridge' else 0 if name == 'display_descriptor_request' else 1)
        self.assertEqual(value['queue_progress_batches'], dict(ctrl=1, cursor=1))
        self.assertEqual((value['flip_pending_peak'], value['flip_retired']), (3, 2))
        self.assertFalse(value['final_record'])
        checkpoint, = self.records('checkpoint')
        self.assertTrue(checkpoint['final_record'])

    def test_all_counters_and_record_budget_saturate_without_panic(self):
        value, = self.records('saturation')
        for field in ['waits', 'empty_waits', 'quick_waits_le_100us', 'wait_ns', 'work_ns', 'flip_retired']:
            self.assertEqual(value[field], 2**64 - 1)
        self.assertTrue(all(count == 2**64 - 1 for count in value['readable_tokens'].values()))
        self.assertTrue(all(count == 2**64 - 1 for count in value['queue_progress_batches'].values()))

if __name__ == '__main__':
    unittest.main()
