#!/usr/bin/env python3
"""Actual host import/detach/resource lifetime functions with native stand-ins.

Unbuilt process-opt-in candidate only. Real owned FDs, ASan/UBSan and exact
patch round-trip checks do not qualify GPU retirement, ACKs or graceful refusal.
"""
from pathlib import Path
import hashlib
import json
import os
import resource
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'patches/tb710fu/virglrenderer/native-import-transactional-staging.patch'
MANIFEST = PATCH.with_suffix('.json')
FIXTURE = ROOT / 'tests/fixtures/native_import_transactional_staging.c'


def function(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for end in range(opening + 1, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1]
    raise AssertionError('unterminated source method')


class TransactionalImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-import-staging-')
        root = Path(cls.work.name)
        cls.manifest = json.loads(MANIFEST.read_text())
        for path, expected in cls.manifest.get('host_inputs', {}).items():
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, path
        cls.base = {}
        for entry in cls.manifest['files']:
            data = (ROOT / entry['base_path']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path']
            path = root / entry['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            cls.base[entry['path']] = data.decode()
        assert hashlib.sha256(PATCH.read_bytes()).hexdigest() == cls.manifest['patch_sha256']
        cls.support = {}
        for path, sha in cls.manifest['support_inputs'].items():
            data = (ROOT / path).read_bytes()
            assert hashlib.sha256(data).hexdigest() == sha, path
            cls.support[Path(path).name] = data.decode()
        for reverse, key in [(False, 'result_sha256'), (True, 'sha256'), (False, 'result_sha256')]:
            command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)]
            if reverse:
                command += ['--reverse']
            subprocess.run(command, cwd=root, check=True, capture_output=True, timeout=10)
            for entry in cls.manifest['files']:
                assert hashlib.sha256((root / entry['path']).read_bytes()).hexdigest() == entry[key]
        cls.patched = (root / 'src/vrend_renderer.c').read_text()
        cls.binaries = {}
        for variant, renderer in [('baseline', cls.base['src/vrend_renderer.c']), ('candidate', cls.patched)]:
            source = FIXTURE.read_text()
            for marker, body, signature in [
                ('// ACTUAL_RESOURCE_CONSTRUCTOR', cls.support['virgl_resource.c'], 'static struct virgl_resource *\nvirgl_resource_create('),
                ('// ACTUAL_RESOURCE_FROM_PIPE', cls.support['virgl_resource.c'], 'struct virgl_resource *\nvirgl_resource_create_from_pipe('),
                ('// ACTUAL_RESOURCE_FROM_FD', cls.support['virgl_resource.c'], 'struct virgl_resource *\nvirgl_resource_create_from_fd('),
                ('// ACTUAL_RESOURCE_FROM_OPAQUE', cls.support['virgl_resource.c'], 'struct virgl_resource *\nvirgl_resource_create_from_opaque_handle('),
                ('// ACTUAL_RESOURCE_DESTRUCTOR', cls.support['virgl_resource.c'], 'static void\nvirgl_resource_destroy_func('),
                ('// ACTUAL_SET_TYPE', renderer, 'int\nvrend_renderer_pipe_resource_set_type('),
                ('// ACTUAL_DETACH', renderer, 'void vrend_renderer_detach_res_ctx('),
            ]:
                assert source.count(marker) == 1
                source = source.replace(marker, function(body, signature))
            # Baseline uses the same appended marker field for common fixture
            # access only; its import/detach bodies are unmodified originals.
            path = root / (variant + '.c')
            path.write_text(source)
            binary = root / variant
            built = subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                                    '-I' + str(root / 'src'), str(path), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            if built.returncode:
                cls.work.cleanup()
                raise AssertionError(built.stdout + built.stderr)
            cls.binaries[variant] = binary

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def run_case(self, scenario, variant='candidate', listed=False):
        def no_core_dump():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return subprocess.run([str(self.binaries[variant]), scenario, 'list' if listed else 'cache'],
                              capture_output=True, text=True, timeout=10,
                              cwd=self.work.name, preexec_fn=no_core_dump,
                              env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                       UBSAN_OPTIONS='halt_on_error=1'))

    def test_original_constructor_failure_loses_lookup_in_both_storage_paths(self):
        for listed in [False, True]:
            with self.subTest(listed=listed):
                result = self.run_case('constructor', variant='baseline', listed=listed)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('retained(&ctx,r)', result.stderr)

    def test_actual_candidate_fault_matrix_cache_and_list(self):
        for scenario in ['success', 'dmabuf', 'constructor', 'format', 'refusal', 'pending_null',
                         'texture', 'texture_pending', 'hash_retry_refused', 'hash_teardown',
                         'cross_context', 'cross_context_hash_failure', 'duplicate_attachments', 'fd_type', 'unsupported_format',
                         'factory_initialization', 'missing_and_bad_plane', 'legacy']:
            for listed in [False, True]:
                with self.subTest(scenario=scenario, listed=listed):
                    result = self.run_case(scenario, listed=listed)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stderr, '')

    def test_ownership_and_no_ack_or_retry_claims_are_source_constrained(self):
        source = self.patched
        self.assertNotIn('in_error = false', source)
        self.assertNotIn('gb_android_image_reap', source)
        base = self.base['src/vrend_renderer.c']
        for operation in ['close(res->fd)', 'virgl_egl_android_bridge_destroy(gr->gb_android_image)',
                          'virgl_egl_image_destroy(egl, gr->egl_image)', 'glFinish();']:
            self.assertEqual(source.count(operation), base.count(operation))
        create = self.support['virgl_resource.c']
        self.assertIn('res = calloc(1, sizeof(*res));', function(create, 'static struct virgl_resource *\nvirgl_resource_create('))
        for name in ['virgl_resource_create_from_pipe', 'virgl_resource_create_from_fd', 'virgl_resource_create_from_opaque_handle']:
            body = function(create, 'struct virgl_resource *\n' + name + '(')
            self.assertIn('virgl_resource_create(res_id)', body)
        unref = function(self.support['virglrenderer.c'], 'void virgl_renderer_resource_unref(')
        self.assertLess(unref.index('virgl_context_foreach(&args)'), unref.index('virgl_resource_remove(res->res_id)'))
        self.assertFalse(self.manifest['graceful_refusal_implemented'])
        self.assertFalse(self.manifest['installed'])
        self.assertFalse(self.manifest['runtime_verified'])


if __name__ == '__main__':
    unittest.main()
