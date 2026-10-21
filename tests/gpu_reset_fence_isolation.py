#!/usr/bin/env python3
"""Offline feasibility regression, not an installed reset-fence patch.

Compile checksum-pinned actual forwarding methods plus the exact upstream ID
allocator with renderer/IPC stand-ins. Demonstrate why isolated remapping needs
export/input-ID translation. No network, native VMM build, or device access.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'patches/tb710fu/crosvm/gpu-reset-fence-isolation.json'
FIXTURE = ROOT / 'tests/fixtures/gpu_reset_fence_isolation.rs'


def function(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    for i in range(opening + 1, len(source)):
        depth += (source[i] == '{') - (source[i] == '}')
        if depth == 0:
            return source[start:i + 1]
    raise AssertionError('Unterminated source function')


class ResetFenceFeasibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())
        cls.sources = {}
        for entry in cls.manifest['source_inputs']:
            path = ROOT / entry['path']
            data = path.read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path']
            cls.sources[entry['id']] = data.decode()
        data = FIXTURE.read_bytes()
        assert hashlib.sha256(data).hexdigest() == cls.manifest['fixture_sha256']
        cls.fixture = data.decode()

    def test_no_backport_is_advertised_and_verbatim_allocator_is_pinned(self):
        self.assertEqual(self.manifest['state'], 'blocked_dependency_translation')
        self.assertFalse(self.manifest['patch_created'])
        self.assertFalse((MANIFEST.parent / 'gpu-reset-fence-isolation.patch').exists())
        allocator = self.fixture.split('// BEGIN VERBATIM UPSTREAM ALLOCATOR\n', 1)[1].split(
            '// END VERBATIM UPSTREAM ALLOCATOR', 1)[0]
        self.assertEqual(hashlib.sha256(allocator.encode()).hexdigest(),
                         self.manifest['upstream_allocator']['sha256'])

    def test_actual_forwarders_expose_missing_and_wrong_fence_id_lookup(self):
        source = self.fixture
        replacements = {
            '// ACTUAL_RESOURCE_BRIDGE': ('frontend', '    pub fn process_resource_bridge('),
            '// ACTUAL_VIRTIO_EXPORT': ('virtio_gpu', '    pub fn export_fence('),
            '// ACTUAL_VIRTIO_SUBMIT': ('virtio_gpu', '    pub fn submit_command('),
            '// ACTUAL_RUTABAGA_EXPORT': ('rutabaga', '    pub fn export_fence('),
            '// ACTUAL_RUTABAGA_SUBMIT': ('rutabaga', '    pub fn submit_command('),
        }
        for marker, (name, signature) in replacements.items():
            self.assertEqual(source.count(marker), 1)
            # Actual source body, without substitutions or a mirrored forwarder.
            source = source.replace(marker, function(self.sources[name], signature))
        with tempfile.TemporaryDirectory(prefix='gb-fence-feasibility-') as directory:
            root = Path(directory)
            rust = root / 'actual.rs'
            rust.write_text(source)
            for mode in ['virgl', 'shareable']:
                with self.subTest(mode=mode):
                    binary = root / mode
                    command = ['rustc', '--edition=2021', '--test', '-D', 'warnings',
                               str(rust), '-o', str(binary)]
                    if mode == 'shareable':
                        command += ['--cfg', 'fence_passing_option1']
                    built = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                    tested = subprocess.run([str(binary), '--nocapture'], capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
                    self.assertIn('7 passed; 0 failed', tested.stdout)

    def test_untranslated_protocol_inputs_and_build_variants_are_present(self):
        frontend = self.sources['frontend']
        self.assertIn('fence_ids.push(fence_id.to_native());', frontend)
        self.assertIn('virtio_gpu_features |= 1 << VIRTIO_GPU_F_FENCE_PASSING;', frontend)
        self.assertIn('ResourceRequest::GetFence { seqno }', frontend)
        build = self.sources['rutabaga_build']
        self.assertIn('use_fence_passing_option1 = false;', build)
        self.assertIn('lib.defines.contains_key("VIRGL_RENDERER_UNSTABLE_APIS")', build)
        backend = self.sources['virgl_backend']
        self.assertIn('virgl_renderer_export_fence(fence_id, &mut fd)', backend)
        self.assertIn('fence_ids.as_ptr() as *mut u64', backend)
        self.assertIn('ResourceRequest::GetFence {', self.sources['virtio_wl'])


if __name__ == '__main__':
    unittest.main()
