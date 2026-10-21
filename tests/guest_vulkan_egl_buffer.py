#!/usr/bin/env python3
"""Host regression for explicit selection and refusal to qualify CPU as Venus.

The physical positive DMA-BUF test requires the tablet's qualified Venus/virgl
pair. This host test deliberately establishes no interoperability capability.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)


def main():
    with tempfile.TemporaryDirectory(prefix='gb-vulkan-egl-host-') as work:
        for kind in ['buffer', 'image']:
            program = Path(work) / ('producer-' + kind)
            subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / ('tests/fixtures/guest_vulkan_egl_' + kind + '.c')),
                            '-ldl', '-o', str(program)], check=True, timeout=60)
            for args in [[], ['--venus-icd', 'relative', '--egl-consumer', '/no-consumer'],
                         ['--venus-icd', '/none', '--egl-consumer', 'relative']]:
                result = run([str(program), *args])
                receipt = json.loads(result.stdout)
                assert result.returncode == 1 and receipt['stage'] == 'explicit_venus_icd_and_consumer_required'
            candidates = list(Path('/usr/share/vulkan/icd.d').glob('lvp*.json'))
            assert len(candidates) == 1, 'one installed Lavapipe control ICD required'
            result = run([str(program), '--venus-icd', str(candidates[0]), '--egl-consumer',
                          str(ROOT / 'tests/fixtures/guest_egl_dma_buf.py')])
            assert result.returncode == 1 and json.loads(result.stdout)['stage'] == 'selected_driver_identity_mismatch'
            if kind == 'image':
                result = run([str(program), '--venus-icd', str(candidates[0]), '--egl-consumer',
                              str(ROOT / 'tests/fixtures/guest_egl_dma_buf.py'), '--reuse'])
                assert result.returncode == 1 and json.loads(result.stdout)['stage'] == 'selected_driver_identity_mismatch'
        helper = ROOT / 'tests/fixtures/guest_egl_dma_buf.py'
        result = run([sys.executable, str(ROOT / 'tests/fixtures/guest_gles_concurrent_control.py')])
        assert result.returncode == 1 and json.loads(result.stdout)['stage'] == 'explicit_owned_image_control_arguments_required'
        for fd in ['0', '1', '2', '4097', 'not-a-fd']:
            result = run([sys.executable, str(helper), '--owned-dma-buf-fd', fd])
            assert result.returncode == 1
            assert json.loads(result.stdout)['stage'] == 'explicit_owned_buffer_fd_required'
        # A valid owned descriptor reaches protocol validation, which must
        # reject unknown modes before loading EGL or issuing GPU operations.
        reader, writer = os.pipe()
        try:
            for key, stage in [('GB_EGL_LINEAR_IMPORT_V1', 'unknown_linear_import_protocol'),
                               ('GB_EGL_DMA_BUF_SAMPLE_V1', 'unknown_dma_buf_sampling_protocol'),
                               ('GB_EGL_DMA_BUF_SAMPLE_TARGET_V1', 'unknown_dma_buf_sampling_target'),
                               ('GB_EGL_DMA_BUF_CONTROL_V1', 'invalid_image_control_mode')]:
                env = os.environ.copy(); env.pop('GB_EGL_LINEAR_IMPORT_V1', None); env.pop('GB_EGL_DMA_BUF_SAMPLE_V1', None); env.pop('GB_EGL_DMA_BUF_SAMPLE_TARGET_V1', None); env.pop('GB_EGL_DMA_BUF_CONTROL_V1', None)
                env[key] = 'invalid'
                result = run([sys.executable, str(helper), '--owned-dma-buf-fd', str(reader)],
                             pass_fds=(reader,), env=env)
                assert result.returncode == 1 and json.loads(result.stdout)['stage'] == stage
        finally:
            os.close(reader); os.close(writer)
        reader, writer = os.pipe()
        try:
            env = os.environ.copy()
            env['GB_EGL_LINEAR_IMPORT_V1'] = 'producer_explicit'
            result = run([sys.executable, str(helper), '--owned-dma-buf-fd', str(reader)],
                         pass_fds=(reader,), env=env)
            assert result.returncode == 1
            assert json.loads(result.stdout)['stage'] == 'producer_explicit_requires_owned_layout_and_roundtrip'
        finally:
            os.close(reader); os.close(writer)
        # subprocess closes these inherited FDs by default; no EGL/GPU operations occur.
        result = run([sys.executable, str(helper), '--owned-dma-buf-fd', '4096'])
        assert result.returncode == 1 and json.loads(result.stdout)['stage'] == 'OSError'
        valid = dict(width=32, height=32, stride=128, offset=0, modifier=0,
                     allocation_bytes=4096, rgba=[19, 67, 139, 255])
        invalid = [dict(valid, width=True), dict(valid, height=129), dict(valid, stride=124),
                   dict(valid, offset=1), dict(valid, modifier=1), dict(valid, rgba=[1, 2, 3]),
                   dict(valid, allocation_bytes=1048577), dict(valid, stride=2**63)]
        for layout in invalid:
            result = run([sys.executable, str(helper), '--owned-dma-buf-fd', '4096',
                          '--image-layout-json', json.dumps(layout)])
            assert result.returncode == 1 and json.loads(result.stdout)['stage'].startswith('image_layout_')
        result = run([sys.executable, str(helper), '--owned-dma-buf-fd', '4096',
                      '--image-layout-json', json.dumps(valid)])
        assert result.returncode == 1 and json.loads(result.stdout)['stage'] == 'OSError'
        for channel in ['0', '1', '2', '4097', '04096', 'invalid']:
            result = run([sys.executable, str(helper), '--owned-dma-buf-fd', '4096',
                          '--image-layout-json', json.dumps(valid), '--roundtrip-fd', channel])
            assert result.returncode == 1 and json.loads(result.stdout)['stage'] == 'explicit_owned_roundtrip_fd_required'
    print('PASS: buffer/image producer arguments, CPU identity refusal, consumer FD/layout guards; no physical DMA-BUF verdict')


if __name__ == '__main__':
    main()
