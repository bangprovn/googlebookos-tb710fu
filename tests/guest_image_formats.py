#!/usr/bin/env python3
"""Validate exact format/alpha metadata and refuse unknown producer profiles.

No GPU is opened by these tests. The actual C producer exits at argument/profile
validation, and the Python consumer is exercised only through its layout parser.
"""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
sys.path.insert(0, str(FIXTURES))
spec = importlib.util.spec_from_file_location('owned_image', FIXTURES / 'guest_egl_dma_buf.py')
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


def base():
    return dict(width=32,height=32,stride=256,offset=0,modifier=0,
                allocation_bytes=8192,rgba=[19,67,139,255])


class Formats(unittest.TestCase):
    def test_legacy_and_exact_new_format_profiles(self):
        value = base()
        self.assertEqual(consumer.parse_layout(json.dumps(value)), value)
        for fourcc in [0x34324241, 0x34325241, 0x34324258, 0x34325258]:
            value = dict(base(),schema_version=2,fourcc=fourcc,
                         source_alpha=[0,73,127] if fourcc in [0x34324258,0x34325258] else [255]*3)
            self.assertEqual(consumer.parse_layout(json.dumps(value)), value)

    def test_invalid_profiles_types_alpha_and_layout_bounds(self):
        valid = dict(base(),schema_version=2,fourcc=0x34325258,source_alpha=[0,73,127])
        for key, value in [('schema_version',True),('schema_version',3),('fourcc',0),
                           ('fourcc',True),('fourcc',0x34324258 + (1 << 32)),
                           ('source_alpha',[255]*3),('source_alpha',[False,73,127]),
                           ('source_alpha',[0,73]),('source_alpha','0,73,127'),
                           ('modifier',(1 << 56)-1),('modifier',True),
                           ('offset',8192),('offset',-1),('stride',127),
                           ('width',0),('height',129),('allocation_bytes',1),
                           ('rgba',[19,67,139,0]),('rgba',[19,67,139,True])]:
            with self.subTest(key=key,value=value):
                with self.assertRaises(consumer.ProbeError):
                    consumer.parse_layout(json.dumps(dict(valid,**{key:value})))
        for value in [dict(valid,extra=1),{k:v for k,v in valid.items() if k!='source_alpha'},
                      dict(base(),fourcc=0x34324241),[],None]:
            with self.assertRaises(consumer.ProbeError):
                consumer.parse_layout(json.dumps(value))
        with self.assertRaises(consumer.ProbeError):
            consumer.parse_layout(' ' * 4097)

    def test_only_exact_large_xrgb_profile_expands_the_allocation_budget(self):
        value = dict(base(), schema_version=2, fourcc=0x34325258, source_alpha=[0,73,127],
                     width=640, height=480, stride=2560, allocation_bytes=1228800)
        self.assertEqual(consumer.parse_layout(json.dumps(value)), value)
        for changes in [dict(width=641), dict(height=479), dict(allocation_bytes=1228799),
                        dict(allocation_bytes=4*1024*1024+1), dict(stride=2556),
                        dict(fourcc=0x34324258), dict(offset=4096)]:
            with self.subTest(changes=changes), self.assertRaises(consumer.ProbeError):
                consumer.parse_layout(json.dumps(dict(value, **changes)))

    def test_actual_c_producer_refuses_unknown_profiles_before_driver_work(self):
        with tempfile.TemporaryDirectory(prefix='gb-image-format-') as temp:
            binary = Path(temp) / 'producer'
            subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                            str(FIXTURES/'guest_vulkan_egl_image.c'),'-ldl','-o',str(binary)],
                           capture_output=True,check=True,timeout=30)
            for profile in ['', 'xrgb8888-extra', 'afbc', 'srgb', 'unknown']:
                result = subprocess.run([str(binary),'--venus-icd','/owned-not-opened.json',
                                         '--egl-consumer','/owned-not-executed.py','--reuse'],
                                        capture_output=True,text=True,timeout=3,
                                        env=dict(os.environ,GB_GUEST_IMAGE_FORMAT_V1=profile,
                                                 ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                                 UBSAN_OPTIONS='halt_on_error=1'))
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertEqual(json.loads(result.stdout)['stage'],'unknown_image_format_profile')
                self.assertNotIn('GB_GUEST_VK_STAGE:',result.stderr)
            for neutral, image_format, reuse in [('', 'xrgb8888', True),
                                                 ('unknown', 'xrgb8888', True),
                                                 ('second-linear-xrgb', 'argb8888', True),
                                                 ('second-linear-xrgb', 'xrgb8888', False)]:
                command = [str(binary), '--venus-icd', '/owned-not-opened.json',
                           '--egl-consumer', '/owned-not-executed.py']
                if reuse:
                    command.append('--reuse')
                result = subprocess.run(command, capture_output=True, text=True, timeout=3,
                                        env=dict(os.environ, GB_GUEST_IMAGE_FORMAT_V1=image_format,
                                                 GB_GUEST_IMAGE_NEUTRAL_V1=neutral,
                                                 ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                                                 UBSAN_OPTIONS='halt_on_error=1'))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)['stage'], 'unknown_neutral_image_profile')
                self.assertNotIn('GB_GUEST_VK_STAGE:', result.stderr)
            for extent in ['', '641x480', '32x32', 'unknown']:
                result = subprocess.run([str(binary), '--venus-icd', '/owned-not-opened.json',
                                         '--egl-consumer', '/owned-not-executed.py', '--reuse'],
                                        capture_output=True, text=True, timeout=3,
                                        env=dict(os.environ, GB_GUEST_IMAGE_FORMAT_V1='xrgb8888',
                                                 GB_GUEST_IMAGE_EXTENT_V1=extent))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)['stage'], 'unknown_image_extent_profile')
                self.assertNotIn('GB_GUEST_VK_STAGE:', result.stderr)
            for render, extent in [('', '640x480'), ('unknown', '640x480'),
                                   ('renderpass-clear', None)]:
                selected = dict(os.environ, GB_GUEST_IMAGE_FORMAT_V1='xrgb8888',
                                GB_GUEST_IMAGE_RENDER_V1=render)
                selected.pop('GB_GUEST_IMAGE_EXTENT_V1', None)
                if extent is not None:
                    selected['GB_GUEST_IMAGE_EXTENT_V1'] = extent
                result = subprocess.run([str(binary), '--venus-icd', '/owned-not-opened.json',
                                         '--egl-consumer', '/owned-not-executed.py', '--reuse'],
                                        capture_output=True, text=True, timeout=3, env=selected)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)['stage'], 'unknown_image_render_profile')
                self.assertNotIn('GB_GUEST_VK_STAGE:', result.stderr)
            for mode, extent in [('', '640x480'), ('unknown', '640x480'), ('gpu-only', None)]:
                selected = dict(os.environ, GB_GUEST_IMAGE_FORMAT_V1='xrgb8888',
                                GB_GUEST_IMAGE_INIT_V1=mode)
                selected.pop('GB_GUEST_IMAGE_EXTENT_V1', None)
                if extent is not None:
                    selected['GB_GUEST_IMAGE_EXTENT_V1'] = extent
                result = subprocess.run([str(binary), '--venus-icd', '/owned-not-opened.json',
                                         '--egl-consumer', '/owned-not-executed.py', '--reuse'],
                                        capture_output=True, text=True, timeout=3, env=selected)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(json.loads(result.stdout)['stage'], 'unknown_image_init_profile')
                self.assertNotIn('GB_GUEST_VK_STAGE:', result.stderr)


if __name__ == '__main__':
    unittest.main()
