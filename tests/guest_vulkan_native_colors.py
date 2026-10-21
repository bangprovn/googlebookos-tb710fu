#!/usr/bin/env python3
"""Build the actual native WSI probe and exercise preflight refusals only.

No Wayland display or GPU is opened by these tests. Device-side presentation
requires the separate owner-scoped observer and exact runtime identity guards.
"""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
XML = ROOT/'artifacts/device/first-boot-20261013/guest-vulkan-work-20261019-v1/guest-command-pool-v1/sdk/usr/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml'


class NativeColors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-native-colors-guard-')
        cls.directory = Path(cls.work.name)
        for kind, name in [('client-header', 'xdg-shell-client-protocol.h'), ('private-code', 'xdg-shell-protocol.c')]:
            subprocess.run(['wayland-scanner', kind, str(XML), str(cls.directory/name)],
                           check=True, capture_output=True, timeout=20)
        cls.binary = cls.directory/'probe'
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-I', str(cls.directory), str(ROOT/'tests/fixtures/guest_vulkan_native_colors.c'),
                        str(cls.directory/'xdg-shell-protocol.c'), '-lwayland-client', '-ldl', '-o', str(cls.binary)],
                       check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def refuse(self, arguments, expected, **variables):
        env = os.environ.copy()
        for name in ['WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'GB_OWNED_COMPOSITOR_PID']:
            env.pop(name, None)
        env.update(variables, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        result = subprocess.run([str(self.binary), *arguments], env=env,
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['stage'], expected)
        self.assertFalse(report['presentation_verified'])
        self.assertEqual(result.stderr, '')

    def test_requires_explicit_absolute_icd(self):
        for arguments in [[], ['--unknown'], ['--venus-icd', 'relative.json'],
                          ['--venus-icd', 'relative.json', '--swapchain-lifecycle'],
                          ['--venus-icd', '/owned-not-opened.json', '--unknown'],
                          ['--venus-icd', '/owned-not-opened.json', '--swapchain-lifecycle', 'extra']]:
            with self.subTest(arguments=arguments):
                self.refuse(arguments, 'explicit_venus_icd_required')

    def test_missing_owned_peer_and_invalid_socket_names(self):
        args = ['--venus-icd', '/owned-not-opened.json']
        self.refuse(args, 'owned_compositor_required')
        for display in ['../other', '/tmp/other', '', 'wayland-99']:
            with self.subTest(display=display):
                self.refuse(args, 'owned_compositor_required', WAYLAND_DISPLAY=display, GB_OWNED_COMPOSITOR_PID='2')

    def test_refuses_invalid_peer_before_connecting(self):
        for peer in ['', '0', '1', '-3', 'abc', '2x', '4194305', '999999999999999999999999999999']:
            with self.subTest(peer=peer):
                self.refuse(['--venus-icd', '/owned-not-opened.json'], 'owned_compositor_identity',
                            WAYLAND_DISPLAY='wayland-1', GB_OWNED_COMPOSITOR_PID=peer)

    def test_lifecycle_mode_preserves_owned_display_and_peer_guards(self):
        args = ['--venus-icd', '/owned-not-opened.json', '--swapchain-lifecycle']
        self.refuse(args, 'owned_compositor_required')
        self.refuse(args, 'owned_compositor_required', WAYLAND_DISPLAY='../other', GB_OWNED_COMPOSITOR_PID='2')
        for peer in ['0', '1', '-3', 'abc', '999999999999999999999999999999']:
            with self.subTest(peer=peer):
                self.refuse(args, 'owned_compositor_identity', WAYLAND_DISPLAY='wayland-1', GB_OWNED_COMPOSITOR_PID=peer)


if __name__ == '__main__':
    unittest.main()
