#!/usr/bin/env python3
"""Privacy/bounds checks for the owned-child numeric protocol parser."""
from pathlib import Path
import importlib.util
import unittest

path = Path(__file__).parent / 'fixtures/owned_wayland_metadata.py'
spec = importlib.util.spec_from_file_location('owned_wayland_metadata', path)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


class Metadata(unittest.TestCase):
    def test_progress_counts_do_not_claim_pixel_updates(self):
        self.assertEqual(parser.event_kind('[1.2] {Default Queue} -> wl_surface#31.attach(wl_buffer#9, 0, 0)'), 'attach')
        self.assertEqual(parser.event_kind('[1.2] -> wl_surface@31.damage(0, 0, 2147483647, 2147483647)'), 'damage')
        self.assertEqual(parser.event_kind('[1.2] -> wl_surface@31.commit()'), 'commit')
        self.assertEqual(parser.event_kind('[1.2] wl_buffer@9.release()'), 'release')
        for line in ['[1.2] -> xdg_toplevel@4.set_title("private")',
                     '[1.2] -> wl_buffer@9.release()', 'x' * 513, None, '\x00']:
            self.assertIsNone(parser.event_kind(line))

    def test_owned_dma_buf_fields_without_fd_or_proxy_identifiers(self):
        result = parser.parse_line('[123.45] -> zwp_linux_buffer_params_v1@13.add(fd 98, 0, 0, 2560, 16777215, 4294967295)')
        self.assertEqual(result, dict(kind='add', plane=0, offset=0, stride=2560,
                                      modifier=(1 << 56) - 1))
        self.assertEqual(parser.parse_line('[1.2] {Default Queue} -> zwp_linux_buffer_params_v1@31.create_immed(new id wl_buffer@32, 640, 480, 875713112, 0)'),
                         dict(kind='create_immed', width=640, height=480,
                              fourcc=875713112, flags=0))
        self.assertEqual(parser.parse_line('[1.2] -> zwp_linux_buffer_params_v1@31.create_immed(new id [unknown]@32, 640, 480, 875713112, 0)')['width'], 640)
        self.assertEqual(parser.parse_line('[  123.456] {Default Queue}  -> zwp_linux_buffer_params_v1#13.add(fd 98, 0, 0, 2560, 16777215, 4294967295)'), result)
        self.assertEqual(parser.parse_line('[1.2] {Default Queue}  -> zwp_linux_buffer_params_v1#31.create_immed(new id wl_buffer#32, 640, 480, 875713112, 0)')['fourcc'], 875713112)

    def test_unrelated_client_strings_and_invalid_metadata_are_discarded(self):
        for line in [
            '[1.2] -> xdg_toplevel@4.set_title("not diagnostic metadata")',
            '[1.2] wl_keyboard@4.key(1, 2, 3, 4)',
            '[1.2] -> zwp_linux_buffer_params_v1@1.add(fd 5, 4, 0, 2560, 0, 0)',
            '[1.2] -> zwp_linux_buffer_params_v1@1.add(fd 5, 0, 0, 0, 0, 0)',
            '[1.2] -> zwp_linux_buffer_params_v1@1.add(fd 5, 0, 0, 2560, 4294967296, 0)',
            '[1.2] -> zwp_linux_buffer_params_v1@1.create_immed(new id wl_buffer@2, 0, 480, 875713112, 0)',
            '[1.2] -> zwp_linux_buffer_params_v1@1.create_immed(new id wl_buffer@2, 640, 480, 875713112, 8)',
            '[1.2] -> zwp_linux_buffer_params_v1@1.create_immed(new id arbitrary_text@2, 640, 480, 875713112, 0)',
            'x' * 513,
            '\x00',
            None,
        ]:
            self.assertIsNone(parser.parse_line(line), repr(line)[:80])


if __name__ == '__main__':
    unittest.main()
