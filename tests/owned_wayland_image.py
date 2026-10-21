#!/usr/bin/env python3
"""Exercise the actual owned window protocol using a local fake compositor."""
import array
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent / 'fixtures'))
import owned_wayland_image as window


class ImageWindow(unittest.TestCase):
    def test_reuses_one_fd_buffer_and_releases_before_each_next_update(self):
        for neutral_dma in [False, True]:
            for extent in [(32, 32), (640, 480)]:
                with self.subTest(neutral_dma=neutral_dma, extent=extent):
                    self.exercise_reuse(neutral_dma, extent)

    def exercise_reuse(self, neutral_dma, extent):
        width, height = extent
        stride = 256 if width == 32 else width * 4
        allocation_size = stride * height
        client, server = socket.socketpair()
        failures, seen, imports = [], [], []

        def compositor():
            next_id = 2
            pending = bytearray(); attached = False; frame = None; configured = False
            def send(obj, opcode, body=b''):
                server.sendall(window.words(obj, ((len(body) + 8) << 16) | opcode) + body)
            try:
                server.settimeout(3)
                while True:
                    data, ancillary, _, _ = server.recvmsg(4096, socket.CMSG_SPACE(64))
                    if not data:
                        break
                    for level, kind, raw in ancillary:
                        self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
                        fds = array.array('i'); fds.frombytes(raw)
                        for fd in fds:
                            imports.append(os.fstat(fd).st_size); os.close(fd)
                    pending.extend(data)
                    while len(pending) >= 8:
                        obj, word = struct.unpack_from('=II', pending)
                        size, opcode = word >> 16, word & 65535
                        if len(pending) < size:
                            break
                        body = bytes(pending[8:size]); del pending[:size]
                        new_id = None
                        if (obj, opcode) in [(1, 0), (1, 1), (4, 0), (10, 1), (6, 1), (13, 3), (5, 2), (7, 1), (9, 3), (17, 0)] or (obj, opcode) == ((16, 3) if neutral_dma else (16, 0)):
                            new_id, = struct.unpack_from('=I', body)
                        elif (obj, opcode) == (2, 0):
                            new_id, = struct.unpack_from('=I', body, len(body) - 4)
                        if new_id is not None:
                            self.assertEqual(new_id, next_id); next_id += 1
                        if (obj, opcode) == (1, 1):
                            for name, interface, version in [(101, 'wl_compositor', 4), (102, 'xdg_wm_base', 1), (103, 'zwp_linux_dmabuf_v1', 3), (104, 'wp_viewporter', 1), (105, 'wl_shm', 1)]:
                                send(2, 0, window.words(name) + window.string(interface) + window.words(version))
                        elif (obj, opcode) == (1, 0):
                            callback, = struct.unpack('=I', body); send(callback, 0, window.words(1)); send(1, 1, window.words(callback))
                        elif (obj, opcode) == (2, 0) and b'zwp_linux_dmabuf_v1\0' in body:
                            send(6, 1, window.words(0x34325258, 0, 0))
                        elif (obj, opcode) == (13, 3):
                            self.assertEqual(struct.unpack('=5I', body), (14, width, height, 0x34325258, 0))
                        elif (obj, opcode) == (12, 2):
                            self.assertEqual(body, window.words(640, 480))
                        elif (obj, opcode) == (9, 1):
                            attached = struct.unpack_from('=I', body)[0] == 14
                            if not attached:
                                self.assertEqual(struct.unpack_from('=I', body)[0], 17 if neutral_dma else 18)
                            seen.append('attach' if attached else 'neutral')
                        elif (obj, opcode) == (9, 3):
                            frame, = struct.unpack('=I', body)
                        elif (obj, opcode) == (9, 6):
                            if not configured:
                                send(10, 0, window.words(99)); configured = True
                            elif frame is not None:
                                self.assertTrue(attached); send(frame, 0, window.words(1)); frame = None
                            elif not attached:
                                seen.append('release'); send(14, 0)
            except Exception as error:
                failures.append(error)
            finally:
                server.close()

        thread = threading.Thread(target=compositor); thread.start()
        try:
            with tempfile.TemporaryFile() as dma, tempfile.TemporaryFile() as neutral:
                dma.truncate(allocation_size)
                neutral.truncate(allocation_size)
                w = window.Window(client)
                w.setup(dma.fileno(), dict(schema_version=2, fourcc=0x34325258, width=width, height=height, modifier=0, offset=0, stride=stride), neutral.fileno() if neutral_dma else None)
                for _ in range(3):
                    w.present(); self.assertFalse(w.released); w.detach(); self.assertTrue(w.released)
        finally:
            client.close(); thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual(imports, [allocation_size, allocation_size if neutral_dma else 4096])
        self.assertEqual(seen, ['attach', 'neutral', 'release'] * 3)

    def test_refuses_unknown_layout_before_any_protocol_write(self):
        client, server = socket.socketpair()
        with client, server:
            with self.assertRaisesRegex(window.ProtocolError, 'qualified_xrgb'):
                window.Window(client).setup(-1, dict(schema_version=2, fourcc=0, width=32, height=32, modifier=0))

    def test_malformed_message_size_is_bounded(self):
        client, server = socket.socketpair()
        with client, server:
            server.sendall(window.words(1, 9 << 16))
            with self.assertRaisesRegex(window.ProtocolError, 'message_size'):
                window.Window(client).event(time.monotonic() + .1)

    def test_unexpected_received_descriptors_are_closed_before_refusal(self):
        client, server = socket.socketpair()
        with client, server, tempfile.TemporaryFile() as owned:
            server.sendmsg([window.words(1, (12 << 16) | 1) + window.words(20)],
                           [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [owned.fileno()]))])
            with mock.patch.object(window.os, 'close', wraps=os.close) as closer:
                with self.assertRaisesRegex(window.ProtocolError, 'unexpected_ancillary'):
                    window.Window(client).event(time.monotonic() + .1)
            self.assertEqual(closer.call_count, 1)
            received = closer.call_args.args[0]
            with self.assertRaises(OSError):
                os.fstat(received)
            os.fstat(owned.fileno())


if __name__ == '__main__':
    unittest.main()
