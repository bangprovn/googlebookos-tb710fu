#!/usr/bin/env python3
"""Exercise an owned read-only client against bounded fake Wayland peers."""
from pathlib import Path
import array
import importlib.util
import os
import socket
import struct
import threading
import unittest

path = Path(__file__).parent / 'fixtures/owned_wayland_capabilities.py'
spec = importlib.util.spec_from_file_location('capabilities', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def message(object_id, opcode, body):
    return struct.pack('=II', object_id, ((len(body) + 8) << 16) | opcode) + body


def global_message(name, interface, version):
    encoded = interface + b'\0'
    return message(2, 0, struct.pack('=II', name, len(encoded)) + encoded +
                   b'\0' * (-len(encoded) % 4) + struct.pack('=I', version))


class Capabilities(unittest.TestCase):
    def test_fragmented_registry_and_numeric_formats_only(self):
        client, server = socket.socketpair()
        errors = []

        def peer():
            try:
                # Wait for get_registry and sync; handle arbitrarily split requests.
                data = b''
                while len(data) < 24:
                    data += server.recv(24 - len(data))
                self.assertEqual(len(data), 24)
                data = global_message(40, b'private_unbound_global', 1)
                data += global_message(41, b'zwp_linux_dmabuf_v1', 5)
                data += message(3, 0, struct.pack('=I', 0))
                for i in range(0, len(data), 7):
                    server.sendall(data[i:i+7])
                # Registry bind is 44 bytes followed by sync (12 bytes).
                data = b''
                while len(data) < 56:
                    part = server.recv(56 - len(data))
                    if not part:
                        raise RuntimeError('client closed')
                    data += part
                self.assertEqual(data[16:16+len(probe.INTERFACE)], probe.INTERFACE)
                self.assertEqual(struct.unpack_from('=II', data, 36), (3, 4))
                server.sendall(message(4, 0, struct.pack('=I', 875713112)) +
                               message(4, 1, struct.pack('=III', 875713112, 0, 0)) +
                               message(4, 1, struct.pack('=III', 875713112, 0xffffff, 0xffffffff)) +
                               message(5, 0, struct.pack('=I', 0)))
            except BaseException as error:
                errors.append(error)
            finally:
                server.close()
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        try:
            value = probe.inspect(client)
            self.assertEqual(value['bound_version'], 3)
            self.assertEqual(value['advertised_version'], 5)
            self.assertEqual(value['formats'], [875713112])
            self.assertEqual(value['modifiers'], [dict(fourcc=875713112,modifier=0),
                                                  dict(fourcc=875713112,modifier=(1 << 56)-1)])
            self.assertFalse(value['surface_or_buffer_created'])
            self.assertNotIn('private_unbound_global', str(value))
        finally:
            client.close()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]

    def test_bad_sizes_server_text_and_unexpected_events(self):
        for data, stage in [(struct.pack('=II', 1, 4 << 16), 'invalid_message_size'),
                            (message(1, 0, b'private server text'.ljust(24, b'\0')), 'display_error'),
                            (message(99, 0, b''), 'unexpected_message')]:
            client, server = socket.socketpair()
            with client, server:
                server.sendall(data)
                with self.assertRaisesRegex(probe.ProtocolError, '^' + stage + '$'):
                    probe.inspect(client)

    def test_unexpected_fds_closed_and_byte_budget(self):
        client, server = socket.socketpair()
        with client, server:
            read_fd, write_fd = os.pipe()
            try:
                before = len(os.listdir('/proc/self/fd'))
                server.sendmsg([message(3, 0, struct.pack('=I', 0))],
                               [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [read_fd]))])
                with self.assertRaisesRegex(probe.ProtocolError, 'unexpected_ancillary'):
                    probe.inspect(client)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            finally:
                os.close(read_fd)
                os.close(write_fd)
        client, server = socket.socketpair()
        with client, server:
            original = probe.MAX_BYTES
            try:
                probe.MAX_BYTES = 8
                server.sendall(message(3, 0, struct.pack('=I', 0)))
                with self.assertRaisesRegex(probe.ProtocolError, 'byte_budget'):
                    probe.inspect(client)
            finally:
                probe.MAX_BYTES = original


if __name__ == '__main__':
    unittest.main()
