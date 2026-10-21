#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Present only an inherited, authenticated diagnostic producer's DMA-BUF.

Three completed producer updates reuse one wl_buffer. No owner window, input,
or framebuffer is read. Screen-pixel verification belongs to the host observer.
"""
import array
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import tempfile
import time
import urllib.request
from guest_egl_dma_buf import parse_layout


class ProtocolError(Exception):
    pass


def words(*values):
    return struct.pack('=' + 'I' * len(values), *values)


def string(value):
    raw = value.encode('ascii') + b'\0'
    return words(len(raw)) + raw + b'\0' * (-len(raw) % 4)


class Window:
    def __init__(self, connection):
        self.connection = connection
        self.pending = bytearray()
        self.total = self.records = 0
        self.next_id = 3
        self.callbacks = set()
        self.globals = {}
        self.done = set()
        self.configured = self.released = False
        self.linear = False
        self.neutral_id = 18

    def send(self, obj, opcode, body=b'', fd=None):
        data = words(obj, ((8 + len(body)) << 16) | opcode) + body
        if fd is None:
            self.connection.sendall(data)
        else:
            count = self.connection.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
            if count != len(data):
                raise ProtocolError('short_fd_message')

    def event(self, deadline):
        while len(self.pending) < 8 or len(self.pending) < (struct.unpack_from('=I', self.pending, 4)[0] >> 16):
            if len(self.pending) >= 8:
                size = struct.unpack_from('=I', self.pending, 4)[0] >> 16
                if size < 8 or size % 4:
                    raise ProtocolError('message_size')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError('deadline')
            self.connection.settimeout(remaining)
            data, ancillary, flags, _ = self.connection.recvmsg(65536, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC)
            for level, kind, raw in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array('i'); fds.frombytes(raw[:len(raw) // fds.itemsize * fds.itemsize])
                    for fd in fds:
                        os.close(fd)
            if ancillary or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise ProtocolError('unexpected_ancillary')
            self.total += len(data)
            if not data or self.total > 1024 * 1024:
                raise ProtocolError('connection_or_byte_budget')
            self.pending.extend(data)
        obj, word = struct.unpack_from('=II', self.pending)
        size, opcode = word >> 16, word & 65535
        if size < 8 or size % 4:
            raise ProtocolError('message_size')
        body = bytes(self.pending[8:size]); del self.pending[:size]
        self.records += 1
        if self.records > 4096:
            raise ProtocolError('record_budget')
        if obj == 1:
            if opcode != 1 or len(body) != 4:
                raise ProtocolError('display_error')
        elif obj == 2 and opcode == 0:
            if len(body) < 12:
                raise ProtocolError('global_size')
            name, length = struct.unpack_from('=II', body)
            end = 8 + (length + 3) // 4 * 4
            if not name or not 1 <= length <= 256 or end + 4 != len(body) or body[8 + length - 1] != 0:
                raise ProtocolError('global_encoding')
            interface = body[8:8 + length - 1]
            if interface in [b'wl_compositor', b'xdg_wm_base', b'zwp_linux_dmabuf_v1', b'wp_viewporter', b'wl_shm']:
                if interface in self.globals:
                    raise ProtocolError('ambiguous_global')
                self.globals[interface] = (name, struct.unpack_from('=I', body, end)[0])
        elif obj == 5 and opcode == 0 and len(body) == 4:
            self.send(5, 3, body)  # owned xdg_wm_base ping
        elif obj == 6 and opcode in [0, 1]:
            if opcode == 1 and len(body) == 12:
                self.linear |= struct.unpack('=III', body) == (0x34325258, 0, 0)
        elif obj == 10 and opcode == 0 and len(body) == 4:
            self.send(10, 4, body); self.configured = True
        elif obj == 11 and opcode == 0:
            pass  # compositor sizing suggestion, never persisted
        elif obj == 14 and opcode == 0 and not body:
            self.released = True
        elif obj == 16 and opcode == 0 and len(body) == 4:
            pass  # wl_shm format advertisement
        elif obj == self.neutral_id and opcode == 0 and not body:
            pass  # independent neutral buffer release
        elif obj in self.callbacks and opcode == 0 and len(body) == 4:
            self.done.add(obj)
        else:
            raise ProtocolError('unexpected_event')

    def wait(self, predicate, seconds=3):
        deadline = time.monotonic() + seconds
        while not predicate():
            self.event(deadline)

    def allocate(self, expected=None):
        obj = self.next_id; self.next_id += 1
        if expected is not None and obj != expected:
            raise ProtocolError('object_allocation_order')
        return obj

    def callback(self):
        obj = self.allocate(); self.callbacks.add(obj)
        return obj

    def sync(self):
        callback = self.callback()
        self.send(1, 0, words(callback)); self.wait(lambda: callback in self.done)

    def bind(self, interface, version, obj):
        if interface not in self.globals or self.globals[interface][1] < version:
            raise ProtocolError('required_global_version')
        name, _ = self.globals[interface]
        self.allocate(obj)
        self.send(2, 0, words(name) + string(interface.decode()) + words(version, obj))

    def setup(self, fd, layout, neutral_fd=None):
        if (layout.get('schema_version') != 2 or layout.get('fourcc') != 0x34325258
                or (layout['width'], layout['height']) not in [(32, 32), (640, 480)]
                or layout['modifier'] != 0):
            raise ProtocolError('qualified_xrgb_layout_required')
        self.send(1, 1, words(2)); self.sync()
        for interface, version, obj in [(b'wl_compositor', 4, 4), (b'xdg_wm_base', 1, 5),
                                         (b'zwp_linux_dmabuf_v1', 3, 6), (b'wp_viewporter', 1, 7)]:
            self.bind(interface, version, obj)
        self.sync()
        if not self.linear:
            raise ProtocolError('xrgb_linear_not_advertised')
        self.send(4, 0, words(self.allocate(9)))  # wl_surface
        self.send(5, 2, words(self.allocate(10), 9))
        self.send(10, 1, words(self.allocate(11)))
        self.send(11, 2, string('Googlebook owned color reuse diagnostic'))
        self.send(7, 1, words(self.allocate(12), 9)); self.send(12, 2, words(640, 480))
        self.send(9, 6); self.wait(lambda: self.configured)
        self.send(6, 1, words(self.allocate(13)))
        self.send(13, 1, words(0, layout['offset'], layout['stride'], 0, 0), fd)
        self.send(13, 3, words(self.allocate(14), layout['width'], layout['height'], 0x34325258, 0)); self.send(13, 0)
        self.sync()
        # Keep the surface mapped while releasing the GPU buffer. An unmapped
        # surface may retain its last buffer without sending release promptly.
        # The neutral allocation never aliases the changing producer memory.
        if neutral_fd is None:
            self.bind(b'wl_shm', 1, 16)
            with tempfile.TemporaryFile() as neutral:
                neutral.write(bytes([32, 32, 32, 255]) * (32 * 32)); neutral.flush()
                self.send(16, 0, words(self.allocate(17), 4096), neutral.fileno())
                self.send(17, 0, words(self.allocate(18), 0, 32, 32, 128, 1))
                self.send(17, 1)
        else:
            a, b = os.fstat(fd), os.fstat(neutral_fd)
            if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
                raise ProtocolError('neutral_memory_alias')
            self.send(6, 1, words(self.allocate(16)))
            self.send(16, 1, words(0, layout['offset'], layout['stride'], 0, 0), neutral_fd)
            self.neutral_id = self.allocate(17)
            self.send(16, 3, words(self.neutral_id, layout['width'], layout['height'], 0x34325258, 0)); self.send(16, 0)
        self.sync()

    def present(self):
        self.released = False
        callback = self.callback()
        self.send(9, 1, words(14, 0, 0)); self.send(9, 2, words(0, 0, 640, 480))
        self.send(9, 3, words(callback)); self.send(9, 6)
        self.wait(lambda: callback in self.done)

    def detach(self):
        self.send(9, 1, words(self.neutral_id, 0, 0))
        self.send(9, 2, words(0, 0, 640, 480)); self.send(9, 6)
        self.wait(lambda: self.released)


def main():
    if (len(sys.argv) != 7 or sys.argv[1] != '--owned-dma-buf-fd'
            or sys.argv[3] != '--image-layout-json' or sys.argv[5] != '--roundtrip-fd'):
        raise ProtocolError('explicit_owned_arguments_required')
    fd, channel = int(sys.argv[2]), int(sys.argv[6])
    if not 3 <= fd <= 4096 or not 3 <= channel <= 4096 or fd == channel:
        raise ProtocolError('descriptor_bounds')
    layout = parse_layout(sys.argv[4]); os.fstat(fd)
    neutral_fd = None
    if 'GB_OWNED_NEUTRAL_DMA_FD' in os.environ:
        neutral_fd = int(os.environ['GB_OWNED_NEUTRAL_DMA_FD'])
        if (os.environ.get('GB_GUEST_IMAGE_NEUTRAL_V1') != 'second-linear-xrgb'
                or not 3 <= neutral_fd <= 4096 or neutral_fd in [fd, channel]):
            raise ProtocolError('neutral_descriptor_profile')
    with socket.fromfd(channel, socket.AF_UNIX, socket.SOCK_SEQPACKET) as ipc:
        pid, uid, _ = struct.unpack('3i', ipc.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != os.getppid() or uid != os.getuid() or ipc.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
            raise ProtocolError('producer_identity')
        runtime = Path('/run/user/1000'); m = runtime.lstat()
        display = os.environ['WAYLAND_DISPLAY']
        if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.getuid() or m.st_mode & 0o077 or display not in ['wayland-0', 'wayland-1', 'wayland-2']:
            raise ProtocolError('runtime_directory')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3); connection.connect(str(runtime / display))
            peer, owner, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if owner != os.getuid() or peer != int(os.environ['GB_OWNED_COMPOSITOR_PID']):
                raise ProtocolError('compositor_identity')
            window = Window(connection); window.setup(fd, layout, neutral_fd)
            colors = [[19, 67, 139], [203, 37, 91], [47, 181, 113]]
            for phase, color in enumerate(colors):
                if ipc.recv(1) != bytes([phase]):
                    raise ProtocolError('producer_sequence')
                window.present()
                payload = json.dumps(dict(schema_version=1, guest_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), phase=phase, expected_rgb=color, producer_completed=True, frame_callback_received=True, presentation_verified=False)).encode()
                with urllib.request.urlopen(urllib.request.Request(os.environ['GB_OWNED_PHASE_URL'] + '/phase' + str(phase), data=payload, headers={'Content-Type': 'application/json'}), timeout=2) as response:
                    if response.read(128) != b'GB_WINDOW_RECEIVED\n':
                        raise ProtocolError('phase_receipt')
                time.sleep(3)
                window.detach()
                if ipc.send(bytes([0x80 | phase])) != 1:
                    raise ProtocolError('producer_ack')
    print(json.dumps(dict(schema_version=1, three_buffer_updates_presented=True, single_wl_buffer_reused=True, releases_before_producer_reuse=True, neutral_kind='independent_DMA_BUF' if neutral_fd is not None else 'independent_SHM', presentation_verified=False, owner_content_read=False)), flush=True)


if __name__ == '__main__':
    signal.alarm(18)
    try:
        main()
    except Exception as error:
        print(json.dumps(dict(schema_version=1, status='failed', error_class=type(error).__name__, stage=str(error) if isinstance(error, ProtocolError) else 'owned_window_exception', presentation_verified=False)), flush=True)
        sys.exit(1)
