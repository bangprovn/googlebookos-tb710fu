#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read only DMA-BUF v1-v3 advertisements; create no surface or buffer.

The connection is dedicated to this probe. Other registry globals and protocol
strings are discarded. Version 3 avoids feedback files/FDs; this does not
inspect version-4 surface-specific feedback or prove import functionality.
"""
import array
import json
import socket
import struct
import time

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 1024
INTERFACE = b'zwp_linux_dmabuf_v1\0'


class ProtocolError(Exception):
    pass


def request(connection, object_id, opcode, body):
    connection.sendall(struct.pack('=II', object_id, ((len(body) + 8) << 16) | opcode) + body)


def inspect(connection, deadline_seconds=3):
    if not 0 < deadline_seconds <= 10:
        raise ProtocolError('invalid_deadline')
    connection.settimeout(deadline_seconds)
    pending = bytearray()
    total = 0
    deadline = time.monotonic() + deadline_seconds
    globals_found = []
    formats = set()
    modifiers = set()

    def messages():
        nonlocal total
        while len(pending) < 8 or len(pending) < (struct.unpack_from('=I', pending, 4)[0] >> 16):
            if len(pending) >= 8:
                size = struct.unpack_from('=I', pending, 4)[0] >> 16
                if size < 8 or size % 4:
                    raise ProtocolError('invalid_message_size')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError('deadline')
            connection.settimeout(remaining)
            try:
                data, ancillary, flags, _ = connection.recvmsg(65536, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC)
            except TimeoutError:
                raise ProtocolError('deadline') from None
            for level, kind, values in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array('i')
                    descriptors.frombytes(values[:len(values) // descriptors.itemsize * descriptors.itemsize])
                    for fd in descriptors:
                        socket.close(fd)
            if ancillary or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise ProtocolError('unexpected_ancillary')
            if not data:
                raise ProtocolError('connection_closed')
            total += len(data)
            if total > MAX_BYTES:
                raise ProtocolError('byte_budget')
            pending.extend(data)
        object_id, word = struct.unpack_from('=II', pending)
        size, opcode = word >> 16, word & 65535
        if size < 8 or size % 4:
            raise ProtocolError('invalid_message_size')
        body = bytes(pending[8:size])
        del pending[:size]
        return object_id, opcode, body

    def roundtrip(callback):
        request(connection, 1, 0, struct.pack('=I', callback))
        while True:
            object_id, opcode, body = messages()
            if object_id == callback and opcode == 0 and len(body) == 4:
                return
            if object_id == 1 and opcode == 1 and len(body) == 4:
                continue  # delete_id on this dedicated connection
            if object_id == 1 and opcode == 0:
                raise ProtocolError('display_error')  # discard server's free-form text
            if object_id == 2 and opcode == 0 and len(body) >= 12:
                name, length = struct.unpack_from('=II', body)
                end = 8 + ((length + 3) // 4) * 4
                if not name or not 1 <= length <= 256 or end + 4 != len(body) or body[8 + length - 1] != 0:
                    raise ProtocolError('invalid_global')
                version, = struct.unpack_from('=I', body, end)
                if body[8:8 + length] == INTERFACE:
                    globals_found.append((name, version))
                    if len(globals_found) > 1:
                        raise ProtocolError('ambiguous_global')
                continue
            if object_id == 2 and opcode == 1 and len(body) == 4:
                raise ProtocolError('global_removed_during_probe')
            if object_id == 4 and opcode == 0 and len(body) == 4:
                formats.add(struct.unpack('=I', body)[0])
            elif object_id == 4 and opcode == 1 and len(body) == 12:
                fourcc, high, low = struct.unpack('=III', body)
                modifiers.add((fourcc, (high << 32) | low))
            else:
                raise ProtocolError('unexpected_message')
            if len(formats) + len(modifiers) > MAX_RECORDS:
                raise ProtocolError('record_budget')

    request(connection, 1, 1, struct.pack('=I', 2))  # get_registry
    roundtrip(3)
    if len(globals_found) != 1 or globals_found[0][1] < 1:
        raise ProtocolError('dma_buf_unavailable')
    name, advertised = globals_found[0]
    version = min(advertised, 3)
    encoded = struct.pack('=II', name, len(INTERFACE)) + INTERFACE
    encoded += b'\0' * (-len(INTERFACE) % 4) + struct.pack('=II', version, 4)
    request(connection, 2, 0, encoded)
    roundtrip(5)
    return dict(schema_version=1,advertised_version=advertised,bound_version=version,
                formats=sorted(formats),modifiers=[dict(fourcc=f,modifier=m) for f,m in sorted(modifiers)],
                wire_bytes=total,capability_advertisement_only=True,
                surface_or_buffer_created=False,feedback_v4_inspected=False,
                presentation_verified=False,full_port_verified=False)
