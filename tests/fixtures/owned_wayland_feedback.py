#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inspect initial v4 feedback for a dedicated, unmapped owned wl_surface.

The caller supplies a dedicated socket to its controlled compositor. UID 1000
is required by default; pass its already checked PID to enforce the same peer
again. No seat, buffer, pixel, device node or arbitrary path is opened. The new
unmapped surface's feedback need not equal another client's maximized feedback.
The registry binding remains alive until the caller closes the connection:
wl_registry has no wire destructor.

Format-table files are read with bounded pread, not dereferenced through mmap:
a peer violating the immutable-table promise cannot cause a truncation SIGBUS.
Only declared numeric format/modifier/device metadata is returned; table padding
and unrelated registry strings are discarded.
"""
import array
import collections
import os
import socket
import stat
import struct
import time

MAX_BYTES = 1024 * 1024
MAX_EVENTS = 4096
MAX_TABLE_BYTES = 65536
MAX_TRANCHES = 16
MAX_INDICES = 4096
INTERFACE = b'zwp_linux_dmabuf_v1\0'
COMPOSITOR = b'wl_compositor\0'
INVALID_MODIFIER = (1 << 56) - 1


class ProtocolError(Exception):
    pass


def _device(body):
    data = _array(body, 8)
    if len(data) not in (4, 8):
        raise ProtocolError('invalid_device_array')
    value, = struct.unpack('=I' if len(data) == 4 else '=Q', data)
    if not value:
        raise ProtocolError('invalid_device_number')
    return dict(dev_t=value, major=os.major(value), minor=os.minor(value))


def _array(body, maximum):
    if len(body) < 4:
        raise ProtocolError('invalid_array')
    length, = struct.unpack_from('=I', body)
    if length > maximum or len(body) != 4 + ((length + 3) // 4) * 4:
        raise ProtocolError('invalid_array')
    return body[4:4+length]


def _table(fd, size):
    try:
        if not size or size % 16 or size > MAX_TABLE_BYTES:
            raise ProtocolError('format_table_size')
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ProtocolError('format_table_not_regular')
        if info.st_size < size:
            raise ProtocolError('format_table_truncated')
        data = bytearray()
        while len(data) < size:
            part = os.pread(fd, size-len(data), len(data))
            if not part:
                raise ProtocolError('format_table_truncated')
            data.extend(part)
        return [dict(index=i, fourcc=fourcc, modifier=modifier)
                for i, (fourcc, modifier) in enumerate(struct.iter_unpack('=I4xQ', data))]
    except OSError:
        raise ProtocolError('format_table_read_failed') from None
    finally:
        os.close(fd)


def inspect(connection, deadline_seconds=3, expected_peer_pid=None, expected_uid=1000):
    if not 0 < deadline_seconds <= 10:
        raise ProtocolError('invalid_deadline')
    if expected_peer_pid is not None and (type(expected_peer_pid) is not int or expected_peer_pid < 1):
        raise ProtocolError('invalid_expected_peer')
    if type(expected_uid) is not int or expected_uid < 0:
        raise ProtocolError('invalid_expected_uid')
    try:
        pid, uid, _gid = struct.unpack('=3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    except OSError:
        raise ProtocolError('peer_credentials_unavailable') from None
    if uid != expected_uid or (expected_peer_pid is not None and pid != expected_peer_pid):
        raise ProtocolError('unexpected_compositor_peer')
    deadline = time.monotonic() + deadline_seconds
    original_timeout = connection.gettimeout()
    pending = bytearray()
    fds = collections.deque()
    total = events = received_fds = 0
    found = {}
    table = None
    main_device = None
    tranches = []
    tranche = dict(target_device=None, flags=None, indices=[])
    all_pairs = set()
    index_count = 0
    done = False

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise ProtocolError('deadline')
        connection.settimeout(value)

    def request(object_id, opcode, body=b''):
        remaining()
        try:
            connection.sendall(struct.pack('=II', object_id, ((len(body)+8) << 16) | opcode)+body)
        except TimeoutError:
            raise ProtocolError('deadline') from None
        except OSError:
            raise ProtocolError('socket_write_failed') from None

    def message():
        nonlocal total, events, received_fds
        while True:
            if len(pending) >= 8:
                word, = struct.unpack_from('=I', pending, 4)
                size = word >> 16
                if size < 8 or size % 4:
                    raise ProtocolError('invalid_message_size')
                if len(pending) >= size:
                    object_id, word = struct.unpack_from('=II', pending)
                    body = bytes(pending[8:size]); del pending[:size]
                    events += 1
                    if events > MAX_EVENTS:
                        raise ProtocolError('event_budget')
                    return object_id, word & 65535, body
            remaining()
            try:
                data, ancillary, flags, _ = connection.recvmsg(65536, socket.CMSG_SPACE(16*4), socket.MSG_CMSG_CLOEXEC)
            except TimeoutError:
                raise ProtocolError('deadline') from None
            except OSError:
                raise ProtocolError('socket_read_failed') from None
            bad_ancillary = False
            for level, kind, values in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors = array.array('i')
                    descriptors.frombytes(values[:len(values)//descriptors.itemsize*descriptors.itemsize])
                    fds.extend(descriptors); received_fds += len(descriptors)
                    if len(values) % descriptors.itemsize:
                        bad_ancillary = True
                else:
                    bad_ancillary = True
            if bad_ancillary or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise ProtocolError('invalid_ancillary')
            if received_fds > 1:
                raise ProtocolError('format_table_fd_budget')
            if not data:
                raise ProtocolError('connection_closed')
            total += len(data)
            if total > MAX_BYTES:
                raise ProtocolError('byte_budget')
            pending.extend(data)

    def dispatch(object_id, opcode, body):
        nonlocal table, main_device, tranche, index_count, done
        if object_id == 1 and opcode == 1 and len(body) == 4:
            return  # delete_id on this dedicated connection; IDs are never reused.
        if object_id == 1 and opcode == 0:
            raise ProtocolError('display_error')  # Never include the server's free text.
        if object_id == 2 and opcode == 0 and len(body) >= 12:
            name, length = struct.unpack_from('=II', body)
            end = 8 + ((length+3)//4)*4
            if not name or not 1 <= length <= 256 or end+4 != len(body) or body[8+length-1] != 0:
                raise ProtocolError('invalid_global')
            interface = body[8:8+length]
            if interface in (INTERFACE, COMPOSITOR):
                if interface in found:
                    raise ProtocolError('ambiguous_global')
                found[interface] = (name, struct.unpack_from('=I', body, end)[0])
            return
        if object_id == 2 and opcode == 1 and len(body) == 4:
            raise ProtocolError('global_removed_during_probe')
        if object_id != 7 or done:
            raise ProtocolError('unexpected_message')
        if opcode == 1 and len(body) == 4:
            if table is not None or not fds:
                raise ProtocolError('format_table_fd_required_once')
            table = _table(fds.popleft(), struct.unpack('=I', body)[0])
        elif opcode == 2:
            if main_device is not None or tranches or tranche['target_device'] is not None:
                raise ProtocolError('main_device_required_once')
            main_device = _device(body)
        elif opcode == 4:
            if main_device is None or tranche['target_device'] is not None:
                raise ProtocolError('tranche_target_required_once')
            tranche['target_device'] = _device(body)
        elif opcode == 6 and len(body) == 4:
            if main_device is None or tranche['flags'] is not None:
                raise ProtocolError('tranche_flags_required_once')
            tranche['flags'], = struct.unpack('=I', body)
        elif opcode == 5:
            if table is None or main_device is None:
                raise ProtocolError('format_table_and_main_device_required')
            values = _array(body, MAX_INDICES*2)
            if not values or len(values) % 2:
                raise ProtocolError('invalid_format_indices')
            indices = [value for value, in struct.iter_unpack('=H', values)]
            if any(index >= len(table) for index in indices):
                raise ProtocolError('format_index_out_of_range')
            index_count += len(indices)
            if index_count > MAX_INDICES:
                raise ProtocolError('index_budget')
            tranche['indices'].extend(indices)
        elif opcode == 3 and not body:
            if tranche['target_device'] is None or not tranche['indices']:
                raise ProtocolError('incomplete_tranche')
            if len(tranches) >= MAX_TRANCHES:
                raise ProtocolError('tranche_budget')
            # Weston can omit tranche_flags when no flags are set. The
            # tranche-local default is zero; absence is not an incomplete set.
            flags = 0 if tranche['flags'] is None else tranche['flags']
            formats = []
            for index in tranche['indices']:
                entry = table[index]
                pair = (tranche['target_device']['dev_t'], flags, entry['fourcc'], entry['modifier'])
                if pair in all_pairs:
                    raise ProtocolError('duplicate_tranche_format')
                all_pairs.add(pair)
                formats.append(dict(fourcc=entry['fourcc'], modifier=entry['modifier'],
                                    explicit_modifier=entry['modifier'] != INVALID_MODIFIER))
            tranches.append(dict(preference=len(tranches), target_device=tranche['target_device'],
                                 flags=flags, flags_event_received=tranche['flags'] is not None,
                                 scanout=bool(flags & 1), unknown_flags=flags & ~1,
                                 format_indices=tranche['indices'], formats=formats))
            tranche = dict(target_device=None, flags=None, indices=[])
        elif opcode == 0 and not body:
            if table is None or main_device is None or not tranches or any(value is not None and value != [] for value in tranche.values()):
                raise ProtocolError('incomplete_feedback')
            # Different DRM node numbers can describe the same physical device.
            # Resolve no device paths here and infer no physical-device equality.
            if fds:
                raise ProtocolError('unexpected_fds')
            done = True
        else:
            raise ProtocolError('unexpected_feedback_event')

    def roundtrip(callback):
        request(1, 0, struct.pack('=I', callback))
        while True:
            object_id, opcode, body = message()
            if object_id == callback and opcode == 0 and len(body) == 4:
                if fds:
                    raise ProtocolError('unexpected_fds')
                return
            dispatch(object_id, opcode, body)

    def bind(interface, version, object_id):
        name, _ = found[interface]
        body = struct.pack('=II', name, len(interface))+interface+b'\0'*(-len(interface)%4)
        request(2, 0, body+struct.pack('=II', version, object_id))

    try:
        request(1, 1, struct.pack('=I', 2))
        roundtrip(3)
        if INTERFACE not in found or found[INTERFACE][1] < 4:
            raise ProtocolError('dma_buf_v4_unavailable')
        if COMPOSITOR not in found or found[COMPOSITOR][1] < 1:
            raise ProtocolError('compositor_unavailable')
        bind(COMPOSITOR, min(found[COMPOSITOR][1], 4), 4)
        bind(INTERFACE, 4, 5)
        request(4, 0, struct.pack('=I', 6))  # compositor.create_surface
        request(5, 3, struct.pack('=II', 7, 6))  # dmabuf.get_surface_feedback
        roundtrip(8)
        if not done:
            raise ProtocolError('feedback_done_required')
        request(7, 0); request(6, 0); request(5, 0)
        # wl_registry has only bind on the wire. wl_registry_destroy() is a
        # local libwayland proxy destructor; disconnect releases this binding.
        roundtrip(9)
        return dict(schema_version=1, advertised_version=found[INTERFACE][1], bound_version=4,
                    format_table=table, main_device=main_device, tranches=tranches,
                    wire_bytes=total, wire_events=events, format_table_fds_received=received_fds,
                    feedback_v4_inspected=True, surface_created=True, surface_destroyed=True,
                    surface_mapped=False, buffer_created=False, input_bound=False,
                    registry_destroy_request_sent=False, registry_alive_until_connection_close=True,
                    physical_device_identity_resolved=False,
                    expected_peer_pid_checked=expected_peer_pid is not None,
                    other_client_surface_inspected=False, capability_advertisement_only=True,
                    presentation_verified=False, full_port_verified=False)
    finally:
        while fds:
            os.close(fds.popleft())
        connection.settimeout(original_timeout)
