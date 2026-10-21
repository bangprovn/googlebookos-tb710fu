#!/usr/bin/env python3
"""Bounded v4 metadata probe against local fake compositors; no GPU/device."""
import array
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import threading
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

path = Path(__file__).parent/'fixtures/owned_wayland_feedback.py'
spec = importlib.util.spec_from_file_location('feedback', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def message(object_id, opcode, body=b''):
    return struct.pack('=II', object_id, ((len(body)+8) << 16) | opcode)+body


def values(data):
    return struct.pack('=I', len(data))+data+b'\0'*(-len(data)%4)


def global_message(name, interface, version):
    return message(2, 0, struct.pack('=I', name)+values(interface+b'\0')+struct.pack('=I', version))


def event(opcode, body=b''):
    return message(7, opcode, body)


def tranche(device, flags, indices):
    flag_event = b'' if flags is None else event(6, struct.pack('=I', flags))
    return (event(4, values(struct.pack('=Q', device))) + flag_event +
            event(5, values(struct.pack('='+str(len(indices))+'H', *indices))) + event(3))


def receive(connection):
    def exact(size):
        data = b''
        while len(data) < size:
            part = connection.recv(size-len(data))
            if not part:
                raise EOFError('client_closed')
            data += part
        return data
    header = exact(8)
    object_id, word = struct.unpack('=II', header)
    return object_id, word & 65535, exact((word >> 16)-8)


class Feedback(unittest.TestCase):
    def test_wire_requests_and_feedback_events_match_local_sdk_xml(self):
        sdk = Path(__file__).resolve().parents[1]/'artifacts/device/first-boot-20261013/guest-vulkan-work-20261019-v1/guest-command-pool-v1/sdk/usr/share'
        core = ET.parse(sdk/'wayland/wayland.xml')
        registry = core.find("interface[@name='wl_registry']")
        self.assertEqual([item.attrib['name'] for item in registry.findall('request')], ['bind'])
        dmabuf = ET.parse(sdk/'wayland-protocols/stable/linux-dmabuf/linux-dmabuf-v1.xml')
        factory = dmabuf.find("interface[@name='zwp_linux_dmabuf_v1']")
        self.assertEqual([item.attrib['name'] for item in factory.findall('request')],
                         ['destroy','create_params','get_default_feedback','get_surface_feedback'])
        feedback = dmabuf.find("interface[@name='zwp_linux_dmabuf_feedback_v1']")
        self.assertEqual([item.attrib['name'] for item in feedback.findall('event')],
                         ['done','format_table','main_device','tranche_done','tranche_target_device','tranche_formats','tranche_flags'])
        self.assertEqual([item.attrib['type'] for item in feedback.find("event[@name='format_table']").findall('arg')], ['fd','uint'])

    def exercise(self, expected=None, body=None, table_size=48, table_bytes=None,
                 fd_count=1, pipe=False, partial=False, advertised=5, budget=None):
        baseline = len(os.listdir('/proc/self/fd'))
        client, server = socket.socketpair()
        server.settimeout(3)
        original_timeout = 1.75
        client.settimeout(original_timeout)
        main = os.makedev(226, 128)
        if body is None:
            body = (event(2, values(struct.pack('=Q', main))) +
                    tranche(os.makedev(226, 0), 1, [1]) + tranche(main, 0, [0, 2]) + event(0))
        failures, received = [], []

        def peer():
            fd = write_fd = None
            try:
                self.assertEqual(receive(server), (1, 1, struct.pack('=I', 2)))
                self.assertEqual(receive(server), (1, 0, struct.pack('=I', 3)))
                registry = (global_message(40, b'private_ignored_global', 1) +
                            global_message(41, b'wl_compositor', 6) +
                            global_message(42, b'zwp_linux_dmabuf_v1', advertised) + message(3, 0, struct.pack('=I', 0)))
                for i in range(0, len(registry), 7):
                    server.sendall(registry[i:i+7])
                if advertised < 4 or budget is not None:
                    return
                for _ in range(5):
                    received.append(receive(server))
                self.assertEqual(received[0], (2, 0, struct.pack('=I', 41)+values(probe.COMPOSITOR)+struct.pack('=II', 4, 4)))
                self.assertEqual(received[1], (2, 0, struct.pack('=I', 42)+values(probe.INTERFACE)+struct.pack('=II', 4, 5)))
                self.assertEqual(received[2:], [(4, 0, struct.pack('=I', 6)), (5, 3, struct.pack('=II', 7, 6)),
                                               (1, 0, struct.pack('=I', 8))])
                if pipe:
                    fd, write_fd = os.pipe()
                else:
                    fd = os.memfd_create('owned-feedback-test', os.MFD_CLOEXEC)
                    table = table_bytes if table_bytes is not None else b''.join(
                        struct.pack('=I4sQ', fourcc, b'PRIV', modifier) for fourcc, modifier in
                        [(875713112, 0), (875713112, probe.INVALID_MODIFIER), (875708993, 0)])
                    os.write(fd, table)
                wire = event(1, struct.pack('=I', table_size))
                descriptors = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]*fd_count))] if fd_count else []
                if partial:
                    self.assertEqual(server.sendmsg([wire[:3]], descriptors), 3)
                    server.sendall(wire[3:])
                else:
                    self.assertEqual(server.sendmsg([wire], descriptors), len(wire))
                wire = body+message(8, 0, struct.pack('=I', 0))
                for i in range(0, len(wire), 11):
                    server.sendall(wire[i:i+11])
                if expected:
                    return
                cleanup = [receive(server) for _ in range(4)]
                if any(object_id == 2 and opcode != 0 for object_id, opcode, _ in cleanup):
                    # Actual wl_registry XML has only bind opcode0. A wire
                    # "destroy" is a protocol error, not a proxy destructor.
                    server.sendall(message(1,0,struct.pack('=II',2,1)+values(b'invalid registry opcode\0')))
                    self.fail('invalid_registry_wire_opcode')
                self.assertEqual(cleanup, [(7, 0, b''), (6, 0, b''), (5, 0, b''),
                                           (1, 0, struct.pack('=I', 9))])
                received.extend(cleanup)
                server.sendall(message(1, 1, struct.pack('=I', 8))+message(9, 0, struct.pack('=I', 0)))
            except (BrokenPipeError, ConnectionResetError, EOFError):
                if not expected:
                    failures.append(AssertionError('client_closed_before_cleanup'))
            except BaseException as error:
                failures.append(error)
            finally:
                if fd is not None:
                    os.close(fd)
                if write_fd is not None:
                    os.close(write_fd)
                server.close()

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        result = None
        try:
            context = mock.patch.object(probe, 'MAX_BYTES', budget) if budget is not None else mock.patch.object(probe, 'MAX_BYTES', probe.MAX_BYTES)
            with context:
                if expected:
                    with self.assertRaisesRegex(probe.ProtocolError, '^'+expected+'$'):
                        probe.inspect(client, expected_peer_pid=os.getpid(), expected_uid=os.getuid())
                else:
                    result = probe.inspect(client, expected_peer_pid=os.getpid(), expected_uid=os.getuid())
            self.assertEqual(client.gettimeout(), original_timeout)
        finally:
            client.close()
            thread.join(4)
            if thread.is_alive():
                server.close()
                thread.join(1)
        self.assertFalse(thread.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)
        return result, received

    def test_fragmented_rights_table_preference_and_explicit_metadata_only(self):
        result, requests = self.exercise(partial=True)
        self.assertEqual(result['bound_version'], 4)
        self.assertEqual(result['advertised_version'], 5)
        self.assertEqual(result['format_table_fds_received'], 1)
        self.assertEqual(result['tranches'][0]['formats'],
                         [dict(fourcc=875713112, modifier=probe.INVALID_MODIFIER, explicit_modifier=False)])
        self.assertTrue(result['tranches'][0]['scanout'])
        self.assertEqual([item['modifier'] for item in result['tranches'][1]['formats']], [0, 0])
        self.assertEqual([item['preference'] for item in result['tranches']], [0, 1])
        self.assertTrue(result['surface_created'] and result['surface_destroyed'])
        self.assertFalse(result['surface_mapped'] or result['buffer_created'] or result['input_bound'])
        self.assertFalse(result['other_client_surface_inspected'] or result['presentation_verified'])
        self.assertTrue(result['expected_peer_pid_checked'])
        encoded = json.dumps(result)
        self.assertNotIn('private_ignored_global', encoded)
        self.assertNotIn('PRIV', encoded)  # Unused table bytes are never reported.
        self.assertTrue(result['registry_alive_until_connection_close'])
        self.assertFalse(result['registry_destroy_request_sent'])
        self.assertEqual(len(requests), 9)  # Registry is released by disconnect, not a wire request.

    def test_omitted_tranche_flags_default_to_zero_and_do_not_inherit_scanout(self):
        main = os.makedev(226,128)
        body = (event(2,values(struct.pack('=Q',main))) +
                tranche(os.makedev(226,0),1,[1]) + tranche(main,None,[0,2]) + event(0))
        result, requests = self.exercise(body=body)
        self.assertEqual([item['flags'] for item in result['tranches']], [1,0])
        self.assertEqual([item['scanout'] for item in result['tranches']], [True,False])
        self.assertEqual([item['flags_event_received'] for item in result['tranches']], [True,False])
        self.assertFalse(any(object_id==2 and opcode!=0 for object_id,opcode,_ in requests))

    def test_table_types_sizes_and_fd_budget_close_every_received_descriptor(self):
        for arguments, expected in [({'table_size':0}, 'format_table_size'),
                                    ({'table_size':17}, 'format_table_size'),
                                    ({'table_size':probe.MAX_TABLE_BYTES+16}, 'format_table_size'),
                                    ({'table_bytes':b'\0'*16}, 'format_table_truncated'),
                                    ({'pipe':True}, 'format_table_not_regular'),
                                    ({'fd_count':0}, 'format_table_fd_required_once'),
                                    ({'fd_count':2}, 'format_table_fd_budget'),
                                    ({'fd_count':40}, 'invalid_ancillary')]:
            with self.subTest(arguments=arguments):
                self.exercise(expected=expected, **arguments)

    def test_feedback_structure_index_and_duplicate_refusals(self):
        main = os.makedev(226,128)
        header = event(2, values(struct.pack('=Q', main)))
        for body, expected in [(header+tranche(main,0,[3])+event(0), 'format_index_out_of_range'),
                               (header+tranche(main,0,[0,0])+event(0), 'duplicate_tranche_format'),
                               (header+event(4,values(struct.pack('=Q',main)))+event(3), 'incomplete_tranche'),
                               (header+tranche(main,0,[0]), 'feedback_done_required'),
                               (header+event(5,values(b'\x00')), 'invalid_format_indices'),
                               (event(2,values(b'\0'*7)), 'invalid_device_array'),
                               (header+event(0), 'incomplete_feedback'),
                               (event(1,struct.pack('=I',48)), 'format_table_fd_required_once'),
                               (event(99), 'unexpected_feedback_event'),
                               (message(99,0), 'unexpected_message')]:
            with self.subTest(expected=expected):
                self.exercise(expected=expected, body=body)

    def test_protocol_and_resource_limits(self):
        self.exercise(expected='dma_buf_v4_unavailable', advertised=3)
        self.exercise(expected='byte_budget', budget=8)
        with mock.patch.object(probe,'MAX_TRANCHES',1):
            self.exercise(expected='tranche_budget')
        with mock.patch.object(probe,'MAX_INDICES',1):
            self.exercise(expected='invalid_array')
        with mock.patch.object(probe,'MAX_EVENTS',1):
            self.exercise(expected='event_budget')

    def test_unexpected_registry_fds_and_malformed_headers(self):
        client, server = socket.socketpair()
        with client, server:
            fd = os.memfd_create('unexpected-feedback-test', os.MFD_CLOEXEC)
            try:
                baseline = len(os.listdir('/proc/self/fd'))
                server.sendmsg([message(3,0,struct.pack('=I',0))],
                               [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
                with self.assertRaisesRegex(probe.ProtocolError, '^unexpected_fds$'):
                    probe.inspect(client, expected_uid=os.getuid())
                self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)
            finally:
                os.close(fd)
        for word in [4 << 16, 10 << 16]:
            client, server = socket.socketpair()
            with client, server:
                server.sendall(struct.pack('=II',1,word))
                with self.assertRaisesRegex(probe.ProtocolError, '^invalid_message_size$'):
                    probe.inspect(client, expected_uid=os.getuid())

    def test_peer_deadline_and_server_text_are_fixed_errors(self):
        client, server = socket.socketpair()
        with client, server:
            with self.assertRaisesRegex(probe.ProtocolError, '^unexpected_compositor_peer$'):
                probe.inspect(client, expected_peer_pid=os.getpid()+10000, expected_uid=os.getuid())
            with self.assertRaisesRegex(probe.ProtocolError, '^unexpected_compositor_peer$'):
                probe.inspect(client, expected_uid=os.getuid()+1)
            server.sendall(message(1,0,b'private server message'.ljust(24,b'\0')))
            with self.assertRaisesRegex(probe.ProtocolError, '^display_error$'):
                probe.inspect(client, expected_uid=os.getuid())
        client, server = socket.socketpair()
        with client, server:
            with self.assertRaisesRegex(probe.ProtocolError, '^deadline$'):
                probe.inspect(client, deadline_seconds=0.02, expected_uid=os.getuid())
        for deadline in [0, -1, 11]:
            with self.assertRaisesRegex(probe.ProtocolError, '^invalid_deadline$'):
                probe.inspect(None, deadline_seconds=deadline)


if __name__ == '__main__':
    unittest.main()
