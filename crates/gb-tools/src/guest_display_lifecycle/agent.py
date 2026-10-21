"""Owned displayed-Vulkan handoff. No device input, profile change or raw log export."""
from pathlib import Path
import ctypes
import hashlib
import ipaddress
import json
import os
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

CONTEXT = json.loads(bytes.fromhex('__CONTEXT_HEX__'))
ARGV = ['--wsi', 'wayland', '--width', '640', '--height', '480', '--c', '3600']
PROFILES = [Path('/etc/profile.d/gb-venus-client-v1.sh'), Path('/etc/profile.d/gb-venus-wsi-v1.sh')]
TOKENS = {'GB_VKCUBE_LIFECYCLE_V1': 'owned-three-phase-v1', 'GB_VKCUBE_PATTERN_V1': 'fixed-quadrants-v1',
          'GB_VKCUBE_OWNED_FIXED_V1': 'owned-fixed-v1',
          'GB_VKCUBE_PATTERN_FULLSCREEN_V1': 'owned-centered-v1'}

class Refused(Exception):
    pass

def require(ok, reason='contract_refused'):
    if not ok:
        raise Refused(reason)

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_field')
        value[key] = item
    return value

def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= limit, 'regular_file_budget')
        data = stream.read(limit + 1)
        require(len(data) == meta.st_size, 'file_changed')
        return data

def digest(path, limit):
    return hashlib.sha256(regular(path, limit)).hexdigest()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise Refused('redirect_refused')

def rpc(base, route, data=None, maximum=2048):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(base + '/' + route, data=data,
                                     headers={'Content-Type': 'application/json'} if data is not None else {})
    with opener.open(request, timeout=3) as response:
        body = response.read(maximum + 1)
        require(len(body) <= maximum, 'http_body_budget')
        return response.status, body

def post(base, route, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    require(len(raw) <= 4096, 'receipt_budget')
    status, body = rpc(base, route, raw, 64)
    require(status == 200 and body == b'GB_DISPLAY_ACCEPTED\n', 'receipt_not_acknowledged')

def common(nonce, agent_sha):
    return dict(schema_version=1, run_nonce=nonce, guest_boot_id=CONTEXT['guest_boot_id'],
                agent_sha256=agent_sha, program_sha256=CONTEXT['program_sha256'], uid=1000)

def birth(pid):
    # Only the owned worker's start time, never a VMM argv/comm/map export.
    text = Path('/proc/%d/stat' % pid).read_text()
    return int(text[text.rfind(') ') + 2:].split()[19])

def inspect_context():
    require(os.getuid() == CONTEXT['uid'] == 1000 and os.uname().machine == 'aarch64', 'guest_identity')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == CONTEXT['guest_boot_id'], 'guest_boot')
    driver = Path('/usr/local/lib/googlebook-port-venus-v1') / ('venus-client-' + CONTEXT['driver_sha256'])
    require(digest(driver / 'libvulkan_virtio.so', 2097152) == CONTEXT['driver_sha256'], 'driver_hash')
    require([digest(p, 16384) for p in PROFILES] == CONTEXT['profiles_sha256'], 'profile_hash')
    require(os.environ.get('VK_DRIVER_FILES') == str(driver / 'virtio_icd.json')
            and os.environ.get('MESA_VK_WSI_DEBUG') == 'sw'
            and os.environ.get('GB_VENUS_COMMAND_POOL_V1') == '1m', 'profile_environment')
    require('WAYLAND_SOCKET' not in os.environ and 'GB_VKCUBE_OWNED_RESIZE_V1' not in os.environ,
            'unexpected_transport_mode')
    process = subprocess.run(['systemctl', '--user', 'show', 'weston', '--property=MainPID',
                              '--property=ActiveState'], capture_output=True, timeout=2)
    require(process.returncode == 0 and len(process.stdout) <= 128 and len(process.stderr) <= 128,
            'compositor_query')
    values = dict(line.split('=', 1) for line in process.stdout.decode('ascii').splitlines())
    require(values == {'MainPID': str(CONTEXT['compositor_pid']), 'ActiveState': 'active'}, 'compositor_identity')
    sockets = []
    for name in ('wayland-0', 'wayland-1', 'wayland-2'):
        path = Path('/run/user/1000') / name
        try:
            meta = path.lstat()
            if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid != 1000:
                continue
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(.4)
                peer.connect(str(path))
                pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if pid == CONTEXT['compositor_pid'] and uid == 1000:
                    sockets.append(name)
        except OSError:
            continue
    require(len(sockets) == 1, 'compositor_socket')
    return sockets[0]

def write_flag(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())

def remove_owned(directory):
    require(directory.parent == Path('/tmp') and directory.name.startswith('gb-display-'), 'cleanup_namespace')
    meta = directory.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 1000 and stat.S_IMODE(meta.st_mode) == 0o700,
            'cleanup_directory')
    allowed = {'program', 'worker.py', 'prepared.json'}
    require(set(p.name for p in directory.iterdir()) <= allowed, 'unexpected_owned_file')
    for name in allowed:
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            pass
    directory.rmdir()
    return not directory.exists()

def stop_child(child):
    if child is None:
        return True
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
    child.wait(timeout=1)
    return child.returncode is not None

def child_parent_death(parent_pid):
    # Same supervisor process group; kernel additionally kills the native child
    # if its Python worker dies unexpectedly before GNU timeout's group deadline.
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0, 'parent_death_signal')
    if os.getppid() != parent_pid:
        os._exit(125)

EXTENTS = ((640, 480), (480, 360), (640, 480))
NATIVE_REFUSAL_STAGES = frozenset(('actual_image_or_recreation_budget', 'configure_extent_or_event_budget', 'configure_state_array_budget', 'create_swapchain_failed', 'explicit_wayland_and_bounded_run_required', 'get_swapchain_image_count_failed', 'get_swapchain_images_failed', 'lifecycle_ack_deadline', 'lifecycle_ack_eof', 'lifecycle_ack_extra', 'lifecycle_ack_pipe', 'lifecycle_ack_sequence', 'lifecycle_advance', 'lifecycle_bounded_initial_state', 'lifecycle_cleanup_fence', 'lifecycle_cleanup_state', 'lifecycle_clock', 'lifecycle_create_sequence', 'lifecycle_device_idle', 'lifecycle_draw_state', 'lifecycle_flush', 'lifecycle_frame_fence', 'lifecycle_incomplete', 'lifecycle_no_queue_witness', 'lifecycle_pending_events', 'lifecycle_poll', 'lifecycle_queue_present', 'lifecycle_reprepare_incomplete', 'lifecycle_token_or_owned_pipe', 'lifecycle_wayland_fd', 'lifecycle_wayland_poll_api', 'lifecycle_wayland_read', 'lifecycle_wayland_state', 'owned_compositor_peer', 'owned_compositor_pid', 'owned_wayland_identity', 'pattern_extent', 'pattern_fullscreen_configure', 'pattern_fullscreen_not_confirmed', 'pattern_selection', 'swapchain_extent_or_requested_image_budget', 'texture_image_api_failure'))

def phase_contract(phase):
    require(type(phase) is int and 0 <= phase <= 2, 'phase_index')
    width, height = EXTENTS[phase]
    text = ('GB_VULKAN_LIFECYCLE_V1:%d:%d:%d:border=8:palette=19,67,139;203,37,91;47,181,113;211,173,53:rotation=%d'
            % (phase, width, height, phase))
    return dict(phase=phase, width=width, height=height,
                contract_sha256=hashlib.sha256(text.encode('ascii')).hexdigest())

def marker(line, state):
    prefix = 'GB_VULKAN_LIFECYCLE_'
    if not line.startswith(prefix):
        return
    kind, raw = line[len(prefix):].split(':', 1)
    require(kind in ('START', 'CONFIGURE', 'CREATE', 'PRESENT', 'ACK', 'COMPLETED', 'REFUSED'), 'marker_kind')
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and type(value.get('schema_version')) is int
            and value['schema_version'] == 2 and value.get('presentation_verified') is False, 'marker_schema')
    if kind == 'START':
        require(value == dict(schema_version=2, phase_count=3, frame_limit=3600,
                              ack_required=True, presentation_verified=False)
                and all(type(value[k]) is int for k in ('schema_version', 'phase_count', 'frame_limit'))
                and value['ack_required'] is True and state['start'] is None, 'start_marker')
        state['start'] = value
        return
    if kind == 'REFUSED':
        require(set(value) == {'schema_version', 'status', 'stage', 'presentation_verified'}
                and value['status'] == 'refused' and type(value['stage']) is str
                and value['stage'] in NATIVE_REFUSAL_STAGES, 'refused_marker_schema')
        state['native_refusal_stage'] = value['stage']
        raise Refused('refused_marker')
    require(state['start'] is not None, 'marker_order')
    if kind == 'CONFIGURE':
        phase = value.get('phase')
        require(type(phase) is int and 0 <= phase <= 2 and phase == len(state['native_acks']), 'configure_marker')
        width, height = EXTENTS[phase]
        require(set(value) == {'schema_version','phase','fullscreen','raw_max_width','raw_max_height','buffer_width','buffer_height','presentation_verified'}
                and all(type(value[k]) is int for k in ('phase','raw_max_width','raw_max_height','buffer_width','buffer_height'))
                and type(value['fullscreen']) is bool and value['buffer_width'] == width and value['buffer_height'] == height
                and state['configure_count'] < 64, 'configure_marker')
        if value['fullscreen']:
            require(640 <= value['raw_max_width'] <= 3200 and 480 <= value['raw_max_height'] <= 2000, 'configure_marker')
            state['fullscreen_seen'] = True
        else:
            require(phase == 0 and not state['fullscreen_seen'] and state['configure_count'] == 0
                    and value['raw_max_width'] in (0,640) and value['raw_max_height'] in (0,480), 'configure_marker')
        state['configure_count'] += 1
        return
    if kind == 'COMPLETED':
        require(value == dict(schema_version=2, phases=3, acknowledgements=3,
                              swapchain_generations=3, frames=3, presentation_verified=False,
                              explicit_present_retirement_verified=False)
                and all(type(value[k]) is int for k in ('schema_version','phases','acknowledgements','swapchain_generations','frames'))
                and all(len(state[k]) == 3 for k in ('creates','presents','native_acks','sent_acks'))
                and value['explicit_present_retirement_verified'] is False
                and state['completed'] is None, 'completion_marker')
        state['completed'] = value
        return
    phase = value.get('phase')
    require(type(phase) is int and 0 <= phase <= 2, 'phase_index')
    width, height = EXTENTS[phase]
    if kind == 'CREATE':
        require(set(value) == {'schema_version','phase','width','height','images','old_swapchain_supplied','swapchain_generation','presentation_verified'}
                and all(type(value[k]) is int for k in ('phase','width','height','images','swapchain_generation'))
                and value['width'] == width and value['height'] == height and 1 <= value['images'] <= 4
                and value['old_swapchain_supplied'] is (phase > 0) and value['swapchain_generation'] == phase + 1
                and len(state['creates']) == phase and len(state['native_acks']) == phase
                and len(state['sent_acks']) == phase, 'create_marker')
        state['creates'].append(value)
    elif kind == 'PRESENT':
        require(set(value) == {'schema_version','phase','width','height','frame','swapchain_generation','queue_present_result','presentation_verified'}
                and all(type(value[k]) is int for k in ('phase','width','height','frame','swapchain_generation','queue_present_result'))
                and value['width'] == width and value['height'] == height and value['frame'] == phase + 1
                and value['swapchain_generation'] == phase + 1 and value['queue_present_result'] == 0
                and len(state['creates']) == phase + 1 and len(state['presents']) == phase
                and len(state['native_acks']) == phase and state['fullscreen_seen'], 'present_marker')
        state['presents'].append(value)
    else:
        require(set(value) == {'schema_version','phase','ack_index','presentation_verified'}
                and type(value['ack_index']) is int and value['ack_index'] == phase + 1
                and len(state['native_acks']) == phase and len(state['sent_acks']) == phase + 1
                and len(state['presents']) == phase + 1, 'ack_marker')
        state['native_acks'].append(value)

def control(base, route, binding):
    status, body = rpc(base, route)
    if status == 204:
        require(not body, 'empty_control')
        return None
    require(status == 200, 'control_status')
    value = json.loads(body, object_pairs_hook=unique)
    expected = dict(binding, kind=route)
    require(type(value) is dict and type(value.get('schema_version')) is int, 'control_types')
    if route.startswith('ack'):
        require(route in ('ack0','ack1','ack2'), 'phase_index')
        expected.update(phase_contract(int(route[-1])))
        require(type(value.get('capture_token')) is str and re.fullmatch('[0-9a-f]{32}', value['capture_token'])
                and type(value.get('capture_sha256')) is str and re.fullmatch('[0-9a-f]{64}', value['capture_sha256']), 'capture_digest')
        expected.update(capture_token=value['capture_token'], capture_sha256=value['capture_sha256'])
    require(value == expected and all(type(value[k]) is int for k in ('schema_version',)
            + (('phase','width','height') if route.startswith('ack') else ())), 'control_context')
    return value

def worker(base, nonce, agent_sha):
    directory = Path(__file__).parent
    deadline = time.monotonic() + 135
    child = None
    readers = selectors.DefaultSelector()
    state = dict(start=None, creates=[], presents=[], native_acks=[], sent_acks=[], completed=None, configure_count=0, fullscreen_seen=False)
    result = dict(common(nonce, agent_sha), kind='result', status='failed', failure_stage='context',
                  failure_kind=None, native_refusal_stage=None, capture_receipts=[], child_started=False, child_reaped=False,
                  child_exit_code=None, child_same_owned_group=False, profiles_retained=False,
                  compositor_retained=False, driver_retained=False, files_removed=False,
                  stdout_bytes=0, stderr_bytes=0, present_count=0, native_ack_count=0,
                  completion=None, graphics_qualified=False)
    binding = dict(schema_version=1, run_nonce=nonce, guest_boot_id=CONTEXT['guest_boot_id'],
                   agent_sha256=agent_sha, program_sha256=CONTEXT['program_sha256'])
    def cancel(*args):
        raise Refused('child_timeout' if args and args[0] == signal.SIGALRM and child is not None else 'cancelled')
    signal.signal(signal.SIGTERM, cancel); signal.signal(signal.SIGINT, cancel); signal.signal(signal.SIGALRM, cancel)
    signal.alarm(135)
    try:
        require(directory.name.startswith('gb-display-' + nonce + '-') and directory.parent == Path('/tmp'), 'worker_namespace')
        require(digest(Path(__file__), 65536) == agent_sha, 'worker_hash')
        require(digest(directory / 'program', 1048576) == CONTEXT['program_sha256'], 'program_hash')
        display = inspect_context()
        post(base, 'prepared', dict(common(nonce, agent_sha), kind='prepared', status='worker_prepared',
             compositor_pid=CONTEXT['compositor_pid'], worker_pid=os.getpid(), worker_start_ticks=birth(os.getpid()),
             profiles_sha256=CONTEXT['profiles_sha256'], driver_sha256=CONTEXT['driver_sha256'],
             profile_environment_checked=True, graphics_qualified=False))
        write_flag(directory / 'prepared.json', binding)
        result['failure_stage'] = 'wait_ready'
        ready_deadline = min(time.monotonic() + 90, deadline - 12)
        while time.monotonic() < ready_deadline:
            if control(base, 'ready', binding) is not None: break
            time.sleep(.3)
        else: raise Refused('ready_timeout')
        require(inspect_context() == display, 'context_changed')
        result['failure_stage'] = 'program'
        environment = dict(os.environ); environment.update(TOKENS)
        environment.update(WAYLAND_DISPLAY=display, GB_OWNED_COMPOSITOR_PID=str(CONTEXT['compositor_pid']),
                           XDG_RUNTIME_DIR='/run/user/1000', MESA_SHADER_CACHE_DISABLE='true')
        worker_pid = os.getpid()
        signal.setitimer(signal.ITIMER_REAL, min(58.0, deadline - time.monotonic()))
        child = subprocess.Popen([str(directory / 'program'), *ARGV], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                 preexec_fn=lambda: child_parent_death(worker_pid))
        result['child_started'] = True
        require(os.getpgid(child.pid) == os.getpgrp(), 'child_group')
        result['child_same_owned_group'] = True
        os.set_blocking(child.stdin.fileno(), False)
        child_deadline = min(time.monotonic() + 60, deadline - 8)
        for name, stream in [('stdout', child.stdout), ('stderr', child.stderr)]:
            os.set_blocking(stream.fileno(), False); readers.register(stream, selectors.EVENT_READ, name)
        pending = b''; announced = set(); next_poll = 0; exit_kind = 'child_exited_before_capture'
        while time.monotonic() < child_deadline:
            for key, _ in readers.select(.05):
                # Drain all currently readable owned output before checking exit.
                # A normal exit can race the final COMPLETE bytes in the pipe.
                while True:
                    try: data = os.read(key.fileobj.fileno(), 1024)
                    except BlockingIOError: break
                    if not data: readers.unregister(key.fileobj); break
                    name = key.data; result[name + '_bytes'] += len(data)
                    require(result[name + '_bytes'] <= (8192 if name == 'stdout' else 4096), 'stdio_budget')
                    if name == 'stdout':
                        pending += data; require(len(pending) <= 4096, 'line_budget')
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            marker(line.decode('utf-8', errors='strict'), state)
            if state['completed'] is not None:
                child.wait(timeout=2); require(child.returncode == 0, 'child_completion_exit')
                if readers.get_map():
                    continue  # Validate tail bytes/EOF and budgets before success.
                require(not pending and len(state['sent_acks']) == 3, 'completion_marker')
                result.update(status='all_phases_capture_acknowledged', failure_stage=None,
                              capture_receipts=state['sent_acks'], completion=state['completed'])
                break
            if child.poll() is not None:
                require(bool(readers.get_map()), exit_kind)
                continue  # Drain final owned pipe bytes/EOF before classifying exit.
            phase = len(state['sent_acks'])
            if phase < 3 and len(state['presents']) == phase + 1:
                if phase not in announced:
                    post(base, 'phase%d' % phase, dict(common(nonce, agent_sha), kind='phase%d' % phase,
                         status='queue_present_api_witness', compositor_pid=CONTEXT['compositor_pid'],
                         start=state['start'], creation=state['creates'][phase], present=state['presents'][phase],
                         preceding_native_ack_count=len(state['native_acks']), child_alive=True, graphics_qualified=False))
                    announced.add(phase)
                    if child.poll() is not None:
                        exit_kind = 'child_exited_during_started_ack'
                        continue  # Drain native tail/EOF before classifying the exit.
                if time.monotonic() >= next_poll:
                    ack = control(base, 'ack%d' % phase, binding); next_poll = time.monotonic() + .3
                    if child.poll() is not None:
                        exit_kind = 'child_exited_during_ack'
                        continue  # A refusal may have arrived during the HTTP read.
                    if ack is not None:
                        require(not any(x['capture_token'] == ack['capture_token'] for x in state['sent_acks']), 'capture_token_reused')
                        line = ('ACK%d\n' % phase).encode('ascii')
                        require(os.write(child.stdin.fileno(), line) == len(line), 'native_ack_write')
                        state['sent_acks'].append(ack)
        else: raise Refused('child_timeout')
    except Exception as error:
        result['failure_kind'] = str(error) if isinstance(error, Refused) else 'operation_failed'
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN); signal.alarm(0)
        try:
            result['child_reaped'] = stop_child(child)
            result['child_exit_code'] = child.returncode if child is not None else None
        except Exception: result['child_reaped'] = False
        for stream in (child.stdin, child.stdout, child.stderr) if child is not None else ():
            try: stream.close()
            except Exception: pass
        readers.close()
        try:
            result['profiles_retained'] = [digest(p, 16384) for p in PROFILES] == CONTEXT['profiles_sha256']
            result['compositor_retained'] = inspect_context() is not None; result['driver_retained'] = True
        except Exception: pass
        try: result['files_removed'] = remove_owned(directory)
        except Exception: pass
        result['native_refusal_stage'] = state.get('native_refusal_stage')
        result['present_count'] = len(state['presents']); result['native_ack_count'] = len(state['native_acks'])
        result['capture_receipts'] = state['sent_acks']
        if not all(result[k] for k in ('child_reaped','profiles_retained','compositor_retained','driver_retained','files_removed')):
            result.update(status='failed', failure_stage='cleanup', failure_kind='cleanup_incomplete')
        try: post(base, 'result', result)
        except Exception: return 2
    return 0 if result['status'] == 'all_phases_capture_acknowledged' else 2


def bootstrap(base, nonce, agent_sha):
    source = Path(__file__)
    require(source.parent == Path('/tmp') and source.name.startswith('gb-gfx-' + nonce + '.'), 'bootstrap_path')
    meta = source.lstat()
    require(meta.st_uid == 1000 and stat.S_IMODE(meta.st_mode) == 0o600
            and digest(source, 65536) == agent_sha, 'bootstrap_hash')
    inspect_context()
    status, program = rpc(base, 'program', maximum=CONTEXT['program_bytes'])
    require(status == 200 and len(program) == CONTEXT['program_bytes']
            and hashlib.sha256(program).hexdigest() == CONTEXT['program_sha256'], 'program_download')
    require(program[:6] == b'\x7fELF\x02\x01' and len(program) >= 64
            and struct.unpack_from('<H', program, 18)[0] == 183, 'program_architecture')
    directory = Path(tempfile.mkdtemp(prefix='gb-display-' + nonce + '-', dir='/tmp'))
    os.chmod(directory, 0o700)
    supervisor = None
    handed_off = False
    try:
        with (directory / 'program').open('xb') as stream:
            stream.write(program)
        os.chmod(directory / 'program', 0o700)
        with (directory / 'worker.py').open('xb') as stream:
            stream.write(regular(source, 65536))
        supervisor = subprocess.Popen(['timeout', '-k', '2', '-s', 'TERM', '148',
                'python3', '-I', str(directory / 'worker.py'), '--worker', base, agent_sha],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        deadline = time.monotonic() + 8
        expected = dict(schema_version=1, run_nonce=nonce, guest_boot_id=CONTEXT['guest_boot_id'],
                        agent_sha256=agent_sha, program_sha256=CONTEXT['program_sha256'])
        while time.monotonic() < deadline and supervisor.poll() is None:
            try:
                value = json.loads(regular(directory / 'prepared.json', 2048), object_pairs_hook=unique)
                require(value == expected, 'prepared_flag')
                require(supervisor.poll() is None, 'supervisor_exited')
                handed_off = True
                return 0
            except FileNotFoundError:
                time.sleep(.05)
        raise Refused('worker_not_prepared')
    finally:
        if not handed_off:
            if supervisor is not None:
                try:
                    os.killpg(supervisor.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    supervisor.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(supervisor.pid, signal.SIGKILL)
                    supervisor.wait(timeout=1)
            if directory.exists():
                remove_owned(directory)

def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2097152, 2097152))
    is_worker = len(sys.argv) == 4 and sys.argv[1] == '--worker'
    require(is_worker or len(sys.argv) == 3, 'arguments')
    base, agent_sha = sys.argv[-2:]
    match = re.fullmatch(r'http://([0-9.]+):([0-9]{4,5})/([0-9a-f]{32})', base)
    require(match and ipaddress.IPv4Address(match[1]) in ipaddress.IPv4Network('10.0.0.0/8')
            or match and ipaddress.IPv4Address(match[1]) in ipaddress.IPv4Network('172.16.0.0/12')
            or match and ipaddress.IPv4Address(match[1]) in ipaddress.IPv4Network('192.168.0.0/16'), 'private_endpoint')
    require(1024 <= int(match[2]) <= 65535 and re.fullmatch('[0-9a-f]{64}', agent_sha), 'endpoint_binding')
    if not is_worker:
        def cancel(*args):
            raise Refused('bootstrap_cancelled')
        signal.signal(signal.SIGTERM, cancel)
        signal.signal(signal.SIGINT, cancel)
    return worker(base, match[3], agent_sha) if is_worker else bootstrap(base, match[3], agent_sha)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit(2)
