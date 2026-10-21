"""Owned guest-only shader agent; template is filled and hash-pinned before use."""
from pathlib import Path
import hashlib, ipaddress, json, os, re, resource, socket, stat, struct, subprocess, sys, types, urllib.request

def require(condition):
    if not condition:
        raise ValueError('handoff contract refused')
EXPECTED_BOOT = '__GUEST_BOOT__'
FIXTURE = bytes.fromhex('__FIXTURE_HEX__').decode('utf-8')

def digest(path, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or not 0 < meta.st_size <= limit:
            raise ValueError('owned file bound')
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def compositor():
    try:
        p = subprocess.run(['systemctl', '--user', 'is-active', 'weston'], capture_output=True, text=True, timeout=3)
        status = p.stdout.strip() if len(p.stdout) <= 64 else 'unknown'
        if status not in ('active', 'inactive', 'failed'):
            status = 'unknown'
        q = subprocess.run(['systemctl', '--user', 'show', 'weston', '--property=MainPID', '--value'], capture_output=True, text=True, timeout=3)
        text = q.stdout.strip()
        pid = int(text) if q.returncode == 0 and re.fullmatch('[0-9]{1,7}', text) else None
        return (status, pid if pid is not None and 1 < pid <= 4194304 else None)
    except (OSError, subprocess.TimeoutExpired):
        return ('unknown', None)

def peer(pid):
    if pid is None:
        return None
    count = 0
    for name in ['wayland-0', 'wayland-1', 'wayland-2']:
        path = Path('/run/user') / str(os.getuid()) / name
        try:
            m = path.lstat()
            if not stat.S_ISSOCK(m.st_mode) or m.st_uid != os.getuid():
                continue
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(str(path))
                p, u, _ = struct.unpack('3i', s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if p == pid and u == os.getuid():
                    count += 1
        except (OSError, TimeoutError):
            continue
    return count == 1

def main():
    require(len(sys.argv) == 3)
    base, expected_sha = sys.argv[1:]
    m = re.fullmatch('http://([0-9.]+):([0-9]{4,5})/([0-9a-f]{32})', base)
    require(m)
    require(ipaddress.IPv4Address(m[1]).is_private and 1024 <= int(m[2]) <= 65535)
    nonce = m[3]
    require(re.fullmatch('[0-9a-f]{64}', expected_sha))
    path = Path(__file__)
    require(path.parent == Path('/tmp') and path.name.startswith('gb-gfx-' + nonce + '.'))
    require(path.lstat().st_uid == os.getuid() and stat.S_IMODE(path.lstat().st_mode) == 384)
    require(digest(path, 65536) == expected_sha)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    result = dict(schema_version=1, run_nonce=nonce, payload_sha256=expected_sha, guest_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), uid=os.getuid(), architecture=os.uname().machine, kernel=os.uname().release, memtotal_kib=int(re.search('^MemTotal:\\s+([0-9]+) kB$', Path('/proc/meminfo').read_text(), re.M)[1]), graphics=None, inventory=None, status='unknown', failure_stage=None, failure_kind=None, firmware_written=False, configuration_changed=False, full_port_verified=False)
    stage = 'context'
    try:
        require(result['guest_boot_id'] == EXPECTED_BOOT and result['architecture'] == 'aarch64')
        stage = 'inventory'
        managed = 'e240b41e0a0be35dc7f5426312cb4a863ca4f362f4cf7d338115363d596c715e'
        directory = Path('/usr/local/lib/googlebook-port-venus-v1') / ('venus-client-' + managed)
        profiles = [Path('/etc/profile.d/gb-venus-client-v1.sh'), Path('/etc/profile.d/gb-venus-wsi-v1.sh')]
        before = [digest(p, 16384) for p in profiles]
        state, pid = compositor()
        result['inventory'] = dict(weston_state=state, weston_main_pid=pid, wayland_peer_matches=peer(pid), managed_driver_sha256=digest(directory / 'libvulkan_virtio.so', 2097152), managed_icd_selected=os.environ.get('VK_DRIVER_FILES') == str(directory / 'virtio_icd.json'), copy_wsi_default=os.environ.get('MESA_VK_WSI_DEBUG') == 'sw', command_pool_1m=os.environ.get('GB_VENUS_COMMAND_POOL_V1') == '1m', gl_override='unset' if 'MESA_LOADER_DRIVER_OVERRIDE' not in os.environ else 'zink' if os.environ['MESA_LOADER_DRIVER_OVERRIDE'] == 'zink' else 'other', software_environment=os.environ.get('LIBGL_ALWAYS_SOFTWARE') == '1', profiles_before=before, profiles_after=None, profiles_unchanged=None)
        stage = 'gles_probe'
        module = types.ModuleType('owned_gles_fixture')
        exec(compile(FIXTURE, '<owned-gles-fixture>', 'exec'), module.__dict__)
        result['graphics'] = module.probe(16)
        stage = 'profile_recheck'
        after = [digest(p, 16384) for p in profiles]
        result['inventory'].update(profiles_after=after, profiles_unchanged=before == after)
        g = result['graphics']
        result['status'] = 'shader_completed' if g['state'] == 'compatible' and (not g['renderer_reports_software']) and g['gl']['renderer'].startswith('virgl (') else 'shader_path_requires_investigation'
    except Exception as error:
        result['failure_stage'] = stage
        kind = type(error).__name__
        result['failure_kind'] = kind if kind in ('ProbeError', 'OSError', 'AttributeError', 'ValueError', 'AssertionError', 'TimeoutExpired') else 'Exception'
    data = json.dumps(result, sort_keys=True).encode()
    require(len(data) <= 8192)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(base + '/receipt', data=data, headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=5) as response:
        require(response.status == 200 and response.read(128) == b'GB_OWNED_GLES_RECEIVED\n')
    print('GB_OWNED_GLES_RECEIPT_SENT', flush=True)
    return 0 if result['status'] == 'shader_completed' else 2
if __name__ == '__main__':
    sys.exit(main())
