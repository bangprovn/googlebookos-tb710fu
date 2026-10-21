"""Bounded one-shot owned fixture relay. Importing this module has no side effects."""
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib, ipaddress, json, os, re, signal, stat, subprocess, sys, time, socket, threading

def require(condition):
    if not condition:
        raise ValueError('handoff contract refused')

def unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError('duplicate field')
        d[k] = v
    return d

def integer(v, lo, hi):
    return type(v) is int and lo <= v <= hi

def sha(v):
    return type(v) is str and re.fullmatch('[0-9a-f]{64}', v) is not None

def receipt(value, nonce, boot, digest):
    keys = set('schema_version run_nonce payload_sha256 guest_boot_id uid architecture kernel memtotal_kib graphics inventory status failure_stage failure_kind firmware_written configuration_changed full_port_verified'.split())
    if type(value) is not dict or set(value) != keys:
        raise ValueError('receipt fields')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['run_nonce'] != nonce or (value['guest_boot_id'] != boot) or (value['payload_sha256'] != digest):
        raise ValueError('receipt context')
    if not integer(value['uid'], 0, 65535) or value['architecture'] != 'aarch64' or (not integer(value['memtotal_kib'], 1, 67108864)) or (type(value['kernel']) is not str) or (re.fullmatch('[0-9][A-Za-z0-9_.+-]{0,79}', value['kernel']) is None):
        raise ValueError('guest scalars')
    if any((value[k] is not False for k in ['firmware_written', 'configuration_changed', 'full_port_verified'])):
        raise ValueError('scope')
    if value['status'] not in ['unknown', 'shader_completed', 'shader_path_requires_investigation'] or value['failure_stage'] not in [None, 'context', 'inventory', 'gles_probe', 'profile_recheck'] or value['failure_kind'] not in [None, 'ProbeError', 'OSError', 'AttributeError', 'ValueError', 'AssertionError', 'TimeoutExpired', 'Exception']:
        raise ValueError('failure enums')
    g = value['graphics']
    if g is not None:
        fields = set('state scope gl egl_version frames_verified pixels_per_frame max_channel_error renderer_reports_software physical_gpu_acceleration_verified android_scanout_verified guest_desktop_verified fixture_artifact_files_written mesa_shader_cache_disabled'.split())
        if type(g) is not dict or set(g) != fields or g['state'] != 'compatible' or (g['scope'] != 'GLES2 surfaceless shader draw and RGBA8 readback only') or (g['egl_version'] != '1.5'):
            raise ValueError('shader fields')
        if type(g['gl']) is not dict or set(g['gl']) != {'renderer', 'vendor', 'version'} or (not all((type(s) is str and 0 < len(s) <= 256 and (not any((ord(c) < 32 or ord(c) == 127 for c in s))) for s in g['gl'].values()))):
            raise ValueError('GL metadata')
        if not integer(g['frames_verified'], 16, 16) or not integer(g['pixels_per_frame'], 256, 256) or (not integer(g['max_channel_error'], 0, 2)) or (type(g['renderer_reports_software']) is not bool):
            raise ValueError('shader values')
        if any((g[k] is not False for k in ['physical_gpu_acceleration_verified', 'android_scanout_verified', 'guest_desktop_verified', 'fixture_artifact_files_written'])) or g['mesa_shader_cache_disabled'] is not True:
            raise ValueError('shader scope')
    v = value['inventory']
    if v is not None:
        keys = set('weston_state weston_main_pid wayland_peer_matches managed_driver_sha256 managed_icd_selected copy_wsi_default command_pool_1m gl_override software_environment profiles_before profiles_after profiles_unchanged'.split())
        if type(v) is not dict or set(v) != keys or v['weston_state'] not in ['active', 'inactive', 'failed', 'unknown'] or (v['gl_override'] not in ['unset', 'zink', 'other']):
            raise ValueError('inventory fields')
        if v['weston_main_pid'] is not None and (not integer(v['weston_main_pid'], 2, 4194304)):
            raise ValueError('compositor PID')
        if v['managed_driver_sha256'] is not None and (not sha(v['managed_driver_sha256'])):
            raise ValueError('driver hash')
        for k in ['wayland_peer_matches', 'profiles_unchanged']:
            if v[k] is not None and type(v[k]) is not bool:
                raise ValueError('optional flags')
        for k in ['managed_icd_selected', 'copy_wsi_default', 'command_pool_1m', 'software_environment']:
            if type(v[k]) is not bool:
                raise ValueError('flags')
        for k in ['profiles_before', 'profiles_after']:
            if v[k] is not None and (type(v[k]) is not list or len(v[k]) != 2 or any((x is not None and (not sha(x)) for x in v[k]))):
                raise ValueError('profile hashes')
    if value['status'] == 'shader_completed' and (g is None or v is None or value['failure_stage'] is not None or (value['failure_kind'] is not None)):
        raise ValueError('inconsistent completion')
    return value

class Relay(HTTPServer):

    def __init__(self, address, peer, nonce, boot, payload, guard, publish, connection_seconds=4):
        require(0 < connection_seconds <= 4)
        self.connection_seconds=connection_seconds
        self.watchdogs={}
        self.peer, self.nonce, self.boot, self.payload, self.guard, self.publish = (peer, nonce, boot, payload, guard, publish)
        self.digest = hashlib.sha256(payload).hexdigest()
        self.served = False
        self.accepted = False
        self.refusals = 0
        self.guard_failures = 0
        super().__init__(address, Handler)
        self.timeout = 0.2

    def get_request(self):
        s, a = super().get_request()
        s.settimeout(self.connection_seconds)
        def expire():
            try:s.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        timer=threading.Timer(self.connection_seconds,expire);timer.daemon=True
        self.watchdogs[s.fileno()]=timer;timer.start()
        return (s, a)

    def shutdown_request(self,request):
        timer=self.watchdogs.pop(request.fileno(),None)
        if timer is not None:timer.cancel()
        super().shutdown_request(request)

    def handle_error(self, *args):
        self.refusals += 1

class Handler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def route(self):
        s = self.server
        if self.client_address[0] != s.peer or len(self.path) > 128:
            return None
        if self.path == '/' + s.nonce + '/runner.py':
            return 'runner'
        if self.path == '/' + s.nonce + '/receipt':
            return 'receipt'
        return None

    def reply(self, code, data=b''):
        self.send_response(code)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def guarded(self):
        try:
            self.server.guard()
            return True
        except Exception:
            self.server.guard_failures += 1
            self.reply(503)
            return False

    def do_GET(self):
        s = self.server
        if self.route() != 'runner':
            s.refusals += 1
            self.reply(404)
            return
        if s.served:
            self.reply(409)
            return
        if not self.guarded():
            return
        s.served = True
        self.reply(200, s.payload)

    def do_POST(self):
        s = self.server
        if self.route() != 'receipt':
            s.refusals += 1
            self.reply(404)
            return
        if s.accepted:
            self.reply(409)
            return
        try:
            n = self.headers.get('Content-Length', '')
            require(re.fullmatch('[0-9]{1,5}', n) and 1 <= int(n) <= 8192 and (self.headers.get('Transfer-Encoding') is None) and s.served)
            data = self.rfile.read(int(n))
            require(len(data) == int(n))
            value = receipt(json.loads(data, object_pairs_hook=unique), s.nonce, s.boot, s.digest)
        except Exception:
            s.refusals += 1
            self.reply(400)
            return
        if not self.guarded():
            return
        s.publish(value)
        s.accepted = True
        self.reply(200, b'GB_OWNED_GLES_RECEIVED\n')

def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())

def main():
    os.umask(63)
    require(len(sys.argv) == 2)
    config = Path(sys.argv[1])
    b = config.parent
    c = json.loads(config.read_text(), object_pairs_hook=unique)
    require(set(c) == {'host', 'expected_peer', 'run_nonce', 'guest_boot_id', 'payload', 'target', 'lifetime_seconds', 'port'})
    require(ipaddress.IPv4Address(c['host']).is_private and ipaddress.IPv4Address(c['expected_peer']).is_private)
    require(integer(c['port'], 1024, 65535))
    require(re.fullmatch('[0-9a-f]{32}', c['run_nonce']) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', c['guest_boot_id']) and integer(c['lifetime_seconds'], 30, 180))
    p = c['payload']
    path = Path(p['path'])
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and 1 <= meta.st_size <= 65536 and (meta.st_size == p['bytes']))
    payload = path.read_bytes()
    require(hashlib.sha256(payload).hexdigest() == p['sha256'])
    t = c['target']
    require(integer(t['android_user'], 0, 1000))
    adb = Path(t['adb']['path'])
    require(hashlib.sha256(adb.read_bytes()).hexdigest() == t['adb']['sha256'])
    for k in ['main_pid', 'main_start_ticks', 'native_pid', 'native_start_ticks', 'uid']:
        require(integer(t[k], 1, 2 ** 63 - 1))
    require(re.fullmatch('[A-Za-z0-9]{1,64}', t['serial']) and re.fullmatch('[0-9a-f-]{36}', t['android_boot_id']))

    def guard():
        require(Path(t['usb_serial_path']).read_text().strip() == t['serial'])
        command = 'cat /proc/sys/kernel/random/boot_id;id -u;getenforce;am get-current-user'
        expected = [t['android_boot_id'], '2000', 'Enforcing', str(t['android_user'])]
        for pid, birth in [(t['main_pid'], t['main_start_ticks']), (t['native_pid'], t['native_start_ticks'])]:
            command += ";awk '{print $22}' /proc/%d/stat;awk '/^Uid:/{print $2}' /proc/%d/status" % (pid, pid)
            expected.extend([str(birth), str(t['uid'])])
        r = subprocess.run([str(adb), '-s', t['serial'], 'shell', command], capture_output=True, text=True, timeout=8)
        require(r.returncode == 0 and len(r.stdout) < 1024 and (r.stdout.splitlines() == expected))
    guard()
    save(b / 'server-attempt.json', dict(schema_version=1, attempted=True, payload_sha256=p['sha256'], raw_requests_saved=False))
    server = Relay((c['host'], c['port']), c['expected_peer'], c['run_nonce'], c['guest_boot_id'], payload, guard, lambda v: save(b / 'receipt.json', v))
    port = server.server_address[1]
    require(port >= 1024)
    save(b / 'link.json', dict(base_url='http://' + c['host'] + ':' + str(port) + '/' + c['run_nonce'], port=port, payload_sha256=p['sha256'], payload_bytes=len(payload)))
    print('{"schema_version":1,"relay_listening":true}', flush=True)

    def stop(*args):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stop)
    deadline = time.monotonic() + c['lifetime_seconds']
    try:
        while time.monotonic() < deadline and (not server.accepted) and (not (b / 'stop-server').exists()):
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        save(b / 'server-cleanup.json', dict(schema_version=1, server_stopped=True, payload_request_consumed=server.served, receipt_accepted=server.accepted, refused_requests=server.refusals, context_guard_failures=server.guard_failures))
if __name__ == '__main__':
    main()
