"""One-agent/one-ELF relay; strict scalar receipts, explicit root-written controls."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time

BASE_SHA = '06b063623e4dfee80a8d4fdd6bc5bd9baba387a6b2e3ea975f177c8cf2438d09'
COMMON = {'schema_version', 'run_nonce', 'guest_boot_id', 'agent_sha256', 'program_sha256', 'uid'}

def require(ok):
    if not ok:
        raise ValueError('display relay refused')

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value

def integer(value, low, high):
    return type(value) is int and low <= value <= high

def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None

def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= limit)
        data = stream.read(limit+1)
        require(len(data) == meta.st_size)
        return data

def pinned(pin, maximum):
    require(type(pin) is dict and set(pin) == {'path', 'sha256', 'bytes'} and sha(pin['sha256'])
            and integer(pin['bytes'], 1, maximum))
    data = regular(Path(pin['path']), maximum)
    require(len(data) == pin['bytes'] and hashlib.sha256(data).hexdigest() == pin['sha256'])
    return data

def binding(config):
    return dict(schema_version=1, run_nonce=config['run_nonce'], guest_boot_id=config['guest_boot_id'],
                agent_sha256=config['agent']['sha256'], program_sha256=config['program']['sha256'])

def receipt(value, kind, config):
    require(type(value) is dict and all(value.get(k) == v for k,v in binding(config).items())
            and type(value.get('schema_version')) is int and value.get('kind') == kind
            and integer(value.get('uid'), 1000, 1000) and value.get('graphics_qualified') is False)
    if kind == 'prepared':
        require(set(value) == COMMON | {'kind', 'status', 'compositor_pid', 'worker_pid', 'worker_start_ticks',
                'profiles_sha256', 'driver_sha256', 'profile_environment_checked', 'graphics_qualified'}
                and value['status'] == 'worker_prepared' and integer(value['compositor_pid'], config['compositor_pid'], config['compositor_pid'])
                and integer(value['worker_pid'], 2, 4194304) and integer(value['worker_start_ticks'], 1, 2**63-1)
                and value['profiles_sha256'] == config['profiles_sha256'] and value['driver_sha256'] == config['driver_sha256']
                and value['profile_environment_checked'] is True)
    elif kind == 'started':
        require(set(value) == COMMON | {'kind','status','compositor_pid','start','configure','present','child_alive','graphics_qualified'}
                and value['status'] == 'queue_present_api_witness' and value['child_alive'] is True
                and integer(value['compositor_pid'], config['compositor_pid'], config['compositor_pid']))
        # Same immutable API-witness schema as the guest parser; these are not pixel/scanout claims.
        s,c,p = value['start'],value['configure'],value['present']
        require(type(s) is dict and s == dict(schema_version=1,phase=0,width=640,height=480,border_pixels=8,fullscreen_requested=True,presentation_verified=False)
                and all(type(s[k]) is int for k in ('schema_version','phase','width','height','border_pixels')))
        require(type(c) is dict and set(c) == {'schema_version','fullscreen','raw_max_width','raw_max_height','buffer_width','buffer_height','presentation_verified'}
                and integer(c['schema_version'],1,1) and c['fullscreen'] is True and c['presentation_verified'] is False
                and integer(c['raw_max_width'],640,3200) and integer(c['raw_max_height'],480,2000)
                and integer(c['buffer_width'],640,640) and integer(c['buffer_height'],480,480))
        require(type(p) is dict and set(p) == {'schema_version','phase','frame','width','height','queue_present_result','presentation_verified'}
                and integer(p['schema_version'],1,1) and integer(p['phase'],0,0) and integer(p['frame'],1,3600)
                and p['frame'] in (1,120,600,1200,1800,2400,3600) and integer(p['width'],640,640)
                and integer(p['height'],480,480) and integer(p['queue_present_result'],0,0) and p['presentation_verified'] is False)
    else:
        require(kind == 'result' and set(value) == COMMON | {'kind','status','failure_stage','failure_kind','capture_sha256',
                'child_started','child_reaped','child_exit_code','child_same_owned_group','profiles_retained','compositor_retained',
                'driver_retained','files_removed','stdout_bytes','stderr_bytes','present_count','graphics_qualified'})
        require(value['status'] in ('capture_acknowledged','failed')
                and value['failure_stage'] in (None,'context','prepared','wait_ready','program','cleanup')
                and value['failure_kind'] in (None,'contract_refused','regular_file_budget','file_changed','redirect_refused',
                    'http_body_budget','receipt_budget','receipt_not_acknowledged','guest_identity','guest_boot','driver_hash','profile_hash',
                    'profile_environment','unexpected_transport_mode','compositor_query','compositor_identity','compositor_socket',
                    'cleanup_namespace','cleanup_directory','unexpected_owned_file','parent_death_signal','marker_schema','start_marker',
                    'configure_marker','present_marker','marker_order','empty_control','done_fields','capture_digest','control_status',
                    'control_context','cancelled','worker_namespace','worker_hash','program_hash','ready_timeout','context_changed',
                    'child_group','child_exited_before_capture','stdio_budget','line_budget','child_exited_during_started_ack',
                    'child_exited_before_ack','child_exited_during_ack','child_timeout','operation_failed','cleanup_incomplete'))
        for name in ('child_started','child_reaped','child_same_owned_group','profiles_retained','compositor_retained','driver_retained','files_removed'):
            require(type(value[name]) is bool)
        require(value['child_exit_code'] is None or integer(value['child_exit_code'],-128,255))
        require(integer(value['stdout_bytes'],0,8192) and integer(value['stderr_bytes'],0,4096) and integer(value['present_count'],0,7))
        require(value['capture_sha256'] is None or sha(value['capture_sha256']))
        if value['status'] == 'capture_acknowledged':
            require(value['failure_stage'] is None and value['failure_kind'] is None and sha(value['capture_sha256'])
                    and all(value[name] is True for name in ('child_started','child_reaped','child_same_owned_group',
                        'profiles_retained','compositor_retained','driver_retained','files_removed')) and value['present_count'] >= 1)
    return value

def control(value, kind, config):
    expected = dict(binding(config), kind=kind, **{k:config['target'][k] for k in ('android_boot_id','android_user','uid',
                       'main_pid','main_start_ticks','native_pid','native_start_ticks')})
    if kind == 'done':
        require(type(value) is dict and sha(value.get('capture_sha256')))
        expected['capture_sha256'] = value['capture_sha256']
    require(type(value) is dict and value == expected
            and all(type(value[k]) is int for k in ('schema_version','android_user','uid','main_pid','main_start_ticks','native_pid','native_start_ticks')))
    result = dict(binding(config), kind=kind)
    if kind == 'done':
        result['capture_sha256'] = value['capture_sha256']
    return result

def handler(base):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass
        def reply(self,code,data=b''):
            self.send_response(code);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def route(self):
            s=self.server
            if self.client_address[0] != s.peer or len(self.path)>128:
                return None
            prefix='/'+s.nonce+'/'
            if not self.path.startswith(prefix):
                return None
            suffix=self.path[len(prefix):]
            return suffix if suffix in ('runner.py','program','ready','done','prepared','started','result') else None
        def guarded(self):
            try:self.server.guard();return True
            except Exception:self.server.guard_failures+=1;self.reply(503);return False
        def do_GET(self):
            s=self.server;route=self.route()
            if route not in ('runner.py','program','ready','done'):
                s.refusals+=1;self.reply(404);return
            if route in s.consumed:
                self.reply(409);return
            if route in ('ready','done'):
                if 'prepared' not in s.receipts or route=='done' and 'started' not in s.receipts:
                    self.reply(409);return
                try:value=json.loads(regular(s.directory/(route+'.json'),2048),object_pairs_hook=unique)
                except FileNotFoundError:self.reply(204);return
                except Exception:s.refusals+=1;self.reply(400);return
                try:data=json.dumps(control(value,route,s.config),separators=(',',':')).encode()
                except Exception:s.refusals+=1;self.reply(400);return
            else:data=s.payload if route=='runner.py' else s.program
            if not self.guarded():return
            s.consumed.add(route);self.reply(200,data)
        def do_POST(self):
            s=self.server;route=self.route()
            if route not in ('prepared','started','result'):
                s.refusals+=1;self.reply(404);return
            if route in s.receipts:
                self.reply(409);return
            try:
                require(self.headers.get('Transfer-Encoding') is None and len(self.headers.get_all('Content-Length',[]))==1)
                length=self.headers.get('Content-Length','');require(re.fullmatch('[0-9]{1,4}',length) and 1<=int(length)<=4096)
                raw=self.rfile.read(int(length));require(len(raw)==int(length))
                value=receipt(json.loads(raw,object_pairs_hook=unique),route,s.config)
                require({'runner.py','program'}<=s.consumed)
                require(route=='prepared' or 'prepared' in s.receipts)
                require(route!='started' or 'ready' in s.consumed)
                require(value.get('status')!='capture_acknowledged' or 'done' in s.consumed and 'started' in s.receipts)
            except Exception:s.refusals+=1;self.reply(400);return
            if not self.guarded():return
            base.save(s.directory/('prepared.json' if route=='prepared' else 'receipt-'+route+'.json'),value)
            s.receipts.add(route);self.reply(200,b'GB_DISPLAY_ACCEPTED\n')
    return Handler

def root_guard(target):
    adb=Path(target['adb']['path'])
    def guard():
        require(Path(target['usb_serial_path']).read_text().strip()==target['serial'])
        command='cat /proc/sys/kernel/random/boot_id;id -u;getenforce;am get-current-user'
        expected=[target['android_boot_id'],'2000','Enforcing',str(target['android_user'])]
        for pid,born in ((target['main_pid'],target['main_start_ticks']),(target['native_pid'],target['native_start_ticks'])):
            command+=";awk '{s=$0;sub(/^.*\\) /,\"\",s);n=split(s,a,\" \");if(n>=20)print a[20];else exit 2}' /proc/%d/stat;awk '/^Uid:/{print $2}' /proc/%d/status"%(pid,pid)
            expected.extend([str(born),str(target['uid'])])
        r=subprocess.run([str(adb),'-s',target['serial'],'shell',command],capture_output=True,text=True,timeout=2)
        require(r.returncode==0 and len(r.stdout)<1024 and not r.stderr and r.stdout.splitlines()==expected)
    return guard

def main():
    os.umask(0o077)
    require(len(sys.argv)==2)
    path=Path(sys.argv[1]);c=json.loads(regular(path,16384),object_pairs_hook=unique);directory=path.parent
    require(set(c)=={'host','expected_peer','port','run_nonce','guest_boot_id','compositor_pid','driver_sha256',
                     'profiles_sha256','agent','program','base_relay','target','lifetime_seconds'})
    networks=tuple(ipaddress.IPv4Network(v) for v in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
    require(all(any(ipaddress.IPv4Address(c[k]) in n for n in networks) for k in ('host','expected_peer')))
    require(integer(c['port'],1024,65535) and re.fullmatch('[0-9a-f]{32}',c['run_nonce'])
            and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',c['guest_boot_id'])
            and integer(c['compositor_pid'],2,4194304) and sha(c['driver_sha256'])
            and type(c['profiles_sha256']) is list and len(c['profiles_sha256'])==2
            and all(sha(v) for v in c['profiles_sha256']) and integer(c['lifetime_seconds'],30,180))
    agent=pinned(c['agent'],65536);program=pinned(c['program'],1048576)
    base_source=pinned(c['base_relay'],32768);require(c['base_relay']['sha256']==BASE_SHA)
    spec=importlib.util.spec_from_loader('owned_display_relay_base',loader=None);base=importlib.util.module_from_spec(spec)
    exec(compile(base_source,'<pinned-owned-relay>','exec'),base.__dict__)
    t=c['target'];require(type(t) is dict and set(t)=={'adb','serial','usb_serial_path','android_boot_id','android_user','uid',
                                                    'main_pid','main_start_ticks','native_pid','native_start_ticks'})
    pinned(t['adb'],33554432)
    require(re.fullmatch('[A-Za-z0-9]{1,64}',t['serial']) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',t['android_boot_id'])
            and integer(t['android_user'],0,32) and integer(t['uid'],10000,3299999)
            and t['uid']//100000==t['android_user']
            and type(t['usb_serial_path']) is str and t['usb_serial_path'].startswith('/sys/bus/usb/devices/')
            and t['usb_serial_path'].endswith('/serial'))
    for name in ('main_pid','native_pid'):require(integer(t[name],2,4194304))
    for name in ('main_start_ticks','native_start_ticks'):require(integer(t[name],1,2**63-1))
    guard=root_guard(t);guard()
    require(not any((directory/n).exists() for n in ('server-attempt.json','ready.json','done.json','prepared.json','receipt-prepared.json','receipt-started.json','receipt-result.json')))
    base.save(directory/'server-attempt.json',dict(schema_version=1,attempted=True,raw_requests_saved=False))
    server=base.Relay((c['host'],c['port']),c['expected_peer'],c['run_nonce'],c['guest_boot_id'],agent,guard,None)
    server.RequestHandlerClass=handler(base);server.program=program;server.directory=directory;server.config=c
    server.consumed=set();server.receipts=set()
    def stop(*args):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    deadline=time.monotonic()+c['lifetime_seconds']
    try:
        base.save(directory/'link.json',dict(base_url='http://'+c['host']+':'+str(c['port'])+'/'+c['run_nonce'],
                                           agent_sha256=c['agent']['sha256'],agent_bytes=len(agent),prepared_proves_graphics=False))
        print('{"relay_listening":true,"schema_version":1}',flush=True)
        while time.monotonic()<deadline and 'result' not in server.receipts:
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        for timer in server.watchdogs.values():timer.cancel()
        base.save(directory/'server-cleanup.json',dict(schema_version=1,server_stopped=True,
            consumed=sorted(server.consumed),receipts=sorted(server.receipts),refused_requests=server.refusals,
            context_guard_failures=server.guard_failures,raw_requests_saved=False))

if __name__=='__main__':
    main()
