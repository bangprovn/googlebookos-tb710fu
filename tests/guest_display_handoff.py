#!/usr/bin/env python3
"""Host-only protocol/lifecycle tests. No Android, firmware ELF or device execution."""
from pathlib import Path
import copy
import hashlib
import http.client
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
CONTEXT=dict(guest_boot_id='12345678-1234-1234-1234-123456789abc',uid=1000,compositor_pid=398,
             driver_sha256='a'*64,profiles_sha256=['b'*64,'c'*64],program_sha256='d'*64,program_bytes=397808)
AGENT_SHA='e'*64
NONCE='f'*32
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
relay=load(ROOT/'crates/gb-tools/src/guest_display/relay.py','display_relay')
base=load(ROOT/'crates/gb-tools/src/guest_handoff/relay.py','display_base')
agent=types.ModuleType('display_agent')
source=(ROOT/'crates/gb-tools/src/guest_display/agent.py').read_text().replace('__CONTEXT_HEX__',json.dumps(CONTEXT).encode().hex())
exec(compile(source,'<owned-display-agent>','exec'),agent.__dict__)

def config():
    return dict(run_nonce=NONCE,guest_boot_id=CONTEXT['guest_boot_id'],compositor_pid=398,
        driver_sha256=CONTEXT['driver_sha256'],profiles_sha256=CONTEXT['profiles_sha256'],
        agent=dict(sha256=AGENT_SHA),program=dict(sha256=CONTEXT['program_sha256']),
        target=dict(android_boot_id='22345678-1234-1234-1234-123456789abc',android_user=11,uid=1110248,
            main_pid=7959,main_start_ticks=18016,native_pid=12203,native_start_ticks=55514))

def markers():
    return [dict(schema_version=1,phase=0,width=640,height=480,border_pixels=8,fullscreen_requested=True,presentation_verified=False),
            dict(schema_version=1,fullscreen=True,raw_max_width=1280,raw_max_height=720,buffer_width=640,buffer_height=480,presentation_verified=False),
            dict(schema_version=1,phase=0,frame=1,width=640,height=480,queue_present_result=0,presentation_verified=False)]

def line(kind,value):
    return 'GB_VULKAN_PATTERN_'+kind+':'+json.dumps(value,separators=(',',':'))

def prepared():
    return dict(agent.common(NONCE,AGENT_SHA),kind='prepared',status='worker_prepared',compositor_pid=398,
                worker_pid=123,worker_start_ticks=456,profiles_sha256=CONTEXT['profiles_sha256'],
                driver_sha256=CONTEXT['driver_sha256'],profile_environment_checked=True,graphics_qualified=False)

class ProtocolTests(unittest.TestCase):
    def test_strict_marker_semantics_and_order(self):
        initial=dict(start=None,configure=None,present=None,configure_count=0,present_count=0,last_frame=0)
        state=copy.deepcopy(initial)
        for kind,value in zip(('START','CONFIGURE','PRESENT'),markers()):agent.marker(line(kind,value),state)
        self.assertEqual(state['present_count'],1)
        self.assertFalse(state['present']['presentation_verified'])
        for kind,index,key,value in [('START',0,'phase',False),('START',0,'fullscreen_requested',False),
            ('CONFIGURE',1,'raw_max_width',3201),('CONFIGURE',1,'buffer_width',1280),
            ('PRESENT',2,'queue_present_result',1),('PRESENT',2,'presentation_verified',True),
            ('PRESENT',2,'frame',2)]:
            with self.subTest(kind=kind,key=key):
                changed=markers()[index];changed[key]=value
                with self.assertRaises(agent.Refused):agent.marker(line(kind,changed),copy.deepcopy(state if kind=='PRESENT' else initial))
        with self.assertRaises(agent.Refused):agent.marker(line('PRESENT',markers()[2]),copy.deepcopy(initial))
        with self.assertRaises(agent.Refused):agent.marker(line('PRESENT',markers()[2]),state)

    def test_receipt_whitelist_and_no_identity_or_pixel_fields(self):
        good=prepared();self.assertEqual(relay.receipt(good,'prepared',config()),good)
        for key,value in [('private_serial','secret'),('graphics_qualified',True),('uid',True),
                          ('worker_start_ticks',False),('profile_environment_checked',False)]:
            changed=copy.deepcopy(good);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):relay.receipt(changed,'prepared',config())
        s,c,p=markers();v=dict(agent.common(NONCE,AGENT_SHA),kind='started',status='queue_present_api_witness',
                              compositor_pid=398,start=s,configure=c,present=p,child_alive=True,graphics_qualified=False)
        relay.receipt(v,'started',config());v['present']['presentation_verified']=True
        with self.assertRaises(ValueError):relay.receipt(v,'started',config())

    def test_controls_require_full_android_and_guest_binding(self):
        c=config();value=dict(relay.binding(c),kind='done',**c['target'],capture_sha256='1'*64)
        self.assertEqual(relay.control(value,'done',c)['capture_sha256'],'1'*64)
        for key,v in [('main_pid',7960),('native_start_ticks',55515),('schema_version',True),('capture_sha256','secret')]:
            changed=dict(value);changed[key]=v
            with self.subTest(key=key),self.assertRaises(ValueError):relay.control(changed,'done',c)
        self.assertNotIn('main_pid',relay.control(value,'done',c))

    def test_regular_file_refuses_symlink_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'f').write_bytes(b'x');(d/'link').symlink_to('f');os.mkfifo(d/'fifo')
            self.assertEqual(agent.regular(d/'f',1),b'x')
            for path in (d/'link',d/'fifo'):
                with self.assertRaises((OSError,agent.Refused)):agent.regular(path,16)
            with self.assertRaises(agent.Refused):agent.regular(d/'f',0)

    def test_stop_child_reaps_owned_host_process(self):
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'],stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.assertTrue(agent.stop_child(child));self.assertIsNotNone(child.returncode)

    def test_parent_death_and_no_new_native_session_contract(self):
        import ast
        tree=ast.parse(source)
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
               and isinstance(node.func,ast.Attribute) and node.func.attr=='Popen']
        native=[node for node in calls if any(k.arg=='preexec_fn' for k in node.keywords)]
        self.assertEqual(len(native),1)
        self.assertFalse(any(k.arg=='start_new_session' for k in native[0].keywords))
        with patch.object(agent.ctypes,'CDLL') as library,patch.object(agent.os,'getppid',return_value=456):
            library.return_value.prctl.return_value=0;agent.child_parent_death(456)
            library.return_value.prctl.assert_called_once_with(1,signal.SIGKILL,0,0,0)

    def test_worker_happy_and_failed_capture_cleanup(self):
        for mode in ('success','child_exited','post_failure','signal_cancel','child_alarm'):
            with self.subTest(mode=mode):
                directory=Path(tempfile.mkdtemp(prefix='gb-display-'+NONCE+'-',dir='/tmp'))
                (directory/'worker.py').write_text('owned test placeholder');(directory/'program').write_bytes(b'owned-not-executable')
                records=[]
                class Child:
                    pid=os.getpid();returncode=None
                    def __init__(self):
                        self.stdout=self.pipe(('\n'.join(line(k,v) for k,v in zip(('START','CONFIGURE','PRESENT'),markers()))+'\n').encode())
                        self.stderr=self.pipe(b'')
                    def pipe(self,data):
                        r,w=os.pipe();os.write(w,data);os.close(w);return os.fdopen(r,'rb',buffering=0)
                    def poll(self):
                        return 1 if mode=='child_exited' else self.returncode
                    def terminate(self):self.returncode=-15
                    def kill(self):self.returncode=-9
                    def wait(self,timeout):
                        if self.returncode is None:self.returncode=1
                        return self.returncode
                child=Child()
                def digest(path,limit):
                    if path in agent.PROFILES:return CONTEXT['profiles_sha256'][agent.PROFILES.index(path)]
                    return CONTEXT['program_sha256'] if Path(path).name=='program' else AGENT_SHA
                def post(base_url,kind,value):
                    records.append((kind,copy.deepcopy(value)))
                    if kind=='result' and mode=='post_failure':raise OSError('not exported')
                def control(base_url,kind,binding):
                    if mode=='signal_cancel':raise agent.Refused('cancelled')
                    if mode=='child_alarm' and kind=='done':signal.raise_signal(signal.SIGALRM)
                    return dict(binding,kind=kind,**({'capture_sha256':'1'*64} if kind=='done' else {}))
                old_handlers={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
                try:
                    with patch.object(agent,'__file__',str(directory/'worker.py'),create=True),patch.object(agent,'digest',side_effect=digest),\
                         patch.object(agent,'inspect_context',return_value='wayland-0'),patch.object(agent,'birth',return_value=1),\
                         patch.object(agent,'post',side_effect=post),patch.object(agent,'control',side_effect=control),\
                         patch.object(agent.subprocess,'Popen',return_value=child):
                        rc=agent.worker('http://10.1.2.3:18900/'+NONCE,NONCE,AGENT_SHA)
                finally:
                    signal.alarm(0)
                    for s,h in old_handlers.items():signal.signal(s,h)
                self.assertFalse(directory.exists())
                if mode=='signal_cancel':
                    child.stdout.close();child.stderr.close()
                else:self.assertIsNotNone(child.returncode)
                final=records[-1][1];self.assertTrue(final['child_reaped']);self.assertTrue(final['files_removed'])
                self.assertFalse(final['graphics_qualified'])
                self.assertEqual(rc,0 if mode=='success' else 2)
                self.assertEqual(final['status'],'capture_acknowledged' if mode in ('success','post_failure') else 'failed')
                if mode=='child_alarm':self.assertEqual(final['failure_kind'],'child_timeout')

    def test_bootstrap_bad_prepared_flag_kills_reaps_and_removes_namespace(self):
        source_path=Path(tempfile.mktemp(prefix='gb-gfx-'+NONCE+'.',dir='/tmp'))
        source_path.write_bytes(b'owned bootstrap test');source_path.chmod(0o600)
        elf=bytearray(64);elf[:6]=b'\x7fELF\x02\x01';elf[18:20]=(183).to_bytes(2,'little')
        directory=[]
        class Supervisor:
            pid=987654;returncode=None
            def poll(self):return None
            def wait(self,timeout):self.returncode=-15;return -15
        supervisor=Supervisor()
        def popen(command,**kwargs):
            own=Path(command[8]).parent;directory.append(own)
            (own/'prepared.json').write_text('{"wrong":"flag"}')
            return supervisor
        try:
            with patch.object(agent,'__file__',str(source_path),create=True),patch.object(agent,'digest',return_value=AGENT_SHA),\
                 patch.object(agent,'inspect_context',return_value='wayland-0'),patch.object(agent,'rpc',return_value=(200,bytes(elf))),\
                 patch.dict(agent.CONTEXT,program_bytes=64,program_sha256=hashlib.sha256(elf).hexdigest()),\
                 patch.object(agent.subprocess,'Popen',side_effect=popen),patch.object(agent.os,'killpg') as kill:
                with self.assertRaises(agent.Refused):agent.bootstrap('http://10.1.2.3:18900/'+NONCE,NONCE,AGENT_SHA)
                kill.assert_called_once_with(supervisor.pid,signal.SIGTERM)
            self.assertIsNotNone(supervisor.returncode);self.assertTrue(directory);self.assertFalse(directory[0].exists())
        finally:source_path.unlink()

class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);self.guards=0
        def guard():self.guards+=1
        self.server=base.Relay(('127.0.0.1',0),'127.0.0.1',NONCE,CONTEXT['guest_boot_id'],b'owned agent',guard,None,connection_seconds=.25)
        self.server.RequestHandlerClass=relay.handler(base);self.server.program=b'owned ELF';self.server.directory=self.directory
        self.server.config=config();self.server.consumed=set();self.server.receipts=set()
    def tearDown(self):
        self.server.server_close()
        for timer in self.server.watchdogs.values():timer.cancel()
        self.tmp.cleanup()
    def request(self,method,route,data=None):
        thread=threading.Thread(target=self.server.handle_request);thread.start()
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=2)
        body=json.dumps(data).encode() if isinstance(data,dict) else data
        connection.request(method,'/'+NONCE+'/'+route,body,{'Content-Type':'application/json'} if body is not None else {})
        response=connection.getresponse();result=(response.status,response.read());connection.close();thread.join(2)
        self.assertFalse(thread.is_alive());return result
    def test_one_shot_assets_and_prepared_receipt(self):
        self.assertEqual(self.request('POST','prepared',prepared())[0],400)
        self.assertEqual(self.request('GET','runner.py'),(200,b'owned agent'))
        self.assertEqual(self.request('GET','runner.py')[0],409)
        self.assertEqual(self.request('GET','program'),(200,b'owned ELF'))
        self.assertEqual(self.request('POST','prepared',prepared()),(200,b'GB_DISPLAY_ACCEPTED\n'))
        self.assertEqual(self.request('POST','prepared',prepared())[0],409)
        self.assertEqual(json.loads((self.directory/'prepared.json').read_text()),prepared())
        self.assertEqual(self.guards,3)
        self.assertEqual(self.request('GET','ready')[0],204)
        value=dict(relay.binding(config()),kind='ready',**config()['target'])
        (self.directory/'ready.json').write_text(json.dumps(value))
        self.assertEqual(self.request('GET','ready')[0],200)
        self.assertEqual(self.request('GET','ready')[0],409)
    def test_duplicate_json_unknown_receipt_refused_before_guard(self):
        before=self.guards
        self.assertEqual(self.request('POST','prepared',b'{"schema_version":1,"schema_version":1}')[0],400)
        value=prepared();value['private_text']='never saved'
        self.assertEqual(self.request('POST','prepared',value)[0],400);self.assertEqual(self.guards,before)
        self.assertEqual(list(self.directory.iterdir()),[])
    def test_connection_watchdog_bounds_incomplete_request(self):
        thread=threading.Thread(target=self.server.handle_request);thread.start()
        with socket.create_connection(('127.0.0.1',self.server.server_port),timeout=1) as sock:
            sock.sendall(b'GET / HTTP/1.1\r\n');thread.join(1)
        self.assertFalse(thread.is_alive());self.assertEqual(self.guards,0)

if __name__=='__main__':unittest.main()
