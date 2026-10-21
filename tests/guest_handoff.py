#!/usr/bin/env python3
"""Owned bootstrap fakes and loopback HTTP parser tests; no ADB/external network."""
from pathlib import Path
import hashlib,importlib.util,json,os,subprocess,tempfile,threading,time,socket,unittest,urllib.request,urllib.error
ROOT=Path(__file__).resolve().parents[1];TOOL=ROOT/'target/debug/examples/guest_handoff'
BOOT='00000000-0000-4000-8000-000000000003';ROUTE='a'*32;OBSERVER='b'*32;DATA=b'owned test source only\n'
s=importlib.util.spec_from_file_location('owned_relay',ROOT/'crates/gb-tools/src/guest_handoff/relay.py');relay=importlib.util.module_from_spec(s);s.loader.exec_module(relay)
REQ=dict(host='192.168.1.2',port=18000,route_nonce=ROUTE,observer_nonce=OBSERVER,guest_boot_id=BOOT,payload_sha256=hashlib.sha256(DATA).hexdigest(),payload_bytes=len(DATA))
PLAN=json.loads(subprocess.check_output([str(TOOL),'prepare'],input=json.dumps(REQ),text=True))
def run(download=DATA,boot=BOOT,fetch_exit=0,python_exit=0):
 with tempfile.TemporaryDirectory() as temp:
  p=Path(temp);(p/'body').write_bytes(download)
  scripts={'cat':"printf '%s' '"+boot+"'",'curl':'out=;while [ "$#" -gt 0 ];do if [ "$1" = --output ];then shift;out=$1;fi;shift;done;printf \'%s\' "$out" > "$OWNED_TEMP_PATH";[ "$OWNED_FETCH_EXIT" = 0 ] || exit "$OWNED_FETCH_EXIT";/bin/cp "$OWNED_BODY" "$out"', 'python3':'[ -f "$1" ] || exit 98;printf yes > "$OWNED_EXEC";exit "$OWNED_PYTHON_EXIT"'}
  for name,body in scripts.items():f=p/name;f.write_text('#!/bin/sh\n'+body+'\n');f.chmod(0o700)
  for name in ['timeout','mktemp','rm','wc','sha256sum','cut']:(p/name).symlink_to('/usr/bin/'+name)
  env=dict(os.environ,PATH=str(p),OWNED_BODY=str(p/'body'),OWNED_TEMP_PATH=str(p/'temp-path'),OWNED_EXEC=str(p/'executed'),OWNED_FETCH_EXIT=str(fetch_exit),OWNED_PYTHON_EXIT=str(python_exit))
  r=subprocess.run(['/bin/sh','-c',PLAN['command']],env=env,capture_output=True,text=True,timeout=3)
  path=Path((p/'temp-path').read_text()) if (p/'temp-path').exists() else None
  return r,(p/'executed').exists(),path is None or not path.exists()
def negative_receipt():return dict(schema_version=1,run_nonce=ROUTE,payload_sha256=hashlib.sha256(DATA).hexdigest(),guest_boot_id=BOOT,uid=1000,architecture='aarch64',kernel='6.12.93-owned',memtotal_kib=2000000,graphics=None,inventory=None,status='unknown',failure_stage='gles_probe',failure_kind='ProbeError',firmware_written=False,configuration_changed=False,full_port_verified=False)
class Bootstrap(unittest.TestCase):
 def test_verified_file_executes_and_temporary_file_is_removed(self):
  r,ran,clean=run();self.assertEqual(r.returncode,0);self.assertTrue(ran);self.assertTrue(clean);self.assertIn(PLAN['success_marker'],r.stdout)
 def test_hash_size_download_and_guest_mismatch_never_execute(self):
  for kwargs in [dict(download=b'wrong'),dict(download=b'x'*len(DATA)),dict(fetch_exit=7),dict(boot='abcdef01-2345-6789-abcd-0123456789ab')]:
   with self.subTest(kwargs=kwargs):
    r,ran,clean=run(**kwargs);self.assertNotEqual(r.returncode,0);self.assertFalse(ran);self.assertTrue(clean);self.assertNotIn(PLAN['success_marker'],r.stdout)
 def test_child_failure_removes_payload_and_never_qualifies_marker(self):
  r,ran,clean=run(python_exit=2);self.assertNotEqual(r.returncode,0);self.assertTrue(ran);self.assertTrue(clean);self.assertNotIn(PLAN['success_marker'],r.stdout)
 def test_bundle_contains_owned_fixture_in_private_namespace(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp);f=p/'fixture';f.write_text('def probe(n): return n\n');out=p/'bundle'
   subprocess.run([str(TOOL),'bundle',str(f),BOOT,str(out)],check=True,timeout=3);text=out.read_text();compile(text,'owned-bundle','exec');self.assertNotIn('__FIXTURE_HEX__',text);self.assertNotIn('__GUEST_BOOT__',text)
   again=subprocess.run([str(TOOL),'bundle',str(f),BOOT,str(out)],capture_output=True,text=True,timeout=3);self.assertNotEqual(again.returncode,0)
class Protocol(unittest.TestCase):
 def test_negative_receipt_has_truthful_bounded_schema(self):
  d=negative_receipt();self.assertEqual(relay.receipt(d,ROUTE,BOOT,REQ['payload_sha256'])['status'],'unknown')
 def test_receipt_unknown_fields_wrong_context_and_scope_refuse(self):
  good=negative_receipt()
  for k,v in [('secret','forbidden'),('guest_boot_id','wrong'),('uid',True),('payload_sha256','0'*64),('firmware_written',True),('failure_kind','private text')]:
   with self.assertRaises(ValueError):relay.receipt(dict(good,**{k:v}),ROUTE,BOOT,REQ['payload_sha256'])
 def test_duplicate_json_keys_refuse(self):
  with self.assertRaises(ValueError):json.loads('{"a":1,"a":2}',object_pairs_hook=relay.unique)
 def test_partial_headers_are_cut_off_by_absolute_connection_deadline(self):
  server=relay.Relay(('127.0.0.1',0),'127.0.0.1',ROUTE,BOOT,DATA,lambda:None,lambda v:None,connection_seconds=.05)
  t=threading.Thread(target=server.handle_request);t.start()
  try:
   with socket.create_connection(server.server_address,timeout=1) as sock:
    for byte in b'GET ':
     try:sock.sendall(bytes([byte]))
     except OSError:break
     time.sleep(.02)
    t.join(timeout=.01);self.assertFalse(t.is_alive())
   self.assertEqual(server.watchdogs,{})
  finally:server.server_close()
 def test_loopback_once_only_routes_and_scoped_receipt(self):
  accepted=[];server=relay.Relay(('127.0.0.1',0),'127.0.0.1',ROUTE,BOOT,DATA,lambda:None,accepted.append)
  stop=threading.Event()
  def serve():
   while not stop.is_set():server.handle_request()
  t=threading.Thread(target=serve);t.start();base='http://127.0.0.1:'+str(server.server_address[1])+'/'+ROUTE;opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  try:
   with self.assertRaises(urllib.error.HTTPError) as e:opener.open(base+'/unknown',timeout=2)
   self.assertEqual(e.exception.code,404)
   self.assertEqual(opener.open(base+'/runner.py',timeout=2).read(),DATA)
   with self.assertRaises(urllib.error.HTTPError) as e:opener.open(base+'/runner.py',timeout=2)
   self.assertEqual(e.exception.code,409)
   data=json.dumps(negative_receipt()).encode();request=urllib.request.Request(base+'/receipt',data=data)
   self.assertEqual(opener.open(request,timeout=2).read(),b'GB_OWNED_GLES_RECEIVED\n');self.assertEqual(len(accepted),1)
   with self.assertRaises(urllib.error.HTTPError) as e:opener.open(request,timeout=2)
   self.assertEqual(e.exception.code,409)
  finally:stop.set();t.join(timeout=3);server.server_close();self.assertFalse(t.is_alive())
if __name__=='__main__':unittest.main()
