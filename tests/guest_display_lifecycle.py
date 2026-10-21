"""Owned host protocol tests; no firmware, device, GPU or real pixels executed."""
from pathlib import Path
import copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'crates/gb-tools/src/guest_display_lifecycle'
CONTEXT=dict(guest_boot_id='12345678-1234-1234-1234-123456789abc',uid=1000,compositor_pid=398,
 driver_sha256='a'*64,profiles_sha256=['b'*64,'c'*64],program_sha256='d'*64,program_bytes=100)

def load_agent(context=CONTEXT, path=None):
 s=(SRC/'agent.py').read_text().replace('__CONTEXT_HEX__',json.dumps(context,separators=(',',':')).encode().hex())
 m=type(sys)('owned_lifecycle_agent');m.__file__=str(path or SRC/'agent.py');exec(compile(s,m.__file__,'exec'),m.__dict__);return m

def load_relay():
 s=importlib.util.spec_from_file_location('owned_lifecycle_relay',SRC/'relay.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def state():return dict(start=None,creates=[],presents=[],native_acks=[],sent_acks=[],completed=None,configure_count=0,fullscreen_seen=False)
def start():return dict(schema_version=2,phase_count=3,frame_limit=3600,ack_required=True,presentation_verified=False)
def creation(p):
 w,h=((640,480),(480,360),(640,480))[p];return dict(schema_version=2,phase=p,width=w,height=h,images=4,old_swapchain_supplied=p>0,swapchain_generation=p+1,presentation_verified=False)
def present(p):
 v=creation(p);del v['images'];del v['old_swapchain_supplied'];v.update(frame=p+1,queue_present_result=0);return v

def emit(m,kind,v,s):m.marker('GB_VULKAN_LIFECYCLE_'+kind+':'+json.dumps(v),s)
def configure():return dict(schema_version=2,phase=0,fullscreen=True,raw_max_width=3200,raw_max_height=1670,buffer_width=640,buffer_height=480,presentation_verified=False)

class Tests(unittest.TestCase):
 def test_actual_marker_sequence_requires_owned_acks_and_three_generations(self):
  m=load_agent();s=state();emit(m,'START',start(),s);emit(m,'CONFIGURE',configure(),s)
  for p in range(3):
   emit(m,'CREATE',creation(p),s);emit(m,'PRESENT',present(p),s)
   ack=dict(schema_version=2,phase=p,ack_index=p+1,presentation_verified=False)
   with self.assertRaises(m.Refused):emit(m,'ACK',ack,s)
   s['sent_acks'].append({'capture_token':str(p)*32});emit(m,'ACK',ack,s)
  emit(m,'COMPLETED',dict(schema_version=2,phases=3,acknowledgements=3,swapchain_generations=3,frames=3,presentation_verified=False,explicit_present_retirement_verified=False),s)
  self.assertIsNotNone(s['completed'])
 def test_rejects_duplicate_out_of_order_bool_or_stale_extent_markers(self):
  m=load_agent()
  for kind,v in [('START',dict(start(),ack_required=1)),('CREATE',creation(1)),('PRESENT',present(0))]:
   s=state()
   if kind!='START':emit(m,'START',start(),s)
   with self.assertRaises(m.Refused):emit(m,kind,v,s)
  s=state();emit(m,'START',start(),s);emit(m,'CONFIGURE',configure(),s);emit(m,'CREATE',creation(0),s)
  for v in [creation(0),dict(creation(1),width=640,height=480),dict(creation(1),old_swapchain_supplied=False)]:
   with self.assertRaises(m.Refused):emit(m,'CREATE',v,s)
  with self.assertRaises(m.Refused):m.marker('GB_VULKAN_LIFECYCLE_START:{"schema_version":2,"schema_version":2}',state())
 def test_native_refusal_only_exports_pinned_static_stage_including_pre_start(self):
  a=load_agent();r=load_relay()
  self.assertEqual(a.NATIVE_REFUSAL_STAGES,r.NATIVE_REFUSAL_STAGES)
  source=ROOT/'artifacts/device/first-boot-20261013/d96-owned-vulkan-lifecycle-20261021-v1/attempt-v2'
  if source.exists():
   import re
   literals=set(re.findall(r'gb_owned_resize_refuse\("([a-z0-9_]+)"\)',(source/'cube.c').read_text()+(source/'terminal_guest_vulkan_lifecycle.c').read_text()))
   self.assertEqual(a.NATIVE_REFUSAL_STAGES,literals)
  good=dict(schema_version=2,status='refused',stage='lifecycle_create_sequence',presentation_verified=False)
  for before_start in (True,False):
   st=state()
   if not before_start:emit(a,'START',start(),st)
   with self.assertRaisesRegex(a.Refused,'^refused_marker$'):emit(a,'REFUSED',good,st)
   self.assertEqual(st['native_refusal_stage'],'lifecycle_create_sequence')
  for bad in [dict(good,stage='private-path-or-token'),dict(good,stage=True),dict(good,stage={}),dict(good,extra='private'),dict(good,status='other'),dict(good,schema_version=True)]:
   st=state()
   with self.assertRaises(a.Refused):emit(a,'REFUSED',bad,st)
   self.assertNotIn('native_refusal_stage',st)
 def test_actual_worker_preserves_refusal_scalar_and_relay_rejects_arbitrary_values(self):
  helper=(ROOT/'tests/fixtures/guest_display_lifecycle_worker_host.py').read_text()
  program="#!/usr/bin/env python3\nimport json\nprint('GB_VULKAN_LIFECYCLE_REFUSED:'+json.dumps(dict(schema_version=2,status='refused',stage='lifecycle_create_sequence',presentation_verified=False)),flush=True)\nraise SystemExit(2)\n"
  helper=helper.replace("if mode=='tail_marker':", "if mode=='native_refused':program="+repr(program)+"\nif mode=='tail_marker':",1)
  helper=helper.replace("print(json.dumps(dict(passed=code==0", "print(json.dumps(dict(full_result=final,passed=code==0",1)
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'helper.py';path.write_text(helper)
   run=subprocess.run([sys.executable,'-I',str(path),str(ROOT),'native_refused'],capture_output=True,text=True,timeout=8)
  self.assertEqual(run.returncode,0,run.stderr[-1000:]);v=json.loads(run.stdout)['full_result']
  self.assertEqual(v['failure_kind'],'refused_marker');self.assertEqual(v['native_refusal_stage'],'lifecycle_create_sequence')
  self.assertTrue(v['child_reaped']);self.assertTrue(v['files_removed'])
  r=load_relay();config=dict(CONTEXT,run_nonce=v['run_nonce'],agent={'sha256':v['agent_sha256']},program={'sha256':v['program_sha256']})
  r.receipt(v,'result',config)
  for value in ['private-path-or-token',True,{},'']:
   with self.assertRaises(ValueError):r.receipt(dict(v,native_refusal_stage=value),'result',config)
  with self.assertRaises(ValueError):r.receipt(dict(v,native_refusal_stage=None),'result',config)
 def test_capture_control_rejects_wrong_phase_digest_context_and_token_reuse_inputs(self):
  m=load_agent();binding=dict(schema_version=1,run_nonce='a'*32,guest_boot_id=CONTEXT['guest_boot_id'],agent_sha256='e'*64,program_sha256='d'*64)
  good=dict(binding,kind='ack1',**m.phase_contract(1),capture_token='b'*32,capture_sha256='f'*64)
  for bad in [dict(good,phase=0),dict(good,width=640),dict(good,contract_sha256='0'*64),dict(good,run_nonce='0'*32),dict(good,phase=True),dict(good,capture_token='peer-name')]:
   m.rpc=lambda *a,**k:(200,json.dumps(bad).encode())
   with self.assertRaises(m.Refused):m.control('unused','ack1',binding)
  m.rpc=lambda *a,**k:(200,json.dumps(good).encode());self.assertEqual(m.control('unused','ack1',binding),good)
 def test_relay_scope_phase_receipt_and_typed_controls(self):
  r=load_relay();config=dict(CONTEXT,run_nonce='a'*32,agent={'sha256':'e'*64},program={'sha256':'d'*64},capture_tokens=['1'*32,'2'*32,'3'*32],target=dict(android_boot_id=CONTEXT['guest_boot_id'],android_user=11,uid=1110248,main_pid=10,main_start_ticks=20,native_pid=11,native_start_ticks=21))
  binding=r.binding(config);v=dict(binding,uid=1000,kind='phase1',status='queue_present_api_witness',compositor_pid=398,start=start(),creation=creation(1),present=present(1),preceding_native_ack_count=1,child_alive=True,graphics_qualified=False)
  r.receipt(v,'phase1',config)
  for bad in [dict(v,preceding_native_ack_count=0),dict(v,creation=creation(0)),dict(v,graphics_qualified=True)]:
   with self.assertRaises(ValueError):r.receipt(bad,'phase1',config)
  ctrl=dict(binding,kind='ack1',**config['target'],**r.phase_contract(1),capture_token='2'*32,capture_sha256='f'*64)
  self.assertEqual(r.control(ctrl,'ack1',config)['phase'],1)
  for bad in [dict(ctrl,capture_token='1'*32),dict(ctrl,phase=True),dict(ctrl,width=640)]:
   with self.assertRaises(ValueError):r.control(bad,'ack1',config)
 def test_cross_module_contract_vectors_and_distinct_restored_phase(self):
  a=load_agent();r=load_relay();vectors=['8f6469453bbd9da94bfb16b7a8f881445d85141851602c70200e8913c47d9e65','c8d7057e4de2d55f67f4b84015a323e6dba9188bc871836d069c690d2dcde28b','e88e8d13efb7060c53713697450806f414fe33feecc348f4222284bfa346febe']
  for p in range(3):self.assertEqual(a.phase_contract(p),r.phase_contract(p));self.assertEqual(a.phase_contract(p)['contract_sha256'],vectors[p])
 def test_actual_worker_drains_refusal_when_child_exits_during_post_or_control(self):
  helper=ROOT/'tests/fixtures/guest_display_lifecycle_worker_host.py'
  for mode in ('exit_during_post','exit_during_control','exit_without_marker_post'):
   with self.subTest(mode=mode):
    run=subprocess.run([sys.executable,'-I',str(helper),str(ROOT),mode],capture_output=True,text=True,timeout=8)
    self.assertEqual(run.returncode,0,run.stderr[-1000:]);value=json.loads(run.stdout)
    self.assertFalse(value['passed']);self.assertTrue(value['child_reaped']);self.assertTrue(value['files_removed'])
    self.assertEqual(value['present_count'],1);self.assertEqual(value['native_ack_count'],0);self.assertEqual(value['child_exit_code'],2)
    if mode=='exit_without_marker_post':
     self.assertEqual(value['failure_kind'],'child_exited_during_started_ack');self.assertIsNone(value['native_refusal_stage'])
    else:
     self.assertEqual(value['failure_kind'],'refused_marker');self.assertEqual(value['native_refusal_stage'],'lifecycle_create_sequence')
 def test_actual_host_worker_child_pipe_completion_and_failure_cleanup(self):
  # Run actual supervisor in isolated host child, with explicit fake context/RPC.
  helper=ROOT/'tests/fixtures/guest_display_lifecycle_worker_host.py'
  for mode in ['pass','bad_digest','reused_token','tail_marker','tail_budget']:
   v=subprocess.run([sys.executable,'-I',str(helper),str(ROOT),mode],capture_output=True,text=True,timeout=8)
   self.assertEqual(v.returncode,0,v.stderr[-1000:]);report=json.loads(v.stdout)
   self.assertTrue(report['child_reaped']);self.assertTrue(report['files_removed'])
   self.assertEqual(report['passed'],mode=='pass')
if __name__=='__main__':unittest.main()
