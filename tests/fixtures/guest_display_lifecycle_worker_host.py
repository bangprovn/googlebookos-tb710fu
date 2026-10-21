"""Host-only emulated child, actual supervisor; no Vulkan/physical claims."""
from pathlib import Path
import hashlib,json,os,sys,tempfile,subprocess,types
ROOT=Path(sys.argv[1]);mode=sys.argv[2];nonce='a'*32
# Import in a normal module dict so function globals use the same namespace.
import importlib.util
spec=importlib.util.spec_from_file_location('lifecycle_tests',ROOT/'tests/guest_display_lifecycle.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
program='''#!/usr/bin/env python3
import json,sys
ext=((640,480),(480,360),(640,480))
def out(k,v):print('GB_VULKAN_LIFECYCLE_'+k+':'+json.dumps(dict(schema_version=2,presentation_verified=False,**v)),flush=True)
out('START',dict(phase_count=3,frame_limit=3600,ack_required=True))
out('CONFIGURE',dict(phase=0,fullscreen=True,raw_max_width=3200,raw_max_height=1670,buffer_width=640,buffer_height=480))
for p,(w,h) in enumerate(ext):
 out('CREATE',dict(phase=p,width=w,height=h,images=4,old_swapchain_supplied=p>0,swapchain_generation=p+1))
 out('PRESENT',dict(phase=p,width=w,height=h,frame=p+1,swapchain_generation=p+1,queue_present_result=0))
 assert sys.stdin.readline()=='ACK%d\\n'%p
 out('ACK',dict(phase=p,ack_index=p+1))
out('COMPLETED',dict(phases=3,acknowledgements=3,swapchain_generations=3,frames=3,explicit_present_retirement_verified=False))
'''
if mode in ('exit_during_post','exit_during_control','exit_without_marker_post'):
 old_line=" assert sys.stdin.readline()=='ACK%d\\n'%p"
 failure="pass" if mode=='exit_without_marker_post' else "out('REFUSED',dict(status='refused',stage='lifecycle_create_sequence'))"
 new_line=" line=sys.stdin.readline()\n if line=='FAIL\\n':\n  "+failure+"\n  raise SystemExit(2)\n assert line=='ACK%d\\n'%p"
 assert old_line in program
 program=program.replace(old_line,new_line)
if mode=='tail_marker':program+="import time;time.sleep(.1);print('GB_VULKAN_LIFECYCLE_BOGUS:{}',flush=True)\n"
if mode=='tail_budget':program+="import time;time.sleep(.1);print('x'*12000,flush=True)\n"
with tempfile.TemporaryDirectory() as tmp:
 profiles=[Path(tmp)/str(i) for i in range(2)]
 for p in profiles:p.write_text('owned fixture profile\n')
 d=Path(tempfile.mkdtemp(prefix='gb-display-'+nonce+'-',dir='/tmp'))
 try:
  ctx=dict(t.CONTEXT,profiles_sha256=[hashlib.sha256(p.read_bytes()).hexdigest() for p in profiles],program_sha256=hashlib.sha256(program.encode()).hexdigest(),program_bytes=len(program))
  raw=(ROOT/'crates/gb-tools/src/guest_display_lifecycle/agent.py').read_text().replace('__CONTEXT_HEX__',json.dumps(ctx,separators=(',',':')).encode().hex())
  (d/'worker.py').write_text(raw);(d/'program').write_text(program);(d/'program').chmod(0o700)
  a=t.load_agent(ctx,d/'worker.py');a.PROFILES=profiles;a.inspect_context=lambda:'owned-test-wayland'
  records=[];children=[];original_popen=subprocess.Popen
  def owned_popen(*args,**kwargs):
   child=original_popen(*args,**kwargs);children.append(child);return child
  a.subprocess=types.SimpleNamespace(Popen=owned_popen,PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired)
  def force_refusal_exit():
   child=children[0];os.write(child.stdin.fileno(),b'FAIL\n');child.wait(timeout=2)
  def post(base,route,value):
   records.append((route,value))
   if route=='phase0' and mode in ('exit_during_post','exit_without_marker_post'):force_refusal_exit()
  a.post=post
  def control(base,route,binding):
   if route=='ready':return dict(binding,kind=route)
   if route=='ack0' and mode=='exit_during_control':force_refusal_exit();return None
   phase=int(route[-1]);v=dict(binding,kind=route,**a.phase_contract(phase),capture_token=str(phase+1)*32,capture_sha256='f'*64)
   if phase==1 and mode=='bad_digest':v['contract_sha256']='0'*64
   if phase==1 and mode=='reused_token':v['capture_token']='1'*32
   a.rpc=lambda *args,**kw:(200,json.dumps(v).encode())
   return ORIGINAL(base,route,binding)
  ORIGINAL=a.control;a.control=control
  code=a.worker('unused',nonce,hashlib.sha256(raw.encode()).hexdigest());final=records[-1][1]
  print(json.dumps(dict(passed=code==0,child_reaped=final['child_reaped'],files_removed=final['files_removed'],status=final['status'],failure_kind=final['failure_kind'],native_refusal_stage=final['native_refusal_stage'],present_count=final['present_count'],native_ack_count=final['native_ack_count'],child_exit_code=final['child_exit_code'])))
 finally:
  if d.exists():
   import shutil;shutil.rmtree(d)
