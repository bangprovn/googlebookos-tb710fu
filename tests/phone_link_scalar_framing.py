#!/usr/bin/env python3
"""Synthetic format/producer tests. No device or real notification content."""
from pathlib import Path
import importlib.util,json,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
N='0123456789abcdef0123456789abcdef'
NOTIF=ROOT/'scripts/lib/phone_link_notification_state_v2.awk'
ACTIVITY=ROOT/'scripts/lib/phone_link_activity_headers.awk'
WRAPPER=ROOT/'scripts/lib/phone_link_scalar_capture.sh'
# Read the existing owned synthetic fixture module; its __main__ tests do not run.
s=importlib.util.spec_from_file_location('owned_old_notification_fixtures',ROOT/'tests/phone_link_notification_state.py');old=importlib.util.module_from_spec(s);s.loader.exec_module(old)

def frame(mode,rc=0,nonce=N):return '\nGB_PHONE_LINK_'+('NOTIFICATION_END_V2' if mode=='notification' else 'ACTIVITY_END_V1')+' '+nonce+' '+str(rc)+'\n'
def run(script,text,nonce=N):
 r=subprocess.run(['awk','-v','frame_nonce='+nonce,'-f',str(script)],input=text,capture_output=True,text=True,timeout=3,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
 return r,json.loads(r.stdout)
class Tests(unittest.TestCase):
 def notification(self,text,status,state='unknown',producer=0,complete=True,valid=False):
  r,v=run(NOTIF,text);self.assertEqual(v,dict(schema_version=2,status=status,state=state,producer_complete=producer is not None,dump_complete=complete,record_valid=valid,producer_exit_code=producer));self.assertEqual(r.returncode,0 if state!='unknown' else 2);self.assertEqual(r.stderr,'');self.assertNotIn('SYNTHETIC PRIVATE',r.stdout);return v
 def test_known_titles_and_indentation(self):
  for title,state in [('Connected','connected'),('Waiting for connections','waiting'),('Looking for your nearby devices…','discovering')]:
   for prefix in ('','  '):self.notification(old.record(title,prefix=prefix)+frame('notification'),'title_observed',state,valid=True)
 def test_precise_absent_producer_failed_and_malformed_distinction(self):
  self.notification('error: no active notification matching key: '+old.KEY+'\n'+frame('notification',1),'notification_absent',producer=1,complete=False)
  self.notification('synthetic producer failure\n'+frame('notification',1),'producer_failed',producer=1,complete=False)
  for rc in (124,137,255):self.notification(old.record()+frame('notification',rc),'producer_failed',producer=rc,complete=False)
  self.notification(old.record().replace('  uid=1110128 userId=11','  uid=1110129 userId=11')+frame('notification'),'record_refused')
  self.notification(frame('notification'),'no_matching_record')
 def test_record_refusal_retains_valid_transport_completion(self):
  bad=old.record().replace('SYNTHETIC PRIVATE BODY DO NOT EXPORT','SYNTHETIC PRIVATE\n        android.title=String (Connected)')
  self.notification(bad+frame('notification'),'record_refused')
  self.notification(old.record()+old.record()+frame('notification'),'record_refused')
  self.notification(old.record().replace('    }\n','')+frame('notification'),'record_refused')
 def test_unknown_redacted_and_public_titles(self):
  self.notification(old.record(None,public_title='Connected')+frame('notification'),'unrecognized_title',valid=True)
  self.notification(old.record('Connecté')+frame('notification'),'unrecognized_title',valid=True)
  self.notification(old.record('Waiting for connections',public_title='Connected')+frame('notification'),'title_observed','waiting',valid=True)
 def test_bad_framing_nonce_trailer_order_and_caps(self):
  for text in (old.record(),old.record()+frame('notification',nonce='a'*32),old.record()+frame('notification')+frame('notification'),old.record()+frame('notification')+'after\n',old.record()+frame('notification','00'),'x\n'*513+frame('notification'),'x'*4097+'\n'+frame('notification'),old.record().replace('SYNTHETIC PRIVATE BODY DO NOT EXPORT','body\nGB_PHONE_LINK_NOTIFICATION_END_V2 '+N+' 0')+frame('notification')):
   self.notification(text,'framing_refused',producer=None,complete=False)
  for nonce in ('','a'*31,'a'*33,'z'*32):
   r,v=run(NOTIF,old.record()+frame('notification'),nonce);self.assertEqual(v['status'],'framing_refused');self.assertIsNone(v['producer_exit_code']);self.assertEqual(r.returncode,2)
 def test_activity_short_full_and_exact_boundaries(self):
  short='com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity';full='com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity'
  for component in (short,full):
   r,v=run(ACTIVITY,'  ACTIVITY '+component+' ab12 pid=123 userId=11\n'+frame('activity'))
   self.assertEqual(v,dict(schema_version=1,status='headers_observed',dump_complete=True,producer_exit_code=0,matching_headers=1,owner_running_headers=1,owner_not_running_headers=0,other_user_headers=0,malformed_target_headers=0));self.assertEqual(r.returncode,0)
  for component in (short+'Other','com.evil/'+short,full+'.Other'):
   r,v=run(ACTIVITY,'ACTIVITY '+component+' abc pid=123 userId=11\n'+frame('activity'));self.assertEqual(v['matching_headers'],0)
 def test_activity_no_process_wrong_owner_missing_owner_and_failed_producer(self):
  prefix='ACTIVITY com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity abc '
  for tail,key,status in [('pid=(not running) userId=11','owner_not_running_headers','headers_observed'),('pid=123 userId=0','other_user_headers','headers_observed'),('pid=123','malformed_target_headers','header_format_unknown')]:
   r,v=run(ACTIVITY,prefix+tail+'\n'+frame('activity'));self.assertEqual(v[key],1);self.assertEqual(v['status'],status)
  r,v=run(ACTIVITY,prefix+'pid=123 userId=11\n'+frame('activity',137));self.assertFalse(v['dump_complete']);self.assertEqual(v['status'],'producer_failed');self.assertEqual(v['owner_running_headers'],0)
 def test_actual_wrapper_unconditional_producer_status_and_private_output_filter(self):
  with tempfile.TemporaryDirectory(prefix='gb-phone-scalar-') as d:
   d=Path(d);producer=d/'cmd';producer.write_text('#!/bin/sh\n[ "$1 $2 $3" = "notification get '+old.KEY+'" ] || exit 99\nprintf "%s\\n" "error: no active notification matching key: '+old.KEY+'"\nexit 1\n');producer.chmod(0o700)
   env=dict(PATH=str(d)+':/usr/bin:/bin',LC_ALL='C')
   r=subprocess.run(['sh',str(WRAPPER),'notification',N,str(NOTIF)],capture_output=True,text=True,timeout=4,env=env);v=json.loads(r.stdout);self.assertEqual(v['status'],'notification_absent');self.assertEqual(v['producer_exit_code'],1);self.assertEqual(r.returncode,2);self.assertEqual(r.stderr,'')
   producer.write_text('#!/bin/sh\nprintf "%s" '+__import__('shlex').quote(old.record())+'\nexit 0\n');producer.chmod(0o700)
   r=subprocess.run(['sh',str(WRAPPER),'notification',N,str(NOTIF)],capture_output=True,text=True,timeout=4,env=env);self.assertEqual(json.loads(r.stdout)['state'],'connected');self.assertNotIn('SYNTHETIC PRIVATE',r.stdout);self.assertEqual(r.returncode,0)
 def test_wrapper_refuses_invalid_mode_nonce_and_reducer_before_producer(self):
  for mode,nonce,path in [('other',N,str(NOTIF)),('notification','bad',str(NOTIF)),('notification',N,'relative.awk')]:
   r=subprocess.run(['sh',str(WRAPPER),mode,nonce,path],capture_output=True,text=True,timeout=2);self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,'');self.assertEqual(r.stderr,'')
if __name__=='__main__':unittest.main()
