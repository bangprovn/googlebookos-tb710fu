#!/usr/bin/env python3
"""Synthetic scalar shape fixtures only; no device or real activity dump input."""
from pathlib import Path
import json,subprocess,unittest
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/lib/phone_link_activity_shape.awk'
NONCE='0123456789abcdef0123456789abcdef'
SHORT='com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity'
FULL='com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity'
def trailer(rc=0,nonce=NONCE):return '\nGB_PHONE_LINK_ACTIVITY_SHAPE_END_V1 '+nonce+' '+str(rc)+'\n'
class Tests(unittest.TestCase):
 def reduce(self,text,nonce=NONCE):
  r=subprocess.run(['awk','-v','frame_nonce='+nonce,'-f',str(SCRIPT)],input=text,capture_output=True,text=True,timeout=3,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'});self.assertEqual(r.stderr,'');o=json.loads(r.stdout)
  self.assertFalse(o['identity_verified']);self.assertFalse(o['foreground_verified']);self.assertFalse(o['raw_fields_exported'])
  for private in (SHORT,FULL,'abc123','1110128','42424','PRIVATE_ACCOUNT','PEER_NAME'):self.assertNotIn(private,r.stdout)
  return r,o
 def header(self,tail='pid=42424 userId=11 uid=1110128 displayId=0(type=INTERNAL)',component=SHORT):return '  ACTIVITY '+component+' abc123 '+tail+'\n'
 def test_actual_reference_full_shape(self):
  r,o=self.reduce(self.header()+trailer());self.assertEqual(r.returncode,0);self.assertEqual(o['status'],'shape_observed');self.assertTrue(o['dump_complete']);s=o['shapes'][0]
  self.assertEqual(s,dict(field_count=7,roles=['activity_keyword','component_short','opaque_hex','pid_positive','user_id_owner','uid_owner','display_internal'],pid_fields=1,user_fields=1,owner_user_fields=1,uid_fields=1,owner_uid_fields=1,display_fields=1,unknown_tokens=0))
 def test_exact_component_variants_and_boundaries(self):
  _,o=self.reduce(self.header(component=FULL)+trailer());self.assertEqual(o['shapes'][0]['roles'][1],'component_full')
  for suffix in ('.Other','Extra'):
   _,o=self.reduce(self.header(component=SHORT+suffix)+trailer());self.assertEqual(o['status'],'no_matching_header');self.assertEqual(o['shapes'],[])
 def test_display_types_unavailable_and_unknown_values(self):
  for name in ('INTERNAL','EXTERNAL','VIRTUAL','OVERLAY','WIFI','UNKNOWN'):
   _,o=self.reduce(self.header('pid=1 userId=11 uid=1110128 displayId=123(type='+name+')')+trailer());self.assertEqual(o['shapes'][0]['roles'][-1],'display_'+name.lower())
  for raw,role in [('N/A','display_unavailable'),('0','display_plain_numeric'),('1(type=PRIVATE_ACCOUNT)','display_malformed'),('-1(type=INTERNAL)','display_malformed')]:
   _,o=self.reduce(self.header('displayId='+raw)+trailer());self.assertEqual(o['shapes'][0]['roles'][-1],role)
 def test_unknowns_other_owner_and_known_additional_tokens(self):
  _,o=self.reduce(self.header('pid=42424 userId=0 uid=1000 PRIVATE_ACCOUNT=PEER_NAME taskId=123 visible=true state=PAUSED')+trailer());s=o['shapes'][0]
  self.assertEqual(s['roles'][3:],['pid_positive','user_id_other','uid_other','unknown','task_numeric','known_boolean','known_state']);self.assertEqual(s['owner_user_fields'],0);self.assertEqual(s['owner_uid_fields'],0);self.assertEqual(s['unknown_tokens'],1)
 def test_not_running_duplicates_and_invalid_numeric_shapes(self):
  _,o=self.reduce(self.header('pid=(not running) userId=11 uid=1110128 uid=1110128 displayId=N/A')+trailer());s=o['shapes'][0]
  self.assertEqual(s['roles'][3:5],['pid_not_running_start','pid_not_running_end']);self.assertEqual(s['uid_fields'],2)
  _,o=self.reduce(self.header('pid=99999999 userId=-1 uid=bad')+trailer());self.assertEqual(o['shapes'][0]['roles'][3:],['pid_malformed','user_id_malformed','uid_malformed'])
 def test_framing_producer_failure_and_caps_clear_shapes(self):
  for text in (self.header(),self.header()+trailer(nonce='a'*32),self.header()+trailer()+trailer(),self.header()+trailer()+'after\n',self.header()*5+trailer(),self.header(' '.join(['PRIVATE_ACCOUNT']*14))+trailer(),'x'*4097+'\n'+trailer()):
   r,o=self.reduce(text);self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'framing_refused');self.assertEqual(o['shapes'],[]);self.assertEqual(o['matching_headers'],0)
  r,o=self.reduce(self.header()+trailer(137));self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'producer_failed');self.assertEqual(o['shapes'],[]);self.assertFalse(o['dump_complete'])
 def test_non_header_text_and_invalid_nonce_are_not_data(self):
  _,o=self.reduce('PRIVATE_ACCOUNT PEER_NAME\n'+trailer());self.assertEqual(o['status'],'no_matching_header')
  for nonce in ('','z'*32,'a'*31):
   r,o=self.reduce(self.header()+trailer(),nonce);self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'framing_refused')
if __name__=='__main__':unittest.main()
