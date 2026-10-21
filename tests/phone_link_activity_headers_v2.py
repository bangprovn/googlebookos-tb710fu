#!/usr/bin/env python3
"""Full reference-format synthetic fixtures; no device/real activity dump input."""
from pathlib import Path
import json,subprocess,unittest
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/lib/phone_link_activity_headers_v2.awk'
N='0123456789abcdef0123456789abcdef'
SHORT='com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity'
FULL='com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity'
def frame(rc=0,nonce=N):return '\nGB_PHONE_LINK_ACTIVITY_END_V2 '+nonce+' '+str(rc)+'\n'
def header(tail='pid=42424 userId=11 uid=1110128 displayId=0(type=INTERNAL)',component=SHORT):return '  ACTIVITY '+component+' ab12 '+tail+'\n'
class Tests(unittest.TestCase):
 def reduce(self,text,nonce=N):
  r=subprocess.run(['awk','-v','frame_nonce='+nonce,'-f',str(SCRIPT)],input=text,capture_output=True,text=True,timeout=3,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'});self.assertEqual(r.stderr,'');o=json.loads(r.stdout)
  for value in (SHORT,FULL,'ab12','42424','1110128','PRIVATE_CONTENT'):self.assertNotIn(value,r.stdout)
  for flag in ('identity_verified','foreground_verified','raw_fields_exported'):self.assertIs(o[flag],False)
  return r,o
 def test_reference_running_form_both_component_spellings(self):
  for component in (SHORT,FULL):
   r,o=self.reduce(header(component=component)+frame());self.assertEqual(r.returncode,0);self.assertEqual(o,dict(schema_version=2,status='header_format_observed',dump_complete=True,producer_exit_code=0,matching_headers=1,owner_running_headers=1,owner_not_running_headers=0,malformed_target_headers=0,scope_refused_headers=0,header_format_verified=True,identity_verified=False,foreground_verified=False,raw_fields_exported=False))
 def test_reference_not_running_and_unavailable_display(self):
  r,o=self.reduce(header('pid=(not running) userId=11 uid=1110128 displayId=N/A')+frame());self.assertEqual(r.returncode,0);self.assertTrue(o['header_format_verified']);self.assertEqual(o['owner_not_running_headers'],1);self.assertEqual(o['owner_running_headers'],0)
 def test_public_display_types_and_bounded_values(self):
  for value in ('INTERNAL','EXTERNAL','VIRTUAL','OVERLAY','WIFI','UNKNOWN'):
   r,o=self.reduce(header('pid=4194304 userId=11 uid=1110128 displayId=2147483647(type='+value+')')+frame());self.assertEqual(r.returncode,0);self.assertTrue(o['header_format_verified'])
 def test_known_broken_nf5_is_not_a_fallback(self):
  for tail in ('pid=42424 userId=11','pid=(not running) userId=11','pid=42424 userId=11 uid=1110128','pid=42424 userId=11 uid=1110128 displayId=0(type=INTERNAL) extra=true'):
   r,o=self.reduce(header(tail)+frame());self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'header_format_unknown');self.assertFalse(o['header_format_verified']);self.assertEqual(o['owner_running_headers'],0)
 def test_owner_uid_and_user_both_required(self):
  for tail in ('pid=1 userId=0 uid=1110128 displayId=N/A','pid=1 userId=11 uid=10128 displayId=N/A','pid=(not running) userId=11 uid=1000 displayId=N/A'):
   r,o=self.reduce(header(tail)+frame());self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'header_scope_refused');self.assertEqual(o['scope_refused_headers'],1);self.assertFalse(o['header_format_verified'])
 def test_bad_numeric_display_or_order_values_refused(self):
  for tail in ('pid=0 userId=11 uid=1110128 displayId=N/A','pid=4194305 userId=11 uid=1110128 displayId=N/A','pid=1 userId=11 uid=1110128 displayId=0','pid=1 userId=11 uid=1110128 displayId=-1(type=INTERNAL)','pid=1 userId=11 uid=1110128 displayId=0(type=PRIVATE_CONTENT)','pid=1 uid=1110128 userId=11 displayId=N/A','pid=1 userId=011 uid=1110128 displayId=N/A'):
   r,o=self.reduce(header(tail)+frame());self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'header_format_unknown');self.assertFalse(o['header_format_verified'])
 def test_exact_component_boundary_count_and_empty(self):
  r,o=self.reduce(header(component=SHORT+'Other')+frame());self.assertEqual(r.returncode,0);self.assertEqual(o['status'],'no_matching_header');self.assertFalse(o['header_format_verified'])
  r,o=self.reduce(header()+header()+frame());self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'header_count_refused');self.assertEqual(o['matching_headers'],2);self.assertEqual(o['owner_running_headers'],0)
 def test_failed_incomplete_old_trailer_and_caps_unknown(self):
  for text in (header(),header()+frame(nonce='a'*32),header()+frame()+frame(),header()+frame()+'after\n',header()+'GB_PHONE_LINK_ACTIVITY_END_V1 '+N+' 0\n','x'*4097+'\n'+frame(),header()*5+frame()):
   r,o=self.reduce(text);self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'framing_refused');self.assertFalse(o['dump_complete']);self.assertIsNone(o['producer_exit_code']);self.assertFalse(o['header_format_verified'])
  r,o=self.reduce(header()+frame(137));self.assertEqual(r.returncode,2);self.assertEqual(o['status'],'producer_failed');self.assertEqual(o['producer_exit_code'],137);self.assertEqual(o['matching_headers'],0)
if __name__=='__main__':unittest.main()
