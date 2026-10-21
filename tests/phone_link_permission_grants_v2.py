#!/usr/bin/env python3
"""Real sh+tr+awk V2 fixtures; Android empty-NUL emulation is test-only."""
from pathlib import Path
import importlib.util,json,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/lib/phone_link_permission_grants_v2.awk'
spec=importlib.util.spec_from_file_location('v1_permission_fixtures',ROOT/'tests/phone_link_permission_grants_v1.py')
v1=importlib.util.module_from_spec(spec);spec.loader.exec_module(v1)
v1.trailer=lambda code=0,nonce=v1.N:'GB_PHONE_LINK_PERMISSION_END_V2 '+nonce+' '+str(code)+'\n'

class Tests(v1.Tests):
 def run_reducer(self,text,package=v1.PKG,owner='11',nonce=v1.N,guard='1',script=SCRIPT):
  command="LC_ALL=C tr '\\000' '\\r' | awk -v expected_package=\"$1\" -v owner_user=\"$2\" -v frame_nonce=\"$3\" -v input_nul_guarded=\"$5\" -f \"$4\""
  return subprocess.run(['sh','-c',command,'permission-fixture',package,owner,nonce,str(script),guard],input=text,capture_output=True,text=True,timeout=3,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
 def reduce(self,text,package=v1.PKG,owner='11',nonce=v1.N):
  run=self.run_reducer(text,package,owner,nonce)
  self.assertEqual(run.stderr,'');value=json.loads(run.stdout)
  self.assertEqual(value['schema_version'],2)
  self.assertIs(value['input_nul_guard_required'],True);self.assertIs(value['input_nul_guard_attested_by_caller'],True)
  for secret in ('PRIVATE_CONTENT','PRIVATE_METADATA','PRIVATE_QUERY','ab12','flags','userId=','1110128'):
   self.assertNotIn(secret,run.stdout)
  for key in ('effective_grants_inferred','appops_checked','discovery_verified','raw_fields_exported'):self.assertIs(value[key],False)
  self.assertEqual(len(value['permissions']),9)
  return run,value,{p['name']:p for p in value['permissions']}
 def test_required_sanitizer_attestation_and_versioned_trailer(self):
  text=v1.block()+v1.trailer()
  for guard in ('','0','true','01','PRIVATE_CONTENT'):
   run=self.run_reducer(text,guard=guard);self.assertEqual(run.returncode,2);value=json.loads(run.stdout)
   self.assertFalse(value['input_nul_guard_attested_by_caller'])
   self.assertTrue(all(row['requested'] is None for row in value['permissions']))
  self.refused(v1.block()+'GB_PHONE_LINK_PERMISSION_END_V1 '+v1.N+' 0\n')
 def test_empty_native_nul_representation_still_requires_real_stream_sanitizer(self):
  source=SCRIPT.read_text();old='native_nul=sprintf("%c",0)';self.assertEqual(source.count(old),1)
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'empty-native-nul.awk';path.write_text(source.replace(old,'native_nul=""'))
   text=v1.block()+v1.trailer()
   run=self.run_reducer(text,script=path);self.assertEqual(run.returncode,0,run.stderr)
   self.assertTrue(json.loads(run.stdout)['owner_runtime_section_complete'])
   for malformed in (text.replace('PRIVATE_METADATA','PRIVATE\x00CONTENT'),text.replace('PRIVATE_METADATA','PRIVATE\rCONTENT')):
    run=self.run_reducer(malformed,script=path);self.assertEqual(run.returncode,2)
    value=json.loads(run.stdout);self.assertFalse(value['dump_complete']);self.assertTrue(all(p['requested'] is None for p in value['permissions']))
if __name__=='__main__':unittest.main()
