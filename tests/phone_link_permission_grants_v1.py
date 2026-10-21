#!/usr/bin/env python3
"""Synthetic public-format fixtures through real sh+awk. No device/package dump."""
from pathlib import Path
import json,subprocess,unittest
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/lib/phone_link_permission_grants_v1.awk'
N='0123456789abcdef0123456789abcdef'
PKG='com.google.ambient.streaming'
P='android.permission.'

def trailer(code=0,nonce=N):return 'GB_PHONE_LINK_PERMISSION_END_V1 '+nonce+' '+str(code)+'\n'
def block(package=PKG):
 return ('Packages:\n  Package ['+package+'] (ab12):\n'
 '    PRIVATE_METADATA=PRIVATE_CONTENT\n'
 '    requested permissions:\n'
 '      android.permission.ACCESS_LOCAL_NETWORK\n'
 '      android.permission.BLUETOOTH_SCAN\n'
 '      android.permission.INTERNET\n'
 '    install permissions:\n'
 '      android.permission.INTERNET: granted=true\n'
 '      android.permission.ACCESS_LOCAL_NETWORK: granted=false, flags=[ SYSTEM_FIXED ]\n'
 '      android.permission.ACCESS_LOCAL_NETWORK: granted=true, flags=[ USER_SET ], userId=11\n'
 '    User 0: installed=true hidden=false\n'
 '      runtime permissions:\n'
 '        android.permission.ACCESS_LOCAL_NETWORK: granted=false, flags=[ USER_FIXED ]\n'
 '    User 11: installed=true hidden=false\n'
 '      PRIVATE_DATA=PRIVATE_CONTENT\n'
 '      runtime permissions:\n'
 '        android.permission.ACCESS_LOCAL_NETWORK: granted=true, flags=[ USER_SET ]\n'
 '        android.permission.BLUETOOTH_SCAN: granted=false\n'
 'Queries:\n  PRIVATE_QUERY=PRIVATE_CONTENT\n')

class Tests(unittest.TestCase):
 def reduce(self,text,package=PKG,owner='11',nonce=N):
  command='exec awk -v expected_package="$1" -v owner_user="$2" -v frame_nonce="$3" -f "$4"'
  r=subprocess.run(['sh','-c',command,'permission-fixture',package,owner,nonce,str(SCRIPT)],input=text,capture_output=True,text=True,timeout=3,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  self.assertEqual(r.stderr,'');value=json.loads(r.stdout)
  for secret in ('PRIVATE_CONTENT','PRIVATE_METADATA','PRIVATE_QUERY','ab12','flags','userId=','1110128'):
   self.assertNotIn(secret,r.stdout)
  for k in ('effective_grants_inferred','appops_checked','discovery_verified','raw_fields_exported'):self.assertIs(value[k],False)
  self.assertEqual(len(value['permissions']),9)
  self.assertEqual(len(set(p['name'] for p in value['permissions'])),9)
  return r,value,{p['name']:p for p in value['permissions']}
 def refused(self,text,**kwargs):
  r,v,rows=self.reduce(text,**kwargs);self.assertEqual(r.returncode,2);self.assertFalse(v['active_package_scope_complete'])
  for row in rows.values():
   for key in ('requested','install_scope_granted','install_owner11_override_granted','runtime_owner11_granted'):self.assertIsNone(row[key])
  return v
 def test_complete_separate_requested_system_install_override_and_owner_runtime(self):
  for pkg in (PKG,'com.google.android.gms'):
   r,v,p=self.reduce(block(pkg)+trailer(),package=pkg);self.assertEqual(r.returncode,0);self.assertEqual(v['status'],'permission_scopes_observed')
   self.assertTrue(v['dump_complete']);self.assertTrue(v['owner_runtime_section_complete'])
   self.assertEqual(v['install_scope'],'system_user_entry')
   lan=p[P+'ACCESS_LOCAL_NETWORK'];self.assertTrue(lan['requested']);self.assertFalse(lan['install_scope_granted']);self.assertTrue(lan['install_owner11_override_granted']);self.assertTrue(lan['runtime_owner11_granted'])
   scan=p[P+'BLUETOOTH_SCAN'];self.assertFalse(scan['runtime_owner11_granted']);self.assertIsNone(scan['install_scope_granted'])
   self.assertTrue(p[P+'INTERNET']['install_scope_granted']);self.assertIsNone(p[P+'INTERNET']['runtime_owner11_granted'])
   self.assertFalse(p[P+'ACCESS_FINE_LOCATION']['requested']);self.assertIsNone(p[P+'ACCESS_FINE_LOCATION']['runtime_owner11_granted'])
 def test_hidden_system_and_pre_packages_stale_rows_never_used(self):
  hidden=block().replace('Packages:','Hidden system packages:').replace('granted=true','granted=false')
  r,v,p=self.reduce('Other:\n'+hidden+block()+hidden+trailer());self.assertEqual(r.returncode,0);self.assertTrue(p[P+'ACCESS_LOCAL_NETWORK']['runtime_owner11_granted'])
 def test_missing_rows_stay_unknown_and_no_effective_install_fallback(self):
  text=block().replace('    install permissions:\n      android.permission.INTERNET: granted=true\n      android.permission.ACCESS_LOCAL_NETWORK: granted=false, flags=[ SYSTEM_FIXED ]\n      android.permission.ACCESS_LOCAL_NETWORK: granted=true, flags=[ USER_SET ], userId=11\n','')
  r,v,p=self.reduce(text+trailer());self.assertEqual(r.returncode,0);self.assertIsNone(p[P+'INTERNET']['install_scope_granted'])
  text=block().replace('        android.permission.ACCESS_LOCAL_NETWORK: granted=true, flags=[ USER_SET ]\n','')
  r,v,p=self.reduce(text+trailer());self.assertEqual(r.returncode,0);self.assertIsNone(p[P+'ACCESS_LOCAL_NETWORK']['runtime_owner11_granted']);self.assertTrue(p[P+'ACCESS_LOCAL_NETWORK']['install_owner11_override_granted'])
 def test_wrong_or_missing_owner_and_runtime_header_are_incomplete(self):
  for text in (block().replace('    User 11:','    User 10:'),block().replace('      runtime permissions:\n        android.permission.ACCESS_LOCAL_NETWORK: granted=true, flags=[ USER_SET ]\n        android.permission.BLUETOOTH_SCAN: granted=false\n',''),block().replace('    requested permissions:','    unknown permissions:')):
   self.refused(text+trailer())
  self.refused(block()+trailer(),owner='0')
 def test_duplicate_packages_headers_user_and_whitelist_rows_refuse(self):
  for text in (
   block()+block(),
   block().replace('Queries:', '  Package ['+PKG+'] (ef01):\nQueries:'),
   block().replace('Queries:', '  Package [foreign.pkg] (ef01):\nQueries:'),
   block().replace('    User 11:', '    User 0: installed=true\n    User 11:'),
   block().replace('      android.permission.BLUETOOTH_SCAN\n','      android.permission.BLUETOOTH_SCAN\n      android.permission.BLUETOOTH_SCAN\n'),
   block().replace('      android.permission.INTERNET: granted=true\n','      android.permission.INTERNET: granted=true\n      android.permission.INTERNET: granted=true\n'),
   block().replace('        android.permission.BLUETOOTH_SCAN: granted=false\n','        android.permission.BLUETOOTH_SCAN: granted=false\n        android.permission.BLUETOOTH_SCAN: granted=true\n')):
   self.refused(text+trailer())
 def test_malformed_scoped_grants_flags_or_headers_refuse(self):
  for text in (block().replace('granted=true','granted=PRIVATE_CONTENT'),block().replace('flags=[ USER_SET ]','flags=[ USER_SET ], other=PRIVATE_CONTENT'),block().replace(', userId=11',', userId=0'),block().replace('    User 11: installed=true','    User 011: installed=true'),block().replace('    User 11: installed=true hidden=false','    User 11:'),block().replace('    User 11: installed=true hidden=false','    User 11: installed=true installed=false'),block().replace('Package ['+PKG+'] (ab12):','Package ['+PKG+'] (PRIVATE_CONTENT):')):
   self.refused(text+trailer())
 def test_framing_nonzero_producer_and_mid_scope_truncation_never_guess(self):
  for text in (block(),block()+trailer(nonce='a'*32),block()+trailer()+trailer(),block()+trailer()+'after\n',block().split('Queries:')[0]+trailer(),block().split('    User 11:')[0]+trailer()):
   self.refused(text)
  value=self.refused(block()+trailer(137));self.assertEqual(value['status'],'producer_failed');self.assertEqual(value['producer_exit_code'],137)
 def test_budgets_and_invalid_arguments_export_no_raw_values(self):
  for text in ('x'*8193+'\n'+block()+trailer(),'x\n'*32769+block()+trailer(),('x'*4096+'\n')*1024+block()+trailer(),block().replace('PRIVATE_METADATA','PRIVATE\x00CONTENT')+trailer()):self.refused(text)
  self.refused(block()+trailer(),package='PRIVATE_CONTENT')
  self.refused(block()+trailer(),nonce='PRIVATE_CONTENT')
if __name__=='__main__':unittest.main()
