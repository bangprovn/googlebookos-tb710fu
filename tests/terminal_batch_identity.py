#!/usr/bin/env python3
"""Batched identity semantics, synthetic transport only; no ADB invocation."""
from pathlib import Path
import importlib.util,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1];s=importlib.util.spec_from_file_location('batch',ROOT/'crates/gb-tools/src/terminal_ui/batch_identity.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Batch(unittest.TestCase):
 def fixture(self,root,native=True):
  p=dict(serial='fixture',usb_serial_path=str(root/'serial'),android_user=11,android_boot_id='boot',fingerprint='donor',vendor_fingerprint='stock',main_pid=123,main_start_ticks=456,native_pid=789,native_start_ticks=900,uid=1110248);(root/'serial').write_text('fixture\n')
  data=['fixture','2000','Enforcing','11','boot','donor','stock','RUNNING_UNLOCKED']
  if native:data+=['456','1110248','900','1110248','789']
  calls=[]
  class C:
   def shell(self,command,limit):calls.append(command);return '\n'.join(data)
  return p,data,calls,C()
 def test_same_checks_need_one_transport_and_never_read_argv_or_maps(self):
  with tempfile.TemporaryDirectory() as t:
   p,d,c,o=self.fixture(Path(t));m.verify(o,p);self.assertEqual(len(c),1);self.assertNotIn('cmdline',c[0]);self.assertNotIn('/maps',c[0]);self.assertIn('ro.vendor.build.fingerprint',c[0])
 def test_every_observed_identity_field_mismatch_refuses(self):
  for i in range(13):
   with tempfile.TemporaryDirectory() as t,self.subTest(i=i):
    p,d,c,o=self.fixture(Path(t));d[i]='mismatch'
    with self.assertRaises(RuntimeError):m.verify(o,p)
 def test_duplicates_or_missing_process_fields_refuse(self):
  for change in [lambda d:d.pop(),lambda d:d.append('790')]:
   with tempfile.TemporaryDirectory() as t:
    p,d,c,o=self.fixture(Path(t));change(d)
    with self.assertRaises(RuntimeError):m.verify(o,p)
 def test_cleanup_accepts_locked_user_without_querying_dead_native(self):
  with tempfile.TemporaryDirectory() as t:
   p,d,c,o=self.fixture(Path(t),False);d[7]='RUNNING_LOCKED';m.verify(o,p,native=False,unlocked=False);self.assertNotIn('/proc/789/',c[0])
   with self.assertRaises(RuntimeError):m.verify(o,p,native=False,unlocked=True)
 def test_wrong_physical_serial_refuses_before_adb(self):
  with tempfile.TemporaryDirectory() as t:
   p,d,c,o=self.fixture(Path(t));Path(p['usb_serial_path']).write_text('other')
   with self.assertRaises(RuntimeError):m.verify(o,p)
   self.assertEqual(c,[])
if __name__=='__main__':unittest.main()
