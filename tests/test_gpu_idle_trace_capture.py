#!/usr/bin/env python3
"""Host-only strict schema, real shell-filter/bounds and fake-ADB lifetime tests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('gpu_trace_capture',ROOT/'scripts/collect-gpu-idle-trace.py')
M=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=M;SPEC.loader.exec_module(M)
BOOT='12345678-1234-1234-1234-123456789abc';UID=1110248
IDENT=dict(pid=123,uid=UID,startticks=1000)
def record(ordinal=1):
 return dict(schema_version=1,scope='worker_event_counters',record=ordinal,final_record=False,
 elapsed_ms=5000,waits=10,empty_waits=0,quick_waits_le_100us=2,wait_ns=1000,work_ns=2000,
 readable_tokens={k:0 for k in M.TOKENS},queue_progress_batches=dict(ctrl=1,cursor=0),
 flip_pending_peak=2,flip_retired=3,cpu_usage_measured=False)
def encoded(v):return json.dumps(v,separators=(',',':'))
class Clock:
 def __init__(self):self.t=0
 def now(self):return self.t
 def sleep(self,_):self.t+=1
class Stream:
 def __init__(self,rows):self.rows=rows;self.n=0;self.closed=False
 def lines(self):
  self.n+=1
  if self.n==1:return ['READY\t'+BOOT+'\t1000.000000000']
  if self.n==2:return self.rows
  return []
 def close(self):self.closed=True
class FakeADB:
 def __init__(self,clock,rows=None,existing=False,fail_sample=False,close_fail=False):
  self.clock=clock;self.probes=0;self.existing=existing;self.fail_sample=fail_sample;self.close_fail=close_fail
  self.trace=Stream(rows if rows is not None else ['TRACE\t1000.100000\t123\t124\t'+encoded(record())])
 def probe(self):
  self.probes+=1
  return ('BASE\t'+BOOT+'\t100\t9.00\n'+('IDENT\t123\t'+str(UID)+'\t1000\n' if self.existing or self.probes>1 else '')).encode()
 def stream(self,uid,seconds):
  assert uid==UID and seconds==10
  if self.close_fail:
   def fail():raise M.CaptureError('mock_cleanup_failed')
   self.trace.close=fail
  return self.trace
 def sample(self,pid):
  assert pid==123
  if self.fail_sample:raise M.CaptureError('device_command_failed')
  t=self.clock.t
  return (f'SAMPLE\t{BOOT}\t123\t{UID}\t1000\t100\t{10+t}.00\t{100+100*t}\t0\n'
          f'TASK\t124\t1000\t{100*t}\t0\t1\nEND\t0\n').encode()
class Capture(unittest.TestCase):
 def test_exact_schema_and_privacy_rejections(self):
  good=record();self.assertEqual(M.parse_record(encoded(good)),good)
  negatives=[]
  for k,v in [('serial','secret'),('scope','other'),('cpu_usage_measured',True),('schema_version',True),('record',17),('wait_ns',-1),('work_ns',1<<64),('final_record',0),('elapsed_ms',M.U64)]:
   bad=copy.deepcopy(good);bad[k]=v;negatives.append(encoded(bad))
  for field in ['readable_tokens','queue_progress_batches']:
   bad=copy.deepcopy(good);bad[field]['unknown']='secret';negatives.append(encoded(bad))
   bad=copy.deepcopy(good);key=next(iter(bad[field]));bad[field][key]=False;negatives.append(encoded(bad))
  negatives += ['{"record":1,"record":2}',encoded(good).replace('"wait_ns":1000','"wait_ns":NaN'),encoded(good)+' '*2048,'[]']
  for text in negatives:
   with self.subTest(text=text[:40]),self.assertRaises(M.CaptureError):M.parse_record(text)
 def test_probe_and_sample_lifetime_task_bounds(self):
  adb=FakeADB(Clock());hz,_,ids=M.parse_probe(adb.probe(),BOOT,UID);self.assertEqual((hz,ids),(100,[]))
  value=M.parse_sample(adb.sample(123),BOOT,IDENT,100);self.assertTrue(value['tasks'][0]['gpu_worker'])
  for change in [('123\t'+str(UID)+'\t1000','123\t'+str(UID)+'\t1001'),(BOOT,'00000000-0000-0000-0000-000000000000'),('TASK\t124','TASK\t0')]:
   with self.assertRaises(M.CaptureError):M.parse_sample(adb.sample(123).replace(change[0].encode(),change[1].encode()),BOOT,IDENT,100)
  data=adb.sample(123).replace(b'END\t0\n',b'TASK\t124\t1000\t0\t0\t1\nEND\t0\n')
  with self.assertRaises(M.CaptureError):M.parse_sample(data,BOOT,IDENT,100)
 def test_fake_adb_prearmed_cpu_is_not_trace_walltime(self):
  with tempfile.TemporaryDirectory() as d:
   clock=Clock();adb=FakeADB(clock);out=Path(d)/'capture';result=M.collect(M.Config(BOOT,UID,10,out),adb,clock)
   self.assertEqual(result['status'],'observed_diagnostic_capture');self.assertTrue(adb.trace.closed)
   self.assertEqual(result['identity'],IDENT);self.assertFalse(result['all16_ordinals_observed'])
   self.assertEqual(result['early_coverage'],'ordinal1_observed');cpu=json.loads((out/'cpu.json').read_text())
   self.assertTrue(cpu['intervals']);self.assertEqual(cpu['intervals'][0]['percent_one_core'],100)
   self.assertEqual(cpu['intervals'][0]['tasks'][0]['percent_one_core'],100)
   self.assertFalse(json.loads((out/'records.json').read_text())[0]['counters']['cpu_usage_measured'])
 def test_fake_adb_empty_current_disappearance_and_cleanup_fail_closed(self):
  cases=[dict(existing=True),dict(fail_sample=True),dict(close_fail=True),dict(rows=['TRACE\t1000.100000\t999\t124\t'+encoded(record())]),dict(rows=['TRACE\t1000.100000\t123\t124\t'+encoded(record())]*2)]
  for index,options in enumerate(cases):
   with tempfile.TemporaryDirectory() as d:
    clock=Clock();adb=FakeADB(clock,**options);out=Path(d)/str(index);value=M.collect(M.Config(BOOT,UID,10,out),adb,clock)
    self.assertEqual(value['status'],'incomplete')
    if options.get('close_fail'):self.assertFalse(value['host_adb_children_reaped'])
    else:self.assertFalse(value['cpu_measured_from_proc_ticks'])
  with tempfile.TemporaryDirectory() as d:
   clock=Clock();adb=FakeADB(clock,existing=True,rows=['TRACE\t1000.100000\t123\t124\t'+encoded(record(8))]);value=M.collect(M.Config(BOOT,UID,10,Path(d)/'current',IDENT),adb,clock)
   self.assertEqual(value['status'],'observed_diagnostic_capture');self.assertEqual(value['early_coverage'],'unknown')
 def test_task_tid_reuse_not_differenced(self):
  adb=FakeADB(Clock());a=M.parse_sample(adb.sample(123),BOOT,IDENT,100);b=copy.deepcopy(a);b.update(uptime_ns=a['uptime_ns']+1000000000,utime=a['utime']+100);b['tasks'][0]['startticks']+=1
  self.assertEqual(M.cpu_intervals([a,b],100)[0]['tasks'],[])
 def test_real_shell_filter_on_device_shape_and_caps(self):
  script=M.trace_script(UID,10)
  for forbidden in ['/cmdline','/maps','/environ','logcat -c','am start','reboot','settings put']:self.assertNotIn(forbidden,script+M.probe_script()+M.snapshot_script(123))
  for s in [script,M.probe_script(),M.snapshot_script(123)]:
   q=subprocess.run(['sh','-n'],input=s,text=True,capture_output=True,timeout=3);self.assertEqual(q.returncode,0,q.stderr)
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);logcat=p/'logcat';logcat.write_text('#!/usr/bin/env python3\nimport os,sys\nassert "--max-count=16" in sys.argv and "--uid='+str(UID)+'" in sys.argv\nsys.stdout.write(open(os.environ["FIXTURE"]).read())\n');logcat.chmod(0o700)
   fixed=script.replace('boot=$(cat /proc/sys/kernel/random/boot_id)', 'boot='+BOOT).replace('since=$(date +%s.%N)','since=1000.000000000')
   fixture=p/'fixture';fixture.write_text('1000.000000 999 999 I secret: NEVER_TRANSPORT\n1000.100000 123 124 I crosvm: '+M.PREFIX+encoded(record())+'\n')
   env=dict(os.environ,PATH=d+':'+os.environ['PATH'],FIXTURE=str(fixture));q=subprocess.run(['sh'],input=fixed,text=True,capture_output=True,env=env,timeout=4)
   self.assertEqual(q.returncode,0,q.stderr);self.assertNotIn('NEVER_TRANSPORT',q.stdout);self.assertIn('TRACE\t1000.100000\t123\t124\t{',q.stdout)
   fixture.write_text('1000.100000 123 124 I crosvm: '+M.PREFIX+'x'*3000+'\n');q=subprocess.run(['sh'],input=fixed,text=True,capture_output=True,env=env,timeout=4)
   self.assertNotIn('x'*100,q.stdout);self.assertIn('ERROR\trecord_size',q.stdout)
 def test_framework_state_schema_and_cpu_only_trace_unknown(self):
  adb=FakeADB(Clock()); original=adb.sample(123)
  state=b'STATE\t10.00\t10.50\tAwake\tfalse\ttrue\n'
  sample=M.parse_sample(original.replace(b'END\t0',state+b'END\t0'),BOOT,IDENT,100)
  self.assertEqual(sample['framework_state']['framework_wakefulness'],'Awake')
  self.assertIs(sample['framework_state']['keyguard_showing'],False)
  self.assertIs(sample['framework_state']['terminal_package_foreground_service_observed'],True)
  self.assertFalse(M.parse_sample(original,BOOT,IDENT,100)['framework_state']['observed'])
  too_many=original.split(b'TASK')[0]+b''.join(f'TASK\t{n}\t1000\t0\t0\t0\n'.encode() for n in range(1,130))+b'END\t0\n'
  with self.assertRaisesRegex(M.CaptureError,'task_count_cap'):M.parse_sample(too_many,BOOT,IDENT,100)
  for wrong in [b'STATE\t10.00\t10.50\tserial\tfalse\ttrue\n',
                b'STATE\t10.00\t10.50\tAwake\tidentifier\ttrue\n',
                b'STATE\t10.00\t10.50\tAwake\tfalse\t1\n',
                b'STATE\t9.00\t10.50\tAwake\tfalse\ttrue\n',
                b'STATE\t10.00\t22.01\tAwake\tfalse\ttrue\n',state+state]:
   with self.subTest(wrong=wrong),self.assertRaises(M.CaptureError):
    M.parse_sample(original.replace(b'END\t0',wrong+b'END\t0'),BOOT,IDENT,100)
  unknown=M.parse_sample(original.replace(b'END\t0',b'STATE\t10.00\t10.00\tunknown\tunknown\tunknown\nEND\t0'),BOOT,IDENT,100)
  self.assertIsNone(unknown['framework_state']['keyguard_showing'])
  after=copy.deepcopy(sample);after.update(uptime_ns=11_000_000_000,utime=sample['utime']+100)
  interval=M.cpu_intervals([sample,after],100)[0]
  self.assertFalse(interval['framework_state_continuous']);self.assertEqual(interval['framework_state_before'],sample['framework_state'])
  with tempfile.TemporaryDirectory() as d:
   clock=Clock();adb=FakeADB(clock,rows=[],existing=True);out=Path(d)/'cpu-only'
   def sample_unknown(pid):
    raw=FakeADB.sample(adb,pid);t=10+clock.t
    return raw.replace(b'END\t0',f'STATE\t{t}.00\t{t}.01\tunknown\tunknown\tunknown\nEND\t0'.encode())
   adb.sample=sample_unknown
   value=M.collect(M.Config(BOOT,UID,10,out,IDENT),adb,clock)
   self.assertEqual(value['status'],'observed_cpu_capture_trace_unknown');self.assertIsNone(value['error_code'])
   self.assertTrue(value['cpu_measured_from_proc_ticks']);self.assertEqual(value['trace_coverage'],'unknown_no_new_records')
   self.assertTrue(json.loads((out/'cpu.json').read_text())['intervals'])
 def test_actual_framework_reducers_redact_and_preserve_unknown(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);fake=p/'dumpsys'
   fake.write_text('#!/usr/bin/env python3\nimport os,sys\na=sys.argv[1:]\nassert a in [["power"],["window","policy"],["activity","services","--user","11","com.android.virtualization.terminal"]]\nkey=a[0].upper()\nprint(os.environ[key])\nsys.exit(int(os.environ.get(key+"_EXIT","0")))\n');fake.chmod(0o700)
   env=dict(os.environ,PATH=d+':'+os.environ['PATH'],POWER='SECRETPOWER mWakefulness=Awake\nmWakefulness=0',WINDOW='SECRETWINDOW\nKeyguardServiceDelegate\n showing=false',ACTIVITY='SECRET_COMPONENT isForeground=true foregroundId=99')
   def run(**changes):
    e=dict(env);e.update(changes)
    q=subprocess.run(['sh'],input='uid=1110248\n'+M.state_script(),text=True,capture_output=True,env=e,timeout=4)
    self.assertEqual(q.returncode,0,q.stderr);self.assertEqual(q.stderr,'');self.assertNotIn('SECRET',q.stdout)
    parts=q.stdout.strip().split('\t');self.assertEqual(len(parts),6);return parts[3:]
   self.assertEqual(run(),['Awake','false','true'])
   self.assertEqual(run(POWER='mWakefulness=Asleep\nmWakefulness=0',WINDOW='KeyguardServiceDelegate\n showing=true',ACTIVITY='isForeground=false'),['Asleep','true','false'])
   self.assertEqual(run(POWER='mWakefulness=Awake\nmWakefulness=Asleep',WINDOW='unexpected showing=true',ACTIVITY='(nothing)'),['unknown']*3)
   self.assertEqual(run(POWER_EXIT='124',WINDOW_EXIT='1',ACTIVITY_EXIT='124'),['unknown']*3)
   for value in ['Dozing','Dreaming']:
    self.assertEqual(run(POWER='mWakefulness='+value)[0],value)
   self.assertEqual(run(WINDOW='KeyguardServiceDelegate\n'+'unknown\n'*65+'showing=true')[1],'unknown')
   self.assertEqual(run(POWER='mWakefulness=unexpectedIdentifier',WINDOW='KeyguardServiceDelegate\n showing=secret',ACTIVITY='isForeground=secret'),['unknown']*3)
 def test_actual_adb_protocol_writes_eof_and_constructor_failure_is_reaped(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'fake-adb';p.write_text('#!/usr/bin/env python3\nimport sys\nassert sys.argv[1:]==["-s","HOST_MOCK","shell","-T","sh"]\nbody=sys.stdin.read()\nassert body.startswith("# GB_GPU_CAPTURE_PROBE_V1")\nprint("BASE\\t'+BOOT+'\\t100\\t9.00")\n');p.chmod(0o700)
   adb=M.ADB(str(p),'HOST_MOCK');self.assertEqual(adb.command[-3:],['shell','-T','sh'])
   self.assertEqual(M.parse_probe(adb.probe(),BOOT,UID),(100,9000000000,[]))
  for fail_at in ['write','close']:
   fake=mock.Mock();fake.poll.return_value=None;fake.wait.return_value=0
   if fail_at=='write':fake.stdin.write.side_effect=BrokenPipeError()
   else:fake.stdin.close.side_effect=[BrokenPipeError(),None]
   with mock.patch.object(M.subprocess,'Popen',return_value=fake),mock.patch.object(M.os,'killpg') as killed:
    with self.assertRaises(BrokenPipeError):M.TraceStream(['fake'], 'body')
    killed.assert_called_once_with(fake.pid,M.signal.SIGKILL);fake.wait.assert_called_once_with(timeout=5);fake.stdout.close.assert_called_once()
  fake=mock.Mock();fake.stdin.write.side_effect=BrokenPipeError();fake.poll.return_value=None;fake.wait.return_value=0
  with mock.patch.object(M.subprocess,'Popen',return_value=fake),mock.patch.object(M.os,'killpg') as killed:
   with self.assertRaises(BrokenPipeError):M.bounded(['fake'],'body')
   killed.assert_called_once_with(fake.pid,M.signal.SIGKILL);fake.wait.assert_called_once_with(timeout=5)
  with tempfile.TemporaryDirectory() as d:
   clock=Clock();adb=FakeADB(clock)
   def failed_constructor(*_):raise M.CaptureError('trace_constructor_cleanup_failed')
   adb.stream=failed_constructor
   value=M.collect(M.Config(BOOT,UID,10,Path(d)/'failed'),adb,clock)
   self.assertEqual(value['status'],'incomplete');self.assertFalse(value['host_adb_children_reaped'])
  fake=mock.Mock();fake.stdin.write.side_effect=BrokenPipeError();fake.poll.return_value=None;fake.wait.side_effect=M.subprocess.TimeoutExpired('owned',5)
  with mock.patch.object(M.subprocess,'Popen',return_value=fake),mock.patch.object(M.os,'killpg'):
   with self.assertRaisesRegex(M.CaptureError,'trace_constructor_cleanup_failed'):M.TraceStream(['fake'],'body')
 def test_actual_stat_parser_and_host_subprocess_caps(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'stat';tail=['S']+[str(123 if f==14 else 45 if f==15 else 999 if f==22 else 0) for f in range(4,53)];p.write_text('123 (odd ) comm) '+' '.join(tail)+'\n')
   funcs=M.COMMON[M.COMMON.index('statnums()'):M.COMMON.index('uidof()')]
   q=subprocess.run(['sh'],input=funcs+'\nstatnums "'+str(p)+'" 123\n',text=True,capture_output=True,timeout=3);self.assertEqual((q.returncode,q.stdout),(0,'999 123 45\n'),q.stderr)
  with self.assertRaises(M.CaptureError):M.bounded([sys.executable,'-c','import sys;sys.stdin.read();print("x"*10000)'],'',maximum=1024,timeout=2)
  with self.assertRaises(M.CaptureError):M.bounded([sys.executable,'-c','import time;time.sleep(1)'],'',timeout=.02)
if __name__=='__main__':unittest.main()
