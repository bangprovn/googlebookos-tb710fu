#!/usr/bin/env python3
"""Self-contained host boundary fixtures; real captures never receive invented events."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('gpu_phase_report', ROOT/'scripts/report-gpu-idle-phases.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
BOOT = '12345678-1234-1234-1234-123456789abc'
IDENTITY = dict(pid=123, uid=1110248, startticks=999)
N = 1_000_000_000

def framework(t, **updates):
    value = dict(observed=True, start_uptime_ns=t*N, end_uptime_ns=t*N+100_000_000,
                 framework_wakefulness='Awake', keyguard_showing=False,
                 terminal_package_foreground_service_observed=True)
    value.update(updates); return value

def sample(t, ticks, **updates):
    value = dict(uptime_ns=t*N, utime=ticks, stime=0, tasks=[], tasks_raced=0,
                 framework_state=framework(t))
    value.update(updates); return value

def event(begin, settled, mode):
    return dict(transition_begin_uptime_ns=begin*N, mode_observed_uptime_ns=settled*N, mode=mode)

class PhaseReport(unittest.TestCase):
    def fixture(self, folder, rows=None, result_updates=None):
        folder.mkdir()
        result = dict(schema_version=2, status='observed_cpu_capture_trace_unknown', error_code=None,
                      boot_id=BOOT, identity=IDENTITY, hz=100, record_count=0,
                      host_adb_children_reaped=True)
        result.update(result_updates or {})
        (folder/'result.json').write_text(json.dumps(result))
        (folder/'cpu.json').write_text(json.dumps(dict(samples=rows or [sample(10, 0), sample(20, 100)], intervals=[])))
        (folder/'records.json').write_text('[]\n')
        return folder

    def transitions(self, folder, events):
        path = folder/'explicit-synthetic-events.json'
        path.write_text(json.dumps(dict(schema_version=1, boot_id=BOOT, identity=IDENTITY, mode_events=events)))
        return path

    def test_zero_trace_cpu_retained_unknown_mode_never_continuous(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.fixture(Path(d)/'capture'); value=M.report(p)
            self.assertEqual(value['cpu']['process_cpu_seconds'], 1)
            self.assertEqual(value['cpu']['percent_one_core'], 10)
            self.assertEqual(value['trace']['coverage'], 'unknown_no_new_records')
            self.assertEqual(value['intervals'][0]['declared_mode'], 'unknown')
            self.assertFalse(value['intervals'][0]['endpoint_correlation_candidate'])
            self.assertFalse(value['continuous_awake_idle_qualified'])
            self.assertFalse(value['continuous_phase_mode_qualified'])
            self.assertFalse(value['explicit_mode_events_supplied'])
            self.assertFalse(value['device_contacted'])

    def test_only_explicit_settled_modes_excluding_transition_windows(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.fixture(Path(d)/'capture', [sample(t, (t-10)*10) for t in (10,20,30,40,50)])
            events=self.transitions(Path(d), [event(0,0,'tty'), event(25,28,'desktop'), event(45,47,'tty')])
            value=M.report(p,events)
            self.assertEqual([v['endpoint_correlation_candidate'] for v in value['intervals']], [True,False,True,False])
            self.assertEqual([v['declared_mode'] for v in value['intervals']], ['tty','unknown','desktop','unknown'])
            self.assertEqual(value['declared_mode_endpoint_groups']['tty']['interval_count'],1)
            self.assertEqual(value['declared_mode_endpoint_groups']['desktop']['interval_count'],1)
            self.assertEqual(value['cpu']['interval_count'],4)
            self.assertTrue(all(not v['continuous_awake_or_mode_verified'] for v in value['intervals']))

    def test_state_lag_and_exact_transition_boundary_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            p=self.fixture(Path(d)/'capture')
            path=self.transitions(Path(d),[event(0,0,'tty'), event(20,21,'desktop')])
            # CPU finishes at20 but second framework query finishes20.1: not a tty group.
            self.assertFalse(M.report(p,path)['intervals'][0]['endpoint_correlation_candidate'])
            data=json.loads(path.read_text());data['mode_events'][1]['transition_begin_uptime_ns']=20*N+100_000_000
            path.write_text(json.dumps(data))
            self.assertFalse(M.report(p,path)['intervals'][0]['endpoint_correlation_candidate'])
            data['mode_events'][1]['transition_begin_uptime_ns']+=1;path.write_text(json.dumps(data))
            self.assertTrue(M.report(p,path)['intervals'][0]['endpoint_correlation_candidate'])

    def test_unknown_locked_asleep_fgs_and_unobserved_excluded_cpu_kept(self):
        states=[framework(10,framework_wakefulness='Asleep'),framework(10,keyguard_showing=True),
                framework(10,keyguard_showing=None),framework(10,terminal_package_foreground_service_observed=False),
                framework(10,terminal_package_foreground_service_observed=None),None,
                dict(observed=False,framework_wakefulness='unknown',keyguard_showing=None,
                     terminal_package_foreground_service_observed=None)]
        for state in states:
            with self.subTest(state=state),tempfile.TemporaryDirectory() as d:
                a=sample(10,0)
                if state is None:del a['framework_state']
                else:a['framework_state']=state
                p=self.fixture(Path(d)/'capture',[a,sample(20,100)])
                path=self.transitions(Path(d),[event(0,0,'tty')]);value=M.report(p,path)
                self.assertEqual(value['cpu']['process_cpu_seconds'],1)
                self.assertFalse(value['intervals'][0]['endpoint_correlation_candidate'])
                self.assertEqual(value['declared_mode_endpoint_groups']['tty']['interval_count'],0)

    def test_overlapping_state_queries_and_incomplete_capture_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            a=sample(10,0,framework_state=framework(10,end_uptime_ns=22*N))
            p=self.fixture(Path(d)/'capture',[a,sample(20,100)])
            path=self.transitions(Path(d),[event(0,0,'tty')]);value=M.report(p,path)
            self.assertIn('state_windows_overlap_cpu_boundary',value['intervals'][0]['excluded_reasons'])
            self.assertEqual(value['cpu']['process_cpu_seconds'],1)
        for changes in [dict(status='incomplete',error_code='trace_cleanup_failed'),dict(host_adb_children_reaped=False)]:
            with tempfile.TemporaryDirectory() as d:
                p=self.fixture(Path(d)/'capture',result_updates=changes);path=self.transitions(Path(d),[event(0,0,'tty')])
                value=M.report(p,path);self.assertFalse(value['source_capture_complete'])
                self.assertFalse(value['intervals'][0]['endpoint_correlation_candidate'])
                self.assertEqual(value['cpu']['process_cpu_seconds'],1)

    def test_explicit_event_identity_schema_order_budget_and_mode_fail_closed(self):
        base=dict(schema_version=1,boot_id=BOOT,identity=IDENTITY,mode_events=[event(0,0,'tty')])
        cases=[]
        for k,v in [('boot_id','00000000-0000-0000-0000-000000000000'),('identity',dict(IDENTITY,pid=124)),
                    ('mode_events',[event(2,1,'tty')]),('mode_events',[event(0,2,'tty'),event(1,3,'desktop')]),
                    ('mode_events',[event(2,2,'tty'),event(1,1,'desktop')]),('mode_events',[event(1,1,'serial')]),
                    ('mode_events',[event(t,t,'tty') for t in range(17)])]:
            a=copy.deepcopy(base);a[k]=v;cases.append(a)
        a=copy.deepcopy(base);a['serial']='private';cases.append(a)
        a=copy.deepcopy(base);a['mode_events'][0]['mode']=[];cases.append(a)
        for value in cases:
            with self.subTest(value=value),self.assertRaises(M.ReportError):M.events(value,BOOT,IDENTITY)
        self.assertEqual(M.events(None,BOOT,IDENTITY),[])
        self.assertEqual(M.mode_at_window(0,N,[event(2,2,'tty')]),'unknown')

    def test_bounds_privacy_keys_counters_and_cached_summaries(self):
        with tempfile.TemporaryDirectory() as d:
            p=self.fixture(Path(d)/'capture');cpu=json.loads((p/'cpu.json').read_text())
            cpu['intervals']=[dict(process_cpu_ticks=99999999,percent_one_core=999999)]
            (p/'cpu.json').write_text(json.dumps(cpu));self.assertEqual(M.report(p)['cpu']['process_cpu_seconds'],1)
            for update in [dict(utime=-1),dict(tasks_raced=129),dict(uptime_ns=True),dict(serial='private'),
                           dict(framework_state=framework(10,end_uptime_ns=23*N)),
                           dict(framework_state=framework(10,keyguard_showing='private'))]:
                bad=copy.deepcopy(cpu);bad['samples'][0].update(update);(p/'cpu.json').write_text(json.dumps(bad))
                with self.subTest(update=update),self.assertRaises(M.ReportError):M.report(p)
            for rows in [[sample(20,100),sample(10,0)],[sample(10,100),sample(20,0)],
                         [sample(10,0,stime=100),sample(20,200,stime=0)],
                         [sample(10,0)]*38]:
                bad=copy.deepcopy(cpu);bad['samples']=rows;(p/'cpu.json').write_text(json.dumps(bad))
                with self.assertRaises(M.ReportError):M.report(p)
            task=dict(tid=1,startticks=1,utime=0,stime=0,gpu_worker=False)
            for tasks in [[task,task],[dict(task,tid=t+1) for t in range(129)]]:
                bad=copy.deepcopy(cpu);bad['samples'][0]['tasks']=tasks;(p/'cpu.json').write_text(json.dumps(bad))
                with self.assertRaises(M.ReportError):M.report(p)

    def test_real_v2_and_v3_cpu_only_readonly_without_invented_events(self):
        base=ROOT/'artifacts/device/first-boot-20261013'
        expected=[('gpu-idle-runtime-install-20261020-v1/original-vm-trace-v2',3,14.39,100830000000),
                  ('gpu-idle-runtime-install-20261020-v1/native-state-after-audio-v1',0,0.38,30060000000),
                  ('usb-awake-fixture-20261020-v3/native-awake-cpu-v1',0,0.37,30040000000)]
        for name, count, seconds, duration in expected:
            p=base/name
            if not p.is_dir():self.skipTest('optional local device evidence unavailable; synthetic boundary tests remain self-contained')
            before={n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ('result.json','cpu.json','records.json')}
            value=M.report(p)
            self.assertEqual(value['trace']['source_record_count'],count)
            self.assertGreater(value['cpu']['process_cpu_seconds'],0)
            if seconds is not None:
                self.assertEqual(value['cpu']['process_cpu_seconds'],seconds)
                self.assertEqual(value['cpu']['elapsed_uptime_ns'],duration)
            self.assertFalse(value['explicit_mode_events_supplied']);self.assertEqual(value['mode_events'],[])
            self.assertFalse(value['continuous_awake_idle_qualified'])
            self.assertFalse(value['natural_idle_qualified'])
            self.assertEqual(value['power_conditions'],'not_inferred_from_capture_or_directory')
            self.assertTrue(all(v['declared_mode']=='unknown' and not v['endpoint_correlation_candidate'] for v in value['intervals']))
            if count==0:self.assertEqual(value['trace']['coverage'],'unknown_no_new_records')
            self.assertEqual(before,{n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in before})

    def test_json_file_caps_duplicate_nonfinite_symlink_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.json'
            for body in ['{"schema_version":1,"schema_version":2}', '{"x":NaN}', 'x'*101]:
                p.write_text(body)
                with self.assertRaises(M.ReportError):M.read_json(p,100)
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(M.ReportError):M.read_json(link,100)
            out=Path(d)/'output.json';M.publish(out,dict(status='synthetic'))
            with self.assertRaises(FileExistsError):M.publish(out,dict(status='changed'))
            self.assertEqual(json.loads(out.read_text()),dict(status='synthetic'))

    def test_cli_has_no_device_processes_and_refusal_never_exports_input(self):
        with tempfile.TemporaryDirectory() as d:
            p=self.fixture(Path(d)/'capture');out=Path(d)/'report.json'
            command=[sys.executable,str(ROOT/'scripts/report-gpu-idle-phases.py'),'--capture',str(p),'--output',str(out)]
            run=subprocess.run(command,text=True,capture_output=True,timeout=3)
            self.assertEqual(run.returncode,0,run.stderr);self.assertFalse(json.loads(run.stdout)['device_contacted'])
            (p/'result.json').write_text('{"PRIVATE_SECRET":"NEVER_EXPORT"}')
            run=subprocess.run(command,text=True,capture_output=True,timeout=3)
            self.assertEqual(run.returncode,2);self.assertNotIn('PRIVATE_SECRET',run.stdout+run.stderr)
            self.assertNotIn('NEVER_EXPORT',run.stdout+run.stderr)
            text=(ROOT/'scripts/report-gpu-idle-phases.py').read_text()
            self.assertNotIn('import subprocess',text);self.assertNotIn('os.system',text)

if __name__=='__main__':unittest.main()
