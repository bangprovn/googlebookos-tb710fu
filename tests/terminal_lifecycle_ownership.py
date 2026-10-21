#!/usr/bin/env python3
"""Actual donor methods + separate host ownership MODEL. Never launches Android.

Pinned APK is parsed, never executed, in an offline unprivileged Docker sandbox.
Temporary reconstructed methods compile only against explicit Java stand-ins.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'patches/tb710fu/terminal/lifecycle-ownership-model.json'
CASES = ['source_ready_race', 'source_worker_first', 'source_late_error_reset',
         'source_running_missing_service', 'model_ready_and_error', 'model_fatal_unknown',
         'model_stale_callbacks', 'model_foreground_denied', 'model_cancel_pending', 'model_pending_failure',
         'source_framework_status_hidden_failure', 'source_framework_stop_loses_binding',
         'source_framework_stop_success']


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def method(text, signature):
    assert text.count(signature) == 1, signature
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 1
    for i in range(opening + 1, len(text)):
        depth += (text[i] == '{') - (text[i] == '}')
        if not depth:
            return text[start:i + 1]
    raise AssertionError('unterminated pinned method')


class LifecycleOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='gb-terminal-lifecycle-model-')
        cls.out = Path(cls.work.name)
        cls.manifest = json.loads(MANIFEST.read_text())
        for path, expected in (cls.manifest['source_inputs'] | cls.manifest.get('host_inputs', {})).items():
            assert digest(ROOT / path) == expected, path
        d = cls.manifest['decompiler']
        assert digest(ROOT / d['jar']) == d['sha256']
        cls.java = Path(shutil.which('java')).resolve()
        cls.javac = Path(shutil.which('javac')).resolve()
        cls.derived = {}
        cls.parsed_classes = {}
        for entry in cls.manifest['actual_methods']:
            if 'source_path' in entry:
                text = (ROOT / entry['source_path']).read_text()
            elif (entry.get('input_path', cls.manifest['apk_path']), entry['class']) in cls.parsed_classes:
                text = cls.parsed_classes[(entry.get('input_path', cls.manifest['apk_path']), entry['class'])]
            else:
                # No APK binary is executed. Host jadx only parses it. Source/SDK
                # binds are read-only; only fresh bounded temporary output is writable.
                cmd = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
                       '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
                       '--memory=1g', '--cpus=2', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                       '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=128m,mode=1777',
                       '--env=XDG_CONFIG_HOME=/tmp/jadx-config', '--env=XDG_CACHE_HOME=/tmp/jadx-cache',
                       '--env=XDG_DATA_HOME=/tmp/jadx-data']
                for source, target in [(Path('/usr'), '/usr'), (Path('/lib').resolve(), '/lib'),
                                       (Path('/lib64').resolve(), '/lib64'),
                                       (Path('/etc/java-21-openjdk'), '/etc/java-21-openjdk'),
                                       ((ROOT / d['jar']).parent, '/jadx'),
                                       (ROOT / entry.get('input_path', cls.manifest['apk_path']), '/input.apk')]:
                    cmd += ['--mount', 'type=bind,src=' + str(source) + ',dst=' + target + ',readonly']
                cmd += ['--mount', 'type=bind,src=' + str(cls.out) + ',dst=/output',
                        '--entrypoint=' + str(cls.java), d['sandbox_image'], '-Duser.home=/tmp', '-Xmx768m',
                        '-cp', '/jadx/*', 'jadx.cli.JadxCLI', '-r', '-j', '2', '--single-class', entry['class'],
                        '--single-class-output', '/output/' + entry['output'], '/input.apk']
                q = subprocess.run(cmd, capture_output=True, text=True, timeout=55)
                assert q.returncode == 0, q.stderr[-2048:]
                path = cls.out / entry['output']
                assert path.is_file() and path.stat().st_size < 256 * 1024
                text = path.read_text()
                cls.parsed_classes[(entry.get('input_path', cls.manifest['apk_path']), entry['class'])] = text
            body = method(text, entry['signature'])
            assert hashlib.sha256(body.encode()).hexdigest() == entry['sha256'], entry['signature']
            cls.derived[entry['marker']] = body
        fixture = (ROOT / 'tests/fixtures/terminal_lifecycle_ownership.java').read_text()
        for marker, body in cls.derived.items():
            assert fixture.count(marker) == 1
            fixture = fixture.replace(marker, body)
        source = cls.out / 'TerminalLifecycleOwnership.java'
        source.write_text(fixture)
        q = subprocess.run([str(cls.javac), '-Xlint:all', '-Werror', '-d', str(cls.out / 'classes'), str(source)],
                           capture_output=True, text=True, timeout=30)
        assert q.returncode == 0, q.stdout + q.stderr

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def observe(self, case, token='owned-state-only-v1'):
        self.assertIn(case, CASES)
        env = dict(os.environ)
        env.pop('GB_TERMINAL_LIFECYCLE_MODEL_V1', None)
        if token is not None:
            env['GB_TERMINAL_LIFECYCLE_MODEL_V1'] = token
        q = subprocess.run([str(self.java), '-cp', str(self.out / 'classes'),
                            'TerminalLifecycleOwnership', case], capture_output=True, text=True, timeout=5, env=env)
        self.assertEqual((q.returncode, q.stderr), (0, ''), q.stdout + q.stderr)
        self.assertLess(len(q.stdout), self.manifest['maximum_stdout_bytes'])
        value = json.loads(q.stdout)
        self.assertEqual(value['implementation_kind'], 'host_lifecycle_model')
        self.assertFalse(value['runtime_verified'])
        self.assertFalse(value['production_fix_implemented'])
        self.assertLessEqual(len(value['records']), 32)
        for row in value['records']:
            self.assertEqual(set(row), {'event', 'controller_state', 'native_status', 'foreground',
                                        'pending_start', 'blocked', 'stop_requests'})
            self.assertIn(row['native_status'], ['NONE', 'RUNNING', 'UNKNOWN', 'STOPPED'])
        return value

    def test_actual_source_permitted_ready_start_counterexample_and_good_interleaving(self):
        bad = self.observe('source_ready_race')['records']
        self.assertEqual(bad[-1]['event'], 'ready_start_race_counterexample')
        self.assertEqual(bad[-1]['native_status'], 'RUNNING')
        self.assertFalse(bad[-1]['foreground'])
        gate = next(row for row in bad if row['event'] == 'actual_gate_stopped_service')
        self.assertEqual(gate['controller_state'], 'Ready')
        good = self.observe('source_worker_first')['records']
        self.assertTrue(good[-1]['foreground'])

    def test_actual_reset_and_existing_running_attachment_retain_missing_coverage(self):
        bad = self.observe('source_late_error_reset')['records']
        self.assertEqual(bad[-1]['controller_state'], 'Ready')
        self.assertEqual(bad[-1]['native_status'], 'RUNNING')
        self.assertFalse(bad[-1]['foreground'])
        bad = self.observe('source_running_missing_service')['records']
        self.assertFalse(bad[-1]['foreground'])
        self.assertFalse(any(row['event'] == 'actual_service_requested' for row in bad))
        # Error transition is a source-constrained stand-in, not a copied/fixed
        # production method: its reconstructed decompile is not compilable Java.
        entry = next(e for e in self.manifest['actual_methods'] if e['marker'] == '// ACTUAL_RESET')
        text = (ROOT / entry['source_path']).read_text()
        body = method(text, 'public final void handleVmError$packages__modules__Virtualization__android__TerminalApp__android_common_apex10000_p__VmTerminalApp_impl(')
        self.assertIn('loggingMutableStateFlow.setValue(error);', body)
        self.assertIn('value.stop();', body)
        self.assertNotIn('vm.stop()', body)
        self.assertNotIn('virtualMachine = null', body)
        self.assertNotIn('virtualMachine', self.derived['// ACTUAL_RESET'])

    def test_actual_donor_framework_status_and_stop_failure_do_not_prove_native_exit(self):
        hidden = self.observe('source_framework_status_hidden_failure')['records']
        self.assertEqual([row['event'] for row in hidden],
                         ['actual_donor_status_hidden_remote_failure',
                          'actual_donor_ambiguous_status_stop_drops_binding'])
        failed = self.observe('source_framework_stop_loses_binding')['records']
        self.assertEqual(failed[-1]['event'], 'actual_donor_failed_stop_drops_binding')
        self.assertTrue(all(row['native_status'] == 'RUNNING' for row in hidden + failed))
        framework = self.manifest['installed_donor_framework']
        text = (ROOT / framework['derived_source_path']).read_text()
        drop = method(text, 'private void dropVm()')
        self.assertLess(drop.index('this.mVirtualMachine = null;'), drop.index('this.mCleanable.clean();'))
        death_action = method(text, 'private static class DeathAction implements Runnable')
        cleanup = method(death_action, 'public void run()')
        self.assertIn('this.mVirtualMachine.stop();', cleanup)
        self.assertIn('catch (Exception e)', cleanup)
        self.assertNotIn('throw e;', cleanup)
        success = self.observe('source_framework_stop_success')['records']
        self.assertEqual(success[-1]['native_status'], 'STOPPED')

    def test_ownership_model_pending_error_and_status_unknown_are_not_stopped(self):
        for case in ['model_ready_and_error', 'model_cancel_pending', 'model_pending_failure',
                     'model_foreground_denied', 'model_stale_callbacks', 'model_fatal_unknown']:
            value = self.observe(case)
            self.assertTrue(value['enabled'])
        unconfirmed = self.observe('model_ready_and_error')['records']
        raw_stopped = next(row for row in unconfirmed if row['event'] == 'model_unconfirmed_stopped_is_unknown')
        self.assertEqual(raw_stopped['native_status'], 'UNKNOWN')
        self.assertTrue(raw_stopped['foreground'])
        stale = self.observe('model_stale_callbacks')['records']
        ignored = [row for row in stale if row['event'] == 'model_stale_foreground_ack_ignored']
        self.assertEqual(len(ignored), 2)
        self.assertTrue(all(row['pending_start'] and not row['foreground'] for row in ignored))
        rows = self.observe('model_fatal_unknown')['records']
        unknown = next(row for row in rows if row['event'] == 'model_binder_failure_is_unknown')
        self.assertEqual(unknown['native_status'], 'UNKNOWN')
        self.assertTrue(unknown['foreground'])
        blocked = next(row for row in rows if row['event'] == 'model_stop_confirmation_missing')
        self.assertTrue(blocked['blocked'])
        self.assertEqual(blocked['stop_requests'], 1)
        self.assertEqual(len(rows), 32)
        finished = self.observe('model_fatal_unknown')
        self.assertGreater(finished['records_suppressed'], 0)
        self.assertEqual(finished['final_model_state']['native_status'], 'STOPPED')
        self.assertFalse(finished['final_model_state']['foreground'])

    def test_exact_opt_in_and_no_identifiers_or_production_activation(self):
        for token in [None, '', '1', 'owned-state-only-v1 ', ' owned-state-only-v1', 'owned-state-only-v1-extra']:
            value = self.observe('source_ready_race', token)
            self.assertFalse(value['enabled'])
            self.assertEqual(value['records'], [])
            self.assertIsNone(value['final_model_state'])
        fixture = (ROOT / 'tests/fixtures/terminal_lifecycle_ownership.java').read_text()
        for forbidden in ['ProcessBuilder', 'Runtime.getRuntime', 'android.os.', 'System.getProperty',
                          'getSerial', 'readAllBytes', 'logcat', '/proc/', 'getIntent']:
            self.assertNotIn(forbidden, fixture)
        self.assertFalse(self.manifest['apk_instrumented'])
        self.assertFalse(self.manifest['installed'])

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--emit-model-case':
        case = sys.argv[2]
        if case not in CASES:
            raise SystemExit('unknown fixed model scenario')
        if os.environ.get('GB_TERMINAL_LIFECYCLE_MODEL_V1') != 'owned-state-only-v1':
            print(json.dumps(dict(schema_version=1, implementation_kind='host_lifecycle_model',
                                  enabled=False, runtime_verified=False, production_fix_implemented=False)))
        else:
            LifecycleOwnership.setUpClass()
            try:
                value = LifecycleOwnership().observe(case)
                value.update(scenario=case, source_apk_sha256=LifecycleOwnership.manifest['installed_apk_sha256'],
                             actual_method_bodies_verified=len(LifecycleOwnership.manifest['actual_methods']))
                print(json.dumps(value, separators=(',', ':')))
            finally:
                LifecycleOwnership.tearDownClass()
    else:
        unittest.main(verbosity=2)
