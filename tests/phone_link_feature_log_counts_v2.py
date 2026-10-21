#!/usr/bin/env python3
"""Synthetic raw-message framing/privacy tests; no device or real logs."""
from pathlib import Path
import json
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/lib/phone_link_feature_log_counts_v2.awk'
NONCE = '0123456789abcdef0123456789abcdef'
LITERALS = {
    'initial_status_load_entered': 'loadInitialFeatureStatus()',
    'initial_status_listener_registered': 'Successfully registered initial status listener',
    'initial_feature_states_loaded': 'Successfully loaded initial feature states: ',
    'initial_status_register_fetch_failed': 'Failed to register/fetch initial statuses',
    'initial_status_loader_cancelled': 'Initial status loader job cancelled (likely due to broadcast from Multidevice)',
    'initial_status_listener_unregistered': 'Successfully unregistered initial status listener',
    'initial_status_listener_unregister_failed': 'Failed to unregister initial status listener',
    'multidevice_sync_disabled': 'MULTIDEVICE_SYNC is disabled',
}


def frame(code=0, nonce=NONCE):
    return 'GB_PHONE_LINK_FEATURE_LOG_END_V2 ' + nonce + ' ' + str(code) + '\n'


class Tests(unittest.TestCase):
    def reduce(self, text, nonce=NONCE):
        run = subprocess.run(['awk', '-v', 'input_nul_guarded=1', '-v', 'frame_nonce=' + nonce, '-f', str(SCRIPT)],
                             input=text, capture_output=True, text=True, timeout=3,
                             env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertEqual(run.stderr, '')
        value = json.loads(run.stdout)
        self.assertEqual(value['schema_version'], 2)
        self.assertEqual(set(value['counts']), set(LITERALS))
        self.assertLess(len(run.stdout), 1536)
        self.assertNotIn('PRIVATE', run.stdout)
        self.assertNotIn(NONCE, run.stdout)
        for key in ('full_history_verified', 'identity_verified', 'fresh_event_verified',
                    'current_feature_state_verified', 'enrollment_verified',
                    'discovery_verified', 'raw_messages_exported'):
            self.assertIs(value[key], False)
        return run, value

    def test_exact_allowlist_and_private_loaded_map_suffix(self):
        text = '\n'.join(message + ('{PRIVATE_ACCOUNT=PRIVATE_PEER}' if key == 'initial_feature_states_loaded' else '')
                         for key, message in LITERALS.items()) + '\n'
        run, value = self.reduce(text + frame())
        self.assertEqual(run.returncode, 0)
        self.assertEqual(value['counts'], dict.fromkeys(LITERALS, 1))
        self.assertTrue(value['counts_valid'])
        self.assertEqual(value['status'], 'retained_log_counts_observed')

    def test_exact_messages_near_misses_unknown_and_multiplicity(self):
        literal = LITERALS['multidevice_sync_disabled']
        run, value = self.reduce(literal + '\n' + literal + '\n' +
                                 ' ' + literal + '\n' + literal + ' PRIVATE\n' +
                                 'PRIVATE exception account URL\n' + frame())
        self.assertEqual(run.returncode, 0)
        self.assertEqual(value['counts']['multidevice_sync_disabled'], 2)
        self.assertEqual(sum(value['counts'].values()), 2)

    def test_framed_empty_is_zero_with_no_state_proof(self):
        run, value = self.reduce(frame())
        self.assertEqual(run.returncode, 0)
        self.assertTrue(value['producer_complete'])
        self.assertEqual(value['producer_exit_code'], 0)
        self.assertEqual(sum(value['counts'].values()), 0)

    def test_numeric_producer_failure_suppresses_partial_counts(self):
        for code in (1, 2, 124, 137, 255):
            run, value = self.reduce(LITERALS['initial_status_load_entered'] + '\n' + frame(code))
            self.assertEqual(run.returncode, 2)
            self.assertEqual(value['status'], 'producer_failed')
            self.assertTrue(value['producer_complete'])
            self.assertEqual(value['producer_exit_code'], code)
            self.assertFalse(value['counts_valid'])
            self.assertEqual(sum(value['counts'].values()), 0)

    def test_missing_wrong_duplicate_trailing_or_malformed_frame(self):
        for text in ('', 'PRIVATE\n', frame(nonce='a' * 32), frame() + frame(),
                     frame() + '\n', frame() + 'PRIVATE\n', frame('00'),
                     frame(-1), frame(256), frame('0 PRIVATE'),
                     'GB_PHONE_LINK_FEATURE_LOG_END_V2 ' + NONCE + '\n'):
            with self.subTest(text=text):
                run, value = self.reduce(text)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(value['status'], 'framing_refused')
                self.assertFalse(value['counts_valid'])
                self.assertIsNone(value['producer_exit_code'])
                self.assertEqual(sum(value['counts'].values()), 0)

    def test_input_caps_control_bytes_and_invalid_nonce(self):
        for text in ('x' * 8193 + '\n' + frame(), 'x\n' * 4096 + frame(),
                     ('x' * 8191 + '\n') * 32 + frame(),
                     'PRIVATE\r\n' + frame(), 'PRIVATE\x00\n' + frame()):
            run, value = self.reduce(text)
            self.assertEqual(run.returncode, 2)
            self.assertFalse(value['counts_valid'])
        for nonce in ('', 'a' * 31, 'A' * 32, 'a' * 33, 'a' * 31 + 'g'):
            run, value = self.reduce(frame(), nonce)
            self.assertEqual(run.returncode, 2)
            self.assertFalse(value['counts_valid'])

    def test_exact_line_and_line_count_boundaries(self):
        for text in ('x' * 8192 + '\n' + frame(), 'x\n' * 4095 + frame()):
            run, value = self.reduce(text)
            self.assertEqual(run.returncode, 0)
            self.assertTrue(value['counts_valid'])

    def test_real_shell_producer_exit_is_not_masked_by_framing(self):
        # Emulate only the owned producer, not logcat/device I/O. The printf
        # trailer succeeds but must retain the preceding producer's exit7.
        command = ("{ printf '%s\\n' 'loadInitialFeatureStatus()'; (exit 7); "
                   "producer_rc=$?; printf '\\nGB_PHONE_LINK_FEATURE_LOG_END_V2 %s %s\\n' "
                   + shlex.quote(NONCE) + ' "$producer_rc"; } | LC_ALL=C awk -v input_nul_guarded=1 -v frame_nonce='
                   + shlex.quote(NONCE) + ' -f ' + shlex.quote(str(SCRIPT)))
        run = subprocess.run(['sh', '-c', command], capture_output=True, text=True, timeout=3)
        self.assertEqual(run.returncode, 2)
        value = json.loads(run.stdout)
        self.assertEqual(value['status'], 'producer_failed')
        self.assertEqual(value['producer_exit_code'], 7)
        self.assertFalse(value['counts_valid'])
        self.assertEqual(sum(value['counts'].values()), 0)

    def test_missing_or_wrong_filter_contract_refused_before_lines(self):
        for flag in ('', '0', 'true', '01'):
            run = subprocess.run(['awk', '-v', 'input_nul_guarded=' + flag,
                                  '-v', 'frame_nonce=' + NONCE, '-f', str(SCRIPT)],
                                 input=frame(), capture_output=True, text=True, timeout=3)
            self.assertEqual(run.returncode, 2)
            self.assertFalse(json.loads(run.stdout)['counts_valid'])

    def test_actual_source_empty_nul_implementation_accepts_valid_and_tr_rejects_nul(self):
        # Reproduce Android's observed sprintf(%c,0) == empty result without
        # adding a test-only bypass argument to the production reducer.
        source = SCRIPT.read_text()
        self.assertEqual(source.count('nul=sprintf("%c",0)'), 1)
        with tempfile.TemporaryDirectory() as tmp:
            simulated = Path(tmp) / 'nul-unavailable.awk'
            simulated.write_text(source.replace('nul=sprintf("%c",0)', 'nul=""'))
            for injected in (False, True):
                command = ('set -o pipefail; LC_ALL=C tr \'\\000\' \'\\r\' | '
                           'LC_ALL=C awk -v input_nul_guarded=1 -v frame_nonce='
                           + shlex.quote(NONCE) + ' -f ' + shlex.quote(str(simulated)))
                data = LITERALS['initial_status_load_entered'] + '\n'
                if injected:
                    data += 'PRIVATE\x00DATA\n'
                run = subprocess.run(['bash', '-c', command], input=data + frame(),
                                     capture_output=True, text=True, timeout=3)
                value = json.loads(run.stdout)
                self.assertEqual(run.returncode, 2 if injected else 0)
                self.assertEqual(value['counts_valid'], not injected)
                self.assertEqual(value['counts']['initial_status_load_entered'], 0 if injected else 1)
                self.assertNotIn('PRIVATE', run.stdout)

    def test_caller_pipefail_preserves_filter_failure_after_valid_output(self):
        # A failed filter could emit a complete frame before failing. AWK cannot
        # see a predecessor's exit; caller must also refuse the pipeline status.
        command = ('set -o pipefail; printf %s ' + shlex.quote(frame())
                   + " | { LC_ALL=C tr '\\000' '\\r'; exit 9; } | "
                   'LC_ALL=C awk -v input_nul_guarded=1 -v frame_nonce='
                   + shlex.quote(NONCE) + ' -f ' + shlex.quote(str(SCRIPT)))
        run = subprocess.run(['bash', '-c', command], capture_output=True, text=True, timeout=3)
        self.assertEqual(run.returncode, 9)
        self.assertTrue(json.loads(run.stdout)['counts_valid'])
        # This apparently valid JSON is deliberately NOT an accepted query:
        # the owning controller must require both process exit0 and valid JSON.


if __name__ == '__main__':
    unittest.main()
