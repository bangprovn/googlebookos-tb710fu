"""Host-only fixture tests. The apparent ADB executable is a temporary fake."""
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/usb-awake-fixture.py"
HELPER = ROOT / "artifacts/device/first-boot-20261013/auth-bound-key-post-reboot-20261020-v1/controller.py"
spec = importlib.util.spec_from_file_location("usb_awake", SOURCE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class UsbAwake(unittest.TestCase):
    def test_cancel_kills_owned_child_group_without_retaining_output(self):
        event = threading.Event()
        holder = {}
        thread = threading.Thread(target=fixture.child, args=(
            [sys.executable, "-c", "import time;print('discarded fixture');time.sleep(30)"],
            2, event, holder))
        thread.start()
        time.sleep(.1)
        event.set()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(holder['result']['cancelled'])
        self.assertTrue(holder['result']['direct_child_reaped'])
        self.assertEqual(holder['result']['stdout_stderr_retained_bytes'],0)

    def exercise(self, prior, child_action="pass", timeout=1, bad_usb=False, unsupported=False,
                 save_failures=(), fail_after_write=False, plug_kind="usb", duplicate_power=False):
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp)
            boot = "12345678-1234-4234-8234-123456789abc"
            (b / "usb").write_text("FIXTURE")
            mask = fixture.PLUG_MASKS[plug_kind]
            state = dict(value=prior, boot=boot, owner="11", awake="Asleep",
                         plug=str(3-mask) if bad_usb else str(mask))
            (b / "state.json").write_text(json.dumps(state))
            adb = b / "fake-adb"
            adb.write_text(f'''#!/usr/bin/env python3
from pathlib import Path
import sys,json,re
b=Path({str(b)!r});cmd=sys.argv[-1];p=b/'state.json';s=json.loads(p.read_text())
def save():p.write_text(json.dumps(s))
with (b/'commands').open('a') as f:f.write(cmd+'\\n')
fixed={{'getprop ro.serialno':'FIXTURE','id -u':'2000','getenforce':'Enforcing',
 'am get-current-user':s['owner'],'am get-started-user-state 11':'RUNNING_UNLOCKED',
 'getprop ro.build.fingerprint':'fixture-donor','getprop ro.vendor.build.fingerprint':'fixture-vendor'}}
if cmd in fixed:print(fixed[cmd])
elif cmd=='cat /proc/sys/kernel/random/boot_id':print(s['boot'])
elif cmd.startswith('svc power --help'):print({'unsupported help' if unsupported else 'usage: svc power stayon [true|false|usb|ac|wireless]'!r})
elif cmd=='settings get global stay_on_while_plugged_in':print('null' if s['value'] is None else s['value'])
elif cmd.startswith('settings list global'):
 if s['value'] is not None:print('stay_on_while_plugged_in='+s['value'])
elif cmd.startswith('dumpsys power'):
 print('  mWakefulness='+s['awake'])
 for _ in range({3 if duplicate_power else 1}):print('  mIsPowered=true')
 for _ in range({2 if duplicate_power else 1}):print('  mPlugType='+s['plug'])
elif 'svc power stayon {plug_kind}' in cmd:
 if s['boot']!={boot!r} or s['owner']!='11':sys.exit(4)
 s['value']={str(mask)!r};s['awake']='Awake';save()
elif 'settings delete global stay_on_while_plugged_in' in cmd or 'settings put global stay_on_while_plugged_in ' in cmd:
 if s['boot']!={boot!r} or s['owner']!='11' or s['value']!={str(mask)!r}:sys.exit(4)
 if 'settings delete global' in cmd:s['value']=None
 else:s['value']=re.search(r'settings put global stay_on_while_plugged_in (-?[0-9]+)$',cmd)[1]
 save();print('Deleted 1 rows' if s['value'] is None else '')
else:raise SystemExit(3)
''')
            adb.chmod(0o700)
            child = b / "owned-child"
            child.write_text(f'''#!/usr/bin/env python3
from pathlib import Path
import json,time,sys
b=Path({str(b)!r});p=b/'state.json';s=json.loads(p.read_text())
print('ARG_AND_OUTPUT_MUST_NOT_BE_RETAINED');print('CHILD_STDERR_PRIVATE_FIXTURE',file=sys.stderr)
(b/'child-ran').touch()
{child_action}
''')
            child.chmod(0o700)
            config = dict(schema_version=1, kind="normal_power_stay_awake", plug_kind=plug_kind, plug_mask=mask, serial="FIXTURE",
                fingerprint="fixture-donor", vendor_fingerprint="fixture-vendor", android_user=11,
                usb_serial_path=str(b/'usb'), adb=dict(path=str(adb), sha256=fixture.digest(adb)))
            (b/'input.json').write_text(json.dumps(config))
            case = b / "case"
            with patch.object(fixture.subprocess, "Popen", side_effect=AssertionError("offline only")):
                profile = fixture.prepare(b/'input.json', case, HELPER)
            profile_path = case/'profile.json'
            fixture.capture(profile_path, profile['sha256'], case/'context.json')
            original_load = fixture.load
            def load_with_failed_diagnostics(*args):
                h,p = original_load(*args)
                original_save = h.save
                def save(path, value):
                    if Path(path).name in save_failures:
                        if fail_after_write:
                            original_save(path, value)
                        raise OSError("injected diagnostic write failure")
                    return original_save(path, value)
                h.save = save
                return h,p
            with patch.object(fixture, "load", side_effect=load_with_failed_diagnostics):
                code = fixture.run(profile_path, profile['sha256'], case/'context.json',
                    fixture.digest(case/'context.json'), [str(child), 'ARG_AND_OUTPUT_MUST_NOT_BE_RETAINED'],
                    fixture.digest(child), timeout)
            result = (json.loads((case/'result.json').read_text()) if (case/'result.json').exists()
                      else dict(status="no_durable_result", vm_or_guest_queried=False,
                                cpu_or_background_policy_changed=False, suspend_or_idle_verified=False))
            journal = json.loads((case/'prior-setting.json').read_text()) if (case/'prior-setting.json').exists() else None
            final = json.loads((b/'state.json').read_text())
            child_result = json.loads((case/'child-result.json').read_text()) if (case/'child-result.json').exists() else None
            retained = ''.join(p.read_text() for p in case.glob('*.json'))
            self.assertNotIn('ARG_AND_OUTPUT_MUST_NOT_BE_RETAINED', retained)
            self.assertNotIn('CHILD_STDERR_PRIVATE_FIXTURE', retained)
            self.assertFalse(result['vm_or_guest_queried'])
            self.assertFalse(result['cpu_or_background_policy_changed'])
            self.assertFalse(result['suspend_or_idle_verified'])
            with self.assertRaises(FileExistsError):
                fixture.run(profile_path, profile['sha256'], case/'context.json',
                    fixture.digest(case/'context.json'), [str(child)], fixture.digest(child), timeout)
            return code,result,journal,final,child_result,(b/'commands').read_text(),(b/'child-ran').exists()

    def test_ac_power_duplicate_consensus_restores_prior_zero(self):
        code,result,journal,final,child,commands,ran = self.exercise(
            '0', plug_kind="ac", duplicate_power=True)
        self.assertEqual(code,0)
        self.assertTrue(ran)
        self.assertEqual(final['value'],'0')
        self.assertTrue(result['setting_restored'])
        self.assertEqual(result['configured_plug_kind'],'ac')
        self.assertEqual(result['configured_plug_mask'],1)
        self.assertEqual(journal['prior_power']['scalar_observation_counts'],
                         dict(Wakefulness=1,IsPowered=3,PlugType=2))
        self.assertIn('svc power stayon ac',commands)
        self.assertNotIn('svc power stayon usb',commands)
        self.assertIn('settings put global stay_on_while_plugged_in 0',commands)

    def test_actual_filtered_power_shape_consensus_and_conflicts(self):
        class Host:
            text = "  mWakefulness=Awake\n  mIsPowered=true\n  mIsPowered=true\n  mIsPowered=true\n  mPlugType=1\n  mPlugType=1"
            def shell(self,p,command):
                self.assert_command = command
                return self.text
            def require(self,ok,message):
                if not ok:raise RuntimeError(message)
        h=Host()
        observed=fixture.power(h,{})
        self.assertEqual(observed['wakefulness'],'Awake')
        self.assertEqual(observed['plug_type'],1)
        self.assertEqual(observed['scalar_observation_counts'],dict(Wakefulness=1,IsPowered=3,PlugType=2))
        self.assertEqual(h.assert_command,fixture.POWER)
        original=h.text
        for conflicting in ['  mPlugType=2','  mIsPowered=false','  mWakefulness=Asleep']:
            with self.subTest(conflicting=conflicting):
                h.text=original+'\n'+conflicting
                with self.assertRaisesRegex(RuntimeError,'conflicting'):
                    fixture.power(h,{})

    def test_unconfigured_or_broad_plug_masks_refused(self):
        for value in [{},dict(plug_kind='ac',plug_mask=2),dict(plug_kind='true',plug_mask=7),
                      dict(plug_kind='usb',plug_mask=True),dict(plug_kind='ac',plug_mask='1')]:
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):fixture.configured_plug(value)

    def test_success_restores_prior_bitmask_and_does_not_retain_child_data(self):
        code,result,journal,final,child,commands,ran = self.exercise('5')
        self.assertEqual(code,0)
        self.assertEqual(journal['prior'],dict(present=True,value='5'))
        self.assertEqual(final['value'],'5')
        self.assertTrue(result['setting_restored'])
        self.assertEqual(child['stdout_stderr_retained_bytes'],0)
        self.assertTrue(child['direct_child_reaped'])
        self.assertIn('svc power --help',commands)
        self.assertNotIn('input keyevent',commands)

    def test_unset_null_is_valid_and_exactly_deleted_after_child_failure(self):
        code,result,journal,final,child,commands,ran = self.exercise(None,'raise SystemExit(7)')
        self.assertEqual(code,2)
        self.assertEqual(journal['prior'],dict(present=False,value=None))
        self.assertIsNone(final['value'])
        self.assertTrue(result['setting_restored'])
        self.assertIn('settings delete global',commands)

    def test_child_timeout_is_bounded_and_prior_zero_restored(self):
        code,result,journal,final,child,commands,ran = self.exercise('0','time.sleep(30)',.15)
        self.assertEqual(code,2)
        self.assertTrue(child['timed_out'])
        self.assertTrue(child['direct_child_reaped'])
        self.assertLess(child['seconds'],2)
        self.assertEqual(final['value'],'0')
        self.assertTrue(result['setting_restored'])

    def test_external_value_change_is_not_overwritten(self):
        code,result,journal,final,child,commands,ran = self.exercise('0',"s['value']='4';p.write_text(json.dumps(s))")
        self.assertEqual(code,2)
        self.assertFalse(result['setting_restored'])
        self.assertEqual(final['value'],'4')
        self.assertNotIn('settings put global stay_on_while_plugged_in 0',commands)

    def test_reboot_or_owner_change_refuses_restoration_to_wrong_context(self):
        for action in ("s['boot']='23456789-1234-4234-8234-123456789abc';p.write_text(json.dumps(s))",
                       "s['owner']='12';p.write_text(json.dumps(s))"):
            with self.subTest(action=action):
                code,result,journal,final,child,commands,ran = self.exercise('0',action)
                self.assertEqual(code,2)
                self.assertFalse(result['setting_restored'])
                self.assertEqual(final['value'],'2')
                self.assertNotIn('settings put global stay_on_while_plugged_in 0',commands)

    def test_non_usb_power_refuses_child_but_restores_setting(self):
        code,result,journal,final,child,commands,ran = self.exercise('1',bad_usb=True)
        self.assertEqual(code,2)
        self.assertFalse(ran)
        self.assertEqual(final['value'],'1')
        self.assertTrue(result['setting_restored'])

    def test_unadvertised_api_refuses_before_mutating(self):
        code,result,journal,final,child,commands,ran = self.exercise(None,unsupported=True)
        self.assertEqual(code,2)
        self.assertIsNone(journal)
        self.assertIsNone(final['value'])
        self.assertFalse(ran)
        self.assertNotIn('svc power stayon usb',commands)

    def test_child_result_write_failure_still_restores_without_retry_or_success(self):
        code,result,journal,final,child,commands,ran = self.exercise('5',save_failures=('child-result.json',))
        self.assertEqual(code,2)
        self.assertEqual(final['value'],'5')
        self.assertTrue(result['setting_restored'])
        self.assertEqual(result['status'],'needs_diagnosis')
        self.assertEqual([x['artifact'] for x in result['diagnostic_write_errors']],['child-result.json'])
        self.assertIn('settings put global stay_on_while_plugged_in 5',commands)

    def test_restore_intent_write_failure_still_restores_and_stays_diagnostic(self):
        code,result,journal,final,child,commands,ran = self.exercise(None,save_failures=('restore-intent.json',))
        self.assertEqual(code,2)
        self.assertIsNone(final['value'])
        self.assertTrue(result['setting_restored'])
        self.assertFalse(result['restore_intent_persisted'])
        self.assertEqual(result['status'],'needs_diagnosis')
        self.assertEqual([x['artifact'] for x in result['diagnostic_write_errors']],['restore-intent.json'])
        self.assertIn('settings delete global',commands)

    def test_final_receipt_post_write_failure_removes_success_and_returns_failure(self):
        code,result,journal,final,child,commands,ran = self.exercise('0',save_failures=('result.json',),
                                                                 fail_after_write=True)
        self.assertEqual(code,2)
        self.assertEqual(final['value'],'0')
        self.assertEqual(result['status'],'no_durable_result')


if __name__ == '__main__':
    unittest.main()
