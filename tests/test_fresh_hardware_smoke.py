"""Host-only tests: all device commands target an owned fake executable."""
from pathlib import Path
import copy
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/prepare-fresh-hardware-smoke.py"
spec = importlib.util.spec_from_file_location("fresh_hardware", SOURCE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def write(path, value):
    path.write_text(json.dumps(value))


def executable(path, source):
    path.write_text("#!/usr/bin/env python3\n" + source)
    path.chmod(0o700)


def runtime(apk_hash, boot):
    row = dict(state="compatible", phase="authentication_gate_observed",
        user_authentication_required=True, authentication_validity_seconds=5,
        authentication_type=1, reported_security_level=1, reported_hardware_auth_enforced=True,
        before_authentication_rejected=True, normal_lock_observed=True, normal_unlock_observed=True,
        signature_after_unlock_verified=True, changed_message_rejected=True,
        after_expiry_rejected=True, owned_keys_removed=True, credential_received_by_app=False,
        private_material_exported=False, attestation_verified=False)
    return dict(status="requested_operation_smoke_passed", boot_id=boot, serial="FIXTURE",
        android_user=11, suite=probe.SUITE, apk_sha256=apk_hash, cleanup_verified=True,
        host_boot_unchanged=True, full_port_verified=False, firmware_written=False, run_id="a" * 32,
        operations=dict(suite=probe.SUITE, package=probe.PACKAGE, run_id="a" * 32,
            fingerprint="fixture-donor-17", uid=1110001, user_content_collected=False,
            keystore=dict(status="observed", results=[row])))


class FreshHardwareSmoke(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.boot = "12345678-1234-4234-8234-123456789abc"
        self.usb = self.base / "usb-serial"
        self.usb.write_text("FIXTURE\n")
        self.adb = self.base / "fake-adb"
        self.runner = self.base / "fake-runner"
        self.apk = self.base / "owned.apk"
        self.apk.write_bytes(b"test fixture only; never an Android APK")
        self.build = self.base / "build.json"
        write(self.build, {"status": "fixture"})
        self.evidence = self.base / "source-receipt.json"
        write(self.evidence, {"status": "fixture only"})
        self.case = self.base / "fresh-case"
        executable(self.adb, "raise SystemExit('must not run during preparation')\n")
        executable(self.runner, "raise SystemExit('must not run during preparation')\n")

    def prepare(self):
        request = dict(schema_version=1, adb=probe.pin(self.adb), apk=probe.pin(self.apk),
            build_report=probe.pin(self.build), serial="FIXTURE", fingerprint="fixture-donor-17",
            android_user=11, suite="usb_inventory")
        write(self.base / "template.json", request)
        value = dict(schema_version=1, suite=probe.SUITE, authentication_validity_seconds=5,
            serial="FIXTURE", fingerprint="fixture-donor-17", vendor_fingerprint="fixture-vendor-16",
            android_user=11, usb_serial_path=str(self.usb), runner=probe.pin(self.runner),
            evidence=[probe.pin(self.evidence)], request_template="template.json")
        write(self.base / "input.json", value)
        return probe.prepare(self.base / "input.json", self.case)

    def test_prepare_is_offline_pinned_and_refuses_namespace_replay(self):
        with patch.object(probe.subprocess, "Popen", side_effect=AssertionError("no execution")):
            result = self.prepare()
        request = probe.read_json(self.case / "run-request.json")
        self.assertEqual(request["suite"], probe.SUITE)
        self.assertEqual(probe.digest(self.case / "profile.json"), result["sha256"])
        self.assertIsNone(probe.read_json(self.case / "preparation.json")["expected_boot_id"])
        self.assertFalse((self.case / "execution-attempt.json").exists())
        with self.assertRaises(RuntimeError):
            probe.prepare(self.base / "input.json", self.case)

    def test_runtime_requires_actual_configured_expiry_sign_tamper_and_cleanup(self):
        profile = dict(serial="FIXTURE", android_user=11, fingerprint="fixture-donor-17",
            authentication_validity_seconds=5, _request={"apk": {"sha256": "b" * 64}})
        value = runtime("b" * 64, self.boot)
        phases = ["waiting_for_normal_unlock", "normal_lock_observed"]
        probe.validate_runtime(value, profile, self.boot, phases)
        mutations = [
            ("authentication_validity_seconds", 30), ("after_expiry_rejected", False),
            ("before_authentication_rejected", False), ("owned_keys_removed", False),
            ("changed_message_rejected", False), ("reported_security_level", 0),
            ("credential_received_by_app", True), ("attestation_verified", True)]
        for key, bad in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(value)
                changed["operations"]["keystore"]["results"][0][key] = bad
                with self.assertRaises(RuntimeError):
                    probe.validate_runtime(changed, profile, self.boot, phases)
        with self.assertRaises(RuntimeError):
            probe.validate_runtime(value, profile, self.boot, ["normal_lock_observed"])
        with self.assertRaises(RuntimeError):
            probe.validate_runtime(value, profile, "23456789-1234-4234-8234-123456789abc", phases)

    def test_bounded_subprocess_limits_output_time_and_cancel(self):
        result = probe.bounded([sys.executable, "-c", "import os;os.write(1,b'x'*65536)"], 2, 256)
        self.assertTrue(result["output_budget_exceeded"])
        self.assertLessEqual(len(result["stdout"]) + len(result["stderr"]), 256)
        result = probe.bounded([sys.executable, "-c", "import time;time.sleep(30)"], .1, 64)
        self.assertTrue(result["timed_out"])
        event = threading.Event()
        event.set()
        result = probe.bounded([sys.executable, "-c", "import time;time.sleep(30)"], 2, 64, event)
        self.assertTrue(result["cancelled"])
        self.assertIsNotNone(result["exit_code"])
        # External credential hook output must not be retained, even on failure.
        result = probe.bounded([sys.executable, "-c", "print('private fixture')"], 2, 0)
        self.assertTrue(result["output_budget_exceeded"])
        self.assertEqual(result["stdout"], b"")
        self.assertEqual(result["stderr"], b"")

    def fake_execution(self, reboot=False, hook_failure=False):
        # Every apparent ADB request is serviced by this fixture; no USB operation exists.
        executable(self.adb, f'''from pathlib import Path
import sys,json
b=Path({str(self.base)!r});cmd=sys.argv[-1];c=b/'fresh-case'
fixed={{'getprop ro.serialno':'FIXTURE','id -u':'2000','getenforce':'Enforcing',
 'am get-current-user':'11','am get-started-user-state 11':'RUNNING_UNLOCKED',
 'getprop ro.build.fingerprint':'fixture-donor-17','getprop ro.vendor.build.fingerprint':'fixture-vendor-16'}}
if cmd in fixed:print(fixed[cmd])
elif cmd=='cat /proc/sys/kernel/random/boot_id':print((b/'boot').read_text().strip())
elif cmd.startswith('pm list packages'):print('package:{probe.PACKAGE}' if (c/'installed').exists() else '')
elif cmd=='input keyevent 223':(c/'locked').touch()
elif 'cat files/auth-stage-' in cmd:
 p=c/'app-stage.json'
 if p.exists():print(p.read_text())
 else:sys.exit(1)
elif cmd.startswith('pm path'):print('package:/data/app/fixture/base.apk')
elif cmd.startswith('sha256sum '):print({probe.digest(self.apk)!r}+'  /data/app/fixture/base.apk')
elif cmd.startswith('am force-stop'):pass
elif cmd.startswith('pm uninstall'):
 (c/'installed').unlink(missing_ok=True);print('Success')
else:raise SystemExit('unknown fake command')
''')
        executable(self.runner, f'''from pathlib import Path
import sys,json,time
b=Path(sys.argv[-1]).parent;req=json.loads(Path(sys.argv[-2]).read_text());nonce='a'*32
def put(p,v):
 q=p.with_suffix('.tmp');q.write_text(json.dumps(v));q.replace(p)
put(b/'runtime.context.json',dict(run_id=nonce,package={probe.PACKAGE!r},suite={probe.SUITE!r},
 android_user=11,apk_sha256=req['apk']['sha256'],namespace_absent_before_install=True))
(b/'installed').touch()
put(b/'app-stage.json',dict(run_id=nonce,phase='waiting_for_normal_unlock',credential_received_by_app=False))
deadline=time.monotonic()+10
while not (b/'locked').exists():
 if time.monotonic()>deadline:raise SystemExit(2)
 time.sleep(.01)
put(b/'app-stage.json',dict(run_id=nonce,phase='normal_lock_observed',credential_received_by_app=False))
while not (b/'unlocked').exists():
 if time.monotonic()>deadline:raise SystemExit(2)
 time.sleep(.01)
put(b/'app-stage.json',dict(run_id=nonce,phase='waiting_for_expiry',credential_received_by_app=False))
put(Path(sys.argv[-1]),json.loads((b.parent/'expected-runtime.json').read_text()))
(b/'installed').unlink();print('{{"status":"fixture-completed"}}')
''')
        self.hook = self.base / "main-owned-hook"
        executable(self.hook, f'''from pathlib import Path
b=Path({str(self.base)!r});c=b/'fresh-case'
with (c/'hook-count').open('a') as f:f.write('1\\n')
{("raise SystemExit(3)" if hook_failure else "(c/'unlocked').touch()")}
{("(b/'boot').write_text('23456789-1234-4234-8234-123456789abc')" if reboot else "")}
''')
        (self.base / "boot").write_text(self.boot)
        write(self.base / "expected-runtime.json", runtime(probe.digest(self.apk), self.boot))
        pin = self.prepare()
        self.profile = self.case / "profile.json"
        self.profile_sha = pin["sha256"]
        self.context = self.case / "fresh-context.json"
        probe.capture_context(self.profile, self.profile_sha, self.context)
        return probe.run(self.profile, self.profile_sha, self.context, probe.digest(self.context),
                         self.hook, probe.digest(self.hook))

    def test_fake_adb_complete_auth_flow_one_hook_no_vm_and_replay_refused(self):
        self.assertEqual(self.fake_execution(), 0)
        result = probe.read_json(self.case / "result.json")
        self.assertEqual(result["status"], "requested_operation_smoke_passed")
        self.assertTrue(result["owned_namespace_cleanup_verified"])
        self.assertFalse(result["vm_or_guest_queried"])
        self.assertEqual((self.case / "hook-count").read_text(), "1\n")
        with self.assertRaises(FileExistsError):
            probe.run(self.profile, self.profile_sha, self.context, probe.digest(self.context),
                      self.hook, probe.digest(self.hook))

    def test_fake_reboot_cannot_pass_or_cleanup_wrong_boot(self):
        self.assertEqual(self.fake_execution(reboot=True), 2)
        result = probe.read_json(self.case / "result.json")
        self.assertEqual(result["status"], "needs_diagnosis")
        self.assertFalse(result["owned_namespace_cleanup_verified"])

    def test_fake_unlock_failure_cancels_runner_and_cleans_owned_namespace(self):
        self.assertEqual(self.fake_execution(hook_failure=True), 2)
        result = probe.read_json(self.case / "result.json")
        self.assertTrue(result["owned_namespace_cleanup_verified"])
        self.assertFalse((self.case / "installed").exists())
        self.assertEqual((self.case / "hook-count").read_text(), "1\n")

    def test_stale_context_and_pinned_mutation_refuse_before_probe(self):
        pin = self.prepare()
        p = probe.profile_read(self.case / "profile.json", pin["sha256"])
        context = self.case / "context.json"
        write(context, dict(schema_version=1, profile_sha256=pin["sha256"], case_id=p["case_id"],
            serial="FIXTURE", android_user=11, boot_id=self.boot,
            captured_monotonic=time.monotonic()-301, vm_or_guest_queried=False))
        with self.assertRaises(RuntimeError):
            probe.context_read(context, probe.digest(context), p, pin["sha256"])
        self.apk.write_bytes(b"changed fixture")
        with self.assertRaises(RuntimeError):
            probe.profile_read(self.case / "profile.json", pin["sha256"])


if __name__ == "__main__":
    unittest.main()
