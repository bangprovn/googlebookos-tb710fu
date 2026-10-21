#!/usr/bin/env python3
"""Host-only: failed/ambiguous installs and corrupt APKs must be cleaned up.

Prerequisite: cargo build --locked -p gb-framework --example android_hardware_probe
The fake installer represents a new owned namespace; no real ADB server is used.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
runner = Path(os.environ.get("GB_HARDWARE_PROBE_RUNNER", root / "target/debug/examples/android_hardware_probe"))
with tempfile.TemporaryDirectory(prefix="gb-hardware-runner-") as temporary:
    work = Path(temporary)
    apk = work / "owned-fixture.apk"
    apk.write_bytes(b"owned-corrupt-transfer-fixture-not-executable")
    source = root / "crates/gb-framework/src/hardware_probe/HardwareProbeActivity.java"
    rust = (root / "crates/gb-framework/src/hardware_probe.rs").read_text()
    manifest = rust.split('const MANIFEST: &str = r#"', 1)[1].split('"#;', 1)[0]
    package = "org.googlebook.port.hardwareprobe"
    provenance = work / "build-report.json"
    provenance.write_text(json.dumps({
        "status": "owned_hardware_apk_built_not_runtime_verified", "package": package,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "audio_source_sha256": hashlib.sha256((source.parent / "AudioProbe.java").read_bytes()).hexdigest(),
        "audio_pattern_sha256": hashlib.sha256((source.parent / "AudioPattern.java").read_bytes()).hexdigest(),
        "playback_source_sha256": hashlib.sha256((source.parent / "AudioPlaybackInstrumentation.java").read_bytes()).hexdigest(),
        "auth_key_source_sha256": hashlib.sha256((source.parent / "AuthKeyProbe.java").read_bytes()).hexdigest(),
        "power_source_sha256": hashlib.sha256((source.parent / "PowerProbe.java").read_bytes()).hexdigest(),
        "network_source_sha256": hashlib.sha256((source.parent / "NetworkProbe.java").read_bytes()).hexdigest(),
        "bluetooth_source_sha256": hashlib.sha256((source.parent / "BluetoothProbe.java").read_bytes()).hexdigest(),
        "usb_source_sha256": hashlib.sha256((source.parent / "UsbProbe.java").read_bytes()).hexdigest(),
        "display_source_sha256": hashlib.sha256((source.parent / "DisplayProbe.java").read_bytes()).hexdigest(),
        "display_pattern_sha256": hashlib.sha256((source.parent / "DisplayPattern.java").read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
    }))
    commands = work / "commands.jsonl"
    mode_file = work / "mode"
    installed = work / "installed"
    mode_file.write_text("corrupt")
    adb = work / "fake-adb"
    adb.write_text("#!" + sys.executable + "\n" + f'''
import sys,json
from pathlib import Path
args=sys.argv[1:]
assert args[:2]==['-s','fixture-serial']
with Path({str(commands)!r}).open('a') as out: out.write(json.dumps(args[2:])+'\\n')
if args[2]=='install':
 assert '-r' not in args
 Path({str(installed)!r}).write_text('owned namespace may exist despite failed install ack')
 mode=Path({str(mode_file)!r}).read_text()
 if mode=='install_no_ack': print('Failure [fixture missing acknowledgement]'); sys.exit(0)
 if mode=='install_exit_error': print('fixture installer failed after namespace creation',file=sys.stderr); sys.exit(1)
 print('Success'); sys.exit(0)
assert args[2]=='shell' and len(args)==4
c=args[3]
values={{'getprop ro.serialno':'fixture-serial','getprop ro.build.fingerprint':'fixture-fingerprint',
'id -u':'2000','getenforce':'Enforcing','am get-current-user':'11',
'am get-started-user-state 11':'RUNNING_UNLOCKED',
'cat /proc/sys/kernel/random/boot_id':'12345678-1234-1234-1234-123456789abc'}}
if c in values: print(values[c])
elif c.startswith('sha256sum '): print('0'*64+'  corrupt-device-copy.apk')
elif c=='pm path --user 11 {package}': print('package:/data/app/~~fixture/pkg-fixture/base.apk')
elif c.startswith('pm uninstall --user 11 {package}'):
 Path({str(installed)!r}).unlink(); print('Success')
elif c.startswith('pm list packages '):
 if Path({str(installed)!r}).exists(): print('package:{package}')
elif c.startswith('am force-stop --user 11 {package}'): pass
else: sys.exit(99) # Includes run-as, permission grants and Activity launches.
''')
    adb.chmod(0o700)

    def pin(path):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    request = work / "run.json"
    request.write_text(json.dumps({
        "schema_version": 1, "adb": pin(adb), "apk": pin(apk),
        "build_report": pin(provenance), "serial": "fixture-serial",
        "fingerprint": "fixture-fingerprint", "android_user": 11,
    }))
    output = work / "report.json"
    result = subprocess.run([
        str(runner), "run",
        str(request), str(output),
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == 2, result.stderr
    report = json.loads(output.read_text())
    assert report["status"] == "needs_diagnosis" and report["operations"] is None
    assert "installed APK hash mismatch" in report["execution_error"]
    called = [json.loads(line) for line in commands.read_text().splitlines()]
    assert not any(any(word in str(args) for word in ["run-as", "pm grant", "am start"]) for args in called)
    assert any(args[0] == "shell" and args[1].startswith("pm uninstall --user 11 " + package) for args in called)
    assert report["cleanup_verified"] and report["host_boot_unchanged"] and not report["firmware_written"]
    print("PASS: corrupt installed copy rejected before permission grant or app execution; owned namespace removed")

    for mode in ["install_no_ack", "install_exit_error"]:
        mode_file.write_text(mode)
        commands.write_text("")
        output = work / (mode + "-report.json")
        result = subprocess.run([
            str(runner), "run",
            str(request), str(output),
        ], capture_output=True, text=True, timeout=20)
        assert result.returncode == 2, (mode, result.stderr)
        report = json.loads(output.read_text())
        assert report["status"] == "needs_diagnosis" and report["operations"] is None
        assert report["execution_error"], mode
        if mode == "install_no_ack":
            assert "APK install not acknowledged" in report["execution_error"]
        assert report["cleanup_verified"] and report["host_boot_unchanged"]
        assert not installed.exists() and not report["firmware_written"]
        called = [json.loads(line) for line in commands.read_text().splitlines()]
        assert not any(any(word in str(args) for word in ["pm path", "run-as", "pm grant", "am start"]) for args in called)
        assert any(args[0] == "shell" and args[1].startswith("am force-stop --user 11 " + package) for args in called)
        assert any(args[0] == "shell" and args[1].startswith("pm uninstall --user 11 " + package) for args in called)
        print("PASS: " + mode + " produces diagnosis, runs no probe and removes partial owned install")

    # A separately built UI observer must never enter a hardware suite, even
    # when a caller supplies otherwise current hardware-source metadata.
    baseline = json.loads(provenance.read_text())
    for status in ["owned_terminal_ui_observer_apk_built_not_runtime_verified",
                   "owned_hardware_apk_built_not_runtime_verified"]:
        observer = dict(baseline, status=status, package="org.googlebook.port.terminaluiobserver")
        provenance.write_text(json.dumps(observer))
        value = json.loads(request.read_text())
        value["build_report"] = pin(provenance)
        request.write_text(json.dumps(value))
        commands.write_text("")
        output = work / (status + "-rejected.json")
        result = subprocess.run([str(runner), "run", str(request), str(output)],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode != 0 and "APK source/build provenance mismatch" in result.stderr
        assert not output.exists() and commands.read_text() == "" and not installed.exists()
    print("PASS: UI observer namespace rejected before any hardware-suite device operation")

    # The inspection command validates bounded scalar receipts without ADB.
    scalar = {
        "schema_version": 1, "probe": "owned_terminal_ui_observer_v1",
        "record_kind": "ready", "status": "ready", "android_user": 11,
        "uid": 1110249, "observation_only": True,
        "command_execution_verified": False, "output_proof_claimed": False,
        "input_performed": False, "raw_content_exported": False,
        "settings_or_permissions_changed": False, "framework_cleanup_verified": False,
        "accessibility_enabled_before_connection": False,
        "accessibility_enabled_after_connection": True,
        "touch_exploration_before_connection": False,
        "touch_exploration_after_connection": False,
        "ui_automation_acquired": True, "first_poll_pending": True,
    }
    receipt = work / "ui-observer.json"
    receipt.write_text(json.dumps(scalar))
    validated = work / "ui-observer-validated.json"
    result = subprocess.run([str(runner), "inspect-ui-observer", str(receipt), str(validated)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    observed = json.loads(validated.read_text())
    assert observed["receipt"] == scalar and not observed["command_execution_verified"]
    assert not observed["external_execution_identity_verified"] and not observed["framework_cleanup_verified"]
    for i, bad in enumerate([
        json.dumps(dict(scalar, raw_text="private fixture")),
        json.dumps(dict(scalar, command_execution_verified=True)),
        json.dumps(scalar)[:-1] + ',"uid":1110249}',
        " " * 65537 + json.dumps(scalar),
    ]):
        receipt.write_text(bad)
        output = work / ("ui-observer-refused-%d.json" % i)
        result = subprocess.run([str(runner), "inspect-ui-observer", str(receipt), str(output)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and not output.exists(), (i, result.stderr)
    # Nonregular inputs must refuse without waiting for a FIFO writer.
    receipt.unlink()
    os.mkfifo(receipt)
    result = subprocess.run([str(runner), "inspect-ui-observer", str(receipt),
                             str(work / "fifo-refused.json")],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode != 0 and not (work / "fifo-refused.json").exists()
    assert commands.read_text() == ""
    print("PASS: scalar UI inspection validates observations; rejects raw content, proof claims, duplicate keys, oversized and nonregular input without ADB")
