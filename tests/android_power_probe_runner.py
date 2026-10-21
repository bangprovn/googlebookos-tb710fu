#!/usr/bin/env python3
"""Host-only power-suite lifecycle/protocol regression; never contacts ADB."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "crates/gb-framework/src/hardware_probe"
package = "org.googlebook.port.hardwareprobe"
with tempfile.TemporaryDirectory(prefix="gb-power-runner-") as temporary:
    work = Path(temporary)
    apk = work / "owned.apk"
    apk.write_bytes(b"owned host-only non-executable fixture")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    rust = (source.parent / "hardware_probe.rs").read_text()
    manifest = rust.split('const MANIFEST: &str = r#"', 1)[1].split('"#;', 1)[0]
    provenance = {"status": "owned_hardware_apk_built_not_runtime_verified", "package": package,
                  "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(), "apk_sha256": digest(apk)}
    for key, name in {"source": "HardwareProbeActivity", "audio_source": "AudioProbe",
                      "audio_pattern": "AudioPattern", "playback_source": "AudioPlaybackInstrumentation",
                      "auth_key_source": "AuthKeyProbe", "power_source": "PowerProbe", "network_source": "NetworkProbe", "usb_source": "UsbProbe"}.items():
        provenance[key + "_sha256"] = digest(source / (name + ".java"))
    built = work / "build.json"
    built.write_text(json.dumps(provenance))
    commands, installed, run_id, mode = [work / name for name in ["commands", "installed", "run-id", "mode"]]
    power = {
        "status": "observed", "read_only": True, "settings_changed": False, "wake_lock_acquired": False,
        "charging_performance_verified": False, "battery_calibration_verified": False,
        "thermal_control_verified": False, "suspend_resume_verified": False,
        "results": [
            {"operation": "battery_snapshot", "state": "compatible", "availability": "available", "present": True,
             "status_code": 2, "level": 50, "scale": 100, "temperature_decic": 315, "temperature_unit": "tenths_degree_celsius"},
            {"operation": "charge_counter", "state": "compatible", "availability": "available", "value_uah": 4000000, "unit": "microampere_hours"},
            {"operation": "thermal_status", "state": "compatible", "availability": "available", "direct_before": 0,
             "direct_after": 0, "listener_registered": True, "listener_removed": True, "callbacks": 1,
             "last_callback_status": 0, "callbacks_valid": True, "callback_budget_exceeded": False,
             "executor_stopped": True, "window_ms": 2000},
            {"operation": "thermal_headroom", "state": "compatible", "availability": "available", "value": 1.2,
             "forecast_seconds": 0, "read_count": 1},
        ]}
    fixture = work / "fixture.json"
    fixture.write_text(json.dumps(power))
    adb = work / "fake-adb"
    adb.write_text("#!" + sys.executable + "\n" + f'''
from pathlib import Path
import json,re,sys
args=sys.argv[1:]; assert args[:2]==['-s','fixture-serial']
with Path({str(commands)!r}).open('a') as out: out.write(json.dumps(args[2:])+'\\n')
state=Path({str(installed)!r}); mode=Path({str(mode)!r}).read_text()
if args[2]=='install':
 assert '-r' not in args; state.write_text('owned'); print('Success'); sys.exit()
assert args[2]=='shell' and len(args)==4
c=args[3]
values={{'getprop ro.serialno':'fixture-serial','getprop ro.build.fingerprint':'fixture-fingerprint',
 'id -u':'2000','getenforce':'Enforcing','am get-current-user':'11',
 'am get-started-user-state 11':'RUNNING_UNLOCKED',
 'cat /proc/sys/kernel/random/boot_id':'12345678-1234-1234-1234-123456789abc'}}
if c in values: print('RUNNING_LOCKED' if mode=='locked' and c=='am get-started-user-state 11' else values[c])
elif c.startswith('pm list packages '):
 if state.exists(): print('package:{package}')
elif c=='pm path --user 11 {package}': print('package:/data/app/~~fixture/pkg/base.apk')
elif c.startswith('sha256sum '): print({digest(apk)!r}+'  base.apk')
elif c=='run-as {package} --user 11 id -u': print('1110001')
elif c.startswith('am start -W '):
 assert c.endswith('--es suite power')
 Path({str(run_id)!r}).write_text(re.search(r'--es run_id ([a-f0-9]{{32}})',c)[1])
elif c.startswith('run-as {package} --user 11 cat files/gb-'):
 power=json.loads(Path({str(fixture)!r}).read_text())
 if mode=='unsupported':
  for i,key in [(1,'value_uah'),(3,'value')]:
   power['results'][i].update(state='unknown',availability='unavailable_or_unsupported'); power['results'][i][key]=None
 if mode=='missing_callback': power['results'][2].update(state='unknown',availability='unavailable_or_unsupported',callbacks=0,last_callback_status=None)
 if mode=='false_callback_pass': power['results'][2]['callbacks']=0
 report=dict(schema_version=1,probe='owned_android_hardware_v1',suite='power',package={package!r},
  run_id=Path({str(run_id)!r}).read_text(),fingerprint='fixture-fingerprint',uid=1110001,
  full_port_verified=False,user_content_collected=False,power=power)
 for name in ['sensors','cameras','audio','keystore']: report[name]={{'status':'not_requested'}}
 print(json.dumps(report))
elif c.startswith('am force-stop --user 11 {package}'): pass
elif c.startswith('pm uninstall --user 11 {package}'): state.unlink(); print('Success')
else: raise AssertionError('unexpected operation, including permissions/settings: '+c)
''')
    adb.chmod(0o700)
    pin = lambda path: {"path": str(path), "sha256": digest(path)}
    request = work / "request.json"
    request.write_text(json.dumps({"schema_version": 1, "adb": pin(adb), "apk": pin(apk),
                                  "build_report": pin(built), "serial": "fixture-serial",
                                  "fingerprint": "fixture-fingerprint", "android_user": 11, "suite": "power"}))
    for scenario in ["good", "unsupported", "missing_callback", "false_callback_pass", "locked"]:
        mode.write_text(scenario)
        commands.write_text("")
        output = work / (scenario + ".json")
        result = subprocess.run([str(root / "target/debug/examples/android_hardware_probe"), "run", str(request), str(output)],
                                capture_output=True, text=True, timeout=25)
        calls = [json.loads(line) for line in commands.read_text().splitlines()]
        assert not any('pm grant' in str(c) or 'settings ' in str(c) or 'reboot' in str(c) for c in calls)
        if scenario == "locked":
            assert result.returncode != 0 and not output.exists()
            assert not any(c[0] == 'install' for c in calls)
        else:
            report = json.loads(output.read_text())
            assert result.returncode == (0 if scenario == "good" else 2), result.stderr
            assert report['status'] == ('requested_operation_smoke_passed' if scenario == 'good' else 'needs_diagnosis')
            assert report['cleanup_verified'] and report['host_boot_unchanged'] and not installed.exists()
            assert not report['firmware_written'] and not report['full_port_verified']
            assert bool(report['execution_error']) == (scenario == 'false_callback_pass')
        print('PASS: bounded power fixture ' + scenario + '; no permission/settings operations')
