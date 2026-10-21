#!/usr/bin/env python3
"""Host-only Network suite lifecycle: fake ADB, no sockets or device access."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "crates/gb-framework/src/hardware_probe"
package = "org.googlebook.port.hardwareprobe"
with tempfile.TemporaryDirectory(prefix="gb-network-runner-") as temporary:
    work = Path(temporary)
    apk = work / "owned.apk"
    apk.write_bytes(b"owned network fixture: never executed")
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
    commands, installed, run_id, mode, responded = [work / name for name in ["commands", "installed", "run-id", "mode", "responded"]]
    network = {"status": "observed", "settings_changed": False, "network_requested_or_process_bound": False,
               "network_identifiers_collected": False, "content_collected": False, "wifi_reconnect_verified": False,
               "radio_change_performed": False, "results": [
        {"operation": "default_network_snapshot", "state": "compatible", "default_present": True, "capabilities_available": True,
         "internet": True, "validated": False, "transport_wifi": True, "transport_cellular": False, "transport_ethernet": False, "transport_vpn": False},
        {"operation": "default_network_callbacks", "state": "compatible", "registered": True, "removed": True,
         "thread_stopped": True, "window_ms": 2000, "observations": 2, "available_events": 1, "capability_events": 1,
         "lost_events": 0, "matching_available": True, "matching_capabilities": True, "network_change_observed": False, "observation_budget_exceeded": False},
        {"operation": "fixed_https_204", "state": "compatible", "endpoint": "https://www.google.com/generate_204",
         "request_count_limit": 1, "attempted": True, "outcome": "https_204_empty_body", "response_code": 204,
         "body_bytes_read": 0, "empty_body": True, "response_stream_closed": True, "disconnect_called": True,
         "worker_stopped": True, "observer_timed_out": False, "default_tls_verification_used": True,
         "redirects_enabled": False, "credentials_or_cookies_sent": False, "body_content_exported": False,
         "captured_network_used": True, "default_network_matches_at_checks": True, "connect_timeout_ms": 4000,
         "read_timeout_ms": 4000, "observer_timeout_ms": 12000},
    ]}
    fixture = work / "fixture.json"
    fixture.write_text(json.dumps(network))
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
if c in values:
 value=values[c]
 if mode=='reboot' and Path({str(responded)!r}).exists() and c=='cat /proc/sys/kernel/random/boot_id': value='87654321-4321-4321-4321-cba987654321'
 print(value)
elif c.startswith('pm list packages '):
 if state.exists(): print('package:{package}')
elif c=='pm path --user 11 {package}': print('package:/data/app/~~fixture/pkg/base.apk')
elif c.startswith('sha256sum '): print({digest(apk)!r}+'  base.apk')
elif c=='run-as {package} --user 11 id -u': print('1110001')
elif c.startswith('am start -W '):
 assert c.endswith('--es suite network')
 Path({str(run_id)!r}).write_text(re.search(r'--es run_id ([a-f0-9]{{32}})',c)[1])
elif c.startswith('run-as {package} --user 11 cat files/gb-'):
 net=json.loads(Path({str(fixture)!r}).read_text()); snap,cb,tls=net['results']
 if mode=='no_network':
  snap.update(state='unknown',default_present=False,capabilities_available=False,internet=False,transport_wifi=False)
  cb.update(state='unknown',registered=False,removed=False,window_ms=0,observations=0,available_events=0,capability_events=0,matching_available=False,matching_capabilities=False)
  tls.update(state='unknown',attempted=False,outcome='no_eligible_default_network',response_code=-1,body_bytes_read=None,empty_body=False,response_stream_closed=False,disconnect_called=False,default_tls_verification_used=False,captured_network_used=False,default_network_matches_at_checks=False)
 elif mode=='tls_failure': tls.update(state='unknown',outcome='tls_error',response_code=-1,body_bytes_read=None,empty_body=False,response_stream_closed=False)
 elif mode=='redirect': tls.update(state='unknown',outcome='unexpected_http_status',response_code=302,body_bytes_read=None,empty_body=False,response_stream_closed=False)
 elif mode=='body': tls.update(state='unknown',outcome='unexpected_body',body_bytes_read=1,empty_body=False)
 elif mode=='mismatch': cb.update(state='unknown',matching_available=False,network_change_observed=True)
 elif mode=='no_callback': cb.update(state='unknown',observations=0,available_events=0,capability_events=0,matching_available=False,matching_capabilities=False)
 elif mode=='unremoved': cb.update(state='unknown',removed=False,thread_stopped=False)
 elif mode=='dns_worker_live': tls.update(state='unknown',outcome='observer_deadline',response_code=-1,body_bytes_read=None,empty_body=False,response_stream_closed=False,disconnect_called=False,worker_stopped=False,observer_timed_out=True)
 elif mode=='false_tls_pass': tls['default_tls_verification_used']=False
 elif mode=='private': snap['ssid']='private'
 report=dict(schema_version=1,probe='owned_android_hardware_v1',suite='network',package={package!r},
  run_id=Path({str(run_id)!r}).read_text(),fingerprint='fixture-fingerprint',uid=1110001,
  full_port_verified=False,user_content_collected=False,network=net)
 for name in ['sensors','cameras','audio','keystore','power']: report[name]={{'status':'not_requested'}}
 Path({str(responded)!r}).touch(); print(json.dumps(report))
elif c.startswith('am force-stop --user 11 {package}'): pass
elif c.startswith('pm uninstall --user 11 {package}'): state.unlink(); print('Success')
else: raise AssertionError('unexpected operation, including permissions/settings/radio: '+c)
''')
    adb.chmod(0o700)
    pin = lambda path: {"path": str(path), "sha256": digest(path)}
    request = work / "request.json"
    request.write_text(json.dumps({"schema_version": 1, "adb": pin(adb), "apk": pin(apk), "build_report": pin(built),
                                  "serial": "fixture-serial", "fingerprint": "fixture-fingerprint", "android_user": 11, "suite": "network"}))
    scenarios = ["good", "no_network", "tls_failure", "redirect", "body", "mismatch", "no_callback", "unremoved", "dns_worker_live", "false_tls_pass", "private", "reboot"]
    for scenario in scenarios:
        mode.write_text(scenario)
        commands.write_text("")
        responded.unlink(missing_ok=True)
        output = work / (scenario + ".json")
        result = subprocess.run([str(root / "target/debug/examples/android_hardware_probe"), "run", str(request), str(output)],
                                capture_output=True, text=True, timeout=25)
        calls = [json.loads(line) for line in commands.read_text().splitlines()]
        assert not any(any(s in str(c) for s in ['pm grant', 'settings ', 'svc wifi', 'reboot', 'ssid', 'dumpsys wifi']) for c in calls)
        report = json.loads(output.read_text())
        assert result.returncode == (0 if scenario == "good" else 2), result.stderr
        assert report['status'] == ('requested_operation_smoke_passed' if scenario == 'good' else 'needs_diagnosis')
        assert report['cleanup_verified'] and not installed.exists()
        assert report['host_boot_unchanged'] == (scenario != 'reboot')
        assert not report['firmware_written'] and not report['full_port_verified']
        assert bool(report['execution_error']) == (scenario in ['false_tls_pass', 'private'])
        print('PASS: network fixture ' + scenario + '; no real network/ADB/radio operations')
