use super::*;
use serde_json::{Value, json};

fn observed() -> Value {
    json!({"status":"observed","state":"unknown","scope":"public_api_status_only",
        "reason":"bounded_status_complete","classic_feature_declared":true,"le_feature_declared":true,
        "connect_permission_granted":true,"adapter_present":true,"state_before":12,"state_after":12,
        "state_matches_at_checks":true,"window_budget_ms":2000,"window_elapsed_ms":2005,"elapsed_ms":2010,
        "receiver_registered":true,"receiver_cleanup_attempted":true,"receiver_removed":true,"callback_thread_stopped":true,
        "callback_count":0,"valid_transition_callbacks":0,"invalid_state_callback":false,
        "callback_budget_exceeded":false,"read_only":true,"identifiers_collected":false,
        "user_content_collected":false,"radio_change_requested":false,"discovery_or_scan_started":false,
        "paired_devices_accessed":false,"socket_opened":false,"functionality_verified":false,
        "radio_transition_verified":false})
}
fn unavailable(reason: &str) -> Value {
    let mut r = observed();
    r["status"] = "unavailable".into();
    r["reason"] = reason.into();
    for key in ["state_before", "state_after", "state_matches_at_checks"] {
        r[key] = Value::Null;
    }
    for key in [
        "receiver_registered",
        "receiver_cleanup_attempted",
        "receiver_removed",
    ] {
        r[key] = false.into();
    }
    r["window_elapsed_ms"] = 0.into();
    r["elapsed_ms"] = 1.into();
    if reason == "adapter_unavailable" {
        r["adapter_present"] = false.into();
    }
    if reason == "manager_unavailable" {
        r["adapter_present"] = Value::Null;
    }
    if reason == "permission_denied" {
        r["connect_permission_granted"] = false.into();
        r["adapter_present"] = Value::Null;
    }
    r
}
fn envelope(value: Value) -> Value {
    json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"bluetooth_status",
        "package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,
        "full_port_verified":false,"user_content_collected":false,"bluetooth":value,
        "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
        "audio":{"status":"not_requested"},"keystore":{"status":"not_requested"},
        "power":{"status":"not_requested"},"network":{"status":"not_requested"},
        "usb":{"status":"not_requested"},"display":{"status":"not_requested"}})
}
#[test]
fn bluetooth_status_zero_callbacks_is_inventory_only_and_all_is_unchanged() {
    for (before, after) in [(10, 10), (11, 12), (12, 12), (13, 10)] {
        let mut r = observed();
        r["state_before"] = before.into();
        r["state_after"] = after.into();
        r["state_matches_at_checks"] = (before == after).into();
        let typed = inspect_bluetooth_status(&r).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), r);
        let report = envelope(r);
        assert!(
            inspect_report(
                &report.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::BluetoothStatus
            )
            .is_ok()
        );
        assert!(!all_requested_passed(&report, Suite::BluetoothStatus));
    }
    assert!(!Suite::All.requests("bluetooth"));
    assert!(!Suite::BluetoothStatus.records_audio());
    for category in [
        "cameras", "sensors", "audio", "network", "usb", "power", "keystore", "display",
    ] {
        assert!(!Suite::BluetoothStatus.requests(category));
    }
    assert!(MANIFEST.contains("android.permission.BLUETOOTH_CONNECT"));
    assert!(MANIFEST.contains("android:usesPermissionFlags=\"neverForLocation\""));
    for forbidden in [
        "BLUETOOTH_ADVERTISE",
        "BLUETOOTH_ADMIN",
        "ACCESS_FINE_LOCATION",
    ] {
        assert!(!MANIFEST.contains(forbidden));
    }
}
#[test]
fn bluetooth_unavailable_is_unknown_and_never_fabricates_an_adapter() {
    for reason in [
        "permission_denied",
        "manager_unavailable",
        "adapter_unavailable",
    ] {
        let r = unavailable(reason);
        assert!(inspect_bluetooth_status(&r).is_ok());
        assert!(
            inspect_report(
                &envelope(r.clone()).to_string(),
                "fixture",
                11,
                "fixture",
                Suite::BluetoothStatus
            )
            .is_ok()
        );
        let mut bad = r;
        bad["status"] = "observed".into();
        assert!(inspect_bluetooth_status(&bad).is_err());
    }
}
#[test]
fn bluetooth_rejects_invalid_states_window_cleanup_and_scope_overclaims() {
    for (key, bad) in [
        ("state_before", json!(14)),
        ("state_after", json!(-1)),
        ("state_matches_at_checks", json!(false)),
        ("connect_permission_granted", json!(false)),
        ("adapter_present", Value::Null),
        ("window_budget_ms", json!(2001)),
        ("window_elapsed_ms", json!(1999)),
        ("elapsed_ms", json!(6001)),
        ("receiver_registered", json!(false)),
        ("receiver_cleanup_attempted", json!(false)),
        ("receiver_removed", json!(false)),
        ("callback_thread_stopped", json!(false)),
        ("callback_count", json!(33)),
        ("valid_transition_callbacks", json!(1)),
        ("invalid_state_callback", json!(true)),
        ("callback_budget_exceeded", json!(true)),
        ("functionality_verified", json!(true)),
        ("radio_transition_verified", json!(true)),
        ("radio_change_requested", json!(true)),
        ("identifiers_collected", json!(true)),
        ("name", json!("forbidden")),
        ("state", json!("compatible")),
    ] {
        let mut r = observed();
        r[key] = bad;
        assert!(inspect_bluetooth_status(&r).is_err(), "{key}");
    }
    let mut r = observed();
    r["callback_count"] = 2.into();
    r["valid_transition_callbacks"] = 1.into();
    assert!(inspect_bluetooth_status(&r).is_ok());
    r["status"] = "unavailable".into();
    r["reason"] = "cleanup_incomplete".into();
    r["receiver_removed"] = false.into();
    assert!(inspect_bluetooth_status(&r).is_ok());
}

#[test]
fn bluetooth_strict_envelope_rejects_unrequested_data_and_preserves_old_reports() {
    let mut r = envelope(observed());
    r["device_address"] = "forbidden".into();
    assert!(
        inspect_report(
            &r.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::BluetoothStatus
        )
        .is_err()
    );
    let mut r = envelope(observed());
    r["network"] = json!({"status":"not_requested","identifier":"forbidden"});
    assert!(
        inspect_report(
            &r.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::BluetoothStatus
        )
        .is_err()
    );
    let mut r = envelope(observed());
    r["suite"] = "all".into();
    for name in ["cameras", "sensors", "audio"] {
        r[name] = json!({"state":"unknown"});
    }
    assert!(inspect_report(&r.to_string(), "fixture", 11, "fixture", Suite::All).is_err());
    r.as_object_mut().unwrap().remove("bluetooth");
    assert!(inspect_report(&r.to_string(), "fixture", 11, "fixture", Suite::All).is_ok());
}

#[test]
#[cfg(unix)]
fn bluetooth_fake_adb_grants_only_connect_and_refuses_false_pass_on_faults() {
    use std::os::unix::fs::PermissionsExt;
    let work = tempfile::tempdir().unwrap();
    let apk = work.path().join("fixture.apk");
    fs::write(&apk, b"owned fixture, never executed").unwrap();
    let digest = gb_core::hash_file(&apk).unwrap();
    let built = work.path().join("build.json");
    gb_core::write_json(&built,&json!({"status":"owned_hardware_apk_built_not_runtime_verified","package":PACKAGE,
        "source_sha256":gb_core::digest(SOURCE.as_bytes()),"audio_source_sha256":gb_core::digest(AUDIO_SOURCE.as_bytes()),
        "audio_pattern_sha256":gb_core::digest(PATTERN_SOURCE.as_bytes()),"playback_source_sha256":gb_core::digest(PLAYBACK_SOURCE.as_bytes()),
        "auth_key_source_sha256":gb_core::digest(AUTH_SOURCE.as_bytes()),"power_source_sha256":gb_core::digest(POWER_SOURCE.as_bytes()),
        "network_source_sha256":gb_core::digest(NETWORK_SOURCE.as_bytes()),"usb_source_sha256":gb_core::digest(USB_SOURCE.as_bytes()),
        "bluetooth_source_sha256":gb_core::digest(BLUETOOTH_SOURCE.as_bytes()),
        "bluetooth_le_scan_source_sha256":gb_core::digest(BLUETOOTH_LE_SCAN_SOURCE.as_bytes()),"display_source_sha256":gb_core::digest(DISPLAY_SOURCE.as_bytes()),
        "display_pattern_sha256":gb_core::digest(DISPLAY_PATTERN_SOURCE.as_bytes()),"manifest_sha256":gb_core::digest(MANIFEST.as_bytes()),"apk_sha256":digest})).unwrap();
    let path = |name: &str| work.path().join(name);
    let literal = |name: &str| serde_json::to_string(&path(name).to_string_lossy()).unwrap();
    let script = format!(
        r#"#!/usr/bin/env python3
from pathlib import Path
import sys,json,re
a=sys.argv[1:];assert a[:2]==['-s','fixture-serial']
with Path({calls}).open('a') as f:f.write(json.dumps(a[2:])+'\n')
state=Path({installed});mode=Path({mode}).read_text()
if a[2]=='install':state.touch();print('Success');sys.exit()
assert a[2]=='shell' and len(a)==4
c=a[3]
identity={{'getprop ro.serialno':'fixture-serial','getprop ro.build.fingerprint':'fixture','id -u':'2000',
'getenforce':'Enforcing','am get-current-user':'11','am get-started-user-state 11':'RUNNING_UNLOCKED',
'cat /proc/sys/kernel/random/boot_id':'12345678-1234-1234-1234-123456789abc'}}
if c in identity:print(identity[c])
elif c.startswith('pm list packages '):
 if state.exists():print('package:{PACKAGE}')
elif c=='pm path --user 11 {PACKAGE}':print('package:/data/app/~~fixture/pkg/base.apk')
elif c.startswith('sha256sum '):print('{digest}  base.apk')
elif c=='run-as {PACKAGE} --user 11 id -u':print('1110001')
elif c=='pm grant --user 11 {PACKAGE} android.permission.BLUETOOTH_CONNECT':
 if mode=='grant_denied':sys.exit(1)
elif c.startswith('am start -W '):
 assert c.endswith('--es suite bluetooth_status')
 Path({nonce}).write_text(re.search(r'--es run_id ([a-f0-9]{{32}})',c)[1])
elif c.startswith('run-as {PACKAGE} --user 11 cat files/gb-'):
 r=json.loads(Path({fixture}).read_text());r['run_id']=Path({nonce}).read_text();print(json.dumps(r))
elif c=='am force-stop --user 11 {PACKAGE}':pass
elif c=='pm uninstall --user 11 {PACKAGE}':
 if mode=='cleanup_failed':print('Failure')
 else:state.unlink();print('Success')
else:raise AssertionError('unapproved fake operation')
"#,
        calls = literal("calls"),
        installed = literal("installed"),
        mode = literal("mode"),
        nonce = literal("nonce"),
        fixture = literal("fixture")
    );
    fs::write(path("adb"), script).unwrap();
    fs::set_permissions(path("adb"), fs::Permissions::from_mode(0o700)).unwrap();
    let pin = |p: &Path| PinnedFile {
        path: p.to_owned(),
        sha256: gb_core::hash_file(p).unwrap(),
    };
    let r = RunRequest {
        schema_version: 1,
        adb: pin(&path("adb")),
        apk: pin(&apk),
        build_report: pin(&built),
        serial: "fixture-serial".into(),
        fingerprint: "fixture".into(),
        android_user: 11,
        suite: Suite::BluetoothStatus,
    };
    for (i, (observation, mode, expected)) in [
        (observed(), "none", "requested_inventory_observed"),
        (unavailable("permission_denied"), "none", "needs_diagnosis"),
        (
            unavailable("adapter_unavailable"),
            "none",
            "needs_diagnosis",
        ),
        (observed(), "grant_denied", "needs_diagnosis"),
        (observed(), "cleanup_failed", "needs_diagnosis"),
    ]
    .into_iter()
    .enumerate()
    {
        gb_core::write_json(&path("fixture"), &envelope(observation)).unwrap();
        fs::write(path("mode"), mode).unwrap();
        fs::write(path("calls"), "").unwrap();
        let report = run(&r, &path(&format!("report{i}.json"))).unwrap();
        assert_eq!(report["status"], expected);
        assert_eq!(report["bluetooth_functional_state"], "unknown");
        assert_eq!(report["full_port_verified"], false);
        let calls = fs::read_to_string(path("calls")).unwrap();
        assert!(calls.contains("BLUETOOTH_CONNECT"));
        assert!(calls.contains("am force-stop"));
        assert!(calls.contains("pm uninstall"));
        for forbidden in [
            "BLUETOOTH_SCAN",
            "BLUETOOTH_ADVERTISE",
            "CAMERA",
            "RECORD_AUDIO",
            "settings ",
            "svc ",
            "reboot",
        ] {
            assert!(!calls.contains(forbidden));
        }
        if mode == "grant_denied" {
            assert!(!calls.contains("am start"));
        }
        if path("installed").exists() {
            fs::remove_file(path("installed")).unwrap();
        }
    }
}
