use super::*;
use serde_json::{Value, json};
fn observed() -> Value {
    serde_json::from_str(r#"{"status":"observed","state":"unknown","scope":"anonymous_passive_le_scan_window",
        "reason":"bounded_scan_window_complete","connect_permission_granted":true,"scan_permission_granted":true,
        "le_feature_declared":true,"adapter_present":true,"state_before":12,"state_after":12,
        "state_matches_at_checks":true,"passive_api_verified":true,"scan_mode":"low_power","scan_type":"passive",
        "never_for_location":true,"window_budget_ms":5000,"window_elapsed_ms":5001,"drain_budget_ms":200,
        "drain_elapsed_ms":201,"elapsed_ms":5210,"scan_start_attempted":true,"scan_start_returned":true,
        "scan_stop_attempted":true,"scan_stop_returned":true,"result_callback_count":0,"batch_callback_count":0,
        "failure_callback_count":0,"late_callback_count":0,"late_failure_count":0,"scan_failure":null,
        "invalid_failure_code":false,"callback_budget_exceeded":false,"callback_gate_closed":true,
        "identifiers_collected":false,"payloads_inspected":false,"rssi_collected":false,"batch_entries_inspected":false,
        "user_content_collected":false,"radio_change_requested":false,"paired_devices_accessed":false,
        "advertising_started":false,"connection_opened":false,"rf_verified":false,"peer_verified":false,"phone_link_verified":false}"#).unwrap()
}
fn unavailable() -> Value {
    let mut r = observed();
    r["status"] = "unavailable".into();
    r["reason"] = "permission_denied".into();
    for k in [
        "connect_permission_granted",
        "scan_permission_granted",
        "passive_api_verified",
        "scan_start_attempted",
        "scan_start_returned",
        "scan_stop_attempted",
        "scan_stop_returned",
    ] {
        r[k] = false.into();
    }
    for k in [
        "state_before",
        "state_after",
        "state_matches_at_checks",
        "adapter_present",
    ] {
        r[k] = Value::Null;
    }
    r["window_elapsed_ms"] = 0.into();
    r["drain_elapsed_ms"] = 0.into();
    r["elapsed_ms"] = 1.into();
    r
}
fn envelope(r: Value) -> Value {
    json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"bluetooth_le_scan",
        "package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,
        "full_port_verified":false,"user_content_collected":false,"bluetooth_le_scan":r,
        "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
        "audio":{"status":"not_requested"},"keystore":{"status":"not_requested"},
        "power":{"status":"not_requested"},"network":{"status":"not_requested"},
        "usb":{"status":"not_requested"},"display":{"status":"not_requested"},"bluetooth":{"status":"not_requested"}})
}
#[test]
fn bluetooth_le_scan_counts_never_qualify_rf_or_phone_link_and_all_stays_unchanged() {
    for (result, batch, late) in [(0, 0, 0), (2, 1, 0), (0, 0, 1)] {
        let mut r = observed();
        r["result_callback_count"] = result.into();
        r["batch_callback_count"] = batch.into();
        r["late_callback_count"] = late.into();
        assert_eq!(
            serde_json::to_value(inspect_bluetooth_le_scan(&r).unwrap()).unwrap(),
            r
        );
        let e = envelope(r);
        assert!(
            inspect_report(
                &e.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::BluetoothLeScan
            )
            .is_ok()
        );
        assert!(!all_requested_passed(&e, Suite::BluetoothLeScan));
    }
    assert!(!Suite::All.requests("bluetooth_le_scan"));
    assert!(!Suite::BluetoothStatus.requests("bluetooth_le_scan"));
    assert!(
        !Suite::BluetoothLeScan.requests("bluetooth") && !Suite::BluetoothLeScan.records_audio()
    );
    for category in [
        "cameras", "sensors", "audio", "network", "usb", "power", "keystore", "display",
    ] {
        assert!(!Suite::BluetoothLeScan.requests(category));
    }
}
#[test]
fn bluetooth_le_scan_refuses_peer_fields_rf_claims_invalid_enums_and_lifecycle() {
    for (key, value) in [
        ("peer_name", json!("not accepted")),
        ("state", json!("compatible")),
        ("scan_type", json!("active")),
        ("scan_mode", json!("low_latency")),
        ("scan_failure", json!("made_up")),
        ("state_after", json!(14)),
        ("state_before", json!(10)),
        ("state_matches_at_checks", json!(false)),
        ("passive_api_verified", json!(false)),
        ("scan_start_attempted", json!(false)),
        ("scan_start_returned", json!(false)),
        ("scan_stop_attempted", json!(false)),
        ("scan_stop_returned", json!(false)),
        ("scan_permission_granted", json!(false)),
        ("connect_permission_granted", json!(false)),
        ("window_budget_ms", json!(5001)),
        ("window_elapsed_ms", json!(4999)),
        ("drain_elapsed_ms", json!(199)),
        ("elapsed_ms", json!(9001)),
        ("callback_gate_closed", json!(false)),
        ("result_callback_count", json!(1025)),
        ("callback_budget_exceeded", json!(true)),
        ("rf_verified", json!(true)),
        ("peer_verified", json!(true)),
        ("phone_link_verified", json!(true)),
        ("payloads_inspected", json!(true)),
        ("rssi_collected", json!(true)),
        ("batch_entries_inspected", json!(true)),
        ("identifiers_collected", json!(true)),
        ("never_for_location", json!(false)),
    ] {
        let mut r = observed();
        r[key] = value;
        assert!(inspect_bluetooth_le_scan(&r).is_err(), "{key}");
    }
    let mut e = envelope(observed());
    e["bluetooth"] = json!({"status":"not_requested","name":"forbidden"});
    assert!(
        inspect_report(
            &e.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::BluetoothLeScan
        )
        .is_err()
    );
    let mut e = envelope(observed());
    e["peer_address"] = json!("forbidden");
    assert!(
        inspect_report(
            &e.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::BluetoothLeScan
        )
        .is_err()
    );
}
#[test]
fn bluetooth_le_scan_unavailable_and_late_failures_are_not_completed_windows() {
    assert!(inspect_bluetooth_le_scan(&unavailable()).is_ok());
    let mut missing = unavailable();
    missing["reason"] = "adapter_unavailable".into();
    missing["adapter_present"] = false.into();
    assert!(inspect_bluetooth_le_scan(&missing).is_ok());
    for reason in ["passive_api_unavailable", "scanner_unavailable"] {
        let mut r = unavailable();
        r["reason"] = reason.into();
        assert!(inspect_bluetooth_le_scan(&r).is_ok());
    }
    for (key, reason, code) in [
        ("failure_callback_count", "scan_failed", "internal_error"),
        (
            "late_failure_count",
            "scan_failed",
            "scanning_too_frequently",
        ),
        ("late_failure_count", "invalid_failure_code", "invalid_code"),
    ] {
        let mut r = observed();
        r["status"] = "unavailable".into();
        r["reason"] = reason.into();
        r[key] = 1.into();
        r["scan_failure"] = code.into();
        if code == "invalid_code" {
            r["invalid_failure_code"] = true.into();
        }
        assert!(inspect_bluetooth_le_scan(&r).is_ok());
        r["status"] = "observed".into();
        assert!(inspect_bluetooth_le_scan(&r).is_err());
    }
    let mut r = observed();
    r["status"] = "unavailable".into();
    r["reason"] = "cleanup_incomplete".into();
    r["scan_stop_returned"] = false.into();
    assert!(inspect_bluetooth_le_scan(&r).is_ok());
    r["reason"] = "scan_failed".into();
    assert!(inspect_bluetooth_le_scan(&r).is_err());
    let mut r = unavailable();
    r["result_callback_count"] = 1.into();
    assert!(inspect_bluetooth_le_scan(&r).is_err());
    let mut r = observed();
    r["status"] = "unavailable".into();
    r["reason"] = "callback_budget_exceeded".into();
    r["result_callback_count"] = 1024.into();
    r["callback_budget_exceeded"] = true.into();
    assert!(inspect_bluetooth_le_scan(&r).is_ok());
    r["result_callback_count"] = 1023.into();
    assert!(inspect_bluetooth_le_scan(&r).is_err());
}

#[test]
#[cfg(unix)]
fn bluetooth_le_scan_fake_adb_grants_only_connect_and_scan_with_owned_cleanup() {
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
elif c in ['pm grant --user 11 {PACKAGE} android.permission.BLUETOOTH_CONNECT','pm grant --user 11 {PACKAGE} android.permission.BLUETOOTH_SCAN']:
 if mode=='grant_denied':sys.exit(1)
elif c.startswith('am start -W '):
 assert c.endswith('--es suite bluetooth_le_scan')
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
        suite: Suite::BluetoothLeScan,
    };
    for (i, (observation, mode, expected)) in [
        (observed(), "none", "requested_inventory_observed"),
        (unavailable(), "none", "needs_diagnosis"),
        (unavailable(), "none", "needs_diagnosis"),
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
        if mode != "grant_denied" {
            assert!(calls.contains("BLUETOOTH_SCAN"));
        }
        assert!(calls.contains("am force-stop"));
        assert!(calls.contains("pm uninstall"));
        for forbidden in [
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
