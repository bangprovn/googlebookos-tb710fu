use super::*;
use serde_json::{Value, json};

fn inventory() -> Value {
    json!({"status":"observed","state":"unknown","scope":"public_api_inventory_only",
        "reason":"snapshot_complete","host_feature_declared":true,"attached_device_count":2,
        "configuration_descriptor_count":3,"interface_descriptor_count":4,
        "device_class_counts":[{"usb_class":0,"count":1},{"usb_class":9,"count":1}],
        "interface_class_counts":[{"usb_class":3,"count":2},{"usb_class":8,"count":2}],
        "inventory_complete":true,"observation_budget_exceeded":false,"read_only":true,
        "permission_requested":false,"device_opened":false,"transfer_performed":false,
        "role_or_settings_changed":false,"identifiers_collected":false,"content_collected":false,
        "host_functionality_verified":false,"typec_or_pd_verified":false})
}
fn envelope(usb: Value) -> Value {
    json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"usb_inventory",
        "package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,
        "full_port_verified":false,"user_content_collected":false,"usb":usb,
        "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
        "audio":{"status":"not_requested"},"keystore":{"status":"not_requested"},
        "power":{"status":"not_requested"},"network":{"status":"not_requested"}})
}
fn empty() -> Value {
    let mut value = inventory();
    for key in [
        "attached_device_count",
        "configuration_descriptor_count",
        "interface_descriptor_count",
    ] {
        value[key] = 0.into();
    }
    value["device_class_counts"] = json!([]);
    value["interface_class_counts"] = json!([]);
    value
}
fn unavailable(reason: &str) -> Value {
    let mut value = empty();
    value["status"] = "unavailable".into();
    value["reason"] = reason.into();
    value["inventory_complete"] = false.into();
    value["observation_budget_exceeded"] = (reason == "budget_exceeded").into();
    for key in [
        "attached_device_count",
        "configuration_descriptor_count",
        "interface_descriptor_count",
    ] {
        value[key] = Value::Null;
    }
    value
}

#[test]
fn usb_inventory_is_typed_bounded_and_never_a_functional_pass() {
    for value in [inventory(), empty()] {
        for feature in [json!(true), json!(false), Value::Null] {
            let mut value = value.clone();
            value["host_feature_declared"] = feature;
            let typed = inspect_usb_inventory(&value).unwrap();
            assert_eq!(typed.state, UsbFunctionalState::Unknown);
            assert_eq!(serde_json::to_value(typed).unwrap(), value);
            let report = envelope(value);
            assert!(
                inspect_report(
                    &report.to_string(),
                    "fixture",
                    11,
                    "fixture",
                    Suite::UsbInventory
                )
                .is_ok()
            );
            assert!(!all_requested_passed(&report, Suite::UsbInventory));
        }
    }
    assert!(!Suite::All.requests("usb"));
    assert!(Suite::UsbInventory.requests("usb"));
    for category in [
        "sensors", "cameras", "audio", "keystore", "power", "network",
    ] {
        assert!(!Suite::UsbInventory.requests(category));
    }
    assert!(!Suite::UsbInventory.records_audio());
    assert_eq!(
        serde_json::from_str::<Suite>("\"usb_inventory\"").unwrap(),
        Suite::UsbInventory
    );
    let mut historical = envelope(Value::Null);
    historical["suite"] = "all".into();
    historical.as_object_mut().unwrap().remove("usb");
    for category in ["sensors", "cameras", "audio"] {
        historical[category] = json!({"state":"unknown"});
    }
    assert!(
        inspect_report(
            &historical.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::All
        )
        .is_ok()
    );
    let mut private_unrequested = historical.clone();
    private_unrequested["usb"] = json!({"status":"not_requested","serial":"forbidden"});
    assert!(
        inspect_report(
            &private_unrequested.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::All
        )
        .is_err()
    );
    let mut unrequested = historical;
    unrequested["usb"] = inventory();
    assert!(
        inspect_report(
            &unrequested.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::All
        )
        .is_err()
    );
}

#[test]
fn usb_inventory_rejects_identifiers_fabricated_verdicts_and_inconsistent_counts() {
    for (key, bad) in [
        ("state", json!("compatible")),
        ("scope", json!("functional_test")),
        ("reason", json!("api_exception")),
        ("attached_device_count", json!(33)),
        ("attached_device_count", json!(-1)),
        ("attached_device_count", json!(1.5)),
        ("configuration_descriptor_count", json!(129)),
        ("configuration_descriptor_count", json!(0)),
        ("interface_descriptor_count", json!(513)),
        ("interface_descriptor_count", json!(3)),
        ("inventory_complete", json!(false)),
        ("observation_budget_exceeded", json!(true)),
        ("read_only", json!(false)),
    ] {
        let mut value = inventory();
        value[key] = bad;
        assert!(inspect_usb_inventory(&value).is_err(), "{key}");
    }
    for key in [
        "permission_requested",
        "device_opened",
        "transfer_performed",
        "role_or_settings_changed",
        "identifiers_collected",
        "content_collected",
        "host_functionality_verified",
        "typec_or_pd_verified",
    ] {
        let mut value = inventory();
        value[key] = true.into();
        assert!(inspect_usb_inventory(&value).is_err(), "{key}");
    }
    for key in [
        "vid", "pid", "serial", "product", "name", "address", "content",
    ] {
        let mut value = inventory();
        value[key] = "must not export".into();
        assert!(inspect_usb_inventory(&value).is_err(), "{key}");
        let mut value = inventory();
        value["device_class_counts"][0][key] = "must not export".into();
        assert!(inspect_usb_inventory(&value).is_err(), "nested {key}");
    }
    for rows in [
        json!([{"usb_class":9,"count":1},{"usb_class":0,"count":1}]),
        json!([{"usb_class":0,"count":1},{"usb_class":0,"count":1}]),
        json!([{"usb_class":0,"count":0},{"usb_class":9,"count":2}]),
        json!([{"usb_class":256,"count":2}]),
        json!([{"usb_class":-1,"count":2}]),
        json!([{"usb_class":0,"count":33}]),
        json!([{"usb_class":0,"count":1}]),
    ] {
        let mut value = inventory();
        value["device_class_counts"] = rows;
        assert!(inspect_usb_inventory(&value).is_err());
    }
    for category in [None, Some("power"), Some("network")] {
        let mut report = envelope(inventory());
        if let Some(category) = category {
            report[category]["serial"] = "forbidden".into();
        } else {
            report["serial"] = "forbidden".into();
        }
        assert!(
            inspect_report(
                &report.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::UsbInventory
            )
            .is_err()
        );
    }
    for (key, invalid) in [
        ("camera_image_quality_verified", json!("peripheral-serial")),
        (
            "physical_rotation_or_calibration_verified",
            json!({"serial":"forbidden"}),
        ),
        ("camera_image_quality_verified", json!(true)),
        ("elapsed_realtime_ms", json!({"serial":"forbidden"})),
        ("elapsed_realtime_ms", json!("peripheral-serial")),
        ("elapsed_realtime_ms", json!(-1)),
        ("elapsed_realtime_ms", json!(1.5)),
        ("elapsed_realtime_ms", json!(u64::MAX)),
    ] {
        let mut report = envelope(inventory());
        report[key] = invalid;
        assert!(
            inspect_report(
                &report.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::UsbInventory
            )
            .is_err(),
            "{key}"
        );
    }
    for elapsed in [0, i64::MAX] {
        let mut report = envelope(empty());
        report["camera_image_quality_verified"] = false.into();
        report["physical_rotation_or_calibration_verified"] = false.into();
        report["elapsed_realtime_ms"] = elapsed.into();
        assert!(
            inspect_report(
                &report.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::UsbInventory
            )
            .is_ok()
        );
    }
    let mut boundary = inventory();
    boundary["interface_descriptor_count"] = 512.into();
    boundary["interface_class_counts"] = json!([{"usb_class":255,"count":512}]);
    assert!(inspect_usb_inventory(&boundary).is_ok());
    boundary["interface_class_counts"] = json!(
        (0..256)
            .map(|code| json!({"usb_class":code,"count":2}))
            .collect::<Vec<_>>()
    );
    assert!(inspect_usb_inventory(&boundary).is_ok());
}

#[test]
fn usb_unavailable_is_explicit_unknown_without_partial_inventory() {
    for reason in [
        "usb_manager_unavailable",
        "api_exception",
        "budget_exceeded",
        "invalid_descriptor",
    ] {
        let good = unavailable(reason);
        assert!(inspect_usb_inventory(&good).is_ok());
        for (key, bad) in [
            ("attached_device_count", json!(0)),
            ("configuration_descriptor_count", json!(0)),
            ("interface_descriptor_count", json!(0)),
            ("inventory_complete", json!(true)),
            ("reason", json!("snapshot_complete")),
            (
                "observation_budget_exceeded",
                json!(reason != "budget_exceeded"),
            ),
        ] {
            let mut value = good.clone();
            value[key] = bad;
            assert!(inspect_usb_inventory(&value).is_err());
        }
    }
}

#[test]
#[cfg(unix)]
fn usb_runner_fake_adb_uses_no_usb_permissions_or_transfers_and_always_cleans() {
    use std::os::unix::fs::PermissionsExt;
    let work = tempfile::tempdir().unwrap();
    let apk = work.path().join("fixture.apk");
    fs::write(&apk, b"owned fake APK, never executed").unwrap();
    let digest = gb_core::hash_file(&apk).unwrap();
    let built = work.path().join("build.json");
    gb_core::write_json(
        &built,
        &json!({"status":"owned_hardware_apk_built_not_runtime_verified","package":PACKAGE,
            "source_sha256":gb_core::digest(SOURCE.as_bytes()),
            "audio_source_sha256":gb_core::digest(AUDIO_SOURCE.as_bytes()),
            "audio_pattern_sha256":gb_core::digest(PATTERN_SOURCE.as_bytes()),
            "playback_source_sha256":gb_core::digest(PLAYBACK_SOURCE.as_bytes()),
            "auth_key_source_sha256":gb_core::digest(AUTH_SOURCE.as_bytes()),
            "power_source_sha256":gb_core::digest(POWER_SOURCE.as_bytes()),
            "network_source_sha256":gb_core::digest(NETWORK_SOURCE.as_bytes()),
            "bluetooth_source_sha256":gb_core::digest(BLUETOOTH_SOURCE.as_bytes()),
            "bluetooth_le_scan_source_sha256":gb_core::digest(BLUETOOTH_LE_SCAN_SOURCE.as_bytes()),
            "usb_source_sha256":gb_core::digest(USB_SOURCE.as_bytes()),
            "display_source_sha256":gb_core::digest(DISPLAY_SOURCE.as_bytes()),
            "display_pattern_sha256":gb_core::digest(DISPLAY_PATTERN_SOURCE.as_bytes()),
            "manifest_sha256":gb_core::digest(MANIFEST.as_bytes()),"apk_sha256":digest}),
    )
    .unwrap();
    let fixture = work.path().join("fixture.json");
    let installed = work.path().join("installed");
    let calls = work.path().join("calls.jsonl");
    let nonce = work.path().join("nonce");
    let adb = work.path().join("fake-adb");
    let mode = work.path().join("mode");
    let responded = work.path().join("responded");
    let literal = |path: &Path| serde_json::to_string(&path.to_string_lossy()).unwrap();
    let script = format!(
        r#"#!/usr/bin/env python3
from pathlib import Path
import sys,json,re
args=sys.argv[1:];assert args[:2]==['-s','fixture-serial']
with Path({calls}).open('a') as stream:stream.write(json.dumps(args[2:])+'\n')
state=Path({installed});mode=Path({mode}).read_text()
if args[2]=='install':
 assert '-r' not in args;state.write_text('owned');print('Success');sys.exit()
assert args[2]=='shell' and len(args)==4
c=args[3]
values={{'getprop ro.serialno':'fixture-serial','getprop ro.build.fingerprint':'fixture',
 'id -u':'2000','getenforce':'Enforcing','am get-current-user':'11',
 'am get-started-user-state 11':'RUNNING_UNLOCKED',
 'cat /proc/sys/kernel/random/boot_id':'12345678-1234-1234-1234-123456789abc'}}
if c in values:print('87654321-1234-1234-1234-123456789abc' if mode=='boot_changed' and c=='cat /proc/sys/kernel/random/boot_id' and Path({responded}).exists() else values[c])
elif c.startswith('pm list packages '):
 if state.exists():print('package:{package}')
elif c=='pm path --user 11 {package}':print('package:/data/app/~~fixture/pkg/base.apk')
elif c.startswith('sha256sum '):print('{digest}  base.apk')
elif c=='run-as {package} --user 11 id -u':print('1110001')
elif c.startswith('am start -W '):
 assert c.endswith('--es suite usb_inventory')
 Path({nonce}).write_text(re.search(r'--es run_id ([a-f0-9]{{32}})',c)[1])
elif c.startswith('run-as {package} --user 11 cat files/gb-'):
 r=json.loads(Path({fixture}).read_text());r['run_id']=Path({nonce}).read_text();Path({responded}).touch();print(json.dumps(r))
elif c=='am force-stop --user 11 {package}':pass
elif c=='pm uninstall --user 11 {package}':
 if mode=='cleanup_failed':print('Failure [owned fake cleanup failure]')
 else:state.unlink();print('Success')
else:raise AssertionError('unexpected fake operation, including USB permission/opens/settings')
"#,
        calls = literal(&calls),
        installed = literal(&installed),
        nonce = literal(&nonce),
        fixture = literal(&fixture),
        mode = literal(&mode),
        responded = literal(&responded),
        package = PACKAGE,
    );
    fs::write(&adb, script).unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let pin = |path: &Path| PinnedFile {
        path: path.to_path_buf(),
        sha256: gb_core::hash_file(path).unwrap(),
    };
    let mut request = RunRequest {
        schema_version: 1,
        adb: pin(&adb),
        apk: pin(&apk),
        build_report: pin(&built),
        serial: "fixture-serial".into(),
        fingerprint: "fixture".into(),
        android_user: 11,
        suite: Suite::UsbInventory,
    };
    let mut overclaim = inventory();
    overclaim["state"] = "compatible".into();
    let mut private = inventory();
    private["serial"] = "forbidden".into();
    let mut mismatch = inventory();
    mismatch["interface_descriptor_count"] = 5.into();
    for (index, (value, invalid, observed, fault)) in [
        (inventory(), false, true, "none"),
        (empty(), false, true, "none"),
        (unavailable("usb_manager_unavailable"), false, false, "none"),
        (unavailable("budget_exceeded"), false, false, "none"),
        (overclaim, true, false, "none"),
        (private, true, false, "none"),
        (mismatch, true, false, "none"),
        (inventory(), false, true, "boot_changed"),
        (inventory(), false, true, "cleanup_failed"),
    ]
    .into_iter()
    .enumerate()
    {
        gb_core::write_json(&fixture, &envelope(value)).unwrap();
        fs::write(&calls, "").unwrap();
        fs::write(&mode, fault).unwrap();
        let _ = fs::remove_file(&responded);
        let report = run(&request, &work.path().join(format!("report{index}.json"))).unwrap();
        assert_eq!(
            report["status"],
            if observed && fault == "none" {
                "requested_inventory_observed"
            } else {
                "needs_diagnosis"
            }
        );
        assert_eq!(report["usb_inventory_observed"], observed);
        assert_eq!(report["usb_functional_state"], "unknown");
        assert_eq!(report["cleanup_verified"], fault != "cleanup_failed");
        assert_eq!(report["host_boot_unchanged"], fault != "boot_changed");
        assert_eq!(report["firmware_written"], false);
        assert_eq!(report["full_port_verified"], false);
        assert_eq!(report["execution_error"].is_string(), invalid);
        assert_eq!(installed.exists(), fault == "cleanup_failed");
        if installed.exists() {
            fs::remove_file(&installed).unwrap();
        }
        let commands = fs::read_to_string(&calls).unwrap();
        for forbidden in [
            "pm grant",
            "requestPermission",
            "openDevice",
            "settings ",
            "svc ",
            "reboot",
            "dumpsys usb",
        ] {
            assert!(!commands.contains(forbidden), "{forbidden}");
        }
        assert!(commands.contains("am force-stop"));
        assert!(commands.contains("pm uninstall"));
    }
    // An old APK provenance record is never silently relabeled as including USB.
    let mut stale: Value = gb_core::read_json(&built, 65536).unwrap();
    stale.as_object_mut().unwrap().remove("usb_source_sha256");
    gb_core::write_json(&built, &stale).unwrap();
    request.build_report = pin(&built);
    fs::write(&calls, "").unwrap();
    let output = work.path().join("stale-provenance.json");
    assert!(
        run(&request, &output)
            .unwrap_err()
            .to_string()
            .contains("APK source/build provenance mismatch")
    );
    assert!(!output.exists());
    assert!(fs::read_to_string(&calls).unwrap().is_empty());
}
