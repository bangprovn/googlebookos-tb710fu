use super::*;

fn display_fixture() -> serde_json::Value {
    serde_json::json!({"status":"observed","owned_window_only":true,"settings_changed":false,
        "physical_panel_verified":false,"physical_touch_verified":false,"external_display_verified":false,
        "results":[{"operation":"owned_window_render_readback","state":"compatible","failure":"none",
            "width":256,"height":256,"phases_completed":3,"draw_calls":4,"draw_budget_exceeded":false,
            "frame_callbacks":3,"frame_commit_callbacks":3,"frame_timestamps_increasing":true,
            "hardware_accelerated_view":true,"hardware_accelerated_canvas":true,"pixel_copy_successes":3,
            "last_pixel_copy_result":0,"sampled_pixels":768,"matching_pixels":768,"color_tolerance":4,
            "owned_bitmap_peak_bytes":262144,"bitmap_released":true,"pixel_copy_pending":false,
            "ui_cleanup_completed":true,"owned_view_removed":true,"timed_out":false,
            "work_budget_ms":12000,"elapsed_ms":250,"owned_source_only":true,
            "raw_pixels_saved_or_exported":false,"other_windows_captured":false}]})
}
fn app_fixture() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"display",
        "package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,
        "full_port_verified":false,"user_content_collected":false,"display":display_fixture(),
        "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
        "audio":{"status":"not_requested"},"keystore":{"status":"not_requested"},
        "power":{"status":"not_requested"},"network":{"status":"not_requested"},
        "usb":{"status":"not_requested"}})
}
#[test]
fn display_requires_actual_accelerated_phase_readbacks_callbacks_and_cleanup() {
    let good = app_fixture();
    assert!(inspect_report(&good.to_string(), "fixture", 11, "fixture", Suite::Display).is_ok());
    assert!(all_requested_passed(&good, Suite::Display));
    for (key, bad) in [
        ("hardware_accelerated_view", serde_json::json!(false)),
        ("hardware_accelerated_canvas", serde_json::json!(false)),
        ("matching_pixels", serde_json::json!(512)),
        ("frame_callbacks", serde_json::json!(2)),
        ("frame_commit_callbacks", serde_json::json!(2)),
        ("frame_timestamps_increasing", serde_json::json!(false)),
        ("pixel_copy_successes", serde_json::json!(2)),
        ("last_pixel_copy_result", serde_json::json!(3)),
        ("bitmap_released", serde_json::json!(false)),
        ("pixel_copy_pending", serde_json::json!(true)),
        ("ui_cleanup_completed", serde_json::json!(false)),
        ("owned_view_removed", serde_json::json!(false)),
        ("timed_out", serde_json::json!(true)),
    ] {
        let mut changed = good.clone();
        changed["display"]["results"][0][key] = bad;
        assert!(
            inspect_report(
                &changed.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::Display
            )
            .is_err(),
            "{key}"
        );
    }
}
#[test]
fn display_rejects_capture_scope_privacy_or_budget_escalation() {
    let good = display_fixture();
    for (key, bad) in [
        ("width", serde_json::json!(1920)),
        ("sampled_pixels", serde_json::json!(769)),
        ("owned_bitmap_peak_bytes", serde_json::json!(1048576)),
        ("raw_pixels_saved_or_exported", serde_json::json!(true)),
        ("other_windows_captured", serde_json::json!(true)),
        ("owned_source_only", serde_json::json!(false)),
        ("pixel_values", serde_json::json!([0, 1])),
    ] {
        let mut changed = good.clone();
        changed["results"][0][key] = bad;
        assert!(display::inspect_display(&changed).is_err(), "{key}");
    }
    for key in [
        "settings_changed",
        "physical_panel_verified",
        "physical_touch_verified",
        "external_display_verified",
    ] {
        let mut changed = good.clone();
        changed[key] = true.into();
        assert!(display::inspect_display(&changed).is_err(), "{key}");
    }
}
#[test]
fn display_unavailable_and_failed_phase_stay_unknown_and_historical_all_is_preserved() {
    assert!(!Suite::All.requests("display"));
    assert!(!Suite::Display.records_audio());
    let mut unknown = app_fixture();
    unknown["display"] = serde_json::json!({"state":"unknown"});
    assert!(
        inspect_report(
            &unknown.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::Display
        )
        .is_ok()
    );
    assert!(!all_requested_passed(&unknown, Suite::Display));
    let mut failed = app_fixture();
    failed["display"]["results"][0]["state"] = "unknown".into();
    failed["display"]["results"][0]["matching_pixels"] = 512.into();
    failed["display"]["results"][0]["failure"] = "pattern_mismatch".into();
    assert!(
        inspect_report(
            &failed.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::Display
        )
        .is_ok()
    );
    assert!(!all_requested_passed(&failed, Suite::Display));
    assert!(
        inspect_report(
            &app_fixture().to_string(),
            "fixture",
            11,
            "fixture",
            Suite::Power
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn display_fake_runner_executes_only_owned_suite_without_permissions_and_cleans() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let apk = base.join("fixture.apk");
    fs::write(&apk, b"owned-not-an-APK").unwrap();
    let apk_sha = gb_core::hash_file(&apk).unwrap();
    let fixture = base.join("fixture.json");
    fs::write(&fixture, app_fixture().to_string()).unwrap();
    let adb = base.join("fake-adb");
    let script = format!(
        r##"#!/usr/bin/env python3
from pathlib import Path
import json,sys
base=Path({base:?});args=sys.argv[1:];assert args[:2]==['-s','fixture']
with (base/'commands').open('a') as f:f.write(json.dumps(args[2:])+'\n')
state=base/'installed'
if args[2]=='install':state.touch();print('Success');sys.exit(0)
c=args[3];fixed={{'getprop ro.serialno':'fixture','getprop ro.build.fingerprint':'fixture','id -u':'2000',
'getenforce':'Enforcing','am get-current-user':'11','am get-started-user-state 11':'RUNNING_UNLOCKED',
'cat /proc/sys/kernel/random/boot_id':'12345678-1234-4234-8234-123456789abc'}}
if c in fixed:print(fixed[c])
elif c.startswith('pm list packages'):print('package:{package}' if state.exists() else '')
elif c.startswith('pm path'):print('package:/data/app/fixture/base.apk')
elif c.startswith('sha256sum '):print('{apk_sha}  /data/app/fixture/base.apk')
elif c=='run-as {package} --user 11 id -u':print('1110001')
elif c.startswith('am start '):
 assert c.endswith('--es suite display')
 runid=c.split('--es run_id ')[1].split()[0]
 v=json.loads((base/'fixture.json').read_text());v['run_id']=runid
 (base/'response.json').write_text(json.dumps(v));print('Status: ok')
elif c.startswith('run-as ') and ' cat files/gb-' in c:print((base/'response.json').read_text())
elif c.startswith('am force-stop '):pass
elif c.startswith('pm uninstall '):state.unlink();print('Success')
else:raise SystemExit(99)
"##,
        base = base.to_str().unwrap(),
        package = PACKAGE
    );
    fs::write(&adb, script).unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let provenance = base.join("build.json");
    fs::write(&provenance, serde_json::json!({"status":"owned_hardware_apk_built_not_runtime_verified","package":PACKAGE,
        "source_sha256":gb_core::digest(SOURCE.as_bytes()),"audio_source_sha256":gb_core::digest(AUDIO_SOURCE.as_bytes()),
        "audio_pattern_sha256":gb_core::digest(PATTERN_SOURCE.as_bytes()),"playback_source_sha256":gb_core::digest(PLAYBACK_SOURCE.as_bytes()),
        "auth_key_source_sha256":gb_core::digest(AUTH_SOURCE.as_bytes()),"power_source_sha256":gb_core::digest(POWER_SOURCE.as_bytes()),
        "network_source_sha256":gb_core::digest(NETWORK_SOURCE.as_bytes()),"usb_source_sha256":gb_core::digest(USB_SOURCE.as_bytes()),
        "bluetooth_source_sha256":gb_core::digest(BLUETOOTH_SOURCE.as_bytes()),
        "bluetooth_le_scan_source_sha256":gb_core::digest(BLUETOOTH_LE_SCAN_SOURCE.as_bytes()),
        "display_source_sha256":gb_core::digest(DISPLAY_SOURCE.as_bytes()),"display_pattern_sha256":gb_core::digest(DISPLAY_PATTERN_SOURCE.as_bytes()),
        "manifest_sha256":gb_core::digest(MANIFEST.as_bytes()),"apk_sha256":apk_sha}).to_string()).unwrap();
    let pin = |p: &Path| PinnedFile {
        path: p.into(),
        sha256: gb_core::hash_file(p).unwrap(),
    };
    let request = RunRequest {
        schema_version: 1,
        adb: pin(&adb),
        apk: pin(&apk),
        build_report: pin(&provenance),
        serial: "fixture".into(),
        fingerprint: "fixture".into(),
        android_user: 11,
        suite: Suite::Display,
    };
    let report = run(&request, &base.join("report.json")).unwrap();
    assert_eq!(report["status"], "requested_operation_smoke_passed");
    assert_eq!(report["cleanup_verified"], true);
    assert!(!base.join("installed").exists());
    let commands = fs::read_to_string(base.join("commands")).unwrap();
    assert!(!commands.contains("pm grant"));
    assert!(!commands.contains("screencap") && !commands.contains("input keyevent"));
    assert!(!commands.contains("settings ") && !commands.contains("svc wifi"));
}
