//! Foreground owned-app sensor/camera operations; no system APK replacement.
use crate::{functional_probe, rro::PinnedFile};
use anyhow::{Context, Result, ensure};
use gb_tools::{Inputs, ReadOnlyInput};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{Duration, Instant},
};

mod bluetooth;
mod bluetooth_le_scan;
pub use bluetooth::{
    BluetoothAdapterState, BluetoothFunctionalState, BluetoothStatus, BluetoothStatusObservation,
    BluetoothStatusReason, BluetoothStatusScope, inspect_bluetooth_status,
};
pub use bluetooth_le_scan::{
    BluetoothLeScanFailure, BluetoothLeScanMode, BluetoothLeScanObservation, BluetoothLeScanReason,
    BluetoothLeScanScope, BluetoothLeScanStatus, BluetoothLeScanType, inspect_bluetooth_le_scan,
};
mod display;
mod ui_observer;
pub use ui_observer::{
    UiObserverCachePolicy, UiObserverFinal, UiObserverObservation, UiObserverProbe,
    UiObserverReady, UiObserverRecord, UiObserverSample, UiObserverStatus, inspect_ui_observer,
};
mod usb;
pub use usb::{
    UsbClassCount, UsbFunctionalState, UsbInventory, UsbInventoryReason, UsbInventoryScope,
    UsbInventoryStatus, inspect_usb_inventory,
};

const PACKAGE: &str = "org.googlebook.port.hardwareprobe";
const SOURCE: &str = include_str!("hardware_probe/HardwareProbeActivity.java");
const AUDIO_SOURCE: &str = include_str!("hardware_probe/AudioProbe.java");
const PATTERN_SOURCE: &str = include_str!("hardware_probe/AudioPattern.java");
const PLAYBACK_SOURCE: &str = include_str!("hardware_probe/AudioPlaybackInstrumentation.java");
const AUTH_SOURCE: &str = include_str!("hardware_probe/AuthKeyProbe.java");
const POWER_SOURCE: &str = include_str!("hardware_probe/PowerProbe.java");
const NETWORK_SOURCE: &str = include_str!("hardware_probe/NetworkProbe.java");
const USB_SOURCE: &str = include_str!("hardware_probe/UsbProbe.java");
const BLUETOOTH_LE_SCAN_SOURCE: &str = include_str!("hardware_probe/BluetoothLeScanProbe.java");
const BLUETOOTH_SOURCE: &str = include_str!("hardware_probe/BluetoothProbe.java");
const DISPLAY_SOURCE: &str = include_str!("hardware_probe/DisplayProbe.java");
const DISPLAY_PATTERN_SOURCE: &str = include_str!("hardware_probe/DisplayPattern.java");
const UI_OBSERVER_SOURCE: &str = include_str!("hardware_probe/TerminalUiObserver.java");
const UI_OBSERVER_PACKAGE: &str = "org.googlebook.port.terminaluiobserver";
const UI_OBSERVER_MANIFEST: &str = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.googlebook.port.terminaluiobserver" android:versionCode="1">
<uses-sdk android:minSdkVersion="31" android:targetSdkVersion="36"/>
<application android:label="Googlebook Terminal UI diagnostics" android:debuggable="true" android:testOnly="true" android:allowBackup="false" android:hasCode="true"/>
<instrumentation android:name=".TerminalUiObserver" android:targetPackage="org.googlebook.port.terminaluiobserver" android:functionalTest="true"/>
</manifest>"#;
const MANIFEST: &str = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.googlebook.port.hardwareprobe" android:versionCode="1">
<uses-sdk android:minSdkVersion="31" android:targetSdkVersion="36"/>
<uses-permission android:name="android.permission.CAMERA"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT"/>
<uses-permission android:name="android.permission.BLUETOOTH_SCAN" android:usesPermissionFlags="neverForLocation"/>
<uses-feature android:name="android.hardware.bluetooth" android:required="false"/>
<uses-feature android:name="android.hardware.bluetooth_le" android:required="false"/>
<uses-feature android:name="android.hardware.usb.host" android:required="false"/>
<uses-feature android:name="android.hardware.camera" android:required="false"/>
<uses-feature android:name="android.hardware.camera.any" android:required="false"/>
<uses-feature android:name="android.hardware.camera.autofocus" android:required="false"/>
<application android:label="Googlebook hardware diagnostics" android:debuggable="true" android:testOnly="true" android:allowBackup="false" android:hasCode="true">
<activity android:name=".HardwareProbeActivity" android:exported="true" android:permission="android.permission.DUMP" android:configChanges="keyboardHidden|orientation|screenSize"/>
</application>
<instrumentation android:name=".AudioPlaybackInstrumentation" android:targetPackage="org.googlebook.port.hardwareprobe"/>
</manifest>"#;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    pub schema_version: u32,
    pub java: functional_probe::BuildRequest,
    pub apk_tools: BTreeMap<String, PinnedFile>,
}
impl BuildRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in r.java.tools.values_mut().chain(r.apk_tools.values_mut()) {
            if p.path.is_relative() {
                p.path = parent.join(&p.path);
            }
        }
        r.validate()?;
        Ok(r)
    }
    fn validate(&self) -> Result<()> {
        let names = ["aapt2", "zipalign", "apksigner", "key", "certificate"];
        ensure!(
            self.schema_version == 1
                && self.apk_tools.len() == names.len()
                && names.iter().all(|k| self.apk_tools.contains_key(*k)),
            "unexpected APK tool/schema"
        );
        self.java.sandbox.validate()
    }
}
pub fn build(r: &BuildRequest, destination: &Path) -> Result<serde_json::Value> {
    build_apk(r, destination, false)
}

/// Build an isolated UI test APK. Its instrumentation targets its own package,
/// receives no runtime permissions and never attaches to the original Terminal.
pub fn build_ui_observer(r: &BuildRequest, destination: &Path) -> Result<serde_json::Value> {
    build_apk(r, destination, true)
}

fn build_apk(r: &BuildRequest, destination: &Path, ui_observer: bool) -> Result<serde_json::Value> {
    r.validate()?;
    ensure!(!destination.exists(), "output exists");
    for p in r.apk_tools.values().chain(r.java.tools.values()) {
        p.verify()?;
        gb_core::separate_from_input(&p.path, destination)?;
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = tempfile::Builder::new()
        .prefix(".gb-hardware-")
        .tempdir_in(parent)?;
    let output = temp.path().join("output");
    let resources = temp.path().join("resources");
    fs::create_dir_all(&output)?;
    fs::create_dir_all(resources.join("java-home/conf/security"))?;
    let sources = if ui_observer {
        vec![("TerminalUiObserver.java", UI_OBSERVER_SOURCE)]
    } else {
        vec![
            ("HardwareProbeActivity.java", SOURCE),
            ("AudioProbe.java", AUDIO_SOURCE),
            ("AudioPattern.java", PATTERN_SOURCE),
            ("AudioPlaybackInstrumentation.java", PLAYBACK_SOURCE),
            ("AuthKeyProbe.java", AUTH_SOURCE),
            ("PowerProbe.java", POWER_SOURCE),
            ("NetworkProbe.java", NETWORK_SOURCE),
            ("UsbProbe.java", USB_SOURCE),
            ("BluetoothProbe.java", BLUETOOTH_SOURCE),
            ("BluetoothLeScanProbe.java", BLUETOOTH_LE_SCAN_SOURCE),
            ("DisplayProbe.java", DISPLAY_SOURCE),
            ("DisplayPattern.java", DISPLAY_PATTERN_SOURCE),
        ]
    };
    let manifest = if ui_observer {
        UI_OBSERVER_MANIFEST
    } else {
        MANIFEST
    };
    let apk_filename = if ui_observer {
        "terminal-ui-observer.apk"
    } else {
        "hardware-probe.apk"
    };
    let sandbox_apk = if ui_observer {
        "/output/terminal-ui-observer.apk"
    } else {
        "/output/hardware-probe.apk"
    };
    let java_report =
        functional_probe::build_owned_sources(&r.java, &output.join("java"), &sources, None)?;
    fs::write(resources.join("AndroidManifest.xml"), manifest)?;
    fs::copy(
        &r.java.tools["security"].path,
        resources.join("java-home/conf/security/java.security"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/inputs/java-runtime/lib", resources.join("java-home/lib"))?;
    let java = r.java.tools["java"].path.canonicalize()?;
    let runtime = java.parent().and_then(Path::parent).context("JDK layout")?;
    let tool = |name: &str| r.apk_tools[name].path.as_path();
    let mut receipts = Vec::new();
    let mut run = |name: &str, args: &[&str], signing: bool| -> Result<String> {
        let program = if name == "launcher" {
            r.java.tools[name].path.as_path()
        } else {
            tool(name)
        };
        let mut extra = vec![
            ReadOnlyInput {
                name: "resources",
                path: &resources,
            },
            ReadOnlyInput {
                name: "java-runtime",
                path: runtime,
            },
            ReadOnlyInput {
                name: "security",
                path: &r.java.tools["security"].path,
            },
            ReadOnlyInput {
                name: "apksigner",
                path: tool("apksigner"),
            },
        ];
        if signing {
            extra.push(ReadOnlyInput {
                name: "key",
                path: tool("key"),
            });
            extra.push(ReadOnlyInput {
                name: "certificate",
                path: tool("certificate"),
            });
        }
        let receipt = gb_tools::run_mounted(
            &r.java.sandbox,
            program,
            args.iter().map(|s| (*s).into()).collect(),
            Inputs {
                primary: &r.java.tools["android"].path,
                extra: &extra,
                source_date_epoch: Some(0),
            },
            &output,
            Duration::from_secs(120),
        )?;
        ensure!(
            !receipt.stderr_truncated && receipt.stdout.len() < 65536,
            "APK tool receipt budget"
        );
        let text = receipt.stdout.clone();
        receipts.push(receipt);
        Ok(text)
    };
    let aapt_version = run("aapt2", &["version"], false)?;
    run(
        "aapt2",
        &[
            "link",
            "-I",
            "/input.img",
            "--manifest",
            "/inputs/resources/AndroidManifest.xml",
            "-o",
            "/output/unsigned.apk",
        ],
        false,
    )?;
    let mut source = zip::ZipArchive::new(fs::File::open(output.join("java/probe.jar"))?)?;
    let mut dex = source.by_name("classes.dex")?;
    ensure!(dex.size() <= 128 * 1024, "DEX budget");
    let mut apk = zip::ZipWriter::new_append(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(output.join("unsigned.apk"))?,
    )?;
    apk.start_file(
        "classes.dex",
        zip::write::SimpleFileOptions::default()
            .last_modified_time(zip::DateTime::default())
            .compression_method(zip::CompressionMethod::Stored),
    )?;
    std::io::copy(&mut dex, &mut apk)?;
    apk.finish()?.sync_all()?;
    run(
        "zipalign",
        &["-f", "4", "/output/unsigned.apk", "/output/aligned.apk"],
        false,
    )?;
    let signer_version = run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-jar",
            "/inputs/apksigner",
            "version",
        ],
        false,
    )?;
    run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-jar",
            "/inputs/apksigner",
            "sign",
            "--key",
            "/inputs/key",
            "--cert",
            "/inputs/certificate",
            "--v1-signing-enabled",
            "false",
            "--v2-signing-enabled",
            "true",
            "--v3-signing-enabled",
            "false",
            "--v4-signing-enabled",
            "false",
            "--out",
            sandbox_apk,
            "/output/aligned.apk",
        ],
        true,
    )?;
    let signature = run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-jar",
            "/inputs/apksigner",
            "verify",
            "--verbose",
            "--print-certs",
            sandbox_apk,
        ],
        false,
    )?;
    ensure!(
        signature.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "APK signature not verified"
    );
    for p in r.apk_tools.values().chain(r.java.tools.values()) {
        p.verify()?;
    }
    let zipalign_identity = gb_tools::identity(tool("zipalign"), &r.java.sandbox)?;
    let mut report = serde_json::json!({"schema_version":1,
        "status":if ui_observer { "owned_terminal_ui_observer_apk_built_not_runtime_verified" } else { "owned_hardware_apk_built_not_runtime_verified" },
        "package":if ui_observer { UI_OBSERVER_PACKAGE } else { PACKAGE },
        "apk_sha256":gb_core::hash_file(&output.join(apk_filename))?,"manifest_sha256":gb_core::digest(manifest.as_bytes()),
        "java_build":java_report,"tools":r.apk_tools,"tool_versions":{"aapt2":aapt_version,"apksigner":signer_version},"zipalign_identity":zipalign_identity,"signature_verification":signature,"commands":receipts,"firmware_written":false,"runtime_verified":false});
    let provenance = if ui_observer {
        vec![("ui_observer_source_sha256", UI_OBSERVER_SOURCE)]
    } else {
        vec![
            ("source_sha256", SOURCE),
            ("audio_source_sha256", AUDIO_SOURCE),
            ("audio_pattern_sha256", PATTERN_SOURCE),
            ("playback_source_sha256", PLAYBACK_SOURCE),
            ("auth_key_source_sha256", AUTH_SOURCE),
            ("power_source_sha256", POWER_SOURCE),
            ("network_source_sha256", NETWORK_SOURCE),
            ("usb_source_sha256", USB_SOURCE),
            ("bluetooth_source_sha256", BLUETOOTH_SOURCE),
            ("bluetooth_le_scan_source_sha256", BLUETOOTH_LE_SCAN_SOURCE),
            ("display_source_sha256", DISPLAY_SOURCE),
            ("display_pattern_sha256", DISPLAY_PATTERN_SOURCE),
        ]
    };
    for (key, source) in provenance {
        report[key] = gb_core::digest(source.as_bytes()).into();
    }
    gb_core::write_json(&output.join("build-report.json"), &report)?;
    gb_core::publish_directory(&output, destination)?;
    Ok(report)
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Suite {
    #[default]
    All,
    Sensors,
    Cameras,
    Audio,
    AudioCapturePattern,
    AudioPlaybackPattern,
    AuthBoundKeys,
    Power,
    Network,
    UsbInventory,
    BluetoothStatus,
    BluetoothLeScan,
    Display,
}
impl Suite {
    fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Sensors => "sensors",
            Self::Cameras => "cameras",
            Self::Audio => "audio",
            Self::AudioCapturePattern => "audio_capture_pattern",
            Self::AudioPlaybackPattern => "audio_playback_pattern",
            Self::AuthBoundKeys => "auth_bound_keys",
            Self::Power => "power",
            Self::Network => "network",
            Self::UsbInventory => "usb_inventory",
            Self::BluetoothStatus => "bluetooth_status",
            Self::BluetoothLeScan => "bluetooth_le_scan",
            Self::Display => "display",
        }
    }
    fn requests(self, category: &str) -> bool {
        (self == Self::All
            && ![
                "keystore",
                "power",
                "network",
                "usb",
                "display",
                "bluetooth",
                "bluetooth_le_scan",
            ]
            .contains(&category))
            || self.name() == category
            || (self == Self::AuthBoundKeys && category == "keystore")
            || (self == Self::UsbInventory && category == "usb")
            || (self == Self::BluetoothStatus && category == "bluetooth")
            || (matches!(self, Self::AudioCapturePattern | Self::AudioPlaybackPattern)
                && category == "audio")
    }
    fn records_audio(self) -> bool {
        matches!(self, Self::All | Self::Audio | Self::AudioCapturePattern)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub schema_version: u32,
    pub adb: PinnedFile,
    pub apk: PinnedFile,
    pub build_report: PinnedFile,
    pub serial: String,
    pub fingerprint: String,
    pub android_user: u32,
    #[serde(default)]
    pub suite: Suite,
}
impl RunRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        for p in [&mut r.adb, &mut r.apk, &mut r.build_report] {
            if p.path.is_relative() {
                p.path = path.parent().unwrap_or(Path::new(".")).join(&p.path);
            }
        }
        ensure!(
            r.schema_version == 1
                && !r.serial.is_empty()
                && r.serial.len() <= 64
                && r.serial
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && r.android_user <= 32
                && !r.fingerprint.is_empty()
                && r.fingerprint.len() < 512,
            "device request schema/identity budget"
        );
        Ok(r)
    }
}
pub fn inspect_report(
    text: &str,
    run_id: &str,
    user: u32,
    fingerprint: &str,
    suite: Suite,
) -> Result<serde_json::Value> {
    ensure!(text.len() < 65536, "hardware response budget");
    let v: serde_json::Value = serde_json::from_str(text)?;
    ensure!(
        v["schema_version"] == 1
            && v["probe"] == "owned_android_hardware_v1"
            && v["package"] == PACKAGE
            && v["run_id"] == run_id
            && v["fingerprint"] == fingerprint
            && v["full_port_verified"] == false
            && v["user_content_collected"] == false,
        "wrong probe identity/scope"
    );
    ensure!(v["suite"] == suite.name(), "wrong requested hardware suite");
    if matches!(
        suite,
        Suite::UsbInventory | Suite::BluetoothStatus | Suite::BluetoothLeScan
    ) {
        let allowed = [
            "schema_version",
            "probe",
            "package",
            "run_id",
            "fingerprint",
            "suite",
            "uid",
            "sensors",
            "cameras",
            "audio",
            "keystore",
            "power",
            "network",
            "usb",
            "display",
            "bluetooth",
            "bluetooth_le_scan",
            "physical_rotation_or_calibration_verified",
            "camera_image_quality_verified",
            "user_content_collected",
            "full_port_verified",
            "elapsed_realtime_ms",
        ];
        ensure!(
            v.as_object()
                .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str()))),
            "unexpected inventory report fields; no identifiers/content accepted"
        );
        for key in [
            "physical_rotation_or_calibration_verified",
            "camera_image_quality_verified",
        ] {
            if let Some(flag) = v.get(key) {
                ensure!(flag == false, "USB inventory cannot claim {key}");
            }
        }
        if let Some(elapsed) = v.get("elapsed_realtime_ms") {
            ensure!(
                elapsed.as_u64().is_some_and(|ms| ms <= i64::MAX as u64),
                "USB elapsed realtime must be a nonnegative Android long"
            );
        }
    }

    let uid = v["uid"].as_u64().context("missing app UID")?;
    ensure!(
        uid / 100000 == u64::from(user) && (10000..20000).contains(&(uid % 100000)),
        "wrong app UID/profile"
    );
    for name in [
        "sensors",
        "cameras",
        "audio",
        "keystore",
        "power",
        "network",
        "usb",
        "display",
        "bluetooth",
        "bluetooth_le_scan",
    ] {
        if !suite.requests(name) {
            // Historical non-auth reports predate the optional category.
            if [
                "keystore",
                "power",
                "network",
                "usb",
                "display",
                "bluetooth",
                "bluetooth_le_scan",
            ]
            .contains(&name)
                && v.get(name).is_none()
            {
                continue;
            }
            if matches!(name, "usb" | "bluetooth" | "bluetooth_le_scan")
                || matches!(
                    suite,
                    Suite::UsbInventory | Suite::BluetoothStatus | Suite::BluetoothLeScan
                )
            {
                ensure!(
                    v[name] == serde_json::json!({"status":"not_requested"}),
                    "unrequested USB inventory categories must contain no observations"
                );
            }
            ensure!(
                v[name]["status"] == "not_requested" && v[name].get("results").is_none(),
                "unexpected unrequested operation"
            );
            continue;
        }
        if name == "bluetooth_le_scan" {
            if v[name] != serde_json::json!({"state":"unknown"}) {
                inspect_bluetooth_le_scan(&v[name])?;
            }
            continue;
        }
        if name == "bluetooth" {
            if v[name] != serde_json::json!({"state":"unknown"}) {
                inspect_bluetooth_status(&v[name])?;
            }
            continue;
        }
        if name == "display" {
            display::inspect_display(&v[name])?;
            continue;
        }
        if name == "usb" {
            inspect_usb_inventory(&v[name])?;
            continue;
        }
        if name == "power" {
            inspect_power(&v[name])?;
            continue;
        }
        if name == "network" {
            inspect_network(&v[name])?;
            continue;
        }
        if let Some(rows) = v[name]["results"].as_array() {
            ensure!(rows.len() <= 16, "observation count budget");
            for row in rows {
                ensure!(
                    matches!(row["state"].as_str(), Some("compatible" | "unknown")),
                    "invalid operation verdict"
                );
                if row["state"] != "compatible" {
                    continue;
                }
                if name == "sensors" {
                    let minimum = if row["reporting_mode"] == 0 { 2 } else { 1 };
                    ensure!(
                        row["exposed"] == true
                            && row["registered"] == true
                            && row["strictly_increasing_timestamps"] == true
                            && row["nonfinite_values"] == 0
                            && row["events"]
                                .as_u64()
                                .is_some_and(|n| (minimum..=1002).contains(&n)),
                        "sensor compatibility requires actual bounded event evidence"
                    );
                } else if name == "cameras" {
                    ensure!(
                        row["frames_delivered"]
                            .as_u64()
                            .is_some_and(|n| (3..=16).contains(&n))
                            && row["phase"] == "frames_verified"
                            && row["increasing_frame_timestamps"] == true
                            && row["yuv_structure_valid"] == true
                            && row["close_callback_observed"] == true
                            && row["pixel_content_read"] == false
                            && row["images_saved"] == false,
                        "camera compatibility requires actual frame and teardown evidence"
                    );
                } else if name == "keystore" {
                    ensure!(
                        row["phase"] == "authentication_gate_observed"
                            && row["user_authentication_required"] == true
                            && row["authentication_validity_seconds"] == 5
                            && row["authentication_type"] == 1
                            && matches!(row["reported_security_level"].as_u64(), Some(1 | 2))
                            && row["reported_hardware_auth_enforced"] == true
                            && row["before_authentication_rejected"] == true
                            && row["normal_lock_observed"] == true
                            && row["normal_unlock_observed"] == true
                            && row["signature_after_unlock_verified"] == true
                            && row["changed_message_rejected"] == true
                            && row["after_expiry_rejected"] == true
                            && row["owned_keys_removed"] == true
                            && row["credential_received_by_app"] == false
                            && row["private_material_exported"] == false
                            && row["attestation_verified"] == false,
                        "auth-bound compatibility requires actual normal unlock, expiry and cleanup evidence"
                    );
                } else if suite == Suite::AudioPlaybackPattern {
                    ensure!(
                        row["local_recording_created"] == false
                            && row["builtin_speaker_verified"] == true
                            && row["output_device_type"] == 2
                            && row["system_volume_changed"] == false
                            && row["sample_rate"] == 48000
                            && row["channels"] == 1
                            && row["track_gain"] == 0.08
                            && row["written_playback_frames"] == 30720
                            && row["playback_head_frames"]
                                .as_u64()
                                .is_some_and(|n| n >= 30720)
                            && row["media_volume"].as_u64().is_some()
                            && row["media_volume"] == row["media_volume_after"],
                        "playback-only requires completed quiet output without local recording"
                    );
                } else if suite == Suite::AudioCapturePattern {
                    ensure!(
                        row["local_playback_created"] == false
                            && row["capture_warmup_frames"]
                                .as_u64()
                                .is_some_and(|n| (12000..=16096).contains(&n))
                            && row["digital_capture_flow_verified"] == true
                            && row["builtin_microphone_verified"] == true
                            && row["client_not_silenced"] == true
                            && row["known_acoustic_pattern_detected"] == true
                            && row["raw_audio_saved_or_exported"] == false
                            && row["system_volume_changed"] == false
                            && row["sample_rate"] == 48000
                            && row["channels"] == 1
                            && row["input_device_type"] == 15
                            && row["recording_configuration_available"] == true
                            && row["media_volume"].as_u64().is_some()
                            && row["media_volume"] == row["media_volume_after"]
                            && row["captured_frames"]
                                .as_u64()
                                .is_some_and(|n| (48000..=144000).contains(&n)),
                        "external-pattern capture requires microphone flow without local playback"
                    );
                } else {
                    ensure!(
                        row["digital_playback_flow_verified"] == true
                            && row["digital_capture_flow_verified"] == true
                            && row["builtin_routes_verified"] == true
                            && row["client_not_silenced"] == true
                            && row["known_acoustic_pattern_detected"] == true
                            && row["raw_audio_saved_or_exported"] == false
                            && row["system_volume_changed"] == false
                            && row["sample_rate"] == 48000
                            && row["channels"] == 1
                            && row["input_device_type"] == 15
                            && row["output_device_type"] == 2
                            && row["recording_configuration_available"] == true
                            && row["media_volume"].as_u64().is_some()
                            && row["media_volume"] == row["media_volume_after"]
                            && row["captured_frames"]
                                .as_u64()
                                .is_some_and(|n| (48000..=144000).contains(&n))
                            && row["playback_head_frames"]
                                .as_u64()
                                .is_some_and(|n| n >= 30720),
                        "audio compatibility requires stream and known-pattern route evidence"
                    );
                }
            }
        } else {
            ensure!(
                v[name]["state"] == "unknown",
                "missing operation observations"
            );
        }
    }
    Ok(v)
}
fn all_requested_passed(value: &serde_json::Value, suite: Suite) -> bool {
    // An anonymous descriptor inventory cannot establish functional USB support.
    if matches!(
        suite,
        Suite::UsbInventory | Suite::BluetoothStatus | Suite::BluetoothLeScan
    ) {
        return false;
    }
    [
        "sensors",
        "cameras",
        "audio",
        "keystore",
        "power",
        "network",
        "usb",
        "display",
        "bluetooth",
        "bluetooth_le_scan",
    ]
    .iter()
    .all(|name| {
        if !suite.requests(name) {
            return true;
        }
        value[name]["results"].as_array().is_some_and(|rows| {
            !rows.is_empty() && rows.iter().all(|row| row["state"] == "compatible")
        })
    })
}

fn power_fields(value: &serde_json::Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().context("power object required")?;
    ensure!(
        object.len() == keys.len() && object.keys().all(|k| keys.contains(&k.as_str())),
        "unexpected power fields; only aggregate public readings accepted"
    );
    Ok(())
}

fn inspect_power(value: &serde_json::Value) -> Result<()> {
    if value == &serde_json::json!({"state":"unknown"}) {
        return Ok(());
    }
    power_fields(
        value,
        &[
            "status",
            "read_only",
            "settings_changed",
            "wake_lock_acquired",
            "charging_performance_verified",
            "battery_calibration_verified",
            "thermal_control_verified",
            "suspend_resume_verified",
            "results",
        ],
    )?;
    ensure!(
        value["status"] == "observed" && value["read_only"] == true,
        "power observation scope"
    );
    for key in [
        "settings_changed",
        "wake_lock_acquired",
        "charging_performance_verified",
        "battery_calibration_verified",
        "thermal_control_verified",
        "suspend_resume_verified",
    ] {
        ensure!(value[key] == false, "power observation cannot claim {key}");
    }
    let rows = value["results"]
        .as_array()
        .context("power observations required")?;
    ensure!(rows.len() == 4, "four distinct power observations required");
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let operation = row["operation"]
            .as_str()
            .context("power operation required")?;
        ensure!(seen.insert(operation), "duplicate power operation");
        ensure!(
            matches!(row["state"].as_str(), Some("compatible" | "unknown"))
                && matches!(
                    row["availability"].as_str(),
                    Some(
                        "available"
                            | "unavailable_or_unsupported"
                            | "invalid_or_unknown_reading"
                            | "api_exception"
                    )
                ),
            "invalid power verdict/availability"
        );
        let mut keys = vec!["operation", "state", "availability"];
        let valid = match operation {
            "battery_snapshot" => {
                keys.extend([
                    "present",
                    "status_code",
                    "level",
                    "scale",
                    "temperature_decic",
                    "temperature_unit",
                ]);
                ensure!(
                    row["present"].is_null() || row["present"].is_boolean(),
                    "battery presence type"
                );
                for key in ["status_code", "level", "scale", "temperature_decic"] {
                    ensure!(
                        row[key].is_null() || row[key].as_i64().is_some(),
                        "battery integer reading"
                    );
                }
                ensure!(
                    row["temperature_unit"] == "tenths_degree_celsius",
                    "battery temperature units"
                );
                row["present"] == true
                    && row["status_code"]
                        .as_u64()
                        .is_some_and(|n| (2..=5).contains(&n))
                    && row["scale"]
                        .as_u64()
                        .is_some_and(|n| (1..=10000).contains(&n))
                    && row["level"]
                        .as_u64()
                        .zip(row["scale"].as_u64())
                        .is_some_and(|(n, s)| n <= s)
                    && row["temperature_decic"]
                        .as_i64()
                        .is_some_and(|n| (-1000..=2000).contains(&n))
            }
            "charge_counter" => {
                keys.extend(["value_uah", "unit"]);
                ensure!(
                    row["unit"] == "microampere_hours"
                        && (row["value_uah"].is_null() || row["value_uah"].as_i64().is_some()),
                    "charge counter units/type"
                );
                row["value_uah"]
                    .as_u64()
                    .is_some_and(|n| n <= i32::MAX as u64)
            }
            "thermal_headroom" => {
                keys.extend(["value", "forecast_seconds", "read_count"]);
                ensure!(
                    row["forecast_seconds"] == 0
                        && matches!(row["read_count"].as_u64(), Some(0 | 1))
                        && (row["value"].is_null() || row["value"].as_f64().is_some()),
                    "headroom single-query budget"
                );
                row["read_count"] == 1
                    && row["value"]
                        .as_f64()
                        .is_some_and(|n| n.is_finite() && n >= 0.0 && n <= f64::from(f32::MAX))
            }
            "thermal_status" => {
                keys.extend([
                    "direct_before",
                    "direct_after",
                    "listener_registered",
                    "listener_removed",
                    "callbacks",
                    "last_callback_status",
                    "callbacks_valid",
                    "callback_budget_exceeded",
                    "executor_stopped",
                    "window_ms",
                ]);
                for key in [
                    "listener_registered",
                    "listener_removed",
                    "callbacks_valid",
                    "callback_budget_exceeded",
                    "executor_stopped",
                ] {
                    ensure!(row[key].is_boolean(), "thermal listener boolean");
                }
                for key in ["direct_before", "direct_after", "last_callback_status"] {
                    ensure!(
                        row[key].is_null() || row[key].as_i64().is_some(),
                        "thermal status type"
                    );
                }
                ensure!(
                    row["callbacks"].as_u64().is_some_and(|n| n <= 32)
                        && row["window_ms"].as_u64().is_some_and(|n| n <= 10000),
                    "thermal observation budget"
                );
                ["direct_before", "direct_after", "last_callback_status"]
                    .iter()
                    .all(|k| row[k].as_u64().is_some_and(|n| n <= 6))
                    && [
                        "listener_registered",
                        "listener_removed",
                        "callbacks_valid",
                        "executor_stopped",
                    ]
                    .iter()
                    .all(|k| row[k] == true)
                    && row["callback_budget_exceeded"] == false
                    && row["callbacks"].as_u64().is_some_and(|n| n > 0)
                    && row["window_ms"].as_u64().is_some_and(|n| n >= 2000)
            }
            _ => anyhow::bail!("unknown power operation"),
        };
        power_fields(row, &keys)?;
        ensure!(
            row["state"] != "compatible" || (valid && row["availability"] == "available"),
            "power API pass lacks valid reading/callback cleanup evidence"
        );
    }
    Ok(())
}

fn network_fields(value: &serde_json::Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().context("network object required")?;
    ensure!(
        object.len() == keys.len() && object.keys().all(|k| keys.contains(&k.as_str())),
        "unexpected network fields; no identifiers/content accepted"
    );
    Ok(())
}
fn inspect_network(value: &serde_json::Value) -> Result<()> {
    if value == &serde_json::json!({"state":"unknown"}) {
        return Ok(());
    }
    network_fields(
        value,
        &[
            "status",
            "settings_changed",
            "network_requested_or_process_bound",
            "network_identifiers_collected",
            "content_collected",
            "wifi_reconnect_verified",
            "radio_change_performed",
            "results",
        ],
    )?;
    ensure!(
        value["status"] == "observed",
        "network observation required"
    );
    for key in [
        "settings_changed",
        "network_requested_or_process_bound",
        "network_identifiers_collected",
        "content_collected",
        "wifi_reconnect_verified",
        "radio_change_performed",
    ] {
        ensure!(
            value[key] == false,
            "network observation cannot claim {key}"
        );
    }
    let rows = value["results"]
        .as_array()
        .context("network observations required")?;
    ensure!(
        rows.len() == 3,
        "three distinct network operations required"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut https_passed = false;
    let mut eligible_snapshot = false;
    for row in rows {
        let operation = row["operation"]
            .as_str()
            .context("network operation required")?;
        ensure!(seen.insert(operation), "duplicate network operation");
        ensure!(
            matches!(row["state"].as_str(), Some("compatible" | "unknown")),
            "invalid network verdict"
        );
        let mut keys = vec!["operation", "state"];
        let valid = match operation {
            "default_network_snapshot" => {
                let fields = [
                    "default_present",
                    "capabilities_available",
                    "internet",
                    "validated",
                    "transport_wifi",
                    "transport_cellular",
                    "transport_ethernet",
                    "transport_vpn",
                ];
                keys.extend(fields);
                ensure!(
                    fields.iter().all(|k| row[k].is_boolean()),
                    "network capability boolean required"
                );
                eligible_snapshot = row["default_present"] == true
                    && row["capabilities_available"] == true
                    && row["internet"] == true;
                row["default_present"] == true && row["capabilities_available"] == true
            }
            "default_network_callbacks" => {
                keys.extend([
                    "registered",
                    "removed",
                    "thread_stopped",
                    "window_ms",
                    "observations",
                    "available_events",
                    "capability_events",
                    "lost_events",
                    "matching_available",
                    "matching_capabilities",
                    "network_change_observed",
                    "observation_budget_exceeded",
                ]);
                for key in [
                    "registered",
                    "removed",
                    "thread_stopped",
                    "matching_available",
                    "matching_capabilities",
                    "network_change_observed",
                    "observation_budget_exceeded",
                ] {
                    ensure!(row[key].is_boolean(), "network callback boolean required");
                }
                let counts = [
                    "observations",
                    "available_events",
                    "capability_events",
                    "lost_events",
                ]
                .map(|k| row[k].as_u64().filter(|n| *n <= 32));
                ensure!(
                    counts.iter().all(Option::is_some),
                    "network callback count budget"
                );
                let counts = counts.map(Option::unwrap);
                ensure!(
                    counts[0] == counts[1] + counts[2] + counts[3]
                        && row["window_ms"].as_u64().is_some_and(|n| n <= 10000),
                    "network callback totals/window budget"
                );
                row["registered"] == true
                    && row["removed"] == true
                    && row["thread_stopped"] == true
                    && row["matching_available"] == true
                    && row["matching_capabilities"] == true
                    && counts[1] > 0
                    && counts[2] > 0
                    && row["network_change_observed"] == false
                    && row["observation_budget_exceeded"] == false
                    && row["window_ms"].as_u64().is_some_and(|n| n >= 2000)
            }
            "fixed_https_204" => {
                keys.extend([
                    "endpoint",
                    "request_count_limit",
                    "attempted",
                    "outcome",
                    "response_code",
                    "body_bytes_read",
                    "empty_body",
                    "response_stream_closed",
                    "disconnect_called",
                    "worker_stopped",
                    "observer_timed_out",
                    "default_tls_verification_used",
                    "redirects_enabled",
                    "credentials_or_cookies_sent",
                    "body_content_exported",
                    "captured_network_used",
                    "default_network_matches_at_checks",
                    "connect_timeout_ms",
                    "read_timeout_ms",
                    "observer_timeout_ms",
                ]);
                ensure!(
                    row["endpoint"] == "https://www.google.com/generate_204"
                        && row["request_count_limit"] == 1
                        && row["connect_timeout_ms"] == 4000
                        && row["read_timeout_ms"] == 4000
                        && row["observer_timeout_ms"] == 12000,
                    "fixed HTTPS endpoint/deadline budget"
                );
                for key in [
                    "attempted",
                    "empty_body",
                    "response_stream_closed",
                    "disconnect_called",
                    "worker_stopped",
                    "observer_timed_out",
                    "default_tls_verification_used",
                    "redirects_enabled",
                    "credentials_or_cookies_sent",
                    "body_content_exported",
                    "captured_network_used",
                    "default_network_matches_at_checks",
                ] {
                    ensure!(row[key].is_boolean(), "HTTPS boolean required");
                }
                ensure!(
                    row["redirects_enabled"] == false
                        && row["credentials_or_cookies_sent"] == false
                        && row["body_content_exported"] == false,
                    "redirects/credentials/content forbidden"
                );
                ensure!(
                    row["response_code"]
                        .as_i64()
                        .is_some_and(|n| n == -1 || (100..=599).contains(&n))
                        && (row["body_bytes_read"].is_null()
                            || matches!(row["body_bytes_read"].as_u64(), Some(0 | 1))),
                    "HTTPS response/body budget"
                );
                ensure!(
                    matches!(
                        row["outcome"].as_str(),
                        Some(
                            "no_eligible_default_network"
                                | "unexpected_auth_or_cookie_handler"
                                | "unexpected_connection_type"
                                | "unexpected_tls_defaults"
                                | "unexpected_http_status"
                                | "endpoint_changed"
                                | "https_204_empty_body"
                                | "unexpected_body"
                                | "tls_error"
                                | "request_error"
                                | "observer_deadline"
                                | "worker_error"
                        )
                    ),
                    "invalid HTTPS outcome"
                );
                https_passed = row["state"] == "compatible";
                [
                    "attempted",
                    "empty_body",
                    "response_stream_closed",
                    "disconnect_called",
                    "worker_stopped",
                    "default_tls_verification_used",
                    "captured_network_used",
                    "default_network_matches_at_checks",
                ]
                .iter()
                .all(|k| row[k] == true)
                    && row["response_code"] == 204
                    && row["body_bytes_read"] == 0
                    && row["observer_timed_out"] == false
                    && row["outcome"] == "https_204_empty_body"
            }
            _ => anyhow::bail!("unknown network operation"),
        };
        network_fields(row, &keys)?;
        ensure!(
            row["state"] != "compatible" || valid,
            "network pass lacks actual API/callback/HTTPS/teardown evidence"
        );
    }
    ensure!(
        !https_passed || eligible_snapshot,
        "HTTPS pass lacks selected internet-capable default network"
    );
    Ok(())
}

/// Validate only the bounded owned guest fixture's receipt. Its execution/VM
/// identity and the external player's completion must be established separately.
pub fn inspect_guest_capture(text: &str) -> Result<serde_json::Value> {
    ensure!(text.len() <= 4096, "guest capture receipt budget");
    let v: serde_json::Value = serde_json::from_str(text)?;
    let keys = [
        "schema_version",
        "probe",
        "state",
        "source_is_non_monitor_alsa_input",
        "rate",
        "channels",
        "frames",
        "capture_warmup_frames",
        "detector",
        "pcm_saved_or_exported",
        "capture_process_stopped",
        "guest_microphone_quality_verified",
        "full_port_verified",
    ];
    let object = v.as_object().context("guest capture object required")?;
    ensure!(
        object.len() == keys.len() && object.keys().all(|k| keys.contains(&k.as_str())),
        "unexpected guest capture fields; no PCM/content accepted"
    );
    ensure!(
        v["schema_version"] == 1
            && v["probe"] == "owned_guest_audio_capture_v1"
            && matches!(v["state"].as_str(), Some("compatible" | "unknown"))
            && v["source_is_non_monitor_alsa_input"] == true
            && v["rate"] == 48000
            && v["channels"] == 1
            && v["pcm_saved_or_exported"] == false
            && v["capture_process_stopped"] == true
            && v["guest_microphone_quality_verified"] == false
            && v["full_port_verified"] == false,
        "wrong guest capture identity/scope"
    );
    let frames = v["frames"]
        .as_u64()
        .context("capture frame count required")?;
    ensure!(
        (48000..=288000).contains(&frames)
            && v["capture_warmup_frames"]
                .as_u64()
                .is_some_and(|n| (12000..=16096).contains(&n)),
        "capture flow/warmup budget"
    );
    let detector = v["detector"]
        .as_object()
        .context("detector object required")?;
    ensure!(
        detector.len() == 3
            && detector
                .keys()
                .all(|k| ["matched", "strong_windows", "analysed_windows"].contains(&k.as_str())),
        "unexpected detector fields; no spectra/content accepted"
    );
    let analysed = v["detector"]["analysed_windows"]
        .as_u64()
        .context("analysis count required")?;
    let strong = v["detector"]["strong_windows"]
        .as_u64()
        .context("strong count required")?;
    ensure!(
        analysed == (frames - 1536) / 384 + 1
            && strong <= analysed
            && v["detector"]["matched"].as_bool().is_some(),
        "invalid detector counters"
    );
    ensure!(
        (v["state"] == "compatible") == (v["detector"]["matched"] == true)
            && (v["state"] != "compatible" || strong >= 32),
        "unsupported capture verdict"
    );
    Ok(v)
}
fn apk_path(text: &str) -> Result<&str> {
    let mut lines = text.lines();
    let path = lines
        .next()
        .and_then(|s| s.strip_prefix("package:"))
        .context("missing APK path")?;
    ensure!(
        lines.next().is_none()
            && path.starts_with("/data/app/")
            && path.ends_with("/base.apk")
            && path.len() < 1024
            && !path.contains("/../")
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._~+=-".contains(&b)),
        "unexpected APK path"
    );
    Ok(path)
}
pub fn run(r: &RunRequest, destination: &Path) -> Result<serde_json::Value> {
    ensure!(!destination.exists(), "report exists");
    for p in [&r.adb, &r.apk, &r.build_report] {
        p.verify()?;
        gb_core::separate_from_input(&p.path, destination)?;
    }
    let built: serde_json::Value = gb_core::read_json(&r.build_report.path, 128 * 1024)?;
    ensure!(
        built["status"] == "owned_hardware_apk_built_not_runtime_verified"
            && built["source_sha256"] == gb_core::digest(SOURCE.as_bytes())
            && built["audio_source_sha256"] == gb_core::digest(AUDIO_SOURCE.as_bytes())
            && built["audio_pattern_sha256"] == gb_core::digest(PATTERN_SOURCE.as_bytes())
            && built["playback_source_sha256"] == gb_core::digest(PLAYBACK_SOURCE.as_bytes())
            && built["auth_key_source_sha256"] == gb_core::digest(AUTH_SOURCE.as_bytes())
            && built["power_source_sha256"] == gb_core::digest(POWER_SOURCE.as_bytes())
            && built["network_source_sha256"] == gb_core::digest(NETWORK_SOURCE.as_bytes())
            && built["usb_source_sha256"] == gb_core::digest(USB_SOURCE.as_bytes())
            && built["bluetooth_source_sha256"] == gb_core::digest(BLUETOOTH_SOURCE.as_bytes())
            && built["bluetooth_le_scan_source_sha256"]
                == gb_core::digest(BLUETOOTH_LE_SCAN_SOURCE.as_bytes())
            && built["display_source_sha256"] == gb_core::digest(DISPLAY_SOURCE.as_bytes())
            && built["display_pattern_sha256"]
                == gb_core::digest(DISPLAY_PATTERN_SOURCE.as_bytes())
            && built["manifest_sha256"] == gb_core::digest(MANIFEST.as_bytes())
            && built["apk_sha256"] == r.apk.sha256
            && built["package"] == PACKAGE,
        "APK source/build provenance mismatch"
    );
    let call = |args: Vec<String>, timeout: u64| -> Result<String> {
        let mut all = vec!["-s".into(), r.serial.clone()];
        all.extend(args);
        let result = gb_core::run_tool(&r.adb.path, &all, Duration::from_secs(timeout))?;
        ensure!(
            !result.stderr_truncated && result.stdout.len() < 65536,
            "ADB receipt budget"
        );
        Ok(result.stdout.trim().into())
    };
    let sh = |c: String| call(vec!["shell".into(), c], 15);
    let identity = || -> Result<String> {
        ensure!(
            sh("getprop ro.serialno".into())? == r.serial
                && sh("getprop ro.build.fingerprint".into())? == r.fingerprint
                && sh("id -u".into())? == "2000"
                && sh("getenforce".into())? == "Enforcing"
                && sh("am get-current-user".into())? == r.android_user.to_string()
                && sh(format!("am get-started-user-state {}", r.android_user))?
                    == "RUNNING_UNLOCKED",
            "device identity/profile/SELinux guard"
        );
        let boot = sh("cat /proc/sys/kernel/random/boot_id".into())?;
        ensure!(
            boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid boot identity"
        );
        Ok(boot)
    };
    let boot = identity()?;
    ensure!(
        sh(format!(
            "pm list packages -u --user {} {PACKAGE}",
            r.android_user
        ))?
        .is_empty(),
        "owned probe namespace already exists; refuse overwrite"
    );
    let nonce = gb_core::digest(
        format!(
            "{}:{}:{}",
            boot,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        )
        .as_bytes(),
    );
    let run_id = &nonce[..32];
    let context = destination.with_extension("context.json");
    ensure!(!context.exists(), "context exists");
    gb_core::write_json(
        &context,
        &serde_json::json!({"package":PACKAGE,"android_user":r.android_user,"serial":r.serial,"run_id":run_id,"apk_sha256":r.apk.sha256,"namespace_absent_before_install":true,"suite":r.suite,"firmware_written":false}),
    )?;
    let attempt = (|| -> Result<serde_json::Value> {
        // No -r: an existing global package must not be silently replaced.
        // An unsuccessful install/ack can still leave this previously absent
        // owned namespace behind. Keep it inside the cleanup/report boundary.
        let install = call(
            vec![
                "install".into(),
                "-t".into(),
                "--user".into(),
                r.android_user.to_string(),
                r.apk.path.to_string_lossy().into_owned(),
            ],
            60,
        )?;
        ensure!(
            install.lines().any(|s| s == "Success"),
            "APK install not acknowledged"
        );
        let path_text = sh(format!("pm path --user {} {PACKAGE}", r.android_user))?;
        let path = apk_path(&path_text)?;
        ensure!(
            sh(format!("sha256sum {path}"))?.split_whitespace().next()
                == Some(r.apk.sha256.as_str()),
            "installed APK hash mismatch; do not execute"
        );
        let uid =
            sh(format!("run-as {PACKAGE} --user {} id -u", r.android_user))?.parse::<u32>()?;
        ensure!(
            uid / 100000 == r.android_user && (10000..20000).contains(&(uid % 100000)),
            "wrong run-as UID"
        );
        if r.suite.requests("cameras") {
            sh(format!(
                "pm grant --user {} {PACKAGE} android.permission.CAMERA",
                r.android_user
            ))?;
        }
        if matches!(r.suite, Suite::BluetoothStatus | Suite::BluetoothLeScan) {
            sh(format!(
                "pm grant --user {} {PACKAGE} android.permission.BLUETOOTH_CONNECT",
                r.android_user
            ))?;
        }
        if r.suite == Suite::BluetoothLeScan {
            sh(format!(
                "pm grant --user {} {PACKAGE} android.permission.BLUETOOTH_SCAN",
                r.android_user
            ))?;
        }
        if r.suite.records_audio() {
            sh(format!(
                "pm grant --user {} {PACKAGE} android.permission.RECORD_AUDIO",
                r.android_user
            ))?;
        }
        call(
            vec![
                "shell".into(),
                if r.suite == Suite::AudioPlaybackPattern {
                    format!(
                        "am instrument -w --user {} -e run_id {run_id} {PACKAGE}/.AudioPlaybackInstrumentation",
                        r.android_user
                    )
                } else {
                    format!(
                        "am start -W --user {} -n {PACKAGE}/.HardwareProbeActivity --es run_id {run_id} --es suite {}",
                        r.android_user,
                        r.suite.name()
                    )
                },
            ],
            30,
        )?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let output = sh(format!(
                "run-as {PACKAGE} --user {} cat files/gb-{run_id}.json",
                r.android_user
            ));
            if let Ok(text) = output {
                return inspect_report(&text, run_id, r.android_user, &r.fingerprint, r.suite);
            }
            ensure!(
                Instant::now() < deadline,
                "owned hardware response deadline exceeded"
            );
            std::thread::sleep(Duration::from_millis(500));
            gb_core::checkpoint()?;
        }
    })();
    let stopped = sh(format!("am force-stop --user {} {PACKAGE}", r.android_user));
    let uninstalled = sh(format!("pm uninstall --user {} {PACKAGE}", r.android_user));
    let absent = sh(format!(
        "pm list packages --user {} {PACKAGE}",
        r.android_user
    ));
    let cleanup = stopped.is_ok()
        && uninstalled.as_ref().is_ok_and(|s| s == "Success")
        && absent.as_ref().is_ok_and(String::is_empty);
    let after = identity();
    let operations = attempt.as_ref().ok();
    let passed = operations.is_some_and(|v| all_requested_passed(v, r.suite));
    let inventory_observed = match r.suite {
        Suite::UsbInventory => operations.is_some_and(|v| v["usb"]["status"] == "observed"),
        Suite::BluetoothStatus => {
            operations.is_some_and(|v| v["bluetooth"]["status"] == "observed")
        }
        Suite::BluetoothLeScan => {
            operations.is_some_and(|v| v["bluetooth_le_scan"]["status"] == "observed")
        }
        _ => false,
    };
    let stable_cleanup = cleanup && after.as_ref().is_ok_and(|s| s == &boot);
    let status = if stable_cleanup && inventory_observed {
        "requested_inventory_observed"
    } else if stable_cleanup && passed {
        "requested_operation_smoke_passed"
    } else {
        "needs_diagnosis"
    };
    let mut report = serde_json::json!({"schema_version":1,"status":status,"boot_id":boot,"run_id":run_id,"serial":r.serial,"android_user":r.android_user,"suite":r.suite,"apk_sha256":r.apk.sha256,"operations":operations,"execution_error":attempt.err().map(|e|e.to_string()),"cleanup_verified":cleanup,"host_boot_unchanged":after.as_ref().is_ok_and(|s|s==&boot),"full_port_verified":false,"firmware_written":false,"scope":"Selected owned-app hardware smoke, optionally normal-unlock-bound signing; not attestation, image/audio quality, controlled motion, calibration, guest audio or whole-port qualification"});
    if r.suite == Suite::UsbInventory {
        report["usb_inventory_observed"] = inventory_observed.into();
        report["usb_functional_state"] = "unknown".into();
        report["scope"] = "Anonymous public-API USB descriptor inventory only; no device opens, permission requests, transfers, identifiers, content or host/Type-C/PD functional qualification".into();
    }
    if r.suite == Suite::BluetoothStatus {
        report["bluetooth_status_observed"] = inventory_observed.into();
        report["bluetooth_functional_state"] = "unknown".into();
        report["scope"] = "Anonymous Bluetooth public-API state reads and bounded receiver lifetime only; no discovery, pairing, connections, identifiers, content, radio changes or functional/transition qualification".into();
    }
    if r.suite == Suite::BluetoothLeScan {
        report["bluetooth_le_scan_window_observed"] = inventory_observed.into();
        report["bluetooth_functional_state"] = "unknown".into();
        report["scope"] = "One bounded low-power passive BLE API scan window and void start/stop returns only; anonymous callback counts without inspecting results/batches; no RF, particular peer, Phone Link, pairing, connection, transition or continuous-scanning qualification; neverForLocation may filter beacons".into();
    }
    gb_core::write_json(destination, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn network_fixture() -> serde_json::Value {
        let https = serde_json::json!({"operation":"fixed_https_204","state":"compatible","endpoint":"https://www.google.com/generate_204","request_count_limit":1,"attempted":true,"outcome":"https_204_empty_body","response_code":204,"body_bytes_read":0,"empty_body":true,"response_stream_closed":true,"disconnect_called":true,"worker_stopped":true,"observer_timed_out":false,"default_tls_verification_used":true,"redirects_enabled":false,"credentials_or_cookies_sent":false,"body_content_exported":false,"captured_network_used":true,"default_network_matches_at_checks":true,"connect_timeout_ms":4000,"read_timeout_ms":4000,"observer_timeout_ms":12000});
        serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"network","package":PACKAGE,
        "run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,
        "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},"audio":{"status":"not_requested"},"keystore":{"status":"not_requested"},"power":{"status":"not_requested"},
        "network":{"status":"observed","settings_changed":false,"network_requested_or_process_bound":false,"network_identifiers_collected":false,
            "content_collected":false,"wifi_reconnect_verified":false,"radio_change_performed":false,"results":[
                {"operation":"default_network_snapshot","state":"compatible","default_present":true,"capabilities_available":true,"internet":true,"validated":false,"transport_wifi":true,"transport_cellular":false,"transport_ethernet":false,"transport_vpn":false},
                {"operation":"default_network_callbacks","state":"compatible","registered":true,"removed":true,"thread_stopped":true,"window_ms":2000,"observations":2,"available_events":1,"capability_events":1,"lost_events":0,"matching_available":true,"matching_capabilities":true,"network_change_observed":false,"observation_budget_exceeded":false},
                    https
            ]}})
    }
    #[test]
    fn network_requires_real_bound_https_and_callback_teardown_without_identifiers() {
        let good = network_fixture();
        let inspect = |v: &serde_json::Value| {
            inspect_report(&v.to_string(), "fixture", 11, "fixture", Suite::Network)
        };
        assert!(inspect(&good).is_ok());
        assert!(all_requested_passed(&good, Suite::Network));
        assert!(
            !Suite::All.requests("network")
                && !Suite::Network.requests("power")
                && !Suite::Network.records_audio()
        );
        for (index, key, bad) in [
            (1, "registered", serde_json::json!(false)),
            (1, "removed", serde_json::json!(false)),
            (1, "thread_stopped", serde_json::json!(false)),
            (1, "matching_available", serde_json::json!(false)),
            (1, "observations", serde_json::json!(33)),
            (1, "observation_budget_exceeded", serde_json::json!(true)),
            (1, "network_change_observed", serde_json::json!(true)),
            (1, "window_ms", serde_json::json!(1999)),
            (2, "response_code", serde_json::json!(302)),
            (2, "body_bytes_read", serde_json::json!(1)),
            (2, "empty_body", serde_json::json!(false)),
            (2, "worker_stopped", serde_json::json!(false)),
            (2, "observer_timed_out", serde_json::json!(true)),
            (2, "default_tls_verification_used", serde_json::json!(false)),
            (2, "response_stream_closed", serde_json::json!(false)),
            (2, "disconnect_called", serde_json::json!(false)),
            (2, "captured_network_used", serde_json::json!(false)),
            (
                2,
                "default_network_matches_at_checks",
                serde_json::json!(false),
            ),
            (
                2,
                "endpoint",
                serde_json::json!("https://arbitrary.invalid/"),
            ),
            (2, "redirects_enabled", serde_json::json!(true)),
            (2, "body_content_exported", serde_json::json!(true)),
            (2, "credentials_or_cookies_sent", serde_json::json!(true)),
        ] {
            let mut v = good.clone();
            v["network"]["results"][index][key] = bad;
            assert!(inspect(&v).is_err(), "accepted invalid {key}");
        }
        for key in [
            "settings_changed",
            "network_requested_or_process_bound",
            "network_identifiers_collected",
            "content_collected",
            "wifi_reconnect_verified",
            "radio_change_performed",
        ] {
            let mut v = good.clone();
            v["network"][key] = true.into();
            assert!(inspect(&v).is_err(), "overclaim {key}");
        }
        let mut private = good.clone();
        private["network"]["results"][0]["ssid"] = "private".into();
        assert!(inspect(&private).is_err());
        let mut continuous_claim = good.clone();
        continuous_claim["network"]["results"][2]["default_network_unchanged"] = true.into();
        assert!(inspect(&continuous_claim).is_err());
        let mut no_internet = good;
        no_internet["network"]["results"][0]["internet"] = false.into();
        assert!(inspect(&no_internet).is_err());
    }
    #[test]
    fn failed_or_unavailable_network_operations_remain_unknown() {
        let mut v = network_fixture();
        v["network"]["results"][2]["state"] = "unknown".into();
        v["network"]["results"][2]["outcome"] = "tls_error".into();
        v["network"]["results"][2]["response_code"] = (-1).into();
        v["network"]["results"][2]["body_bytes_read"] = serde_json::Value::Null;
        assert!(inspect_report(&v.to_string(), "fixture", 11, "fixture", Suite::Network).is_ok());
        assert!(!all_requested_passed(&v, Suite::Network));
        v["network"]["results"][2]["worker_stopped"] = false.into();
        v["network"]["results"][2]["observer_timed_out"] = true.into();
        v["network"]["results"][2]["outcome"] = "observer_deadline".into();
        assert!(inspect_report(&v.to_string(), "fixture", 11, "fixture", Suite::Network).is_ok());
        assert!(!all_requested_passed(&v, Suite::Network));
        v["network"] = serde_json::json!({"state":"unknown"});
        assert!(inspect_report(&v.to_string(), "fixture", 11, "fixture", Suite::Network).is_ok());
        assert!(!all_requested_passed(&v, Suite::Network));
    }

    fn power_fixture() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"power","package":PACKAGE,
        "run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,
        "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},"audio":{"status":"not_requested"},"keystore":{"status":"not_requested"},
        "power":{"status":"observed","read_only":true,"settings_changed":false,"wake_lock_acquired":false,
            "charging_performance_verified":false,"battery_calibration_verified":false,"thermal_control_verified":false,"suspend_resume_verified":false,
            "results":[
                {"operation":"battery_snapshot","state":"compatible","availability":"available","present":true,"status_code":2,"level":60,"scale":100,"temperature_decic":310,"temperature_unit":"tenths_degree_celsius"},
                {"operation":"charge_counter","state":"compatible","availability":"available","value_uah":4000000,"unit":"microampere_hours"},
                {"operation":"thermal_status","state":"compatible","availability":"available","direct_before":0,"direct_after":0,"listener_registered":true,"listener_removed":true,"callbacks":1,"last_callback_status":0,"callbacks_valid":true,"callback_budget_exceeded":false,"executor_stopped":true,"window_ms":2000},
                {"operation":"thermal_headroom","state":"compatible","availability":"available","value":1.25,"forecast_seconds":0,"read_count":1}
            ]}})
    }
    #[test]
    fn power_suite_requires_readings_real_callback_and_cleanup_without_scope_escalation() {
        let good = power_fixture();
        let inspect = |v: &serde_json::Value| {
            inspect_report(&v.to_string(), "fixture", 11, "fixture", Suite::Power)
        };
        assert!(inspect(&good).is_ok());
        assert!(all_requested_passed(&good, Suite::Power));
        assert!(!Suite::Power.records_audio() && !Suite::Power.requests("cameras"));
        assert!(!Suite::All.requests("power"));
        for (index, key, bad) in [
            (0, "temperature_decic", serde_json::json!(-2147483648i64)),
            (0, "status_code", serde_json::json!(1)),
            (0, "level", serde_json::json!(101)),
            (1, "value_uah", serde_json::json!(-2147483648i64)),
            (2, "callbacks", serde_json::json!(0)),
            (2, "listener_removed", serde_json::json!(false)),
            (2, "executor_stopped", serde_json::json!(false)),
            (2, "callback_budget_exceeded", serde_json::json!(true)),
            (2, "direct_after", serde_json::json!(7)),
            (2, "window_ms", serde_json::json!(1999)),
            (3, "value", serde_json::json!(-1)),
            (3, "read_count", serde_json::json!(2)),
        ] {
            let mut v = good.clone();
            v["power"]["results"][index][key] = bad;
            assert!(inspect(&v).is_err(), "invalid {key}");
        }
        for key in [
            "settings_changed",
            "wake_lock_acquired",
            "charging_performance_verified",
            "battery_calibration_verified",
            "thermal_control_verified",
            "suspend_resume_verified",
        ] {
            let mut v = good.clone();
            v["power"][key] = true.into();
            assert!(inspect(&v).is_err(), "overclaim {key}");
        }
        let mut private = good.clone();
        private["power"]["results"][0]["battery_serial"] = "private".into();
        assert!(inspect(&private).is_err());
        let mut duplicate = good.clone();
        duplicate["power"]["results"][3] = good["power"]["results"][0].clone();
        assert!(inspect(&duplicate).is_err());
    }
    #[test]
    fn unavailable_power_readings_stay_unknown_and_historical_all_is_unchanged() {
        let mut value = power_fixture();
        for (index, key) in [(1, "value_uah"), (3, "value")] {
            value["power"]["results"][index][key] = serde_json::Value::Null;
            value["power"]["results"][index]["state"] = "unknown".into();
            value["power"]["results"][index]["availability"] = "unavailable_or_unsupported".into();
        }
        assert!(inspect_report(&value.to_string(), "fixture", 11, "fixture", Suite::Power).is_ok());
        assert!(!all_requested_passed(&value, Suite::Power));
        value["power"] = serde_json::json!({"state":"unknown"});
        assert!(inspect_report(&value.to_string(), "fixture", 11, "fixture", Suite::Power).is_ok());
        assert!(!all_requested_passed(&value, Suite::Power));
    }

    #[test]
    fn auth_bound_probe_requires_real_unlock_expiry_and_owned_key_cleanup() {
        let good = serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"auth_bound_keys","package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,"sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},"audio":{"status":"not_requested"},"keystore":{"status":"observed","results":[{
            "state":"compatible","phase":"authentication_gate_observed","user_authentication_required":true,"authentication_validity_seconds":5,"authentication_type":1,"reported_security_level":1,"reported_hardware_auth_enforced":true,"before_authentication_rejected":true,"normal_lock_observed":true,"normal_unlock_observed":true,"signature_after_unlock_verified":true,"changed_message_rejected":true,"after_expiry_rejected":true,"owned_keys_removed":true,"credential_received_by_app":false,"private_material_exported":false,"attestation_verified":false
        }]}});
        let inspect = |v: &serde_json::Value| {
            inspect_report(
                &v.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::AuthBoundKeys,
            )
        };
        assert!(inspect(&good).is_ok());
        assert!(all_requested_passed(&good, Suite::AuthBoundKeys));
        assert!(!Suite::AuthBoundKeys.records_audio());
        assert!(!Suite::AuthBoundKeys.requests("cameras"));
        assert!(!Suite::All.requests("keystore"));
        for key in [
            "user_authentication_required",
            "reported_hardware_auth_enforced",
            "before_authentication_rejected",
            "normal_lock_observed",
            "normal_unlock_observed",
            "signature_after_unlock_verified",
            "changed_message_rejected",
            "after_expiry_rejected",
            "owned_keys_removed",
        ] {
            let mut missing = good.clone();
            missing["keystore"]["results"][0][key] = false.into();
            assert!(inspect(&missing).is_err(), "missing {key}");
        }
        for key in [
            "credential_received_by_app",
            "private_material_exported",
            "attestation_verified",
        ] {
            let mut overclaim = good.clone();
            overclaim["keystore"]["results"][0][key] = true.into();
            assert!(inspect(&overclaim).is_err(), "unexpected {key}");
        }
        let mut software = good.clone();
        software["keystore"]["results"][0]["reported_security_level"] = 0.into();
        assert!(inspect(&software).is_err());
        software["keystore"]["results"][0]["state"] = "unknown".into();
        assert!(inspect(&software).is_ok());
        assert!(!all_requested_passed(&software, Suite::AuthBoundKeys));
        let mut unrequested = good;
        unrequested["suite"] = "sensors".into();
        unrequested["sensors"] = serde_json::json!({"results":[{"state":"unknown"}]});
        let error = inspect_report(
            &unrequested.to_string(),
            "fixture",
            11,
            "fixture",
            Suite::Sensors,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unexpected unrequested operation")
        );
    }

    #[test]
    fn rejects_split_paths_and_unexecuted_or_wrong_profile_evidence() {
        assert!(apk_path("package:/data/app/~~fixture/pkg-fixture/base.apk").is_ok());
        for p in [
            "package:/data/app/a;touch-b/base.apk",
            "package:/data/app/../base.apk",
            "package:/data/app/a/base.apk\npackage:/data/app/b/base.apk",
            "package:/system/app/base.apk",
        ] {
            assert!(apk_path(p).is_err());
        }
        let good = serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"all","package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,"sensors":{"results":[{"state":"compatible","exposed":true,"registered":true,"strictly_increasing_timestamps":true,"reporting_mode":0,"nonfinite_values":0,"events":20}]},"cameras":{"results":[{"state":"unknown"}]},"audio":{"state":"unknown"}});
        assert!(inspect_report(&good.to_string(), "fixture", 11, "fixture", Suite::All).is_ok());
        assert!(!all_requested_passed(&good, Suite::All));
        assert!(inspect_report(&good.to_string(), "fixture", 0, "fixture", Suite::All).is_err());
        assert!(inspect_report(&good.to_string(), "other", 11, "fixture", Suite::All).is_err());
        assert!(
            inspect_report(
                "am start --es run_id fixture",
                "fixture",
                11,
                "fixture",
                Suite::All
            )
            .is_err()
        );
        let mut false_green = good.clone();
        false_green["cameras"]["results"][0]["state"] = "compatible".into();
        assert!(
            inspect_report(
                &false_green.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::All
            )
            .is_err()
        );
        let mut missing_events = good;
        missing_events["sensors"]["results"][0]["events"] = 0.into();
        assert!(
            inspect_report(
                &missing_events.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::All
            )
            .is_err()
        );
    }
    #[test]
    fn selected_audio_needs_acoustic_route_and_flow_evidence_and_does_not_claim_other_suites() {
        let mut value = serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"audio","package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,
            "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
            "audio":{"results":[{"state":"compatible","digital_playback_flow_verified":true,"digital_capture_flow_verified":true,"builtin_routes_verified":true,"client_not_silenced":true,"known_acoustic_pattern_detected":true,"raw_audio_saved_or_exported":false,"system_volume_changed":false,"sample_rate":48000,"channels":1,"input_device_type":15,"output_device_type":2,"recording_configuration_available":true,"media_volume":9,"media_volume_after":9,"captured_frames":96000,"playback_head_frames":30720}]}});
        assert!(inspect_report(&value.to_string(), "fixture", 11, "fixture", Suite::Audio).is_ok());
        assert!(all_requested_passed(&value, Suite::Audio));
        value["audio"]["results"][0]["known_acoustic_pattern_detected"] = false.into();
        assert!(
            inspect_report(&value.to_string(), "fixture", 11, "fixture", Suite::Audio).is_err()
        );
        value["audio"]["results"][0]["known_acoustic_pattern_detected"] = true.into();
        value["cameras"]["results"] = serde_json::json!([]);
        assert!(
            inspect_report(&value.to_string(), "fixture", 11, "fixture", Suite::Audio).is_err()
        );
        value["cameras"] = serde_json::json!({"status":"not_requested"});
        value["audio"]["results"][0]["input_device_type"] = 0.into();
        assert!(
            inspect_report(&value.to_string(), "fixture", 11, "fixture", Suite::Audio).is_err()
        );
    }
    #[test]
    fn capture_pattern_cannot_use_local_playback_or_claim_an_external_source() {
        let good = serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"audio_capture_pattern","package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,
            "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
            "audio":{"results":[{"state":"compatible","local_playback_created":false,"capture_warmup_frames":12000,"digital_capture_flow_verified":true,"builtin_microphone_verified":true,"client_not_silenced":true,"known_acoustic_pattern_detected":true,"raw_audio_saved_or_exported":false,"system_volume_changed":false,"sample_rate":48000,"channels":1,"input_device_type":15,"recording_configuration_available":true,"media_volume":9,"media_volume_after":9,"captured_frames":144000}]}});
        let inspect = |v: &serde_json::Value| {
            inspect_report(
                &v.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::AudioCapturePattern,
            )
        };
        assert!(inspect(&good).is_ok());
        assert!(all_requested_passed(&good, Suite::AudioCapturePattern));
        assert!(!Suite::AudioCapturePattern.requests("cameras"));
        for (key, bad) in [
            ("local_playback_created", serde_json::json!(true)),
            ("known_acoustic_pattern_detected", serde_json::json!(false)),
            ("client_not_silenced", serde_json::json!(false)),
            ("captured_frames", serde_json::json!(144001)),
            ("capture_warmup_frames", serde_json::json!(11999)),
            ("input_device_type", serde_json::json!(0)),
            ("media_volume_after", serde_json::json!(10)),
        ] {
            let mut value = good.clone();
            value["audio"]["results"][0][key] = bad;
            assert!(inspect(&value).is_err(), "accepted invalid {key}");
        }
        assert!(inspect_report(&good.to_string(), "fixture", 11, "fixture", Suite::Audio).is_err());
        // The microphone report contains no provenance for a particular guest or player.
        assert!(good.get("guest_playback_verified").is_none());
    }
    #[test]
    fn playback_only_cannot_record_or_qualify_external_capture() {
        let good = serde_json::json!({"schema_version":1,"probe":"owned_android_hardware_v1","suite":"audio_playback_pattern","package":PACKAGE,"run_id":"fixture","fingerprint":"fixture","uid":1110001,"full_port_verified":false,"user_content_collected":false,
            "sensors":{"status":"not_requested"},"cameras":{"status":"not_requested"},
            "audio":{"results":[{"state":"compatible","local_recording_created":false,"builtin_speaker_verified":true,"output_device_type":2,"system_volume_changed":false,"sample_rate":48000,"channels":1,"track_gain":0.08,"written_playback_frames":30720,"playback_head_frames":30720,"media_volume":9,"media_volume_after":9}]}});
        let inspect = |v: &serde_json::Value| {
            inspect_report(
                &v.to_string(),
                "fixture",
                11,
                "fixture",
                Suite::AudioPlaybackPattern,
            )
        };
        assert!(inspect(&good).is_ok());
        assert!(all_requested_passed(&good, Suite::AudioPlaybackPattern));
        assert!(!Suite::AudioPlaybackPattern.records_audio());
        assert!(!Suite::AudioPlaybackPattern.requests("cameras"));
        for (key, bad) in [
            ("local_recording_created", serde_json::json!(true)),
            ("playback_head_frames", serde_json::json!(0)),
            ("output_device_type", serde_json::json!(0)),
            ("track_gain", serde_json::json!(1.0)),
            ("media_volume_after", serde_json::json!(10)),
        ] {
            let mut value = good.clone();
            value["audio"]["results"][0][key] = bad;
            assert!(inspect(&value).is_err(), "accepted invalid {key}");
        }
        assert!(good.get("guest_microphone_capture_verified").is_none());
    }
    #[test]
    fn guest_capture_receipts_reject_monitor_content_and_inconsistent_counters() {
        let good = serde_json::json!({"schema_version":1,"probe":"owned_guest_audio_capture_v1",
            "state":"compatible","source_is_non_monitor_alsa_input":true,"rate":48000,"channels":1,
            "frames":288000,"capture_warmup_frames":12122,"detector":{"matched":true,"strong_windows":79,"analysed_windows":747},
            "pcm_saved_or_exported":false,"capture_process_stopped":true,"guest_microphone_quality_verified":false,"full_port_verified":false});
        assert!(inspect_guest_capture(&good.to_string()).is_ok());
        for (key, bad) in [
            ("source_is_non_monitor_alsa_input", serde_json::json!(false)),
            ("frames", serde_json::json!(288001)),
            ("pcm_saved_or_exported", serde_json::json!(true)),
            ("capture_process_stopped", serde_json::json!(false)),
            ("capture_warmup_frames", serde_json::json!(0)),
        ] {
            let mut v = good.clone();
            v[key] = bad;
            assert!(inspect_guest_capture(&v.to_string()).is_err());
        }
        let mut v = good.clone();
        v["samples"] = serde_json::json!([0, 1, 2]);
        assert!(inspect_guest_capture(&v.to_string()).is_err());
        let mut v = good.clone();
        v["detector"]["analysed_windows"] = 746.into();
        assert!(inspect_guest_capture(&v.to_string()).is_err());
        let mut v = good.clone();
        v["detector"]["strong_windows"] = 0.into();
        assert!(inspect_guest_capture(&v.to_string()).is_err());
        v["state"] = "unknown".into();
        v["detector"]["matched"] = false.into();
        assert!(inspect_guest_capture(&v.to_string()).is_ok());
    }
}

#[cfg(test)]
#[path = "hardware_probe/usb_tests.rs"]
mod usb_tests;

#[cfg(test)]
mod display_tests;

#[cfg(test)]
mod bluetooth_tests;

#[cfg(test)]
mod bluetooth_le_scan_tests;
