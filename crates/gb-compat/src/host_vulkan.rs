//! Android host Vulkan advertisements needed by Venus. Enumeration is not interop validation.
use anyhow::{Context, Result, ensure};
use gb_core::State;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, time::Duration};

pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
const REQUIRED: [&str; 4] = [
    "VK_KHR_external_memory_fd",
    "VK_EXT_external_memory_dma_buf",
    "VK_EXT_image_drm_format_modifier",
    "VK_EXT_queue_family_foreign",
];
const INFORMATIONAL: [&str; 4] = [
    "VK_KHR_external_fence_fd",
    "VK_KHR_external_semaphore_fd",
    "VK_EXT_external_memory_host",
    "VK_ANDROID_external_memory_android_hardware_buffer",
];
#[derive(Deserialize)]
struct Raw {
    devices: Option<Vec<RawDevice>>,
}
#[derive(Deserialize)]
struct RawDevice {
    properties: Option<Properties>,
    extensions: Option<Vec<Extension>>,
}
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Properties {
    #[serde(default, deserialize_with = "optional_u32")]
    pub api_version: Option<u32>,
    #[serde(default, deserialize_with = "optional_u32")]
    pub driver_version: Option<u32>,
    #[serde(rename = "vendorID", default, deserialize_with = "optional_u32")]
    pub vendor_id: Option<u32>,
    #[serde(rename = "deviceID", default, deserialize_with = "optional_u32")]
    pub device_id: Option<u32>,
    #[serde(default, deserialize_with = "optional_u32")]
    pub device_type: Option<u32>,
    pub device_name: Option<String>,
}
// Android vkjson serializes some uint32_t fields as JSON doubles. Accept only
// exact integral values within u32, never fractions, negative values or strings.
fn optional_u32<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<u32>, D::Error> {
    let value = Option::<serde_json::Number>::deserialize(d)?;
    value
        .map(|n| {
            if let Some(n) = n.as_u64() {
                return u32::try_from(n).map_err(serde::de::Error::custom);
            }
            let number = n
                .as_f64()
                .ok_or_else(|| serde::de::Error::custom("u32 number required"))?;
            if number.is_finite()
                && number.fract() == 0.0
                && (0.0..=u32::MAX as f64).contains(&number)
            {
                Ok(number as u32)
            } else {
                Err(serde::de::Error::custom("exact integral u32 required"))
            }
        })
        .transpose()
}
#[derive(Deserialize)]
struct Extension {
    #[serde(rename = "extensionName")]
    name: String,
}
#[derive(Debug, Serialize)]
pub struct ExtensionObservation {
    pub name: String,
    pub advertised: Option<bool>,
    pub required: bool,
}
#[derive(Debug, Serialize)]
pub struct Device {
    pub state: State,
    pub properties: Properties,
    pub hardware_device_type_reported: bool,
    pub vulkan_1_1_or_later_advertised: Option<bool>,
    pub extension_inventory_present: bool,
    pub extensions: Vec<ExtensionObservation>,
    pub required_extensions_missing: Vec<String>,
    pub runtime_memory_import_verified: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub state: State,
    pub scope: String,
    pub devices: Vec<Device>,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub raw_uuid_or_pipeline_cache_identifiers_retained: bool,
    pub memory_import_or_export_verified: bool,
    pub fence_signalling_verified: bool,
    pub guest_vulkan_verified: bool,
    pub full_port_verified: bool,
}
pub fn inspect(text: &str) -> Result<Report> {
    ensure!(
        text.len() < MAX_JSON_BYTES,
        "Vulkan JSON reached capture budget; completeness unknown"
    );
    let raw: Raw = serde_json::from_str(text).context("GPU service response is not Vulkan JSON")?;
    let devices = raw.devices.context("Vulkan device inventory absent")?;
    ensure!(devices.len() <= 8, "Vulkan device count budget");
    let mut out = Vec::new();
    for d in devices {
        let properties = d.properties.unwrap_or_default();
        if let Some(name) = &properties.device_name {
            ensure!(
                !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control),
                "invalid Vulkan device name"
            );
        }
        let inventory = d.extensions.is_some();
        let mut names = BTreeSet::new();
        if let Some(entries) = d.extensions {
            ensure!(entries.len() <= 2048, "extension count budget");
            for entry in entries {
                ensure!(
                    entry.name.starts_with("VK_")
                        && entry.name.len() <= 128
                        && entry
                            .name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "invalid Vulkan extension"
                );
                ensure!(names.insert(entry.name), "duplicate Vulkan extension");
            }
        }
        let api = properties
            .api_version
            .map(|v| v >> 29 == 0 && (v >> 22) & 127 == 1 && (v >> 12) & 1023 >= 1);
        let hardware = matches!(properties.device_type, Some(1 | 2));
        let missing: Vec<String> = if inventory {
            REQUIRED
                .iter()
                .filter(|n| !names.contains(**n))
                .map(|n| (*n).into())
                .collect()
        } else {
            Vec::new()
        };
        let state = if !hardware {
            State::Unknown
        } else if api == Some(false) || (inventory && !missing.is_empty()) {
            State::PatchRequired
        } else if api == Some(true) && inventory {
            State::Compatible
        } else {
            State::Unknown
        };
        let extensions = REQUIRED
            .iter()
            .chain(INFORMATIONAL.iter())
            .map(|n| ExtensionObservation {
                name: (*n).into(),
                advertised: inventory.then(|| names.contains(*n)),
                required: REQUIRED.contains(n),
            })
            .collect();
        out.push(Device {
            state,
            properties,
            hardware_device_type_reported: hardware,
            vulkan_1_1_or_later_advertised: api,
            extension_inventory_present: inventory,
            extensions,
            required_extensions_missing: missing,
            runtime_memory_import_verified: false,
        });
    }
    let state = if out.iter().any(|d| d.state == State::Compatible) {
        State::Compatible
    } else if out.iter().any(|d| d.state == State::PatchRequired) {
        State::PatchRequired
    } else {
        State::Unknown
    };
    Ok(Report {schema_version:1,state,scope:"Necessary Android host Venus Vulkan version/extension advertisements only; no allocation, sharing, render or guest success claim".into(),devices:out,source_sha256:gb_core::digest(text.as_bytes()),source_bytes:text.len(),raw_uuid_or_pipeline_cache_identifiers_retained:false,memory_import_or_export_verified:false,fence_signalling_verified:false,guest_vulkan_verified:false,full_port_verified:false})
}

/// Normalize a bounded caller-provided receipt without executing a device tool.
/// Its originating process, device and runtime context remain unverified.
pub fn inspect_file(source: &Path, destination: &Path) -> Result<serde_json::Value> {
    use std::io::Read;
    ensure!(!destination.exists(), "report exists");
    gb_core::separate_from_input(source, destination)?;
    let file = std::fs::File::open(source)?;
    ensure!(file.metadata()?.is_file(), "regular JSON receipt required");
    let mut text = String::new();
    file.take(MAX_JSON_BYTES as u64).read_to_string(&mut text)?;
    let observed = inspect(&text)?;
    let report = serde_json::json!({
        "schema_version": 1,
        "status": "provided_vulkan_json_normalized",
        "enumeration_context": "provided_json_unverified",
        "device_identity_verified": false,
        "original_vmm_namespace_verified": false,
        "observed": observed,
        "firmware_written": false,
        "full_port_verified": false
    });
    gb_core::write_json(destination, &report)?;
    Ok(report)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdbPin {
    pub path: std::path::PathBuf,
    pub sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub schema_version: u32,
    pub adb: AdbPin,
    pub serial: String,
    pub fingerprint: String,
    pub android_user: u32,
}
impl CaptureRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 16384)?;
        if r.adb.path.is_relative() {
            r.adb.path = path.parent().unwrap_or(Path::new(".")).join(&r.adb.path);
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
                && r.fingerprint.len() <= 512
                && !r.fingerprint.chars().any(char::is_control),
            "invalid capture identity/schema"
        );
        ensure!(
            gb_core::hash_file(&r.adb.path)? == r.adb.sha256,
            "ADB input hash mismatch"
        );
        Ok(r)
    }
}
pub fn capture(r: &CaptureRequest, destination: &Path) -> Result<serde_json::Value> {
    ensure!(!destination.exists(), "report exists");
    gb_core::separate_from_input(&r.adb.path, destination)?;
    ensure!(
        gb_core::hash_file(&r.adb.path)? == r.adb.sha256,
        "ADB input changed"
    );
    let query = |command: &str, budget: usize, seconds| -> Result<String> {
        let result = gb_core::run_tool_with_stdout_budget(
            &r.adb.path,
            &[
                "-s".into(),
                r.serial.clone(),
                "shell".into(),
                command.into(),
            ],
            Duration::from_secs(seconds),
            budget,
        )
        .map_err(|_| anyhow::anyhow!("bounded ADB command failed: {command}"))?;
        ensure!(
            result.stdout.len() < budget && !result.stderr_truncated,
            "incomplete ADB receipt"
        );
        Ok(result.stdout.trim().into())
    };
    let identity = || -> Result<String> {
        ensure!(
            query("getprop ro.serialno", 1024, 10)? == r.serial
                && query("getprop ro.build.fingerprint", 1024, 10)? == r.fingerprint
                && query("id -u", 64, 10)? == "2000"
                && query("getenforce", 64, 10)? == "Enforcing"
                && query("am get-current-user", 64, 10)? == r.android_user.to_string(),
            "device/profile/SELinux mismatch"
        );
        let boot = query("cat /proc/sys/kernel/random/boot_id", 128, 10)?;
        ensure!(
            boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid boot identity"
        );
        Ok(boot)
    };
    let boot = identity()?;
    let raw = query("cmd gpu vkjson", MAX_JSON_BYTES, 30)?;
    let observed = inspect(&raw)?;
    let after = identity()?;
    ensure!(
        after == boot && gb_core::hash_file(&r.adb.path)? == r.adb.sha256,
        "capture identity/input changed"
    );
    let report = serde_json::json!({
        "schema_version": 1,
        "status": "host_vulkan_advertisements_observed",
        "serial": r.serial,
        "android_user": r.android_user,
        "fingerprint": r.fingerprint,
        "boot_id": boot,
        "adb_sha256": r.adb.sha256,
        "source_command": "cmd gpu vkjson",
        "enumeration_context": "android_gpu_service",
        "original_vmm_namespace_verified": false,
        "observed": observed,
        "host_boot_unchanged": true,
        "firmware_written": false,
        "full_port_verified": false
    });
    gb_core::write_json(destination, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({"devices":[{"properties":{"apiVersion":(1<<22)|(1<<12),"deviceType":1,"deviceName":"fixture GPU","pipelineCacheUUID":[1,2,3]},"extensions":REQUIRED.iter().map(|n|serde_json::json!({"extensionName":n,"specVersion":1})).collect::<Vec<_>>()}]})
    }
    #[test]
    fn advertisement_does_not_prove_render_or_memory_interop() {
        let report = inspect(&fixture().to_string()).unwrap();
        assert_eq!(report.state, State::Compatible);
        assert!(
            !report.memory_import_or_export_verified
                && !report.guest_vulkan_verified
                && !report.full_port_verified
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("pipelineCacheUUID")
        );
        let mut v = fixture();
        v["devices"][0]["extensions"].as_array_mut().unwrap().pop();
        assert_eq!(inspect(&v.to_string()).unwrap().state, State::PatchRequired);
    }
    #[test]
    fn missing_inventory_cpu_and_bad_types_are_not_hardware_passes() {
        let mut v = fixture();
        v["devices"][0]
            .as_object_mut()
            .unwrap()
            .remove("extensions");
        assert_eq!(inspect(&v.to_string()).unwrap().state, State::Unknown);
        assert!(inspect("{}").is_err());
        assert_eq!(inspect("{\"devices\":[]}").unwrap().state, State::Unknown);
        let mut v = fixture();
        v["devices"][0]["properties"]["deviceType"] = 4.into();
        assert_eq!(inspect(&v.to_string()).unwrap().state, State::Unknown);
        v["devices"][0]["properties"]["apiVersion"] = "1.3".into();
        assert!(inspect(&v.to_string()).is_err());
    }
    #[test]
    fn duplicate_extensions_and_budget_exhaustion_refused() {
        let mut v = fixture();
        let same = v["devices"][0]["extensions"][0].clone();
        v["devices"][0]["extensions"]
            .as_array_mut()
            .unwrap()
            .push(same);
        assert!(inspect(&v.to_string()).is_err());
        assert!(inspect(&" ".repeat(MAX_JSON_BYTES)).is_err());
    }
    #[test]
    fn native_integral_double_encoding_is_exactly_bounded() {
        let mut v = fixture();
        v["devices"][0]["properties"]["apiVersion"] = serde_json::json!(4206720.0);
        v["devices"][0]["properties"]["deviceType"] = serde_json::json!(1.0);
        assert_eq!(
            inspect(&v.to_string()).unwrap().devices[0]
                .properties
                .api_version,
            Some(4206720)
        );
        for bad in [
            serde_json::json!(-1.0),
            serde_json::json!(1.5),
            serde_json::json!(4294967296.0),
            serde_json::json!("4206720"),
        ] {
            v["devices"][0]["properties"]["apiVersion"] = bad;
            assert!(inspect(&v.to_string()).is_err());
        }
    }
    #[test]
    fn offline_json_never_asserts_capture_identity_and_refuses_incomplete_input() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.json");
        let output = dir.path().join("report.json");
        std::fs::write(&source, fixture().to_string()).unwrap();
        let report = inspect_file(&source, &output).unwrap();
        assert_eq!(report["enumeration_context"], "provided_json_unverified");
        assert_eq!(report["device_identity_verified"], false);
        assert!(inspect_file(&source, &output).is_err());
        assert!(inspect_file(&source, &source).is_err());
        std::fs::write(&source, " ".repeat(MAX_JSON_BYTES)).unwrap();
        let rejected = dir.path().join("rejected.json");
        assert!(inspect_file(&source, &rejected).is_err());
        assert!(!rejected.exists());
    }
}
