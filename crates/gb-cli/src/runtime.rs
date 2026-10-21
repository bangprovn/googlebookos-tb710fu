//! Read-only, bounded first-boot diagnostics. No flash, reboot or device writes.
use anyhow::{Result, ensure};
use gb_core::{ToolFailure, ToolResult, checkpoint, run_tool};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, time::Duration};

// Match message prefixes on the device, before log output crosses ADB. General
// virtmgr/crosvm logs can include the original guest's authentication arguments.
const PROJECT_LOG_PATTERN: &str = "^(gb-runtime-adapter:|gb-avf-display:|GH-RAM-POOL:|GH-PIN:|GH-PMD:|GH-SHIM:|GUNYAH-SHARE-BLOB:|gb-gunyah-phase-v1:|gb-gunyah-span-budget-v1:)";

#[derive(Debug, Serialize)]
pub struct Capture {
    pub result: Option<ToolResult>,
    pub error: Option<String>,
    // run_tool retains at most 64 KiB. At the boundary, conservatively refuse
    // to claim complete output (stdout currently has no truncation counter).
    pub output_complete: bool,
}
impl Capture {
    fn from_result(result: Result<ToolResult>) -> Self {
        match result {
            Ok(result) => Self {
                output_complete: result.stdout.len() < 65536 && !result.stderr_truncated,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                result: error
                    .downcast_ref::<ToolFailure>()
                    .map(|f| f.result.clone()),
                error: Some(error.to_string()),
                output_complete: false,
            },
        }
    }
    fn text(&self) -> Option<&str> {
        if self.error.is_some() || !self.output_complete {
            return None;
        }
        self.result.as_ref().map(|r| r.stdout.trim())
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    DeviceUnavailable,
    BootIncomplete,
    SystemIdentityUnknown,
    UnexpectedSystem,
    BootCompletedNeedsValidation,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub source: &'static str,
    pub captured_at_unix_seconds: u64,
    pub serial: String,
    pub expected_fingerprint: String,
    pub status: Status,
    pub boot_completed: bool,
    pub requested_system_observed: bool,
    pub desktop_verified: bool,
    pub hardware_runtime_verified: bool,
    pub log_capture_scope: &'static str,
    pub captures: BTreeMap<String, Capture>,
    pub limitations: Vec<&'static str>,
}

pub fn collect(adb: &Path, serial: &str, fingerprint: &str) -> Result<Report> {
    collect_with(serial, fingerprint, |args| {
        run_tool(adb, args, Duration::from_secs(10))
    })
}
fn collect_with(
    serial: &str,
    fingerprint: &str,
    mut run: impl FnMut(&[String]) -> Result<ToolResult>,
) -> Result<Report> {
    let captured_at_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    ensure!(
        !serial.is_empty()
            && serial.len() <= 256
            && serial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)),
        "invalid ADB serial"
    );
    ensure!(
        !fingerprint.is_empty()
            && fingerprint.len() <= 4096
            && !fingerprint.chars().any(char::is_control),
        "expected fingerprint must be a complete, nonempty value"
    );
    let mut captures = BTreeMap::new();
    let prefix = ["-s".to_string(), serial.to_string()];
    let mut capture = |name: &str, tail: &[&str]| -> Result<()> {
        checkpoint()?;
        let args: Vec<_> = prefix
            .iter()
            .cloned()
            .chain(tail.iter().map(|s| s.to_string()))
            .collect();
        captures.insert(name.to_string(), Capture::from_result(run(&args)));
        checkpoint()?;
        Ok(())
    };
    capture("connection", &["get-state"])?;
    if captures.get("connection").and_then(Capture::text) == Some("device") {
        for key in [
            "sys.boot_completed",
            "ro.build.fingerprint",
            "ro.vendor.build.fingerprint",
            "ro.product.device",
            "ro.build.version.sdk",
            "ro.boot.slot_suffix",
            "ro.boot.verifiedbootstate",
            "ro.boot.vbmeta.device_state",
            "ro.fw.mu.headless_system_user",
            "ro.boot.hypervisor.vm.supported",
            "ro.boot.hypervisor.protected_vm.supported",
            "ro.boot.hypervisor.version",
            "ro.adb.secure",
            "ro.debuggable",
            "persist.sys.usb.config",
            "sys.usb.config",
            "sys.usb.state",
            "init.svc.adbd",
            "hwservicemanager.always_sets_disabled",
            "hwservicemanager.disabled",
            "hwservicemanager.ready",
            "init.svc.vold",
            "init.svc.keystore2",
            "apexd.status",
            "init.svc.zygote",
            "init.svc.surfaceflinger",
            "init.svc.bootanim",
        ] {
            checkpoint()?;
            let args = ["-s", serial, "shell", "getprop", key].map(str::to_string);
            captures.insert(key.to_string(), Capture::from_result(run(&args)));
        }
        for (name, tail) in [
            ("shell_identity", vec!["shell", "id"]),
            ("kernel", vec!["shell", "uname", "-a"]),
            ("selinux", vec!["shell", "getenforce"]),
            ("main_user", vec!["shell", "cmd", "user", "get-main-user"]),
            ("foreground_user", vec!["shell", "am", "get-current-user"]),
            ("features", vec!["shell", "pm", "list", "features"]),
            (
                "virtualization_info",
                vec!["shell", "/apex/com.android.virt/bin/vm", "info"],
            ),
            (
                "virtualization_devices",
                vec!["shell", "ls", "-l", "/dev/kvm", "/dev/gunyah"],
            ),
            ("services", vec!["shell", "service", "list"]),
            ("hal_services", vec!["shell", "lshal"]),
            ("display", vec!["shell", "dumpsys", "SurfaceFlinger"]),
            (
                "processes",
                vec!["shell", "ps", "-A", "-o", "PID,PPID,NAME"],
            ),
            (
                "logcat",
                vec![
                    "logcat",
                    "-b",
                    "all",
                    "-d",
                    "-t",
                    "200",
                    "-v",
                    "threadtime",
                    "-e",
                    PROJECT_LOG_PATTERN,
                ],
            ),
            (
                "crash_buffer_statistics",
                vec!["logcat", "-b", "crash", "-g"],
            ),
        ] {
            checkpoint()?;
            let args: Vec<_> = prefix
                .iter()
                .cloned()
                .chain(tail.iter().map(|s| s.to_string()))
                .collect();
            captures.insert(name.to_string(), Capture::from_result(run(&args)));
        }
    }
    checkpoint()?;
    let value = |key: &str| captures.get(key).and_then(Capture::text);
    let connected = value("connection") == Some("device");
    let boot_completed = value("sys.boot_completed") == Some("1");
    let observed = value("ro.build.fingerprint").filter(|s| !s.is_empty());
    let requested_system_observed = boot_completed && observed == Some(fingerprint);
    let status = if !connected {
        Status::DeviceUnavailable
    } else if !boot_completed {
        Status::BootIncomplete
    } else if observed.is_none() {
        Status::SystemIdentityUnknown
    } else if observed != Some(fingerprint) {
        Status::UnexpectedSystem
    } else {
        Status::BootCompletedNeedsValidation
    };
    Ok(Report {
        schema_version: 1,
        source: "read_only_adb_boot_probe",
        captured_at_unix_seconds,
        serial: serial.to_string(),
        expected_fingerprint: fingerprint.to_string(),
        status,
        boot_completed,
        requested_system_observed,
        desktop_verified: false,
        hardware_runtime_verified: false,
        log_capture_scope: "on_device_project_message_prefix_allowlist_and_crash_buffer_statistics",
        captures,
        limitations: vec![
            "A fingerprint and boot-completed property are observations, not proof of a functional desktop",
            "Services and HAL declarations do not prove hardware operation",
            "Only bounded recent project-prefix messages and crash-buffer statistics are requested; general application logs and full process arguments are not collected",
            "Filtered logs do not establish absence of other application, kernel or hardware errors; privileged diagnostics may be unavailable",
            "ADB boot-state properties do not validate AVB acceptance or rollback floors",
            "Sequential observations are not an atomic device snapshot",
            "Hypervisor properties, feature declarations and device nodes do not establish that a VM can boot",
            "A missing KVM device alone does not rule out another virtualization backend such as Gunyah",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tool(args: &[String], stdout: &str) -> ToolResult {
        ToolResult {
            program: "fixture-adb".into(),
            args: args.to_vec(),
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
            stderr_filtered_lines: 0,
            stderr_truncated: false,
        }
    }
    #[test]
    fn diagnostics_never_request_unfiltered_logs_or_full_process_arguments() {
        let mut log_queries = 0;
        let mut process_queries = 0;
        let r = collect_with("fixture", "donor", |args| {
            if args.iter().any(|s| s == "logcat") {
                log_queries += 1;
                if args.iter().any(|s| s == "-g") {
                    assert!(!args.iter().any(|s| s == "-d"));
                } else {
                    let filter = args
                        .iter()
                        .position(|s| s == "-e")
                        .expect("device-side filter required");
                    assert_eq!(
                        args.get(filter + 1).map(String::as_str),
                        Some(PROJECT_LOG_PATTERN)
                    );
                    assert!(PROJECT_LOG_PATTERN.starts_with("^("));
                }
            }
            if args.iter().any(|s| s == "ps") {
                process_queries += 1;
                assert_eq!(&args[args.len() - 4..], ["ps", "-A", "-o", "PID,PPID,NAME"]);
            }
            let out = match args.last().map(String::as_str) {
                Some("get-state") => "device",
                Some("sys.boot_completed") => "1",
                Some("ro.build.fingerprint") => "donor",
                _ => "",
            };
            Ok(tool(args, out))
        })
        .unwrap();
        assert_eq!(log_queries, 2);
        assert_eq!(process_queries, 1);
        assert!(!r.desktop_verified && !r.hardware_runtime_verified);
        assert!(r.captures.contains_key("crash_buffer_statistics"));
    }
    #[test]
    fn stock_boot_cannot_be_reported_as_donor_boot() {
        let r = collect_with("fixture", "donor", |args| {
            let out = match args.last().map(String::as_str) {
                Some("get-state") => "device",
                Some("sys.boot_completed") => "1",
                Some("ro.build.fingerprint") => "stock",
                _ => "",
            };
            Ok(tool(args, out))
        })
        .unwrap();
        assert_eq!(r.status, Status::UnexpectedSystem);
        assert!(
            !r.requested_system_observed && !r.desktop_verified && !r.hardware_runtime_verified
        );
    }
    #[test]
    fn booted_donor_still_requires_desktop_and_hardware_tests() {
        let r = collect_with("fixture", "donor", |args| {
            let out = match args.last().map(String::as_str) {
                Some("get-state") => "device",
                Some("sys.boot_completed") => "1",
                Some("ro.build.fingerprint") => "donor",
                _ => "",
            };
            Ok(tool(args, out))
        })
        .unwrap();
        assert_eq!(r.status, Status::BootCompletedNeedsValidation);
        assert!(r.requested_system_observed);
        assert!(!r.desktop_verified && !r.hardware_runtime_verified);
    }
    #[test]
    fn unavailable_device_retains_diagnostics_without_further_calls() {
        let mut calls = 0;
        let r = collect_with("fixture", "donor", |args| {
            calls += 1;
            let mut t = tool(args, "");
            t.exit_code = Some(1);
            t.stderr = "device offline".into();
            Err(ToolFailure { result: t }.into())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(r.status, Status::DeviceUnavailable);
        assert!(r.captures["connection"].result.is_some());
    }

    #[test]
    fn gunyah_and_advertised_capabilities_do_not_certify_vm_boot() {
        let r = collect_with("fixture", "donor", |args| {
            assert_eq!(&args[..2], &["-s".to_string(), "fixture".to_string()]);
            if args.iter().any(|a| a == "/dev/gunyah") {
                let mut t = tool(args, "crw-rw-rw- root root /dev/gunyah\n");
                t.exit_code = Some(1);
                t.stderr = "ls: /dev/kvm: No such file or directory".into();
                return Err(ToolFailure { result: t }.into());
            }
            let out = match args.last().map(String::as_str) {
                Some("get-state") => "device",
                Some("sys.boot_completed" | "ro.boot.hypervisor.vm.supported") => "1",
                Some("ro.build.fingerprint") => "donor",
                Some("get-main-user" | "get-current-user") => "11",
                Some("info") => "Only non-protected VMs are supported.\n/dev/kvm does not exist.",
                _ => "",
            };
            Ok(tool(args, out))
        })
        .unwrap();
        assert_eq!(r.status, Status::BootCompletedNeedsValidation);
        assert!(r.requested_system_observed);
        assert_eq!(r.captures["main_user"].text(), Some("11"));
        assert_eq!(r.captures["foreground_user"].text(), Some("11"));
        assert!(r.captures["virtualization_devices"].error.is_some());
        assert!(r.captures["virtualization_devices"].result.is_some());
        assert!(!r.desktop_verified && !r.hardware_runtime_verified);
    }
    #[test]
    fn bounded_identity_output_never_matches() {
        let value = "x".repeat(65536);
        let c = Capture::from_result(Ok(tool(&[], &value)));
        assert!(c.text().is_none());
    }
}
