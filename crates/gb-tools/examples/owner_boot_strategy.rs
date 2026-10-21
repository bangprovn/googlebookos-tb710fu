//! Apply the existing Android HSUM boot policy without selecting a user ID,
//! changing credentials, weakening SELinux or writing firmware. A reboot must
//! independently prove owner selection; successful setprop is not that proof.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

const PROPERTY: &str = "persist.user.hsum_boot_strategy";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    adb: PathBuf,
    serial: String,
    usb_serial_file: PathBuf,
    android_boot_id: String,
    system_fingerprint: String,
    vendor_fingerprint: String,
    owner_id: u32,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Policy {
    headless: bool,
    resource: i32,
    property_override: Option<i32>,
    effective: i32,
}

fn parse_override(value: &str) -> Result<Option<i32>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let value: i32 = value.trim().parse()?;
    ensure!(
        [-1, 0, 1].contains(&value),
        "unknown HSUM strategy override"
    );
    Ok(Some(value))
}

fn desired(action: &str, policy: &Policy) -> Result<Option<i32>> {
    ensure!(
        policy.headless && policy.resource == 1,
        "not the qualified headless donor policy"
    );
    let expected = match policy.property_override {
        Some(0) => 0,
        Some(1) => 1,
        None | Some(-1) => 1,
        _ => anyhow::bail!("unsupported override"),
    };
    ensure!(
        policy.effective == expected,
        "framework strategy differs from property/resource evidence"
    );
    match action {
        "inspect" => Ok(None),
        "use-previous-user" => {
            ensure!(
                policy.property_override.is_none() || policy.property_override == Some(-1),
                "an explicit owner override already exists; preserving it"
            );
            Ok(Some(0))
        }
        "restore-donor" => {
            ensure!(
                policy.property_override == Some(0),
                "expected the installed previous-user override"
            );
            Ok(Some(-1))
        }
        _ => anyhow::bail!("unsupported action"),
    }
}

struct Device<'a> {
    target: &'a Target,
    adb: PathBuf,
}
impl Device<'_> {
    fn shell(&self, command: &str) -> Result<String> {
        let result = gb_core::run_tool(
            &self.adb,
            &[
                "-s".into(),
                self.target.serial.clone(),
                "shell".into(),
                command.into(),
            ],
            Duration::from_secs(15),
        )?;
        Ok(result.stdout.trim().to_owned())
    }
    fn guard(&self, require_quiescent_owner: bool) -> Result<()> {
        let t = self.target;
        ensure!(
            fs::read_to_string(&t.usb_serial_file)?.trim() == t.serial,
            "USB identity differs"
        );
        ensure!(
            self.shell("getprop ro.serialno")? == t.serial,
            "ADB serial differs"
        );
        ensure!(
            self.shell("cat /proc/sys/kernel/random/boot_id")? == t.android_boot_id,
            "Android boot differs"
        );
        ensure!(
            self.shell("getprop ro.build.fingerprint")? == t.system_fingerprint
                && self.shell("getprop ro.vendor.build.fingerprint")? == t.vendor_fingerprint,
            "system/vendor fingerprint differs"
        );
        ensure!(
            self.shell("getprop sys.boot_completed")? == "1"
                && self.shell("getenforce")? == "Enforcing",
            "boot incomplete or SELinux not enforcing"
        );
        if !require_quiescent_owner {
            return Ok(());
        }
        ensure!(
            self.shell("am get-current-user")? == t.owner_id.to_string()
                && self.shell(&format!("am get-started-user-state {}", t.owner_id))?
                    == "RUNNING_UNLOCKED",
            "authorized owner is not foreground/unlocked"
        );
        let policy = self.shell("dumpsys window policy")?;
        let delegate = policy
            .split_once("KeyguardServiceDelegate")
            .context("keyguard state absent")?
            .1;
        let showing: Vec<_> = delegate
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("showing="))
            .collect();
        ensure!(
            showing == ["false"],
            "normal owner keyguard unlock required"
        );
        ensure!(
            self.shell("/apex/com.android.virt/bin/vm list")? == "On device VMs: []",
            "stop the original VM normally before changing boot policy"
        );
        Ok(())
    }
    fn policy(&self) -> Result<Policy> {
        let headless = self.shell("getprop ro.fw.mu.headless_system_user")?;
        ensure!(
            ["true", "false"].contains(&headless.as_str()),
            "unknown headless mode"
        );
        let resource = self
            .shell("cmd overlay lookup android android:integer/config_hsumBootStrategy")?
            .parse()?;
        let property_override = parse_override(&self.shell(&format!("getprop {PROPERTY}"))?)?;
        let diagnostic = self.shell("dumpsys user | grep -E '^  HSUM Boot Strategy:'")?;
        let values: Vec<_> = diagnostic
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("HSUM Boot Strategy: "))
            .collect();
        ensure!(values.len() == 1, "unambiguous framework strategy absent");
        Ok(Policy {
            headless: headless == "true",
            resource,
            property_override,
            effective: values[0].parse()?,
        })
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: owner_boot_strategy inspect|use-previous-user|restore-donor TARGET.json RECEIPT.json"
    );
    let action = args[0].to_str().context("invalid action")?;
    let target: Target = gb_core::read_json(Path::new(&args[1]), 16384)?;
    ensure!(
        target.owner_id > 0
            && target.serial.len() <= 128
            && !target.serial.is_empty()
            && target
                .serial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid owner/serial"
    );
    ensure!(
        target.android_boot_id.len() == 36
            && target
                .android_boot_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid pinned boot ID"
    );
    let adb = gb_tools::host_tool(&target.adb, &[])?;
    let device = Device {
        target: &target,
        adb,
    };
    device.guard(action != "inspect")?;
    let before = device.policy()?;
    let value = desired(action, &before)?;
    let version = gb_core::run_tool(&device.adb, &["version".into()], Duration::from_secs(5))?;
    ensure!(
        version.stdout.starts_with("Android Debug Bridge version"),
        "unrecognized ADB version"
    );
    let mut report = json!({"schema_version":1,"action":action,"serial":target.serial,
        "android_boot_id":target.android_boot_id,"before":before,"property":PROPERTY,
        "planned_value":value,"mutation_attempted":false,"status":"prepared",
        "credential_policy_changed":false,"credentials_in_report":false,"firmware_written":false,
        "selinux_policy_changed":false,"runtime_reboot_verified":false,
        "requires_reboot_validation":value.is_some(),"adb_version":version.stdout.trim(),
        "adb_sha256":gb_core::hash_file(&device.adb)?});
    let receipt = Path::new(&args[2]);
    let mut initial = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(receipt)?;
    initial.write_all(serde_json::to_string_pretty(&report)?.as_bytes())?;
    initial.sync_all()?;
    drop(initial);
    if let Some(value) = value {
        device.guard(true)?;
        ensure!(
            device.policy()? == before,
            "policy changed during preflight"
        );
        report["mutation_attempted"] = json!(true);
        report["status"] = json!("mutation_attempted_not_yet_verified");
        gb_core::write_json(receipt, &report)?;
        device.shell(&format!("setprop {PROPERTY} {value}"))?;
        let after = device.policy()?;
        ensure!(
            after.property_override == Some(value)
                && after.effective == if value == -1 { after.resource } else { value },
            "property/framework readback differs; inspect before any retry"
        );
        device.guard(true)?;
        report["after"] = serde_json::to_value(after)?;
        report["status"] = json!("native_property_verified_pending_reboot_validation");
    } else {
        report["status"] = json!("observed_no_change");
    }
    gb_core::write_json(receipt, &report)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn donor(property_override: Option<i32>, effective: i32) -> Policy {
        Policy {
            headless: true,
            resource: 1,
            property_override,
            effective,
        }
    }
    #[test]
    fn only_supported_overrides_parse() -> Result<()> {
        assert_eq!(parse_override("")?, None);
        assert_eq!(parse_override("-1")?, Some(-1));
        assert_eq!(parse_override("0")?, Some(0));
        assert_eq!(parse_override("1")?, Some(1));
        for value in ["2", "true", "0; reboot", "-2"] {
            assert!(parse_override(value).is_err());
        }
        Ok(())
    }
    #[test]
    fn explicit_owner_choices_and_inconsistent_framework_state_are_preserved() -> Result<()> {
        assert_eq!(desired("use-previous-user", &donor(None, 1))?, Some(0));
        assert_eq!(desired("use-previous-user", &donor(Some(-1), 1))?, Some(0));
        assert!(desired("use-previous-user", &donor(Some(0), 0)).is_err());
        assert!(desired("use-previous-user", &donor(Some(1), 1)).is_err());
        assert!(desired("use-previous-user", &donor(None, 0)).is_err());
        Ok(())
    }
    #[test]
    fn restore_uses_native_default_sentinel_without_a_user_number() -> Result<()> {
        assert_eq!(desired("restore-donor", &donor(Some(0), 0))?, Some(-1));
        assert!(desired("restore-donor", &donor(None, 1)).is_err());
        assert_eq!(desired("inspect", &donor(None, 1))?, None);
        Ok(())
    }
    #[test]
    fn non_hsum_or_different_donor_policy_is_refused() {
        let mut p = donor(None, 1);
        p.headless = false;
        assert!(desired("use-previous-user", &p).is_err());
        p.headless = true;
        p.resource = 0;
        assert!(desired("use-previous-user", &p).is_err());
        assert!(desired("invented", &donor(None, 1)).is_err());
    }
}
