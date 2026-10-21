//! Offline, pinned role-enum inspection. Never invokes ADB or changes USB roles.
use anyhow::{Result, ensure};
use gb_framework::rro::PinnedFile;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::Path,
};

const COLLECTOR: &str = include_str!("../../../scripts/inspect-android-usb-roles.sh");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    capture: PinnedFile,
    collector: PinnedFile,
    android_boot_id: String,
    serial: String,
}

#[derive(Debug, Serialize)]
struct Role {
    kind: String,
    index: u8,
    observation: String,
    current_role: Option<String>,
    advertised_roles: Vec<String>,
}

fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && before.len() > 0 && before.len() <= limit,
        "bounded regular file required"
    );
    #[cfg(target_os = "linux")]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux UAPI: O_NOFOLLOW | O_NONBLOCK prevents leaf-link/FIFO races.
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(path)?
    };
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("bounded no-follow reader initially supports Linux");
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        ensure!(
            opened.is_file() && opened.dev() == before.dev() && opened.ino() == before.ino(),
            "input changed while opening"
        );
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == before.len(), "input size changed");
        Ok(bytes)
    }
}

fn pinned(pin: &PinnedFile, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        pin.sha256.len() == 64 && pin.sha256.bytes().all(|c| c.is_ascii_hexdigit()),
        "SHA-256 required"
    );
    let bytes = bounded(&pin.path, limit)?;
    ensure!(
        gb_core::digest(&bytes) == pin.sha256.to_ascii_lowercase(),
        "input pin mismatch"
    );
    Ok(bytes)
}

fn role(kind: &str, index: u8, value: &str) -> Result<Role> {
    let mut r = Role {
        kind: kind.into(),
        index,
        observation: "observed".into(),
        current_role: None,
        advertised_roles: Vec::new(),
    };
    if ["unreadable", "unrecognized", "over_budget"].contains(&value) {
        r.observation = value.into();
        return Ok(r);
    }
    if kind == "usb_role" {
        ensure!(
            ["none", "host", "device"].contains(&value),
            "invalid USB role enum"
        );
        r.current_role = Some(value.into());
        return Ok(r);
    }
    let allowed: &[&str] = match kind {
        "data_role" => &["[host]", "[device]", "[host] device", "host [device]"],
        "power_role" => &["[source]", "[sink]", "[source] sink", "source [sink]"],
        "port_type" => &[
            "[source]",
            "[sink]",
            "[source] sink dual",
            "source [sink] dual",
            "source sink [dual]",
        ],
        _ => anyhow::bail!("unknown role family"),
    };
    ensure!(
        allowed.contains(&value),
        "unrecognized or content-bearing role field"
    );
    for token in value.split(' ') {
        let selected = token.starts_with('[') && token.ends_with(']');
        let word = token.trim_matches(['[', ']']);
        if selected {
            r.current_role = Some(word.into());
        }
        r.advertised_roles.push(word.into());
    }
    Ok(r)
}

fn inspect(text: &str, expected_boot: &str) -> Result<serde_json::Value> {
    ensure!(
        uuid(expected_boot)
            && text.len() <= 8192
            && text.is_ascii()
            && text.ends_with('\n')
            && !text.contains('\0'),
        "snapshot size/encoding/boot guard"
    );
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some("GB_USB_ROLE_SNAPSHOT_V1"),
        "collector protocol header required"
    );
    let mut uid = None;
    let mut boot = None;
    let mut classes = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut roles = Vec::new();
    let mut limits = BTreeSet::new();
    for line in lines {
        ensure!(line.len() <= 128, "snapshot line budget");
        let parts: Vec<_> = line.split('\t').collect();
        match parts.as_slice() {
            ["uid", value] => {
                ensure!(
                    uid.is_none() && *value == "2000",
                    "shell UID2000 required once"
                );
                uid = Some(*value);
            }
            ["boot_id", value] => {
                ensure!(
                    boot.is_none() && *value == expected_boot,
                    "unexpected/duplicate Android boot"
                );
                boot = Some(*value);
            }
            ["class", name, value] => {
                ensure!(
                    ["usb_role", "typec"].contains(name)
                        && ["present", "missing", "unreadable"].contains(value),
                    "class enum required"
                );
                ensure!(
                    classes
                        .insert((*name).to_owned(), (*value).to_owned())
                        .is_none(),
                    "duplicate class field"
                );
            }
            ["limit", name] => {
                ensure!(
                    ["usb_role", "typec"].contains(name) && limits.insert((*name).to_owned()),
                    "invalid/duplicate limit field"
                );
            }
            ["role", kind, index, value] => {
                ensure!(
                    ["usb_role", "data_role", "power_role", "port_type"].contains(kind),
                    "unexpected metadata family"
                );
                let index = index.parse::<u8>()?;
                ensure!(
                    index < 8 && seen.insert(((*kind).to_owned(), index)),
                    "role count/duplicate guard"
                );
                roles.push(role(kind, index, value)?);
            }
            _ => anyhow::bail!(
                "unexpected snapshot field; device descriptors and identifiers are not accepted"
            ),
        }
    }
    ensure!(
        uid.is_some() && boot.is_some() && classes.len() == 2 && roles.len() <= 32,
        "incomplete snapshot"
    );
    for r in &roles {
        let family = if r.kind == "usb_role" {
            "usb_role"
        } else {
            "typec"
        };
        ensure!(
            classes.get(family).is_some_and(|s| s == "present"),
            "role observed under absent/unreadable class"
        );
    }
    // These are observations/declarations only, including when host is selected.
    let host_observed = roles.iter().any(|r| {
        ["usb_role", "data_role"].contains(&r.kind.as_str())
            && r.current_role.as_deref() == Some("host")
    });
    let host_declared = roles
        .iter()
        .any(|r| r.kind == "data_role" && r.advertised_roles.iter().any(|s| s == "host"));
    Ok(
        json!({"schema_version":1,"state":"unknown","status":"role_metadata_inspected_not_functional_host_test",
        "android_boot_id":expected_boot,"reported_uid":2000,"classes":classes,"roles":roles,"truncated_families":limits,
        "host_data_role_observed":host_observed,"host_data_role_advertised":host_declared,
        "usb_host_function_verified":false,"accessory_enumeration_verified":false,"usb_transfer_verified":false,
        "power_delivery_verified":false,"external_display_verified":false,"full_port_verified":false,"hardware_identity_attested":false,
        "role_or_permission_changes":false,"device_identifiers_collected":false,
        "scope":"Pinned read-only role enums only; selected host role and declared capabilities do not prove working accessory I/O or power delivery"}),
    )
}

fn validate(request_path: &Path, output: &Path) -> Result<serde_json::Value> {
    let mut r: Request = serde_json::from_slice(&bounded(request_path, 16384)?)?;
    ensure!(
        r.schema_version == 1
            && !r.serial.is_empty()
            && r.serial.len() <= 64
            && r.serial
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "request identity/schema"
    );
    let parent = request_path.parent().unwrap_or(Path::new("."));
    for pin in [&mut r.capture, &mut r.collector] {
        if pin.path.is_relative() {
            pin.path = parent.join(&pin.path);
        }
        gb_core::separate_from_input(&pin.path, output)?;
    }
    ensure!(
        pinned(&r.collector, 16384)? == COLLECTOR.as_bytes(),
        "collector does not match repository-owned source"
    );
    let capture = pinned(&r.capture, 8192)?;
    let text = std::str::from_utf8(&capture)?;
    let mut report = inspect(text, &r.android_boot_id)?;
    report["configured_serial"] = json!(r.serial);
    report["serial_origin_verified"] = json!(false);
    report["input_sha256"] = json!({"capture":r.capture.sha256,"collector":r.collector.sha256});
    ensure!(
        matches!(fs::symlink_metadata(output),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "new report path required"
    );
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, &report)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output).map_err(|e| e.error)?;
    Ok(report)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: usb_role_snapshot PINNED_REQUEST.json NEW_REPORT.json (offline only)"
    );
    let report = validate(Path::new(&args[0]), Path::new(&args[1]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    fn snapshot(tail: &str) -> String {
        format!(
            "GB_USB_ROLE_SNAPSHOT_V1\nuid\t2000\nboot_id\t{BOOT}\nclass\tusb_role\tpresent\nclass\ttypec\tpresent\n{tail}"
        )
    }
    #[test]
    fn role_and_dual_role_declarations_never_promote_functionality() {
        let value=inspect(&snapshot("role\tusb_role\t0\thost\nrole\tdata_role\t0\t[host] device\nrole\tpower_role\t0\tsource [sink]\nrole\tport_type\t0\tsource sink [dual]\n"),BOOT).unwrap();
        assert_eq!(value["host_data_role_observed"], true);
        assert_eq!(value["host_data_role_advertised"], true);
        for field in [
            "usb_host_function_verified",
            "accessory_enumeration_verified",
            "usb_transfer_verified",
            "power_delivery_verified",
            "external_display_verified",
            "full_port_verified",
            "hardware_identity_attested",
        ] {
            assert_eq!(value[field], false);
        }
        assert_eq!(value["state"], "unknown");
        let device = inspect(
            &snapshot("role\tdata_role\t0\thost [device]\nrole\tpower_role\t0\t[source] sink\n"),
            BOOT,
        )
        .unwrap();
        assert_eq!(device["host_data_role_observed"], false);
        assert_eq!(device["host_data_role_advertised"], true);
    }
    #[test]
    fn missing_denied_and_unknown_abi_are_unknown_not_unsupported() {
        let absent = snapshot("")
            .replace("usb_role\tpresent", "usb_role\tmissing")
            .replace("typec\tpresent", "typec\tunreadable");
        let value = inspect(&absent, BOOT).unwrap();
        assert_eq!(value["state"], "unknown");
        for v in ["unreadable", "unrecognized", "over_budget"] {
            assert!(inspect(&snapshot(&format!("role\tusb_role\t0\t{v}\n")), BOOT).is_ok());
        }
        assert!(inspect(&(absent + "role\tdata_role\t0\t[host]\n"), BOOT).is_err());
    }
    #[test]
    fn refuses_reboots_uid_malformed_duplicate_and_private_fields() {
        for tail in [
            "role\tusb_role\t0\thost\nrole\tusb_role\t0\tdevice\n",
            "role\tusb_role\t8\thost\n",
            "serial\tprivate\n",
            "role\tdata_role\t0\thost serial=private\n",
            "role\tdevice_name\t0\tprivate\n",
            "class\ttypec\tpresent\n",
        ] {
            assert!(inspect(&snapshot(tail), BOOT).is_err());
        }
        assert!(inspect(&snapshot("").replace("uid\t2000", "uid\t0"), BOOT).is_err());
        assert!(inspect(&snapshot(""), "different-boot").is_err());
        assert!(inspect(&(snapshot("") + &"x".repeat(8192)), BOOT).is_err());
    }
    #[test]
    fn pin_checks_and_noclobber_apply_to_real_files() {
        let d = tempfile::tempdir().unwrap();
        let cap = d.path().join("capture");
        fs::write(&cap, snapshot("role\tusb_role\t0\tdevice\n")).unwrap();
        let script = d.path().join("collector");
        fs::write(&script, COLLECTOR).unwrap();
        let pin = |p: &Path| json!({"path":p,"sha256":gb_core::hash_file(p).unwrap()});
        let request = d.path().join("request.json");
        fs::write(&request,json!({"schema_version":1,"capture":pin(&cap),"collector":pin(&script),"android_boot_id":BOOT,"serial":"fixture"}).to_string()).unwrap();
        let output = d.path().join("report.json");
        assert!(validate(&request, &output).is_ok());
        assert!(validate(&request, &output).is_err());
        fs::write(&cap, "modified").unwrap();
        assert!(validate(&request, &d.path().join("other.json")).is_err());
        #[cfg(unix)]
        {
            let link = d.path().join("link");
            std::os::unix::fs::symlink(&script, &link).unwrap();
            assert!(bounded(&link, 16384).is_err());
        }
    }
}
