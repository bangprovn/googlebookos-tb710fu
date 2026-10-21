//! Kernel-only boot v4 adaptation with declared project kernel options.
//! No ramdisk, DTB, vendor_boot, AVB policy or device writes are performed here.
use anyhow::{Context, Result, ensure};
use gb_core::{hash_file, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub input: PathBuf,
    pub sha256: String,
    pub kernel: PathBuf,
    pub kernel_sha256: String,
    pub partition_bytes: u64,
    pub pack: PathBuf,
    pub sandbox: gb_tools::Sandbox,
    /// Append only project-namespaced kernel options; existing values cannot
    /// be overridden. Empty keeps the original exact-header contract.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cmdline_append: BTreeMap<String, String>,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [&mut r.input, &mut r.kernel, &mut r.pack] {
            if p.is_relative() {
                *p = parent.join(&*p);
            }
        }
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.partition_bytes >= 1024 * 1024
                && self.partition_bytes.is_multiple_of(4096),
            "invalid kernel adaptation request"
        );
        for sha in [&self.sha256, &self.kernel_sha256] {
            ensure!(
                sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                "SHA256 pins required"
            );
        }
        declared_cmdline("", &self.cmdline_append)?;
        self.sandbox.validate()
    }
}

fn header(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let info = gb_partition::inspect(&mut f, &gb_core::Format::Boot)?;
    ensure!(
        info["header_version"] == 4
            && info["kernel_bytes"]
                .as_u64()
                .is_some_and(|v| v > 0 && v <= 64 * 1024 * 1024)
            && info["ramdisk_bytes"] == 0
            && info["signature_bytes"] == 0,
        "requires kernel-only boot v4 without GKI signature"
    );
    gb_partition::read_at(&mut f, 0, 4096)
}

fn declared_cmdline(original: &str, options: &BTreeMap<String, String>) -> Result<String> {
    if options.is_empty() {
        return Ok(original.to_owned());
    }
    ensure!(
        !original.split_ascii_whitespace().any(|arg| arg == "--"),
        "cannot append kernel options after init-argument separator"
    );
    let mut result = original.to_owned();
    for (key, value) in options {
        let suffix = key
            .strip_prefix("gb_")
            .context("only gb_ kernel options may be appended")?;
        ensure!(
            !suffix.is_empty()
                && key.len() <= 64
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                && !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b",._:-".contains(&b)),
            "invalid project kernel option"
        );
        ensure!(
            !original
                .split_ascii_whitespace()
                .any(|arg| arg.split('=').next() == Some(key)),
            "project kernel option already present: {key}"
        );
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(key);
        result.push('=');
        result.push_str(value);
    }
    ensure!(
        result.len() < 1536,
        "boot v4 command line exceeds header budget"
    );
    Ok(result)
}

fn preserved(before: &[u8], after: &[u8], cmdline: Option<&str>) -> Result<()> {
    ensure!(
        before.len() == 4096 && after.len() == 4096,
        "invalid boot header window"
    );
    let mut expected = before.to_vec();
    if let Some(cmdline) = cmdline {
        ensure!(cmdline.len() < 1536, "invalid expected command line");
        expected[44..1580].fill(0);
        expected[44..44 + cmdline.len()].copy_from_slice(cmdline.as_bytes());
    }
    ensure!(
        expected[..8] == after[..8] && expected[12..] == after[12..],
        "boot header changed outside kernel length and declared options"
    );
    Ok(())
}

pub fn build(request: &Request, output: &Path) -> Result<serde_json::Value> {
    request.validate()?;
    ensure!(
        output.is_dir() && std::fs::read_dir(output)?.next().is_none(),
        "empty staging output required"
    );
    for (p, sha) in [
        (&request.input, &request.sha256),
        (&request.kernel, &request.kernel_sha256),
    ] {
        gb_core::separate_from_input(p, output)?;
        let m = std::fs::symlink_metadata(p)?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink() && hash_file(p)? == *sha,
            "kernel/boot input pin mismatch"
        );
    }
    let before = header(&request.input)?;
    let len = std::fs::metadata(&request.kernel)?.len();
    ensure!(
        (64..=64 * 1024 * 1024).contains(&len) && len + 128 * 1024 < request.partition_bytes,
        "kernel exceeds image/partition budget"
    );
    let image_header = gb_partition::read_at(&mut File::open(&request.kernel)?, 0, 64)?;
    ensure!(
        &image_header[56..60] == b"ARM\x64",
        "kernel must be an uncompressed ARM64 Linux Image"
    );
    let tool = gb_tools::host_tool(&request.pack, &[&request.input, &request.kernel])?;
    let identity = gb_tools::identity(&tool, &request.sandbox)?;
    let encoded = u32::from_le_bytes(before[16..20].try_into()?);
    let version = encoded >> 11;
    let patch = encoded & 0x7ff;
    let cmdline = std::str::from_utf8(
        before[44..1580]
            .split(|b| *b == 0)
            .next()
            .context("boot cmdline absent")?,
    )?;
    let cmdline = declared_cmdline(cmdline, &request.cmdline_append)?;
    let mut args = vec![
        "--header_version".into(),
        "4".into(),
        "--kernel".into(),
        "/input.img".into(),
        "--cmdline".into(),
        cmdline.clone(),
        "--os_version".into(),
        format!(
            "{}.{}.{}",
            (version >> 14) & 127,
            (version >> 7) & 127,
            version & 127
        ),
        "--output".into(),
        "/output/boot.img".into(),
    ];
    if patch != 0 {
        ensure!((1..=12).contains(&(patch & 15)), "invalid boot patch month");
        args.extend([
            "--os_patch_level".into(),
            format!("{:04}-{:02}", 2000 + (patch >> 4), patch & 15),
        ]);
    }
    gb_tools::run(
        &request.sandbox,
        &tool,
        args,
        &request.kernel,
        output,
        Duration::from_secs(120),
    )?;
    let image = output.join("boot.img");
    preserved(
        &before,
        &header(&image)?,
        (!request.cmdline_append.is_empty()).then_some(cmdline.as_str()),
    )?;
    let mut f = File::open(&image)?;
    f.seek(SeekFrom::Start(4096))?;
    ensure!(
        gb_core::hash_reader(f.take(len))? == request.kernel_sha256,
        "repacked kernel differs"
    );
    ensure!(
        std::fs::metadata(&image)?.len() + 128 * 1024 < request.partition_bytes,
        "boot image exceeds partition/AVB reserve"
    );
    for (p, sha) in [
        (&request.input, &request.sha256),
        (&request.kernel, &request.kernel_sha256),
    ] {
        ensure!(hash_file(p)? == *sha, "source changed during repack");
    }
    let report = serde_json::json!({"schema_version":1,"status":"unsigned_kernel_boot_candidate","image_sha256":hash_file(&image)?,"image_bytes":std::fs::metadata(&image)?.len(),"source_sha256":request.sha256,"kernel_sha256":request.kernel_sha256,"header_preserved_except_kernel_length":request.cmdline_append.is_empty(),"header_preserved_except_kernel_length_and_declared_options":true,"declared_cmdline_append":request.cmdline_append,"avb_signed":false,"runtime_verified":false,"bootable":false,"firmware_written":false,"tool":identity});
    write_json(&output.join("kernel-boot-report.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_length_is_only_permitted_header_change() {
        let a = vec![0; 4096];
        let mut b = a.clone();
        b[8] = 1;
        assert!(preserved(&a, &b, None).is_ok());
        for index in [0, 12, 16, 20, 40, 44, 1580, 4095] {
            let mut bad = b.clone();
            bad[index] ^= 1;
            assert!(preserved(&a, &bad, None).is_err());
        }
        assert!(preserved(&a, &b[..4095], None).is_err());
    }

    #[test]
    fn declared_options_are_literal_bounded_and_cannot_override_existing_state() {
        let opts = BTreeMap::from([("gb_vm_pool_mib".into(), "2048".into())]);
        assert_eq!(
            declared_cmdline("console=hvc0", &opts).unwrap(),
            "console=hvc0 gb_vm_pool_mib=2048"
        );
        for original in ["gb_vm_pool_mib=0", "gb_vm_pool_mib", "console=hvc0 --"] {
            assert!(declared_cmdline(original, &opts).is_err());
        }
        for (key, val) in [
            ("androidboot.verifiedbootstate", "orange"),
            ("gb_x", "x y"),
            ("gb_x", "x\0"),
            ("gb_", "1"),
            ("gb_x", "\"x\""),
        ] {
            assert!(declared_cmdline("", &BTreeMap::from([(key.into(), val.into())])).is_err());
        }
        assert!(declared_cmdline(&"x".repeat(1535), &opts).is_err());
        let mut before = vec![0; 4096];
        before[44..47].copy_from_slice(b"old");
        let mut after = before.clone();
        after[44..1580].fill(0);
        after[44..47].copy_from_slice(b"new");
        assert!(preserved(&before, &after, Some("new")).is_ok());
        assert!(preserved(&before, &after, None).is_err());
        after[1580] = 1;
        assert!(preserved(&before, &after, Some("new")).is_err());
    }
}
