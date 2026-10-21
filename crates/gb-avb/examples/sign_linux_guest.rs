//! Sign an owner's raw ARM64 guest kernel and bind its debug initrd using AVB.
//! REQUEST_JSON NEW_OUTPUT. This never creates a device flash plan or writes USB.
use anyhow::{Context, Result, ensure};
use gb_avb::{Input, Key};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    kernel: Input,
    initrd: Input,
    key: Key,
    tool: PathBuf,
    sandbox: gb_tools::Sandbox,
    guest_rollback_index: u64,
}
fn regular(input: &Input, max: u64) -> Result<()> {
    ensure!(
        input.sha256.len() == 64 && input.sha256.bytes().all(|c| c.is_ascii_hexdigit()),
        "input hash required"
    );
    let m = fs::symlink_metadata(&input.path)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && m.len() > 0 && m.len() <= max,
        "bounded regular input required"
    );
    ensure!(
        gb_core::hash_file(&input.path)? == input.sha256,
        "input SHA256 differs"
    );
    Ok(())
}
fn snapshot(input: &Input, out: &Path) -> Result<()> {
    gb_core::copy_stream(fs::File::open(&input.path)?, fs::File::create(out)?)?;
    ensure!(gb_core::hash_file(out)? == input.sha256, "snapshot differs");
    Ok(())
}
fn prepare(r: &Request, out: &Path) -> Result<()> {
    ensure!(r.schema_version == 1, "unsupported schema");
    ensure!(!out.exists(), "output already exists");
    r.sandbox.validate()?;
    ensure!(
        r.key.algorithm == "SHA256_RSA4096"
            && r.key.public_key_sha256.len() == 64
            && r.key
                .public_key_sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit()),
        "explicit authorized RSA4096 guest key required"
    );
    for (i, limit) in [
        (&r.kernel, 128 * 1024 * 1024),
        (&r.initrd, 128 * 1024 * 1024),
        (&r.key.input, 64 * 1024),
    ] {
        gb_core::separate_from_input(&i.path, out)?;
        regular(i, limit)?;
    }
    let mut kernel = fs::File::open(&r.kernel.path)?;
    ensure!(
        gb_partition::read_at(&mut kernel, 56, 4)? == b"ARM\x64",
        "raw ARM64 Image required"
    );
    ensure!(
        gb_partition::avb_footer(&mut kernel)?.is_none(),
        "signed guest kernel requires explicit normalization first"
    );
    let mut initrd = fs::File::open(&r.initrd.path)?;
    ensure!(
        gb_partition::read_at(&mut initrd, 0, 2)? == [0x1f, 0x8b],
        "gzip initrd required by this adapter"
    );
    let tool = gb_tools::host_tool(
        &r.tool,
        &[&r.kernel.path, &r.initrd.path, &r.key.input.path],
    )?;
    gb_core::separate_from_input(&tool, out)?;
    let identity = gb_tools::identity(&tool, &r.sandbox)?;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let stage = tempfile::tempdir_in(parent)?;
    let dir = stage.path();
    let mut results = Vec::new();
    let run = |args: Vec<String>| {
        gb_tools::run(
            &r.sandbox,
            &tool,
            args,
            &r.key.input.path,
            dir,
            Duration::from_secs(60),
        )
    };
    results.push(run(vec![
        "extract_public_key".into(),
        "--key".into(),
        "/input.img".into(),
        "--output".into(),
        "/output/guest.avbpubkey".into(),
    ])?);
    ensure!(
        gb_core::hash_file(&dir.join("guest.avbpubkey"))? == r.key.public_key_sha256,
        "authorized guest public key differs"
    );
    snapshot(&r.kernel, &dir.join("boot.img"))?;
    snapshot(&r.initrd, &dir.join("initrd.img"))?;
    snapshot(&r.initrd, &dir.join("initrd_debug.img"))?;
    for (file, partition, salt) in [
        ("initrd_debug.img", "initrd_debug", &r.initrd.sha256),
        ("boot.img", "boot", &r.kernel.sha256),
    ] {
        let mut args: Vec<String> = [
            "add_hash_footer",
            "--image",
            &format!("/output/{file}"),
            "--partition_name",
            partition,
            "--dynamic_partition_size",
            "--algorithm",
            "SHA256_RSA4096",
            "--key",
            "/input.img",
            "--salt",
            salt,
            "--rollback_index",
            &r.guest_rollback_index.to_string(),
            "--flags",
            "0",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if partition == "boot" {
            args.extend([
                "--include_descriptors_from_image".into(),
                "/output/initrd_debug.img".into(),
            ]);
        }
        results.push(run(args)?);
    }
    results.push(run(vec![
        "verify_image".into(),
        "--image".into(),
        "/output/boot.img".into(),
        "--key".into(),
        "/input.img".into(),
    ])?);
    let mut metadata = gb_partition::avb_footer(&mut fs::File::open(dir.join("boot.img"))?)?
        .context("signed footer absent")?;
    ensure!(
        metadata["flags"] == 0
            && metadata["algorithm_type"] == 2
            && metadata["rollback_index"] == r.guest_rollback_index,
        "signed metadata differs"
    );
    let descriptors = metadata["descriptors"]
        .as_array()
        .context("descriptors absent")?;
    ensure!(
        descriptors.len() == 2
            && ["boot", "initrd_debug"].iter().all(|name| descriptors
                .iter()
                .any(|v| v["partition"] == *name && v["tag"] == 2)),
        "unexpected guest descriptors"
    );
    // The parser alone makes no signature claim. The standard verifier above
    // has now checked the configured key and both complete payload hashes.
    metadata["cryptographic_signature_verified"] = serde_json::json!(true);
    fs::rename(dir.join("boot.img"), dir.join("guest-kernel.img"))?;
    fs::remove_file(dir.join("initrd_debug.img"))?;
    for input in [&r.kernel, &r.initrd, &r.key.input] {
        ensure!(
            gb_core::hash_file(&input.path)? == input.sha256,
            "source changed during signing"
        );
    }
    ensure!(
        gb_core::hash_file(&tool)?
            == identity["binary_sha256"]
                .as_str()
                .context("tool identity absent")?,
        "host tool changed"
    );
    let report = serde_json::json!({"schema_version":1,"status":"development_guest_signed_runtime_unverified",
        "kernel_source_sha256":r.kernel.sha256,"initrd_source_sha256":r.initrd.sha256,
        "guest_kernel_sha256":gb_core::hash_file(&dir.join("guest-kernel.img"))?,"guest_public_key_sha256":r.key.public_key_sha256,
        "avb_metadata":metadata,"standard_signature_and_payload_verification_passed":true,
        "hypervisor_key_acceptance_verified":false,"guest_runtime_verified":false,"terminal_verified":false,
        "firmware_written":false,"device_rollback_state_modified":false,"tool":identity,"tool_results":results,
        "scope":"Raw Linux guest only. Not an Android boot partition image. No OEM signature or attestation claim."});
    gb_core::write_json(&dir.join("guest-signing-report.json"), &report)?;
    for name in [
        "guest-kernel.img",
        "initrd.img",
        "guest.avbpubkey",
        "guest-signing-report.json",
    ] {
        fs::File::open(dir.join(name))?.sync_all()?;
    }
    gb_core::publish_directory(dir, out)
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 2, "expected REQUEST_JSON NEW_OUTPUT");
    let r: Request = gb_core::read_json(Path::new(&a[0]), 1024 * 1024)?;
    prepare(&r, Path::new(&a[1]))?;
    println!(
        "Development guest signed and verified; hypervisor acceptance and Terminal remain unverified."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(dir: &Path) -> Request {
        let mut header = vec![0u8; 65536];
        header[56..60].copy_from_slice(b"ARM\x64");
        fs::write(dir.join("kernel"), header).unwrap();
        fs::write(
            dir.join("initrd"),
            [
                31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 75, 47, 77, 45, 46, 81, 72, 203, 172, 40, 41, 45,
                74, 229, 2, 0, 215, 232, 80, 37, 14, 0, 0, 0,
            ],
        )
        .unwrap();
        fs::write(
            dir.join("key"),
            b"not a key; no tool may run in guard tests",
        )
        .unwrap();
        let input = |name: &str| Input {
            path: dir.join(name),
            sha256: gb_core::hash_file(&dir.join(name)).unwrap(),
        };
        Request {
            schema_version: 1,
            kernel: input("kernel"),
            initrd: input("initrd"),
            key: Key {
                input: input("key"),
                algorithm: "SHA256_RSA4096".into(),
                public_key_sha256: "0".repeat(64),
            },
            tool: dir.join("nonexistent-host-tool"),
            sandbox: gb_tools::Sandbox::Bubblewrap,
            guest_rollback_index: 0,
        }
    }
    #[test]
    fn changed_input_wrong_format_and_unsigned_key_selection_fail_before_tools() {
        for kind in 0..4 {
            let d = tempfile::tempdir().unwrap();
            let mut r = fixture(d.path());
            let out = d.path().join("output");
            match kind {
                0 => {
                    fs::write(&r.kernel.path, b"changed").unwrap();
                }
                1 => {
                    fs::write(&r.kernel.path, vec![0; 65536]).unwrap();
                    r.kernel.sha256 = gb_core::hash_file(&r.kernel.path).unwrap();
                }
                2 => {
                    fs::write(&r.initrd.path, b"encrypted or unknown").unwrap();
                    r.initrd.sha256 = gb_core::hash_file(&r.initrd.path).unwrap();
                }
                _ => r.key.algorithm = "NONE".into(),
            }
            let error = format!("{:#}", prepare(&r, &out).unwrap_err());
            assert!(!error.contains("configured host tool unavailable"));
            assert!(!out.exists());
        }
    }
    #[test]
    #[ignore = "requires GB_TEST_AVBTOOL, GB_TEST_AVB_KEY, GB_TEST_SANDBOX_IMAGE (public AOSP RSA4096 test key)"]
    fn real_tool_signs_both_payloads_reproducibly_without_runtime_claim() {
        let d = tempfile::tempdir().unwrap();
        let mut r = fixture(d.path());
        r.tool = std::env::var_os("GB_TEST_AVBTOOL").unwrap().into();
        r.key.input.path = std::env::var_os("GB_TEST_AVB_KEY").unwrap().into();
        r.key.input.sha256 = gb_core::hash_file(&r.key.input.path).unwrap();
        r.key.public_key_sha256 =
            "7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6".into();
        r.sandbox = gb_tools::Sandbox::Docker {
            image: std::env::var("GB_TEST_SANDBOX_IMAGE").unwrap(),
        };
        let a = d.path().join("a");
        let b = d.path().join("b");
        prepare(&r, &a).unwrap();
        prepare(&r, &b).unwrap();
        assert_eq!(
            gb_core::hash_file(&a.join("guest-kernel.img")).unwrap(),
            gb_core::hash_file(&b.join("guest-kernel.img")).unwrap()
        );
        let report: serde_json::Value =
            gb_core::read_json(&a.join("guest-signing-report.json"), 1024 * 1024).unwrap();
        assert_eq!(
            report["standard_signature_and_payload_verification_passed"],
            true
        );
        assert_eq!(report["guest_runtime_verified"], false);
        assert_eq!(report["firmware_written"], false);
        assert!(!a.join("boot.img").exists());
        assert_eq!(
            gb_core::hash_file(&a.join("initrd.img")).unwrap(),
            r.initrd.sha256
        );
    }
}
