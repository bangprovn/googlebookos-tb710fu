//! Verify vbmeta_system against its actual three logical images and retained pvmfw.
//! NEW_SIGNED_DIR RETAINED_SIGNED_DIR PVMFW KEY HOST_AVBTOOL IMAGE_ID NEW_OUTPUT
use anyhow::{Context, Result, ensure};
use std::{path::PathBuf, time::Duration};
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        a.len() == 7,
        "expected NEW_SIGNED RETAINED_SIGNED PVMFW KEY AVBTOOL IMAGE NEW_OUTPUT"
    );
    let new = PathBuf::from(&a[0]);
    let retained = PathBuf::from(&a[1]);
    let pvmfw = PathBuf::from(&a[2]);
    let key = PathBuf::from(&a[3]);
    let tool = PathBuf::from(&a[4]);
    let out = PathBuf::from(&a[6]);
    let sandbox = gb_tools::Sandbox::Docker {
        image: a[5].to_str().context("image must be UTF8")?.into(),
    };
    ensure!(!out.exists(), "output already exists");
    // A candidate may replace any subset of these userspace images.
    // The retained directory must contain the actual current versions of the rest.
    let payload = |name: &str| {
        let path = new.join(name);
        if path.is_file() {
            path
        } else {
            retained.join(name)
        }
    };
    let files = [
        new.join("vbmeta_system.img"),
        payload("system_ext.img"),
        payload("system.img"),
        payload("product.img"),
        pvmfw,
        key,
    ];
    for f in &files {
        gb_core::separate_from_input(f, &out)?;
    }
    let paths: Vec<_> = files.iter().map(|p| p.as_path()).collect();
    let tool = gb_tools::host_tool(&tool, &paths)?;
    gb_core::separate_from_input(&tool, &out)?;
    sandbox.validate()?;
    let mut digests = Vec::new();
    for f in &files {
        digests.push(gb_core::hash_file(f)?);
    }
    std::fs::create_dir_all(&out)?;
    let extra: Vec<_> = files
        .iter()
        .zip([
            "vbmeta_system.img",
            "system_ext.img",
            "system.img",
            "product.img",
            "pvmfw.img",
            "key.pem",
        ])
        .map(|(path, name)| gb_tools::ReadOnlyInput { name, path })
        .collect();
    let identity = gb_tools::identity(&tool, &sandbox)?;
    let result = gb_tools::run_mounted(
        &sandbox,
        &tool,
        vec![
            "verify_image".into(),
            "--image".into(),
            "/inputs/vbmeta_system.img".into(),
            "--key".into(),
            "/inputs/key.pem".into(),
        ],
        gb_tools::Inputs {
            primary: &files[0],
            extra: &extra,
            source_date_epoch: Some(0),
        },
        &out,
        Duration::from_secs(300),
    )?;
    for (f, h) in files.iter().zip(&digests) {
        ensure!(
            &gb_core::hash_file(f)? == h,
            "input changed during verification"
        );
    }
    gb_core::write_json(
        &out.join("verification.json"),
        &serde_json::json!({"schema_version":1,"status":"passed","scope":"standard parent signature, actual system/product/system_ext hashtrees and retained pvmfw hash verification; runtime unverified","input_sha256":digests,"tool":identity,"result":result}),
    )?;
    Ok(())
}
