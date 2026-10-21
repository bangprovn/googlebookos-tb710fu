//! BOOT_IMAGE AUTHORIZED_KEY HOST_AVBTOOL DOCKER_IMAGE NEW_OUTPUT.
//! Standard signed leaf and complete boot payload verification; no device writes.
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        a.len() == 5,
        "expected BOOT_IMAGE AUTHORIZED_KEY HOST_AVBTOOL DOCKER_IMAGE NEW_OUTPUT"
    );
    let boot = Path::new(&a[0]);
    let key = Path::new(&a[1]);
    let output = PathBuf::from(&a[4]);
    ensure!(!output.exists(), "output exists");
    for input in [boot, key] {
        gb_core::separate_from_input(input, &output)?;
    }
    let sandbox = gb_tools::Sandbox::Docker {
        image: a[3].to_str().context("image must be UTF8")?.into(),
    };
    sandbox.validate()?;
    let tool = gb_tools::host_tool(Path::new(&a[2]), &[boot, key])?;
    gb_core::separate_from_input(&tool, &output)?;
    let hashes = [gb_core::hash_file(boot)?, gb_core::hash_file(key)?];
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let identity = gb_tools::identity(&tool, &sandbox)?;
    let result = gb_tools::run_mounted(
        &sandbox,
        &tool,
        [
            "verify_image",
            "--image",
            "/inputs/boot.img",
            "--key",
            "/inputs/key.pem",
        ]
        .map(String::from)
        .to_vec(),
        gb_tools::Inputs {
            primary: boot,
            extra: &[
                gb_tools::ReadOnlyInput {
                    name: "boot.img",
                    path: boot,
                },
                gb_tools::ReadOnlyInput {
                    name: "key.pem",
                    path: key,
                },
            ],
            source_date_epoch: Some(0),
        },
        staging.path(),
        Duration::from_secs(120),
    )?;
    ensure!(
        gb_core::hash_file(boot)? == hashes[0] && gb_core::hash_file(key)? == hashes[1],
        "verification input changed"
    );
    gb_core::write_json(
        &staging.path().join("verification.json"),
        &serde_json::json!({"schema_version":1,"status":"passed","scope":"standard AVB signed boot footer and full boot payload hash verification","input_sha256":hashes,"tool":identity,"result":result,"firmware_written":false,"runtime_verified":false}),
    )?;
    gb_core::publish_directory(staging.path(), &output)?;
    println!("Boot signature and payload verified; runtime unverified.");
    Ok(())
}
