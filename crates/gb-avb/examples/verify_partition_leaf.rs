//! PARTITION IMAGE AUTHORIZED_KEY_OR_DASH HOST_AVBTOOL DOCKER_IMAGE NEW_OUTPUT.
//! Verify one changed AVB leaf without rescanning unchanged parent-chain images.
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        a.len() == 6,
        "expected PARTITION IMAGE AUTHORIZED_KEY HOST_AVBTOOL DOCKER_IMAGE NEW_OUTPUT"
    );
    let partition = a[0].to_str().context("partition must be UTF8")?;
    ensure!(
        [
            "boot",
            "init_boot",
            "vendor_boot",
            "system",
            "system_ext",
            "product",
            "vendor",
            "odm"
        ]
        .contains(&partition),
        "unsupported leaf partition"
    );
    let name = format!("{partition}.img");
    let guest_image = format!("/inputs/{name}");
    let image = Path::new(&a[1]);
    let key = (a[2] != "-").then(|| Path::new(&a[2]));
    ensure!(
        key.is_some() || ["system", "system_ext", "product", "vendor", "odm"].contains(&partition),
        "boot-chain leaves require an authorized key"
    );
    let mut files = vec![image];
    files.extend(key);
    let output = PathBuf::from(&a[5]);
    ensure!(!output.exists(), "output exists");
    for input in &files {
        gb_core::separate_from_input(input, &output)?;
    }
    let sandbox = gb_tools::Sandbox::Docker {
        image: a[4].to_str().context("image must be UTF8")?.into(),
    };
    sandbox.validate()?;
    let tool = gb_tools::host_tool(Path::new(&a[3]), &files)?;
    gb_core::separate_from_input(&tool, &output)?;
    let hashes = files
        .iter()
        .map(|p| gb_core::hash_file(p))
        .collect::<Result<Vec<_>>>()?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let identity = gb_tools::identity(&tool, &sandbox)?;
    let mut arguments = vec!["verify_image".into(), "--image".into(), guest_image];
    let mut inputs = vec![gb_tools::ReadOnlyInput {
        name: &name,
        path: image,
    }];
    if let Some(key) = key {
        arguments.extend(["--key".into(), "/inputs/key.pem".into()]);
        inputs.push(gb_tools::ReadOnlyInput {
            name: "key.pem",
            path: key,
        });
    }
    let result = gb_tools::run_mounted(
        &sandbox,
        &tool,
        arguments,
        gb_tools::Inputs {
            primary: image,
            extra: &inputs,
            source_date_epoch: Some(0),
        },
        staging.path(),
        Duration::from_secs(120),
    )?;
    for (file, hash) in files.iter().zip(&hashes) {
        ensure!(
            gb_core::hash_file(file)? == *hash,
            "verification input changed"
        );
    }
    gb_core::write_json(
        &staging.path().join("verification.json"),
        &serde_json::json!({"schema_version":1,"status":"passed","scope":"one leaf payload/hash-tree verification; optional leaf key check; parent signature/chain and physical acceptance remain unverified","partition":partition,"authorized_leaf_key_checked":key.is_some(),"parent_chain_verified":false,"input_sha256":hashes,"tool":identity,"result":result,"firmware_written":false,"runtime_verified":false}),
    )?;
    gb_core::publish_directory(staging.path(), &output)?;
    println!("Leaf payload verified; parent signature/chain and runtime unverified.");
    Ok(())
}
