//! Validate a compiled policy's file contexts and an init script with host tools.
//! POLICY CONTEXTS RC HOST_TOOLS_DIRECTORY IMMUTABLE_SANDBOX_ID NEW_OUTPUT
use anyhow::{Context, Result, ensure};
use std::{path::PathBuf, time::Duration};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 6,
        "expected POLICY CONTEXTS RC TOOLS IMAGE NEW_OUTPUT"
    );
    let files: Vec<_> = args[..3].iter().map(PathBuf::from).collect();
    let tools = PathBuf::from(&args[3]);
    let sandbox = gb_tools::Sandbox::Docker {
        image: args[4].to_str().context("image must be UTF8")?.into(),
    };
    let out = PathBuf::from(&args[5]);
    ensure!(!out.exists(), "output already exists");
    for file in &files {
        gb_core::separate_from_input(file, &out)?;
    }
    gb_core::separate_from_input(&tools, &out)?;
    sandbox.validate()?;
    std::fs::create_dir_all(&out)?;
    let input = tempfile::tempdir_in(&out)?;
    let mut checksums = Vec::new();
    for (file, name) in files
        .iter()
        .zip(["policy", "file_contexts", "gb-boot-logger.rc"])
    {
        ensure!(
            std::fs::symlink_metadata(file)?.is_file()
                && std::fs::metadata(file)?.len() <= 16 * 1024 * 1024,
            "bounded regular input required"
        );
        checksums.push(gb_core::hash_file(file)?);
        gb_core::copy_stream(
            std::fs::File::open(file)?,
            std::fs::File::create(input.path().join(name))?,
        )?;
    }
    let mut results = Vec::new();
    for (name, arguments) in [
        (
            "sefcontext_compile",
            vec![
                "-p",
                "/input.img/policy",
                "-o",
                "/output/file_contexts.bin",
                "/input.img/file_contexts",
            ],
        ),
        ("host_init_verifier", vec!["/input.img/gb-boot-logger.rc"]),
    ] {
        let tool = gb_tools::host_tool(&tools.join(name), &[input.path()])?;
        let identity = gb_tools::identity(&tool, &sandbox)?;
        let result = gb_tools::run(
            &sandbox,
            &tool,
            arguments.into_iter().map(str::to_owned).collect(),
            input.path(),
            &out,
            Duration::from_secs(60),
        )?;
        results.push(serde_json::json!({"tool":identity,"result":result}));
    }
    for (file, expected) in files.iter().zip(&checksums) {
        ensure!(
            &gb_core::hash_file(file)? == expected,
            "source changed during verification"
        );
    }
    gb_core::write_json(
        &out.join("verification.json"),
        &serde_json::json!({"schema_version":1,"status":"passed","source_checksums":checksums,"results":results,"scope":"file-context type validation and init syntax; runtime remains unverified"}),
    )?;
    Ok(())
}
