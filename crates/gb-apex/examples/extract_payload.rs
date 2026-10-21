//! Read-only, checksum-pinned APEX/cAPEX payload extraction.
//! CONTAINER SHA256 NEW_OUTPUT. No image or extracted program is executed.
use anyhow::{Result, ensure};
use std::{fs, path::Path};

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 3, "expected CONTAINER SHA256 NEW_OUTPUT");
    let input = Path::new(&a[0]);
    let sha = a[1].to_str().unwrap_or("");
    let out = Path::new(&a[2]);
    ensure!(
        sha.len() == 64 && sha.bytes().all(|v| v.is_ascii_hexdigit()),
        "SHA256 pin required"
    );
    ensure!(!out.exists(), "output exists");
    gb_core::separate_from_input(input, out)?;
    let m = fs::symlink_metadata(input)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink() && m.len() <= 16 * 1024 * 1024 * 1024,
        "regular bounded APEX input required"
    );
    ensure!(gb_core::hash_file(input)? == sha, "container pin mismatch");
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let decoded = gb_apex::extract(
        &mut fs::File::open(input)?,
        "input.apex",
        sha,
        staging.path(),
    )?;
    let payload = staging.path().join("apex_payload.img");
    fs::copy(decoded.payload.path(), &payload)?;
    ensure!(
        gb_core::hash_file(&payload)? == decoded.package.payload_sha256,
        "payload snapshot differs"
    );
    fs::File::open(&payload)?.sync_all()?;
    gb_core::write_json(
        &staging.path().join("extraction-report.json"),
        &serde_json::json!({"schema_version":1,"status":"extracted_for_analysis","source_sha256":sha,"package":decoded.package,"avb_metadata":decoded.avb_metadata,"read_only":true,"metadata_complete_for_repacking":false,"signatures_verified":false,"firmware_written":false}),
    )?;
    drop(decoded);
    ensure!(gb_core::hash_file(input)? == sha, "container changed");
    gb_core::publish_directory(staging.path(), out)?;
    println!("APEX payload extracted; signatures remain unverified.");
    Ok(())
}
