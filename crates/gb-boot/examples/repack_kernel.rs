//! REQUEST_TOML NEW_OUTPUT_DIRECTORY. Host-only unsigned boot preparation.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 2, "expected REQUEST_TOML NEW_OUTPUT_DIRECTORY");
    let request = gb_boot::kernel::Request::read(Path::new(&a[0]))?;
    let output = Path::new(&a[1]);
    ensure!(!output.exists(), "output exists");
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let report = gb_boot::kernel::build(&request, staging.path())?;
    gb_core::publish_directory(staging.path(), output)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
