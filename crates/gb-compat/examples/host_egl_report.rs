//! Read-only normalization of host image witnesses, without device access.
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        (1..=5).contains(&args.len()),
        "usage: host_egl_report CAPABILITIES.json [AHB_RECEIPT.json ...] (at most four AHB witnesses)"
    );
    let sampling: Vec<PathBuf> = args[1..].iter().map(PathBuf::from).collect();
    let report = gb_compat::host_egl::inspect_files(Path::new(&args[0]), &sampling)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
