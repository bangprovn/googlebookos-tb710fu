//! Render one evidence-backed allowlist delta; does not install or disable filters.
use anyhow::{Result, ensure};
use std::path::PathBuf;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(args.len() == 2, "expected REQUEST_JSON NEW_OUTPUT");
    let request = gb_core::read_json(&args[0], 65536)?;
    gb_framework::seccomp_compat::render(&request, &args[1])?;
    println!("Candidate policy generated; target Minijail runtime validation required.");
    Ok(())
}
