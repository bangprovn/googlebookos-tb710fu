//! Explicit, sandboxed native RUNPATH transformation, with no device writes.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: patch_native_runpath PINNED_REQUEST.json NEW_OUTPUT"
    );
    let request: gb_firmware::runpath::Request =
        gb_core::read_json(Path::new(&args[0]), 1024 * 1024)?;
    gb_firmware::runpath::patch(&request, Path::new(&args[1]))?;
    Ok(())
}
