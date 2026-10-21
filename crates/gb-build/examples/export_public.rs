//! Explicit curated export only. REQUEST_JSON NEW_OUTPUT_DIRECTORY.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "expected REQUEST_JSON NEW_OUTPUT_DIRECTORY"
    );
    let request: gb_build::public_export::Request = gb_core::read_json(Path::new(&args[0]), 65536)
        .map_err(|_| anyhow::anyhow!("public export request is invalid"))?;
    let manifest = gb_build::public_export::export(&request, Path::new(&args[1]))?;
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}
