//! REQUEST.toml NEW_OUTPUT; creates donor userspace only, never a device build.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 2, "expected REQUEST.toml NEW_OUTPUT");
    let request = gb_firmware::ota_reconstruct::Request::read(Path::new(&args[0]))?;
    let report = gb_firmware::ota_reconstruct::reconstruct(&request, Path::new(&args[1]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
