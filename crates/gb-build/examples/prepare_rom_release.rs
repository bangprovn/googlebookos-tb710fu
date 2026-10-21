//! REQUEST_JSON NEW_OUTPUT: package pinned ROM images; never flash a device.
use anyhow::{Result, ensure};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 2, "expected REQUEST_JSON NEW_OUTPUT");
    let request = gb_build::rom_release::Request::read(Path::new(&args[0]))?;
    let report = gb_build::rom_release::prepare(&request, Path::new(&args[1]))?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
