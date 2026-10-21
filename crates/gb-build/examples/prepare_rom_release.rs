//! REQUEST_JSON NEW_OUTPUT [PREVIOUS_ASSETS]: package pinned images; never flash.
use anyhow::{Result, ensure};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        (2..=3).contains(&args.len()),
        "expected REQUEST_JSON NEW_OUTPUT [PREVIOUS_ASSETS]"
    );
    let request = gb_build::rom_release::Request::read(Path::new(&args[0]))?;
    let report = if args.len() == 3 {
        gb_build::rom_release::prepare_incremental(
            &request,
            Path::new(&args[1]),
            Path::new(&args[2]),
        )?
    } else {
        gb_build::rom_release::prepare(&request, Path::new(&args[1]))?
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
