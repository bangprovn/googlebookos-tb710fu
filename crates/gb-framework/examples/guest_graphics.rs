use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: guest_graphics PINNED_REQUEST.json NEW_OUTPUT_DIRECTORY"
    );
    let report = gb_framework::guest_graphics::render(
        &gb_framework::guest_graphics::Request::read(Path::new(&args[0]))?,
        Path::new(&args[1]),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
