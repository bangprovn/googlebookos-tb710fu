//! REQUEST.json NEW_OUTPUT; stage relative ranges with a complete partition digest proof.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 2, "expected REQUEST.json NEW_OUTPUT");
    let r = gb_build::range_delta::Request::read(Path::new(&a[0]))?;
    let report = gb_build::range_delta::stage(&r, Path::new(&a[1]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
