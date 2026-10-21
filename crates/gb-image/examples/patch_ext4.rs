//! REQUEST.json NEW_OUTPUT; creates an unsigned ext4 candidate offline.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 2, "expected REQUEST.json NEW_OUTPUT");
    let r = gb_image::ext4_patch::Request::read(Path::new(&a[0]))?;
    let report = gb_image::ext4_patch::build(&r, Path::new(&a[1]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
