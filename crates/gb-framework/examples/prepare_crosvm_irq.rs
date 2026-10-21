//! Offline exact-build allocator adapter. DONOR_CROSVM NEW_OUTPUT.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 2, "expected DONOR_CROSVM NEW_OUTPUT");
    gb_framework::crosvm::prepare(Path::new(&a[0]), Path::new(&a[1]))?;
    println!("Prepared exact-build IRQ adapter; runtime validation required.");
    Ok(())
}
