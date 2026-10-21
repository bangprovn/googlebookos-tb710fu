//! Read only LP metadata; full content verification remains the builder's job.
use anyhow::{Result, ensure};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "expected SUPER_IMAGE SLOT");
    let mut file = std::fs::File::open(&args[0])?;
    let layout = gb_partition::super_metadata(&mut file, args[1].parse()?)?;
    println!("{}", serde_json::to_string_pretty(&layout)?);
    Ok(())
}
