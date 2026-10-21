//! Generates a bounded probe; never contacts Android or executes the command.
use anyhow::{Result, ensure};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: terminal_workload NONCE32 ANDROID_BOOT_UUID"
    );
    let plan = gb_tools::terminal_workload::prepare(&args[0], &args[1])?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}
