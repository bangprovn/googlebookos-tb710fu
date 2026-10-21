use anyhow::{Result, ensure};
use gb_framework::terminal_soak::{Request, inspect_to};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: terminal_soak PINNED_REQUEST.json NEW_REPORT.json"
    );
    let report = inspect_to(&Request::read(Path::new(&args[0]))?, Path::new(&args[1]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
