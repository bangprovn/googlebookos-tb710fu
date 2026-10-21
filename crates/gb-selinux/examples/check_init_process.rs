//! REQUEST.json NEW_OUTPUT; validates explicit process contexts offline.
use anyhow::{Context, Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 2, "expected REQUEST.json NEW_OUTPUT");
    let request = gb_selinux::init_process::Request::read(Path::new(&args[0]))?;
    let report = gb_selinux::init_process::check(&request, Path::new(&args[1]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("serialize init process report")?
    );
    if !report.all_explicit_contexts_valid {
        std::process::exit(2);
    }
    Ok(())
}
