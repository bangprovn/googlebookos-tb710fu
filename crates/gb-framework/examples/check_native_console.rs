//! MEMORY_MIB CONSOLE CLIENT; bounded diagnostic fixture verification only.
use anyhow::{Context, Result, ensure};
use std::{io::Read, path::Path};
fn text(path: &Path) -> Result<String> {
    ensure!(
        std::fs::symlink_metadata(path)?.is_file(),
        "regular log required"
    );
    let mut s = String::new();
    std::fs::File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut s)?;
    ensure!(s.len() <= 4 * 1024 * 1024, "log exceeds bound");
    Ok(s)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 3, "expected MEMORY_MIB CONSOLE CLIENT");
    let memory = args[0].to_str().context("memory must be UTF8")?.parse()?;
    let r = gb_framework::terminal_console::inspect_native_console(
        &text(Path::new(&args[1]))?,
        &text(Path::new(&args[2]))?,
        memory,
    )?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    ensure!(
        r.guest_commands_verified && r.normal_shutdown_verified,
        "guest execution/shutdown not verified"
    );
    Ok(())
}
