use anyhow::{Result, ensure};
use gb_tools::guest_display;
use std::{
    io::{Read, Write},
    path::Path,
};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "bundle" {
        let path = Path::new(&args[1]);
        ensure!(
            std::fs::symlink_metadata(path)?.is_file(),
            "regular context required"
        );
        let mut text = String::new();
        std::fs::File::open(path)?
            .take(8193)
            .read_to_string(&mut text)?;
        ensure!(text.len() <= 8192, "context budget");
        let result = guest_display::bundle(&serde_json::from_str(&text)?)?;
        let destination = Path::new(&args[2]);
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut f = tempfile::NamedTempFile::new_in(parent)?;
        f.write_all(result.as_bytes())?;
        f.as_file().sync_all()?;
        f.persist_noclobber(destination)?;
        std::fs::File::open(parent)?.sync_all()?;
    } else if args == ["prepare"] {
        let mut text = String::new();
        std::io::stdin().take(8193).read_to_string(&mut text)?;
        ensure!(text.len() <= 8192, "request budget");
        let request = serde_json::from_str(&text)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&gb_tools::guest_handoff::prepare(&request)?)?
        );
    } else if args.len() == 2 && args[0] == "relay-source" {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&args[1])?;
        file.write_all(guest_display::RELAY.as_bytes())?;
        file.sync_all()?;
    } else {
        anyhow::bail!(
            "usage: guest_display bundle CONTEXT.json NEW_AGENT.py | prepare < REQUEST.json | relay-source NEW_RELAY.py"
        );
    }
    Ok(())
}
