use anyhow::{Result, ensure};
use std::{io::Read, path::Path};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 4 && args[0] == "bundle" {
        ensure!(
            std::fs::symlink_metadata(&args[1])?.is_file(),
            "regular fixture required"
        );
        let mut f = String::new();
        std::fs::File::open(&args[1])?
            .take(24577)
            .read_to_string(&mut f)?;
        ensure!(f.len() <= 24576, "fixture exceeds budget");
        let body = gb_tools::guest_handoff::graphics_bundle(&f, &args[2])?;
        ensure!(!Path::new(&args[3]).exists(), "fresh output required");
        use std::io::Write;
        let destination = Path::new(&args[3]);
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut out = tempfile::NamedTempFile::new_in(parent)?;
        out.write_all(body.as_bytes())?;
        out.as_file().sync_all()?;
        out.persist_noclobber(destination)?;
        std::fs::File::open(parent)?.sync_all()?;
    } else {
        ensure!(
            args == ["prepare"],
            "usage: guest_handoff bundle FIXTURE GUEST_UUID NEW_OUTPUT | prepare < REQUEST.json"
        );
        let mut text = String::new();
        std::io::stdin().take(8193).read_to_string(&mut text)?;
        ensure!(text.len() <= 8192, "request budget");
        let r = serde_json::from_str(&text)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&gb_tools::guest_handoff::prepare(&r)?)?
        );
    }
    Ok(())
}
