//! INPUT_LOG NEW_OUTPUT_JSON; read-only, bounded host-tool diagnostics.
use anyhow::{Result, ensure};
use std::{fs::File, io::Write, path::Path};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2, "expected INPUT_LOG NEW_OUTPUT_JSON");
    let input = Path::new(&args[0]);
    let output = Path::new(&args[1]);
    ensure!(!output.exists(), "output already exists");
    gb_core::separate_from_input(input, output)?;
    let excerpt = gb_core::tool_log::capture(input, gb_core::tool_log::MAX_RETAINED_BYTES)?;
    let source_bytes = excerpt.source_bytes;
    let retained = excerpt.retained_source_bytes;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(
        &mut temporary,
        &serde_json::json!({"schema_version":1,"scope":"bounded diagnostic excerpt; omitted content is not validated","excerpt":excerpt}),
    )?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    println!("Retained {retained} of {source_bytes} source bytes");
    Ok(())
}
