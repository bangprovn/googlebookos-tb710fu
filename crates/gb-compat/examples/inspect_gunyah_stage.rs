//! LOG SHA256 NEW_OUTPUT_DIRECTORY. Stage telemetry never establishes guest boot.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{io::Read, path::Path};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 3, "expected LOG SHA256 NEW_OUTPUT_DIRECTORY");
    let input = Path::new(&args[0]);
    let output = Path::new(&args[2]);
    let expected = args[1].to_str().context("checksum encoding")?;
    ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid checksum"
    );
    ensure!(
        std::fs::symlink_metadata(input)?.is_file(),
        "regular log input required"
    );
    ensure!(!output.exists(), "output exists");
    gb_core::separate_from_input(input, output)?;
    let mut bytes = Vec::new();
    std::fs::File::open(input)?
        .take(gb_compat::gunyah_memory::MAX_LOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= gb_compat::gunyah_memory::MAX_LOG_BYTES,
        "source log too large"
    );
    let actual = gb_core::digest(&bytes);
    ensure!(
        actual == expected.to_ascii_lowercase(),
        "source checksum mismatch"
    );
    let telemetry = gb_compat::gunyah_stage::inspect(std::str::from_utf8(&bytes)?)?;
    let count = telemetry.events.len();
    #[derive(Serialize)]
    struct Evidence {
        source_sha256: String,
        telemetry: gb_compat::gunyah_stage::Report,
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp = tempfile::tempdir_in(parent)?;
    gb_core::write_json(
        &temp.path().join("stage-report.json"),
        &Evidence {
            source_sha256: actual,
            telemetry,
        },
    )?;
    gb_core::publish_directory(temp.path(), output)?;
    println!(
        "Parsed {count} stage records; guest boot, Terminal and reset cause remain unverified."
    );
    Ok(())
}
