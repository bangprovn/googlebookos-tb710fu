//! LOG SHA256 NEW_OUTPUT_DIRECTORY. Parsed counters alone never imply VM success.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{io::Read, path::Path};
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 3, "expected LOG SHA256 NEW_OUTPUT_DIRECTORY");
    let input = Path::new(&a[0]);
    let output = Path::new(&a[2]);
    let expected = a[1].to_str().context("checksum encoding")?;
    ensure!(
        expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid source checksum"
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
        actual == expected.to_lowercase(),
        "source checksum mismatch"
    );
    let report = gb_compat::gunyah_memory::inspect(
        std::str::from_utf8(&bytes).context("kernel log must be UTF8 text")?,
    )?;
    let allocation_count = report.allocations.len();
    let failure_count = report.start_failures.len();
    #[derive(Serialize)]
    struct Evidence {
        source_sha256: String,
        telemetry: gb_compat::gunyah_memory::Report,
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp = tempfile::tempdir_in(parent)?;
    gb_core::write_json(
        &temp.path().join("memory-report.json"),
        &Evidence {
            source_sha256: actual,
            telemetry: report,
        },
    )?;
    gb_core::publish_directory(temp.path(), output)?;
    println!(
        "Parsed {allocation_count} allocation records and {failure_count} start failures; guest boot and compatibility remain unverified."
    );
    Ok(())
}
