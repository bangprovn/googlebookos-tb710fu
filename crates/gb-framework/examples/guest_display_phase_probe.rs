use anyhow::{Result, ensure};
use std::{io::Read, path::Path};
fn small(path: &Path, max: u64) -> Result<String> {
    let mut s = String::new();
    gb_core::open_regular_file(path, std::fs::OpenOptions::new().read(true))?
        .take(max + 1)
        .read_to_string(&mut s)?;
    ensure!(s.len() as u64 <= max, "input budget");
    Ok(s)
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        a.len() >= 3,
        "usage: guest_display_phase_probe build REQUEST NEW_OUTPUT | inspect CONTEXT RECEIPT NEW_REPORT"
    );
    if a[0] == "build" {
        ensure!(a.len() == 3, "build arguments");
        let r = gb_framework::functional_probe::BuildRequest::read(Path::new(&a[1]))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&gb_framework::guest_display_phase::build(
                &r,
                Path::new(&a[2])
            )?)?
        );
    } else {
        ensure!(a[0] == "inspect" && a.len() == 4, "inspect arguments");
        let output = Path::new(&a[3]);
        ensure!(!output.exists(), "output exists");
        for p in [&a[1], &a[2]] {
            gb_core::separate_from_input(Path::new(p), output)?;
        }
        let expected: gb_framework::guest_display_phase::ExpectedContext =
            serde_json::from_str(&small(Path::new(&a[1]), 4096)?)?;
        let observed = gb_framework::guest_display_phase::inspect_capture(
            &small(Path::new(&a[2]), 8192)?,
            &expected,
        )?;
        gb_core::write_json(
            output,
            &serde_json::json!({"schema_version":1,"status":"owned_phase_capture_metadata_validated","observation":observed,"physical_panel_verified":false,"full_port_verified":false,"external_native_lifetimes_independently_verified":false}),
        )?;
    }
    Ok(())
}
