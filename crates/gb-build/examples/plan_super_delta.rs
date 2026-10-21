//! REQUEST PHYSICAL_SUPER_JSON NEW_OUTPUT_JSON; previews only, never flashes.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3,
        "expected REQUEST PHYSICAL_SUPER_JSON NEW_OUTPUT_JSON"
    );
    let out = Path::new(&args[2]);
    ensure!(!out.exists(), "output already exists");
    for input in &args[..2] {
        gb_core::separate_from_input(Path::new(input), out)?;
    }
    let request = gb_build::super_image::Request::read(Path::new(&args[0]))?;
    for input in std::iter::once(&request.base).chain(request.replacements.values()) {
        gb_core::separate_from_input(&input.path, out)?;
    }
    let physical: gb_build::delta::PhysicalSuper = gb_core::read_json(Path::new(&args[1]), 65536)?;
    let plan = gb_build::delta::plan(&request, &physical)?;
    gb_core::write_json(
        out,
        &serde_json::json!({"schema_version":1,"status":"dry_run_requires_device_verification_and_confirmation","source_super_sha256":request.base.sha256,"resulting_super_sha256":plan.resulting_super_sha256,"physical_super":physical,"writes":plan.writes,"layout_modified":false,"firmware_written":false,"runtime_verified":false}),
    )?;
    Ok(())
}
