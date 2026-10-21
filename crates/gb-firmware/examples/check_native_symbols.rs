//! Offline symbol/version preflight; never executes the supplied native objects.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() >= 2,
        "usage: check_native_symbols NEW_REPORT.json ELF..."
    );
    let output = Path::new(&arguments[0]);
    ensure!(!output.exists(), "report destination exists");
    let mut objects = Vec::new();
    for path in &arguments[1..] {
        gb_core::separate_from_input(Path::new(path), output)?;
        objects.push(gb_firmware::abi::inspect(Path::new(path))?);
    }
    let report = gb_firmware::abi::evaluate(objects)?;
    gb_core::write_json(output, &report)?;
    ensure!(
        report.static_symbols_resolved,
        "native dependency or versioned symbol requirements unresolved; see report"
    );
    Ok(())
}
