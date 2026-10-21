use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: android_functional_probe build|run REQUEST.json NEW_OUTPUT"
    );
    let mode = args[0].to_str().unwrap_or("");
    let report = match mode {
        "build" => gb_framework::functional_probe::build(
            &gb_framework::functional_probe::BuildRequest::read(Path::new(&args[1]))?,
            Path::new(&args[2]),
        )?,
        "run" => gb_framework::functional_probe::run(
            &gb_framework::functional_probe::RunRequest::read(Path::new(&args[1]))?,
            Path::new(&args[2]),
        )?,
        _ => anyhow::bail!("expected build or run"),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if mode == "run" && report["status"] != "bounded_operations_passed" {
        std::process::exit(2);
    }
    Ok(())
}
