use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: android_hardware_probe build|build-ui-observer|run|inspect-guest-capture|inspect-ui-observer INPUT.json NEW_OUTPUT"
    );
    let mode = args[0].to_str().unwrap_or("");
    let report = match mode {
        "build" => gb_framework::hardware_probe::build(
            &gb_framework::hardware_probe::BuildRequest::read(Path::new(&args[1]))?,
            Path::new(&args[2]),
        )?,
        "build-ui-observer" => gb_framework::hardware_probe::build_ui_observer(
            &gb_framework::hardware_probe::BuildRequest::read(Path::new(&args[1]))?,
            Path::new(&args[2]),
        )?,
        "run" => gb_framework::hardware_probe::run(
            &gb_framework::hardware_probe::RunRequest::read(Path::new(&args[1]))?,
            Path::new(&args[2]),
        )?,
        "inspect-guest-capture" => {
            let input = Path::new(&args[1]);
            let output = Path::new(&args[2]);
            ensure!(!output.exists(), "output already exists");
            gb_core::separate_from_input(input, output)?;
            let value: serde_json::Value = gb_core::read_json(input, 4096)?;
            let observed = gb_framework::hardware_probe::inspect_guest_capture(&value.to_string())?;
            let report = serde_json::json!({"schema_version":1,"status":"capture_metadata_validated",
                "observed_state":observed["state"],"receipt":observed,"external_execution_identity_verified":false,
                "external_playback_verified":false,"full_port_verified":false,"firmware_written":false});
            gb_core::write_json(output, &report)?;
            report
        }
        "inspect-ui-observer" => {
            let input = Path::new(&args[1]);
            let output = Path::new(&args[2]);
            ensure!(!output.exists(), "output already exists");
            gb_core::separate_from_input(input, output)?;
            // Read bounded UTF-8 directly: converting through Value would hide
            // duplicate keys before the strict typed parser can reject them.
            use std::io::Read;
            let mut text = String::new();
            gb_core::open_regular_file(input, std::fs::OpenOptions::new().read(true))?
                .take(65537)
                .read_to_string(&mut text)?;
            let observed = gb_framework::hardware_probe::inspect_ui_observer(&text)?;
            let report = serde_json::json!({"schema_version":1,"status":"ui_observer_metadata_validated",
                "receipt":observed,"external_execution_identity_verified":false,
                "command_execution_verified":false,"output_proof_claimed":false,
                "framework_cleanup_verified":false,"full_port_verified":false,"firmware_written":false});
            gb_core::write_json(output, &report)?;
            report
        }
        _ => anyhow::bail!(
            "expected build, build-ui-observer, run, inspect-guest-capture or inspect-ui-observer"
        ),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if mode == "run"
        && !matches!(
            report["status"].as_str(),
            Some("requested_operation_smoke_passed" | "requested_inventory_observed")
        )
    {
        std::process::exit(2);
    }
    if mode == "inspect-guest-capture" && report["observed_state"] != "compatible" {
        std::process::exit(2);
    }
    Ok(())
}
