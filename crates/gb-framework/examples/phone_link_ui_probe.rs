use anyhow::{Result, ensure};
use std::{io::Read, path::Path};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: phone_link_ui_probe build|inspect INPUT.json NEW_OUTPUT"
    );
    let input = Path::new(&args[1]);
    let output = Path::new(&args[2]);
    let report = match args[0].to_str().unwrap_or("") {
        "build" => gb_framework::phone_link_ui_probe::build(
            &gb_framework::hardware_probe::BuildRequest::read(input)?,
            output,
        )?,
        "inspect" => {
            ensure!(!output.exists(), "output exists");
            gb_core::separate_from_input(input, output)?;
            let mut text = String::new();
            gb_core::open_regular_file(input, std::fs::OpenOptions::new().read(true))?
                .take(65537)
                .read_to_string(&mut text)?;
            let r = gb_framework::phone_link_ui_probe::inspect_phone_link_ui(&text)?;
            let report = serde_json::json!({"schema_version":1,"status":"phone_link_ui_schema_validated",
                "receipt":r,"external_target_identity_verified":false,"functional_phone_link_verified":false,
                "framework_cleanup_verified":false,"firmware_written":false});
            gb_core::write_json(output, &report)?;
            report
        }
        _ => anyhow::bail!("expected build or inspect"),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
