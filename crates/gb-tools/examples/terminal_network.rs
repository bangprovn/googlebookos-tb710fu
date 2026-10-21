use anyhow::{Result, ensure};
use std::io::Read;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 3 && args[0] == "prepare" {
        println!(
            "{}",
            serde_json::to_string_pretty(&gb_tools::terminal_network::prepare(
                &args[1], &args[2]
            )?)?
        );
    } else {
        ensure!(
            args == ["validate"],
            "usage: terminal_network prepare NONCE32 GUEST_UUID | validate < SCALARS.json"
        );
        let mut input = String::new();
        std::io::stdin().take(4097).read_to_string(&mut input)?;
        ensure!(input.len() <= 4096, "network observation exceeds budget");
        let observation: gb_tools::terminal_network::Observation = serde_json::from_str(&input)?;
        let passed = observation.validate()?;
        println!(
            "{}",
            serde_json::json!({"metadata":observation,"requested_semantics_match":passed,"external_capture_context_verified":false,"command_execution_verified":false,"full_port_verified":false})
        );
    }
    Ok(())
}
