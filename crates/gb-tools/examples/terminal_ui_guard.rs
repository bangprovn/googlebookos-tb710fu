//! Read-only guard for ADB UI snapshots, supplied as JSON on stdin.
//! This does not issue input, unlock a device, or qualify hardware behavior.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    owner: u32,
    focus: String,
    xml: String,
    #[serde(default)]
    ime_shown: Option<bool>,
    #[serde(default)]
    tty_refreshed: bool,
}

fn main() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(3 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 3 * 1024 * 1024,
        "snapshot JSON exceeds budget"
    );
    let input: Input = serde_json::from_slice(&bytes)?;
    gb_tools::terminal_ui::verify_window_focus(&input.focus, input.owner)?;
    let snapshot = gb_tools::terminal_ui::inspect(&input.xml)?;
    let mut report = serde_json::to_value(&snapshot)?;
    if let Some(shown) = input.ime_shown {
        report["input_preparation"] =
            serde_json::to_value(gb_tools::terminal_ui::prepare_input_with_refresh(
                &snapshot,
                shown,
                input.tty_refreshed,
            )?)?;
    }
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
