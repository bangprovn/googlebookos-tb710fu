//! Pure native tab-control guard; never issues ADB or device input.
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
    previous_xml: Option<String>,
}
fn main() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(5 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 5 * 1024 * 1024,
        "tab snapshot JSON exceeds budget"
    );
    let input: Input = serde_json::from_slice(&bytes)?;
    gb_tools::terminal_ui::verify_window_focus(&input.focus, input.owner)?;
    let snapshot = gb_tools::terminal_tabs::inspect(&input.xml)?;
    let mut report = serde_json::to_value(&snapshot)?;
    if let Some(previous) = input.previous_xml {
        let before = gb_tools::terminal_tabs::inspect(&previous)?;
        report["append_observation"] = serde_json::to_value(
            gb_tools::terminal_tabs::verify_append_transition(&before, &snapshot)?,
        )?;
    }
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
