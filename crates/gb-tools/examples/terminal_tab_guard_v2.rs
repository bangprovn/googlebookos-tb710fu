//! Mode-aware read-only guard; never issues device input.
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
    #[serde(default)]
    previous_selected_xml: Option<String>,
    #[serde(default)]
    previous_selected_decorated_xml: Option<String>,
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
    ensure!(
        usize::from(input.previous_xml.is_some())
            + usize::from(input.previous_selected_xml.is_some())
            + usize::from(input.previous_selected_decorated_xml.is_some())
            <= 1,
        "append policies are mutually exclusive"
    );
    gb_tools::terminal_ui::verify_window_focus(&input.focus, input.owner)?;
    let snapshot = gb_tools::terminal_tabs::inspect_mode_aware(&input.xml)?;
    let mut report = serde_json::to_value(&snapshot)?;
    if let Some(previous) = input.previous_xml {
        let before = gb_tools::terminal_tabs::inspect(&previous)?;
        report["retained_append_observation"] = serde_json::to_value(
            gb_tools::terminal_tabs::verify_retained_append(&before, &snapshot)?,
        )?;
        if snapshot.display_enabled {
            report["select_retained_last"] = serde_json::to_value(
                gb_tools::terminal_tabs::select_retained_last(&before, &snapshot)?,
            )?;
        }
    }
    if let Some(previous) = input.previous_selected_xml {
        let before = gb_tools::terminal_tabs::inspect(&previous)?;
        let after = gb_tools::terminal_tabs::inspect(&input.xml)?;
        report["selected_append_observation"] = serde_json::to_value(
            gb_tools::terminal_tabs::verify_selected_append(&before, &after)?,
        )?;
    }
    if let Some(previous) = input.previous_selected_decorated_xml {
        report["selected_append_observation"] = serde_json::to_value(
            gb_tools::terminal_tabs::verify_selected_decorated_append(&previous, &input.xml)?,
        )?;
    }
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
