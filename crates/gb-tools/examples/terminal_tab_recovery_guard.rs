//! Return-only clipped desktop recovery; no device actions or input authorization.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::io::Read;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    owner: u32,
    focus: String,
    previous_tty_xml: String,
    current_desktop_xml: String,
}
fn main() -> Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(5 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 5 * 1024 * 1024,
        "recovery JSON exceeds budget"
    );
    let input: Input = serde_json::from_slice(&bytes)?;
    gb_tools::terminal_ui::verify_window_focus(&input.focus, input.owner)?;
    let observation = gb_tools::terminal_tabs::select_clipped_desktop_last(
        &input.previous_tty_xml,
        &input.current_desktop_xml,
    )?;
    println!("{}", serde_json::to_string(&observation)?);
    Ok(())
}
