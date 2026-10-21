//! Pure source-bound native setup selection plan; no device actions.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::io::Read;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    owner: u32,
    focus: String,
    xml: String,
}
fn main() -> Result<()> {
    let mut input = Vec::new();
    std::io::stdin().take(100001).read_to_end(&mut input)?;
    ensure!(input.len() <= 100000, "setup snapshot JSON budget");
    let r: Input = serde_json::from_slice(&input)?;
    let plan = gb_tools::phone_link_setup::plan_get_started(&r.xml, &r.focus, r.owner)?;
    println!("{}", serde_json::to_string(&plan)?);
    Ok(())
}
