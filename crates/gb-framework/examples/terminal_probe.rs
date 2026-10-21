//! build REQUEST_JSON NEW_OUTPUT; send REQUEST_JSON HOST_FORWARD_PORT ID PAYLOAD.
use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        a.len() >= 3,
        "expected build REQUEST NEW_OUTPUT or send REQUEST HOST_PORT ID PAYLOAD"
    );
    let r = gb_framework::terminal_probe::Request::read(Path::new(&a[1]))?;
    match a[0].as_str() {
        "build" => {
            ensure!(a.len() == 3, "unexpected arguments");
            gb_framework::terminal_probe::build(&r, Path::new(&a[2]))?;
            println!("Owner development APK built; not installed or runtime verified.");
        }
        "send" => {
            ensure!(a.len() == 5, "expected request, port, ID, payload");
            ensure!(
                r.manifest.action == gb_framework::terminal_probe::ProbeAction::StageGuest,
                "runtime inspection does not open a payload receiver"
            );
            let item = r
                .manifest
                .payloads
                .get(&a[3])
                .ok_or_else(|| anyhow::anyhow!("unknown payload"))?;
            println!(
                "{}",
                gb_framework::terminal_probe::send_payload(
                    a[2].parse()?,
                    &a[3],
                    Path::new(&a[4]),
                    item
                )?
            );
        }
        _ => anyhow::bail!("unknown operation"),
    }
    Ok(())
}
