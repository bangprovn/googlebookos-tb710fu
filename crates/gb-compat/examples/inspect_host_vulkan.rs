use anyhow::{Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let report = if args.len() == 3 && args[0] == "--from-json" {
        gb_compat::host_vulkan::inspect_file(Path::new(&args[1]), Path::new(&args[2]))?
    } else {
        ensure!(
            args.len() == 2,
            "usage: inspect_host_vulkan PINNED_ADB_REQUEST.json NEW_REPORT.json\n       inspect_host_vulkan --from-json INPUT.json NEW_REPORT.json"
        );
        let request = gb_compat::host_vulkan::CaptureRequest::read(Path::new(&args[0]))?;
        gb_compat::host_vulkan::capture(&request, Path::new(&args[1]))?
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report["observed"]["state"] != "compatible" {
        std::process::exit(2);
    }
    Ok(())
}
