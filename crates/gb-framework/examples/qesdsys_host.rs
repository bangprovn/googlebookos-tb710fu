use anyhow::{Result, ensure};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: qesdsys_host REQUEST.json NEW_OUTPUT"
    );
    let request = gb_framework::service_host::Request::read(std::path::Path::new(&args[0]))?;
    let report = gb_framework::service_host::build(&request, std::path::Path::new(&args[1]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
