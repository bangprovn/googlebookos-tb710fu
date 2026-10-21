#[path = "../src/serviceability_client.rs"]
mod serviceability_client;

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    anyhow::ensure!(
        args.len() == 3,
        "usage: serviceability_client REQUEST.json NEW_OUTPUT_DIRECTORY"
    );
    let request = serviceability_client::BuildRequest::read(std::path::Path::new(&args[1]))?;
    let report = serviceability_client::build(&request, std::path::Path::new(&args[2]))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
