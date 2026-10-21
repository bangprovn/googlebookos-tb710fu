fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    anyhow::ensure!(
        args.len() == 3,
        "usage: guest_display_probe BUILD_REQUEST.json NEW_OUTPUT"
    );
    let request =
        gb_framework::functional_probe::BuildRequest::read(std::path::Path::new(&args[1]))?;
    let report = gb_framework::functional_probe::build_guest_display_probe(
        &request,
        std::path::Path::new(&args[2]),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
