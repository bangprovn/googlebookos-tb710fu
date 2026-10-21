//! Run the actual pinned kernel irqfd driver in a host resource/eventfd model.
//! KERNEL_TREE HOST_CLANG NEW_OUTPUT. Never contacts a device or runs firmware.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, time::Duration};

fn source(path: &Path, pin: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 128 * 1024,
        "regular source file no larger than 128 KiB required"
    );
    ensure!(gb_core::hash_file(path)? == pin, "source pin mismatch");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "expected KERNEL_TREE HOST_CLANG NEW_OUTPUT"
    );
    let kernel = Path::new(&args[0]);
    let output = Path::new(&args[2]);
    ensure!(!output.exists(), "output already exists");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inputs = [
        kernel.join("drivers/virt/gunyah/gunyah_irqfd.c"),
        kernel.join("include/uapi/linux/gunyah.h"),
        repo.join("tests/gunyah_irqfd.c"),
        repo.join("tests/gunyah_irqfd_mock.h"),
    ];
    source(
        &inputs[0],
        "653c61a77b01e11e4f818d01e8949e5b655b058a83904f4ba5da9ca9ed0d5cad",
    )?;
    source(
        &inputs[1],
        "920a78b98eb0d209d3974caf9edb459659520db31518cbb4594e967f46ebb7b5",
    )?;
    let hashes: Vec<_> = inputs
        .iter()
        .map(|p| gb_core::hash_file(p))
        .collect::<Result<_>>()?;
    for p in &inputs {
        gb_core::separate_from_input(p, output)?;
    }
    let compiler = gb_tools::host_tool(Path::new(&args[1]), &[])?;
    gb_core::separate_from_input(&compiler, output)?;
    let compiler_sha = gb_core::hash_file(&compiler)?;
    let version = gb_core::run_tool(&compiler, &["--version".into()], Duration::from_secs(5))?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let dir = staging.path().canonicalize()?;
    let names = ["source.c", "uapi.h", "test.c", "gunyah_irqfd_mock.h"];
    for ((p, name), hash) in inputs.iter().zip(names).zip(&hashes) {
        source(p, hash)?;
        let snapshot = dir.join(name);
        fs::copy(p, &snapshot)?;
        source(&snapshot, hash)?;
    }
    source(
        &dir.join("source.c"),
        "653c61a77b01e11e4f818d01e8949e5b655b058a83904f4ba5da9ca9ed0d5cad",
    )?;
    source(
        &dir.join("uapi.h"),
        "920a78b98eb0d209d3974caf9edb459659520db31518cbb4594e967f46ebb7b5",
    )?;
    for name in [
        "linux/eventfd.h",
        "linux/file.h",
        "linux/fs.h",
        "linux/gunyah.h",
        "linux/gunyah_vm_mgr.h",
        "linux/module.h",
        "linux/poll.h",
        "linux/printk.h",
        "linux/mutex.h",
        "uapi/linux/gunyah.h",
    ] {
        let p = dir.join("include").join(name);
        fs::create_dir_all(p.parent().context("include parent")?)?;
        fs::write(p, "/* Host resource/eventfd model supplies this API. */\n")?;
    }
    let dir_text = dir.to_str().context("staging path must be UTF8")?;
    let compile = gb_core::run_tool(
        &compiler,
        &[
            "-std=gnu11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-Wno-unused-parameter".into(),
            "-g".into(),
            "-fsanitize=address,undefined".into(),
            "-pthread".into(),
            format!("-I{dir_text}/include"),
            format!("-DGB_IRQFD_SOURCE=\"{dir_text}/source.c\""),
            format!("-DGB_GUNYAH_UAPI=\"{dir_text}/uapi.h\""),
            format!("{dir_text}/test.c"),
            "-o".into(),
            format!("{dir_text}/test"),
        ],
        Duration::from_secs(60),
    )?;
    let mut runs = Vec::new();
    for _ in 0..10 {
        runs.push(gb_core::run_tool(
            &dir.join("test"),
            &[],
            Duration::from_secs(30),
        )?);
    }
    for (p, hash) in inputs.iter().zip(&hashes) {
        ensure!(gb_core::hash_file(p)? == *hash, "input changed during test");
    }
    ensure!(
        gb_core::hash_file(&compiler)? == compiler_sha,
        "compiler changed"
    );
    gb_core::write_json(
        &dir.join("report.json"),
        &serde_json::json!({"schema_version":1,"status":"passed","source_hashes":hashes,"compiler_sha256":compiler_sha,"version":version,"compile":compile,"runs":runs,"firmware_written":false,"hardware_interrupt_delivery_verified":false,"scope":"actual kernel driver with host resource/eventfd model; not a hypervisor simulation"}),
    )?;
    gb_core::publish_directory(staging.path(), output)?;
    println!("Shared IRQ host tests passed; hardware delivery remains unverified.");
    Ok(())
}
