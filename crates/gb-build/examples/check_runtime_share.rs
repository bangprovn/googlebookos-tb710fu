//! Execute the actual runtime-sharing adapter in a bounded host fault model.
//! KERNEL_TREE HOST_CLANG NEW_OUTPUT. No device or firmware operations.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, time::Duration};

fn regular(path: &Path) -> Result<String> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.len() <= 128 * 1024,
        "bounded regular input required"
    );
    gb_core::hash_file(path)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "expected KERNEL_TREE HOST_CLANG NEW_OUTPUT"
    );
    let source = Path::new(&args[0]).join("drivers/virt/gunyah");
    let output = Path::new(&args[2]);
    ensure!(!output.exists(), "output already exists");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inputs = [
        source.join("gb-runtime-share.c"),
        source.join("gb-runtime-share.h"),
        repo.join("tests/gunyah_runtime_share.c"),
        repo.join("tests/gunyah_runtime_share_mock.h"),
    ];
    for (input, name) in inputs
        .iter()
        .take(2)
        .zip(["gb-runtime-share.c", "gb-runtime-share.h"])
    {
        ensure!(
            regular(input)? == regular(&repo.join("patches/tb710fu/kernel").join(name))?,
            "kernel adapter differs from repository source"
        );
    }
    let hashes: Vec<_> = inputs.iter().map(|p| regular(p)).collect::<Result<_>>()?;
    let compiler = gb_tools::host_tool(Path::new(&args[1]), &[])?;
    for input in inputs.iter().chain(std::iter::once(&compiler)) {
        gb_core::separate_from_input(input, output)?;
    }
    let version = gb_core::run_tool(&compiler, &["--version".into()], Duration::from_secs(5))?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let dir = staging.path().canonicalize()?;
    let names = [
        "gb-runtime-share.c",
        "gb-runtime-share.h",
        "test.c",
        "gunyah_runtime_share_mock.h",
    ];
    for ((input, name), hash) in inputs.iter().zip(names).zip(&hashes) {
        fs::copy(input, dir.join(name))?;
        ensure!(
            regular(&dir.join(name))? == *hash,
            "snapshot checksum mismatch"
        );
    }
    for name in [
        "file.h",
        "compat.h",
        "fs.h",
        "gunyah_rsc_mgr.h",
        "mm.h",
        "module.h",
        "overflow.h",
        "sched/mm.h",
        "sizes.h",
        "slab.h",
        "uaccess.h",
        "vmalloc.h",
        "types.h",
    ] {
        let p = dir.join("include/linux").join(name);
        fs::create_dir_all(p.parent().context("header parent")?)?;
        fs::write(
            p,
            "/* Supplied by host fault model; not a layout check. */\n",
        )?;
    }
    fs::write(
        dir.join("include/linux/ioctl.h"),
        "#include <asm-generic/ioctl.h>\n",
    )?;
    for name in ["vm_mgr.h", "rsc_mgr.h"] {
        fs::write(
            dir.join(name),
            "/* Real types are checked by the separate kernel build. */\n",
        )?;
    }
    let dir_text = dir.to_str().context("UTF8 staging path required")?;
    let command = [
        "-std=gnu11",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-pthread",
        "-I",
        &format!("{dir_text}/include"),
        "-DGB_RUNTIME_SHARE_SOURCE=\"gb-runtime-share.c\"",
        &format!("{dir_text}/test.c"),
        "-o",
        &format!("{dir_text}/test"),
    ]
    .map(String::from);
    let compile = gb_core::run_tool(&compiler, &command, Duration::from_secs(30))?;
    let run = gb_core::run_tool(&dir.join("test"), &[], Duration::from_secs(20))?;
    for (input, hash) in inputs.iter().zip(&hashes) {
        ensure!(regular(input)? == *hash, "input changed while testing");
    }
    gb_core::write_json(
        &dir.join("verification.json"),
        &serde_json::json!({
            "schema_version":1, "status":"actual_source_host_fault_model_passed",
            "source_sha256":hashes, "compiler_sha256":gb_core::hash_file(&compiler)?,
            "compiler_version":version, "compile":compile, "run":run,
            "concurrent_share_reclaim_cycles":256, "sanitizers":["address","undefined"],
            "kernel_layout_verified_by_this_model":false, "firmware_reset_verified":false,
            "physical_runtime_verified":false, "terminal_working_verified":false,
            "device_contacted":false, "firmware_written":false
        }),
    )?;
    gb_core::publish_directory(&dir, output)?;
    println!("Runtime-share host fault model passed; hardware and Terminal remain unverified.");
    Ok(())
}
