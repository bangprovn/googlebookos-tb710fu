//! Read-only stock input preparation for a kernel compatibility check. Never flashes.
//! STOCK_SUPER SHA256 STOCK_BOOT SHA256 VENDOR_CPIO SHA256 HOST_DEBUGFS
//! HOST_E2FSCK HOST_EROFS HOST_CPIO DOCKER_IMAGE NEW_OUTPUT_DIRECTORY
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::Duration,
};

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        a.len() == 12,
        "expected SUPER SHA256 BOOT SHA256 CPIO SHA256 DEBUGFS E2FSCK EROFS CPIO_TOOL DOCKER_IMAGE NEW_OUTPUT"
    );
    let p = |i| Path::new(&a[i]);
    let output = p(11);
    ensure!(!output.exists(), "output already exists");
    let mut sources = Vec::new();
    for i in [0, 2, 4] {
        let meta = fs::symlink_metadata(p(i))?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "regular, non-symlink source required"
        );
        let sha = a[i + 1].to_str().context("SHA256 must be UTF8")?;
        ensure!(
            sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid SHA256"
        );
        gb_core::separate_from_input(p(i), output)?;
        ensure!(
            gb_core::hash_file(p(i))? == sha,
            "source checksum mismatch: {}",
            p(i).display()
        );
        sources.push((p(i), sha));
    }
    let sandbox = gb_tools::Sandbox::Docker {
        image: a[10].to_str().context("image must be UTF8")?.into(),
    };
    sandbox.validate()?;
    let tools = gb_firmware::filesystem::FilesystemTools {
        ext4: p(6).into(),
        checker: p(7).into(),
        erofs: p(8).into(),
        sandbox: sandbox.clone(),
    };
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let mut f = File::open(p(0))?;
    let layout = gb_partition::super_metadata(&mut f, 0)?;
    let mut partitions = Vec::new();
    for name in ["system_dlkm_a", "vendor_dlkm_a"] {
        let part = layout
            .partitions
            .iter()
            .find(|v| v.name == name)
            .context("stock module partition absent")?;
        ensure!(
            part.bytes > 0 && part.bytes < 1024 * 1024 * 1024,
            "module partition exceeds 1 GiB budget"
        );
        ensure!(
            fs2::available_space(staging.path())? > part.bytes * 4 + 256 * 1024 * 1024,
            "insufficient staging space"
        );
        let image = staging.path().join(format!("{name}.img"));
        let mut dst = File::create(&image)?;
        gb_partition::extract_logical(&mut f, 0, name, &mut dst)?;
        dst.sync_all()?;
        let tree = staging.path().join(name);
        fs::create_dir(&tree)?;
        let (format, _) = gb_firmware::filesystem::extract_tree(&image, &tree, &tools)?;
        partitions.push(serde_json::json!({"partition":name,"bytes":part.bytes,"sha256":gb_core::hash_file(&image)?,"format":format}));
    }
    let mut boot = File::open(p(2))?;
    let info = gb_partition::inspect(&mut boot, &gb_core::Format::Boot)?;
    ensure!(
        info["header_version"] == 4 && info["ramdisk_bytes"] == 0 && info["signature_bytes"] == 0,
        "requires kernel-only boot v4 without GKI signature"
    );
    let len = info["kernel_bytes"]
        .as_u64()
        .context("kernel size absent")?;
    ensure!(
        len > 0 && len < 64 * 1024 * 1024,
        "kernel exceeds 64 MiB budget"
    );
    boot.seek(SeekFrom::Start(4096))?;
    let kernel = staging.path().join("stock-kernel");
    let mut dst = File::create(&kernel)?;
    ensure!(
        gb_core::copy_stream(boot.take(len), &mut dst)? == len,
        "truncated kernel"
    );
    dst.sync_all()?;
    let ramdisk = staging.path().join("vendor-ramdisk");
    fs::create_dir(&ramdisk)?;
    let cpio = gb_tools::host_tool(p(9), &[p(0), p(2), p(4)])?;
    gb_tools::run(
        &sandbox,
        &cpio,
        [
            "--extract",
            "--make-directories",
            "--no-absolute-filenames",
            "--no-preserve-owner",
            "--directory=/output",
            "--file=/input.img",
            "*.ko",
        ]
        .map(String::from)
        .to_vec(),
        p(4),
        &ramdisk,
        Duration::from_secs(120),
    )?;
    for (path, sha) in &sources {
        ensure!(
            gb_core::hash_file(path)? == *sha,
            "source changed during preparation"
        );
    }
    gb_core::write_json(
        &staging.path().join("preparation.json"),
        &serde_json::json!({
            "schema_version":1,"status":"stock_kernel_validation_inputs_prepared",
            "source_sha256":sources.iter().map(|(_,s)| *s).collect::<Vec<_>>(),
            "partitions":partitions,"stock_kernel_sha256":gb_core::hash_file(&kernel)?,
            "stock_boot":info,"firmware_written":false,"runtime_verified":false,
            "limitations":["Extracted analysis trees are not repacking recipes; module KMI and certificate checks remain required"]
        }),
    )?;
    gb_core::publish_directory(staging.path(), output)?;
    println!("Stock kernel and module analysis inputs prepared; no device writes.");
    Ok(())
}
