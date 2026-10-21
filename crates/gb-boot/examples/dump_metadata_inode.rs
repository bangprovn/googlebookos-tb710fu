//! Read-only F2FS inode inspection using a separately verified host package.
//! Usage: cargo run -p gb-boot --example dump_metadata_inode -- IMAGE TOOL IMAGE_ID INODE OUTPUT
use anyhow::{Context, Result, ensure};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, time::Duration};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 5, "expected IMAGE TOOL IMAGE_ID INODE OUTPUT");
    let input = PathBuf::from(&args[0]);
    let tool = PathBuf::from(&args[1]);
    let image = args[2]
        .to_str()
        .context("image ID must be UTF8")?
        .to_owned();
    let inode = args[3].to_str().context("inode must be hexadecimal")?;
    let tree = inode == "tree";
    let parsed = if tree {
        0
    } else {
        u32::from_str_radix(inode, 16)?
    };
    ensure!(tree || parsed > 0, "inode zero is not a file");
    let out = PathBuf::from(&args[4]);
    ensure!(!out.exists(), "output already exists");
    gb_core::separate_from_input(&input, &out)?;
    gb_core::separate_from_input(&tool, &out)?;
    let sandbox = gb_tools::Sandbox::Docker { image };
    sandbox.validate()?;
    let tool = gb_tools::host_tool(&tool, &[&input])?;
    let support = tool
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("lib64"));
    let mut extra = vec![gb_tools::ReadOnlyInput {
        name: "f2fs-tool",
        path: &tool,
    }];
    if let Some(support) = support.as_ref().filter(|p| p.is_dir()) {
        extra.push(gb_tools::ReadOnlyInput {
            name: "tool-lib64",
            path: support,
        });
    }
    // F2FS dispatches by argv[0]. The controlled shell executes only this
    // inspected host package; no executable from the firmware is invoked.
    let identity = gb_tools::identity(&tool, &sandbox)?;
    let before = gb_core::hash_file(&input)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&out)?;
    // dump.f2fs can update superblock version metadata even during extraction.
    // Keep the capture read-only and permit those tool writes only in a private,
    // disposable copy, never on a device or the captured evidence. Tree mode
    // already supports --dry-run and continues to inspect the original directly.
    let scratch = if tree {
        None
    } else {
        ensure!(
            std::fs::metadata(&input)?.len() <= 512 * 1024 * 1024,
            "metadata scratch-copy limit exceeded"
        );
        let mut copy = tempfile::NamedTempFile::new_in(&out)?;
        gb_core::copy_stream(std::fs::File::open(&input)?, copy.as_file_mut())?;
        copy.as_file().sync_all()?;
        ensure!(
            gb_core::hash_file(copy.path())? == before,
            "source changed while copying metadata"
        );
        Some(copy)
    };
    let dump_input = match &scratch {
        Some(copy) => format!(
            "/output/{}",
            copy.path()
                .file_name()
                .and_then(|name| name.to_str())
                .context("scratch name must be UTF8")?
        ),
        None => "/input.img".to_owned(),
    };
    let command = if tree {
        "export LD_LIBRARY_PATH=/inputs/tool-lib64:/host-libs; cd /output && exec -a fsck.f2fs /inputs/f2fs-tool --dry-run -t /input.img"
    } else {
        // This answers only dump mode's host-file extraction prompt. Firmware
        // stays bind-mounted read-only; tree/fsck mode receives no answer.
        "export LD_LIBRARY_PATH=/inputs/tool-lib64:/host-libs; cd /output && printf 'Y\\n' | (exec -a dump.f2fs /inputs/f2fs-tool -i \"$1\" \"$2\")"
    };
    let result = gb_tools::run_mounted(
        &sandbox,
        &std::env::split_paths(&std::env::var_os("PATH").context("host PATH unavailable")?)
            .map(|p| p.join("bash"))
            .find(|p| p.is_file())
            .context("host bash unavailable")?,
        vec![
            "-c".into(),
            command.into(),
            "gb-f2fs-inode-inspection".into(),
            format!("0x{parsed:x}"),
            dump_input,
        ],
        gb_tools::Inputs {
            primary: &input,
            extra: &extra,
            source_date_epoch: Some(0),
        },
        &out,
        Duration::from_secs(60),
    );
    ensure!(
        gb_core::hash_file(&input)? == before,
        "source metadata image changed"
    );
    let scratch_after = scratch
        .as_ref()
        .map(|copy| gb_core::hash_file(copy.path()))
        .transpose()?;
    drop(scratch);
    let result = result?;
    gb_core::write_json(
        &out.join("inspection.json"),
        &serde_json::json!({"schema_version":1,"source_sha256":before,"tool":identity,"inode":parsed,"read_only_input":true,"disposable_copy_sha256_after":scratch_after,"result":result}),
    )?;
    Ok(())
}
