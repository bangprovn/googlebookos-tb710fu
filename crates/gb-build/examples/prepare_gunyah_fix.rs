//! Prepare a checksum-pinned upstream source fix; never builds or flashes firmware.
//! SOURCE_FILE PATCH_FILE HOST_GIT NEW_OUTPUT_DIRECTORY
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path, time::Duration};

const SOURCE: &str = "2fd254230b3c02ac05542ae6a4afe682162c9b74314a3614cea3f0666eede47f";
const PATCH: &str = "b7d8ccacdb4c2e84ffc09e486c3c9cbd0ae590bbe7502e42e095dc054a80a906";
const FIXED: &str = "c60daa8b2a051396186f0ad569d7e1d1335031299ca443ab7c74bb044124f993";
const RELATIVE: &str = "drivers/virt/gunyah/vm_mgr_mm.c";

fn checked_file(path: &Path, expected: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65536,
        "expected a regular source/patch file no larger than 64 KiB: {}",
        path.display()
    );
    ensure!(
        gb_core::hash_file(path)? == expected,
        "source/patch checksum mismatch: {}",
        path.display()
    );
    Ok(())
}

fn prepare(source: &Path, patch: &Path, git: &Path, output: &Path) -> Result<()> {
    ensure!(!output.exists(), "output already exists");
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
    ] {
        ensure!(
            std::env::var_os(key).is_none(),
            "unset Git environment override {key}"
        );
    }
    for input in [source, patch, git] {
        gb_core::separate_from_input(input, output)?;
    }
    checked_file(source, SOURCE)?;
    checked_file(patch, PATCH)?;
    let patch = patch.canonicalize()?;
    let git = gb_tools::host_tool(git, &[source, &patch])?;
    let git_sha256 = gb_core::hash_file(&git)?;
    let version = gb_core::run_tool(&git, &["--version".into()], Duration::from_secs(5))?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let tree = staging.path().join("tree");
    fs::create_dir_all(tree.join("drivers/virt/gunyah"))?;
    let file = tree.join(RELATIVE);
    fs::copy(source, &file)?;
    checked_file(&file, SOURCE)?;
    let patch_snapshot = staging.path().join("upstream.patch");
    fs::copy(&patch, &patch_snapshot)?;
    checked_file(&patch_snapshot, PATCH)?;
    let prefix = vec![
        "-C".to_owned(),
        tree.canonicalize()?
            .to_str()
            .context("staging path must be UTF8")?
            .to_owned(),
    ];
    let run = |tail: &[&str]| -> Result<gb_core::ToolResult> {
        let mut command = prefix.clone();
        command.extend(tail.iter().map(|s| (*s).to_owned()));
        gb_core::run_tool(&git, &command, Duration::from_secs(15))
    };
    run(&["init", "--quiet"])?;
    let patch_arg = patch_snapshot.to_str().context("patch path must be UTF8")?;
    run(&["apply", "--check", patch_arg])?;
    run(&["apply", patch_arg])?;
    checked_file(&file, FIXED)?;
    // Verify reversal too, without ever mutating the caller's source tree.
    run(&["apply", "--reverse", "--check", patch_arg])?;
    run(&["apply", "--reverse", patch_arg])?;
    checked_file(&file, SOURCE)?;
    run(&["apply", patch_arg])?;
    checked_file(&file, FIXED)?;
    checked_file(source, SOURCE)?;
    checked_file(&patch, PATCH)?;
    ensure!(gb_core::hash_file(&git)? == git_sha256, "host Git changed");
    fs::remove_dir_all(tree.join(".git"))?;
    fs::File::open(&file)?.sync_all()?;
    gb_core::write_json(
        &tree.join("preparation.json"),
        &serde_json::json!({
            "schema_version": 1,
            "status": "source_patch_verified_not_built",
            "reference_kernel_base_commit": "5c2cea985a841939e6d074cbed2019dec0245fcd",
            "source_tree_commit_verified": false,
            "upstream_fix_commit": "c9e2710a7bd01bbb73280dfe37937d5b6e24eb0b",
            "source_sha256": SOURCE, "patch_sha256": PATCH, "fixed_sha256": FIXED,
            "relative_path": RELATIVE, "source_modified": false,
            "reversal_verified": true, "git_sha256": git_sha256, "git_version": version,
            "kernel_built": false, "abi_validated": false, "firmware_written": false,
            "runtime_verified": false
        }),
    )?;
    gb_core::publish_directory(&tree, output)?;
    fs::File::open(parent)?.sync_all()?;
    println!(
        "Verified upstream source fix published; kernel build, ABI validation and device testing remain required."
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 4,
        "expected SOURCE_FILE PATCH_FILE HOST_GIT NEW_OUTPUT_DIRECTORY"
    );
    prepare(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[3]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "set GB_GUNYAH_SOURCE to the verified public base source file; requires host Git"]
    fn upstream_patch_roundtrip_preserves_input_and_refuses_bad_inputs() -> Result<()> {
        let source = std::env::var_os("GB_GUNYAH_SOURCE")
            .context("GB_GUNYAH_SOURCE is required for this real-source replay")?;
        let source = Path::new(&source);
        let patch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../patches/tb710fu/kernel/gunyah-kvcalloc.patch");
        let git = std::env::split_paths(&std::env::var_os("PATH").context("PATH unavailable")?)
            .map(|dir| dir.join("git"))
            .find(|path| path.is_file())
            .context("host Git unavailable")?;
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("prepared");
        prepare(source, &patch, &git, &output)?;
        checked_file(source, SOURCE)?;
        checked_file(&output.join(RELATIVE), FIXED)?;
        let receipt: serde_json::Value =
            gb_core::read_json(&output.join("preparation.json"), 65536)?;
        assert_eq!(receipt["reversal_verified"], true);
        assert_eq!(receipt["kernel_built"], false);
        assert_eq!(receipt["source_tree_commit_verified"], false);
        assert!(prepare(source, &patch, &git, &output).is_err());
        checked_file(&output.join(RELATIVE), FIXED)?;

        let bad_source = temp.path().join("changed.c");
        let mut changed = fs::read(source)?;
        changed.push(b'\n');
        fs::write(&bad_source, changed)?;
        let bad_output = temp.path().join("must-not-publish-source");
        assert!(prepare(&bad_source, &patch, &git, &bad_output).is_err());
        assert!(!bad_output.exists());

        let bad_patch = temp.path().join("changed.patch");
        let mut changed = fs::read(&patch)?;
        changed.push(b'\n');
        fs::write(&bad_patch, changed)?;
        let bad_output = temp.path().join("must-not-publish-patch");
        assert!(prepare(source, &bad_patch, &git, &bad_output).is_err());
        assert!(!bad_output.exists());
        checked_file(source, SOURCE)?;
        Ok(())
    }
}
