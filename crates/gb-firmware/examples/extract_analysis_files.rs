//! Extract selected checksum-pinned analysis files through sandboxed host tooling.
//! The decoded tree is temporary and is never used for metadata-preserving repacks.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    image: PathBuf,
    sha256: String,
    tools: gb_firmware::filesystem::FilesystemTools,
    files: BTreeMap<String, String>,
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: extract_analysis_files REQUEST.json NEW_OUTPUT"
    );
    let request: Request = gb_core::read_json(std::path::Path::new(&args[0]), 1024 * 1024)?;
    let out = PathBuf::from(&args[1]);
    ensure!(
        !out.exists() && !request.files.is_empty() && request.files.len() <= 256,
        "invalid output or extraction budget"
    );
    gb_core::separate_from_input(&request.image, &out)?;
    request.tools.sandbox.validate()?;
    let mut identities = Vec::new();
    for tool in [
        &request.tools.erofs,
        &request.tools.ext4,
        &request.tools.checker,
    ] {
        let tool = gb_tools::host_tool(tool, &[&request.image])?;
        identities.push(gb_tools::identity(&tool, &request.tools.sandbox)?);
    }
    ensure!(
        gb_core::hash_file(&request.image)? == request.sha256,
        "source image SHA256 mismatch"
    );
    for path in request.files.keys() {
        gb_core::safe_relative(std::path::Path::new(path))?;
    }
    let temp = tempfile::tempdir_in(out.parent().unwrap_or(std::path::Path::new(".")))?;
    let tree = temp.path().join("tree");
    std::fs::create_dir(&tree)?;
    let format = gb_firmware::filesystem::extract_tree(&request.image, &tree, &request.tools)?.0;
    let selected = temp.path().join("selected");
    std::fs::create_dir(&selected)?;
    for (path, sha) in &request.files {
        let file = tree.join(path);
        ensure!(
            std::fs::symlink_metadata(&file)?.is_file()
                && file.canonicalize()?.starts_with(tree.canonicalize()?)
                && gb_core::hash_file(&file)? == *sha,
            "selected file type/path/SHA256 mismatch: {path}"
        );
        let destination = selected.join(path);
        std::fs::create_dir_all(destination.parent().unwrap_or(&selected))?;
        std::fs::copy(file, destination)?;
    }
    ensure!(
        gb_core::hash_file(&request.image)? == request.sha256,
        "source image changed during read-only extraction"
    );
    gb_core::write_json(
        &selected.join("extraction-report.json"),
        &serde_json::json!({"read_only":true,"source_sha256":request.sha256,"format":format,"files":request.files,"tools":identities,"metadata_complete_for_repacking":false}),
    )?;
    std::fs::rename(selected, out)?;
    Ok(())
}
