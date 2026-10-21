//! Collect missing metadata from pinned images without re-decoding every APEX.
use crate::{analysis::Image, filesystem::FilesystemTools};
use anyhow::{Context, Result, ensure};
use gb_core::{Artifact, FirmwareManifest, checkpoint, hash_file, safe_relative};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub partition: String,
    pub image_sha256: String,
    pub text: BTreeMap<String, String>,
}
pub fn missing(manifest: &FirmwareManifest, partition: &str) -> Vec<Artifact> {
    manifest
        .artifacts
        .iter()
        .filter(|a| {
            a.path.starts_with(&format!("{partition}/"))
                && crate::is_metadata_text(&a.path)
                && !manifest.inventory.metadata_text.contains_key(&a.path)
                && !manifest
                    .inventory
                    .apex_packages
                    .iter()
                    .any(|p| a.path.starts_with(&format!("{}/payload/", p.path)))
        })
        .cloned()
        .collect()
}
fn regular_in_tree(root: &Path, relative: &Path) -> Result<std::path::PathBuf> {
    safe_relative(relative)?;
    let mut path = root.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    for (i, c) in components.iter().enumerate() {
        path.push(c.as_os_str());
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(!metadata.is_symlink(), "metadata path traverses a link");
        if i + 1 == components.len() {
            ensure!(metadata.is_file(), "metadata is not a regular file");
        } else {
            ensure!(metadata.is_dir(), "metadata ancestor is not a directory");
        }
    }
    Ok(path)
}
pub fn collect(
    image: &Image,
    tools: &FilesystemTools,
    expected: &[Artifact],
    output: &Path,
) -> Result<Collection> {
    ensure!(
        hash_file(&image.input)? == image.sha256,
        "metadata image SHA256 mismatch"
    );
    let mut f = File::open(&image.input)?;
    let length = f.metadata()?.len();
    let format = gb_partition::detect(&gb_partition::read_at(
        &mut f,
        0,
        length.min(8192) as usize,
    )?);
    ensure!(
        matches!(format, gb_core::Format::Ext4 | gb_core::Format::Erofs),
        "unsupported text-collection filesystem"
    );
    gb_partition::inspect(&mut f, &format)?;
    let estimate = if format == gb_core::Format::Ext4 {
        expected.iter().try_fold(0u64, |n, a| {
            n.checked_add(a.bytes).context("metadata size overflow")
        })?
    } else {
        length.checked_mul(8).context("disk estimate overflow")?
    };
    ensure!(
        fs2::available_space(output)? > estimate + 256 * 1024 * 1024,
        "insufficient metadata extraction space"
    );
    let tree = tempfile::tempdir_in(output)?;
    let selective = format == gb_core::Format::Ext4;
    if selective {
        let checker = gb_tools::host_tool(&tools.checker, &[&image.input])?;
        gb_tools::run(
            &tools.sandbox,
            &checker,
            vec!["-f".into(), "-n".into(), "/input.img".into()],
            &image.input,
            tree.path(),
            std::time::Duration::from_secs(1200),
        )?;
        let mut commands = String::new();
        for (i, artifact) in expected.iter().enumerate() {
            let relative = artifact
                .path
                .strip_prefix(&format!("{}/", image.partition))
                .context("text is outside selected partition")?;
            safe_relative(Path::new(relative))?;
            ensure!(
                relative
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b)),
                "unsupported debugfs metadata path characters"
            );
            commands.push_str(&format!("dump /{relative} /output/metadata-{i}\n"));
        }
        let command_path = tree.path().join("commands.txt");
        std::fs::write(&command_path, &commands)?;
        let tool = gb_tools::host_tool(&tools.ext4, &[&image.input])?;
        let result = gb_tools::run(
            &tools.sandbox,
            &tool,
            vec![
                "-f".into(),
                "/output/commands.txt".into(),
                "/input.img".into(),
            ],
            &image.input,
            tree.path(),
            std::time::Duration::from_secs(1200),
        )?;
        ensure!(
            !result.stderr_truncated
                && result
                    .stderr
                    .lines()
                    .all(|s| s.trim().is_empty() || s.starts_with("debugfs ")),
            "debugfs selected metadata extraction failed: {}",
            result.stderr
        );
        ensure!(
            std::fs::read_to_string(command_path)? == commands,
            "metadata extraction command file changed"
        );
    } else {
        crate::filesystem::extract_tree(&image.input, tree.path(), tools)?;
    }
    let mut text = BTreeMap::new();
    let mut bytes_total = 0usize;
    for (i, artifact) in expected.iter().enumerate() {
        checkpoint()?;
        ensure!(
            crate::is_metadata_text(&artifact.path),
            "unsupported requested text path"
        );
        let relative = artifact
            .path
            .strip_prefix(&format!("{}/", image.partition))
            .context("text is outside selected partition")?;
        let lookup = if selective {
            format!("metadata-{i}")
        } else {
            relative.to_string()
        };
        let path = regular_in_tree(tree.path(), Path::new(&lookup))?;
        ensure!(
            std::fs::metadata(&path)?.len() == artifact.bytes && artifact.bytes <= 16 * 1024 * 1024,
            "text size mismatch or limit exceeded"
        );
        let mut bytes = Vec::new();
        File::open(path)?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == artifact.bytes && gb_core::digest(&bytes) == artifact.sha256,
            "metadata does not match baseline artifact"
        );
        bytes_total = bytes_total
            .checked_add(bytes.len())
            .context("text length overflow")?;
        ensure!(
            bytes_total <= 32 * 1024 * 1024,
            "text collection exceeds aggregate bound"
        );
        ensure!(
            text.insert(artifact.path.clone(), String::from_utf8(bytes)?)
                .is_none(),
            "duplicate text collection path"
        );
    }
    ensure!(
        hash_file(&image.input)? == image.sha256,
        "metadata image changed while reading"
    );
    Ok(Collection {
        partition: image.partition.clone(),
        image_sha256: image.sha256.clone(),
        text,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn read_paths_cannot_escape_through_symlink_ancestors() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        std::fs::write(root.path().join("etc/metadata"), b"text").unwrap();
        assert!(regular_in_tree(root.path(), Path::new("etc/metadata")).is_ok());
        assert!(regular_in_tree(root.path(), Path::new("../escape")).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", root.path().join("link")).unwrap();
            assert!(regular_in_tree(root.path(), Path::new("link/passwd")).is_err());
            std::os::unix::fs::symlink("metadata", root.path().join("etc/alias")).unwrap();
            assert!(regular_in_tree(root.path(), Path::new("etc/alias")).is_err());
        }
    }
}
