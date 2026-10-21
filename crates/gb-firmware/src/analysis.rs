//! Deepen partition inventories using retained, checksum-pinned images.
use crate::filesystem::FilesystemTools;
use anyhow::{Context, Result, ensure};
use gb_core::{FirmwareManifest, digest, hash_file, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub partition: String,
    pub input: PathBuf,
    pub sha256: String,
    pub reuse_manifest: Option<VerifiedManifest>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedManifest {
    pub input: PathBuf,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub base_manifest: PathBuf,
    pub images: Vec<Image>,
    pub tools: FilesystemTools,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut request: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        if request.base_manifest.is_relative() {
            request.base_manifest = parent.join(&request.base_manifest);
        }
        let mut names = std::collections::BTreeSet::new();
        ensure!(
            request.schema_version == 1 && !request.images.is_empty(),
            "invalid analysis request schema/empty images"
        );
        for image in &mut request.images {
            ensure!(
                !image.partition.is_empty()
                    && image
                        .partition
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && names.insert(image.partition.clone()),
                "invalid/duplicate analysis partition"
            );
            ensure!(
                image.sha256.len() == 64 && image.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid analysis image SHA256"
            );
            if image.input.is_relative() {
                image.input = parent.join(&image.input);
            }
            if let Some(report) = &mut image.reuse_manifest {
                ensure!(
                    report.sha256.len() == 64
                        && report.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid reused manifest SHA256"
                );
                if report.input.is_relative() {
                    report.input = parent.join(&report.input);
                }
            }
        }
        for tool in [
            &mut request.tools.erofs,
            &mut request.tools.ext4,
            &mut request.tools.checker,
        ] {
            if tool.is_relative() {
                *tool = parent.join(&*tool);
            }
        }
        request.tools.sandbox.validate()?;
        Ok(request)
    }
}
pub fn image_inventory(
    image: &Image,
    tools: &FilesystemTools,
    out: &Path,
) -> Result<FirmwareManifest> {
    ensure!(
        hash_file(&image.input)? == image.sha256,
        "analysis source SHA256 mismatch"
    );
    ensure!(
        fs2::available_space(out)?
            > std::fs::metadata(&image.input)?
                .len()
                .checked_mul(8)
                .context("disk estimate overflow")?
                + 256 * 1024 * 1024,
        "insufficient space for deep filesystem analysis"
    );
    let tree = tempfile::tempdir_in(out)?;
    let (format, warnings) = crate::filesystem::extract_tree(&image.input, tree.path(), tools)?;
    let scratch = tempfile::tempdir_in(out)?;
    let limits = crate::Limits {
        apex_tools: Some(tools.clone()),
        ..Default::default()
    };
    let mut m = crate::inspect_firmware(tree.path(), scratch.path(), &limits)?;
    crate::filesystem::prefix(&mut m, &image.partition);
    m.source_sha256 = image.sha256.clone();
    m.limitations.push("APEX payloads are inspected without executing code; APK/APEX signatures, namespace access and ABI symbols remain unverified".into());
    m.limitations.push("Extraction is for analysis; Android ownership, xattrs and capabilities are not an image assembly recipe".into());
    drop(scratch);
    drop(tree);
    ensure!(
        hash_file(&image.input)? == image.sha256,
        "analysis input changed while being read"
    );
    m.validate()?;
    write_json(&out.join("manifest.json"), &m)?;
    write_json(
        &out.join("provenance.json"),
        &serde_json::json!({"image_sha256":image.sha256,"partition":image.partition,"format":format,"expected_ownership_warnings":warnings,"runtime_verified":false,"signatures_verified":false}),
    )?;
    Ok(m)
}
pub fn compose(
    base: &FirmwareManifest,
    images: &[Image],
    parts: Vec<FirmwareManifest>,
) -> Result<FirmwareManifest> {
    base.validate()?;
    ensure!(
        images.len() == parts.len(),
        "analysis partition/report count differs"
    );
    for (image, part) in images.iter().zip(&parts) {
        part.validate()?;
        ensure!(
            part.source_sha256 == image.sha256,
            "partition report image digest mismatch"
        );
        ensure!(
            part.artifacts
                .iter()
                .all(|a| a.path.starts_with(&format!("{}/", image.partition))),
            "partition report contains files outside its namespace"
        );
    }
    let replaced = |path: &str| {
        images
            .iter()
            .any(|i| path.starts_with(&format!("{}/", i.partition)))
    };
    let records = parts
        .iter()
        .flat_map(|m| m.artifacts.iter())
        .map(|a| (a.path.as_str(), a))
        .collect::<BTreeMap<_, _>>();
    for old in base.artifacts.iter().filter(|a| replaced(&a.path)) {
        let new = records
            .get(old.path.as_str())
            .with_context(|| format!("baseline file absent from pinned image: {}", old.path))?;
        ensure!(
            old.sha256 == new.sha256 && old.bytes == new.bytes,
            "deep analysis baseline content mismatch: {}",
            old.path
        );
    }
    let mut remainder = base.clone();
    remainder.artifacts.retain(|a| !replaced(&a.path));
    remainder
        .inventory
        .properties
        .retain(|a| !replaced(&a.path));
    remainder.inventory.vintf.retain(|a| !replaced(&a.path));
    remainder
        .inventory
        .native_libraries
        .retain(|a| !replaced(&a.path));
    remainder
        .inventory
        .apex_packages
        .retain(|a| !replaced(&a.path));
    remainder
        .inventory
        .metadata_text
        .retain(|p, _| !replaced(p));
    remainder.inventory.symlinks.retain(|p, _| !replaced(p));
    remainder.limitations.retain(|s| {
        !s.contains("skipped above 16 MiB")
            && !s.contains("inventories require explicit sandboxed")
            && !s.contains("APK/JAR/APEX payloads")
    });
    let sources = images
        .iter()
        .map(|i| (&i.partition, &i.sha256))
        .collect::<BTreeMap<_, _>>();
    let source_sha = digest(&serde_json::to_vec(
        &serde_json::json!({"base_manifest":digest(&serde_json::to_vec(base)?),"images":sources}),
    )?);
    let mut all = vec![remainder];
    all.extend(parts);
    let mut merged = crate::filesystem::merge(all, source_sha)?;
    crate::reindex_categories(&mut merged);
    merged.validate()?;
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(path: &str, text: &str) -> FirmwareManifest {
        FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "1".repeat(64),
            artifacts: vec![gb_core::Artifact {
                path: path.into(),
                bytes: text.len() as u64,
                sha256: digest(text.as_bytes()),
                format: gb_core::Format::Unknown,
                metadata: serde_json::json!({}),
            }],
            inventory: Default::default(),
            limitations: vec![],
        }
    }
    fn image() -> Image {
        Image {
            partition: "system_a".into(),
            input: "not-opened.img".into(),
            sha256: "1".repeat(64),
            reuse_manifest: None,
        }
    }
    #[test]
    fn composition_preserves_baseline_and_is_repeatable() {
        let base = manifest("system_a/build.prop", "baseline");
        let part = base.clone();
        let one = compose(&base, &[image()], vec![part.clone()]).unwrap();
        let two = compose(&base, &[image()], vec![part]).unwrap();
        assert_eq!(
            serde_json::to_vec(&one).unwrap(),
            serde_json::to_vec(&two).unwrap()
        );
        assert_eq!(one.artifacts[0].sha256, base.artifacts[0].sha256);
        assert_ne!(one.source_sha256, base.source_sha256);
    }
    #[test]
    fn composition_refuses_mismatched_sources_content_and_namespaces() {
        let base = manifest("system_a/build.prop", "baseline");
        assert!(compose(&base, &[image()], vec![]).is_err());
        let mut part = base.clone();
        part.source_sha256 = "2".repeat(64);
        assert!(compose(&base, &[image()], vec![part]).is_err());
        assert!(
            compose(
                &base,
                &[image()],
                vec![manifest("system_a/build.prop", "modified")]
            )
            .is_err()
        );
        assert!(
            compose(
                &base,
                &[image()],
                vec![manifest("vendor_a/build.prop", "baseline")]
            )
            .is_err()
        );
    }
}
