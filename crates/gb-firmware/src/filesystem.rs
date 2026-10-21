//! Filesystem inventories are analysis outputs, never metadata-complete repacking trees.
use anyhow::{Context, Result, ensure};
use gb_core::{FirmwareManifest, Format, checkpoint, hash_file, separate_from_input, write_json};
use gb_partition::{ReadSeek, Region, detect, extract_logical, gpt, read_at, super_metadata};
use gb_tools::Sandbox;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemTools {
    pub erofs: PathBuf,
    pub ext4: PathBuf,
    pub checker: PathBuf,
    pub sandbox: Sandbox,
}
pub fn extract_tree(input: &Path, output: &Path, tools: &FilesystemTools) -> Result<(Format, u64)> {
    separate_from_input(input, output)?;
    let mut f = File::open(input)?;
    let len = f.metadata()?.len();
    let format = detect(&read_at(&mut f, 0, len.min(8192) as usize)?);
    ensure!(
        matches!(format, Format::Erofs | Format::Ext4),
        "unsupported filesystem {format:?}"
    );
    gb_partition::inspect(&mut f, &format)?;
    let tool = gb_tools::host_tool(
        if format == Format::Erofs {
            &tools.erofs
        } else {
            &tools.ext4
        },
        &[input],
    )?;
    if format == Format::Ext4 {
        let checker = gb_tools::host_tool(&tools.checker, &[input])?;
        let check = tempfile::tempdir()?;
        gb_tools::run(
            &tools.sandbox,
            &checker,
            vec!["-f".into(), "-n".into(), "/input.img".into()],
            input,
            check.path(),
            Duration::from_secs(1200),
        )?;
    }
    let args = if format == Format::Erofs {
        vec![
            "--extract=/output".into(),
            "--no-preserve".into(),
            "/input.img".into(),
        ]
    } else {
        vec!["-R".into(), "rdump / /output".into(), "/input.img".into()]
    };
    let result = gb_tools::run_filtered(
        &tools.sandbox,
        &tool,
        args,
        input,
        output,
        Duration::from_secs(1200),
        if format == Format::Ext4 {
            Some(expected_ownership_warning)
        } else {
            None
        },
    )?;
    if format == Format::Ext4 {
        ensure!(
            !result.stderr_truncated
                && result
                    .stderr
                    .lines()
                    .all(|s| s.trim().is_empty() || s.starts_with("debugfs ")),
            "debugfs extraction failed: {}",
            result.stderr
        );
    }
    Ok((format, result.stderr_filtered_lines))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRequest {
    pub gpt_partition: Option<String>,
    pub slot: u32,
    pub partitions: Vec<String>,
    pub tool: PathBuf,
    pub check_tool: Option<PathBuf>,
    pub sandbox: Sandbox,
}
impl InventoryRequest {
    pub fn validate(&self) -> Result<()> {
        self.sandbox.validate()?;
        ensure!(
            !self.partitions.is_empty(),
            "select at least one logical partition"
        );
        let mut unique = std::collections::BTreeSet::new();
        for name in self.partitions.iter().chain(self.gpt_partition.iter()) {
            ensure!(
                !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "invalid partition selector"
            );
        }
        for name in &self.partitions {
            ensure!(unique.insert(name), "duplicate partition selector");
        }
        Ok(())
    }
}
pub fn with_super<T>(
    input: &Path,
    parent: Option<&str>,
    operation: impl FnOnce(&mut dyn ReadSeek) -> Result<T>,
) -> Result<T> {
    ensure!(
        std::fs::symlink_metadata(input)?.is_file(),
        "image input must be a regular file"
    );
    let mut f = File::open(input)?;
    if let Some(name) = parent {
        let table = gpt(&mut f)?;
        let p = table
            .partitions
            .iter()
            .find(|p| p.name == name)
            .context("required GPT partition missing")?;
        operation(&mut Region::new(&mut f, p.offset, p.bytes)?)
    } else {
        operation(&mut f)
    }
}
/// Fast structural report; explicitly does not hash complete partition contents.
pub fn layout(input: &Path, parent: Option<&str>, slot: u32) -> Result<Value> {
    with_super(input, parent, |r| {
        let len = r.seek(std::io::SeekFrom::End(0))?;
        let format = detect(&read_at(r, 0, len.min(8192) as usize)?);
        let metadata = match format {
            Format::Gpt if parent.is_none() => serde_json::to_value(gpt(r)?)?,
            Format::Super => serde_json::to_value(super_metadata(r, slot)?)?,
            _ => anyhow::bail!(
                "layout requires raw GPT or raw super input; sparse conversion is explicit"
            ),
        };
        Ok(
            json!({"schema_version":1,"format":format,"metadata":metadata,"content_checksums_verified":false,"other_slots_and_backups_verified":false}),
        )
    })
}
pub fn inventory_partition(
    input: &Path,
    request: &InventoryRequest,
    partition: &str,
    out: &Path,
) -> Result<FirmwareManifest> {
    request.validate()?;
    ensure!(
        request.partitions.iter().any(|p| p == partition),
        "unselected partition"
    );
    separate_from_input(input, out)?;
    let tool = gb_tools::host_tool(&request.tool, &[input])?;
    let image = out.join("partition.img");
    let info = with_super(input, request.gpt_partition.as_deref(), |r| {
        let lp = super_metadata(r, request.slot)?;
        let p = lp
            .partitions
            .iter()
            .find(|p| p.name == partition)
            .context("required logical partition missing")?;
        ensure!(
            fs2::available_space(out)?
                > p.bytes.checked_mul(8).context("disk estimate overflow")? + 256 * 1024 * 1024,
            "insufficient disk space for image and filesystem staging"
        );
        let mut dst = File::options().write(true).create_new(true).open(&image)?;
        let p = extract_logical(r, request.slot, partition, &mut dst)?;
        dst.sync_all()?;
        Ok(p)
    })?;
    let image_sha = hash_file(&image)?;
    let mut f = File::open(&image)?;
    let format = detect(&read_at(&mut f, 0, info.bytes.min(8192) as usize)?);
    ensure!(
        matches!(format, Format::Erofs | Format::Ext4),
        "selected partition is {format:?}; no supported filesystem extractor"
    );
    if format == Format::Ext4 {
        let checker = request
            .check_tool
            .as_deref()
            .context("ext4 inventory requires an explicitly configured read-only e2fsck checker")?;
        let checker = gb_tools::host_tool(checker, &[input])?;
        let check_dir = tempfile::tempdir_in(out)?;
        gb_tools::run(
            &request.sandbox,
            &checker,
            vec!["-f".into(), "-n".into(), "/input.img".into()],
            &image,
            check_dir.path(),
            Duration::from_secs(1200),
        )?;
    }
    let tree = tempfile::Builder::new()
        .prefix("gb-fs-tree-")
        .tempdir_in(out)?;
    let args = match format {
        Format::Erofs => vec![
            "--extract=/output".into(),
            "--no-preserve".into(),
            "/input.img".into(),
        ],
        Format::Ext4 => vec!["-R".into(), "rdump / /output".into(), "/input.img".into()],
        _ => anyhow::bail!("unsupported filesystem"),
    };
    let extraction = gb_tools::run_filtered(
        &request.sandbox,
        &tool,
        args,
        &image,
        tree.path(),
        Duration::from_secs(1200),
        if format == Format::Ext4 {
            Some(expected_ownership_warning)
        } else {
            None
        },
    )?;
    if format == Format::Ext4 {
        // debugfs can return zero after a failed rdump. Do not accept diagnostic errors.
        ensure!(
            !extraction.stderr_truncated
                && extraction
                    .stderr
                    .lines()
                    .all(|line| line.trim().is_empty() || line.starts_with("debugfs ")),
            "debugfs extraction diagnostics indicate failure: {}",
            extraction.stderr
        );
    }
    checkpoint()?;
    let scratch = tempfile::tempdir_in(out)?;
    let mut m = crate::inspect_firmware(tree.path(), scratch.path(), &crate::Limits::default())?;
    ensure!(
        !m.artifacts.is_empty(),
        "filesystem extraction yielded no regular files"
    );
    m.source_sha256 = image_sha.clone();
    m.limitations.push("Filesystem extraction uses host ownership/modes for analysis; Android xattrs, capabilities and ownership are not a repacking recipe".into());
    m.limitations
        .push("APK/JAR/APEX payloads and linker namespaces require separate analysis".into());
    prefix(&mut m, partition);
    drop(scratch);
    drop(tree);
    write_json(
        &out.join("partition-provenance.json"),
        &json!({"logical_partition":info,"slot":request.slot,"gpt_partition":request.gpt_partition,"image_sha256":image_sha,"format":format,"tree_metadata_preserved":false,"expected_ownership_warnings":extraction.stderr_filtered_lines}),
    )?;
    write_json(&out.join("manifest.json"), &m)?;
    Ok(m)
}
fn expected_ownership_warning(line: &str) -> bool {
    ["rdump", "dump_file"].iter().any(|prefix| {
        line.starts_with(&format!(
            "{prefix}: Operation not permitted while changing ownership of /output/"
        ))
    })
}
pub fn prefix(m: &mut FirmwareManifest, name: &str) {
    let add = |p: &mut String| {
        *p = format!("{name}/{p}");
    };
    for a in &mut m.artifacts {
        add(&mut a.path);
    }
    for p in &mut m.inventory.properties {
        add(&mut p.path);
    }
    for v in &mut m.inventory.vintf {
        add(&mut v.path);
    }
    for l in &mut m.inventory.native_libraries {
        add(&mut l.path);
    }
    for package in &mut m.inventory.apex_packages {
        add(&mut package.path);
    }
    m.inventory.metadata_text = std::mem::take(&mut m.inventory.metadata_text)
        .into_iter()
        .map(|(p, t)| (format!("{name}/{p}"), t))
        .collect();
    for list in [
        &mut m.inventory.framework,
        &mut m.inventory.apex,
        &mut m.inventory.selinux,
        &mut m.inventory.init,
        &mut m.inventory.permissions,
        &mut m.inventory.modules,
    ] {
        for p in list {
            add(p);
        }
    }
    m.inventory.symlinks = std::mem::take(&mut m.inventory.symlinks)
        .into_iter()
        .map(|(p, t)| (format!("{name}/{p}"), t))
        .collect();
}
pub fn merge(manifests: Vec<FirmwareManifest>, source_sha256: String) -> Result<FirmwareManifest> {
    ensure!(!manifests.is_empty(), "no partition inventories");
    let mut merged = FirmwareManifest {
        schema_version: 1,
        inspector_version: env!("CARGO_PKG_VERSION").into(),
        source_sha256,
        artifacts: vec![],
        inventory: Default::default(),
        limitations: vec![],
    };
    for m in manifests {
        merged.artifacts.extend(m.artifacts);
        merged.inventory.properties.extend(m.inventory.properties);
        merged.inventory.vintf.extend(m.inventory.vintf);
        merged
            .inventory
            .native_libraries
            .extend(m.inventory.native_libraries);
        merged.inventory.framework.extend(m.inventory.framework);
        merged.inventory.apex.extend(m.inventory.apex);
        merged
            .inventory
            .apex_packages
            .extend(m.inventory.apex_packages);
        merged
            .inventory
            .metadata_text
            .extend(m.inventory.metadata_text);
        merged.inventory.selinux.extend(m.inventory.selinux);
        merged.inventory.init.extend(m.inventory.init);
        merged.inventory.permissions.extend(m.inventory.permissions);
        merged.inventory.modules.extend(m.inventory.modules);
        merged.inventory.symlinks.extend(m.inventory.symlinks);
        merged.limitations.extend(m.limitations);
    }
    merged.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    ensure!(
        merged.artifacts.windows(2).all(|p| p[0].path != p[1].path),
        "duplicate inventory paths"
    );
    merged.limitations.sort();
    merged.limitations.dedup();
    Ok(merged)
}
