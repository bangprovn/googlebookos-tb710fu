//! Content-addressed DAG stages with verified cache hits and atomic publication.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use gb_config::{Donor, Profile, Source, Transform, TransformManifest};
use gb_core::{
    CompatibilityReport, FirmwareManifest, Format, checkpoint, copy_stream, digest, hash_file,
    safe_relative, separate_from_input, write_json,
};
use gb_firmware::{Limits, input_digest, inspect_firmware};
use gb_partition::{Region, detect, gpt, read_at};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub mod delta;
pub mod public_export;
pub mod range_delta;
pub mod rom_release;
pub mod super_image;
pub fn init_diagnostic_cached(
    request: &gb_boot::diagnostic::Request,
    cache: &Path,
) -> Result<(gb_boot::diagnostic::Report, StageOutcome)> {
    request.validate()?;
    for (path, sha) in [
        (&request.input, &request.sha256),
        (&request.logger, &request.logger_sha256),
    ] {
        separate_from_input(path, cache)?;
        ensure!(
            hash_file(path)? == *sha,
            "init diagnostic input SHA256 mismatch"
        );
    }
    let mut identities = Vec::new();
    for tool in [&request.unpack, &request.pack, &request.lz4] {
        identities.push(gb_tools::identity(
            &gb_tools::host_tool(tool, &[&request.input, &request.logger])?,
            &request.sandbox,
        )?);
    }
    let stage = cached(
        cache,
        "temporary_init_boot_diagnostics",
        &(request, identities),
        true,
        |out| {
            gb_boot::diagnostic::build(request, out)?;
            Ok(())
        },
    )?;
    let report: gb_boot::diagnostic::Report = gb_core::read_json(
        &stage.directory.join("diagnostic-report.json"),
        4 * 1024 * 1024,
    )?;
    ensure!(
        stage.files.get("init_boot.img") == Some(&report.image_sha256),
        "init diagnostic report checksum differs"
    );
    Ok((report, stage))
}
pub fn publish_init_diagnostic(stage: &StageOutcome, destination: &Path) -> Result<()> {
    publish_verified(
        stage,
        destination,
        &["init_boot.img", "diagnostic-report.json"],
    )
}
pub fn super_assemble_cached(
    request: &super_image::Request,
    cache: &Path,
) -> Result<(super_image::Report, StageOutcome)> {
    request.validate()?;
    for input in std::iter::once(&request.base).chain(request.replacements.values()) {
        separate_from_input(&input.path, cache)?;
        ensure!(
            hash_file(&input.path)? == input.sha256,
            "super input SHA256 mismatch"
        );
    }
    let stage = cached(cache, "fixed_layout_super_assembly", request, true, |out| {
        super_image::build(request, out)?;
        Ok(())
    })?;
    let report: super_image::Report =
        gb_core::read_json(&stage.directory.join("super-report.json"), 4 * 1024 * 1024)?;
    ensure!(
        stage.files.get("super.img") == Some(&report.image_sha256),
        "super report checksum differs"
    );
    Ok((report, stage))
}
pub fn publish_super(stage: &StageOutcome, destination: &Path) -> Result<()> {
    publish_verified(stage, destination, &["super.img", "super-report.json"])
}
pub const ENGINE_DIGEST: &str = env!("GB_ENGINE_DIGEST");
pub fn avb_assemble_cached(
    request: &gb_avb::Request,
    cache: &Path,
) -> Result<(gb_avb::Report, StageOutcome)> {
    request.validate()?;
    for input in request.inputs() {
        separate_from_input(&input.path, cache)?;
        ensure!(
            hash_file(&input.path)? == input.sha256,
            "AVB input SHA mismatch"
        );
    }
    let inputs = request.inputs();
    let paths: Vec<_> = inputs.iter().map(|i| i.path.as_path()).collect();
    let tool = gb_tools::host_tool(&request.tool, &paths)?;
    let identity = gb_tools::identity(&tool, &request.sandbox)?;
    let stage = cached(
        cache,
        "avb_image_assembly",
        &(request, identity),
        true,
        |out| {
            gb_avb::build(request, out)?;
            Ok(())
        },
    )?;
    let report: gb_avb::Report =
        gb_core::read_json(&stage.directory.join("avb-report.json"), 4 * 1024 * 1024)?;
    for (name, sha) in &report.checksums {
        ensure!(
            stage.files.get(name) == Some(sha),
            "AVB report disagrees with verified image"
        );
    }
    Ok((report, stage))
}
pub fn publish_avb(
    stage: &StageOutcome,
    destination: &Path,
    report: &gb_avb::Report,
) -> Result<()> {
    let mut names: Vec<_> = report.checksums.keys().map(|s| s.as_str()).collect();
    names.push("avb-report.json");
    publish_verified(stage, destination, &names)
}
pub fn boot_adapt_cached(
    request: &gb_boot::Request,
    cache: &Path,
) -> Result<(gb_boot::Report, StageOutcome)> {
    request.validate()?;
    separate_from_input(&request.input, cache)?;
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "boot input SHA256 mismatch"
    );
    let mut identities = Vec::new();
    for tool in [&request.unpack, &request.pack, &request.lz4] {
        let tool = gb_tools::host_tool(tool, &[&request.input])?;
        identities.push(gb_tools::identity(&tool, &request.sandbox)?);
    }
    let stage = cached(
        cache,
        "vendor_boot_mount_adaptation",
        &(request, identities),
        true,
        |out| {
            gb_boot::build(request, out)?;
            Ok(())
        },
    )?;
    let report: gb_boot::Report =
        gb_core::read_json(&stage.directory.join("boot-report.json"), 4 * 1024 * 1024)?;
    ensure!(
        stage.files.get("vendor_boot.img") == Some(&report.image_sha256),
        "boot report does not match verified artifact"
    );
    Ok((report, stage))
}
pub fn kernel_boot_cached(
    request: &gb_boot::kernel::Request,
    cache: &Path,
) -> Result<(serde_json::Value, StageOutcome)> {
    request.validate()?;
    for (input, sha) in [
        (&request.input, &request.sha256),
        (&request.kernel, &request.kernel_sha256),
    ] {
        separate_from_input(input, cache)?;
        ensure!(
            hash_file(input)? == *sha,
            "kernel boot input checksum mismatch"
        );
    }
    let tool = gb_tools::host_tool(&request.pack, &[&request.input, &request.kernel])?;
    let identity = gb_tools::identity(&tool, &request.sandbox)?;
    let stage = cached(
        cache,
        "kernel_boot_v4_adaptation",
        &(request, identity),
        true,
        |out| {
            gb_boot::kernel::build(request, out)?;
            Ok(())
        },
    )?;
    let report: serde_json::Value = gb_core::read_json(
        &stage.directory.join("kernel-boot-report.json"),
        1024 * 1024,
    )?;
    ensure!(
        stage.files.get("boot.img").map(|s| s.as_str()) == report["image_sha256"].as_str(),
        "kernel boot report checksum differs"
    );
    Ok((report, stage))
}
pub fn publish_kernel_boot(stage: &StageOutcome, destination: &Path) -> Result<()> {
    publish_verified(stage, destination, &["boot.img", "kernel-boot-report.json"])
}
pub fn import_ext4_cached(
    request: &gb_image::import::Request,
    sandbox: &gb_tools::Sandbox,
    cache: &Path,
) -> Result<gb_image::import::Resolved> {
    request.validate()?;
    separate_from_input(&request.image, cache)?;
    ensure!(
        hash_file(&request.image)? == request.image_sha256,
        "import image SHA256 mismatch before cache lookup"
    );
    let mut identities = Vec::new();
    for tool in [&request.debugfs, &request.checker] {
        let tool = gb_tools::host_tool(tool, &[&request.image])?;
        identities.push(gb_tools::identity(&tool, sandbox)?);
    }
    let stage = cached(
        cache,
        "ext4_file_import",
        &(request, sandbox, identities),
        true,
        |out| {
            gb_image::import::extract(request, sandbox, out)?;
            Ok(())
        },
    )?;
    let report: gb_image::import::Report =
        gb_core::read_json(&stage.directory.join("import-report.json"), 4 * 1024 * 1024)?;
    ensure!(
        stage.files.get("payload") == Some(&request.sha256)
            && report.sha256 == request.sha256
            && report.image_sha256 == request.image_sha256
            && report.source_path == request.source_path
            && report.destination == request.destination,
        "verified import receipt/report differs from request"
    );
    Ok(gb_image::import::Resolved {
        file: stage.directory.join("payload"),
        report,
    })
}
pub fn import_ext4_batch_cached(
    requests: &[gb_image::import::Request],
    sandbox: &gb_tools::Sandbox,
    cache: &Path,
) -> Result<Vec<gb_image::import::Resolved>> {
    let first = requests.first().context("empty import cache batch")?;
    ensure!(requests.len() <= 4096, "import cache batch budget exceeded");
    for request in requests {
        request.validate()?;
        ensure!(
            request.image == first.image
                && request.image_sha256 == first.image_sha256
                && request.debugfs == first.debugfs
                && request.checker == first.checker,
            "import cache batch mixes source images or toolchains"
        );
    }
    separate_from_input(&first.image, cache)?;
    ensure!(
        hash_file(&first.image)? == first.image_sha256,
        "import batch source SHA256 mismatch before cache lookup"
    );
    let mut identities = Vec::new();
    for tool in [&first.debugfs, &first.checker] {
        let tool = gb_tools::host_tool(tool, &[&first.image])?;
        identities.push(gb_tools::identity(&tool, sandbox)?);
    }
    let stage = cached(
        cache,
        "ext4_file_import_batch",
        &(requests, sandbox, identities),
        true,
        |out| {
            gb_image::import::extract_batch(requests, sandbox, out)?;
            Ok(())
        },
    )?;
    let mut resolved = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        let prefix = format!("import-{index}");
        let report: gb_image::import::Report = gb_core::read_json(
            &stage.directory.join(&prefix).join("import-report.json"),
            4 * 1024 * 1024,
        )?;
        ensure!(
            stage.files.get(&format!("{prefix}/payload")) == Some(&request.sha256)
                && report.sha256 == request.sha256
                && report.image_sha256 == request.image_sha256
                && report.source_path == request.source_path
                && report.destination == request.destination,
            "verified batch import receipt/report differs from request"
        );
        resolved.push(gb_image::import::Resolved {
            file: stage.directory.join(prefix).join("payload"),
            report,
        });
    }
    Ok(resolved)
}

pub fn assemble_partition_cached(
    request: &gb_image::assemble::Request,
    cache: &Path,
) -> Result<(gb_image::assemble::Report, StageOutcome)> {
    request.validate()?;
    separate_from_input(&request.input, cache)?;
    for p in &request.patches {
        separate_from_input(&p.input, cache)?;
    }
    for p in &request.additions {
        separate_from_input(&p.input, cache)?;
        ensure!(
            hash_file(&p.input)? == p.sha256,
            "assembly addition input SHA256 mismatch"
        );
    }
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "assembly base input SHA256 mismatch"
    );
    for p in &request.patches {
        ensure!(
            hash_file(&p.input)? == p.sha256,
            "assembly patch input SHA256 mismatch"
        );
    }
    let inputs: Vec<_> = std::iter::once(request.input.as_path())
        .chain(request.patches.iter().map(|p| p.input.as_path()))
        .chain(request.additions.iter().map(|p| p.input.as_path()))
        .chain(request.imports.iter().map(|i| i.image.as_path()))
        .collect();
    let mut identities = Vec::new();
    for t in [&request.mkfs, &request.fsck, &request.dump] {
        let t = gb_tools::host_tool(t, &inputs)?;
        identities.push(gb_tools::identity(&t, &request.sandbox)?);
    }
    let mut groups = BTreeMap::new();
    for (index, import) in request.imports.iter().enumerate() {
        groups
            .entry((
                &import.image,
                &import.image_sha256,
                &import.debugfs,
                &import.checker,
            ))
            .or_insert_with(Vec::new)
            .push((index, import.clone()));
    }
    let mut ordered_imports = BTreeMap::new();
    for group in groups.values() {
        let requests: Vec<_> = group.iter().map(|(_, r)| r.clone()).collect();
        for ((index, _), resolved) in group.iter().zip(import_ext4_batch_cached(
            &requests,
            &request.sandbox,
            cache,
        )?) {
            ordered_imports.insert(*index, resolved);
        }
    }
    let imports: Vec<_> = ordered_imports.into_values().collect();
    let import_reports: Vec<_> = imports.iter().map(|i| &i.report).collect();
    let stage = cached(
        cache,
        "erofs_partition_assembly",
        &(request, &identities, &import_reports),
        true,
        |out| {
            gb_image::assemble::build_resolved(request, &imports, out)?;
            Ok(())
        },
    )?;
    let report: gb_image::assemble::Report =
        gb_core::read_json(&stage.directory.join("image-report.json"), 16 * 1024 * 1024)?;
    ensure!(
        stage.files.get("partition.img") == Some(&report.image_sha256),
        "image report disagrees with verified artifact"
    );
    Ok((report, stage))
}
pub fn publish_partition(stage: &StageOutcome, destination: &Path) -> Result<()> {
    publish_verified(stage, destination, &["partition.img", "image-report.json"])
}
pub fn publish_boot(stage: &StageOutcome, destination: &Path) -> Result<()> {
    publish_verified(stage, destination, &["vendor_boot.img", "boot-report.json"])
}
fn publish_verified(stage: &StageOutcome, destination: &Path, names: &[&str]) -> Result<()> {
    ensure!(
        !destination.exists(),
        "image artifact destination already exists"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".image-staging-")
        .tempdir_in(parent)?;
    let mut hashes = BTreeMap::new();
    for &name in names {
        let want = stage
            .files
            .get(name)
            .context("image publication lacks verified file")?;
        let path = staging.path().join(name);
        copy_stream(
            File::open(stage.directory.join(name))?,
            File::create(&path)?,
        )?;
        ensure!(
            hash_file(&path)? == *want,
            "published partition artifact digest mismatch"
        );
        File::open(path)?.sync_all()?;
        hashes.insert(name, want);
    }
    let ledger = hashes
        .iter()
        .map(|(p, h)| format!("{h}  {p}\n"))
        .collect::<String>();
    fs::write(staging.path().join("SHA256SUMS"), ledger)?;
    File::open(staging.path().join("SHA256SUMS"))?.sync_all()?;
    File::open(staging.path())?.sync_all()?;
    gb_core::publish_directory(staging.path(), destination)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn contexts_cached(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &gb_framework::Recipe,
    inputs: &gb_selinux::contexts::Inputs,
    tool: &Path,
    sandbox: &gb_tools::Sandbox,
    cache: &Path,
) -> Result<(gb_selinux::contexts::Report, StageOutcome)> {
    let policy = &inputs.policy;
    separate_from_input(&policy.input, cache)?;
    ensure!(
        hash_file(&policy.input)? == policy.sha256,
        "context policy artifact SHA256 mismatch"
    );
    let tool = gb_tools::host_tool(tool, &[&policy.input])?;
    let identity = gb_tools::identity(&tool, sandbox)?;
    let stage = cached(
        cache,
        "selinux_context_validation",
        &(
            donor,
            target,
            recipe,
            &policy.sha256,
            policy.policy_version,
            &policy.policy_report_sha256,
            policy.strict_audit_passed,
            &inputs.feature_observation,
            &identity,
        ),
        true,
        |out| {
            let report = gb_selinux::contexts::check(
                donor,
                target,
                recipe,
                inputs,
                gb_selinux::Compiler {
                    path: &tool,
                    sandbox,
                    identity: &identity,
                },
                out,
            )?;
            ensure!(
                report.state != gb_core::State::Unknown,
                "context compiler/sandbox outcome indeterminate; not cached: {}",
                serde_json::to_string(&report.file_contexts_check)?
            );
            Ok(())
        },
    )?;
    let report = gb_core::read_json(&stage.directory.join("report.json"), 32 * 1024 * 1024)?;
    Ok((report, stage))
}
pub fn collect_text_cached(
    request: &gb_firmware::analysis::Request,
    cache: &Path,
) -> Result<(FirmwareManifest, Vec<StageOutcome>)> {
    separate_from_input(&request.base_manifest, cache)?;
    let mut manifest: FirmwareManifest =
        gb_core::read_json(&request.base_manifest, 64 * 1024 * 1024)?;
    manifest.validate()?;
    let inputs: Vec<_> = request.images.iter().map(|i| i.input.as_path()).collect();
    let mut identities = Vec::new();
    for tool in [
        &request.tools.erofs,
        &request.tools.ext4,
        &request.tools.checker,
    ] {
        let tool = gb_tools::host_tool(tool, &inputs)?;
        identities.push(gb_tools::identity(&tool, &request.tools.sandbox)?);
    }
    let mut stages = Vec::new();
    for image in &request.images {
        ensure!(
            image.reuse_manifest.is_none(),
            "text collection does not import prior image-analysis reports"
        );
        separate_from_input(&image.input, cache)?;
        let expected = gb_firmware::text_collection::missing(&manifest, &image.partition);
        ensure!(
            hash_file(&image.input)? == image.sha256,
            "text collection source SHA256 mismatch"
        );
        if expected.is_empty() {
            continue;
        }
        let stage = cached(
            cache,
            "firmware_text_collection",
            &(&image.partition, &image.sha256, &expected, &identities),
            true,
            |out| {
                let collection =
                    gb_firmware::text_collection::collect(image, &request.tools, &expected, out)?;
                write_json(&out.join("text.json"), &collection)?;
                write_json(&out.join("tools.json"), &identities)
            },
        )?;
        let collection: gb_firmware::text_collection::Collection =
            gb_core::read_json(&stage.directory.join("text.json"), 64 * 1024 * 1024)?;
        ensure!(
            collection.image_sha256 == image.sha256
                && collection.partition == image.partition
                && collection.text.len() == expected.len(),
            "cached text collection identity mismatch"
        );
        for artifact in &expected {
            let text = collection
                .text
                .get(&artifact.path)
                .context("collected metadata path absent")?;
            gb_firmware::attach_text(&mut manifest, &artifact.path, text.as_bytes())?;
        }
        stages.push(stage);
    }
    manifest.limitations.push("Missing text collected from checksum-pinned filesystem images and matched to original artifact digests; source identity unchanged; extraction metadata is not a repacking recipe".into());
    manifest.validate()?;
    Ok((manifest, stages))
}
pub fn selinux_cached(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &gb_framework::Recipe,
    options: gb_selinux::Options,
    tool: &Path,
    sandbox: &gb_tools::Sandbox,
    cache: &Path,
) -> Result<(gb_selinux::Report, StageOutcome)> {
    gb_selinux::select(donor, target, recipe, options)?;
    let tool = gb_tools::host_tool(tool, &[])?;
    let identity = gb_tools::identity(&tool, sandbox)?;
    let stage = cached(
        cache,
        "selinux_split_policy",
        &(donor, target, recipe, options, &identity),
        true,
        |out| {
            let report = gb_selinux::compile(
                donor,
                target,
                recipe,
                options,
                gb_selinux::Compiler {
                    path: &tool,
                    sandbox,
                    identity: &identity,
                },
                out,
            )?;
            ensure!(
                report.state != gb_core::State::Unknown,
                "SELinux compiler/sandbox outcome indeterminate; not cached: {}",
                serde_json::to_string(&report.result)?
            );
            if let Some(link) = &report.android_init_link_check {
                ensure!(
                    link.state != gb_core::State::Unknown,
                    "Android-init compiler/sandbox outcome indeterminate; not cached: {}",
                    serde_json::to_string(&link.result)?
                );
            }
            Ok(())
        },
    )?;
    let mut report: gb_selinux::Report =
        gb_core::read_json(&stage.directory.join("report.json"), 1024 * 1024)?;
    for policy in report.binary_policy.iter().chain(
        report
            .android_init_link_check
            .iter()
            .flat_map(|l| l.binary_policy.iter()),
    ) {
        safe_relative(Path::new(&policy.file))?;
        ensure!(
            stage.files.get(&policy.file) == Some(&policy.sha256),
            "policy report does not match verified cached artifact"
        );
    }
    report.artifact_cache_key = Some(stage.key.clone());
    Ok((report, stage))
}
pub fn analyze_cached(
    request: &gb_firmware::analysis::Request,
    cache: &Path,
) -> Result<(FirmwareManifest, Vec<StageOutcome>)> {
    separate_from_input(&request.base_manifest, cache)?;
    let base: FirmwareManifest = gb_core::read_json(&request.base_manifest, 64 * 1024 * 1024)?;
    base.validate()?;
    let inputs = request
        .images
        .iter()
        .map(|i| i.input.as_path())
        .collect::<Vec<_>>();
    let mut tool_ids = Vec::new();
    for tool in [
        &request.tools.erofs,
        &request.tools.ext4,
        &request.tools.checker,
    ] {
        let tool = gb_tools::host_tool(tool, &inputs)?;
        tool_ids.push(gb_tools::identity(&tool, &request.tools.sandbox)?);
    }
    let mut parts = Vec::new();
    let mut stages = Vec::new();
    for image in &request.images {
        separate_from_input(&image.input, cache)?;
        ensure!(
            hash_file(&image.input)? == image.sha256,
            "deep analysis image SHA256 mismatch: {}",
            image.partition
        );
        let stage = cached(
            cache,
            "deep_filesystem_analysis",
            &(
                &image.partition,
                &image.sha256,
                &tool_ids,
                image.reuse_manifest.as_ref().map(|m| &m.sha256),
            ),
            true,
            |out| {
                tracing::info!(
                    partition = image.partition,
                    "inspecting APEX payloads and ELF metadata"
                );
                if let Some(report) = &image.reuse_manifest {
                    separate_from_input(&report.input, cache)?;
                    ensure!(
                        hash_file(&report.input)? == report.sha256,
                        "reused analysis report SHA256 mismatch"
                    );
                    let mut m: FirmwareManifest =
                        gb_core::read_json(&report.input, 64 * 1024 * 1024)?;
                    m.validate()?;
                    ensure!(
                        m.source_sha256 == image.sha256,
                        "reused report does not describe the pinned image"
                    );
                    for apex in &mut m.inventory.apex_packages {
                        apex.signatures_verified = false;
                    }
                    m.limitations.push("Imported prior checksum-pinned analysis report; source image checksum rechecked, source binaries not executed, no runtime or signature certification".into());
                    write_json(&out.join("manifest.json"), &m)?;
                    write_json(
                        &out.join("provenance.json"),
                        &serde_json::json!({"image_sha256":image.sha256,"partition":image.partition,"imported_manifest_sha256":report.sha256}),
                    )?;
                } else {
                    gb_firmware::analysis::image_inventory(image, &request.tools, out)?;
                }
                write_json(&out.join("tools.json"), &tool_ids)
            },
        )?;
        parts.push(gb_core::read_json(
            &stage.directory.join("manifest.json"),
            64 * 1024 * 1024,
        )?);
        stages.push(stage);
    }
    Ok((
        gb_firmware::analysis::compose(&base, &request.images, parts)?,
        stages,
    ))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub id: String,
    pub dependencies: Vec<String>,
}
pub fn validate_graph(stages: &[Stage]) -> Result<Vec<String>> {
    let nodes = stages
        .iter()
        .map(|s| (s.id.clone(), s))
        .collect::<BTreeMap<_, _>>();
    ensure!(nodes.len() == stages.len(), "duplicate DAG stage id");
    let mut order = Vec::new();
    for s in stages {
        ensure!(
            s.dependencies.iter().all(|d| nodes.contains_key(d)),
            "DAG dependency missing for {}",
            s.id
        );
    }
    while order.len() < stages.len() {
        let ready = nodes
            .values()
            .filter(|s| !order.contains(&s.id) && s.dependencies.iter().all(|d| order.contains(d)))
            .map(|s| s.id.clone())
            .collect::<Vec<_>>();
        ensure!(!ready.is_empty(), "DAG cycle detected");
        order.extend(ready);
    }
    Ok(order)
}
pub fn graph() -> Vec<Stage> {
    vec![
        Stage {
            id: "donor_inspection".into(),
            dependencies: vec![],
        },
        Stage {
            id: "target_inspection".into(),
            dependencies: vec![],
        },
        Stage {
            id: "compatibility".into(),
            dependencies: vec!["donor_inspection".into(), "target_inspection".into()],
        },
        Stage {
            id: "transformations".into(),
            dependencies: vec!["compatibility".into()],
        },
        Stage {
            id: "report".into(),
            dependencies: vec!["transformations".into()],
        },
    ]
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub schema_version: u32,
    pub key: String,
    pub engine_digest: String,
    pub files: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageOutcome {
    pub key: String,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(skip)]
    pub directory: PathBuf,
    #[serde(skip)]
    pub files: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReport {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub engine_digest: String,
    pub donor_sha256: String,
    pub target_sha256: String,
    pub profile_sha256: String,
    pub transformation_sha256: String,
    pub stages: BTreeMap<String, StageOutcome>,
    pub artifacts: BTreeMap<String, String>,
    pub blockers: Vec<String>,
}
fn files(root: &Path) -> Result<BTreeMap<String, String>> {
    output_files(root, false)
}
fn output_files(root: &Path, include_receipt: bool) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    fn walk(
        root: &Path,
        p: &Path,
        out: &mut BTreeMap<String, String>,
        include_receipt: bool,
    ) -> Result<()> {
        for e in fs::read_dir(p)? {
            checkpoint()?;
            let e = e?;
            let p = e.path();
            let t = e.file_type()?;
            ensure!(!t.is_symlink(), "cache/artifact symlink refused");
            if t.is_dir() {
                walk(root, &p, out, include_receipt)?;
            } else {
                ensure!(t.is_file(), "special build output refused");
                let rel = p
                    .strip_prefix(root)?
                    .to_str()
                    .context("non-UTF8 output path")?
                    .to_string();
                if include_receipt || rel != "receipt.json" {
                    out.insert(rel, hash_file(&p)?);
                }
            }
        }
        Ok(())
    }
    walk(root, root, &mut out, include_receipt)?;
    Ok(out)
}
/// Refuse pre-existing redirects inside an already isolated cache root.
/// create_dir_all would otherwise follow existing objects or locks symlinks.
/// The cache must have trusted, cooperative writers: these path checks are not
/// dirfd-rooted confinement against adversarial concurrent ancestor swaps.
fn cache_subdirectory(cache: &Path, name: &str) -> Result<PathBuf> {
    let path = cache.join(name);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure!(
        fs::symlink_metadata(&path)?.file_type().is_dir(),
        "cache {name} must be a real directory, not a symlink or special file"
    );
    Ok(path)
}

fn cache_object_exists(directory: &Path) -> Result<bool> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_dir(),
                "cache object must be a real directory, not a symlink or special file"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn cached(
    cache: &Path,
    stage: &str,
    inputs: &impl Serialize,
    incremental: bool,
    operation: impl FnOnce(&Path) -> Result<()>,
) -> Result<StageOutcome> {
    checkpoint()?;
    fs::create_dir_all(cache)?;
    let objects = cache_subdirectory(cache, "objects")?;
    let locks = cache_subdirectory(cache, "locks")?;
    let key = digest(&serde_json::to_vec(
        &json!({"stage":stage,"engine":ENGINE_DIGEST,"inputs":inputs}),
    )?);
    checkpoint()?;
    let lock_path = locks.join(&key);
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_file(),
            "cache lock must be a regular file, not a symlink or special file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let lock = gb_core::open_regular_file(
        &lock_path,
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true),
    )?;
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                checkpoint()?;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let directory = objects.join(&key);
    if cache_object_exists(&directory)? && incremental {
        let verify = (|| -> Result<Receipt> {
            let receipt: Receipt =
                gb_core::read_json(&directory.join("receipt.json"), 64 * 1024 * 1024)?;
            ensure!(
                receipt.schema_version == 1
                    && receipt.key == key
                    && receipt.engine_digest == ENGINE_DIGEST
                    && receipt.files == files(&directory)?,
                "cache receipt or contents invalid"
            );
            Ok(receipt)
        })();
        // Cancellation during verification is not cache corruption. Propagate
        // it before logging/rebuilding or returning a cache hit.
        checkpoint()?;
        if let Ok(receipt) = verify {
            tracing::info!(stage, key, "verified cache hit");
            return Ok(StageOutcome {
                key,
                cache_hit: true,
                directory,
                files: receipt.files,
            });
        }
        tracing::warn!(stage, key, "cache integrity failure; rebuilding");
    }
    let temporary = tempfile::Builder::new()
        .prefix("stage-")
        .tempdir_in(&objects)?;
    checkpoint()?;
    tracing::info!(stage, key, "running stage");
    operation(temporary.path())?;
    checkpoint()?;
    // This root filename belongs to the cache, not the operation. Otherwise
    // files() omits a requested artifact and write_json silently replaces it.
    match fs::symlink_metadata(temporary.path().join("receipt.json")) {
        Ok(_) => bail!("stage output uses reserved cache metadata path: receipt.json"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let hashes = files(temporary.path())?;
    write_json(
        &temporary.path().join("receipt.json"),
        &Receipt {
            schema_version: 1,
            key: key.clone(),
            engine_digest: ENGINE_DIGEST.into(),
            files: hashes.clone(),
        },
    )?;
    // Hold a per-key lock throughout; never expose a partially populated cache directory.
    // This is a cooperative commit boundary, not exclusion of a signal arriving
    // after the final check while replacing the directory.
    checkpoint()?;
    if cache_object_exists(&directory)? {
        fs::remove_dir_all(&directory)?;
    }
    let staging = temporary.keep();
    if let Err(e) = fs::rename(&staging, &directory) {
        let _ = fs::remove_dir_all(staging);
        return Err(e.into());
    }
    File::open(objects)?.sync_all()?;
    tracing::info!(stage, key, "published cache stage");
    Ok(StageOutcome {
        key,
        cache_hit: false,
        directory,
        files: hashes,
    })
}
fn verify_expected(got: &str, want: Option<&str>, label: &str) -> Result<()> {
    if let Some(want) = want {
        ensure!(
            got == want,
            "SHA256 mismatch for {label}: expected {want}, got {got}"
        );
    }
    Ok(())
}
pub fn inspect_cached(
    input: &Path,
    cache: &Path,
    incremental: bool,
) -> Result<(FirmwareManifest, StageOutcome)> {
    separate_from_input(input, cache)?;
    let sha = input_digest(input)?;
    let input = input.canonicalize()?;
    let stage = cached(cache, "firmware_inspection", &sha, incremental, |out| {
        ensure!(
            fs2::available_space(out)? > estimate_scratch(&input)?,
            "insufficient disk space for firmware normalization"
        );
        let scratch = tempfile::tempdir_in(out)?;
        let m = inspect_firmware(&input, scratch.path(), &Limits::default())?;
        ensure!(m.source_sha256 == sha, "firmware changed during inspection");
        drop(scratch);
        ensure!(
            input_digest(&input)? == sha,
            "firmware changed during inspection"
        );
        write_json(&out.join("manifest.json"), &m)
    })?;
    let m: FirmwareManifest =
        serde_json::from_reader(File::open(stage.directory.join("manifest.json"))?)?;
    Ok((m, stage))
}
/// Independently cached filesystem partitions; raw image receipts are retained for
/// later integration while temporary analysis trees (including symlinks) are removed.
pub fn inventory_cached(
    input: &Path,
    request: &gb_firmware::filesystem::InventoryRequest,
    cache: &Path,
    incremental: bool,
) -> Result<(FirmwareManifest, Vec<StageOutcome>)> {
    request.validate()?;
    separate_from_input(input, cache)?;
    let input = input.canonicalize()?;
    let sha = input_digest(&input)?;
    let tool = gb_tools::host_tool(&request.tool, &[&input])?;
    let checker = request
        .check_tool
        .as_deref()
        .map(|p| {
            gb_tools::host_tool(p, &[&input]).and_then(|p| gb_tools::identity(&p, &request.sandbox))
        })
        .transpose()?;
    let tools = json!({"extractor":gb_tools::identity(&tool, &request.sandbox)?,"checker":checker});
    let mut manifests = Vec::new();
    let mut stages = Vec::new();
    for name in &request.partitions {
        let mut single = request.clone();
        single.partitions = vec![name.clone()];
        single.tool = PathBuf::from("content-addressed-host-tool");
        single.check_tool = request
            .check_tool
            .as_ref()
            .map(|_| PathBuf::from("content-addressed-check-tool"));
        let stage = cached(
            cache,
            "filesystem_inventory",
            &(&sha, &single, &tools),
            incremental,
            |out| {
                tracing::info!(partition = name, "extracting and inventorying filesystem");
                gb_firmware::filesystem::inventory_partition(&input, request, name, out)?;
                write_json(&out.join("tool-provenance.json"), &tools)
            },
        )?;
        manifests.push(serde_json::from_reader(File::open(
            stage.directory.join("manifest.json"),
        )?)?);
        stages.push(stage);
    }
    ensure!(
        input_digest(&input)? == sha,
        "source changed during filesystem inventory"
    );
    let mut manifest = gb_firmware::filesystem::merge(manifests, sha)?;
    manifest.limitations.push(format!("Selected logical partitions only: {}; boot chain and omitted partitions are separate evidence", request.partitions.join(", ")));
    Ok((manifest, stages))
}
fn estimate_scratch(input: &Path) -> Result<u64> {
    if input.is_dir() {
        return Ok(64 * 1024 * 1024);
    }
    let mut f = File::open(input)?;
    let len = f.metadata()?.len();
    let prefix = read_at(&mut f, 0, len.min(8192) as usize)?;
    if detect(&prefix) == Format::Zip {
        let mut z = zip::ZipArchive::new(f)?;
        let mut biggest = 0;
        for i in 0..z.len() {
            biggest = biggest.max(z.by_index(i)?.size());
        }
        biggest
            .checked_add(256 * 1024 * 1024)
            .context("scratch estimate overflow")
    } else {
        Ok(256 * 1024 * 1024)
    }
}
fn source<'a>(which: &Source, donor: &'a Path, target: &'a Path, build: &'a Path) -> &'a Path {
    match which {
        Source::Donor => donor,
        Source::Target => target,
        Source::Build => build,
    }
}
fn input_path(root: &Path, relative: Option<&Path>) -> Result<PathBuf> {
    if let Some(relative) = relative {
        safe_relative(relative)?;
        ensure!(
            root.is_dir(),
            "relative firmware file requires an extracted tree or prior build outputs"
        );
        let canonical = root.canonicalize()?;
        let mut p = canonical.clone();
        for c in relative.components() {
            p.push(c);
            ensure!(
                !fs::symlink_metadata(&p)?.file_type().is_symlink(),
                "symlink traversal refused"
            );
        }
        ensure!(
            p.canonicalize()?.starts_with(canonical),
            "input escaped source root"
        );
        Ok(p)
    } else {
        ensure!(
            root.is_file(),
            "container operation requires regular file input"
        );
        Ok(root.to_owned())
    }
}
fn output_file(root: &Path, relative: &Path) -> Result<File> {
    safe_relative(relative)?;
    let p = root.join(relative);
    fs::create_dir_all(p.parent().context("output parent")?)?;
    ensure!(!p.exists(), "output already exists: {}", relative.display());
    Ok(OpenOptions::new().create_new(true).write(true).open(p)?)
}
fn transform_manifest(
    manifest: &TransformManifest,
    donor: &Path,
    target: &Path,
    out: &Path,
) -> Result<()> {
    for op in &manifest.operations {
        checkpoint()?;
        match op {
            Transform::Copy {
                source: which,
                input,
                output,
                sha256,
            } => {
                let p = input_path(source(which, donor, target, out), Some(input))?;
                verify_expected(&hash_file(&p)?, Some(sha256), "copy source")?;
                let mut dst = output_file(out, output)?;
                copy_stream(File::open(p)?, &mut dst)?;
                dst.sync_all()?;
                verify_expected(&hash_file(&out.join(output))?, Some(sha256), "copy output")?;
            }
            Transform::ExtractZipMember {
                source: which,
                member,
                output,
                sha256,
            } => {
                let p = input_path(source(which, donor, target, out), None)?;
                let mut z = zip::ZipArchive::new(File::open(p)?)?;
                let mut e = z.by_name(member).context("required ZIP member missing")?;
                safe_relative(Path::new(e.name()))?;
                ensure!(
                    e.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
                    "ZIP symlink refused"
                );
                ensure!(
                    e.size() < 512 * 1024 * 1024 * 1024,
                    "ZIP member exceeds extraction budget"
                );
                ensure!(
                    fs2::available_space(out)? > e.size() + 256 * 1024 * 1024,
                    "insufficient disk space to extract ZIP member"
                );
                let mut dst = output_file(out, output)?;
                let n = copy_stream(&mut e, &mut dst)?;
                ensure!(n == e.size(), "ZIP output size mismatch");
                dst.sync_all()?;
                verify_expected(&hash_file(&out.join(output))?, Some(sha256), "ZIP member")?;
            }
            Transform::ExtractGptPartition {
                source: which,
                input,
                partition,
                output,
                sha256,
            } => {
                let p = input_path(source(which, donor, target, out), input.as_deref())?;
                let mut f = File::open(p)?;
                let table = gpt(&mut f)?;
                let part = table
                    .partitions
                    .iter()
                    .find(|p| p.name == *partition)
                    .context("required GPT partition missing")?;
                ensure!(
                    fs2::available_space(out)? > part.bytes + 256 * 1024 * 1024,
                    "insufficient disk space for GPT slice"
                );
                let mut dst = output_file(out, output)?;
                let region = Region::new(&mut f, part.offset, part.bytes)?;
                ensure!(
                    copy_stream(region, &mut dst)? == part.bytes,
                    "GPT slice truncated"
                );
                dst.sync_all()?;
                verify_expected(
                    &hash_file(&out.join(output))?,
                    sha256.as_deref(),
                    "GPT output",
                )?;
            }
            Transform::ExtractLogicalPartition {
                source: which,
                input,
                partition,
                slot,
                output,
                sha256,
            } => {
                let p = input_path(source(which, donor, target, out), Some(input))?;
                let mut f = File::open(p)?;
                let lp = gb_partition::super_metadata(&mut f, *slot)?;
                let part = lp
                    .partitions
                    .iter()
                    .find(|p| p.name == *partition)
                    .context("required logical partition missing")?;
                ensure!(
                    fs2::available_space(out)? > part.bytes + 256 * 1024 * 1024,
                    "insufficient disk space for logical partition"
                );
                let mut dst = output_file(out, output)?;
                gb_partition::extract_logical(&mut f, *slot, partition, &mut dst)?;
                dst.sync_all()?;
                verify_expected(
                    &hash_file(&out.join(output))?,
                    sha256.as_deref(),
                    "logical output",
                )?;
            }
            Transform::SparseToRaw {
                source: which,
                input,
                output,
                sha256,
                tool,
                sandbox,
            } => {
                let p = input_path(source(which, donor, target, out), Some(input))?;
                verify_expected(&hash_file(&p)?, Some(sha256), "sparse source")?;
                let mut f = File::open(&p)?;
                let info = gb_partition::inspect(&mut f, &Format::Sparse)?;
                let size = info["expanded_bytes"]
                    .as_u64()
                    .context("sparse expanded bytes missing")?;
                ensure!(
                    fs2::available_space(out)? > size + 256 * 1024 * 1024,
                    "insufficient disk space for sparse conversion"
                );
                let tool = gb_tools::host_tool(tool, &[donor, target])?;
                let temp = tempfile::tempdir_in(out)?;
                gb_tools::run(
                    sandbox,
                    &tool,
                    vec!["/input.img".into(), "/output/raw.img".into()],
                    &p,
                    temp.path(),
                    Duration::from_secs(600),
                )?;
                let raw = temp.path().join("raw.img");
                ensure!(fs::metadata(&raw)?.len() == size, "simg2img size mismatch");
                let mut dst = output_file(out, output)?;
                copy_stream(File::open(raw)?, &mut dst)?;
                dst.sync_all()?;
            }
            Transform::ExtractFilesystem {
                source: which,
                input,
                output,
                sha256,
                tool,
                sandbox,
            } => {
                let p = input_path(source(which, donor, target, out), Some(input))?;
                verify_expected(&hash_file(&p)?, Some(sha256), "filesystem source")?;
                let mut f = File::open(&p)?;
                let len = f.metadata()?.len();
                let format = detect(&read_at(&mut f, 0, len.min(8192) as usize)?);
                ensure!(
                    format == Format::Erofs,
                    "filesystem extraction currently supports EROFS only; ext4 requires a vetted host tool adapter"
                );
                let tool = gb_tools::host_tool(tool, &[donor, target])?;
                let dir = out.join(output);
                fs::create_dir_all(&dir)?;
                gb_tools::run(
                    sandbox,
                    &tool,
                    vec![
                        "--extract=/output".into(),
                        "--no-preserve".into(),
                        "/input.img".into(),
                    ],
                    &p,
                    &dir,
                    Duration::from_secs(1200),
                )?;
                let inventory =
                    inspect_firmware(&dir, tempfile::tempdir()?.path(), &Limits::default())?;
                ensure!(
                    inventory.inventory.symlinks.is_empty(),
                    "extracted symlinks need a metadata-preserving assembly adapter; refusing generic publication"
                );
            }
            Transform::Overlay {
                partition,
                source: which,
                input,
                output,
                sha256,
                replaces_sha256,
            } => {
                ensure!(
                    ["system", "system_ext", "product"].contains(&partition.as_str()),
                    "hardware partition overlay refused: {partition}"
                );
                ensure!(
                    output
                        .components()
                        .next()
                        .is_some_and(|c| c.as_os_str() == partition.as_str()),
                    "overlay output must be partition-aware"
                );
                let p = input_path(source(which, donor, target, out), Some(input))?;
                verify_expected(&hash_file(&p)?, Some(sha256), "overlay source")?;
                let dst = out.join(output);
                if let Some(old) = replaces_sha256 {
                    ensure!(dst.is_file(), "overlay replacement baseline missing");
                    verify_expected(&hash_file(&dst)?, Some(old), "overlay baseline")?;
                    fs::remove_file(&dst)?;
                }
                let mut dst = output_file(out, output)?;
                copy_stream(File::open(p)?, &mut dst)?;
                dst.sync_all()?;
                verify_expected(
                    &hash_file(&out.join(output))?,
                    Some(sha256),
                    "overlay output",
                )?;
            }
        }
    }
    Ok(())
}
fn tools_digest(m: &TransformManifest, donor: &Path, target: &Path) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for op in &m.operations {
        if let Transform::SparseToRaw { tool, sandbox, .. }
        | Transform::ExtractFilesystem { tool, sandbox, .. } = op
        {
            let tool = gb_tools::host_tool(tool, &[donor, target])?;
            results.push(gb_tools::identity(&tool, sandbox)?);
        }
    }
    Ok(results)
}
pub fn build(
    donor: &Donor,
    profile: &Profile,
    transforms: &TransformManifest,
    cache: &Path,
    output: &Path,
    incremental: bool,
) -> Result<BuildReport> {
    validate_graph(&graph())?;
    for input in [&donor.input, &profile.firmware.input] {
        separate_from_input(input, cache)?;
        separate_from_input(input, output)?;
    }
    ensure!(
        !output.exists(),
        "artifact destination exists; choose a new destination for atomic publication"
    );
    let donor_sha = input_digest(&donor.input)?;
    verify_expected(&donor_sha, donor.sha256.as_deref(), "donor firmware")?;
    let target_sha = input_digest(&profile.firmware.input)?;
    verify_expected(
        &target_sha,
        profile.firmware.sha256.as_deref(),
        "target firmware",
    )?;
    let ((dm, ds), (tm, ts)) = std::thread::scope(|scope| -> Result<_> {
        let d = scope.spawn(|| inspect_cached(&donor.input, cache, incremental));
        let t = scope.spawn(|| inspect_cached(&profile.firmware.input, cache, incremental));
        Ok((
            d.join()
                .map_err(|_| anyhow::anyhow!("donor inspection worker failed"))??,
            t.join()
                .map_err(|_| anyhow::anyhow!("target inspection worker failed"))??,
        ))
    })?;
    if let Some(fp) = &transforms.donor_fingerprint {
        ensure!(
            dm.property("ro.build.fingerprint") == Some(fp),
            "donor fingerprint guard failed"
        );
    }
    if let Some(fp) = &transforms.target_fingerprint {
        ensure!(
            tm.property("ro.build.fingerprint") == Some(fp),
            "target fingerprint guard failed"
        );
    }
    let mut semantic_profile = profile.clone();
    // Input content is keyed separately; workspace location must not affect reproducibility.
    semantic_profile.firmware.input = PathBuf::from("content-addressed-target");
    let profile_sha = digest(&serde_json::to_vec(&semantic_profile)?);
    let transform_sha = digest(&serde_json::to_vec(transforms)?);
    let compat = cached(
        cache,
        "compatibility",
        &(&donor_sha, &target_sha, &profile_sha),
        incremental,
        |out| {
            write_json(
                &out.join("compatibility.json"),
                &gb_compat::check(&dm, &tm, Some(profile)),
            )
        },
    )?;
    let report: CompatibilityReport =
        serde_json::from_reader(File::open(compat.directory.join("compatibility.json"))?)?;
    let tools = tools_digest(transforms, &donor.input, &profile.firmware.input)?;
    let transformed = cached(
        cache,
        "transformations",
        &(
            &donor_sha,
            &target_sha,
            &profile_sha,
            &transform_sha,
            &tools,
        ),
        incremental,
        |out| {
            transform_manifest(transforms, &donor.input, &profile.firmware.input, out)?;
            ensure!(
                input_digest(&donor.input)? == donor_sha
                    && input_digest(&profile.firmware.input)? == target_sha,
                "source firmware changed during transformations"
            );
            write_json(
                &out.join("transformation-provenance.json"),
                &json!({"manifest":transforms,"tools":tools,"input_donor":donor_sha,"input_target":target_sha}),
            )
        },
    )?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix("gb-publish-")
        .tempdir_in(parent)?;
    let copy = |src: &Path, dst: &Path, expected: &str| -> Result<()> {
        ensure!(
            src.is_file() && !fs::symlink_metadata(src)?.file_type().is_symlink(),
            "publication requires regular files"
        );
        let p = staging.path().join(dst);
        fs::create_dir_all(p.parent().context("publication parent")?)?;
        let mut f = OpenOptions::new().write(true).create_new(true).open(&p)?;
        copy_stream(File::open(src)?, &mut f)?;
        f.sync_all()?;
        verify_expected(&hash_file(&p)?, Some(expected), "published cache output")?;
        Ok(())
    };
    copy(
        &ds.directory.join("manifest.json"),
        Path::new("donor-manifest.json"),
        &ds.files["manifest.json"],
    )?;
    copy(
        &ts.directory.join("manifest.json"),
        Path::new("target-manifest.json"),
        &ts.files["manifest.json"],
    )?;
    copy(
        &compat.directory.join("compatibility.json"),
        Path::new("compatibility.json"),
        &compat.files["compatibility.json"],
    )?;
    // These hashes were computed/verified by cached(). Do not rehash unpublished
    // multi-gigabyte intermediates merely to enumerate publication candidates.
    let transform_files = &transformed.files;
    let publication_size = transform_files
        .keys()
        .filter(|p| {
            transforms.publish.is_empty()
                || transforms
                    .publish
                    .iter()
                    .any(|x| Path::new(p).starts_with(x))
                || *p == "transformation-provenance.json"
        })
        .try_fold(0u64, |n, p| -> Result<u64> {
            n.checked_add(fs::metadata(transformed.directory.join(p))?.len())
                .context("publication size overflow")
        })?;
    ensure!(
        fs2::available_space(parent)? > publication_size + 256 * 1024 * 1024,
        "insufficient disk space for publication"
    );
    for p in transform_files.keys() {
        if transforms.publish.is_empty()
            || transforms
                .publish
                .iter()
                .any(|x| Path::new(p).starts_with(x))
            || p == "transformation-provenance.json"
        {
            copy(
                &transformed.directory.join(p),
                &Path::new("processed").join(p),
                &transform_files[p],
            )?;
        }
    }
    let mut stages = BTreeMap::new();
    stages.insert("donor_inspection".into(), ds);
    stages.insert("target_inspection".into(), ts);
    stages.insert("compatibility".into(), compat);
    stages.insert("transformations".into(), transformed);
    write_json(&staging.path().join("graph.json"), &graph())?;
    let mut hashes = files(staging.path())?;
    let build = BuildReport {
        schema_version: 1,
        status: "blocked_rom_assembly".into(),
        bootable: false,
        engine_digest: ENGINE_DIGEST.into(),
        donor_sha256: donor_sha,
        target_sha256: target_sha,
        profile_sha256: profile_sha,
        transformation_sha256: transform_sha,
        stages,
        artifacts: std::mem::take(&mut hashes),
        blockers: report.blockers,
    };
    let mut persisted = serde_json::to_value(&build)?;
    if let Some(stages) = persisted["stages"].as_object_mut() {
        for stage in stages.values_mut() {
            if let Some(stage) = stage.as_object_mut() {
                stage.remove("cache_hit");
            }
        }
    }
    write_json(&staging.path().join("build-report.json"), &persisted)?;
    let summary = format!(
        "Offline image processing completed. ROM assembly is BLOCKED.\nNo bootable ROM or validated flash instructions were produced.\n\nMissing requirements:\n{}\n",
        build
            .blockers
            .iter()
            .map(|b| format!("- {b}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    fs::write(staging.path().join("SUMMARY.txt"), summary)?;
    let hashes = files(staging.path())?;
    let text = hashes
        .iter()
        .map(|(p, h)| format!("{h}  {p}\n"))
        .collect::<String>();
    fs::write(staging.path().join("SHA256SUMS"), text)?;
    for p in files(staging.path())?.keys() {
        File::open(staging.path().join(p))?.sync_all()?;
    }
    File::open(staging.path())?.sync_all()?;
    checkpoint()?;
    let path = staging.keep();
    if let Err(e) = gb_core::publish_directory(&path, output) {
        let _ = fs::remove_dir_all(path);
        return Err(e);
    }
    File::open(parent)?.sync_all()?;
    Ok(build)
}
pub fn offline_validate(artifact: &Path) -> Result<Value> {
    let report: BuildReport =
        gb_core::read_json(&artifact.join("build-report.json"), 64 * 1024 * 1024)?;
    const MAX_CHECKSUM_BYTES: u64 = 64 * 1024 * 1024;
    let ledger =
        gb_core::open_regular_file(&artifact.join("SHA256SUMS"), OpenOptions::new().read(true))?;
    ensure!(
        ledger.metadata()?.len() <= MAX_CHECKSUM_BYTES,
        "checksum listing exceeds size budget"
    );
    let mut checksums = String::new();
    ledger
        .take(MAX_CHECKSUM_BYTES + 1)
        .read_to_string(&mut checksums)?;
    ensure!(
        checksums.len() as u64 <= MAX_CHECKSUM_BYTES,
        "checksum listing exceeds size budget"
    );
    let mut listed = BTreeMap::new();
    for line in checksums.lines() {
        let (want, p) = line.split_once("  ").context("invalid checksum listing")?;
        safe_relative(Path::new(p))?;
        ensure!(
            listed.insert(p.to_owned(), want.to_owned()).is_none(),
            "duplicate artifact checksum entry: {p}"
        );
    }
    ensure!(!listed.is_empty(), "empty checksum listing");
    // Cache receipts are excluded only while verifying a cache object. In a
    // published artifact every regular file, including metadata, needs a ledger
    // entry. SHA256SUMS is necessarily the sole file that cannot list itself.
    let mut actual = output_files(artifact, true)?;
    actual.remove("SHA256SUMS");
    ensure!(
        listed.keys().eq(actual.keys()),
        "checksum listing must cover every artifact file except SHA256SUMS exactly once"
    );
    for (p, want) in &listed {
        verify_expected(
            actual.get(p).context("checksum artifact missing")?,
            Some(want),
            p,
        )?;
    }
    for (p, want) in &report.artifacts {
        safe_relative(Path::new(p))?;
        verify_expected(
            actual.get(p).context("reported artifact missing")?,
            Some(want),
            p,
        )?;
    }
    Ok(
        json!({"schema_version":1,"static_checksums":"passed","files_checked":listed.len(),"bootable":report.bootable,"runtime_verified":false,"rom_assembly_status":report.status,"blockers":report.blockers}),
    )
}
pub fn flash_plan(profile: &Profile, artifact: &Path) -> Result<Value> {
    let validation = offline_validate(artifact)?;
    ensure!(
        validation["bootable"] == true,
        "flash plan blocked: artifact is offline processing evidence, not an assembled bootable ROM"
    );
    bail!(
        "flash adapter not implemented for {:?}; no device operations performed",
        profile.boot.strategy.value
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_cache_accepts_extracted_containers_and_invalidates_changed_input() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let tree = temp.path().join("firmware");
        let cache = temp.path().join("cache");
        fs::create_dir(&tree).unwrap();
        let write_archive = |release: &str| {
            let mut archive = zip::ZipWriter::new(File::create(tree.join("firmware.zip")).unwrap());
            archive
                .start_file(
                    "system/build.prop",
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            archive
                .write_all(format!("ro.build.version.release={release}\n").as_bytes())
                .unwrap();
            archive.finish().unwrap();
        };
        write_archive("16");
        let (first, miss) = inspect_cached(&tree, &cache, true).unwrap();
        assert!(!miss.cache_hit);
        assert_eq!(first.source_sha256, input_digest(&tree).unwrap());
        assert_eq!(first.property("ro.build.version.release"), Some("16"));
        let (same, hit) = inspect_cached(&tree, &cache, true).unwrap();
        assert!(hit.cache_hit);
        assert_eq!(same.source_sha256, first.source_sha256);

        write_archive("17");
        let (changed, rebuilt) = inspect_cached(&tree, &cache, true).unwrap();
        assert!(!rebuilt.cache_hit);
        assert_ne!(rebuilt.key, miss.key);
        assert_ne!(changed.source_sha256, first.source_sha256);
        assert_eq!(changed.source_sha256, input_digest(&tree).unwrap());
        assert_eq!(changed.property("ro.build.version.release"), Some("17"));
    }

    fn offline_artifact_fixture(root: &Path) {
        fs::write(root.join("payload.img"), b"processed firmware").unwrap();
        let report = BuildReport {
            schema_version: 1,
            status: "blocked_rom_assembly".into(),
            bootable: false,
            engine_digest: ENGINE_DIGEST.into(),
            donor_sha256: digest(b"donor"),
            target_sha256: digest(b"target"),
            profile_sha256: digest(b"profile"),
            transformation_sha256: digest(b"transforms"),
            stages: BTreeMap::new(),
            artifacts: BTreeMap::from([("payload.img".into(), digest(b"processed firmware"))]),
            blockers: vec!["Runtime validation required".into()],
        };
        write_json(&root.join("build-report.json"), &report).unwrap();
        fs::write(root.join("SUMMARY.txt"), b"ROM assembly is blocked\n").unwrap();
        let ledger = files(root)
            .unwrap()
            .iter()
            .map(|(path, sha)| format!("{sha}  {path}\n"))
            .collect::<String>();
        fs::write(root.join("SHA256SUMS"), ledger).unwrap();
    }

    #[test]
    fn offline_validation_accepts_complete_artifact_and_keeps_runtime_unknown() {
        let temp = tempfile::tempdir().unwrap();
        offline_artifact_fixture(temp.path());
        let report = offline_validate(temp.path()).unwrap();
        assert_eq!(report["files_checked"], 3);
        assert_eq!(report["bootable"], false);
        assert_eq!(report["runtime_verified"], false);
    }

    #[test]
    fn offline_validation_refuses_an_omitted_and_changed_build_report() {
        let temp = tempfile::tempdir().unwrap();
        offline_artifact_fixture(temp.path());
        let ledger = fs::read_to_string(temp.path().join("SHA256SUMS")).unwrap();
        let truncated = ledger
            .lines()
            .filter(|line| !line.ends_with("  build-report.json"))
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        fs::write(temp.path().join("SHA256SUMS"), truncated).unwrap();
        let path = temp.path().join("build-report.json");
        let mut report: BuildReport = gb_core::read_json(&path, 1024 * 1024).unwrap();
        report.bootable = true;
        write_json(&path, &report).unwrap();
        assert!(
            offline_validate(temp.path()).is_err(),
            "a report omitted from the checksum ledger must not become trusted metadata"
        );
    }

    #[test]
    fn offline_validation_refuses_unlisted_files_including_reserved_cache_receipts() {
        for name in ["unlisted.img", "receipt.json"] {
            let temp = tempfile::tempdir().unwrap();
            offline_artifact_fixture(temp.path());
            fs::write(temp.path().join(name), b"not in the ledger").unwrap();
            assert!(
                offline_validate(temp.path()).is_err(),
                "publication validation must include every regular artifact file: {name}"
            );
        }
    }

    #[test]
    fn offline_validation_refuses_duplicate_checksum_entries() {
        let temp = tempfile::tempdir().unwrap();
        offline_artifact_fixture(temp.path());
        let mut ledger = fs::read_to_string(temp.path().join("SHA256SUMS")).unwrap();
        let first = ledger.lines().next().unwrap().to_owned();
        ledger.push_str(&first);
        ledger.push('\n');
        fs::write(temp.path().join("SHA256SUMS"), ledger).unwrap();
        assert!(
            offline_validate(temp.path()).is_err(),
            "duplicate valid entries must not substitute for complete inventory coverage"
        );
    }

    #[test]
    fn offline_validation_refuses_oversized_checksum_metadata_before_reading_it() {
        let temp = tempfile::tempdir().unwrap();
        offline_artifact_fixture(temp.path());
        OpenOptions::new()
            .write(true)
            .open(temp.path().join("SHA256SUMS"))
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        let error = offline_validate(temp.path()).unwrap_err();
        assert!(error.to_string().contains("size budget"), "{error}");
    }

    #[test]
    fn graph_rejects_cycles() {
        assert!(validate_graph(&graph()).is_ok());
        assert!(
            validate_graph(&[Stage {
                id: "a".into(),
                dependencies: vec!["a".into()]
            }])
            .is_err()
        );
        assert!(
            validate_graph(&[Stage {
                id: "a".into(),
                dependencies: vec!["missing".into()]
            }])
            .is_err()
        );
    }
    #[test]
    fn cache_hit_and_corruption_rebuild() {
        let t = tempfile::tempdir().unwrap();
        let run = || {
            cached(t.path(), "test", &"input", true, |p| {
                fs::write(p.join("file"), b"good")?;
                Ok(())
            })
        };
        let a = run().unwrap();
        assert!(!a.cache_hit);
        assert!(run().unwrap().cache_hit);
        fs::write(a.directory.join("file"), b"bad").unwrap();
        assert!(!run().unwrap().cache_hit);
        assert_eq!(fs::read(a.directory.join("file")).unwrap(), b"good");
    }
    #[test]
    fn cache_cancellation_does_not_run_a_stage_or_replace_a_valid_hit() {
        // CANCELLED is process-global. The child prevents this deterministic
        // cancellation injection from racing unrelated parallel unit tests.
        gb_core::run_tool(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "tests::cache_cancellation_boundary_child".into(),
                "--ignored".into(),
                "--test-threads=1".into(),
            ],
            Duration::from_secs(20),
        )
        .unwrap();
    }

    #[test]
    #[ignore = "invoked only by the process-isolated cancellation regression"]
    fn cache_cancellation_boundary_child() {
        use std::sync::atomic::Ordering;

        struct CancelDuringKeySerialization;
        impl Serialize for CancelDuringKeySerialization {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let value = serializer.serialize_str("input")?;
                gb_core::CANCELLED.store(true, Ordering::Relaxed);
                Ok(value)
            }
        }

        let mut invoked = Vec::new();
        for prior_hit in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let original = prior_hit.then(|| {
                cached(temp.path(), "cancel-boundary", &"input", true, |out| {
                    fs::write(out.join("payload"), b"original verified data")?;
                    Ok(())
                })
                .unwrap()
            });
            let before = original.as_ref().map(|stage| {
                (
                    fs::read(stage.directory.join("receipt.json")).unwrap(),
                    fs::read(stage.directory.join("payload")).unwrap(),
                )
            });
            let called = std::cell::Cell::new(false);
            let result = cached(
                temp.path(),
                "cancel-boundary",
                &CancelDuringKeySerialization,
                true,
                |out| {
                    called.set(true);
                    fs::write(out.join("unexpected-work"), b"must not run")?;
                    Ok(())
                },
            );
            gb_core::CANCELLED.store(false, Ordering::Relaxed);
            assert!(result.unwrap_err().to_string().contains("cancelled"));
            invoked.push(called.get());
            if let (Some(stage), Some((receipt, payload))) = (original, before) {
                assert_eq!(
                    fs::read(stage.directory.join("receipt.json")).unwrap(),
                    receipt
                );
                assert_eq!(fs::read(stage.directory.join("payload")).unwrap(), payload);
                assert!(
                    cached(temp.path(), "cancel-boundary", &"input", true, |_| {
                        panic!("a cancelled lookup must preserve the verified existing hit")
                    })
                    .unwrap()
                    .cache_hit
                );
            } else {
                assert_eq!(
                    fs::read_dir(temp.path().join("objects")).unwrap().count(),
                    0
                );
            }
        }
        assert_eq!(
            invoked,
            [false, false],
            "no operation may start after cancellation"
        );
    }
    #[test]
    fn cache_refuses_transformation_output_at_reserved_receipt_path() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("firmware");
        fs::create_dir(&source).unwrap();
        let payload = b"requested firmware artifact, not cache metadata";
        fs::write(source.join("payload"), payload).unwrap();
        let manifest = TransformManifest {
            schema_version: 1,
            id: "reserved-receipt".into(),
            revision: 1,
            operations: vec![Transform::Copy {
                source: Source::Donor,
                input: "payload".into(),
                output: "receipt.json".into(),
                sha256: digest(payload),
            }],
            ..Default::default()
        };
        let cache = temp.path().join("cache");
        let error = cached(&cache, "transformations", &manifest, true, |out| {
            transform_manifest(&manifest, &source, &source, out)
        })
        .expect_err("a requested artifact must not be silently replaced by cache metadata");
        assert!(error.to_string().contains("reserved"), "{error}");
        assert_eq!(fs::read(source.join("payload")).unwrap(), payload);
        assert_eq!(fs::read_dir(cache.join("objects")).unwrap().count(), 0);
    }

    #[test]
    fn cache_preserves_nested_receipts_and_existing_object_on_reserved_output_failure() {
        let temp = tempfile::tempdir().unwrap();
        let first = cached(temp.path(), "nested-receipt", &"input", true, |out| {
            fs::create_dir(out.join("payload"))?;
            fs::write(out.join("payload/receipt.json"), b"nested firmware payload")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            first.files.get("payload/receipt.json"),
            Some(&digest(b"nested firmware payload"))
        );
        assert!(
            cached(temp.path(), "nested-receipt", &"input", true, |_| {
                panic!("a nested receipt must remain a valid cache hit")
            })
            .unwrap()
            .cache_hit
        );
        let original_receipt = fs::read(first.directory.join("receipt.json")).unwrap();
        let error = cached(temp.path(), "nested-receipt", &"input", false, |out| {
            fs::write(out.join("receipt.json"), b"colliding artifact")?;
            Ok(())
        })
        .expect_err("a reserved output must fail before replacing the prior object");
        assert!(error.to_string().contains("reserved"), "{error}");
        assert_eq!(
            fs::read(first.directory.join("receipt.json")).unwrap(),
            original_receipt
        );
        assert_eq!(
            fs::read(first.directory.join("payload/receipt.json")).unwrap(),
            b"nested firmware payload"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_receipt_symlinks_cannot_redirect_metadata_or_become_verified_hits() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside-receipt.json");
        fs::write(&outside, b"outside data must remain intact").unwrap();
        let missing = temp.path().join("missing-receipt.json");
        let cache = temp.path().join("cache");
        for target in [&outside, &missing] {
            let error = cached(&cache, "receipt-link", &"input", true, |out| {
                symlink(target, out.join("receipt.json"))?;
                Ok(())
            })
            .unwrap_err();
            assert!(error.to_string().contains("reserved"), "{error}");
        }
        assert!(
            !missing.exists(),
            "a dangling receipt must not create its target"
        );
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"outside data must remain intact"
        );
        let first = cached(&cache, "receipt-link", &"input", true, |out| {
            fs::write(out.join("payload"), b"verified")?;
            Ok(())
        })
        .unwrap();
        let valid_receipt = fs::read(first.directory.join("receipt.json")).unwrap();
        let matching_outside = temp.path().join("matching-receipt.json");
        fs::write(&matching_outside, &valid_receipt).unwrap();
        let copied: Receipt = serde_json::from_slice(&valid_receipt).unwrap();
        assert_eq!(copied.key, first.key);
        assert_eq!(copied.files, first.files);
        fs::remove_file(first.directory.join("receipt.json")).unwrap();
        symlink(&matching_outside, first.directory.join("receipt.json")).unwrap();
        let rebuilt = cached(&cache, "receipt-link", &"input", true, |out| {
            fs::write(out.join("payload"), b"verified")?;
            Ok(())
        })
        .unwrap();
        assert!(!rebuilt.cache_hit);
        assert!(
            fs::symlink_metadata(rebuilt.directory.join("receipt.json"))
                .unwrap()
                .file_type()
                .is_file()
        );
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"outside data must remain intact"
        );
        assert_eq!(fs::read(matching_outside).unwrap(), valid_receipt);
    }
    #[cfg(unix)]
    #[test]
    fn redirected_cache_internals_never_write_into_source_firmware() {
        use std::os::unix::fs::symlink;

        for redirected in ["objects", "locks"] {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("firmware");
            let cache = temp.path().join("cache");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&cache).unwrap();
            fs::write(source.join("stock.img"), b"original firmware").unwrap();
            symlink(&source, cache.join(redirected)).unwrap();
            // Root separation alone cannot detect links inside the cache.
            separate_from_input(&source, &cache).unwrap();
            let called = std::cell::Cell::new(false);
            let error = cached(&cache, "test", &"input", true, |path| {
                called.set(true);
                fs::write(path.join("candidate.img"), b"candidate")?;
                Ok(())
            })
            .unwrap_err();
            assert!(error.to_string().contains("real directory"), "{error}");
            assert!(!called.get());
            assert_eq!(fs::read_dir(&source).unwrap().count(), 1);
            assert_eq!(
                fs::read(source.join("stock.img")).unwrap(),
                b"original firmware"
            );
            assert!(
                fs::symlink_metadata(cache.join(redirected))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn object_symlink_is_neither_a_verified_hit_nor_a_rebuild_destination() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let stage = cached(&cache, "test", &"input", true, |path| {
            fs::write(path.join("file"), b"verified")?;
            Ok(())
        })
        .unwrap();
        let outside = temp.path().join("outside");
        fs::rename(&stage.directory, &outside).unwrap();
        symlink(&outside, &stage.directory).unwrap();
        for incremental in [true, false] {
            let called = std::cell::Cell::new(false);
            let error = cached(&cache, "test", &"input", incremental, |_| {
                called.set(true);
                Ok(())
            })
            .unwrap_err();
            assert!(error.to_string().contains("cache object"), "{error}");
            assert!(!called.get());
            assert_eq!(fs::read(outside.join("file")).unwrap(), b"verified");
            assert!(
                fs::symlink_metadata(&stage.directory)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn dangling_cache_links_and_redirected_key_locks_are_refused() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        let stage = cached(&cache, "test", &"input", true, |_| Ok(())).unwrap();
        fs::remove_dir_all(&stage.directory).unwrap();
        symlink(temp.path().join("missing"), &stage.directory).unwrap();
        let error = cached(&cache, "test", &"input", true, |_| {
            panic!("a dangling object link must fail before running the stage")
        })
        .unwrap_err();
        assert!(error.to_string().contains("cache object"), "{error}");
        fs::remove_file(&stage.directory).unwrap();

        let stock = temp.path().join("stock.img");
        fs::write(&stock, b"stock").unwrap();
        let lock = cache.join("locks").join(&stage.key);
        fs::remove_file(&lock).unwrap();
        symlink(&stock, &lock).unwrap();
        let error = cached(&cache, "test", &"input", true, |_| {
            panic!("a redirected lock must fail before running the stage")
        })
        .unwrap_err();
        assert!(error.to_string().contains("cache lock"), "{error}");
        assert_eq!(fs::read(stock).unwrap(), b"stock");
        assert!(fs::symlink_metadata(lock).unwrap().file_type().is_symlink());
    }
    #[test]
    fn cache_key_changes_with_input() {
        let t = tempfile::tempdir().unwrap();
        let a = cached(t.path(), "test", &"a", true, |_| Ok(())).unwrap();
        let b = cached(t.path(), "test", &"b", true, |_| Ok(())).unwrap();
        assert_ne!(a.key, b.key);
    }
    #[test]
    fn failed_stage_never_publishes() {
        let t = tempfile::tempdir().unwrap();
        assert!(
            cached(t.path(), "fail", &"input", true, |p| {
                fs::write(p.join("partial"), b"partial")?;
                bail!("failure")
            })
            .is_err()
        );
        assert_eq!(fs::read_dir(t.path().join("objects")).unwrap().count(), 0);
    }
    #[test]
    #[ignore = "requires GB_TEST_MKE2FS, GB_TEST_DEBUGFS, GB_TEST_CHECKER, GB_TEST_SANDBOX_IMAGE"]
    fn real_ext4_batch_preserves_files_metadata_and_revalidates_cache_and_source() {
        let tool =
            |name| PathBuf::from(std::env::var_os(name).expect("configured trusted host tool"));
        let sandbox = gb_tools::Sandbox::Docker {
            image: std::env::var("GB_TEST_SANDBOX_IMAGE").unwrap(),
        };
        let temp = tempfile::tempdir().unwrap();
        let seed = temp.path().join("seed");
        fs::create_dir(&seed).unwrap();
        fs::write(seed.join("android.hidl.token@1.0.so"), b"first").unwrap();
        fs::write(seed.join("libc++.so"), b"second").unwrap();
        let generated = temp.path().join("generated");
        fs::create_dir(&generated).unwrap();
        gb_tools::run(
            &sandbox,
            &tool("GB_TEST_MKE2FS"),
            vec![
                "-t".into(),
                "ext4".into(),
                "-F".into(),
                "-d".into(),
                "/input.img".into(),
                "/output/stock.img".into(),
                "8192".into(),
            ],
            &seed,
            &generated,
            Duration::from_secs(30),
        )
        .unwrap();
        let image = generated.join("stock.img");
        let image_sha256 = hash_file(&image).unwrap();
        let requests: Vec<_> = [
            ("android.hidl.token@1.0.so", b"first".as_slice()),
            ("libc++.so", b"second".as_slice()),
        ]
        .into_iter()
        .map(|(path, bytes)| gb_image::import::Request {
            image: image.clone(),
            image_sha256: image_sha256.clone(),
            source_path: path.into(),
            destination: format!("lib64/isolated/{path}"),
            sha256: digest(bytes),
            debugfs: tool("GB_TEST_DEBUGFS"),
            checker: tool("GB_TEST_CHECKER"),
            apex_name: None,
        })
        .collect();
        let cache = temp.path().join("cache");
        let first = import_ext4_batch_cached(&requests, &sandbox, &cache).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(fs::read_dir(cache.join("objects")).unwrap().count(), 1);
        assert_eq!(fs::read(&first[0].file).unwrap(), b"first");
        assert_eq!(fs::read(&first[1].file).unwrap(), b"second");
        assert_eq!(first[0].report.metadata.nlink, 1);
        let second = import_ext4_batch_cached(&requests, &sandbox, &cache).unwrap();
        assert_eq!(first[0].file, second[0].file);
        assert_eq!(first[0].report.metadata, second[0].report.metadata);
        fs::write(&first[1].file, b"tampered").unwrap();
        let rebuilt = import_ext4_batch_cached(&requests, &sandbox, &cache).unwrap();
        assert_eq!(fs::read(&rebuilt[1].file).unwrap(), b"second");
        let mut source = OpenOptions::new().write(true).open(&image).unwrap();
        use std::io::Write;
        source.write_all(b"corrupt").unwrap();
        assert!(import_ext4_batch_cached(&requests, &sandbox, &cache).is_err());
    }
}
