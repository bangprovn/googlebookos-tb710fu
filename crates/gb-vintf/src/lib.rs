//! Official checkvintf boundary for a donor userspace + target hardware stack.
pub mod merge;
use anyhow::{Context, Result, ensure};
use gb_core::{FirmwareManifest, State, ToolFailure, ToolResult, digest, hash_file, safe_relative};
use gb_framework::Recipe;
use gb_tools::Sandbox;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Duration};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub state: State,
    pub runtime_verified: bool,
    pub bootable: bool,
    pub kernel_checked: bool,
    pub kernel_version: Option<String>,
    pub kernel_config_sha256: Option<String>,
    pub donor_manifest_sha256: String,
    pub target_manifest_sha256: String,
    pub recipe_sha256: String,
    pub tool: serde_json::Value,
    pub properties: BTreeMap<String, String>,
    pub files: BTreeMap<String, String>,
    pub overlays: Vec<merge::Overlay>,
    pub planned_apex: Vec<PlannedApex>,
    pub result: ToolResult,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedApex {
    pub name: String,
    pub version: i64,
    pub partition: String,
    pub preinstalled_path: String,
    pub package_sha256: String,
}
fn xml_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
fn apex_plan(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
) -> Result<Vec<PlannedApex>> {
    let mut plan = BTreeMap::new();
    for (manifest, is_donor) in [(donor, true), (target, false)] {
        for package in &manifest.inventory.apex_packages {
            let (first, rest) = partition(&package.path);
            let part = role(first);
            let retained = recipe
                .retain_target_apex
                .iter()
                .any(|p| p.name == package.name && p.sha256 == package.package_sha256);
            if (is_donor && !selected(&package.path, recipe))
                || (!is_donor && !["vendor", "odm"].contains(&part) && !retained)
            {
                continue;
            }
            ensure!(
                !package.name.is_empty()
                    && package
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "unsafe APEX module name"
            );
            safe_relative(Path::new(&package.path))?;
            let tail = rest.strip_prefix(&format!("{part}/")).unwrap_or(rest);
            let p = PlannedApex {
                name: package.name.clone(),
                version: package.version,
                partition: part.to_uppercase(),
                preinstalled_path: format!("/{part}/{tail}"),
                package_sha256: package.package_sha256.clone(),
            };
            ensure!(
                plan.insert(p.name.clone(), p).is_none(),
                "ambiguous planned APEX module {}",
                package.name
            );
        }
    }
    Ok(plan.into_values().collect())
}
fn export_apex_plan(
    plan: &[PlannedApex],
    root: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<()> {
    let mut text = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<apex-info-list>\n".to_string();
    for package in plan {
        text.push_str(&format!("  <apex-info moduleName=\"{}\" modulePath=\"{}\" preinstalledModulePath=\"{}\" versionCode=\"{}\" versionName=\"\" isFactory=\"true\" isActive=\"true\" lastUpdateMillis=\"0\" provideSharedApexLibs=\"false\" partition=\"{}\" />\n",xml_attribute(&package.name),xml_attribute(&package.preinstalled_path),xml_attribute(&package.preinstalled_path),package.version,xml_attribute(&package.partition)));
        std::fs::create_dir_all(root.join("apex").join(&package.name).join("etc/vintf"))?;
    }
    text.push_str("</apex-info-list>\n");
    let path = "apex/apex-info-list.xml";
    std::fs::write(root.join(path), &text)?;
    files.insert(path.into(), digest(text.as_bytes()));
    Ok(())
}
/// Publish reviewable XML transformations; these are not filesystem images.
pub fn publish_overlays(report: &Report, destination: &Path) -> Result<()> {
    ensure!(
        !report.overlays.is_empty(),
        "no VINTF transformations to publish"
    );
    ensure!(!destination.exists(), "overlay destination already exists");
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".vintf-staging-")
        .tempdir_in(parent)?;
    let mut checksums = BTreeMap::new();
    for overlay in &report.overlays {
        safe_relative(Path::new(&overlay.donor_path))?;
        ensure!(
            digest(overlay.content.as_bytes()) == overlay.output_sha256,
            "overlay checksum mismatch"
        );
        let path = staging.path().join(&overlay.donor_path);
        std::fs::create_dir_all(path.parent().context("overlay parent")?)?;
        std::fs::write(&path, &overlay.content)?;
        std::fs::File::open(&path)?.sync_all()?;
        checksums.insert(overlay.donor_path.clone(), overlay.output_sha256.clone());
    }
    let manifest = serde_json::to_vec_pretty(report)?;
    let receipt = staging.path().join("vintf-report.json");
    std::fs::write(&receipt, &manifest)?;
    std::fs::File::open(&receipt)?.sync_all()?;
    checksums.insert("vintf-report.json".into(), digest(&manifest));
    let ledger = checksums
        .iter()
        .map(|(p, h)| format!("{h}  {p}\n"))
        .collect::<String>();
    let path = staging.path().join("SHA256SUMS");
    std::fs::write(&path, ledger)?;
    std::fs::File::open(&path)?.sync_all()?;
    gb_core::publish_directory(staging.path(), destination)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn partition(path: &str) -> (&str, &str) {
    path.split_once('/').unwrap_or((path, ""))
}
fn role(name: &str) -> &str {
    name.strip_suffix("_a")
        .or_else(|| name.strip_suffix("_b"))
        .unwrap_or(name)
}
fn selected(path: &str, recipe: &Recipe) -> bool {
    recipe
        .partitions
        .values()
        .any(|p| path.starts_with(&format!("{}/", p.donor)))
}
fn export(
    m: &FirmwareManifest,
    root: &Path,
    recipe: &Recipe,
    donor: bool,
    files: &mut BTreeMap<String, String>,
) -> Result<()> {
    for (path, text) in &m.inventory.metadata_text {
        if !path.contains("/vintf/") || !path.ends_with(".xml") {
            continue;
        }
        let (first, rest) = partition(path);
        let part = role(first);
        if donor && !selected(path, recipe) {
            continue;
        }
        if !donor && !["vendor", "odm"].contains(&part) {
            continue;
        }
        let relative = if let Some(package) = m
            .inventory
            .apex_packages
            .iter()
            .find(|a| path.starts_with(&format!("{}/payload/", a.path)))
        {
            let tail = path
                .strip_prefix(&format!("{}/payload/", package.path))
                .context("APEX VINTF path")?;
            format!("apex/{}/{tail}", package.name)
        } else {
            let tail = rest.strip_prefix(&format!("{part}/")).unwrap_or(rest);
            format!("{part}/{tail}")
        };
        safe_relative(Path::new(&relative))?;
        let sha = digest(text.as_bytes());
        if let Some(old) = files.get(&relative) {
            ensure!(old == &sha, "conflicting VINTF exports for {relative}");
            continue;
        }
        let file = root.join(&relative);
        std::fs::create_dir_all(file.parent().context("metadata parent")?)?;
        std::fs::write(&file, text)?;
        files.insert(relative, sha);
    }
    Ok(())
}
pub fn check(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
    tool: &Path,
    sandbox: &Sandbox,
    mut properties: BTreeMap<String, String>,
    kernel: Option<(&str, &Path)>,
) -> Result<Report> {
    donor.validate()?;
    target.validate()?;
    recipe.check_sources(donor, target)?;
    let overlays = merge::generate(donor, target, recipe)?;
    let mut proposed = donor.clone();
    for overlay in &overlays {
        proposed
            .inventory
            .metadata_text
            .insert(overlay.donor_path.clone(), overlay.content.clone());
    }
    let tool = gb_tools::host_tool(tool, &[])?;
    let identity = gb_tools::identity(&tool, sandbox)?;
    let input = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    let mut files = BTreeMap::new();
    for dir in ["system", "system_ext", "product", "vendor", "odm", "apex"] {
        std::fs::create_dir(input.path().join(dir))?;
    }
    export(&proposed, input.path(), recipe, true, &mut files)?;
    export(target, input.path(), recipe, false, &mut files)?;
    let planned_apex = apex_plan(donor, target, recipe)?;
    export_apex_plan(&planned_apex, input.path(), &mut files)?;
    let ready = properties
        .entry("apex.all.ready".into())
        .or_insert_with(|| "true".into());
    ensure!(
        ready == "true",
        "VINTF analysis models planned post-activation APEX only"
    );
    ensure!(
        files.keys().any(|p| p.starts_with("system/etc/vintf/"))
            && files.keys().any(|p| p.starts_with("vendor/etc/vintf/")),
        "complete system/vendor VINTF text evidence is required"
    );
    let mut args = vec!["--check-compat".into()];
    for partition in ["system", "system_ext", "product", "vendor", "odm", "apex"] {
        args.extend([
            "--dirmap".into(),
            format!("/{partition}:/input.img/{partition}"),
        ]);
    }
    for (key, value) in &properties {
        ensure!(
            !key.is_empty() && !key.contains(['=', '\n']) && !value.contains('\n'),
            "invalid VINTF property"
        );
        args.extend(["--property".into(), format!("{key}={value}")]);
    }
    let mut kernel_sha = None;
    let mut kernel_version = None;
    if let Some((version, path)) = kernel {
        ensure!(
            !version.is_empty()
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
            "invalid kernel version"
        );
        ensure!(
            std::fs::symlink_metadata(path)?.is_file()
                && std::fs::metadata(path)?.len() <= 1024 * 1024,
            "kernel config must be a bounded regular file"
        );
        let data = std::fs::read(path)?;
        ensure!(data.len() <= 1024 * 1024, "kernel config exceeds limit");
        std::fs::write(input.path().join("kernel.config"), &data)?;
        kernel_sha = Some(hash_file(path)?);
        kernel_version = Some(version.into());
        args.extend([
            "--kernel".into(),
            format!("{version}:/input.img/kernel.config"),
        ]);
    }
    let logical_args = args.clone();
    let mut result = match gb_tools::run(
        sandbox,
        &tool,
        args,
        input.path(),
        output.path(),
        Duration::from_secs(60),
    ) {
        Ok(result) => result,
        Err(error) => error
            .downcast_ref::<ToolFailure>()
            .map(|e| e.result.clone())
            .ok_or(error)?,
    };
    // Container names and host staging mounts are operational details; retain
    // the exact in-sandbox invocation and diagnostics in reproducible reports.
    result.program = "/host-tool".into();
    result.args = logical_args;
    let state = if result.stderr_truncated
        || result.stdout.len() >= 65536
        || matches!(result.exit_code, Some(64 | 70) | None)
    {
        State::Unknown
    } else if result.exit_code == Some(0) {
        State::Compatible
    } else {
        State::PatchRequired
    };
    Ok(Report{schema_version:1,state,runtime_verified:false,bootable:false,kernel_checked:kernel.is_some() && result.exit_code==Some(0),kernel_version,kernel_config_sha256:kernel_sha,
        donor_manifest_sha256:digest(&serde_json::to_vec(donor)?),target_manifest_sha256:digest(&serde_json::to_vec(target)?),recipe_sha256:digest(&serde_json::to_vec(recipe)?),tool:identity,properties,files,overlays,planned_apex,result,
        limitations:vec!["Official VINTF result is static, not proof of service operation or a bootable ROM".into(),"Factory APEX activation is a proposed composition, not an observed runtime state; userdata APEX updates are not modeled".into(),"APEX activation, signatures, SELinux, ABI symbols, KMI and boot chain need separate validation".into()]})
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> FirmwareManifest {
        FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "0".repeat(64),
            artifacts: vec![],
            inventory: Default::default(),
            limitations: vec![],
        }
    }
    fn recipe() -> Recipe {
        Recipe {
            schema_version: 1,
            id: "test".into(),
            revision: 1,
            partitions: BTreeMap::from([(
                "system".into(),
                gb_framework::PartitionPair {
                    donor: "system_a".into(),
                    target: "system_a".into(),
                },
            )]),
            donor_fingerprint: None,
            target_fingerprint: None,
            donor_source_sha256: None,
            target_source_sha256: None,
            retain_target_apex: vec![],
            vintf_merges: vec![],
            context_patches: vec![],
        }
    }
    #[test]
    fn exports_selected_system_and_preserved_vendor_without_path_escape() {
        let mut m = manifest();
        m.inventory.metadata_text.insert(
            "system_a/system/etc/vintf/manifest.xml".into(),
            "system".into(),
        );
        m.inventory
            .metadata_text
            .insert("vendor_a/etc/vintf/manifest.xml".into(), "vendor".into());
        let t = tempfile::tempdir().unwrap();
        let mut files = BTreeMap::new();
        export(&m, t.path(), &recipe(), true, &mut files).unwrap();
        assert_eq!(files.len(), 1);
        export(&m, t.path(), &recipe(), false, &mut files).unwrap();
        assert_eq!(files.len(), 2);
        m.inventory.metadata_text.insert(
            "vendor_a/etc/vintf/../../../escape.xml".into(),
            "bad".into(),
        );
        assert!(export(&m, t.path(), &recipe(), false, &mut files).is_err());
        assert!(!t.path().join("escape.xml").exists());
    }
    #[test]
    fn ambiguous_exports_are_rejected() {
        let mut m = manifest();
        m.inventory.metadata_text.insert(
            "system_a/system/etc/vintf/manifest.xml".into(),
            "one".into(),
        );
        m.inventory
            .metadata_text
            .insert("system_a/etc/vintf/manifest.xml".into(), "two".into());
        assert!(
            export(
                &m,
                tempfile::tempdir().unwrap().path(),
                &recipe(),
                true,
                &mut BTreeMap::new()
            )
            .is_err()
        );
    }
    #[test]
    fn factory_apex_composition_excludes_discarded_system_and_duplicate_modules() {
        let package = |name: &str, path: &str| gb_core::ApexPackage {
            path: path.into(),
            name: name.into(),
            version: 1,
            version_name: String::new(),
            compressed: false,
            package_sha256: "1".repeat(64),
            original_apex_sha256: None,
            payload_sha256: "2".repeat(64),
            payload_format: gb_core::Format::Ext4,
            public_key_sha256: "3".repeat(64),
            provide_native_libs: vec![],
            require_native_libs: vec![],
            jni_libs: vec![],
            bootstrap: false,
            signatures_verified: false,
        };
        let mut donor = manifest();
        let mut target = manifest();
        donor
            .inventory
            .apex_packages
            .push(package("desktop", "system_a/system/apex/desktop.apex"));
        target
            .inventory
            .apex_packages
            .push(package("discarded", "system_a/system/apex/discarded.apex"));
        target
            .inventory
            .apex_packages
            .push(package("hardware", "vendor_a/apex/hardware.apex"));
        let r = recipe();
        let plan = apex_plan(&donor, &target, &r).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].preinstalled_path, "/system/apex/desktop.apex");
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("apex")).unwrap();
        export_apex_plan(&plan, root.path(), &mut BTreeMap::new()).unwrap();
        let info = std::fs::read_to_string(root.path().join("apex/apex-info-list.xml")).unwrap();
        let doc = roxmltree::Document::parse(&info).unwrap();
        assert_eq!(
            doc.descendants()
                .filter(|n| n.has_tag_name("apex-info"))
                .count(),
            2
        );
        assert!(info.contains("partition=\"VENDOR\""));
        target
            .inventory
            .apex_packages
            .push(package("desktop", "vendor_a/apex/duplicate.apex"));
        assert!(apex_plan(&donor, &target, &r).is_err());
    }
}
