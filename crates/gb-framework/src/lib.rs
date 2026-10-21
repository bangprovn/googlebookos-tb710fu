//! Inventory-backed system-stack integration plans, preserving target hardware.
pub mod crosvm;
pub mod functional_probe;
pub mod guest_graphics;
pub mod hardware_probe;
pub mod phone_link_ui_probe;
pub mod rro;
pub mod seccomp_compat;
pub mod service_host;
pub mod terminal_console;
pub mod terminal_probe;
pub mod terminal_soak;
use anyhow::{Context, Result, ensure};
use gb_config::Profile;
use gb_core::{FirmwareManifest, NativeLibrary, digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionPair {
    pub donor: String,
    pub target: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub partitions: BTreeMap<String, PartitionPair>,
    pub donor_fingerprint: Option<String>,
    pub target_fingerprint: Option<String>,
    pub donor_source_sha256: Option<String>,
    pub target_source_sha256: Option<String>,
    #[serde(default)]
    pub retain_target_apex: Vec<RetainedApex>,
    #[serde(default)]
    pub vintf_merges: Vec<VintfMerge>,
    #[serde(default)]
    pub context_patches: Vec<ContextPatch>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPatch {
    pub donor_path: String,
    pub donor_sha256: String,
    pub reason: String,
    pub operation: ContextPatchOperation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextPatchOperation {
    RemoveExactRule {
        rule: String,
        target_path_absent: Option<String>,
        absent_target_feature: Option<String>,
    },
    UseTargetLabel {
        target_path: String,
        target_sha256: String,
        selector: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VintfMerge {
    pub donor_path: String,
    pub target_path: String,
    pub donor_sha256: String,
    pub target_sha256: String,
    pub operation: VintfMergeOperation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VintfMergeOperation {
    RetainedVndk {
        version: u32,
    },
    HalDeclarations {
        names: Vec<String>,
        #[serde(default)]
        device_extensions: Vec<DeviceHalExtension>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceHalExtension {
    pub path: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedApex {
    pub name: String,
    pub sha256: String,
}
impl Recipe {
    pub fn read(path: &Path) -> Result<Self> {
        let recipe: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        recipe.validate()?;
        Ok(recipe)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.revision > 0 && !self.id.is_empty(),
            "invalid integration recipe schema or revision"
        );
        ensure!(
            self.partitions.contains_key("system"),
            "integration recipe must select the donor system partition"
        );
        for (name, pair) in &self.partitions {
            ensure!(
                ["system", "system_ext", "product"].contains(&name.as_str()),
                "hardware partition replacement refused: {name}"
            );
            for selector in [&pair.donor, &pair.target] {
                ensure!(
                    selector == name
                        || selector == &format!("{name}_a")
                        || selector == &format!("{name}_b"),
                    "partition selector must match its integration role"
                );
            }
        }
        for hash in [&self.donor_source_sha256, &self.target_source_sha256]
            .into_iter()
            .flatten()
        {
            ensure!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid recipe source SHA256 condition"
            );
        }
        let mut names = BTreeSet::new();
        for apex in &self.retain_target_apex {
            ensure!(
                !apex.name.is_empty()
                    && names.insert(&apex.name)
                    && apex.sha256.len() == 64
                    && apex.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid or duplicate retained target APEX"
            );
        }
        let mut destinations = BTreeSet::new();
        for patch in &self.context_patches {
            gb_core::safe_relative(Path::new(&patch.donor_path))?;
            ensure!(
                selected(&patch.donor_path, self, true)
                    && patch.donor_path.contains("/etc/selinux/")
                    && patch.donor_path.ends_with("_contexts"),
                "context patch must use selected donor context text"
            );
            ensure!(
                !patch.reason.trim().is_empty()
                    && patch.donor_sha256.len() == 64
                    && patch.donor_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "context patch requires reason and input digest"
            );
            ensure!(
                self.donor_source_sha256.is_some() && self.target_source_sha256.is_some(),
                "context patches require source identity guards"
            );
            match &patch.operation {
                ContextPatchOperation::RemoveExactRule {
                    rule,
                    target_path_absent,
                    absent_target_feature,
                } => {
                    ensure!(
                        !rule.is_empty()
                            && !rule.contains(['\n', '\r'])
                            && (target_path_absent.is_some() || absent_target_feature.is_some()),
                        "context removal requires a single exact rule and a target condition"
                    );
                    if let Some(path) = target_path_absent {
                        gb_core::safe_relative(Path::new(path))?;
                        ensure!(
                            hardware(path),
                            "absent target path must be a hardware partition file"
                        );
                    }
                    if let Some(feature) = absent_target_feature {
                        ensure!(
                            !feature.is_empty()
                                && feature
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                            "invalid feature condition"
                        );
                    }
                }
                ContextPatchOperation::UseTargetLabel {
                    target_path,
                    target_sha256,
                    selector,
                } => {
                    gb_core::safe_relative(Path::new(target_path))?;
                    ensure!(
                        hardware(target_path)
                            && target_path.contains("/etc/selinux/")
                            && target_path.ends_with("_contexts")
                            && !selector.is_empty()
                            && !selector.bytes().any(|b| b.is_ascii_whitespace()),
                        "target context label requires a hardware context file and exact selector"
                    );
                    ensure!(
                        target_sha256.len() == 64
                            && target_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                        "invalid target context input digest"
                    );
                }
            }
        }
        for merge in &self.vintf_merges {
            for path in [&merge.donor_path, &merge.target_path] {
                gb_core::safe_relative(Path::new(path))?;
                ensure!(
                    path.contains("/etc/vintf/") && path.ends_with(".xml"),
                    "merge requires a VINTF XML path"
                );
            }
            ensure!(
                selected(&merge.donor_path, self, true)
                    && selected(&merge.target_path, self, false),
                "VINTF merge must use selected userspace partitions"
            );
            ensure!(
                destinations.insert(&merge.donor_path),
                "duplicate VINTF merge destination"
            );
            for hash in [&merge.donor_sha256, &merge.target_sha256] {
                ensure!(
                    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid VINTF merge SHA256 condition"
                );
            }
            match &merge.operation {
                VintfMergeOperation::RetainedVndk { version } => {
                    ensure!(*version > 0, "invalid VNDK version")
                }
                VintfMergeOperation::HalDeclarations {
                    names,
                    device_extensions,
                } => {
                    let unique: BTreeSet<_> = names.iter().collect();
                    ensure!(
                        !names.is_empty()
                            && names.len() <= 256
                            && unique.len() == names.len()
                            && names.iter().all(|n| !n.is_empty()),
                        "invalid HAL merge selectors"
                    );
                    ensure!(device_extensions.len() <= 256, "too many HAL extensions");
                    for extension in device_extensions {
                        gb_core::safe_relative(Path::new(&extension.path))?;
                        ensure!(
                            hardware(&extension.path)
                                && extension.path.contains("/etc/vintf/manifest/")
                                && extension.path.ends_with(".xml"),
                            "device HAL extension must be a hardware VINTF fragment"
                        );
                        ensure!(
                            extension.sha256.len() == 64
                                && extension.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                            "invalid HAL extension checksum"
                        );
                    }
                }
            }
        }
        Ok(())
    }
    pub fn check_sources(&self, donor: &FirmwareManifest, target: &FirmwareManifest) -> Result<()> {
        self.validate()?;
        for (manifest, fingerprint, label) in [
            (donor, &self.donor_fingerprint, "donor"),
            (target, &self.target_fingerprint, "target"),
        ] {
            if let Some(expected) = fingerprint {
                ensure!(
                    manifest.property("ro.build.fingerprint") == Some(expected),
                    "{label} fingerprint condition failed"
                );
            }
        }
        for (manifest, hash, label) in [
            (donor, &self.donor_source_sha256, "donor"),
            (target, &self.target_source_sha256, "target"),
        ] {
            if let Some(hash) = hash {
                ensure!(
                    &manifest.source_sha256 == hash,
                    "{label} integration recipe SHA256 condition failed"
                );
            }
        }
        for keep in &self.retain_target_apex {
            let packages = target
                .inventory
                .apex_packages
                .iter()
                .filter(|p| p.name == keep.name)
                .collect::<Vec<_>>();
            ensure!(
                packages.len() == 1 && packages[0].package_sha256 == keep.sha256,
                "retained target APEX missing, ambiguous or checksum differs: {}",
                keep.name
            );
            ensure!(
                !donor
                    .inventory
                    .apex_packages
                    .iter()
                    .any(|p| p.name == keep.name && selected(&p.path, self, true)),
                "retained target APEX conflicts with donor module: {}",
                keep.name
            );
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub path: String,
    pub category: String,
    pub donor_sha256: String,
    pub target_sha256: Option<String>,
    pub comparison: ComponentComparison,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentComparison {
    Identical,
    Changed,
    DonorOnly,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStatus {
    UnresolvedInventoryCandidate,
    ProviderInventoryCandidate,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub consumer: String,
    pub architecture: String,
    pub needed: String,
    pub candidate_providers: Vec<String>,
    pub excluded_old_target_system_providers: Vec<String>,
    pub status: DependencyStatus,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalRequirement {
    pub matrix: String,
    pub name: String,
    pub format: String,
    pub versions: Vec<String>,
    pub interfaces: Vec<String>,
    pub optional_attribute: bool,
    pub candidate_device_manifests: Vec<String>,
    pub runtime_verified: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub device: String,
    pub recipe: Recipe,
    pub recipe_sha256: String,
    pub profile_sha256: String,
    pub donor_source_sha256: String,
    pub target_source_sha256: String,
    pub donor_manifest_sha256: String,
    pub target_manifest_sha256: String,
    pub preserve_target_partitions: Vec<String>,
    pub components: Vec<Component>,
    pub category_counts: BTreeMap<String, usize>,
    pub dependencies: Vec<Dependency>,
    pub unresolved_dependency_candidates: usize,
    pub donor_framework_matrix_levels: Vec<String>,
    pub target_manifest_levels: Vec<String>,
    pub hal_requirement_candidates: Vec<HalRequirement>,
    pub unselected_donor_partition_files: BTreeMap<String, usize>,
    pub blockers: Vec<String>,
}
fn role(path: &str) -> &str {
    let partition = path.split('/').next().unwrap_or("");
    partition
        .strip_suffix("_a")
        .or_else(|| partition.strip_suffix("_b"))
        .unwrap_or(partition)
}
fn hardware(path: &str) -> bool {
    ["vendor", "odm", "vendor_dlkm", "odm_dlkm"].contains(&role(path))
}
fn android_native(library: &NativeLibrary) -> bool {
    ["aarch64", "arm", "x86_64", "x86"].contains(&library.architecture.as_str())
        && !library
            .path
            .split('/')
            .any(|p| ["firmware", "firmware_mnt", "rfsa"].contains(&p))
}
fn retained_apex_path(path: &str, target: &FirmwareManifest, recipe: &Recipe) -> bool {
    target.inventory.apex_packages.iter().any(|p| {
        recipe
            .retain_target_apex
            .iter()
            .any(|keep| keep.name == p.name)
            && path.starts_with(&format!("{}/payload/", p.path))
    })
}
fn selected(path: &str, recipe: &Recipe, donor: bool) -> bool {
    recipe.partitions.values().any(|pair| {
        path.strip_prefix(if donor { &pair.donor } else { &pair.target })
            .is_some_and(|tail| tail.starts_with('/'))
    })
}
/// Retain only the donor userspace partitions chosen by the integration recipe.
/// Both raw donor slots remain available in the original inventory for comparison.
pub fn selected_donor(donor: &FirmwareManifest, recipe: &Recipe) -> Result<FirmwareManifest> {
    recipe.validate()?;
    let mut m = donor.clone();
    m.artifacts.retain(|a| selected(&a.path, recipe, true));
    m.inventory
        .properties
        .retain(|p| selected(&p.path, recipe, true));
    m.inventory
        .vintf
        .retain(|d| selected(&d.path, recipe, true));
    m.inventory
        .native_libraries
        .retain(|l| selected(&l.path, recipe, true));
    for list in [
        &mut m.inventory.framework,
        &mut m.inventory.apex,
        &mut m.inventory.selinux,
        &mut m.inventory.init,
        &mut m.inventory.permissions,
        &mut m.inventory.modules,
    ] {
        list.retain(|p| selected(p, recipe, true));
    }
    m.inventory
        .symlinks
        .retain(|p, _| selected(p, recipe, true));
    m.inventory
        .apex_packages
        .retain(|p| selected(&p.path, recipe, true));
    m.inventory
        .metadata_text
        .retain(|p, _| selected(p, recipe, true));
    ensure!(!m.artifacts.is_empty(), "selected donor inventory is empty");
    m.limitations.push(format!("Donor userspace selection uses recipe {} revision {}; hardware partitions and unselected slots excluded",recipe.id,recipe.revision));
    Ok(m)
}
fn relative(path: &str) -> Option<&str> {
    path.split_once('/').map(|(_, tail)| tail)
}
fn category(path: &str) -> Option<&'static str> {
    if path.contains("/framework/") {
        Some("framework")
    } else if path.ends_with(".apex") || path.ends_with(".capex") {
        Some("apex")
    } else if path.contains("/permissions/") {
        Some("permissions")
    } else if path.contains("/init/") && path.ends_with(".rc") {
        Some("init")
    } else if path.contains("/selinux/") {
        Some("selinux")
    } else if path.contains("/priv-app/") && path.ends_with(".apk") {
        Some("privileged_application")
    } else if path.ends_with(".prop") {
        Some("properties")
    } else if path.contains("/lib64/") || path.contains("/lib/") {
        Some("native_library")
    } else {
        None
    }
}
fn names(library: &NativeLibrary) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(soname) = &library.soname {
        names.insert(soname.clone());
    }
    if let Some(file) = library
        .path
        .rsplit('/')
        .next()
        .filter(|n| n.ends_with(".so"))
    {
        names.insert(file.into());
    }
    names
}
pub fn plan(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    profile: &Profile,
    recipe: &Recipe,
) -> Result<Plan> {
    recipe.check_sources(donor, target)?;
    if let (Some(expected), Some(actual)) = (
        profile.device.architecture.observed(),
        target.architecture(),
    ) {
        ensure!(
            expected == actual,
            "device profile architecture conflicts with target inventory"
        );
    }
    for (m, fingerprint, label) in [
        (donor, &recipe.donor_fingerprint, "donor"),
        (target, &recipe.target_fingerprint, "target"),
    ] {
        ensure!(m.schema_version == 1, "unsupported {label} manifest");
        if let Some(want) = fingerprint {
            ensure!(
                m.property("ro.build.fingerprint") == Some(want),
                "{label} fingerprint condition failed"
            );
        }
    }
    for pair in recipe.partitions.values() {
        for (manifest, name, label) in [
            (donor, &pair.donor, "donor"),
            (target, &pair.target, "target"),
        ] {
            ensure!(
                manifest
                    .artifacts
                    .iter()
                    .any(|a| a.path.starts_with(&format!("{name}/"))),
                "{label} partition inventory missing: {name}"
            );
        }
    }
    let mut components = Vec::new();
    let mut counts = BTreeMap::new();
    for (partition, pair) in &recipe.partitions {
        let old = target
            .artifacts
            .iter()
            .filter(|a| a.path.starts_with(&format!("{}/", pair.target)))
            .filter_map(|a| relative(&a.path).map(|p| (p, a)))
            .collect::<BTreeMap<_, _>>();
        for a in donor
            .artifacts
            .iter()
            .filter(|a| a.path.starts_with(&format!("{}/", pair.donor)))
        {
            let path = relative(&a.path).context("component partition path")?;
            let Some(category) = category(&a.path) else {
                continue;
            };
            let target = old.get(path).map(|a| a.sha256.clone());
            let comparison = match &target {
                Some(hash) if hash == &a.sha256 => ComponentComparison::Identical,
                Some(_) => ComponentComparison::Changed,
                None => ComponentComparison::DonorOnly,
            };
            components.push(Component {
                path: format!("{partition}/{path}"),
                category: category.into(),
                donor_sha256: a.sha256.clone(),
                target_sha256: target,
                comparison,
            });
            *counts.entry(category.into()).or_insert(0) += 1;
        }
    }
    components.sort_by(|a, b| a.path.cmp(&b.path));
    let pool = donor
        .inventory
        .native_libraries
        .iter()
        .filter(|l| selected(&l.path, recipe, true) && android_native(l))
        .chain(target.inventory.native_libraries.iter().filter(|l| {
            (hardware(&l.path) || retained_apex_path(&l.path, target, recipe)) && android_native(l)
        }))
        .collect::<Vec<_>>();
    let mut providers: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for l in &pool {
        for name in names(l) {
            providers
                .entry((l.architecture.clone(), name))
                .or_default()
                .push(l.path.clone());
        }
    }
    let mut discarded: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for library in target
        .inventory
        .native_libraries
        .iter()
        .filter(|l| !hardware(&l.path))
    {
        gb_core::checkpoint()?;
        for name in names(library) {
            discarded
                .entry((library.architecture.clone(), name))
                .or_default()
                .push(library.path.clone());
        }
    }
    let mut dependencies = Vec::new();
    for l in &pool {
        gb_core::checkpoint()?;
        for needed in &l.needed {
            let mut candidates = providers
                .get(&(l.architecture.clone(), needed.clone()))
                .cloned()
                .unwrap_or_default();
            candidates.sort();
            candidates.dedup();
            let mut excluded = discarded
                .get(&(l.architecture.clone(), needed.clone()))
                .cloned()
                .unwrap_or_default();
            excluded.sort();
            excluded.dedup();
            dependencies.push(Dependency {
                consumer: l.path.clone(),
                architecture: l.architecture.clone(),
                needed: needed.clone(),
                status: if candidates.is_empty() {
                    DependencyStatus::UnresolvedInventoryCandidate
                } else {
                    DependencyStatus::ProviderInventoryCandidate
                },
                candidate_providers: candidates,
                excluded_old_target_system_providers: excluded,
            });
        }
    }
    dependencies.sort_by(|a, b| (&a.consumer, &a.needed).cmp(&(&b.consumer, &b.needed)));
    let unresolved = dependencies
        .iter()
        .filter(|d| d.candidate_providers.is_empty())
        .count();
    let levels = |m: &FirmwareManifest, kind: &str, role: &str| {
        m.inventory
            .vintf
            .iter()
            .filter(|d| d.kind == kind && d.role.as_deref() == Some(role))
            .filter_map(|d| d.level.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    let mut preserve = profile.firmware.preserve_partitions.clone();
    for required in [
        "boot",
        "vendor_boot",
        "init_boot",
        "dtbo",
        "vendor",
        "odm",
        "vendor_dlkm",
        "system_dlkm",
        "modem",
        "persist",
        "metadata",
    ] {
        if !preserve.iter().any(|p| p == required) {
            preserve.push(required.into());
        }
    }
    preserve.sort();
    preserve.dedup();
    let mut blockers = vec![
        "Candidate providers do not verify Android linker namespaces, exported symbols, symbol versions or APEX contents".into(),
        format!("{unresolved} DT_NEEDED edges lack an inspected provider in the proposed stack; reconcile APEX contents, library symlinks and external dependencies"),
        "Validate selected FCM/SKU manifests and both VINTF directions with Android checkvintf, including kernel requirements".into(),
        "Compile and validate donor platform SELinux policy with target vendor policy and required mapping versions".into(),
        "Validate APEX signatures, boot classpath, system server, privileged permissions and desktop services".into(),
        "Supply Android filesystem metadata, image assembly, authorized signing and enforced rollback constraints".into(),
        "No temporary boot or physical Googlebook desktop/hardware runtime validation has been performed".into(),
        "Proprietary donor components remain local source prerequisites; redistribution authorization is not established".into(),
    ];
    let donor_selected = selected_donor(donor, recipe)?;
    if let (Some(d), Some(t)) = (
        donor_selected.property("ro.build.version.release"),
        target.property("ro.build.version.release"),
    ) && d != t
    {
        blockers.push(format!("Donor framework Android {d} replaces Android {t} userspace; vendor compatibility requires VINTF, binder, SELinux and kernel validation"));
    }
    let target_levels = levels(target, "manifest", "device");
    let mut requirements = Vec::new();
    for matrix in donor_selected
        .inventory
        .vintf
        .iter()
        .filter(|d| d.kind == "compatibility-matrix" && d.role.as_deref() == Some("framework"))
    {
        if matrix
            .level
            .as_ref()
            .is_some_and(|level| target_levels.len() != 1 || !target_levels.contains(level))
        {
            continue;
        }
        for hal in &matrix.hals {
            let mut candidates = target
                .inventory
                .vintf
                .iter()
                .filter(|d| d.kind == "manifest" && d.role.as_deref() == Some("device"))
                .filter(|d| {
                    d.hals
                        .iter()
                        .any(|h| h.name == hal.name && h.format == hal.format)
                })
                .map(|d| d.path.clone())
                .collect::<Vec<_>>();
            candidates.sort();
            candidates.dedup();
            requirements.push(HalRequirement {
                matrix: matrix.path.clone(),
                name: hal.name.clone(),
                format: hal.format.clone(),
                versions: hal.versions.clone(),
                interfaces: hal.interfaces.clone(),
                optional_attribute: hal.optional,
                candidate_device_manifests: candidates,
                runtime_verified: false,
            });
        }
    }
    requirements.sort_by(|a, b| (&a.matrix, &a.name).cmp(&(&b.matrix, &b.name)));
    let mut unselected = BTreeMap::new();
    for artifact in donor
        .artifacts
        .iter()
        .filter(|a| !selected(&a.path, recipe, true))
    {
        let partition = artifact
            .path
            .split('/')
            .next()
            .context("partition inventory path")?;
        *unselected.entry(partition.to_string()).or_insert(0) += 1;
    }
    if unselected.contains_key("system_b") {
        blockers.push("Donor system_b contents are excluded from the system replacement; determine factory preload/precompiled-file mounts and ART regeneration requirements before assembly".into());
    }
    blockers.extend(profile.external_prerequisites.iter().cloned());
    let mut semantic_profile = profile.clone();
    semantic_profile.firmware.input = "content-addressed-target".into();
    Ok(Plan {
        schema_version: 1,
        status: "blocked_integration_validation".into(),
        bootable: false,
        runtime_verified: false,
        device: profile.device.codename.clone(),
        recipe: recipe.clone(),
        recipe_sha256: digest(&serde_json::to_vec(recipe)?),
        profile_sha256: digest(&serde_json::to_vec(&semantic_profile)?),
        donor_source_sha256: donor.source_sha256.clone(),
        target_source_sha256: target.source_sha256.clone(),
        donor_manifest_sha256: digest(&serde_json::to_vec(donor)?),
        target_manifest_sha256: digest(&serde_json::to_vec(target)?),
        preserve_target_partitions: preserve,
        components,
        category_counts: counts,
        dependencies,
        unresolved_dependency_candidates: unresolved,
        donor_framework_matrix_levels: levels(donor, "compatibility-matrix", "framework"),
        target_manifest_levels: target_levels,
        hal_requirement_candidates: requirements,
        unselected_donor_partition_files: unselected,
        blockers,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use gb_core::{Artifact, Format, Inventory};
    fn m(partition: &str) -> FirmwareManifest {
        FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "test".into(),
            artifacts: vec![Artifact {
                path: format!("{partition}/build.prop"),
                bytes: 1,
                sha256: "test".into(),
                format: Format::Unknown,
                metadata: serde_json::json!({}),
            }],
            inventory: Inventory::default(),
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
                PartitionPair {
                    donor: "system_b".into(),
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
    fn library(path: &str, arch: &str, name: &str, needed: &[&str]) -> NativeLibrary {
        NativeLibrary {
            path: path.into(),
            architecture: arch.into(),
            soname: Some(name.into()),
            needed: needed.iter().map(|s| s.to_string()).collect(),
        }
    }
    #[test]
    fn excludes_discarded_system_and_donor_vendor_and_wrong_abi() {
        let mut d = m("system_b");
        let mut t = m("system_a");
        d.inventory.native_libraries = vec![
            library(
                "system_b/lib64/client.so",
                "aarch64",
                "client.so",
                &["proprietary.so", "wrong.so", "keep.so"],
            ),
            library(
                "vendor_a/lib64/proprietary.so",
                "aarch64",
                "proprietary.so",
                &[],
            ),
            library("system_b/lib/wrong.so", "arm", "wrong.so", &[]),
        ];
        t.inventory.native_libraries = vec![
            library(
                "system_a/lib64/proprietary.so",
                "aarch64",
                "proprietary.so",
                &[],
            ),
            library("vendor_a/lib64/keep.so", "aarch64", "keep.so", &[]),
        ];
        let p = gb_config::profile(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devices/example-tablet.toml"),
        )
        .unwrap();
        let plan = plan(&d, &t, &p, &recipe()).unwrap();
        assert_eq!(plan.unresolved_dependency_candidates, 2);
        let lost = plan
            .dependencies
            .iter()
            .find(|d| d.needed == "proprietary.so")
            .unwrap();
        assert!(lost.candidate_providers.is_empty());
        assert_eq!(lost.excluded_old_target_system_providers.len(), 1);
        assert!(!plan.bootable && !plan.runtime_verified);
    }
    #[test]
    fn refuses_hardware_replacement_and_missing_inventory() {
        let mut r = recipe();
        r.partitions.insert(
            "vendor".into(),
            PartitionPair {
                donor: "vendor_a".into(),
                target: "vendor_a".into(),
            },
        );
        assert!(r.validate().is_err());
        let p = gb_config::profile(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devices/example-tablet.toml"),
        )
        .unwrap();
        assert!(plan(&m("system_a"), &m("system_a"), &p, &recipe()).is_err());
        let mut guarded = recipe();
        guarded.donor_source_sha256 = Some("a".repeat(64));
        assert!(
            guarded
                .check_sources(&m("system_b"), &m("system_a"))
                .is_err()
        );
    }
}

pub mod guest_display_phase;
