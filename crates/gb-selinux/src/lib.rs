//! Compile the proposed split policy with an explicitly configured host secilc.
//! Inputs remain untrusted text; the compiler runs in the image-tool sandbox.
pub mod cil;
pub mod context_patch;
pub mod contexts;
pub mod init_process;
#[cfg(test)]
mod tests;
use anyhow::{Context, Result, ensure};
use gb_core::{
    FirmwareManifest, State, ToolFailure, ToolResult, digest, hash_file, safe_relative, write_json,
};
use gb_framework::Recipe;
use gb_tools::Sandbox;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path, time::Duration};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// Must come from the target kernel, not the donor userspace release.
    pub kernel_policy_version: u32,
    /// Desired binary format; it may be below the kernel's supported maximum.
    pub policy_version: u32,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Donor,
    Target,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unit {
    pub source: Source,
    pub path: String,
    pub sha256: String,
    pub neverallow_rules: usize,
    pub permissive_domains: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Selection {
    pub vendor_mapping_version: String,
    pub vendor_mapping_version_path: String,
    pub vendor_mapping_version_sha256: String,
    pub genfs_labels_version: u32,
    pub genfs_uses_android_default: bool,
    pub genfs_version_path: Option<String>,
    pub genfs_version_sha256: Option<String>,
    pub units: Vec<Unit>,
    pub omitted_optional_files: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryPolicy {
    pub file: String,
    pub bytes: u64,
    pub sha256: String,
    pub policy_version: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitLinkCheck {
    pub state: State,
    pub neverallow_checks_enabled: bool,
    pub result: ToolResult,
    pub binary_policy: Option<BinaryPolicy>,
}
pub struct Compiler<'a> {
    pub path: &'a Path,
    pub sandbox: &'a Sandbox,
    pub identity: &'a serde_json::Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub state: State,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub neverallow_checks_enabled: bool,
    pub options: Options,
    pub selection: Selection,
    pub donor_manifest_sha256: String,
    pub target_manifest_sha256: String,
    pub recipe_sha256: String,
    pub tool: serde_json::Value,
    pub result: ToolResult,
    pub binary_policy: Option<BinaryPolicy>,
    pub android_init_link_check: Option<InitLinkCheck>,
    /// Relative binary filenames are within CACHE/objects/this-key.
    #[serde(default)]
    pub artifact_cache_key: Option<String>,
    pub limitations: Vec<String>,
}
fn partition_role(path: &str) -> &str {
    let part = path.split('/').next().unwrap_or("");
    part.strip_suffix("_a")
        .or_else(|| part.strip_suffix("_b"))
        .unwrap_or(part)
}
fn unique_file(
    m: &FirmwareManifest,
    prefix: Option<&str>,
    role: Option<&str>,
    suffix: &str,
) -> Result<Option<String>> {
    let found: Vec<_> = m
        .artifacts
        .iter()
        .filter(|a| {
            prefix.is_none_or(|p| a.path.starts_with(&format!("{p}/")))
                && role.is_none_or(|r| partition_role(&a.path) == r)
                && a.path.ends_with(&format!("/{suffix}"))
                && !a.path.contains("/payload/")
        })
        .collect();
    ensure!(
        found.len() <= 1,
        "ambiguous policy file: {suffix}; normalize/select the active partition first"
    );
    Ok(found.first().map(|a| a.path.clone()))
}
fn text<'a>(m: &'a FirmwareManifest, path: &str) -> Result<&'a str> {
    m.inventory
        .metadata_text
        .get(path)
        .map(String::as_str)
        .with_context(|| {
            format!("policy text missing: {path}; inspect or attach checksum-verified text")
        })
}
fn add(
    selection: &mut Selection,
    m: &FirmwareManifest,
    source: Source,
    path: String,
    required: bool,
) -> Result<()> {
    if !m.artifacts.iter().any(|a| a.path == path) {
        ensure!(!required, "required policy file missing: {path}");
        selection.omitted_optional_files.push(path);
        return Ok(());
    }
    let content = text(m, &path)?;
    let forms = cil::forms(content).with_context(|| format!("CIL metadata: {path}"))?;
    let neverallow_rules = forms
        .iter()
        .filter(|f| f.head == "neverallow" || f.head == "neverallowx")
        .count();
    let permissive_domains = forms.iter().filter(|f| f.head == "typepermissive").count();
    ensure!(
        permissive_domains == 0,
        "permissive domains are unsupported in production policy validation: {path}"
    );
    selection.units.push(Unit {
        source,
        path,
        sha256: digest(content.as_bytes()),
        neverallow_rules,
        permissive_domains,
    });
    Ok(())
}
pub fn select(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
    options: Options,
) -> Result<Selection> {
    donor.validate()?;
    target.validate()?;
    recipe.check_sources(donor, target)?;
    ensure!(
        (30..=40).contains(&options.kernel_policy_version)
            && (30..=options.kernel_policy_version).contains(&options.policy_version),
        "requested policy format exceeds target kernel capability or supported validation range"
    );
    let version_path = unique_file(
        target,
        None,
        Some("vendor"),
        "etc/selinux/plat_sepolicy_vers.txt",
    )?
    .context("target vendor policy version file absent")?;
    let version = text(target, &version_path)?.trim();
    ensure!(
        !version.is_empty()
            && version.len() <= 16
            && version.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && version.split('.').all(|s| !s.is_empty()),
        "invalid target vendor mapping version"
    );
    let version_sha = digest(text(target, &version_path)?.as_bytes());
    let vendor_root = version_path
        .strip_suffix("plat_sepolicy_vers.txt")
        .context("vendor policy root")?;
    let genfs_path = format!("{vendor_root}genfs_labels_version.txt");
    let genfs_exists = target.artifacts.iter().any(|a| a.path == genfs_path);
    let genfs_version = if genfs_exists {
        text(target, &genfs_path)?.trim().parse::<u32>()?
    } else {
        202404
    };
    ensure!(
        (202404..=999999).contains(&genfs_version),
        "invalid vendor genfs labels version"
    );
    let mut selection = Selection {
        vendor_mapping_version: version.into(),
        vendor_mapping_version_path: version_path.clone(),
        vendor_mapping_version_sha256: version_sha,
        genfs_labels_version: genfs_version,
        genfs_uses_android_default: !genfs_exists,
        genfs_version_path: genfs_exists.then_some(genfs_path.clone()),
        genfs_version_sha256: if genfs_exists {
            Some(digest(text(target, &genfs_path)?.as_bytes()))
        } else {
            None
        },
        units: vec![],
        omitted_optional_files: vec![],
    };
    let system = recipe
        .partitions
        .get("system")
        .context("system partition selection absent")?;
    let platform = unique_file(
        donor,
        Some(&system.donor),
        None,
        "etc/selinux/plat_sepolicy.cil",
    )?
    .context("selected donor platform policy absent")?;
    let root = platform
        .strip_suffix("plat_sepolicy.cil")
        .context("platform policy root")?;
    add(&mut selection, donor, Source::Donor, platform.clone(), true)?;
    add(
        &mut selection,
        donor,
        Source::Donor,
        format!("{root}mapping/{version}.cil"),
        true,
    )?;
    add(
        &mut selection,
        donor,
        Source::Donor,
        format!("{root}mapping/{version}.compat.cil"),
        false,
    )?;
    for (role, filename) in [
        ("system_ext", "system_ext_sepolicy.cil"),
        ("product", "product_sepolicy.cil"),
    ] {
        if let Some(pair) = recipe.partitions.get(role) {
            if let Some(policy) = unique_file(
                donor,
                Some(&pair.donor),
                None,
                &format!("etc/selinux/{filename}"),
            )? {
                let base = policy
                    .strip_suffix(filename)
                    .context("partition policy root")?;
                add(&mut selection, donor, Source::Donor, policy.clone(), true)?;
                add(
                    &mut selection,
                    donor,
                    Source::Donor,
                    format!("{base}mapping/{version}.cil"),
                    false,
                )?;
                if role == "system_ext" {
                    add(
                        &mut selection,
                        donor,
                        Source::Donor,
                        format!("{base}mapping/{version}.compat.cil"),
                        false,
                    )?;
                }
            } else {
                selection
                    .omitted_optional_files
                    .push(format!("{}/{filename}", pair.donor));
            }
        }
    }
    add(
        &mut selection,
        target,
        Source::Target,
        format!("{vendor_root}plat_pub_versioned.cil"),
        true,
    )?;
    add(
        &mut selection,
        target,
        Source::Target,
        format!("{vendor_root}vendor_sepolicy.cil"),
        true,
    )?;
    if let Some(odm) = unique_file(target, None, Some("odm"), "etc/selinux/odm_sepolicy.cil")? {
        add(&mut selection, target, Source::Target, odm, true)?;
    }
    add(
        &mut selection,
        donor,
        Source::Donor,
        format!("{root}plat_sepolicy_genfs_{genfs_version}.cil"),
        genfs_version >= 202504,
    )?;
    Ok(selection)
}
fn policy_header(path: &Path, expected: u32) -> Result<BinaryPolicy> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && (32..=64 * 1024 * 1024).contains(&meta.len()),
        "compiler policy output missing or outside size bounds"
    );
    let mut header = [0; 20];
    File::open(path)?.read_exact(&mut header)?;
    ensure!(
        header[..4] == 0xf97cff8cu32.to_le_bytes()
            && header[4..8] == 8u32.to_le_bytes()
            && &header[8..16] == b"SE Linux",
        "compiler output is not a kernel SELinux policy"
    );
    let version = u32::from_le_bytes(header[16..20].try_into()?);
    ensure!(
        version == expected,
        "compiled policy version differs from requested kernel policy version"
    );
    Ok(BinaryPolicy {
        file: "sepolicy".into(),
        bytes: meta.len(),
        sha256: hash_file(path)?,
        policy_version: version,
    })
}
fn invoke(
    compiler: &Compiler<'_>,
    args: Vec<String>,
    input: &Path,
    output: &Path,
) -> Result<(State, ToolResult)> {
    let logical = args.clone();
    let mut result = match gb_tools::run(
        compiler.sandbox,
        compiler.path,
        args,
        input,
        output,
        Duration::from_secs(120),
    ) {
        Ok(result) => result,
        Err(error) => error
            .downcast_ref::<ToolFailure>()
            .map(|e| e.result.clone())
            .ok_or(error)?,
    };
    result.program = "/host-tool".into();
    result.args = logical;
    let state =
        if result.stderr_truncated || result.stdout.len() >= 65536 || result.exit_code.is_none() {
            State::Unknown
        } else if result.exit_code == Some(0) {
            State::Compatible
        } else if result.exit_code == Some(255)
            || result.stderr.contains("Failed to compile")
            || result.stderr.contains("neverallow check failed")
        {
            State::PatchRequired
        } else {
            State::Unknown
        };
    Ok((state, result))
}
/// The caller caches this stage using manifests, recipe, options and tool identity.
pub fn compile(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
    options: Options,
    compiler: Compiler<'_>,
    output: &Path,
) -> Result<Report> {
    let Compiler {
        path: tool,
        sandbox,
        identity,
    } = compiler;
    let selection = select(donor, target, recipe, options)?;
    let tool = gb_tools::host_tool(tool, &[])?;
    ensure!(
        identity.get("binary_sha256").and_then(|v| v.as_str()) == Some(hash_file(&tool)?.as_str()),
        "configured compiler changed after identification"
    );
    ensure!(
        fs2::available_space(output)? > 256 * 1024 * 1024,
        "insufficient space for policy compilation"
    );
    let input = tempfile::tempdir_in(output)?;
    let work = tempfile::tempdir_in(output)?;
    let mut inputs = Vec::new();
    for unit in &selection.units {
        safe_relative(Path::new(&unit.path))?;
        let source = match unit.source {
            Source::Donor => donor,
            Source::Target => target,
        };
        let relative = format!(
            "{}/{path}",
            match unit.source {
                Source::Donor => "donor",
                Source::Target => "target",
            },
            path = unit.path
        );
        let path = input.path().join(&relative);
        std::fs::create_dir_all(path.parent().context("CIL staging parent")?)?;
        std::fs::write(path, text(source, &unit.path)?)?;
        inputs.push(format!("/input.img/{relative}"));
    }
    let mut args = vec![
        "-m".into(),
        "-M".into(),
        "true".into(),
        "-G".into(),
        "-c".into(),
        options.policy_version.to_string(),
        "-o".into(),
        "/output/sepolicy".into(),
        "-f".into(),
        "/output/file_contexts".into(),
    ];
    args.extend(inputs);
    let compiler = Compiler {
        path: &tool,
        sandbox,
        identity,
    };
    let (state, result) = invoke(&compiler, args.clone(), input.path(), work.path())?;
    ensure!(
        identity.get("binary_sha256").and_then(|v| v.as_str()) == Some(hash_file(&tool)?.as_str()),
        "compiler changed during invocation"
    );
    let mut binary_policy = None;
    if state == State::Compatible {
        let path = work.path().join("sepolicy");
        binary_policy = Some(policy_header(&path, options.policy_version)?);
        let destination = output.join("sepolicy");
        std::fs::copy(&path, &destination)?;
        File::open(&destination)?.sync_all()?;
    }
    let mut android_init_link_check = None;
    if state == State::PatchRequired {
        // Android 17 init uses -N for structural runtime recompilation. Retain
        // the failed strict audit; this artifact is not neverallow-certified.
        let link = tempfile::tempdir_in(output)?;
        args.insert(0, "-N".into());
        let (link_state, link_result) = invoke(&compiler, args, input.path(), link.path())?;
        let mut policy = None;
        if link_state == State::Compatible {
            let path = link.path().join("sepolicy");
            let mut binary = policy_header(&path, options.policy_version)?;
            binary.file = "init-linked-sepolicy".into();
            let dest = output.join(&binary.file);
            std::fs::copy(&path, &dest)?;
            File::open(dest)?.sync_all()?;
            policy = Some(binary);
        }
        android_init_link_check = Some(InitLinkCheck {
            state: link_state,
            neverallow_checks_enabled: false,
            result: link_result,
            binary_policy: policy,
        });
    }
    ensure!(
        identity.get("binary_sha256").and_then(|v| v.as_str()) == Some(hash_file(&tool)?.as_str()),
        "compiler changed during policy checks"
    );
    let report = Report { schema_version:1,state,bootable:false,runtime_verified:false,neverallow_checks_enabled:true,options,selection,donor_manifest_sha256:digest(&serde_json::to_vec(donor)?),target_manifest_sha256:digest(&serde_json::to_vec(target)?),recipe_sha256:digest(&serde_json::to_vec(recipe)?),tool:identity.clone(),result,binary_policy,
        android_init_link_check,artifact_cache_key:None,
        limitations:vec!["Compiler success is a static split-policy check, not proof of enforcement or device operation".into(),"Kernel policy version is explicitly supplied from target evidence; kernel load compatibility still needs runtime validation".into(),"File/property/service/seapp contexts, init permissions and APEX policy updates require separate validation".into(),"Strict neverallow audit is retained as the overall result; the separate Android-init link check uses the documented -N flag, preserves source neverallows, and does not change kernel enforcement".into()] };
    write_json(&output.join("report.json"), &report)?;
    Ok(report)
}
