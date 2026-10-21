//! Validate file regexes and literal context labels with libselinux/libsepol.
//! Named/service applicability, access rules and runtime are separate checks.
use anyhow::{Context, Result, ensure};
use gb_core::{
    FirmwareManifest, State, ToolFailure, ToolResult, digest, hash_file, safe_relative, write_json,
};
use gb_framework::Recipe;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Property,
    Service,
    Hwservice,
    Vndservice,
    Seapp,
    Keystore2Key,
    TeeService,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextFile {
    pub source: super::Source,
    pub path: String,
    pub sha256: String,
    pub kind: Kind,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub path: String,
    pub line: usize,
    pub selector: String,
    pub context: String,
    pub kind: Kind,
    pub property_value_type: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub kind: Kind,
    pub selector: String,
    pub first: Label,
    pub second: Label,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReference {
    pub input: PathBuf,
    pub sha256: String,
    pub policy_version: u32,
    pub policy_report_sha256: String,
    pub strict_audit_passed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub policy: PolicyReference,
    pub feature_observation: Option<super::context_patch::FeatureObservation>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub state: State,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub donor_manifest_sha256: String,
    pub target_manifest_sha256: String,
    pub recipe_sha256: String,
    pub policy_sha256: String,
    pub policy_version: u32,
    pub policy_report_sha256: String,
    pub strict_policy_audit_passed: bool,
    pub files: Vec<ContextFile>,
    pub labels: Vec<Label>,
    pub conflicts: Vec<Conflict>,
    pub tool: serde_json::Value,
    pub file_contexts_check: ToolResult,
    pub literal_labels_check: ToolResult,
    pub overlays: Vec<super::context_patch::Overlay>,
    pub feature_observation_sha256: Option<String>,
    pub limitations: Vec<String>,
}
pub(super) fn kind(path: &str) -> Option<Kind> {
    let name = path.rsplit('/').next()?;
    for (suffix, k) in [
        ("_file_contexts", Kind::File),
        ("_property_contexts", Kind::Property),
        ("_hwservice_contexts", Kind::Hwservice),
        ("_tee_service_contexts", Kind::TeeService),
        ("_service_contexts", Kind::Service),
        ("vndservice_contexts", Kind::Vndservice),
        ("_seapp_contexts", Kind::Seapp),
        ("_keystore2_key_contexts", Kind::Keystore2Key),
    ] {
        if name.ends_with(suffix) {
            return Some(k);
        }
    }
    None
}
pub fn publish_overlays(report: &Report, destination: &Path) -> Result<()> {
    ensure!(
        !report.overlays.is_empty(),
        "no context transformations to publish"
    );
    ensure!(
        !destination.exists(),
        "context overlay destination already exists"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".context-staging-")
        .tempdir_in(parent)?;
    let mut hashes = BTreeMap::new();
    let mut dirs = BTreeSet::new();
    for overlay in &report.overlays {
        safe_relative(Path::new(&overlay.path))?;
        ensure!(
            digest(overlay.content.as_bytes()) == overlay.output_sha256,
            "context overlay digest mismatch"
        );
        let path = staging.path().join(&overlay.path);
        let dir = path.parent().context("context parent")?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&path, &overlay.content)?;
        std::fs::File::open(&path)?.sync_all()?;
        for ancestor in dir
            .ancestors()
            .take_while(|p| p.starts_with(staging.path()))
        {
            dirs.insert(ancestor.to_path_buf());
        }
        hashes.insert(overlay.path.clone(), overlay.output_sha256.clone());
    }
    let metadata = serde_json::to_vec_pretty(report)?;
    let path = staging.path().join("context-report.json");
    std::fs::write(&path, &metadata)?;
    std::fs::File::open(path)?.sync_all()?;
    hashes.insert("context-report.json".into(), digest(&metadata));
    let ledger = hashes
        .iter()
        .map(|(p, h)| format!("{h}  {p}\n"))
        .collect::<String>();
    let path = staging.path().join("SHA256SUMS");
    std::fs::write(&path, ledger)?;
    std::fs::File::open(path)?.sync_all()?;
    for dir in dirs.iter().rev() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    std::fs::File::open(staging.path())?.sync_all()?;
    gb_core::publish_directory(staging.path(), destination)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn identifier(s: &str) -> Result<&str> {
    ensure!(
        !s.is_empty()
            && s.len() <= 512
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "unsupported SELinux identifier"
    );
    Ok(s)
}
fn literal(context: &str) -> Result<&str> {
    let parts: Vec<_> = context.splitn(4, ':').collect();
    ensure!(
        parts.len() == 4
            && !parts[3].is_empty()
            && context.len() <= 4096
            && !context
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b == b'\0'),
        "invalid context literal"
    );
    for v in &parts[..3] {
        identifier(v)?;
    }
    Ok(context)
}
pub fn parse(file: &ContextFile, text: &str) -> Result<Vec<Label>> {
    ensure!(
        text.len() <= 16 * 1024 * 1024 && !text.contains('\0'),
        "context input exceeds limit or contains NUL"
    );
    let mut result = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        ensure!(line.len() <= 16384, "context line exceeds bound");
        let fields: Vec<_> = line.split_whitespace().collect();
        if file.kind == Kind::File {
            continue;
        } // The official parser owns regex/flags.
        if file.kind == Kind::Seapp {
            ensure!(
                fields.first() != Some(&"neverallow"),
                "unprocessed seapp assertions are unsupported"
            );
            let mut values = BTreeMap::new();
            for item in &fields {
                let (k, v) = item.split_once('=').context("seapp requires key=value")?;
                ensure!(
                    !v.is_empty() && values.insert(k.to_ascii_lowercase(), v).is_none(),
                    "empty or duplicate seapp field"
                );
            }
            let selectors = values
                .iter()
                .filter(|(k, _)| !["domain", "type", "levelfrom", "level"].contains(&k.as_str()))
                .map(|(k, v)| format!("{k}={}", v.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(" ");
            for (key, role) in [("domain", "r"), ("type", "object_r")] {
                if let Some(value) = values.get(key) {
                    identifier(value)?;
                    let level = values.get("level").copied().unwrap_or("s0");
                    let context = format!("u:{role}:{value}:{level}");
                    literal(&context)?;
                    result.push(Label {
                        path: file.path.clone(),
                        line: index + 1,
                        selector: format!("{selectors} output={key}"),
                        context,
                        kind: file.kind,
                        property_value_type: None,
                    });
                }
            }
            ensure!(
                values.contains_key("domain") || values.contains_key("type"),
                "seapp entry has no output label"
            );
        } else {
            ensure!(fields.len() >= 2, "context mapping lacks label");
            literal(fields[1])?;
            let match_mode = if file.kind == Kind::Property {
                ensure!(fields.len() <= 1024, "property fields exceed limit");
                if fields.len() > 2 {
                    ensure!(
                        ["exact", "prefix"].contains(&fields[2]),
                        "unknown property match mode"
                    );
                    fields[2]
                } else {
                    "prefix"
                }
            } else {
                ensure!(fields.len() == 2, "unexpected named-context fields");
                "exact"
            };
            if file.kind == Kind::Keystore2Key {
                let id = fields[0].parse::<u32>()?;
                ensure!(
                    id < (1u32 << 31),
                    "keystore namespace outside Android range"
                );
            }
            let property_value_type = if file.kind == Kind::Property && fields.len() > 3 {
                ensure!(
                    ["string", "bool", "int", "uint", "double", "enum"].contains(&fields[3]),
                    "unsupported property value type"
                );
                ensure!(
                    (fields[3] == "enum" && fields.len() > 4)
                        || (fields[3] != "enum" && fields.len() == 4),
                    "invalid property value type arguments"
                );
                Some(fields[3..].join(" "))
            } else {
                None
            };
            result.push(Label {
                path: file.path.clone(),
                line: index + 1,
                selector: format!("{} {match_mode}", fields[0]),
                context: fields[1].into(),
                kind: file.kind,
                property_value_type,
            });
        }
        ensure!(
            result.len() <= 100_000,
            "context mapping count exceeds limit"
        );
    }
    Ok(result)
}
fn select(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
) -> Result<Vec<ContextFile>> {
    donor.validate()?;
    target.validate()?;
    recipe.check_sources(donor, target)?;
    let mut files = Vec::new();
    for role in ["system", "system_ext", "product", "vendor", "odm"] {
        let (manifest, source, prefix) = if ["vendor", "odm"].contains(&role) {
            (target, super::Source::Target, None)
        } else {
            let Some(pair) = recipe.partitions.get(role) else {
                continue;
            };
            (donor, super::Source::Donor, Some(pair.donor.as_str()))
        };
        let mut partitions = BTreeSet::new();
        for artifact in &manifest.artifacts {
            if artifact.path.contains("/payload/") || !artifact.path.contains("/etc/selinux/") {
                continue;
            }
            let part = artifact.path.split('/').next().unwrap_or("");
            let actual = part
                .strip_suffix("_a")
                .or_else(|| part.strip_suffix("_b"))
                .unwrap_or(part);
            if actual != role || prefix.is_some_and(|p| part != p) {
                continue;
            }
            let Some(kind) = kind(&artifact.path) else {
                continue;
            };
            partitions.insert(part);
            ensure!(
                manifest
                    .inventory
                    .metadata_text
                    .contains_key(&artifact.path),
                "context text missing: {}; collect checksum-pinned metadata first",
                artifact.path
            );
            files.push(ContextFile {
                source,
                path: artifact.path.clone(),
                sha256: artifact.sha256.clone(),
                kind,
            });
        }
        ensure!(
            partitions.len() <= 1,
            "ambiguous hardware context partition for {role}"
        );
    }
    ensure!(
        files
            .iter()
            .any(|f| f.kind == Kind::File && f.source == super::Source::Donor)
            && files
                .iter()
                .any(|f| f.kind == Kind::File && f.source == super::Source::Target),
        "framework and retained hardware file contexts are required"
    );
    Ok(files)
}
fn run(
    checker: &super::Compiler<'_>,
    name: &str,
    input: &Path,
    output: &Path,
) -> Result<ToolResult> {
    let args = vec![
        "-r".into(),
        "-p".into(),
        "/input.img/policy".into(),
        "-o".into(),
        format!("/output/{name}.bin"),
        format!("/input.img/{name}.txt"),
    ];
    let mut result = match gb_tools::run(
        checker.sandbox,
        checker.path,
        args.clone(),
        input,
        output,
        Duration::from_secs(120),
    ) {
        Ok(r) => r,
        Err(e) => e
            .downcast_ref::<ToolFailure>()
            .map(|f| f.result.clone())
            .ok_or(e)?,
    };
    result.program = "/host-tool".into();
    result.args = args;
    Ok(result)
}
pub fn check(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
    inputs: &Inputs,
    checker: super::Compiler<'_>,
    output: &Path,
) -> Result<Report> {
    let policy = &inputs.policy;
    let files = select(donor, target, recipe)?;
    let overlays =
        super::context_patch::generate(donor, target, recipe, inputs.feature_observation.as_ref())?;
    super::policy_header(&policy.input, policy.policy_version)?;
    ensure!(
        hash_file(&policy.input)? == policy.sha256,
        "context validation policy digest mismatch"
    );
    ensure!(
        checker
            .identity
            .get("binary_sha256")
            .and_then(|v| v.as_str())
            == Some(hash_file(checker.path)?.as_str()),
        "context checker changed after identification"
    );
    let input = tempfile::tempdir_in(output)?;
    let work = tempfile::tempdir_in(output)?;
    std::fs::copy(&policy.input, input.path().join("policy"))?;
    let mut file_text = String::new();
    let mut labels = Vec::new();
    for file in &files {
        safe_relative(Path::new(&file.path))?;
        let manifest = if file.source == super::Source::Donor {
            donor
        } else {
            target
        };
        let original = manifest
            .inventory
            .metadata_text
            .get(&file.path)
            .context("selected text absent")?;
        let text = if file.source == super::Source::Donor {
            overlays
                .iter()
                .find(|o| o.path == file.path)
                .map(|o| &o.content)
                .unwrap_or(original)
        } else {
            original
        };
        if file.kind == Kind::File {
            file_text.push_str(text);
            file_text.push('\n');
        } else {
            labels.extend(parse(file, text)?);
        }
    }
    ensure!(
        labels.len() <= 100_000 && file_text.len() <= 32 * 1024 * 1024,
        "combined context inventory exceeds bounds"
    );
    let mut seen = BTreeMap::new();
    let mut conflicts = Vec::new();
    for label in &labels {
        if let Some(first) = seen.get(&(label.kind, label.selector.clone())) {
            let first: &Label = first;
            if first.context != label.context
                || (first.property_value_type.is_some()
                    && label.property_value_type.is_some()
                    && first.property_value_type != label.property_value_type)
            {
                conflicts.push(Conflict {
                    kind: label.kind,
                    selector: label.selector.clone(),
                    first: first.clone(),
                    second: label.clone(),
                });
            }
        } else {
            seen.insert((label.kind, label.selector.clone()), label.clone());
        }
    }
    let distinct: BTreeSet<_> = labels.iter().map(|l| &l.context).collect();
    let label_text = distinct
        .into_iter()
        .enumerate()
        .map(|(i, context)| format!("/__gb_context_validation/{i} {context}\n"))
        .collect::<String>();
    std::fs::write(input.path().join("files.txt"), file_text)?;
    std::fs::write(input.path().join("labels.txt"), label_text)?;
    let file_contexts_check = run(&checker, "files", input.path(), work.path())?;
    let literal_labels_check = run(&checker, "labels", input.path(), work.path())?;
    ensure!(
        hash_file(&policy.input)? == policy.sha256,
        "policy changed during context checks"
    );
    ensure!(
        checker
            .identity
            .get("binary_sha256")
            .and_then(|v| v.as_str())
            == Some(hash_file(checker.path)?.as_str()),
        "context checker changed during invocation"
    );
    let results = [&file_contexts_check, &literal_labels_check];
    let state = if results.iter().any(|r| {
        r.stderr_truncated
            || r.stdout.len() >= 65536
            || r.exit_code.is_none()
            || r.stderr
                .lines()
                .any(|s| s.starts_with("bwrap:") || s.starts_with("docker:"))
    }) {
        State::Unknown
    } else if results.iter().all(|r| r.exit_code == Some(0)) && conflicts.is_empty() {
        State::Compatible
    } else if results
        .iter()
        .any(|r| matches!(r.exit_code, Some(125..=127)))
    {
        State::Unknown
    } else {
        State::PatchRequired
    };
    let report=Report {schema_version:1,state,bootable:false,runtime_verified:false,donor_manifest_sha256:digest(&serde_json::to_vec(donor)?),target_manifest_sha256:digest(&serde_json::to_vec(target)?),recipe_sha256:digest(&serde_json::to_vec(recipe)?),policy_sha256:policy.sha256.clone(),policy_version:policy.policy_version,policy_report_sha256:policy.policy_report_sha256.clone(),strict_policy_audit_passed:policy.strict_audit_passed,files,labels,conflicts,tool:checker.identity.clone(),file_contexts_check,literal_labels_check,overlays,feature_observation_sha256:inputs.feature_observation.as_ref().map(|f|f.sha256.clone()),
        limitations:vec!["Checks file regex/context syntax, literal user/role/type/MLS validity and conflicting identical named selectors; it does not prove file labeling, access permissions or hardware operation".into(),"Synthetic file paths validate named labels through libsepol; service/property/keystore/tee attributes and binder access are separate requirements".into(),"Seapp output labels are checked at their fixed/minimum MLS level; UID-derived category calculations, selector precedence and app-signature/seinfo bindings remain unverified".into(),"APEX-specific context overrides, init permissions, MAC permissions XML and runtime enforcement require separate checks".into(),"Compiled context binaries are temporary analysis outputs with precompiled regexes omitted; no architecture-specific binary is published".into()]};
    write_json(&output.join("report.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(kind: Kind) -> ContextFile {
        ContextFile {
            source: super::super::Source::Donor,
            path: "system_a/system/etc/selinux/test_contexts".into(),
            sha256: "0".repeat(64),
            kind,
        }
    }
    #[test]
    fn typed_properties_and_seapp_outputs_keep_their_meaning() {
        let rows=parse(&file(Kind::Property),"# comment\nfoo u:object_r:foo_prop:s0 exact enum on off\nlegacy. u:object_r:old_prop:s0\n").unwrap();
        assert_eq!(rows[0].property_value_type.as_deref(), Some("enum on off"));
        assert_eq!(rows[1].selector, "legacy. prefix");
        let rows = parse(
            &file(Kind::Seapp),
            "user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user",
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].context, "u:r:platform_app:s0");
        assert_eq!(rows[1].context, "u:object_r:app_data_file:s0");
    }
    #[test]
    fn malformed_context_and_unsupported_properties_are_errors() {
        for text in [
            "foo missing",
            "foo u:object_r:t:s0 wildcard bool",
            "foo u:object_r:t:s0 exact enum",
            "foo u:object_r:t:s0 exact mysterious",
        ] {
            assert!(parse(&file(Kind::Property), text).is_err());
        }
        assert!(parse(&file(Kind::Seapp), "user=_app domain=t domain=other").is_err());
        assert!(parse(&file(Kind::Seapp), "neverallow user=.* domain=bad").is_err());
        assert!(parse(&file(Kind::Keystore2Key), "2147483648 u:object_r:t:s0").is_err());
    }
    #[test]
    fn context_kinds_do_not_mix_tee_vnd_or_framework_services() {
        assert_eq!(kind("plat_tee_service_contexts"), Some(Kind::TeeService));
        assert_eq!(kind("vndservice_contexts"), Some(Kind::Vndservice));
        assert_eq!(kind("vendor_service_contexts"), Some(Kind::Service));
        assert_eq!(kind("plat_hwservice_contexts"), Some(Kind::Hwservice));
    }
}
