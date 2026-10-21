//! Validate explicit init process labels against a pinned compiled policy.
//! libsepol, through sefcontext_compile, owns user/role/type/MLS semantics.
use anyhow::{Result, ensure};
use gb_core::{State, ToolFailure, ToolResult, hash_file, safe_relative};
use gb_framework::rro::PinnedFile;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitFile {
    pub source: String,
    pub input: PinnedFile,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub policy: PinnedFile,
    pub policy_version: u32,
    pub checker: PinnedFile,
    pub init_files: Vec<InitFile>,
    pub sandbox: gb_tools::Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 1024 * 1024)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [&mut r.policy, &mut r.checker]
            .into_iter()
            .chain(r.init_files.iter_mut().map(|f| &mut f.input))
        {
            if p.path.is_relative() {
                p.path = parent.join(&p.path);
            }
        }
        Ok(r)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Service,
    Exec,
    ExecBackground,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reference {
    pub source: String,
    pub line: usize,
    pub kind: ReferenceKind,
    pub service: Option<String>,
    pub context: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub context: String,
    pub state: State,
    pub references: Vec<Reference>,
    pub result: ToolResult,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub state: State,
    pub all_explicit_contexts_valid: bool,
    pub policy_sha256: String,
    pub policy_version: u32,
    pub source_sha256: BTreeMap<String, String>,
    pub checker: serde_json::Value,
    pub checks: Vec<Check>,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub limitations: Vec<String>,
}
fn label(s: &str) -> Result<String> {
    let s = s
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(s);
    ensure!(
        s.len() <= 512
            && s.split(':').count() >= 4
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_:-,.".contains(&c)),
        "unsupported, dynamic or malformed init process label"
    );
    Ok(s.into())
}
/// Explicit labels only. Full Android init grammar remains host_init_verifier's job.
/// Command arguments are deliberately never retained in this report.
pub fn references(source: &str, text: &str) -> Result<Vec<Reference>> {
    safe_relative(Path::new(source))?;
    ensure!(
        source.len() <= 1024
            && source
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-@+".contains(&b)),
        "unsafe init source name"
    );
    ensure!(
        text.len() <= 1024 * 1024 && !text.contains('\0'),
        "init text exceeds bounds or contains NUL"
    );
    let mut result = Vec::new();
    let mut statement = String::new();
    let mut first = 0;
    let mut service = None;
    let mut service_label = false;
    for (index, raw) in text.lines().enumerate() {
        if statement.is_empty() {
            first = index + 1;
        }
        let raw = raw.trim_end();
        let continued = raw.ends_with('\\') && !raw.trim_start().starts_with('#');
        statement.push_str(if continued {
            &raw[..raw.len() - 1]
        } else {
            raw
        });
        ensure!(statement.len() <= 65536, "init logical line exceeds bounds");
        if continued {
            statement.push(' ');
            continue;
        }
        let words: Vec<_> = statement.split_whitespace().collect();
        if !words.is_empty() && !words[0].starts_with('#') {
            if !statement.starts_with(char::is_whitespace) {
                service = if words[0] == "service" {
                    ensure!(words.len() >= 3, "malformed service declaration");
                    ensure!(
                        words[1].len() <= 256
                            && words[1]
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_.@-".contains(&c)),
                        "unsupported init service name"
                    );
                    Some(words[1].to_string())
                } else {
                    None
                };
                service_label = false;
            }
            if ["exec", "exec_background"].contains(&words[0]) && words.len() >= 2 {
                ensure!(
                    !words[1].contains('$'),
                    "dynamic exec context or executable is unsupported"
                );
            }
            let selected = if words[0] == "seclabel" {
                ensure!(
                    service.is_some()
                        && !service_label
                        && words.len() >= 2
                        && (words.len() == 2 || words[2].starts_with('#')),
                    "ambiguous init service label"
                );
                service_label = true;
                Some((ReferenceKind::Service, words[1]))
            } else if ["exec", "exec_background"].contains(&words[0])
                && words.len() >= 2
                && words[1].contains(':')
            {
                Some((
                    if words[0] == "exec" {
                        ReferenceKind::Exec
                    } else {
                        ReferenceKind::ExecBackground
                    },
                    words[1],
                ))
            } else {
                None
            };
            if let Some((kind, context)) = selected {
                result.push(Reference {
                    source: source.into(),
                    line: first,
                    kind,
                    service: service.clone(),
                    context: label(context)?,
                });
                ensure!(result.len() <= 4096, "init label reference budget exceeded");
            }
        }
        statement.clear();
    }
    ensure!(statement.is_empty(), "unterminated init line continuation");
    Ok(result)
}
fn pin(p: &PinnedFile, max: u64) -> Result<()> {
    let m = std::fs::symlink_metadata(&p.path)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.len() <= max
            && p.sha256.len() == 64
            && p.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && hash_file(&p.path)? == p.sha256,
        "pinned regular input differs or exceeds bounds: {}",
        p.path.display()
    );
    Ok(())
}
pub fn check(r: &Request, output: &Path) -> Result<Report> {
    ensure!(
        r.schema_version == 1
            && !r.init_files.is_empty()
            && r.init_files.len() <= 1024
            && !output.exists(),
        "invalid request or existing output"
    );
    r.sandbox.validate()?;
    pin(&r.policy, 64 * 1024 * 1024)?;
    pin(&r.checker, 64 * 1024 * 1024)?;
    super::policy_header(&r.policy.path, r.policy_version)?;
    let mut grouped: BTreeMap<String, Vec<Reference>> = BTreeMap::new();
    let mut source_sha256 = BTreeMap::new();
    let mut total = 0usize;
    for file in &r.init_files {
        pin(&file.input, 1024 * 1024)?;
        ensure!(
            source_sha256
                .insert(file.source.clone(), file.input.sha256.clone())
                .is_none(),
            "duplicate init source"
        );
        let mut text = String::new();
        std::fs::File::open(&file.input.path)?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut text)?;
        ensure!(
            text.len() <= 1024 * 1024 && gb_core::digest(text.as_bytes()) == file.input.sha256,
            "init text changed during bounded read"
        );
        total += text.len();
        ensure!(
            total <= 32 * 1024 * 1024,
            "combined init text budget exceeded"
        );
        for reference in references(&file.source, &text)? {
            grouped
                .entry(reference.context.clone())
                .or_default()
                .push(reference);
        }
    }
    ensure!(
        !grouped.is_empty() && grouped.len() <= 256,
        "no explicit labels or distinct label budget exceeded"
    );
    for p in [&r.policy, &r.checker]
        .into_iter()
        .chain(r.init_files.iter().map(|f| &f.input))
    {
        gb_core::separate_from_input(&p.path, output)?;
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let input = tempfile::tempdir_in(staging.path())?;
    let copied = input.path().join("policy");
    let bytes = gb_core::copy_stream(
        std::fs::File::open(&r.policy.path)?.take(64 * 1024 * 1024 + 1),
        std::fs::File::create(&copied)?,
    )?;
    ensure!(
        bytes <= 64 * 1024 * 1024 && hash_file(&copied)? == r.policy.sha256,
        "policy changed during bounded copy"
    );
    let tool = gb_tools::host_tool(&r.checker.path, &[input.path()])?;
    let identity = gb_tools::identity(&tool, &r.sandbox)?;
    let mut checks = Vec::new();
    for (index, (context, references)) in grouped.into_iter().enumerate() {
        gb_core::checkpoint()?;
        let work = tempfile::tempdir_in(staging.path())?;
        std::fs::write(
            input.path().join("label.txt"),
            format!("/__gb_init_context/{index} {context}\n"),
        )?;
        let args = [
            "-r",
            "-p",
            "/input.img/policy",
            "-o",
            "/output/label.bin",
            "/input.img/label.txt",
        ]
        .map(str::to_owned)
        .to_vec();
        let result = match gb_tools::run(
            &r.sandbox,
            &tool,
            args,
            input.path(),
            work.path(),
            Duration::from_secs(30),
        ) {
            Ok(v) => v,
            Err(e) => e
                .downcast_ref::<ToolFailure>()
                .map(|f| f.result.clone())
                .ok_or(e)?,
        };
        let valid = result.exit_code == Some(0)
            && !result.stderr_truncated
            && result.stderr.trim().is_empty()
            && std::fs::metadata(work.path().join("label.bin"))
                .is_ok_and(|m| m.is_file() && m.len() > 0);
        let rejected = !result.stderr_truncated
            && result.exit_code.is_some_and(|n| n != 0)
            && result
                .stderr
                .contains(&format!("has invalid context {context}"));
        checks.push(Check {
            context,
            state: if valid {
                State::Compatible
            } else if rejected {
                State::PatchRequired
            } else {
                State::Unknown
            },
            references,
            result,
        });
    }
    let all_explicit_contexts_valid = checks.iter().all(|c| c.state == State::Compatible);
    let state = if checks.iter().any(|c| c.state == State::PatchRequired) {
        State::PatchRequired
    } else if all_explicit_contexts_valid {
        State::Compatible
    } else {
        State::Unknown
    };
    pin(&r.policy, 64 * 1024 * 1024)?;
    pin(&r.checker, 64 * 1024 * 1024)?;
    for file in &r.init_files {
        pin(&file.input, 1024 * 1024)?;
    }
    let report = Report { schema_version: 1, state, all_explicit_contexts_valid, policy_sha256: r.policy.sha256.clone(), policy_version: r.policy_version,
        source_sha256, checker: identity, checks, bootable: false, runtime_verified: false,
        limitations: vec!["Only explicit service seclabel and exec/exec_background process labels in supplied init sources are checked. Source selection must match the assembled images; imports, property activation and absent files are separate checks.".into(),
            "The libsepol check validates user, role, type and MLS membership. It does not prove transition/entrypoint permissions, executable availability, HAL behavior or successful boot.".into(),
            "Dynamic labels, unsupported syntax and oversized source inputs are refused. Full init syntax requires host_init_verifier.".into()] };
    drop(input);
    gb_core::write_json(&staging.path().join("init-process-report.json"), &report)?;
    gb_core::publish_directory(staging.path(), output)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_named_and_continued_exec_contexts_without_arguments() {
        let r = references("vendor_a/etc/init/a.rc", "# header\nservice qti /system/bin/sh private-argument\n    seclabel \"u:r:qti-testscripts:s0\" # note\non init\n    exec_background u:r:vendor-qti-testscripts:s0 \\\n        -- /vendor/bin/sh secret-argument\n    exec -- /system/bin/true\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].service.as_deref(), Some("qti"));
        assert_eq!(r[0].line, 3);
        assert_eq!(r[1].line, 5);
        assert_eq!(r[1].kind, ReferenceKind::ExecBackground);
        assert!(!serde_json::to_string(&r).unwrap().contains("argument"));
    }
    #[test]
    fn refuses_ambiguous_dynamic_and_unterminated_inputs() {
        for text in [
            "    seclabel u:r:init:s0\n",
            "service x /bin/x\n    seclabel u:r:x:s0\n    seclabel u:r:y:s0\n",
            "service x /bin/x\n    seclabel ${ctx}\n",
            "on init\n    exec ${ctx} -- /bin/x\n",
            "on init\n    exec u:r:init:s0 \\\n",
        ] {
            assert!(references("a.rc", text).is_err(), "{text}");
        }
        assert!(references("../escape.rc", "").is_err());
        assert!(references("a.rc", "\0").is_err());
    }
    #[test]
    fn retains_every_use_of_a_repeated_context() {
        let r = references("a.rc", "service x /bin/x\n    seclabel u:r:init:s0\non boot\n    exec u:r:init:s0 root -- /bin/y\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].kind, ReferenceKind::Exec);
        assert_eq!(r[0].context, r[1].context);
    }
}
