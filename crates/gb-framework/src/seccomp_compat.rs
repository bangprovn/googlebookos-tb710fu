//! Evidence-backed, append-only compatibility deltas for existing Minijail
//! allowlists. This is not a replacement policy parser/compiler or filter bypass.
use crate::rro::PinnedFile;
use anyhow::{Context, Result, ensure};
use gb_core::{checkpoint, digest, publish_directory, separate_from_input, write_json};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub donor_fingerprint: String,
    pub target_vendor_fingerprint: String,
    pub daemon: String,
    pub policy: PinnedFile,
    /// A small, pinned excerpt captured from the target, not a fabricated trace.
    pub observation: PinnedFile,
}

fn bounded(input: &PinnedFile) -> Result<String> {
    ensure!(
        fs::symlink_metadata(&input.path)?.is_file(),
        "regular input required"
    );
    ensure!(
        fs::metadata(&input.path)?.len() <= 65536,
        "input exceeds 64 KiB"
    );
    let mut text = String::new();
    fs::File::open(&input.path)?
        .take(65537)
        .read_to_string(&mut text)?;
    ensure!(
        text.len() <= 65536 && !text.contains('\0'),
        "invalid bounded text"
    );
    ensure!(
        digest(text.as_bytes()) == input.sha256,
        "input digest differs"
    );
    Ok(text)
}

fn append_lseek(policy: &str) -> Result<String> {
    let mut count = 0;
    for line in policy.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Preserve expressions as opaque bytes for Minijail. Refuse containers,
        // includes, multiline extensions and unknown syntax instead of guessing.
        ensure!(
            !line.starts_with('@') && !line.ends_with('\\'),
            "unsupported policy directive"
        );
        let (name, expression) = line
            .split_once(':')
            .context("expected syscall allowlist line")?;
        let name = name.trim();
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "invalid syscall name"
        );
        ensure!(!expression.trim().is_empty(), "empty syscall expression");
        ensure!(
            name != "lseek",
            "lseek already has a rule; no automatic replacement"
        );
        count += 1;
    }
    ensure!(count > 0, "empty allowlist");
    let mut output = policy.to_owned();
    if !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str("\n# Googlebook port: observed target Minijail lseek failure.\nlseek: 1\n");
    Ok(output)
}

pub fn render(request: &Request, destination: &Path) -> Result<()> {
    checkpoint()?;
    ensure!(request.schema_version == 1, "unsupported schema");
    for fingerprint in [
        &request.donor_fingerprint,
        &request.target_vendor_fingerprint,
    ] {
        ensure!(
            !fingerprint.is_empty()
                && fingerprint.len() <= 512
                && !fingerprint.chars().any(char::is_control),
            "invalid firmware fingerprint"
        );
    }
    ensure!(
        !request.daemon.is_empty()
            && request.daemon.len() <= 64
            && request
                .daemon
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid daemon tag"
    );
    ensure!(!destination.exists(), "output exists");
    for input in [&request.policy, &request.observation] {
        separate_from_input(&input.path, destination)?;
    }
    let policy = bounded(&request.policy)?;
    let observation = bounded(&request.observation)?;
    let tag = format!(" {}:", request.daemon);
    ensure!(
        observation.lines().any(|line| line.contains(&tag)
            && line.contains("libminijail[")
            && line.ends_with(": blocked syscall: lseek")),
        "matching observed lseek failure required"
    );
    let patched = append_lseek(&policy)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let output = staging.path().join("policy");
    fs::write(&output, &patched)?;
    fs::File::open(&output)?.sync_all()?;
    write_json(
        &staging.path().join("report.json"),
        &serde_json::json!({
            "schema_version":1,
            "status":"candidate_requires_target_minijail_runtime_validation",
            "request":request,
            "source_sha256":digest(policy.as_bytes()),
            "patched_sha256":digest(patched.as_bytes()),
            "original_bytes_preserved_as_prefix":patched.starts_with(&policy),
            "added_syscalls":["lseek"],
            "filter_disabled":false,
            "original_expressions_modified":false,
            "consumer_policy_association":"configured; must verify against target runtime",
            "minijail_compile_verified":false,
            "runtime_verified":false,
            "redistribution_authorized":false,
            "external_prerequisites":["Owner-provided original firmware policies and applicable redistribution rights"]
        }),
    )?;
    // Inputs changing during generation invalidate publication.
    ensure!(
        bounded(&request.policy)? == policy && bounded(&request.observation)? == observation,
        "source changed"
    );
    checkpoint()?;
    publish_directory(staging.path(), destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_filters_and_refuses_existing_rules_or_unknown_directives() -> Result<()> {
        let input = "# fixture\nmmap: arg2 in ~PROT_EXEC || arg2 in ~PROT_WRITE\nsocket: arg0 == AF_UNIX\nread: 1";
        let output = append_lseek(input)?;
        assert!(output.starts_with(input));
        assert_eq!(
            output
                .lines()
                .filter(|l| !l.starts_with('#') && l.contains(':'))
                .count(),
            4
        );
        for invalid in [
            "lseek: return 1\n",
            "@include /missing\n",
            "not a policy",
            "# only a comment",
            "read: \n",
        ] {
            assert!(append_lseek(invalid).is_err());
        }
        Ok(())
    }
    #[test]
    fn requires_pinned_matching_evidence_and_never_replaces_output() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("original");
        let e = d.path().join("observed");
        fs::write(&p, "read: 1\n")?;
        fs::write(&e, "E other: libminijail[7]: blocked syscall: lseek\n")?;
        let mut r = Request {
            schema_version: 1,
            donor_fingerprint: "donor".into(),
            target_vendor_fingerprint: "target".into(),
            daemon: "fixture".into(),
            policy: PinnedFile {
                path: p.clone(),
                sha256: gb_core::hash_file(&p)?,
            },
            observation: PinnedFile {
                path: e.clone(),
                sha256: gb_core::hash_file(&e)?,
            },
        };
        let out = d.path().join("candidate");
        assert!(render(&r, &out).is_err());
        assert!(!out.exists());
        fs::write(&e, "E fixture: libminijail[7]: blocked syscall: lseek\n")?;
        assert!(render(&r, &out).is_err()); // Changed evidence is not silently trusted.
        r.observation.sha256 = gb_core::hash_file(&e)?;
        render(&r, &out)?;
        assert!(render(&r, &out).is_err());
        assert_eq!(fs::read_to_string(&p)?, "read: 1\n");
        assert_eq!(
            fs::read_to_string(out.join("policy"))?
                .matches("lseek: 1")
                .count(),
            1
        );
        Ok(())
    }
}
