//! Curated, committed text-source export without Git history or local artifacts.
//! The caller still audits licensing and privacy. Deny rules are safeguards, not
//! proof that arbitrary source is public. Filesystem ancestors and Git/tool
//! configuration are trusted/cooperatively accessed, not hostile swap-safe.
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const MAX_FILES: usize = 4096;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const GIT_BUDGET: usize = 4 * 1024 * 1024;
const LEDGER: &str = "PUBLIC_SOURCE_MANIFEST.json";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub root: PathBuf,
    pub include_roots: Vec<String>,
    pub include_files: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// UTF-8 lines, up to 128 nonempty literal patterns. Never serialized into
    /// the export, its digest or diagnostics. Keep this private input outside
    /// selected source; it is not an exported artifact.
    #[serde(default, skip_serializing)]
    pub deny_literals_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    /// Normalized portable permissions: 0644 or 0755, never special bits.
    pub mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub source_commit: String,
    pub git_version: String,
    pub files: Vec<Entry>,
    pub total_bytes: u64,
    pub file_ledger_sha256: String,
    pub git_history_included: bool,
    pub untracked_files_included: bool,
    pub automatic_privacy_or_licensing_certification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Object {
    mode: String,
    oid: String,
}

fn relative(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value.chars().all(|c| !c.is_control())
            && !value.contains(['\\', '\0', '\n', '\r', '\t', '\u{fffd}'])
            && Path::new(value)
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
            && !value.contains("//")
            && !value.ends_with('/'),
        "invalid export-relative path"
    );
    Ok(())
}

fn blocked_path(path: &str) -> bool {
    const BLOCKED: &[&str] = &[
        ".git",
        ".gb-cache",
        "artifacts",
        "target",
        "cache",
        "firmware",
        "logs",
        "keys",
        "secrets",
        "credentials",
        "private",
        "private-fixtures",
        "node_modules",
        ".ssh",
        ".gnupg",
        ".env",
    ];
    path.split('/')
        .any(|p| BLOCKED.contains(&p.to_ascii_lowercase().as_str()))
}

fn source_name(path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    if matches!(
        name,
        "LICENSE" | "NOTICE" | "COPYING" | "Makefile" | ".gitignore" | ".gitattributes"
    ) {
        return true;
    }
    matches!(
        Path::new(path)
            .extension()
            .and_then(|p| p.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(
            "rs" | "toml"
                | "lock"
                | "md"
                | "txt"
                | "json"
                | "py"
                | "sh"
                | "awk"
                | "java"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "cc"
                | "patch"
                | "diff"
                | "cil"
                | "te"
                | "xml"
                | "rc"
                | "prop"
                | "proto"
                | "aidl"
                | "map"
                | "def"
                | "lds"
                | "in"
                | "cmake"
                | "yml"
                | "yaml"
                | "license"
                | "inc"
                | "comp"
                | "js"
                | "service"
                | "config"
                | "mit"
                | "rules"
        )
    )
}

fn within(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|p| p.starts_with('/'))
}

fn git(root: &Path, args: &[String]) -> Result<String> {
    let root = root
        .to_str()
        .ok_or_else(|| anyhow!("source root is not UTF-8"))?;
    let mut command = vec![
        "--no-pager".into(),
        "--no-optional-locks".into(),
        "--literal-pathspecs".into(),
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-c".into(),
        "core.hooksPath=/dev/null".into(),
        "-C".into(),
        root.into(),
    ];
    command.extend_from_slice(args);
    let result = gb_core::run_tool_with_stdout_budget(
        Path::new("git"),
        &command,
        Duration::from_secs(30),
        GIT_BUDGET,
    )
    .map_err(|_| anyhow!("bounded Git inspection failed"))?;
    ensure!(
        result.stdout.len() < GIT_BUDGET && !result.stdout.contains('\u{fffd}'),
        "Git inventory is oversized or non-UTF-8"
    );
    Ok(result.stdout)
}

fn oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn tree(root: &Path, index: bool) -> Result<BTreeMap<String, Object>> {
    let args: Vec<String> = if index {
        ["ls-files", "--stage", "-z"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        ["ls-tree", "-r", "-z", "--full-tree", "HEAD"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    };
    let output = git(root, &args)?;
    ensure!(
        output.is_empty() || output.ends_with('\0'),
        "incomplete Git inventory"
    );
    let mut objects = BTreeMap::new();
    for record in output.split_terminator('\0') {
        let (metadata, path) = record
            .split_once('\t')
            .ok_or_else(|| anyhow!("invalid Git inventory"))?;
        relative(path)?;
        let fields: Vec<_> = metadata.split(' ').collect();
        ensure!(fields.len() == 3, "invalid Git object metadata");
        let hash = if index {
            ensure!(fields[2] == "0", "unmerged Git index is unsupported");
            fields[1]
        } else {
            // Submodules and links are rejected if selected below.
            fields[2]
        };
        ensure!(oid(hash), "invalid Git object ID");
        ensure!(
            objects
                .insert(
                    path.to_owned(),
                    Object {
                        mode: fields[0].into(),
                        oid: hash.into()
                    }
                )
                .is_none(),
            "duplicate Git path"
        );
    }
    Ok(objects)
}

fn regular_path(root: &Path, relative: &Path) -> Result<()> {
    let mut path = root.to_owned();
    for part in relative.components() {
        ensure!(
            matches!(part, Component::Normal(_)),
            "invalid source path component"
        );
        path.push(part);
        let meta = fs::symlink_metadata(&path).map_err(|_| anyhow!("source path unavailable"))?;
        ensure!(!meta.file_type().is_symlink(), "source symlink refused");
        if path != root.join(relative) {
            ensure!(meta.is_dir(), "source ancestor is not a directory");
        } else {
            ensure!(meta.is_file(), "source is not a regular file");
        }
    }
    Ok(())
}

fn read_text(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    let file = gb_core::open_regular_file(path, &mut options)
        .map_err(|_| anyhow!("regular source input unavailable"))?;
    let expected = file.metadata()?.len();
    ensure!(expected <= cap, "source input exceeds byte limit");
    let mut data = Vec::new();
    file.take(cap + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 == expected && !data.contains(&0),
        "source input changed or contains NUL"
    );
    std::str::from_utf8(&data).map_err(|_| anyhow!("source input is not UTF-8 text"))?;
    Ok(data)
}

fn suspicious(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.lines().any(|line| {
        let trimmed = line.trim();
        if (trimmed.starts_with("-----BEGIN ") && trimmed.ends_with("PRIVATE KEY-----"))
            || trimmed == "GIT binary patch"
        {
            return true;
        }
        let lower = line.to_ascii_lowercase();
        lower.match_indices("bearer ").any(|(at, _)| {
            let token = &line[at + 7..];
            token
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(b))
                .count()
                >= 16
        })
    })
}

fn raw_hashes(root: &Path, paths: &[PathBuf], expected: &[String]) -> Result<()> {
    for (chunk, expected) in paths.chunks(32).zip(expected.chunks(32)) {
        let mut args = vec!["hash-object".into(), "--no-filters".into(), "--".into()];
        for path in chunk {
            args.push(
                path.to_str()
                    .ok_or_else(|| anyhow!("hash input is not UTF-8"))?
                    .to_owned(),
            );
        }
        let output = git(root, &args)?;
        ensure!(
            output.lines().eq(expected.iter().map(String::as_str)),
            "selected source differs from committed raw bytes"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_directories(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            normalize_directories(&entry.path())?;
        }
    }
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

/// Publish into a new sibling-staged directory. Only committed, selected files
/// are copied, with no Git history. Requires Linux atomic no-replace publication.
/// All content/path refusal diagnostics omit offending values and private paths.
pub fn export(request: &Request, output: &Path) -> Result<Manifest> {
    gb_core::checkpoint()?;
    ensure!(
        request.schema_version == 1,
        "unsupported public export schema"
    );
    ensure!(
        request.include_roots.len() + request.include_files.len() > 0,
        "public export selection is empty"
    );
    ensure!(
        request.include_roots.len() + request.include_files.len() + request.exclude_paths.len()
            <= MAX_FILES,
        "export policy exceeds path limit"
    );
    for value in request
        .include_roots
        .iter()
        .chain(&request.include_files)
        .chain(&request.exclude_paths)
    {
        relative(value)?;
    }
    let root_meta =
        fs::symlink_metadata(&request.root).map_err(|_| anyhow!("source root unavailable"))?;
    ensure!(
        root_meta.is_dir() && !root_meta.file_type().is_symlink(),
        "source root must be a real directory"
    );
    let root = request
        .root
        .canonicalize()
        .map_err(|_| anyhow!("source root unavailable"))?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_meta =
        fs::symlink_metadata(parent).map_err(|_| anyhow!("export parent unavailable"))?;
    ensure!(
        parent_meta.is_dir() && !parent_meta.file_type().is_symlink(),
        "export parent must be a real directory"
    );
    let parent = parent
        .canonicalize()
        .map_err(|_| anyhow!("export parent unavailable"))?;
    let name = output
        .file_name()
        .and_then(|p| p.to_str())
        .ok_or_else(|| anyhow!("invalid output name"))?;
    relative(name)?;
    let destination = parent.join(name);
    ensure!(
        !destination.starts_with(&root) && !root.starts_with(&destination),
        "export destination overlaps source root"
    );
    ensure!(
        fs::symlink_metadata(&destination).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "export destination already exists or is unavailable"
    );
    let top = git(&root, &["rev-parse".into(), "--show-toplevel".into()])?;
    ensure!(
        Path::new(top.trim_end_matches('\n')) == root,
        "source root is not the Git worktree root"
    );
    let version = git(&root, &["--version".into()])?;
    let version = version
        .strip_prefix("git version ")
        .and_then(|p| p.split_whitespace().next())
        .ok_or_else(|| anyhow!("Git version unavailable"))?
        .to_owned();
    ensure!(
        version.len() <= 64 && version.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "Git version is unsupported"
    );
    let commit = git(
        &root,
        &["rev-parse".into(), "--verify".into(), "HEAD".into()],
    )?
    .trim()
    .to_owned();
    ensure!(oid(&commit), "invalid source commit");
    let head = tree(&root, false)?;
    let index = tree(&root, true)?;
    let selected: Vec<_> = head
        .keys()
        .filter(|path| {
            (request.include_files.contains(path)
                || request.include_roots.iter().any(|p| within(path, p)))
                && !request.exclude_paths.iter().any(|p| within(path, p))
        })
        .cloned()
        .collect();
    ensure!(
        index.keys().all(|path| {
            !((request.include_files.contains(path)
                || request.include_roots.iter().any(|p| within(path, p)))
                && !request.exclude_paths.iter().any(|p| within(path, p)))
                || head.contains_key(path)
        }),
        "selected index contains uncommitted additions"
    );
    ensure!(
        !selected.is_empty() && selected.len() <= MAX_FILES,
        "selected source count is outside limits"
    );
    for file in &request.include_files {
        ensure!(
            selected.contains(file),
            "explicit source file is untracked, excluded or absent"
        );
    }
    for directory in &request.include_roots {
        ensure!(
            selected
                .iter()
                .any(|p| p.starts_with(&format!("{directory}/"))),
            "included source root has no selected tracked files"
        );
    }
    let mut deny = Vec::new();
    if let Some(path) = &request.deny_literals_file {
        let data = read_text(path, 65536)?;
        for line in std::str::from_utf8(&data)
            .map_err(|_| anyhow!("invalid private deny policy"))?
            .lines()
        {
            ensure!(
                !line.is_empty() && line.len() <= 1024,
                "invalid private deny policy line"
            );
            deny.push(line.to_owned());
        }
        ensure!(
            !deny.is_empty() && deny.len() <= 128,
            "private deny policy count is outside limits"
        );
        let canonical = path
            .canonicalize()
            .map_err(|_| anyhow!("private deny policy unavailable"))?;
        ensure!(
            !selected.iter().any(|p| root.join(p) == canonical),
            "private deny policy cannot be exported"
        );
    }
    let temp = tempfile::Builder::new()
        .prefix(".public-source-")
        .tempdir_in(&parent)
        .map_err(|_| anyhow!("export staging unavailable"))?;
    let mut entries = Vec::new();
    let mut total = 0_u64;
    let mut copied = Vec::new();
    let mut originals = Vec::new();
    let mut objects = Vec::new();
    for path in &selected {
        gb_core::checkpoint()?;
        ensure!(
            path != LEDGER && !blocked_path(path) && source_name(path),
            "selected path is not permitted public source"
        );
        let object = &head[path];
        ensure!(
            matches!(object.mode.as_str(), "100644" | "100755") && index.get(path) == Some(object),
            "selected index differs from committed regular source"
        );
        regular_path(&root, Path::new(path))?;
        let original = root.join(path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let executable = fs::metadata(&original)?.permissions().mode() & 0o100 != 0;
            ensure!(
                executable == (object.mode == "100755"),
                "selected executable mode differs from committed source"
            );
        }
        let data = read_text(&original, MAX_FILE)?;
        ensure!(
            !suspicious(&data),
            "selected content has a private or binary signature"
        );
        ensure!(
            !deny
                .iter()
                .any(|d| path.contains(d) || data.windows(d.len()).any(|w| w == d.as_bytes())),
            "selected content matches private deny policy"
        );
        total = total
            .checked_add(data.len() as u64)
            .ok_or_else(|| anyhow!("export total overflow"))?;
        ensure!(total <= MAX_TOTAL, "export exceeds total source byte limit");
        let target = temp.path().join(path);
        fs::create_dir_all(
            target
                .parent()
                .ok_or_else(|| anyhow!("invalid source destination"))?,
        )?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        file.write_all(&data)?;
        let mode = if object.mode == "100755" {
            0o755
        } else {
            0o644
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        }
        file.sync_all()?;
        entries.push(Entry {
            path: path.clone(),
            sha256: gb_core::digest(&data),
            bytes: data.len() as u64,
            mode,
        });
        copied.push(target);
        originals.push(original);
        objects.push(object.oid.clone());
    }
    raw_hashes(&root, &copied, &objects)?;
    // Recheck original selection without running Git filters, hooks or source.
    raw_hashes(&root, &originals, &objects)?;
    let final_index = tree(&root, true)?;
    ensure!(
        selected.iter().all(|p| final_index.get(p) == head.get(p)),
        "selected index changed during export"
    );
    ensure!(
        final_index.keys().all(|path| {
            !((request.include_files.contains(path)
                || request.include_roots.iter().any(|p| within(path, p)))
                && !request.exclude_paths.iter().any(|p| within(path, p)))
                || head.contains_key(path)
        }),
        "selected index gained uncommitted additions during export"
    );
    ensure!(
        git(
            &root,
            &["rev-parse".into(), "--verify".into(), "HEAD".into()]
        )?
        .trim()
            == commit,
        "source commit changed during export"
    );
    let manifest = Manifest {
        schema_version: 1,
        source_commit: commit,
        git_version: version,
        file_ledger_sha256: gb_core::digest(&serde_json::to_vec(&entries)?),
        files: entries,
        total_bytes: total,
        git_history_included: false,
        untracked_files_included: false,
        automatic_privacy_or_licensing_certification: false,
    };
    gb_core::write_json(&temp.path().join(LEDGER), &manifest)
        .map_err(|_| anyhow!("export ledger publication failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path().join(LEDGER), fs::Permissions::from_mode(0o644))?;
        fs::File::open(temp.path().join(LEDGER))?.sync_all()?;
        normalize_directories(temp.path())?;
    }
    gb_core::checkpoint()?;
    gb_core::publish_directory(temp.path(), &destination)
        .map_err(|_| anyhow!("atomic public export publication failed"))?;
    Ok(manifest)
}

#[cfg(test)]
mod tests;
