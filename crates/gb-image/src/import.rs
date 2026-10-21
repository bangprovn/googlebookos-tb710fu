//! Exact regular-file imports from checked, read-only ext4 source images.
use crate::metadata::Metadata;
use anyhow::{Context, Result, ensure};
use gb_core::{Format, ToolResult, hash_file, safe_relative, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub image: PathBuf,
    pub image_sha256: String,
    pub source_path: String,
    pub destination: String,
    pub sha256: String,
    pub debugfs: PathBuf,
    pub checker: PathBuf,
    pub apex_name: Option<String>,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        let sha = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            sha(&self.image_sha256) && sha(&self.sha256),
            "import requires pinned image and file SHA256"
        );
        for p in [&self.source_path, &self.destination] {
            safe_relative(Path::new(p))?;
            ensure!(
                p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./-@+".contains(&b)),
                "unsafe import path"
            );
        }
        if let Some(name) = &self.apex_name {
            ensure!(
                !name.is_empty()
                    && name.len() <= 255
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid retained APEX identity"
            );
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub image_sha256: String,
    pub source_path: String,
    pub destination: String,
    pub sha256: String,
    pub metadata: Metadata,
    pub apex: Option<gb_core::ApexPackage>,
    pub tools: Vec<serde_json::Value>,
}
#[derive(Debug, Clone)]
pub struct Resolved {
    pub file: PathBuf,
    pub report: Report,
}
pub(crate) fn diagnostics(r: &ToolResult) -> Result<()> {
    ensure!(
        !r.stderr_truncated
            && r.stdout.len() < 65536
            && r.stderr
                .lines()
                .all(|l| l.trim().is_empty() || l.starts_with("debugfs ")),
        "read-only debugfs diagnostics indicate failure: {}",
        r.stderr
    );
    Ok(())
}
pub(crate) fn field<'a>(text: &'a str, name: &str) -> Result<&'a str> {
    let values: Vec<_> = text
        .lines()
        .flat_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words
                .windows(2)
                .filter(move |v| v[0] == name)
                .map(|v| v[1])
                .collect::<Vec<_>>()
        })
        .collect();
    ensure!(values.len() == 1, "missing/ambiguous debugfs field {name}");
    Ok(values[0])
}
fn stat(text: &str) -> Result<Metadata> {
    ensure!(
        field(text, "Type:")? == "regular",
        "only regular ext4 files may be imported"
    );
    let mode = u16::from_str_radix(field(text, "Mode:")?, 8)?;
    ensure!(mode & !0o7777 == 0, "invalid ext4 permission bits");
    let links: u32 = field(text, "Links:")?.parse()?;
    ensure!(
        links == 1,
        "hardlinked ext4 imports require a separate group recipe"
    );
    let time = field(text, "mtime:")?
        .strip_prefix("0x")
        .context("missing raw ext4 mtime")?;
    let mut parts = time.split(':');
    let low = u32::from_str_radix(parts.next().context("missing mtime")?, 16)?;
    let extra = parts
        .next()
        .map(|v| u32::from_str_radix(v, 16))
        .transpose()?
        .unwrap_or(0);
    ensure!(parts.next().is_none(), "invalid ext4 mtime encoding");
    let sec = (low as i32 as i64) + (((extra & 3) as i64) << 32);
    ensure!(
        sec >= 0 && extra >> 2 < 1_000_000_000,
        "unsupported ext4 timestamp"
    );
    Ok(Metadata {
        mode: mode | 0o100000,
        uid: field(text, "User:")?.parse()?,
        gid: field(text, "Group:")?.parse()?,
        size: field(
            text.lines()
                .find(|l| l.trim_start().starts_with("User:"))
                .context("missing ownership line")?,
            "Size:",
        )?
        .parse()?,
        nlink: links,
        mtime: sec as u64,
        mtime_nsec: extra >> 2,
        xattrs: BTreeMap::new(),
    })
}
fn xattr_names(text: &str) -> Result<BTreeMap<String, usize>> {
    let mut result = BTreeMap::new();
    let mut in_attributes = false;
    let mut total = 0usize;
    for line in text.lines() {
        if line == "Extended attributes:" {
            in_attributes = true;
            continue;
        }
        if !in_attributes {
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        let mut tokens = line.split_whitespace();
        let name = tokens.next().context("xattr name missing")?;
        ensure!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            "unrepresentable xattr name"
        );
        let size = tokens
            .next()
            .context("xattr size missing")?
            .trim_start_matches('(')
            .trim_end_matches(')')
            .parse::<usize>()?;
        total = total.checked_add(size).context("xattr size overflow")?;
        ensure!(
            total <= 1024 * 1024
                && result.len() < 256
                && result.insert(name.into(), size).is_none(),
            "ext4 xattr budget/duplicate failure"
        );
    }
    Ok(result)
}
#[cfg(unix)]
pub(crate) fn source_identity(m: &std::fs::Metadata) -> Vec<i128> {
    use std::os::unix::fs::MetadataExt;
    vec![
        m.dev() as i128,
        m.ino() as i128,
        m.len() as i128,
        m.mtime() as i128,
        m.mtime_nsec() as i128,
        m.ctime() as i128,
        m.ctime_nsec() as i128,
    ]
}
#[cfg(not(unix))]
pub(crate) fn source_identity(m: &std::fs::Metadata) -> Vec<i128> {
    vec![
        m.len() as i128,
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|t| t.as_nanos() as i128)
            .unwrap_or(-1),
    ]
}
struct Prepared {
    source: File,
    identity: Vec<i128>,
    image: PathBuf,
    sha256: String,
    debugfs: PathBuf,
    tools: Vec<serde_json::Value>,
}
impl Prepared {
    fn unchanged(&self) -> Result<()> {
        ensure!(
            source_identity(&self.source.metadata()?) == self.identity
                && source_identity(&std::fs::metadata(&self.image)?) == self.identity,
            "import source identity changed during batch"
        );
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        use std::io::{Seek, SeekFrom};
        self.unchanged()?;
        self.source.seek(SeekFrom::Start(0))?;
        ensure!(
            gb_core::hash_reader(&mut self.source)? == self.sha256,
            "import source changed during read-only processing"
        );
        self.unchanged()
    }
}
fn prepare(request: &Request, sandbox: &gb_tools::Sandbox, out: &Path) -> Result<Prepared> {
    request.validate()?;
    sandbox.validate()?;
    gb_core::separate_from_input(&request.image, out)?;
    let mut source = File::open(&request.image)?;
    let identity = source_identity(&source.metadata()?);
    ensure!(
        gb_core::hash_reader(&mut source)? == request.image_sha256,
        "import source image SHA256 mismatch"
    );
    gb_partition::inspect(&mut File::open(&request.image)?, &Format::Ext4)?;
    let debugfs = gb_tools::host_tool(&request.debugfs, &[&request.image])?;
    let checker = gb_tools::host_tool(&request.checker, &[&request.image])?;
    let tools = vec![
        gb_tools::identity(&debugfs, sandbox)?,
        gb_tools::identity(&checker, sandbox)?,
    ];
    let scratch = tempfile::tempdir_in(out)?;
    gb_tools::run(
        sandbox,
        &checker,
        vec!["-f".into(), "-n".into(), "/input.img".into()],
        &request.image,
        scratch.path(),
        Duration::from_secs(1200),
    )?;
    let prepared = Prepared {
        source,
        identity,
        image: request.image.clone(),
        sha256: request.image_sha256.clone(),
        debugfs,
        tools,
    };
    prepared.unchanged()?;
    Ok(prepared)
}
fn extract_prepared(
    request: &Request,
    sandbox: &gb_tools::Sandbox,
    out: &Path,
    prepared: &Prepared,
) -> Result<Report> {
    prepared.unchanged()?;
    let debugfs = &prepared.debugfs;
    let scratch = tempfile::tempdir_in(out)?;
    let lookup = format!("stat /{}", request.source_path);
    let observed = gb_tools::run(
        sandbox,
        debugfs,
        vec!["-R".into(), lookup, "/input.img".into()],
        &request.image,
        scratch.path(),
        Duration::from_secs(30),
    )?;
    diagnostics(&observed)?;
    let mut metadata = stat(&observed.stdout)?;
    ensure!(
        metadata.size <= 16 * 1024 * 1024 * 1024
            && fs2::available_space(out)?
                > metadata
                    .size
                    .checked_add(256 * 1024 * 1024)
                    .context("import disk estimate overflow")?,
        "import exceeds size/disk budget"
    );
    let attributes = xattr_names(&observed.stdout)?;
    let mut commands = format!("dump /{} /output/payload\n", request.source_path);
    for (i, name) in attributes.keys().enumerate() {
        commands.push_str(&format!(
            "ea_get -f /output/xattr-{i} /{} {name}\n",
            request.source_path
        ));
    }
    let command_file = scratch.path().join("commands.txt");
    std::fs::write(&command_file, &commands)?;
    gb_tools::run_mounted(
        sandbox,
        debugfs,
        vec![
            "-f".into(),
            "/inputs/commands.txt".into(),
            "/input.img".into(),
        ],
        gb_tools::Inputs {
            primary: &request.image,
            extra: &[gb_tools::ReadOnlyInput {
                name: "commands.txt",
                path: &command_file,
            }],
            source_date_epoch: Some(0),
        },
        out,
        Duration::from_secs(1200),
    )
    .and_then(|r| {
        diagnostics(&r)?;
        Ok(r)
    })?;
    ensure!(
        std::fs::read_to_string(&command_file)? == commands,
        "import command file changed"
    );
    for (i, (name, size)) in attributes.iter().enumerate() {
        let path = out.join(format!("xattr-{i}"));
        ensure!(
            std::fs::symlink_metadata(&path)?.is_file()
                && std::fs::metadata(&path)?.len() == *size as u64,
            "extracted xattr size/type differs"
        );
        metadata.xattrs.insert(name.clone(), std::fs::read(&path)?);
        std::fs::remove_file(path)?;
    }
    let file = out.join("payload");
    ensure!(
        std::fs::symlink_metadata(&file)?.is_file()
            && file.canonicalize()?.starts_with(out.canonicalize()?)
            && std::fs::metadata(&file)?.len() == metadata.size
            && hash_file(&file)? == request.sha256,
        "imported file size/type/SHA256 differs"
    );
    let apex = if let Some(name) = &request.apex_name {
        let extracted = gb_apex::extract(
            &mut File::open(&file)?,
            &request.destination,
            &request.sha256,
            scratch.path(),
        )?;
        ensure!(
            extracted.package.name == *name,
            "retained APEX identity differs"
        );
        Some(extracted.package)
    } else {
        None
    };
    prepared.unchanged()?;
    let report = Report {
        schema_version: 1,
        image_sha256: request.image_sha256.clone(),
        source_path: request.source_path.clone(),
        destination: request.destination.clone(),
        sha256: request.sha256.clone(),
        metadata,
        apex,
        tools: prepared.tools.clone(),
    };
    write_json(&out.join("import-report.json"), &report)?;
    Ok(report)
}

pub fn extract(request: &Request, sandbox: &gb_tools::Sandbox, out: &Path) -> Result<Report> {
    let mut prepared = prepare(request, sandbox, out)?;
    let report = extract_prepared(request, sandbox, out, &prepared)?;
    prepared.finish()?;
    Ok(report)
}

/// One checked source and toolchain per batch; each file retains its own hash and metadata.
/// No batch output may be published until the final source digest succeeds.
pub fn extract_batch(
    requests: &[Request],
    sandbox: &gb_tools::Sandbox,
    out: &Path,
) -> Result<Vec<Resolved>> {
    let first = requests.first().context("empty import batch")?;
    ensure!(requests.len() <= 4096, "import batch budget exceeded");
    for request in requests {
        request.validate()?;
        ensure!(
            request.image == first.image
                && request.image_sha256 == first.image_sha256
                && request.debugfs == first.debugfs
                && request.checker == first.checker,
            "import batch mixes source images or toolchains"
        );
    }
    let mut prepared = prepare(first, sandbox, out)?;
    let mut resolved = Vec::new();
    for (index, request) in requests.iter().enumerate() {
        gb_core::checkpoint()?;
        let dir = out.join(format!("import-{index}"));
        std::fs::create_dir(&dir)?;
        let report = extract_prepared(request, sandbox, &dir, &prepared)?;
        resolved.push(Resolved {
            file: dir.join("payload"),
            report,
        });
    }
    prepared.finish()?;
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    const STAT: &str = "Inode: 18 Type: regular Mode: 0644 Flags: 0x80000\nUser: 70000 Group: 2345 Project: 0 Size: 1234\nLinks: 1 Blockcount: 3\n mtime: 0x495c0780:00000000 -- Thu Jan 1 2009\nExtended attributes:\n  security.selinux (26) = label\nEXTENTS:\n";
    #[test]
    fn ownership_and_raw_timestamps_are_parsed_without_timezone_guesses() {
        let m = stat(STAT).unwrap();
        assert_eq!(m.uid, 70000);
        assert_eq!(m.mode, 0o100644);
        assert_eq!(m.mtime, 1230768000);
        assert_eq!(xattr_names(STAT).unwrap()["security.selinux"], 26);
        let m = stat(&STAT.replace("495c0780:00000000", "ffffffff:00000001")).unwrap();
        assert_eq!(m.mtime, 4294967295);
        assert!(stat(&STAT.replace("Links: 1", "Links: 2")).is_err());
    }
    #[test]
    fn missing_ambiguous_and_injectable_metadata_is_rejected() {
        assert!(stat("").is_err());
        assert!(stat(&format!("{STAT}User: 42\n")).is_err());
        assert!(xattr_names(&STAT.replace("security.selinux", "security.bad;quit")).is_err());
        assert!(xattr_names(&STAT.replace("(26)", "(999999999)")).is_err());
    }
    #[test]
    fn pinned_batch_rejects_source_replacement_and_mixed_requests() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image");
        std::fs::write(&image, b"original").unwrap();
        let source = File::open(&image).unwrap();
        let prepared = Prepared {
            identity: source_identity(&source.metadata().unwrap()),
            source,
            image: image.clone(),
            sha256: gb_core::digest(b"original"),
            debugfs: "debugfs".into(),
            tools: vec![],
        };
        assert!(prepared.unchanged().is_ok());
        let replacement = dir.path().join("replacement");
        std::fs::write(&replacement, b"original").unwrap();
        std::fs::rename(replacement, &image).unwrap();
        assert!(prepared.unchanged().is_err());
        let first = Request {
            image,
            image_sha256: "a".repeat(64),
            source_path: "file".into(),
            destination: "file".into(),
            sha256: "b".repeat(64),
            debugfs: "debugfs".into(),
            checker: "e2fsck".into(),
            apex_name: None,
        };
        let mut other = first.clone();
        other.image_sha256 = "c".repeat(64);
        let error =
            extract_batch(&[first, other], &gb_tools::Sandbox::Bubblewrap, dir.path()).unwrap_err();
        assert!(error.to_string().contains("mixes source images"));
    }
    #[test]
    fn versioned_hidl_names_are_safe_but_debugfs_commands_are_not() {
        let mut r = Request {
            image: "stock.img".into(),
            image_sha256: "a".repeat(64),
            source_path: "system/lib64/android.hidl.token@1.0.so".into(),
            destination: "lib64/gb-hidl/android.hidl.token@1.0.so".into(),
            sha256: "b".repeat(64),
            debugfs: "debugfs".into(),
            checker: "e2fsck".into(),
            apex_name: None,
        };
        assert!(r.validate().is_ok());
        r.source_path = "system/lib64/libc++.so".into();
        r.destination = "lib64/gb-hidl/libc++.so".into();
        assert!(r.validate().is_ok());
        for path in [
            "../escape",
            "lib/name;quit",
            "lib/name\nquit",
            "lib/name space",
            "lib/\"name\"",
        ] {
            r.source_path = path.into();
            assert!(r.validate().is_err(), "{path}");
        }
    }
}
