//! Metadata-preserving EROFS builds through the mature Android tool.
use anyhow::{Context, Result, ensure};
use gb_core::{checkpoint, digest, hash_file, safe_relative, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub path: String,
    pub input: PathBuf,
    pub sha256: String,
    pub original_sha256: String,
}
/// New regular file with explicit Android metadata; no implicit host ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Addition {
    pub path: String,
    pub input: PathBuf,
    pub sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub mtime: u64,
    pub selinux: String,
    /// Explicit Linux VFS revision-2 file capabilities; never inferred from host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<FileCapabilities>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCapabilities {
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
}
impl FileCapabilities {
    fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            (self.permitted | self.inheritable) >> 41 == 0,
            "unknown Linux capability bits (supported range 0..=40)"
        );
        let mut b = Vec::with_capacity(20);
        for value in [
            0x02000000u32 | u32::from(self.effective),
            self.permitted as u32,
            self.inheritable as u32,
            (self.permitted >> 32) as u32,
            (self.inheritable >> 32) as u32,
        ] {
            b.extend_from_slice(&value.to_le_bytes());
        }
        Ok(b)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub mtime: u64,
    pub selinux: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub partition: String,
    pub input: PathBuf,
    pub sha256: String,
    pub max_bytes: u64,
    /// Explicit LZ4 cluster bound, accepted only within the source's existing limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_cluster_bytes: Option<u32>,
    #[serde(default)]
    pub patches: Vec<Patch>,
    #[serde(default)]
    pub imports: Vec<super::import::Request>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additions: Vec<Addition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directories: Vec<Directory>,
    pub mkfs: PathBuf,
    pub fsck: PathBuf,
    pub dump: PathBuf,
    pub sandbox: gb_tools::Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [&mut r.input, &mut r.mkfs, &mut r.fsck, &mut r.dump] {
            if p.is_relative() {
                *p = parent.join(&*p);
            }
        }
        for p in &mut r.patches {
            if p.input.is_relative() {
                p.input = parent.join(&p.input);
            }
        }
        for p in &mut r.additions {
            if p.input.is_relative() {
                p.input = parent.join(&p.input);
            }
        }
        for import in &mut r.imports {
            for path in [&mut import.image, &mut import.debugfs, &mut import.checker] {
                if path.is_relative() {
                    *path = parent.join(&*path);
                }
            }
        }
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && !self.id.is_empty()
                && self.revision > 0
                && ["system", "system_ext", "product"].contains(&self.partition.as_str()),
            "invalid userspace assembly request"
        );
        self.sandbox.validate()?;
        if let Some(cluster) = self.compression_cluster_bytes {
            ensure!(
                cluster.is_power_of_two() && (4096..=1048576).contains(&cluster),
                "invalid compression cluster size"
            );
        }
        let valid = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            valid(&self.sha256)
                && self.max_bytes > 0
                && (!self.patches.is_empty()
                    || !self.imports.is_empty()
                    || !self.additions.is_empty()
                    || !self.directories.is_empty()),
            "assembly requires pinned source, size limit and transformations"
        );
        let mut paths = BTreeSet::new();
        for directory in &self.directories {
            safe_relative(Path::new(&directory.path))?;
            ensure!(
                directory
                    .path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./-@+".contains(&b))
                    && paths.insert(Path::new(&directory.path).components().collect::<PathBuf>())
                    && directory.mode <= 0o777
                    && directory.selinux.starts_with("u:object_r:")
                    && directory.selinux.ends_with(":s0")
                    && directory.selinux.len() <= 128
                    && directory
                        .selinux
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_:".contains(&b))
                    && directory.selinux.split(':').count() == 4,
                "invalid/conflicting new directory metadata"
            );
        }
        for p in &self.patches {
            safe_relative(Path::new(&p.path))?;
            ensure!(
                p.path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./-@+".contains(&b))
                    && paths.insert(Path::new(&p.path).components().collect::<PathBuf>())
                    && valid(&p.sha256)
                    && valid(&p.original_sha256),
                "invalid/duplicate guarded image patch"
            );
        }
        for import in &self.imports {
            import.validate()?;
            ensure!(
                paths.insert(
                    Path::new(&import.destination)
                        .components()
                        .collect::<PathBuf>()
                ),
                "duplicate/conflicting import destination"
            );
        }
        for p in &self.additions {
            if let Some(caps) = &p.capabilities {
                caps.encode()?;
                ensure!(
                    p.uid == 0 && p.mode & 0o022 == 0 && p.mode & 0o111 != 0,
                    "capability-bearing additions require a root-owned executable without group/other writes"
                );
            }
            safe_relative(Path::new(&p.path))?;
            ensure!(
                p.path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./-@+".contains(&b))
                    && paths.insert(Path::new(&p.path).components().collect::<PathBuf>())
                    && valid(&p.sha256)
                    && p.mode <= 0o777
                    && p.selinux.starts_with("u:object_r:")
                    && p.selinux.ends_with(":s0")
                    && p.selinux.len() <= 128
                    && p.selinux
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_:".contains(&b))
                    && p.selinux.split(':').count() == 4,
                "invalid/conflicting new file or explicit metadata"
            );
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub avb_signed: bool,
    pub partition: String,
    pub source_sha256: String,
    pub image_sha256: String,
    pub image_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_cluster_bytes: Option<u32>,
    pub request_sha256: String,
    pub metadata: BTreeMap<String, super::metadata::Metadata>,
    pub verified_tree_entries: usize,
    pub decoded_content_equivalence: bool,
    pub full_metadata_equivalence: bool,
    pub tools: Vec<serde_json::Value>,
    #[serde(default)]
    pub imports: Vec<super::import::Report>,
    pub limitations: Vec<String>,
}
fn uuid(bytes: &[u8]) -> String {
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
fn check_lz4_cluster(sb: &[u8], config: &[u8], requested: u32) -> Result<()> {
    ensure!(
        sb.len() >= 128 && config.len() == 16,
        "truncated LZ4 compression configuration"
    );
    ensure!((9..=16).contains(&sb[12]), "invalid filesystem block size");
    let block = 1u32 << sb[12];
    ensure!(
        u32::from_le_bytes(sb[80..84].try_into()?) & 2 != 0
            && u16::from_le_bytes(sb[84..86].try_into()?) == 1,
        "explicit clusters require existing LZ4-only big-cluster support"
    );
    ensure!(
        u16::from_le_bytes(config[0..2].try_into()?) == 14,
        "unsupported LZ4 configuration length"
    );
    let max_blocks = u16::from_le_bytes(config[4..6].try_into()?) as u32;
    ensure!(
        requested.is_power_of_two()
            && requested >= block
            && requested <= 1048576
            && max_blocks > 0
            && requested <= max_blocks * block,
        "requested cluster exceeds source's proven compression bound"
    );
    Ok(())
}
fn pax(builder: &mut tar::Builder<File>, headers: Vec<(String, Vec<u8>)>) -> Result<()> {
    // erofs-utils validates numeric fields even in PAX pseudo entries. The tar
    // crate's convenience writer leaves those fields blank, so populate them.
    if !headers.is_empty() {
        let mut payload = Vec::new();
        for (name, value) in headers {
            let mut suffix = format!(" {name}=").into_bytes();
            suffix.extend_from_slice(&value);
            let mut length = suffix.len() + 2;
            loop {
                let actual = length.to_string().len() + suffix.len() + 1;
                if actual == length {
                    break;
                }
                length = actual;
            }
            payload.extend_from_slice(length.to_string().as_bytes());
            payload.extend_from_slice(&suffix);
            payload.push(b'\n');
        }
        let mut h = tar::Header::new_ustar();
        h.set_path("PaxHeaders/metadata")?;
        h.set_uid(0);
        h.set_gid(0);
        h.set_mode(0);
        h.set_mtime(0);
        h.set_size(payload.len() as u64);
        h.set_entry_type(tar::EntryType::XHeader);
        h.set_cksum();
        builder.append(&h, payload.as_slice())?;
    }
    Ok(())
}
fn append(
    builder: &mut tar::Builder<File>,
    path: &str,
    m: &super::metadata::Metadata,
    input: Option<&Path>,
) -> Result<()> {
    let mut headers = Vec::new();
    for (name, value) in &m.xattrs {
        headers.push((format!("SCHILY.xattr.{name}"), value.clone()));
    }
    if m.mtime_nsec != 0 {
        headers.push((
            "mtime".into(),
            format!("{}.{:09}", m.mtime, m.mtime_nsec).into_bytes(),
        ));
    }
    headers.push(("path".into(), path.as_bytes().to_vec()));
    if m.mode & 0o170000 == 0o120000 {
        use std::os::unix::ffi::OsStrExt;
        let target = std::fs::read_link(input.context("symlink input missing")?)?;
        headers.push(("linkpath".into(), target.as_os_str().as_bytes().to_vec()));
    }
    pax(builder, headers)?;
    let mut h = tar::Header::new_ustar();
    h.set_uid(m.uid as u64);
    h.set_gid(m.gid as u64);
    h.set_mode((m.mode & 0o7777) as u32);
    h.set_mtime(m.mtime);
    if let Some(input) = input {
        if m.mode & 0o170000 == 0o120000 {
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_link_name("link")?;
            h.set_size(0);
            h.set_cksum();
            h.set_path("entry")?;
            h.set_cksum();
            builder.append(&h, std::io::empty())?;
        } else {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(std::fs::metadata(input)?.len());
            h.set_cksum();
            h.set_path("entry")?;
            h.set_cksum();
            builder.append(&h, File::open(input)?)?;
        }
    } else {
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_cksum();
        h.set_path("entry")?;
        h.set_cksum();
        builder.append(&h, std::io::empty())?;
    }
    Ok(())
}
// Compare decoded namespace and content without following image-supplied links.
fn tree_inventory(root: &Path) -> Result<BTreeMap<PathBuf, (String, String)>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        checkpoint()?;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            let relative = path.strip_prefix(root)?.to_owned();
            let item = if metadata.is_symlink() {
                use std::os::unix::ffi::OsStrExt;
                (
                    "symlink".into(),
                    digest(std::fs::read_link(&path)?.as_os_str().as_bytes()),
                )
            } else if metadata.is_dir() {
                pending.push(path.clone());
                ("directory".into(), String::new())
            } else if metadata.is_file() {
                ("file".into(), hash_file(&path)?)
            } else {
                anyhow::bail!("unsupported special decoded inode: {}", relative.display());
            };
            ensure!(result.len() < 500_000, "decoded tree entry limit exceeded");
            result.insert(relative, item);
        }
    }
    Ok(result)
}
pub fn build(request: &Request, out: &Path) -> Result<Report> {
    request.validate()?;
    let mut staging = Vec::new();
    let mut imports = Vec::new();
    for request_import in &request.imports {
        let dir = tempfile::tempdir_in(out)?;
        let report = super::import::extract(request_import, &request.sandbox, dir.path())?;
        imports.push(super::import::Resolved {
            file: dir.path().join("payload"),
            report,
        });
        staging.push(dir);
    }
    build_resolved(request, &imports, out)
}
pub fn build_resolved(
    request: &Request,
    imports: &[super::import::Resolved],
    out: &Path,
) -> Result<Report> {
    request.validate()?;
    gb_core::separate_from_input(&request.input, out)?;
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "assembly base SHA256 mismatch"
    );
    let mut base = File::open(&request.input)?;
    gb_partition::inspect(&mut base, &gb_core::Format::Erofs)?;
    let sb = gb_partition::read_at(&mut base, 1024, 128)?;
    if let Some(cluster) = request.compression_cluster_bytes {
        let config = gb_partition::read_at(&mut base, 1024 + 128 + u64::from(sb[13]) * 16, 16)?;
        check_lz4_cluster(&sb, &config, cluster)?;
    }
    let shift = sb[12];
    ensure!(
        (9..=16).contains(&shift),
        "unsupported filesystem block size"
    );
    ensure!(
        u16::from_le_bytes(sb[86..88].try_into()?) == 0
            && u32::from_le_bytes(sb[80..84].try_into()?) & 0x80 == 0,
        "standalone legacy-addressed EROFS required"
    );
    let fs_bytes = (u32::from_le_bytes(sb[36..40].try_into()?) as u64)
        .checked_mul(1u64 << shift)
        .context("filesystem size overflow")?;
    ensure!(
        fs_bytes <= std::fs::metadata(&request.input)?.len() && fs_bytes <= request.max_bytes,
        "source filesystem exceeds image/partition bounds"
    );
    ensure!(
        fs2::available_space(out)?
            > fs_bytes.checked_mul(3).context("disk estimate overflow")? + 256 * 1024 * 1024,
        "insufficient assembly staging space"
    );
    let inputs: Vec<_> = std::iter::once(request.input.as_path())
        .chain(request.patches.iter().map(|p| p.input.as_path()))
        .chain(request.additions.iter().map(|p| p.input.as_path()))
        .collect();
    let mut tools = Vec::new();
    for path in [&request.mkfs, &request.fsck, &request.dump] {
        let tool = gb_tools::host_tool(path, &inputs)?;
        tools.push(gb_tools::identity(&tool, &request.sandbox)?);
    }
    let scratch = tempfile::tempdir_in(out)?;
    gb_tools::run(
        &request.sandbox,
        &request.fsck,
        vec!["--extract".into(), "/input.img".into()],
        &request.input,
        scratch.path(),
        Duration::from_secs(1200),
    )?;
    let original_entries = super::metadata::inventory(&request.input)?;
    // The verified Android host-tool bundle drops TAR nanoseconds. Refuse
    // affected sources before rebuilding rather than silently normalizing them.
    ensure!(
        original_entries
            .values()
            .all(|e| e.metadata.mtime_nsec == 0),
        "nonzero inode nanosecond timestamps require a separately verified capable image tool"
    );
    let mut seen = BTreeSet::new();
    let mut decoded_bytes = 0u64;
    for entry in original_entries.values() {
        if entry.metadata.mode & 0o170000 == 0o100000 && seen.insert(entry.nid) {
            decoded_bytes = decoded_bytes
                .checked_add(entry.metadata.size)
                .context("decoded data size overflow")?;
        }
    }
    for import in imports {
        decoded_bytes = decoded_bytes
            .checked_add(import.report.metadata.size)
            .context("import staging size overflow")?;
    }
    for patch in &request.patches {
        decoded_bytes = decoded_bytes
            .checked_add(std::fs::metadata(&patch.input)?.len())
            .context("replacement staging size overflow")?;
    }
    for addition in &request.additions {
        decoded_bytes = decoded_bytes
            .checked_add(std::fs::metadata(&addition.input)?.len())
            .context("addition staging size overflow")?;
    }
    ensure!(
        fs2::available_space(out)?
            > decoded_bytes
                .checked_mul(2)
                .and_then(|v| v.checked_add(fs_bytes.checked_mul(2)?))
                .and_then(|v| v.checked_add(512 * 1024 * 1024))
                .context("metadata-based staging estimate overflow")?,
        "insufficient space for decoded files, metadata TAR and rebuilt image"
    );
    let mut metadata: BTreeMap<_, _> = original_entries
        .iter()
        .map(|(path, e)| (path.clone(), e.metadata.clone()))
        .collect();
    for patch in &request.patches {
        checkpoint()?;
        gb_core::separate_from_input(&patch.input, out)?;
        ensure!(
            hash_file(&patch.input)? == patch.sha256,
            "replacement SHA256 mismatch"
        );
        let path = format!("/{}", patch.path);
        let meta = metadata
            .get(&path)
            .context("replacement path absent from image")?;
        ensure!(
            meta.mode & 0o170000 == 0o100000 && meta.nlink == 1,
            "patch must address an existing, non-hardlinked regular file"
        );
    }
    ensure!(
        imports.len() == request.imports.len(),
        "resolved import count differs"
    );
    let mut directories: Vec<_> = request.directories.iter().collect();
    directories.sort_by_key(|d| (Path::new(&d.path).components().count(), &d.path));
    for directory in &directories {
        let destination = format!("/{}", directory.path);
        let parent = Path::new(&destination)
            .parent()
            .context("directory parent absent")?
            .to_str()
            .context("invalid directory parent")?;
        ensure!(
            !metadata.contains_key(&destination)
                && metadata
                    .get(parent)
                    .is_some_and(|m| m.mode & 0o170000 == 0o040000),
            "new directory conflicts or parent is absent/non-directory"
        );
        let mut label = directory.selinux.as_bytes().to_vec();
        label.push(0);
        metadata.insert(
            destination,
            super::metadata::Metadata {
                mode: 0o040000 | directory.mode,
                uid: directory.uid,
                gid: directory.gid,
                size: 0,
                nlink: 2,
                mtime: directory.mtime,
                mtime_nsec: 0,
                xattrs: BTreeMap::from([("security.selinux".into(), label)]),
            },
        );
    }
    for (wanted, import) in request.imports.iter().zip(imports) {
        let observed = &import.report;
        ensure!(
            observed.image_sha256 == wanted.image_sha256
                && observed.source_path == wanted.source_path
                && observed.destination == wanted.destination
                && observed.sha256 == wanted.sha256
                && observed.metadata.mode & 0o170000 == 0o100000
                && observed.metadata.nlink == 1
                && observed.metadata.mtime_nsec == 0
                && std::fs::symlink_metadata(&import.file)?.is_file()
                && std::fs::metadata(&import.file)?.len() == observed.metadata.size
                && hash_file(&import.file)? == wanted.sha256,
            "resolved import does not match pinned request or supported metadata"
        );
        ensure!(
            observed.apex.as_ref().map(|a| &a.name) == wanted.apex_name.as_ref(),
            "resolved APEX import identity differs"
        );
        gb_core::separate_from_input(&wanted.image, out)?;
        gb_core::separate_from_input(&import.file, out)?;
        let destination = format!("/{}", wanted.destination);
        ensure!(
            !metadata.contains_key(&destination),
            "import destination already exists"
        );
        let parent = Path::new(&destination)
            .parent()
            .context("import parent absent")?
            .to_str()
            .context("invalid import parent")?;
        ensure!(
            metadata
                .get(parent)
                .is_some_and(|m| m.mode & 0o170000 == 0o040000),
            "import requires an existing directory parent"
        );
        metadata.insert(destination, observed.metadata.clone());
    }
    for addition in &request.additions {
        checkpoint()?;
        gb_core::separate_from_input(&addition.input, out)?;
        let info = std::fs::symlink_metadata(&addition.input)?;
        ensure!(
            info.is_file() && hash_file(&addition.input)? == addition.sha256,
            "new file must be a pinned regular host file"
        );
        let destination = format!("/{}", addition.path);
        ensure!(
            !metadata.contains_key(&destination),
            "new file destination already exists"
        );
        let parent = Path::new(&destination)
            .parent()
            .context("new file parent absent")?
            .to_str()
            .context("invalid new file parent")?;
        ensure!(
            metadata
                .get(parent)
                .is_some_and(|m| m.mode & 0o170000 == 0o040000),
            "new file requires an existing directory parent"
        );
        let mut label = addition.selinux.as_bytes().to_vec();
        label.push(0);
        let mut xattrs = BTreeMap::from([("security.selinux".into(), label)]);
        if let Some(caps) = &addition.capabilities {
            xattrs.insert("security.capability".into(), caps.encode()?);
        }
        metadata.insert(
            destination,
            super::metadata::Metadata {
                mode: 0o100000 | addition.mode,
                uid: addition.uid,
                gid: addition.gid,
                size: info.len(),
                nlink: 1,
                mtime: addition.mtime,
                mtime_nsec: 0,
                xattrs,
            },
        );
    }
    let tree = tempfile::tempdir_in(out)?;
    gb_tools::run(
        &request.sandbox,
        &request.fsck,
        vec![
            "--extract=/output".into(),
            "--no-preserve".into(),
            "/input.img".into(),
        ],
        &request.input,
        tree.path(),
        Duration::from_secs(1200),
    )?;
    for patch in &request.patches {
        let path = tree.path().join(&patch.path);
        ensure!(
            std::fs::symlink_metadata(&path)?.is_file()
                && path
                    .canonicalize()?
                    .starts_with(tree.path().canonicalize()?),
            "decoded patch path escaped tree"
        );
        ensure!(
            hash_file(&path)? == patch.original_sha256,
            "original file digest condition failed"
        );
    }
    let mut expected_tree = tree_inventory(tree.path())?;
    for directory in &directories {
        expected_tree.insert(
            PathBuf::from(&directory.path),
            ("directory".into(), String::new()),
        );
    }
    for p in &request.patches {
        expected_tree.insert(PathBuf::from(&p.path), ("file".into(), p.sha256.clone()));
    }
    for import in imports {
        expected_tree.insert(
            PathBuf::from(&import.report.destination),
            ("file".into(), import.report.sha256.clone()),
        );
    }
    for addition in &request.additions {
        expected_tree.insert(
            PathBuf::from(&addition.path),
            ("file".into(), addition.sha256.clone()),
        );
    }
    let tar_path = scratch.path().join("overlay.tar");
    let mut archive = tar::Builder::new(File::create(&tar_path)?);
    let patches: BTreeMap<_, _> = request
        .patches
        .iter()
        .map(|p| (format!("/{}", p.path), p))
        .collect();
    let mut hardlinks = BTreeMap::<u64, String>::new();
    for (path, e) in &original_entries {
        let m = &e.metadata;
        let name = if path == "/" { "." } else { &path[1..] };
        let decoded = tree.path().join(name);
        let decoded_meta = std::fs::symlink_metadata(&decoded)?;
        let file_type = m.mode & 0o170000;
        ensure!(
            (file_type == 0o040000 && decoded_meta.is_dir())
                || (file_type == 0o100000 && decoded_meta.is_file())
                || (file_type == 0o120000 && decoded_meta.is_symlink()),
            "decoder inode type differs at {path}"
        );
        if !decoded_meta.is_symlink() {
            ensure!(
                decoded
                    .canonicalize()?
                    .starts_with(tree.path().canonicalize()?),
                "decoded inode escaped staging tree"
            );
        }
        match m.mode & 0o170000 {
            0o040000 => append(&mut archive, name, m, None)?,
            0o100000 | 0o120000 => {
                if let Some(first) = hardlinks.get(&e.nid) {
                    let mut h = tar::Header::new_ustar();
                    h.set_entry_type(tar::EntryType::Link);
                    pax(
                        &mut archive,
                        vec![
                            ("path".into(), name.as_bytes().to_vec()),
                            ("linkpath".into(), first.as_bytes().to_vec()),
                        ],
                    )?;
                    h.set_link_name("link")?;
                    h.set_path("entry")?;
                    h.set_uid(m.uid as u64);
                    h.set_gid(m.gid as u64);
                    h.set_mode((m.mode & 0o7777) as u32);
                    h.set_mtime(m.mtime);
                    h.set_size(0);
                    h.set_cksum();
                    archive.append(&h, std::io::empty())?;
                } else {
                    hardlinks.insert(e.nid, name.to_owned());
                    let input = patches
                        .get(path)
                        .map(|p| p.input.as_path())
                        .unwrap_or(&decoded);
                    append(&mut archive, name, m, Some(input))?;
                }
            }
            _ => anyhow::bail!("unsupported special image inode at {path}"),
        }
    }
    for directory in &directories {
        append(
            &mut archive,
            &directory.path,
            metadata
                .get(&format!("/{}", directory.path))
                .context("new directory metadata missing")?,
            None,
        )?;
    }
    for import in imports {
        append(
            &mut archive,
            &import.report.destination,
            &import.report.metadata,
            Some(&import.file),
        )?;
    }
    for addition in &request.additions {
        append(
            &mut archive,
            &addition.path,
            metadata
                .get(&format!("/{}", addition.path))
                .context("new file metadata missing")?,
            Some(&addition.input),
        )?;
    }
    archive.finish()?;
    drop(archive);
    drop(tree);
    let image = out.join("partition.img");

    ensure!(
        u32::from_le_bytes(sb[32..36].try_into()?) == 0,
        "nonzero compact-inode timestamp nanoseconds require a supported builder option"
    );
    let build_time = u64::from_le_bytes(sb[24..32].try_into()?);
    let mut args = vec![
        "--clean=data".into(),
        "--tar=f".into(),
        "--mkfs-time".into(),
        // This Android tool build retains startup errno; a no-op UID offset
        // clears it before its worker-count parser. Pin one compression worker.
        "--uid-offset=0".into(),
        "--workers=1".into(),
        format!("-T{build_time}"),
        "--preserve-mtime".into(),
        "--ovlfs-strip=0".into(),
        format!("-b{}", 1u64 << shift),
        format!("-U{}", uuid(&sb[48..64])),
        "-zlz4hc,level=9".into(),
    ];
    if let Some(cluster) = request.compression_cluster_bytes {
        args.push(format!("-C{cluster}"));
    }
    args.extend(["/output/partition.img".into(), "/inputs/overlay.tar".into()]);
    gb_tools::run_mounted(
        &request.sandbox,
        &request.mkfs,
        args,
        gb_tools::Inputs {
            primary: &request.input,
            extra: &[gb_tools::ReadOnlyInput {
                name: "overlay.tar",
                path: &tar_path,
            }],
            source_date_epoch: None,
        },
        out,
        Duration::from_secs(1200),
    )?;
    let bytes = std::fs::metadata(&image)?.len();
    ensure!(
        bytes <= request.max_bytes && bytes % (1u64 << shift) == 0,
        "assembled filesystem size/alignment exceeds partition constraints"
    );
    gb_tools::run(
        &request.sandbox,
        &request.fsck,
        vec!["--extract".into(), "/input.img".into()],
        &image,
        scratch.path(),
        Duration::from_secs(1200),
    )?;
    let assembled = super::metadata::inventory(&image)?;
    ensure!(
        assembled.len() == metadata.len(),
        "assembled metadata namespace changed"
    );
    let mut links = BTreeMap::new();
    let mut inverse = BTreeMap::new();
    for (path, original) in &original_entries {
        if original.metadata.mode & 0o170000 == 0o040000 {
            continue;
        }
        let rebuilt = assembled.get(path).context("rebuilt path missing")?.nid;
        if let Some(previous) = links.insert(original.nid, rebuilt) {
            ensure!(
                previous == rebuilt,
                "original hardlink group split at {path}"
            );
        }
        if let Some(previous) = inverse.insert(rebuilt, original.nid) {
            ensure!(
                previous == original.nid,
                "distinct source inode groups merged at {path}"
            );
        }
    }
    let mut imported_inodes = BTreeSet::new();
    for import in imports {
        let nid = assembled
            .get(&format!("/{}", import.report.destination))
            .context("imported inode absent")?
            .nid;
        ensure!(
            !inverse.contains_key(&nid) && imported_inodes.insert(nid),
            "imported file unexpectedly shares an inode"
        );
    }
    for addition in &request.additions {
        let nid = assembled
            .get(&format!("/{}", addition.path))
            .context("new inode absent")?
            .nid;
        ensure!(
            !inverse.contains_key(&nid) && imported_inodes.insert(nid),
            "new file unexpectedly shares an inode"
        );
    }
    for (path, expected) in &mut metadata {
        let actual = &assembled
            .get(path)
            .context("assembled inode missing")?
            .metadata;
        if let Some(patch) = patches.get(path) {
            expected.size = std::fs::metadata(&patch.input)?.len();
        }
        ensure!(
            actual.uid == expected.uid
                && actual.gid == expected.gid
                && actual.mode == expected.mode
                && actual.xattrs == expected.xattrs
                && actual.mtime == expected.mtime
                && actual.mtime_nsec == expected.mtime_nsec
                && (expected.mode & 0o170000 == 0o040000
                    || (actual.size == expected.size && actual.nlink == expected.nlink)),
            "assembled metadata differs at {path}: expected uid/gid/mode/time/size/links={}/{}/{:o}/{}.{:09}/{}/{}, actual={}/{}/{:o}/{}.{:09}/{}/{}, xattrs_equal={}",
            expected.uid,
            expected.gid,
            expected.mode,
            expected.mtime,
            expected.mtime_nsec,
            expected.size,
            expected.nlink,
            actual.uid,
            actual.gid,
            actual.mode,
            actual.mtime,
            actual.mtime_nsec,
            actual.size,
            actual.nlink,
            actual.xattrs == expected.xattrs
        );
    }
    let verify = tempfile::tempdir_in(out)?;
    gb_tools::run(
        &request.sandbox,
        &request.fsck,
        vec![
            "--extract=/output".into(),
            "--no-preserve".into(),
            "/input.img".into(),
        ],
        &image,
        verify.path(),
        Duration::from_secs(1200),
    )?;
    ensure!(
        tree_inventory(verify.path())? == expected_tree,
        "assembled tree differs beyond the declared replacements"
    );
    for p in &request.patches {
        ensure!(
            hash_file(&verify.path().join(&p.path))? == p.sha256,
            "assembled replacement content mismatch"
        );
        ensure!(
            hash_file(&p.input)? == p.sha256,
            "replacement changed during assembly"
        );
    }
    for addition in &request.additions {
        ensure!(
            hash_file(&verify.path().join(&addition.path))? == addition.sha256
                && hash_file(&addition.input)? == addition.sha256,
            "new file content changed during assembly"
        );
    }
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "original image changed during assembly"
    );
    let mut verified_sources = BTreeMap::new();
    for (wanted, import) in request.imports.iter().zip(imports) {
        if let Some(previous) = verified_sources.insert(&wanted.image, &wanted.image_sha256) {
            ensure!(
                previous == &wanted.image_sha256,
                "conflicting import source digests"
            );
        } else {
            ensure!(
                hash_file(&wanted.image)? == wanted.image_sha256,
                "import image changed during assembly"
            );
        }
        ensure!(
            hash_file(&import.file)? == import.report.sha256,
            "import bytes changed during assembly"
        );
    }
    metadata = assembled
        .into_iter()
        .map(|(path, e)| (path, e.metadata))
        .collect();
    let report = Report {
        schema_version: 1,
        status: "unsigned_partition_candidate".into(),
        bootable: false, runtime_verified: false, avb_signed: false,
        partition: request.partition.clone(),
        source_sha256: request.sha256.clone(),
        image_sha256: hash_file(&image)?, image_bytes: bytes,
        compression_cluster_bytes: request.compression_cluster_bytes,
        request_sha256: digest(&serde_json::to_vec(request)?),
        verified_tree_entries: expected_tree.len(),
        decoded_content_equivalence: true, full_metadata_equivalence: true,
        metadata, tools,
        imports: imports.iter().map(|i| i.report.clone()).collect(),
        limitations: vec![
            "Unsigned standalone filesystem candidate; AVB, LP/boot-chain assembly, dependency checks and runtime remain required".into(),
            "Metadata equivalence excludes directory packed sizes and link counts; nonzero inode nanoseconds, special inodes and newer addressing/prefix layouts are refused".into(),
        ],
    };
    write_json(&out.join("image-report.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_cluster_cannot_exceed_source_or_enable_a_new_algorithm() {
        let mut sb = [0u8; 128];
        sb[12] = 12;
        sb[80..84].copy_from_slice(&3u32.to_le_bytes());
        sb[84..86].copy_from_slice(&1u16.to_le_bytes());
        let mut config = [0u8; 16];
        config[..2].copy_from_slice(&14u16.to_le_bytes());
        config[4..6].copy_from_slice(&8u16.to_le_bytes());
        assert!(check_lz4_cluster(&sb, &config, 32768).is_ok());
        for size in [0, 2048, 12288, 65536] {
            assert!(check_lz4_cluster(&sb, &config, size).is_err());
        }
        assert!(check_lz4_cluster(&sb, &config[..4], 32768).is_err());
        sb[84..86].copy_from_slice(&8u16.to_le_bytes());
        assert!(check_lz4_cluster(&sb, &config, 32768).is_err());
    }
    #[test]
    fn decoded_tree_detects_changes_without_following_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("directory")).unwrap();
        std::fs::write(root.path().join("directory/file"), b"old").unwrap();
        symlink("/unavailable/outside", root.path().join("link")).unwrap();
        let first = tree_inventory(root.path()).unwrap();
        assert_eq!(first.len(), 3);
        assert_eq!(first[Path::new("link")].0, "symlink");
        std::fs::write(root.path().join("directory/file"), b"new").unwrap();
        assert_ne!(first, tree_inventory(root.path()).unwrap());
    }
    #[test]
    fn requests_reject_unpinned_unsafe_and_duplicate_replacements() {
        let mut r = Request {
            schema_version: 1,
            id: "fixture".into(),
            revision: 1,
            partition: "system".into(),
            input: "source".into(),
            sha256: "0".repeat(64),
            max_bytes: 4096,
            compression_cluster_bytes: None,
            patches: vec![Patch {
                path: "etc/file".into(),
                input: "replacement".into(),
                sha256: "1".repeat(64),
                original_sha256: "2".repeat(64),
            }],
            imports: vec![],
            additions: vec![],
            directories: vec![],
            mkfs: "mkfs".into(),
            fsck: "fsck".into(),
            dump: "dump".into(),
            sandbox: gb_tools::Sandbox::Bubblewrap,
        };
        r.validate().unwrap();
        r.patches[0].path = "../escape".into();
        assert!(r.validate().is_err());
        r.patches[0].path = "etc/file".into();
        r.patches.push(r.patches[0].clone());
        assert!(r.validate().is_err());
        r.patches.pop();
        r.patches[0].original_sha256.clear();
        assert!(r.validate().is_err());
        r.patches[0].original_sha256 = "2".repeat(64);
        let addition = Addition {
            path: "etc/new".into(),
            input: "new".into(),
            sha256: "3".repeat(64),
            uid: 0,
            gid: 0,
            mode: 0o644,
            mtime: 0,
            selinux: "u:object_r:system_file:s0".into(),
            capabilities: None,
        };
        r.additions.push(addition.clone());
        r.validate().unwrap();
        r.additions[0].capabilities = Some(FileCapabilities {
            permitted: 1 << 23,
            inheritable: 0,
            effective: true,
        });
        r.additions[0].mode = 0o755;
        r.validate().unwrap();
        r.additions[0].uid = 1000;
        assert!(r.validate().is_err());
        r.additions[0].uid = 0;
        r.additions[0].mode = 0o775;
        assert!(r.validate().is_err());
        r.additions[0].mode = 0o755;
        r.additions[0].capabilities.as_mut().unwrap().permitted = 1 << 41;
        assert!(r.validate().is_err());
        r.additions[0] = addition.clone();
        r.additions[0].path = "etc/file".into();
        assert!(r.validate().is_err());
        r.additions[0] = addition;
        r.additions[0].mode = 0o4755;
        assert!(r.validate().is_err());
        r.additions[0].mode = 0o644;
        r.additions[0].selinux.push('\0');
        assert!(r.validate().is_err());
        r.additions.clear();
        r.directories.push(Directory {
            path: "lib64/isolated".into(),
            uid: 0,
            gid: 0,
            mode: 0o755,
            mtime: 0,
            selinux: "u:object_r:system_lib_file:s0".into(),
        });
        r.validate().unwrap();
        r.directories[0].path = "etc/file".into();
        assert!(r.validate().is_err());
        r.directories[0].path = "../escape".into();
        assert!(r.validate().is_err());
        r.directories[0].path = "lib64/isolated".into();
        r.directories[0].mode = 0o4755;
        assert!(r.validate().is_err());
        r.directories.clear();
        r.partition = "vendor".into();
        assert!(r.validate().is_err());
    }
    fn metadata(
        mode: u16,
        uid: u32,
        xattrs: BTreeMap<String, Vec<u8>>,
    ) -> super::super::metadata::Metadata {
        super::super::metadata::Metadata {
            mode,
            uid,
            gid: 2345,
            size: 0,
            nlink: 1,
            mtime: 1230768000,
            mtime_nsec: 0,
            xattrs,
        }
    }
    #[test]
    #[ignore = "requires GB_TEST_MKFS, GB_TEST_FSCK, GB_TEST_DUMP, GB_TEST_SANDBOX_IMAGE"]
    fn real_rebuilt_image_preserves_unmodified_metadata_hardlinks_and_binary_xattrs() {
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path();
        let sandbox = gb_tools::Sandbox::Docker {
            image: std::env::var("GB_TEST_SANDBOX_IMAGE").unwrap(),
        };
        let mkfs = PathBuf::from(std::env::var("GB_TEST_MKFS").unwrap());
        let fsck = PathBuf::from(std::env::var("GB_TEST_FSCK").unwrap());
        let dump = PathBuf::from(std::env::var("GB_TEST_DUMP").unwrap());
        let original = root.join("original.txt");
        let replacement = root.join("replacement.txt");
        let keep = root.join("keep.txt");
        std::fs::write(&original, b"original\n").unwrap();
        std::fs::write(&replacement, b"updated\n").unwrap();
        std::fs::write(&keep, b"unchanged hardlink\n").unwrap();
        let tar = root.join("source.tar");
        let mut a = tar::Builder::new(File::create(&tar).unwrap());
        let attrs = BTreeMap::from([
            (
                "security.selinux".into(),
                b"u:object_r:system_file:s0\0".to_vec(),
            ),
            ("user.binary".into(), vec![1, 0, 255, 2]),
        ]);
        append(&mut a, ".", &metadata(0o040755, 1234, attrs.clone()), None).unwrap();
        append(
            &mut a,
            "system",
            &metadata(0o040755, 1234, attrs.clone()),
            None,
        )
        .unwrap();
        append(
            &mut a,
            "system/bin",
            &metadata(0o040750, 1234, attrs.clone()),
            None,
        )
        .unwrap();
        append(
            &mut a,
            "system/bin/change",
            &metadata(0o100640, 1234, attrs.clone()),
            Some(&original),
        )
        .unwrap();
        let mut cap = attrs.clone();
        cap.insert(
            "security.capability".into(),
            vec![0, 0, 0, 2, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        append(
            &mut a,
            "system/bin/keep",
            &metadata(0o104750, 2000, cap),
            Some(&keep),
        )
        .unwrap();
        let long_name = format!("system/bin/{}", "long".repeat(40));
        let mut fractional = metadata(0o100644, 3000, attrs.clone());
        fractional.mtime = 1230768001;
        fractional.uid = 70000;
        append(&mut a, &long_name, &fractional, Some(&keep)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink("/unavailable/outside", &link).unwrap();
        append(
            &mut a,
            "system/bin/link",
            &metadata(0o120777, 4000, attrs.clone()),
            Some(&link),
        )
        .unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Link);
        h.set_link_name("system/bin/keep").unwrap();
        h.set_mode(0o4750);
        h.set_uid(2000);
        h.set_gid(2345);
        h.set_mtime(1230768000);
        h.set_size(0);
        h.set_cksum();
        a.append_data(&mut h, "system/bin/keep2", std::io::empty())
            .unwrap();
        a.finish().unwrap();
        drop(a);
        let base_dir = root.join("base");
        std::fs::create_dir(&base_dir).unwrap();
        gb_tools::run_mounted(
            &sandbox,
            &mkfs,
            vec![
                "--tar=f".into(),
                "--mkfs-time".into(),
                "--preserve-mtime".into(),
                // This Android tool build retains startup errno; a no-op UID offset
                // clears it before its worker-count parser. Pin one compression worker.
                "--uid-offset=0".into(),
                "--workers=1".into(),
                "-T1230768000".into(),
                "-U00000000-0000-0000-0000-000000000001".into(),
                "/output/base.img".into(),
                "/input.img".into(),
            ],
            gb_tools::Inputs {
                primary: &tar,
                extra: &[],
                source_date_epoch: None,
            },
            &base_dir,
            Duration::from_secs(60),
        )
        .unwrap();
        let base = base_dir.join("base.img");
        let before =
            super::super::metadata::at_path(&base, "/system/bin/keep", &dump, &sandbox).unwrap();
        assert_eq!(before.nlink, 2);
        assert_eq!(before.mtime, 1230768000);
        let entries = super::super::metadata::inventory(&base).unwrap();
        assert_eq!(entries[&format!("/{long_name}")].metadata.mtime, 1230768001);
        assert_eq!(entries[&format!("/{long_name}")].metadata.uid, 70000);
        assert_eq!(before.uid, 2000);
        assert_eq!(before.xattrs["security.capability"].len(), 20);
        assert_eq!(before.xattrs["user.binary"], vec![1, 0, 255, 2]);
        let request = Request {
            schema_version: 1,
            id: "fixture".into(),
            revision: 1,
            partition: "system".into(),
            input: base.clone(),
            sha256: hash_file(&base).unwrap(),
            max_bytes: 16 * 1024 * 1024,
            compression_cluster_bytes: None,
            patches: vec![Patch {
                path: "system/bin/change".into(),
                input: replacement.clone(),
                sha256: hash_file(&replacement).unwrap(),
                original_sha256: hash_file(&original).unwrap(),
            }],
            imports: vec![],
            mkfs,
            directories: vec![Directory {
                path: "system/bin/isolated".into(),
                uid: 70000,
                gid: 2345,
                mode: 0o750,
                mtime: 0,
                selinux: "u:object_r:system_file:s0".into(),
            }],
            additions: vec![Addition {
                path: "system/bin/isolated/new-collector@1.0++".into(),
                input: replacement.clone(),
                sha256: hash_file(&replacement).unwrap(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                mtime: 0,
                selinux: "u:object_r:system_file:s0".into(),
                capabilities: Some(FileCapabilities {
                    permitted: 1 << 23,
                    inheritable: 0,
                    effective: true,
                }),
            }],
            fsck,
            dump,
            sandbox,
        };
        let out = root.join("out");
        std::fs::create_dir(&out).unwrap();
        let report = build(&request, &out).unwrap();
        assert!(!report.bootable && !report.avb_signed);
        let after = super::super::metadata::at_path(
            &out.join("partition.img"),
            "/system/bin/keep",
            &request.dump,
            &request.sandbox,
        )
        .unwrap();
        assert_eq!(before, after);
        let other = super::super::metadata::at_path(
            &out.join("partition.img"),
            "/system/bin/keep2",
            &request.dump,
            &request.sandbox,
        )
        .unwrap();
        assert_eq!(after, other);
        let added = super::super::metadata::at_path(
            &out.join("partition.img"),
            "/system/bin/isolated/new-collector@1.0++",
            &request.dump,
            &request.sandbox,
        )
        .unwrap();
        assert_eq!(
            (added.uid, added.gid, added.mode, added.mtime, added.nlink),
            (0, 0, 0o100755, 0, 1)
        );
        assert_eq!(
            added.xattrs["security.selinux"],
            b"u:object_r:system_file:s0\0"
        );
        assert_eq!(
            added.xattrs["security.capability"],
            [1, 0, 0, 2, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let directory = super::super::metadata::at_path(
            &out.join("partition.img"),
            "/system/bin/isolated",
            &request.dump,
            &request.sandbox,
        )
        .unwrap();
        assert_eq!(
            (
                directory.uid,
                directory.gid,
                directory.mode,
                directory.mtime
            ),
            (70000, 2345, 0o040750, 0)
        );
        let repeated = root.join("repeat");
        std::fs::create_dir(&repeated).unwrap();
        let r = build(&request, &repeated).unwrap();
        assert_eq!(report.image_sha256, r.image_sha256);
        // This official Android tool build drops TAR nanoseconds. A synthetic
        // extended inode carrying them must cause a rejected build, not a pass.
        use std::io::{Seek, Write};
        let sb = gb_partition::read_at(&mut File::open(&base).unwrap(), 1024, 128).unwrap();
        let entry = &entries[&format!("/{long_name}")];
        let meta_block = u32::from_le_bytes(sb[40..44].try_into().unwrap()) as u64;
        let offset = (meta_block << sb[12]) + entry.nid * 32 + 40;
        let mut f = std::fs::OpenOptions::new().write(true).open(&base).unwrap();
        f.seek(std::io::SeekFrom::Start(offset)).unwrap();
        f.write_all(&123456789u32.to_le_bytes()).unwrap();
        drop(f);
        let mut unsupported = request.clone();
        unsupported.sha256 = hash_file(&base).unwrap();
        let rejected = root.join("rejected");
        std::fs::create_dir(&rejected).unwrap();
        let error = build(&unsupported, &rejected).unwrap_err().to_string();
        assert!(
            error.contains("nonzero inode nanosecond timestamps"),
            "{error}"
        );
    }
}
