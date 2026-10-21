//! Small, same-size regular-text edits on disposable ext4 image copies.
//! e2fsck validates the filesystem; debugfs owns inode lookup and block mapping.
//! A complete streaming byte comparison proves that no unrelated image byte changed.
use anyhow::{Context, Result, ensure};
use gb_core::{Format, ToolResult, hash_file};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    pub path: String,
    pub original_sha256: String,
    pub replacement: Input,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub partition: String,
    pub image: Input,
    pub max_image_bytes: u64,
    pub debugfs: Input,
    pub checker: Input,
    pub patches: Vec<Patch>,
    pub sandbox: gb_tools::Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 1024 * 1024)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [&mut r.image, &mut r.debugfs, &mut r.checker]
            .into_iter()
            .chain(r.patches.iter_mut().map(|p| &mut p.replacement))
        {
            if p.path.is_relative() {
                p.path = parent.join(&p.path);
            }
        }
        Ok(r)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteChange {
    pub offset: u64,
    pub before: u8,
    pub after: u8,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub metadata: crate::metadata::Metadata,
    pub changed_bytes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub id: String,
    pub revision: u32,
    pub partition: String,
    pub source_sha256: String,
    pub image_sha256: String,
    pub image_bytes: u64,
    pub block_size: u64,
    pub files: Vec<FileChange>,
    pub changes: Vec<ByteChange>,
    pub unrelated_image_bytes_identical: bool,
    pub filesystem_metadata_bytes_preserved: bool,
    pub filesystem_check: ToolResult,
    pub tools: Vec<serde_json::Value>,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub avb_signed: bool,
    pub limitations: Vec<String>,
}
fn sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn pin(p: &Input, max: u64) -> Result<()> {
    let m = std::fs::symlink_metadata(&p.path)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.len() <= max
            && sha(&p.sha256)
            && hash_file(&p.path)? == p.sha256,
        "input pin, type or size differs: {}",
        p.path.display()
    );
    Ok(())
}
fn text(path: &Path) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    File::open(path)?.take(65537).read_to_end(&mut b)?;
    ensure!(
        !b.is_empty() && b.len() <= 65536 && !b.contains(&0),
        "only bounded nonempty regular text may be patched"
    );
    std::str::from_utf8(&b)?;
    Ok(b)
}
fn debug(r: &Request, image: &Path, command: String, out: &Path) -> Result<ToolResult> {
    let result = gb_tools::run(
        &r.sandbox,
        &r.debugfs.path,
        vec!["-R".into(), command, "/input.img".into()],
        image,
        out,
        Duration::from_secs(30),
    )?;
    crate::import::diagnostics(&result)?;
    Ok(result)
}
/// Compare every image byte while hashing both streams; no multi-gigabyte buffers.
fn exact_delta(
    mut a: impl Read,
    mut b: impl Read,
    length: u64,
    expected: &BTreeMap<u64, (u8, u8)>,
) -> Result<(String, String)> {
    ensure!(
        !expected.is_empty() && expected.len() <= 4096 && expected.keys().all(|p| *p < length),
        "invalid byte delta bounds"
    );
    let mut x = [0u8; 65536];
    let mut y = [0u8; 65536];
    let mut ha = Sha256::new();
    let mut hb = Sha256::new();
    let mut at = 0;
    let mut seen = 0;
    while at < length {
        gb_core::checkpoint()?;
        let n = (length - at).min(x.len() as u64) as usize;
        a.read_exact(&mut x[..n])?;
        b.read_exact(&mut y[..n])?;
        ha.update(&x[..n]);
        hb.update(&y[..n]);
        if x[..n] != y[..n] || expected.range(at..at + n as u64).next().is_some() {
            for i in 0..n {
                if let Some(&(old, new)) = expected.get(&(at + i as u64)) {
                    ensure!(
                        old != new && x[i] == old && y[i] == new,
                        "expected byte change differs"
                    );
                    seen += 1;
                } else {
                    ensure!(
                        x[i] == y[i],
                        "unexpected image mutation at byte {}",
                        at + i as u64
                    );
                }
            }
        }
        at += n as u64;
    }
    ensure!(
        seen == expected.len() && a.read(&mut x[..1])? == 0 && b.read(&mut y[..1])? == 0,
        "truncated, extended or incomplete image delta"
    );
    Ok((
        format!("{:x}", ha.finalize()),
        format!("{:x}", hb.finalize()),
    ))
}
pub fn build(r: &Request, output: &Path) -> Result<Report> {
    ensure!(
        r.schema_version == 1
            && r.revision > 0
            && !r.id.is_empty()
            && r.id.len() <= 128
            && r.id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            && ["vendor", "odm", "system", "system_ext", "product"].contains(&r.partition.as_str())
            && !r.patches.is_empty()
            && r.patches.len() <= 64
            && !output.exists(),
        "invalid patch request or existing output"
    );
    r.sandbox.validate()?;
    ensure!(r.max_image_bytes > 0, "image bound must be explicit");
    pin(&r.image, r.max_image_bytes)?;
    pin(&r.debugfs, 64 * 1024 * 1024)?;
    pin(&r.checker, 64 * 1024 * 1024)?;
    let mut names = BTreeSet::new();
    for p in &r.patches {
        gb_core::safe_relative(Path::new(&p.path))?;
        ensure!(
            p.path.len() <= 1024
                && p.path
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_./-@+".contains(&c))
                && names.insert(&p.path)
                && sha(&p.original_sha256),
            "unsafe or duplicate patch path"
        );
        pin(&p.replacement, 65536)?;
    }
    for p in [&r.image, &r.debugfs, &r.checker]
        .into_iter()
        .chain(r.patches.iter().map(|p| &p.replacement))
    {
        gb_core::separate_from_input(&p.path, output)?;
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    let mut source = File::open(&r.image.path)?;
    let length = source.metadata()?.len();
    ensure!(
        fs2::available_space(staging.path())?
            > length
                .checked_add(512 * 1024 * 1024)
                .context("disk estimate overflow")?,
        "insufficient patch staging space"
    );
    ensure!(
        gb_partition::detect(&gb_partition::read_at(
            &mut source,
            0,
            length.min(8192) as usize
        )?) == Format::Ext4,
        "source is not a raw ext4 image"
    );
    let info = gb_partition::inspect(&mut source, &Format::Ext4)?;
    let block = info["block_size"]
        .as_u64()
        .context("ext4 block size missing")?;
    let fs_bytes = info["filesystem_bytes"]
        .as_u64()
        .context("ext4 length missing")?;
    let imports: Vec<_> = r
        .patches
        .iter()
        .map(|p| crate::import::Request {
            image: r.image.path.clone(),
            image_sha256: r.image.sha256.clone(),
            source_path: p.path.clone(),
            destination: p.path.clone(),
            sha256: p.original_sha256.clone(),
            debugfs: r.debugfs.path.clone(),
            checker: r.checker.path.clone(),
            apex_name: None,
        })
        .collect();
    let imports_dir = tempfile::tempdir_in(staging.path())?;
    let originals = crate::import::extract_batch(&imports, &r.sandbox, imports_dir.path())?;
    let candidate = staging.path().join("partition.img");
    let mut dest = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&candidate)?;
    source.seek(SeekFrom::Start(0))?;
    ensure!(
        gb_core::copy_stream((&mut source).take(length), &mut dest)? == length,
        "source copy truncated"
    );
    let mut deltas = BTreeMap::new();
    let mut files = Vec::new();
    let work = tempfile::tempdir_in(staging.path())?;
    for (patch, original) in r.patches.iter().zip(&originals) {
        gb_core::checkpoint()?;
        let before = text(&original.file)?;
        let after = text(&patch.replacement.path)?;
        ensure!(
            before.len() == after.len() && gb_core::digest(&after) == patch.replacement.sha256,
            "replacement size or pin differs"
        );
        let observed = debug(
            r,
            &r.image.path,
            format!("stat /{}", patch.path),
            work.path(),
        )?;
        let flags = u32::from_str_radix(
            crate::import::field(&observed.stdout, "Flags:")?
                .strip_prefix("0x")
                .context("missing inode flags")?,
            16,
        )?;
        ensure!(
            flags & !0x80000 == 0,
            "encrypted, inline, verity, compressed or special inode flags are unsupported"
        );
        let mut maps = BTreeMap::new();
        let mut changed = 0;
        for (i, (&old, &new)) in before
            .iter()
            .zip(&after)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
        {
            let logical = i as u64 / block;
            let physical = if let Some(p) = maps.get(&logical) {
                *p
            } else {
                let answer = debug(
                    r,
                    &r.image.path,
                    format!("bmap /{} {logical}", patch.path),
                    work.path(),
                )?;
                let p = answer
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .context("invalid debugfs block mapping")?;
                ensure!(p > 0, "patch byte maps to a hole");
                maps.insert(logical, p);
                p
            };
            let address = physical
                .checked_mul(block)
                .and_then(|p| p.checked_add(i as u64 % block))
                .context("mapped offset overflow")?;
            ensure!(
                address < fs_bytes
                    && deltas.insert(address, (old, new)).is_none()
                    && deltas.len() <= 4096,
                "overlapping or excessive mapped byte changes"
            );
            source.seek(SeekFrom::Start(address))?;
            let mut v = [0];
            source.read_exact(&mut v)?;
            ensure!(v[0] == old, "mapped source byte differs");
            dest.seek(SeekFrom::Start(address))?;
            dest.write_all(&[new])?;
            changed += 1;
        }
        ensure!(changed > 0, "requested patch changes no bytes");
        files.push(FileChange {
            path: patch.path.clone(),
            before_sha256: patch.original_sha256.clone(),
            after_sha256: patch.replacement.sha256.clone(),
            metadata: original.report.metadata.clone(),
            changed_bytes: changed,
        });
    }
    dest.sync_all()?;
    ensure!(
        dest.metadata()?.len() == length,
        "candidate image size changed"
    );
    source.seek(SeekFrom::Start(0))?;
    dest.seek(SeekFrom::Start(0))?;
    let (source_sha256, image_sha256) = exact_delta(&mut source, &mut dest, length, &deltas)?;
    ensure!(
        source_sha256 == r.image.sha256,
        "source changed during patching"
    );
    // The changed data must still be reached through the original inode/path.
    for (i, patch) in r.patches.iter().enumerate() {
        let name = format!("after-{i}");
        debug(
            r,
            &candidate,
            format!("dump /{} /output/{name}", patch.path),
            work.path(),
        )?;
        ensure!(
            hash_file(&work.path().join(name))? == patch.replacement.sha256,
            "candidate file payload differs from replacement"
        );
    }
    let filesystem_check = gb_tools::run(
        &r.sandbox,
        &r.checker.path,
        vec!["-f".into(), "-n".into(), "/input.img".into()],
        &candidate,
        work.path(),
        Duration::from_secs(1200),
    )?;
    pin(&r.debugfs, 64 * 1024 * 1024)?;
    pin(&r.checker, 64 * 1024 * 1024)?;
    for patch in &r.patches {
        pin(&patch.replacement, 65536)?;
    }
    // Detect replacement/rename of the source path without another whole-image scan.
    ensure!(
        crate::import::source_identity(&source.metadata()?)
            == crate::import::source_identity(&std::fs::metadata(&r.image.path)?),
        "source path identity changed"
    );
    let tools = originals[0].report.tools.clone();
    let report=Report {schema_version:1,status:"unsigned_ext4_byte_patch_candidate".into(),id:r.id.clone(),revision:r.revision,partition:r.partition.clone(),source_sha256,image_sha256:image_sha256.clone(),image_bytes:length,block_size:block,files,
        changes:deltas.into_iter().map(|(offset,(before,after))|ByteChange{offset,before,after}).collect(),unrelated_image_bytes_identical:true,filesystem_metadata_bytes_preserved:true,filesystem_check,tools,bootable:false,runtime_verified:false,avb_signed:false,
        limitations:vec!["Only bounded, same-size, singly linked regular UTF-8 text files with ordinary inode flags are supported; debugfs resolves blocks and e2fsck validates the filesystems.".into(),"Any source AVB metadata retained in this disposable copy is invalidated by payload edits. Explicit authorized re-signing, partition/boot-chain verification and runtime tests are required.".into(),"Exact image byte deltas preserve every unrelated byte, including metadata. This is not permission to redistribute source firmware or evidence of hardware compatibility.".into()]};
    drop(dest);
    drop(source);
    drop(work);
    drop(imports_dir);
    let mut permissions = std::fs::metadata(&candidate)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&candidate, permissions)?;
    gb_core::write_json(&staging.path().join("ext4-patch-report.json"), &report)?;
    std::fs::write(
        staging.path().join("SHA256SUMS"),
        format!("{image_sha256}  partition.img\n"),
    )?;
    gb_core::publish_directory(staging.path(), output)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_exact_deltas_across_chunk_boundaries_and_hashes() {
        let a = vec![b'a'; 131073];
        let mut b = a.clone();
        b[65535] = b'#';
        b[65536] = b'z';
        let changes = BTreeMap::from([(65535, (b'a', b'#')), (65536, (b'a', b'z'))]);
        let (x, y) = exact_delta(&a[..], &b[..], a.len() as u64, &changes).unwrap();
        assert_eq!(x, gb_core::digest(&a));
        assert_eq!(y, gb_core::digest(&b));
        b[131072] = b'q';
        assert!(exact_delta(&a[..], &b[..], a.len() as u64, &changes).is_err());
    }
    #[test]
    fn rejects_missing_wrong_truncated_and_extended_changes() {
        let d = BTreeMap::from([(1, (b'b', b'#'))]);
        for (a, b) in [
            (b"abc".as_slice(), b"abc".as_slice()),
            (b"axc", b"a#c"),
            (b"abc", b"a#"),
            (b"abc", b"a#cd"),
        ] {
            assert!(exact_delta(a, b, 3, &d).is_err());
        }
        assert!(exact_delta(b"abc".as_slice(), b"a#c".as_slice(), 3, &BTreeMap::new()).is_err());
        assert!(
            exact_delta(
                b"abc".as_slice(),
                b"a#c".as_slice(),
                3,
                &BTreeMap::from([(3, (0, 1))])
            )
            .is_err()
        );
    }
}
