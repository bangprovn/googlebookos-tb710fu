//! Bounded EROFS inode metadata only. Mature tools locate paths and copy data.
use anyhow::{Context, Result, ensure};
use gb_core::{Format, ToolResult};
use gb_partition::{ReadSeek, read_at};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Duration};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub nlink: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub xattrs: BTreeMap<String, Vec<u8>>,
}
fn u16v(b: &[u8], i: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2).context("truncated inode")?.try_into()?,
    ))
}
fn u32v(b: &[u8], i: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4).context("truncated inode")?.try_into()?,
    ))
}
fn u64v(b: &[u8], i: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8).context("truncated inode")?.try_into()?,
    ))
}
fn prefix(index: u8) -> Result<&'static str> {
    Ok(match index {
        0 => "",
        1 => "user.",
        2 => "system.posix_acl_access",
        3 => "system.posix_acl_default",
        4 => "trusted.",
        5 => "lustre.",
        6 => "security.",
        _ => anyhow::bail!("unsupported extended xattr prefix"),
    })
}
fn entry(r: &mut dyn ReadSeek, offset: u64, limit: u64) -> Result<(String, Vec<u8>, u64)> {
    ensure!(
        offset.checked_add(4).is_some_and(|n| n <= limit),
        "xattr header exceeds bounds"
    );
    let h = read_at(r, offset, 4)?;
    let len = 4u64 + h[0] as u64 + u16v(&h, 2)? as u64;
    let padded = (len + 3) & !3;
    ensure!(
        offset.checked_add(padded).is_some_and(|n| n <= limit),
        "xattr exceeds bounds"
    );
    let b = read_at(r, offset, len as usize)?;
    let name = std::str::from_utf8(&b[4..4 + h[0] as usize])?;
    ensure!(!name.contains('\0'), "invalid xattr name");
    let name = format!("{}{name}", prefix(h[1])?);
    ensure!(
        !name.is_empty() && name.len() <= 512,
        "invalid xattr name length"
    );
    Ok((name, b[4 + h[0] as usize..].to_vec(), padded))
}
pub fn inode(r: &mut dyn ReadSeek, nid: u64) -> Result<Metadata> {
    let length = r.seek(std::io::SeekFrom::End(0))?;
    let sb = read_at(r, 1024, 128)?;
    ensure!(
        gb_partition::detect(&read_at(r, 0, 8192.min(length) as usize)?) == Format::Erofs,
        "metadata requires EROFS"
    );
    let shift = sb[12];
    ensure!((9..=16).contains(&shift), "unsupported EROFS block size");
    ensure!(
        u16v(&sb, 86)? == 0 && u32v(&sb, 80)? & 0x80 == 0,
        "external devices or 48-bit inode addressing are unsupported for metadata edits"
    );
    let block = 1u64 << shift;
    let base = (u32v(&sb, 40)? as u64)
        .checked_mul(block)
        .context("metadata address overflow")?;
    let offset = base
        .checked_add(nid.checked_mul(32).context("inode offset overflow")?)
        .context("inode address overflow")?;
    ensure!(
        offset.checked_add(32).is_some_and(|n| n <= length),
        "inode exceeds image bounds"
    );
    let first = read_at(r, offset, 32)?;
    let format = u16v(&first, 0)?;
    ensure!(format & !15 == 0, "unsupported inode format flags");
    let extended = format & 1 != 0;
    let bytes = if extended { 64 } else { 32 };
    ensure!(offset + bytes <= length, "extended inode exceeds bounds");
    let b = read_at(r, offset, bytes as usize)?;
    let mut m = Metadata {
        mode: u16v(&b, 4)?,
        uid: if extended {
            u32v(&b, 24)?
        } else {
            u16v(&b, 24)? as u32
        },
        gid: if extended {
            u32v(&b, 28)?
        } else {
            u16v(&b, 26)? as u32
        },
        size: if extended {
            u64v(&b, 8)?
        } else {
            u32v(&b, 8)? as u64
        },
        nlink: if extended {
            u32v(&b, 44)?
        } else {
            u16v(&b, 6)? as u32
        },
        mtime: if extended {
            u64v(&b, 32)?
        } else {
            u64v(&sb, 24)?
        },
        mtime_nsec: if extended {
            u32v(&b, 40)?
        } else {
            u32v(&sb, 32)?
        },
        xattrs: BTreeMap::new(),
    };
    ensure!(m.mtime_nsec < 1_000_000_000, "invalid inode timestamp");
    let count = u16v(&b, 2)? as u64;
    if count == 0 {
        return Ok(m);
    }
    let attr_len = 12 + (count - 1) * 4;
    let attr_start = offset + bytes;
    ensure!(
        attr_start
            .checked_add(attr_len)
            .is_some_and(|n| n <= length),
        "inline xattr block exceeds image"
    );
    let h = read_at(r, attr_start, 12)?;
    let shared = h[4] as u64;
    ensure!(
        12 + shared * 4 <= attr_len,
        "shared xattr ids exceed inode storage"
    );
    let xbase = (u32v(&sb, 44)? as u64)
        .checked_mul(block)
        .context("xattr base overflow")?;
    let mut attr_bytes = 0usize;
    for i in 0..shared {
        let id = u32v(&read_at(r, attr_start + 12 + i * 4, 4)?, 0)? as u64;
        let pos = xbase
            .checked_add(id.checked_mul(4).context("shared xattr overflow")?)
            .context("shared xattr address overflow")?;
        let (name, value, _) = entry(r, pos, length)?;
        attr_bytes += name.len() + value.len();
        ensure!(attr_bytes <= 1024 * 1024, "inode xattr budget exceeded");
        ensure!(
            m.xattrs.insert(name, value).is_none(),
            "duplicate shared xattr"
        );
    }
    let mut pos = attr_start + 12 + shared * 4;
    let end = attr_start + attr_len;
    while pos < end {
        if read_at(r, pos, 4)? == [0; 4] {
            pos += 4;
            continue; // reserved zero-size xattr entries
        }
        let (name, value, size) = entry(r, pos, end)?;
        attr_bytes += name.len() + value.len();
        ensure!(attr_bytes <= 1024 * 1024, "inode xattr budget exceeded");
        ensure!(
            m.xattrs.insert(name, value).is_none(),
            "duplicate inline xattr"
        );
        pos += size;
    }
    Ok(m)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub nid: u64,
    pub metadata: Metadata,
}
/// Read uncompressed directory metadata only. File data remains the decoder's
/// responsibility. Refuse newer/address-expanded layouts rather than guessing.
pub fn inventory(image: &Path) -> Result<BTreeMap<String, Entry>> {
    let mut r = std::fs::File::open(image)?;
    let sb = read_at(&mut r, 1024, 128)?;
    ensure!(sb[90] == 0, "unsupported EROFS directory block shift");
    let root = u16v(&sb, 14)? as u64;
    let mut pending = vec![("/".to_owned(), root, 0usize)];
    let mut result = BTreeMap::new();
    let mut directories = std::collections::BTreeSet::new();
    let mut metadata_bytes = 0usize;
    let mut namespace_bytes = 1usize;
    while let Some((path, nid, depth)) = pending.pop() {
        gb_core::checkpoint()?;
        ensure!(
            result.len() < 500_000 && depth <= 128 && path.len() <= 4096,
            "EROFS metadata inventory limit exceeded"
        );
        let meta = inode(&mut r, nid)?;
        let footprint = meta
            .xattrs
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
            + path.len()
            + 128;
        metadata_bytes = metadata_bytes
            .checked_add(footprint)
            .context("metadata inventory size overflow")?;
        ensure!(
            metadata_bytes <= 64 * 1024 * 1024,
            "EROFS metadata inventory exceeds 64 MiB budget"
        );
        if meta.mode & 0o170000 == 0o040000 {
            ensure!(directories.insert(nid), "cyclic/hardlinked EROFS directory");
            for (name, child) in directory(&mut r, nid, &meta, &sb)? {
                let child_path = if path == "/" {
                    format!("/{name}")
                } else {
                    format!("{path}/{name}")
                };
                namespace_bytes = namespace_bytes
                    .checked_add(child_path.len())
                    .context("directory path budget overflow")?;
                ensure!(
                    namespace_bytes <= 64 * 1024 * 1024,
                    "directory path budget exceeded"
                );
                ensure!(
                    pending.len() + result.len() < 500_000,
                    "directory namespace limit exceeded"
                );
                pending.push((child_path, child, depth + 1));
            }
        }
        ensure!(
            result
                .insert(
                    path,
                    Entry {
                        nid,
                        metadata: meta
                    }
                )
                .is_none(),
            "duplicate EROFS path"
        );
    }
    Ok(result)
}
fn directory(
    r: &mut dyn ReadSeek,
    nid: u64,
    meta: &Metadata,
    sb: &[u8],
) -> Result<Vec<(String, u64)>> {
    ensure!(
        meta.size > 0 && meta.size <= 16 * 1024 * 1024,
        "empty/oversized EROFS directory"
    );
    let block = 1u64 << sb[12];
    let offset = (u32v(sb, 40)? as u64)
        .checked_mul(block)
        .and_then(|v| nid.checked_mul(32).and_then(|n| v.checked_add(n)))
        .context("directory inode address overflow")?;
    let first = read_at(r, offset, 32)?;
    let format = u16v(&first, 0)?;
    let layout = (format >> 1) & 7;
    ensure!(
        layout == 0 || layout == 2,
        "unsupported compressed/chunked EROFS directory"
    );
    let header_bytes = if format & 1 != 0 { 64 } else { 32 };
    let count = u16v(&first, 2)? as u64;
    let xattrs = if count == 0 { 0 } else { 12 + (count - 1) * 4 };
    let raw = u32v(&first, 16)? as u64;
    let mut result = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let full = meta.size / block;
    let mut logical = 0;
    while logical < meta.size {
        let length = (meta.size - logical).min(block) as usize;
        let pos = if layout == 2 && logical / block == full {
            offset.checked_add(header_bytes + xattrs)
        } else {
            raw.checked_mul(block).and_then(|p| p.checked_add(logical))
        }
        .context("directory data address overflow")?;
        let data = read_at(r, pos, length)?;
        ensure!(data.len() >= 12, "truncated EROFS directory record");
        let name_start = u16v(&data, 8)? as usize;
        ensure!(
            name_start > 0 && name_start.is_multiple_of(12) && name_start <= length,
            "invalid EROFS directory name offset"
        );
        let entries = name_start / 12;
        for i in 0..entries {
            let off = i * 12;
            let start = u16v(&data, off + 8)? as usize;
            let end = if i + 1 < entries {
                u16v(&data, off + 20)? as usize
            } else {
                length
            };
            ensure!(
                start >= name_start && start < end && end <= length,
                "invalid EROFS directory name bounds"
            );
            let bytes = &data[start..end];
            let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            ensure!(
                bytes[len..].iter().all(|b| *b == 0),
                "invalid directory name padding"
            );
            let name = std::str::from_utf8(&bytes[..len])?;
            ensure!(
                !name.is_empty() && name.len() <= 255 && !name.contains('/'),
                "invalid EROFS directory name"
            );
            if name == "." || name == ".." {
                continue;
            }
            ensure!(
                names.insert(name.to_owned()),
                "duplicate EROFS directory name"
            );
            result.push((name.to_owned(), u64v(&data, off)?));
        }
        logical += length as u64;
    }
    Ok(result)
}
fn nid(result: &ToolResult) -> Result<u64> {
    ensure!(
        result.stdout.len() < 65536 && !result.stderr_truncated,
        "inode lookup diagnostics truncated"
    );
    let rows: Vec<_> = result
        .stdout
        .lines()
        .filter(|l| l.starts_with("NID:"))
        .collect();
    ensure!(rows.len() == 1, "inode lookup did not return a unique NID");
    rows[0]
        .split_whitespace()
        .nth(1)
        .context("inode id missing")?
        .parse()
        .context("invalid inode id")
}
pub fn at_path(
    image: &Path,
    path: &str,
    tool: &Path,
    sandbox: &gb_tools::Sandbox,
) -> Result<Metadata> {
    ensure!(
        path.starts_with('/')
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-@+".contains(&b)),
        "unsupported metadata path characters"
    );
    if path != "/" {
        gb_core::safe_relative(Path::new(&path[1..]))?;
    }
    let tool = gb_tools::host_tool(tool, &[image])?;
    let out = tempfile::tempdir()?;
    let result = gb_tools::run(
        sandbox,
        &tool,
        vec![format!("--path={path}"), "/input.img".into()],
        image,
        out.path(),
        Duration::from_secs(30),
    )?;
    inode(&mut std::fs::File::open(image)?, nid(&result)?)
}
