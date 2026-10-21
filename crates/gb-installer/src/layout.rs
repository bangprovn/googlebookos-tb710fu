//! Read-only GPT/LP discovery. No partition-table or super-metadata writes.
use crate::{
    Image, PARTITIONS,
    edl::{Device, Identity, Range},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub filename: String,
    pub range: Range,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    pub identity: Identity,
    pub guards: Vec<Guard>,
    pub partitions: BTreeMap<String, Range>,
}
/// A bounded set of readback fragments with the original disk's virtual length.
/// Unread holes produce errors instead of fabricating zeroes or allocating a LUN.
struct Fragments {
    len: u64,
    pos: u64,
    chunks: Vec<(u64, Vec<u8>)>,
}
impl Read for Fragments {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.pos == self.len {
            return Ok(0);
        }
        for (offset, bytes) in &self.chunks {
            if self.pos >= *offset && self.pos - offset < bytes.len() as u64 {
                let start = (self.pos - offset) as usize;
                let n = out.len().min(bytes.len() - start);
                out[..n].copy_from_slice(&bytes[start..start + n]);
                self.pos += n as u64;
                return Ok(n);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "parser requested an unread disk fragment",
        ))
    }
}
impl Seek for Fragments {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let value = match p {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.len as i128 + n as i128,
            SeekFrom::Current(n) => self.pos as i128 + n as i128,
        };
        if value < 0 || value > self.len as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside disk",
            ));
        }
        self.pos = value as u64;
        Ok(self.pos)
    }
}
fn u32le(b: &[u8], n: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(n..n + 4).context("truncated metadata")?.try_into()?,
    ))
}
fn u64le(b: &[u8], n: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(n..n + 8).context("truncated metadata")?.try_into()?,
    ))
}
fn aligned(bytes: u64) -> Result<u64> {
    Ok(bytes.checked_add(4095).context("alignment overflow")? / 4096 * 4096)
}
fn header(h: &[u8], lba: u64) -> Result<()> {
    ensure!(
        h.get(..8) == Some(b"EFI PART")
            && u32le(h, 8)? == 0x10000
            && u32le(h, 20)? == 0
            && u64le(h, 24)? == lba,
        "invalid GPT header"
    );
    let n = u32le(h, 12)? as usize;
    ensure!((92..=4096).contains(&n), "invalid GPT header size");
    let mut check = h.get(..n).context("short GPT header")?.to_vec();
    check[16..20].fill(0);
    ensure!(
        crc32fast::hash(&check) == u32le(h, 16)?,
        "GPT header CRC mismatch"
    );
    Ok(())
}
fn table_geometry(h: &[u8]) -> Result<(u64, u64, usize)> {
    let count = u32le(h, 80)? as u64;
    let size = u32le(h, 84)? as u64;
    ensure!(
        (1..=65536).contains(&count) && (128..=4096).contains(&size) && size.is_multiple_of(8),
        "unsupported GPT entry geometry"
    );
    let bytes = count.checked_mul(size).context("GPT table overflow")?;
    ensure!(bytes <= 16 * 1024 * 1024, "GPT table exceeds bound");
    Ok((u64le(h, 72)?, aligned(bytes)? / 4096, bytes as usize))
}
fn read_guard(
    d: &dyn Device,
    dir: &Path,
    guards: &mut Vec<Guard>,
    name: String,
    r: Range,
) -> Result<Vec<u8>> {
    ensure!(
        r.bytes()? <= 16 * 1024 * 1024,
        "metadata read exceeds bound"
    );
    let path = dir.join(&name);
    d.read(&r, &path)?;
    ensure!(
        fs::metadata(&path)?.len() == r.bytes()?,
        "short metadata readback"
    );
    guards.push(Guard {
        filename: name,
        range: r,
        sha256: gb_core::hash_file(&path)?,
    });
    Ok(fs::read(path)?)
}
pub fn capture(d: &dyn Device, dir: &Path) -> Result<Layout> {
    let identity = d.identity()?;
    identity.validate()?;
    let mut guards = Vec::new();
    let mut physical = BTreeMap::new();
    let mut active = BTreeMap::new();
    for lun in 0..identity.luns {
        let prefix = read_guard(
            d,
            dir,
            &mut guards,
            format!("lun{lun}-primary.bin"),
            Range {
                lun,
                start_sector: 0,
                sectors: 2,
            },
        )?;
        let h = &prefix[4096..];
        header(h, 1)?;
        let end = u64le(h, 32)?;
        ensure!(
            (16..(1 << 40)).contains(&end),
            "invalid backup GPT position"
        );
        let disk_len = (end + 1).checked_mul(4096).context("LUN size overflow")?;
        let (table_start, table_sectors, bytes) = table_geometry(h)?;
        let first = u64le(h, 40)?;
        let last = u64le(h, 48)?;
        ensure!(
            table_start >= 2
                && table_start
                    .checked_add(table_sectors)
                    .is_some_and(|n| n <= first)
                && first <= last
                && last < end,
            "GPT metadata overlaps usable area"
        );
        let entries = read_guard(
            d,
            dir,
            &mut guards,
            format!("lun{lun}-entries.bin"),
            Range {
                lun,
                start_sector: table_start,
                sectors: table_sectors,
            },
        )?;
        let backup = read_guard(
            d,
            dir,
            &mut guards,
            format!("lun{lun}-backup.bin"),
            Range {
                lun,
                start_sector: end,
                sectors: 1,
            },
        )?;
        header(&backup, end)?;
        let (bt, bs, bb) = table_geometry(&backup)?;
        ensure!(
            u64le(&backup, 32)? == 1
                && backup[40..72] == h[40..72]
                && backup[80..92] == h[80..92]
                && bt > last
                && bt.checked_add(bs).is_some_and(|n| n <= end)
                && bb == bytes,
            "backup GPT geometry differs"
        );
        let backup_entries = read_guard(
            d,
            dir,
            &mut guards,
            format!("lun{lun}-backup-entries.bin"),
            Range {
                lun,
                start_sector: bt,
                sectors: bs,
            },
        )?;
        ensure!(
            entries[..bytes] == backup_entries[..bytes]
                && crc32fast::hash(&entries[..bytes]) == u32le(h, 88)?,
            "GPT entries disagree or CRC failed"
        );
        let mut reader = Fragments {
            len: disk_len,
            pos: 0,
            chunks: vec![(0, prefix.clone()), (table_start * 4096, entries.clone())],
        };
        let parsed = gb_partition::gpt(&mut reader)?;
        ensure!(
            parsed.sector_size == 4096 && parsed.primary_crc_verified,
            "unsupported GPT sectors"
        );
        for p in parsed.partitions {
            let r = Range {
                lun,
                start_sector: p.offset / 4096,
                sectors: p.bytes / 4096,
            };
            r.bytes()?;
            ensure!(
                physical.insert(p.name.clone(), r).is_none(),
                "duplicate partition across LUNs: {}",
                p.name
            );
        }
        for e in entries[..bytes].chunks_exact(u32le(h, 84)? as usize) {
            if e[..16].iter().all(|v| *v == 0) {
                continue;
            }
            let name = String::from_utf16(
                &e[56..128]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .take_while(|c| *c != 0)
                    .collect::<Vec<_>>(),
            )?;
            if ["boot_a", "boot_b"].contains(&name.as_str()) {
                active.insert(name, u64le(e, 48)? & (1 << 50) != 0);
            }
        }
    }
    ensure!(
        active.get("boot_a") == Some(&true) && active.get("boot_b") == Some(&false),
        "slot A must already be active; this installer never changes GPT slot flags"
    );
    let super_range = physical
        .get("super")
        .context("super GPT partition missing")?;
    let geometry = read_guard(
        d,
        dir,
        &mut guards,
        "super-geometry.bin".into(),
        Range {
            lun: super_range.lun,
            start_sector: super_range.start_sector,
            sectors: 3,
        },
    )?;
    ensure!(
        geometry[4096..4148] == geometry[8192..8244],
        "LP geometry copies differ"
    );
    let max = u32le(&geometry, 4096 + 40)? as u64;
    let count = u32le(&geometry, 4096 + 44)? as u64;
    ensure!(
        (128..=16 * 1024 * 1024).contains(&max)
            && max.is_multiple_of(512)
            && (1..=32).contains(&count),
        "invalid LP metadata geometry"
    );
    let prefix_bytes = aligned(12288 + 2 * max * count)?;
    ensure!(
        prefix_bytes <= 16 * 1024 * 1024 && prefix_bytes < super_range.bytes()?,
        "LP metadata exceeds bound"
    );
    let prefix = read_guard(
        d,
        dir,
        &mut guards,
        "super-metadata.bin".into(),
        Range {
            lun: super_range.lun,
            start_sector: super_range.start_sector,
            sectors: prefix_bytes / 4096,
        },
    )?;
    ensure!(
        prefix[..12288] == geometry,
        "LP geometry changed during readback"
    );
    let first = &prefix[12288..(12288 + max) as usize];
    for i in 1..2 * count {
        ensure!(
            &prefix[(12288 + i * max) as usize..(12288 + (i + 1) * max) as usize] == first,
            "LP metadata slots differ; pending OTA/snapshots or alternate layouts are unsupported"
        );
    }
    let hs = u32le(first, 8)? as usize;
    let ts = u32le(first, 44)? as usize;
    ensure!(
        (hs == 128 || hs == 256) && hs.checked_add(ts).is_some_and(|n| n <= first.len()),
        "invalid LP header/table size"
    );
    if hs == 256 {
        ensure!(
            u32le(first, 128)? & !1 == 0,
            "LP overlays or unknown header flags are unsupported"
        );
    }
    let po = u32le(first, 80)? as usize;
    let pn = u32le(first, 84)? as usize;
    let ps = u32le(first, 88)? as usize;
    ensure!(ps == 52 && pn <= 65536, "invalid LP partition table");
    let table = &first[hs..hs + ts];
    let parts = table
        .get(
            po..po
                .checked_add(pn.checked_mul(ps).context("LP count overflow")?)
                .context("LP offset overflow")?,
        )
        .context("LP partition bounds")?;
    for p in parts.chunks_exact(52) {
        ensure!(
            u32le(p, 36)? == 1,
            "LP attributes indicate snapshot, slot suffixing or unsupported writable partition"
        );
    }
    let mut reader = Fragments {
        len: super_range.bytes()?,
        pos: 0,
        chunks: vec![(0, prefix)],
    };
    let lp = gb_partition::super_metadata(&mut reader, 0)?;
    let mut partitions = BTreeMap::new();
    for name in PARTITIONS {
        let slot_name = format!("{name}_a");
        let range = if ["system", "product", "system_ext", "vendor"].contains(name) {
            let p = lp
                .partitions
                .iter()
                .find(|p| p.name == slot_name)
                .context("required logical partition missing")?;
            ensure!(
                p.extents.len() == 1 && p.bytes > 0,
                "fragmented or empty {slot_name} is unsupported; no automatic resize"
            );
            let e = &p.extents[0];
            ensure!(
                !e.zero
                    && e.source == 0
                    && e.offset.is_multiple_of(4096)
                    && e.bytes.is_multiple_of(4096)
                    && e.offset >= prefix_bytes
                    && e.offset
                        .checked_add(e.bytes)
                        .is_some_and(|n| n <= super_range.sectors * 4096),
                "unsupported or out-of-bounds LP extent"
            );
            Range {
                lun: super_range.lun,
                start_sector: super_range.start_sector + e.offset / 4096,
                sectors: e.bytes / 4096,
            }
        } else {
            physical
                .get(&slot_name)
                .context("required physical partition missing")?
                .clone()
        };
        range.bytes()?;
        partitions.insert((*name).into(), range);
    }
    let mut ranges: Vec<_> = partitions.values().collect();
    ranges.sort_by_key(|r| (r.lun, r.start_sector));
    ensure!(
        ranges
            .windows(2)
            .all(|w| w[0].lun != w[1].lun || w[0].start_sector + w[0].sectors <= w[1].start_sector),
        "write ranges overlap"
    );
    Ok(Layout {
        identity,
        guards,
        partitions,
    })
}
pub fn writes(
    layout: &Layout,
    images: &BTreeMap<String, Image>,
) -> Result<BTreeMap<String, Range>> {
    let mut writes = BTreeMap::new();
    for name in PARTITIONS {
        let p = layout
            .partitions
            .get(*name)
            .context("partition mapping missing")?;
        let i = images.get(*name).context("image missing")?;
        ensure!(
            i.bytes > 0 && i.bytes.is_multiple_of(4096) && i.bytes <= p.bytes()?,
            "image does not fit aligned {name}_a"
        );
        if ["system", "product", "system_ext", "vendor"].contains(name) {
            ensure!(
                i.bytes == p.bytes()?,
                "logical image size differs from this device's LP allocation; resizing is unsupported"
            );
        }
        writes.insert(
            (*name).into(),
            Range {
                sectors: i.bytes / 4096,
                ..p.clone()
            },
        );
    }
    Ok(writes)
}
