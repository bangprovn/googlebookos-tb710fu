//! Bounded, read-only Android image and partition metadata inspection.
use anyhow::{Context, Result, bail, ensure};
use gb_core::{Format, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom, Write};

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}
pub struct Region<'a> {
    inner: &'a mut dyn ReadSeek,
    start: u64,
    len: u64,
    pos: u64,
}
impl<'a> Region<'a> {
    pub fn new(inner: &'a mut dyn ReadSeek, start: u64, len: u64) -> Result<Self> {
        let size = inner.seek(SeekFrom::End(0))?;
        ensure!(
            start.checked_add(len).is_some_and(|n| n <= size),
            "region exceeds image bounds"
        );
        Ok(Self {
            inner,
            start,
            len,
            pos: 0,
        })
    }
}
impl Read for Region<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let count = (self.len - self.pos).min(b.len() as u64) as usize;
        let n = self.inner.read(&mut b[..count])?;
        self.pos += n as u64;
        Ok(n)
    }
}
impl Seek for Region<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let next = match from {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::Current(p) => self.pos as i128 + p as i128,
            SeekFrom::End(p) => self.len as i128 + p as i128,
        };
        if next < 0 || next > self.len as i128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek exceeds region",
            ));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}
pub fn read_at(r: &mut dyn ReadSeek, offset: u64, size: usize) -> Result<Vec<u8>> {
    ensure!(
        size <= 16 * 1024 * 1024,
        "metadata read exceeds 16 MiB limit"
    );
    r.seek(SeekFrom::Start(offset))?;
    let mut b = vec![0; size];
    r.read_exact(&mut b)
        .context("truncated firmware metadata")?;
    Ok(b)
}
fn slice(b: &[u8], offset: usize, n: usize) -> Result<&[u8]> {
    b.get(offset..offset.checked_add(n).context("offset overflow")?)
        .context("truncated metadata field")
}
fn u16le(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, o, 2)?.try_into()?))
}
fn u32le(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(b, o, 4)?.try_into()?))
}
fn u64le(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(slice(b, o, 8)?.try_into()?))
}
fn u32be(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(slice(b, o, 4)?.try_into()?))
}
fn u64be(b: &[u8], o: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(slice(b, o, 8)?.try_into()?))
}
fn string(b: &[u8]) -> String {
    String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or_default()).into_owned()
}
pub fn align(n: u64, page: u64) -> Result<u64> {
    ensure!(page.is_power_of_two(), "invalid image alignment");
    n.checked_add(page - 1)
        .map(|v| v / page * page)
        .context("alignment overflow")
}
fn bounded(start: u64, bytes: u64, len: u64) -> Result<()> {
    ensure!(
        start.checked_add(bytes).is_some_and(|e| e <= len),
        "component exceeds image bounds"
    );
    Ok(())
}

pub fn detect(b: &[u8]) -> Format {
    if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        Format::Zip
    } else if b.starts_with(&[0x3a, 0xff, 0x26, 0xed]) {
        Format::Sparse
    } else if b.starts_with(b"ANDROID!") {
        Format::Boot
    } else if b.starts_with(b"VNDRBOOT") {
        Format::VendorBoot
    } else if b.starts_with(b"AVB0") {
        Format::Vbmeta
    } else if b.starts_with(&[0xd7, 0xb7, 0xab, 0x1e]) {
        Format::Dtbo
    } else if b.starts_with(b"CrAU") {
        Format::OtaPayload
    } else if b.get(512..520) == Some(b"EFI PART") || b.get(4096..4104) == Some(b"EFI PART") {
        Format::Gpt
    } else if b.get(4096..4100) == Some(&[0x67, 0x44, 0x6c, 0x61]) {
        Format::Super
    } else if b.get(1024..1028) == Some(&[0xe2, 0xe1, 0xf5, 0xe0]) {
        Format::Erofs
    } else if b.get(1080..1082) == Some(&[0x53, 0xef]) {
        Format::Ext4
    } else if b.starts_with(b"\x7fELF") {
        Format::Elf
    } else if b.starts_with(&[0x1f, 0x8b]) {
        Format::Gzip
    } else if b.starts_with(&[0x02, 0x21, 0x4c, 0x18]) || b.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        Format::Lz4
    } else {
        Format::Unknown
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub name: String,
    pub offset: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gpt {
    pub sector_size: u64,
    pub primary_crc_verified: bool,
    pub backup_verified: bool,
    pub partitions: Vec<Partition>,
}
pub fn gpt(r: &mut dyn ReadSeek) -> Result<Gpt> {
    let len = r.seek(SeekFrom::End(0))?;
    let sector = if read_at(r, 512, 8)? == b"EFI PART" {
        512
    } else {
        ensure!(read_at(r, 4096, 8)? == b"EFI PART", "GPT signature absent");
        4096
    };
    let h = read_at(r, sector, 92)?;
    let hs = u32le(&h, 12)? as usize;
    ensure!(
        (92..=sector as usize).contains(&hs),
        "invalid GPT header size"
    );
    let mut full = read_at(r, sector, hs)?;
    full[16..20].fill(0);
    ensure!(
        crc32fast::hash(&full) == u32le(&h, 16)?,
        "GPT header CRC mismatch"
    );
    ensure!(u64le(&h, 24)? == 1, "GPT primary LBA invalid");
    let first = u64le(&h, 40)?;
    let last = u64le(&h, 48)?;
    ensure!(
        first <= last && last < len / sector,
        "GPT usable bounds invalid"
    );
    let count = u32le(&h, 80)? as usize;
    let es = u32le(&h, 84)? as usize;
    ensure!(
        (128..=4096).contains(&es) && es.is_multiple_of(8) && count <= 65536,
        "invalid GPT entry geometry"
    );
    let offset = u64le(&h, 72)?
        .checked_mul(sector)
        .context("GPT LBA overflow")?;
    let table_bytes = count.checked_mul(es).context("GPT table overflow")?;
    bounded(offset, table_bytes as u64, len)?;
    let table = read_at(r, offset, table_bytes)?;
    ensure!(
        crc32fast::hash(&table) == u32le(&h, 88)?,
        "GPT entry CRC mismatch"
    );
    let mut partitions = Vec::new();
    for e in table.chunks_exact(es) {
        if e[..16].iter().all(|b| *b == 0) {
            continue;
        }
        let name = String::from_utf16(
            &e[56..128]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|c| *c != 0)
                .collect::<Vec<_>>(),
        )
        .context("invalid GPT partition name")?;
        ensure!(
            !name.is_empty() && !name.contains('/') && !name.contains('\\'),
            "invalid GPT partition name"
        );
        let start = u64le(e, 32)?;
        let end = u64le(e, 40)?;
        ensure!(
            start >= first && end >= start && end <= last,
            "GPT partition out of bounds: {name}"
        );
        ensure!(
            !partitions.iter().any(|p: &Partition| p.name == name),
            "duplicate GPT name: {name}"
        );
        partitions.push(Partition {
            name,
            offset: start.checked_mul(sector).context("GPT range overflow")?,
            bytes: (end - start + 1)
                .checked_mul(sector)
                .context("GPT size overflow")?,
        });
    }
    let mut ranges = partitions.iter().collect::<Vec<_>>();
    ranges.sort_by_key(|p| p.offset);
    ensure!(
        ranges
            .windows(2)
            .all(|w| w[0].offset + w[0].bytes <= w[1].offset),
        "overlapping GPT partitions"
    );
    Ok(Gpt {
        sector_size: sector,
        primary_crc_verified: true,
        backup_verified: false,
        partitions,
    })
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extent {
    pub bytes: u64,
    pub offset: u64,
    pub zero: bool,
    pub source: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalPartition {
    pub name: String,
    pub group: u32,
    pub bytes: u64,
    pub extents: Vec<Extent>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub maximum_size: u64,
    pub allocated_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Super {
    pub slot: u32,
    pub slot_count: u32,
    pub logical_block_size: u32,
    pub groups: Vec<Group>,
    pub partitions: Vec<LogicalPartition>,
}
fn table<'a>(h: &[u8], t: &'a [u8], o: usize, expected: usize) -> Result<Vec<&'a [u8]>> {
    let start = u32le(h, o)? as usize;
    let n = u32le(h, o + 4)? as usize;
    let es = u32le(h, o + 8)? as usize;
    ensure!(
        es == expected && n <= 65536,
        "unsupported logical partition entry geometry"
    );
    let b = slice(t, start, n.checked_mul(es).context("LP table overflow")?)?;
    Ok(b.chunks_exact(es).collect())
}
pub fn super_metadata(r: &mut dyn ReadSeek, slot: u32) -> Result<Super> {
    let len = r.seek(SeekFrom::End(0))?;
    let g = read_at(r, 4096, 52)?;
    ensure!(
        u32le(&g, 0)? == 0x616c4467 && u32le(&g, 4)? == 52,
        "invalid LP geometry"
    );
    let mut check = g.clone();
    check[8..40].fill(0);
    ensure!(
        digest(&check) == hex(&g[8..40]),
        "LP geometry SHA256 mismatch"
    );
    let max = u32le(&g, 40)?;
    let count = u32le(&g, 44)?;
    let block = u32le(&g, 48)?;
    ensure!(
        (128..=16 * 1024 * 1024).contains(&max)
            && max % 512 == 0
            && (1..=32).contains(&count)
            && slot < count
            && block.is_power_of_two()
            && block >= 512,
        "invalid LP geometry sizes"
    );
    let offset = 12288 + slot as u64 * max as u64;
    let fixed = read_at(r, offset, 128)?;
    ensure!(
        u32le(&fixed, 0)? == 0x414c5030 && u16le(&fixed, 4)? == 10 && u16le(&fixed, 6)? <= 2,
        "unsupported LP metadata version"
    );
    let hs = u32le(&fixed, 8)? as usize;
    ensure!(hs == 128 || hs == 256, "unsupported LP header size");
    let ts = u32le(&fixed, 44)? as usize;
    ensure!(
        hs + ts <= max as usize,
        "LP metadata exceeds slot allocation"
    );
    let h = read_at(r, offset, hs)?;
    let mut chk = h.clone();
    chk[12..44].fill(0);
    ensure!(digest(&chk) == hex(&h[12..44]), "LP header SHA256 mismatch");
    let t = read_at(r, offset + hs as u64, ts)?;
    ensure!(digest(&t) == hex(&h[48..80]), "LP table SHA256 mismatch");
    let parts = table(&h, &t, 80, 52)?;
    let ext = table(&h, &t, 92, 24)?;
    let groups = table(&h, &t, 104, 48)?;
    let devices = table(&h, &t, 116, 64)?;
    ensure!(!devices.is_empty(), "super has no block devices");
    let mut gs = groups
        .iter()
        .map(|g| {
            Ok(Group {
                name: string(&g[..36]),
                maximum_size: u64le(g, 40)?,
                allocated_bytes: 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut ps = Vec::new();
    let mut used = Vec::new();
    for p in parts {
        let name = string(&p[..36]);
        ensure!(
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "invalid logical partition name"
        );
        ensure!(
            !ps.iter().any(|p: &LogicalPartition| p.name == name),
            "duplicate logical partition name"
        );
        let first = u32le(p, 40)? as usize;
        let n = u32le(p, 44)? as usize;
        let group = u32le(p, 48)?;
        let group_ref = gs
            .get_mut(group as usize)
            .context("invalid LP group reference")?;
        let mut extents = Vec::new();
        let mut bytes = 0u64;
        for e in ext
            .get(first..first.checked_add(n).context("LP extent index overflow")?)
            .context("invalid LP extent reference")?
        {
            let size = u64le(e, 0)?.checked_mul(512).context("LP size overflow")?;
            let kind = u32le(e, 8)?;
            let source = u32le(e, 20)?;
            let off = u64le(e, 12)?
                .checked_mul(512)
                .context("LP offset overflow")?;
            ensure!(kind <= 1, "unsupported LP extent type");
            if kind == 0 {
                let d = devices
                    .get(source as usize)
                    .context("LP extent references absent block device")?;
                bounded(off, size, u64le(d, 16)?)?;
                ensure!(
                    off / 512 >= u64le(d, 0)?,
                    "LP extent overlaps reserved metadata"
                );
                if source == 0 {
                    bounded(off, size, len)?;
                }
                if size > 0 {
                    used.push((source, off, off + size));
                }
            } else {
                ensure!(source == 0 && off == 0, "invalid zero extent");
            }
            bytes = bytes.checked_add(size).context("LP partition overflow")?;
            extents.push(Extent {
                bytes: size,
                offset: off,
                zero: kind == 1,
                source,
            });
        }
        group_ref.allocated_bytes = group_ref
            .allocated_bytes
            .checked_add(bytes)
            .context("LP group overflow")?;
        ps.push(LogicalPartition {
            name,
            group,
            bytes,
            extents,
        });
    }
    used.sort();
    ensure!(
        used.windows(2)
            .all(|w| w[0].0 != w[1].0 || w[0].2 <= w[1].1),
        "overlapping LP extents"
    );
    ensure!(
        gs.iter()
            .all(|g| g.maximum_size == 0 || g.allocated_bytes <= g.maximum_size),
        "LP group capacity exceeded"
    );
    Ok(Super {
        slot,
        slot_count: count,
        logical_block_size: block,
        groups: gs,
        partitions: ps,
    })
}
/// Copy a validated internal logical partition, in logical extent order.
/// External block-device references are rejected before writing any output.
pub fn extract_logical(
    r: &mut dyn ReadSeek,
    slot: u32,
    name: &str,
    out: &mut dyn Write,
) -> Result<LogicalPartition> {
    let metadata = super_metadata(r, slot)?;
    let part = metadata
        .partitions
        .into_iter()
        .find(|p| p.name == name)
        .context("required logical partition missing")?;
    ensure!(part.bytes > 0, "logical partition is empty");
    ensure!(
        part.extents.iter().all(|e| e.source == 0),
        "external block-device extents require a multi-device liblp adapter"
    );
    for extent in &part.extents {
        gb_core::checkpoint()?;
        let n = if extent.zero {
            gb_core::copy_stream(std::io::repeat(0).take(extent.bytes), &mut *out)?
        } else {
            gb_core::copy_stream(Region::new(r, extent.offset, extent.bytes)?, &mut *out)?
        };
        ensure!(n == extent.bytes, "logical extent truncated");
    }
    Ok(part)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

pub fn inspect(r: &mut dyn ReadSeek, format: &Format) -> Result<Value> {
    let len = r.seek(SeekFrom::End(0))?;
    let b = read_at(r, 0, len.min(8192) as usize)?;
    match format {
        Format::Gpt => Ok(serde_json::to_value(gpt(r)?)?),
        Format::Super => Ok(serde_json::to_value(super_metadata(r, 0)?)?),
        Format::Boot => {
            let version = u32le(&b, 40)?;
            ensure!(
                version == 3 || version == 4,
                "boot header v{version} recognized; only v3/v4 parsing supported"
            );
            let hs = u32le(&b, 20)?;
            ensure!(
                hs == if version == 4 { 1584 } else { 1580 },
                "invalid boot header size"
            );
            let k = u32le(&b, 8)? as u64;
            let ram = u32le(&b, 12)? as u64;
            let ro = 4096 + align(k, 4096)?;
            bounded(4096, k, len)?;
            bounded(ro, ram, len)?;
            let sig = if version == 4 {
                u32le(&b, 1580)? as u64
            } else {
                0
            };
            bounded(ro + align(ram, 4096)?, sig, len)?;
            let mut arch = None;
            let mut kernel_version = None;
            let mut compression = "uncompressed_or_unknown";
            if k >= 2 {
                let prefix = read_at(r, 4096, k.min(64) as usize)?;
                let kb = if prefix.starts_with(&[0x1f, 0x8b]) {
                    compression = "gzip_bounded_16mib";
                    let region = Region::new(r, 4096, k)?;
                    let mut decoder = flate2::read::GzDecoder::new(region).take(16 * 1024 * 1024);
                    let mut kernel = Vec::new();
                    decoder
                        .read_to_end(&mut kernel)
                        .context("malformed compressed kernel")?;
                    kernel
                } else {
                    read_at(r, 4096, k.min(16 * 1024 * 1024) as usize)?
                };
                if kb.get(56..60) == Some(b"ARM\x64") {
                    arch = Some("aarch64");
                }
                if let Some(pos) = kb.windows(14).position(|x| x == b"Linux version ") {
                    kernel_version = Some(string(&kb[pos..kb.len().min(pos + 256)]));
                }
            }
            Ok(
                json!({"header_version":version,"header_size":hs,"kernel_bytes":k,"ramdisk_bytes":ram,"ramdisk_offset":ro,"signature_bytes":sig,"os_version_encoded":u32le(&b,16)?,"cmdline":string(slice(&b,44,1536)?),"kernel_architecture":arch,"kernel_version":kernel_version,"kernel_inspection_window_bytes":16*1024*1024,"compressed_kernel_analysis":compression}),
            )
        }
        Format::VendorBoot => {
            let v = u32le(&b, 8)?;
            ensure!(v == 3 || v == 4, "unsupported vendor boot version");
            let page = u32le(&b, 12)? as u64;
            ensure!(
                (2048..=65536).contains(&page) && page.is_power_of_two(),
                "invalid vendor boot page size"
            );
            let hs = u32le(&b, 2096)? as u64;
            ensure!(
                hs == if v == 4 { 2128 } else { 2112 },
                "invalid vendor boot header size"
            );
            let ram = u32le(&b, 24)? as u64;
            let dtb = u32le(&b, 2100)? as u64;
            let start = align(hs, page)?;
            bounded(start, ram, len)?;
            bounded(start + align(ram, page)?, dtb, len)?;
            let mut fragments = Vec::new();
            let mut bootconfig = 0;
            if v == 4 {
                let ts = u32le(&b, 2112)? as u64;
                let n = u32le(&b, 2116)? as usize;
                let es = u32le(&b, 2120)? as usize;
                bootconfig = u32le(&b, 2124)?;
                ensure!(
                    es == 108 && n <= 65536 && n as u64 * es as u64 == ts,
                    "invalid vendor ramdisk table geometry"
                );
                let table_offset = start + align(ram, page)? + align(dtb, page)?;
                let table = read_at(r, table_offset, ts as usize)?;
                for e in table.chunks_exact(es) {
                    let size = u32le(e, 0)?;
                    let off = u32le(e, 4)?;
                    bounded(off as u64, size as u64, ram)?;
                    fragments.push(json!({"name":string(&e[12..44]),"bytes":size,"offset":off,"kind":u32le(e,8)?}));
                }
                bounded(table_offset + align(ts, page)?, bootconfig as u64, len)?;
            }
            Ok(
                json!({"header_version":v,"page_size":page,"ramdisk_bytes":ram,"dtb_bytes":dtb,"bootconfig_bytes":bootconfig,"fragments":fragments,"cmdline":string(slice(&b,28,2048)?)}),
            )
        }
        Format::Vbmeta => avb(r, 0),
        Format::Dtbo => {
            let total = u32be(&b, 4)?;
            let hs = u32be(&b, 8)?;
            let es = u32be(&b, 12)?;
            let n = u32be(&b, 16)?;
            let off = u32be(&b, 20)?;
            ensure!(
                total as u64 <= len && hs >= 32 && es >= 32 && n <= 65536,
                "invalid DTBO header"
            );
            let table = read_at(
                r,
                off as u64,
                (n as usize)
                    .checked_mul(es as usize)
                    .context("DTBO table overflow")?,
            )?;
            for e in table.chunks_exact(es as usize) {
                bounded(u32be(e, 4)? as u64, u32be(e, 0)? as u64, total as u64)?;
            }
            Ok(
                json!({"entries":n,"total_bytes":total,"page_size":u32be(&b,24)?,"version":u32be(&b,28)?}),
            )
        }
        Format::Sparse => sparse(r),
        Format::Ext4 => {
            let log = u32le(&b, 1048)?;
            ensure!(log <= 6, "invalid ext4 block size");
            let block = 1024u64 << log;
            let flags = u32le(&b, 1120)?;
            let blocks = u32le(&b, 1028)? as u64
                | if flags & 0x80 != 0 {
                    (u32le(&b, 1360)? as u64) << 32
                } else {
                    0
                };
            let bytes = blocks.checked_mul(block).context("ext4 size overflow")?;
            ensure!(bytes <= len, "truncated ext4 filesystem");
            Ok(
                json!({"block_size":block,"filesystem_bytes":bytes,"label":string(slice(&b,1144,16)?),"feature_incompat":flags,"extraction_required":true}),
            )
        }
        Format::Erofs => {
            let bits = *slice(&b, 1036, 1)?
                .first()
                .context("EROFS block size absent")?;
            ensure!((9..=16).contains(&bits), "invalid EROFS block size");
            let flags = u32le(&b, 1104)?;
            let blocks = u32le(&b, 1060)? as u64
                | if flags & 0x80 != 0 {
                    (u16le(&b, 1038)? as u64) << 32
                } else {
                    0
                };
            let bytes = blocks
                .checked_mul(1u64 << bits)
                .context("EROFS size overflow")?;
            ensure!(bytes <= len, "truncated EROFS filesystem");
            Ok(
                json!({"block_size":1u64<<bits,"filesystem_bytes":bytes,"feature_compat":u32le(&b,1032)?,"feature_incompat":flags,"superblock_checksum":u32le(&b,1028)?,"superblock_checksum_verified":false,"extra_devices":u16le(&b,1110)?,"extraction_required":true}),
            )
        }
        Format::OtaPayload => {
            let version = u64be(&b, 4)?;
            ensure!(
                version == 1 || version == 2,
                "unsupported OTA payload version"
            );
            let manifest = u64be(&b, 12)?;
            let sig = if version == 2 { u32be(&b, 20)? } else { 0 };
            bounded(
                if version == 2 { 24 } else { 20 },
                manifest
                    .checked_add(sig as u64)
                    .context("OTA size overflow")?,
                len,
            )?;
            Ok(
                json!({"version":version,"manifest_bytes":manifest,"signature_bytes":sig,"decoder_supported":false}),
            )
        }
        _ => Ok(json!({})),
    }
}
pub fn avb(r: &mut dyn ReadSeek, offset: u64) -> Result<Value> {
    let len = r.seek(SeekFrom::End(0))?;
    let h = read_at(r, offset, 256)?;
    ensure!(&h[..4] == b"AVB0", "invalid AVB header");
    let auth = u64be(&h, 12)?;
    let aux = u64be(&h, 20)?;
    let aux_offset = offset
        .checked_add(256)
        .and_then(|n| n.checked_add(auth))
        .context("AVB block overflow")?;
    bounded(aux_offset, aux, len)?;
    for (off, size) in [(32, 40), (48, 56)] {
        bounded(u64be(&h, off)?, u64be(&h, size)?, auth)?;
    }
    for (off, size) in [(64, 72), (80, 88), (96, 104)] {
        bounded(u64be(&h, off)?, u64be(&h, size)?, aux)?;
    }
    let ds = u64be(&h, 104)?;
    ensure!(ds <= 16 * 1024 * 1024, "AVB descriptors too large");
    let desc = read_at(r, aux_offset + u64be(&h, 96)?, ds as usize)?;
    let mut descriptors = Vec::new();
    let mut pos = 0;
    while pos < desc.len() {
        let tag = u64be(&desc, pos)?;
        let follow = u64be(&desc, pos + 8)?;
        let size = follow.checked_add(16).context("AVB descriptor overflow")?;
        ensure!(size % 8 == 0, "unaligned AVB descriptor");
        let e = slice(&desc, pos, size.try_into()?)?;
        let mut info = json!({"tag":tag,"bytes":size,"sha256":digest(e)});
        if tag == 2 {
            let n = u32be(e, 56)? as usize;
            let salt = u32be(e, 60)? as usize;
            let dg = u32be(e, 64)? as usize;
            let name = string(slice(e, 132, n)?);
            slice(
                e,
                132 + n,
                salt.checked_add(dg).context("AVB hash size overflow")?,
            )?;
            info["partition"] = json!(name);
            info["image_bytes"] = json!(u64be(e, 16)?);
            info["hash_algorithm"] = json!(string(slice(e, 24, 32)?));
        }
        if tag == 1 {
            let n = u32be(e, 104)? as usize;
            let salt = u32be(e, 108)? as usize;
            let root = u32be(e, 112)? as usize;
            info["partition"] = json!(string(slice(e, 180, n)?));
            slice(
                e,
                180 + n,
                salt.checked_add(root)
                    .context("AVB hashtree sizes overflow")?,
            )?;
            info["image_bytes"] = json!(u64be(e, 20)?);
            info["hash_algorithm"] = json!(string(slice(e, 72, 32)?));
            info["tree_offset"] = json!(u64be(e, 28)?);
            info["tree_bytes"] = json!(u64be(e, 36)?);
        }
        if tag == 4 {
            let n = u32be(e, 20)? as usize;
            let key = u32be(e, 24)? as usize;
            info["partition"] = json!(string(slice(e, 92, n)?));
            slice(e, 92 + n, key)?;
            info["rollback_index_location"] = json!(u32be(e, 16)?);
        }
        descriptors.push(info);
        pos = pos
            .checked_add(size as usize)
            .context("AVB descriptor position overflow")?;
    }
    Ok(
        json!({"required_libavb_major":u32be(&h,4)?,"required_libavb_minor":u32be(&h,8)?,"algorithm_type":u32be(&h,28)?,"rollback_index":u64be(&h,112)?,"rollback_index_location":u32be(&h,124)?,"flags":u32be(&h,120)?,"release_string":string(&h[128..176]),"descriptors":descriptors,"cryptographic_signature_verified":false}),
    )
}
pub fn avb_footer(r: &mut dyn ReadSeek) -> Result<Option<Value>> {
    let len = r.seek(SeekFrom::End(0))?;
    if len < 64 {
        return Ok(None);
    }
    let h = read_at(r, len - 64, 64)?;
    if &h[..4] != b"AVBf" {
        return Ok(None);
    }
    let offset = u64be(&h, 20)?;
    let size = u64be(&h, 28)?;
    bounded(offset, size, len - 64)?;
    ensure!(u64be(&h, 12)? <= offset, "AVB footer original size invalid");
    Ok(Some(avb(r, offset)?))
}
fn sparse(r: &mut dyn ReadSeek) -> Result<Value> {
    let len = r.seek(SeekFrom::End(0))?;
    let h = read_at(r, 0, 28)?;
    ensure!(u16le(&h, 4)? == 1, "unsupported sparse version");
    let fh = u16le(&h, 8)? as u64;
    let ch = u16le(&h, 10)? as u64;
    let block = u32le(&h, 12)? as u64;
    let blocks = u32le(&h, 16)? as u64;
    let chunks = u32le(&h, 20)?;
    ensure!(
        fh >= 28
            && (12..=4096).contains(&ch)
            && block > 0
            && block.is_multiple_of(4)
            && chunks <= 10_000_000,
        "invalid sparse geometry"
    );
    let mut pos = fh;
    let mut total = 0u64;
    for _ in 0..chunks {
        let e = read_at(r, pos, 12)?;
        let kind = u16le(&e, 0)?;
        let n = u32le(&e, 4)? as u64;
        let size = u32le(&e, 8)? as u64;
        let data = match kind {
            0xcac1 => n.checked_mul(block).context("sparse raw size overflow")?,
            0xcac2 => 4,
            0xcac3 => 0,
            0xcac4 => {
                ensure!(n == 0, "invalid sparse CRC chunk");
                4
            }
            _ => bail!("unknown sparse chunk type"),
        };
        ensure!(size == ch + data, "sparse chunk size mismatch");
        bounded(pos, size, len)?;
        total = total.checked_add(n).context("sparse blocks overflow")?;
        pos = pos.checked_add(size).context("sparse cursor overflow")?;
    }
    ensure!(total == blocks && pos == len, "sparse total size mismatch");
    Ok(
        json!({"block_size":block,"blocks":blocks,"chunks":chunks,"expanded_bytes":blocks.checked_mul(block).context("sparse expansion overflow")?,"checksum_verified":false,"conversion_tool":"simg2img"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn super_fixture(external: bool) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut image = vec![0; 65536];
        let mut geometry = vec![0; 52];
        geometry[0..4].copy_from_slice(&0x616c4467u32.to_le_bytes());
        geometry[4..8].copy_from_slice(&52u32.to_le_bytes());
        geometry[40..44].copy_from_slice(&4096u32.to_le_bytes());
        geometry[44..48].copy_from_slice(&2u32.to_le_bytes());
        geometry[48..52].copy_from_slice(&4096u32.to_le_bytes());
        let sha = Sha256::digest(&geometry);
        geometry[8..40].copy_from_slice(&sha);
        image[4096..4148].copy_from_slice(&geometry);
        let mut table = vec![0; 300];
        table[..8].copy_from_slice(b"system_a");
        table[44..48].copy_from_slice(&3u32.to_le_bytes());
        for (i, sector, zero) in [(0, 100u64, false), (1, 0, true), (2, 80, false)] {
            let e = &mut table[52 + i * 24..52 + (i + 1) * 24];
            e[..8].copy_from_slice(&1u64.to_le_bytes());
            e[8..12].copy_from_slice(&u32::from(zero).to_le_bytes());
            e[12..20].copy_from_slice(&sector.to_le_bytes());
            if external && i == 2 {
                e[20..24].copy_from_slice(&1u32.to_le_bytes());
            }
        }
        table[124..131].copy_from_slice(b"default");
        for start in [172, 236] {
            table[start..start + 8].copy_from_slice(&64u64.to_le_bytes());
            table[start + 16..start + 24].copy_from_slice(&65536u64.to_le_bytes());
        }
        let mut header = vec![0; 128];
        header[..4].copy_from_slice(&0x414c5030u32.to_le_bytes());
        header[4..6].copy_from_slice(&10u16.to_le_bytes());
        header[8..12].copy_from_slice(&128u32.to_le_bytes());
        header[44..48].copy_from_slice(&(table.len() as u32).to_le_bytes());
        header[48..80].copy_from_slice(&Sha256::digest(&table));
        for (base, start, count, size) in [
            (80, 0u32, 1u32, 52u32),
            (92, 52, 3, 24),
            (104, 124, 1, 48),
            (116, 172, 2, 64),
        ] {
            header[base..base + 4].copy_from_slice(&start.to_le_bytes());
            header[base + 4..base + 8].copy_from_slice(&count.to_le_bytes());
            header[base + 8..base + 12].copy_from_slice(&size.to_le_bytes());
        }
        let sha = Sha256::digest(&header);
        header[12..44].copy_from_slice(&sha);
        image[12288..12416].copy_from_slice(&header);
        image[12416..12416 + table.len()].copy_from_slice(&table);
        image[100 * 512..101 * 512].fill(0xA1);
        image[80 * 512..81 * 512].fill(0xB2);
        image
    }
    #[test]
    fn logical_extent_order_zero_and_external_refusal() {
        let mut out = vec![];
        let part = extract_logical(
            &mut Cursor::new(super_fixture(false)),
            0,
            "system_a",
            &mut out,
        )
        .unwrap();
        assert_eq!(part.bytes, 1536);
        assert_eq!(
            out,
            [vec![0xA1; 512], vec![0; 512], vec![0xB2; 512]].concat()
        );
        let mut out = vec![];
        assert!(
            extract_logical(
                &mut Cursor::new(super_fixture(true)),
                0,
                "system_a",
                &mut out
            )
            .is_err()
        );
        assert!(out.is_empty());
    }
    #[test]
    fn corrupt_logical_metadata_refused_before_output() {
        let mut image = super_fixture(false);
        image[12416] ^= 1;
        let mut out = vec![];
        assert!(extract_logical(&mut Cursor::new(image), 0, "system_a", &mut out).is_err());
        assert!(out.is_empty());
        assert!(
            extract_logical(
                &mut Cursor::new(super_fixture(false)),
                2,
                "system_a",
                &mut out
            )
            .is_err()
        );
    }
    #[test]
    fn erofs_checksum_is_distinct_from_features() {
        let mut b = vec![0; 4096];
        b[1024..1028].copy_from_slice(&0xe0f5e1e2u32.to_le_bytes());
        b[1028..1032].copy_from_slice(&0x12345678u32.to_le_bytes());
        b[1032..1036].copy_from_slice(&7u32.to_le_bytes());
        b[1036] = 12;
        b[1060..1064].copy_from_slice(&1u32.to_le_bytes());
        b[1104..1108].copy_from_slice(&3u32.to_le_bytes());
        let m = inspect(&mut Cursor::new(b.clone()), &Format::Erofs).unwrap();
        assert_eq!(m["feature_compat"], 7);
        assert_eq!(m["superblock_checksum"], 0x12345678u32);
        assert_eq!(m["superblock_checksum_verified"], false);
        b[1104..1108].copy_from_slice(&0x80u32.to_le_bytes());
        b[1038..1040].copy_from_slice(&1u16.to_le_bytes());
        assert!(inspect(&mut Cursor::new(b), &Format::Erofs).is_err());
    }
    use std::io::Cursor;
    #[test]
    fn signature_not_extension() {
        assert_eq!(detect(b"ANDROID!"), Format::Boot);
        assert_eq!(detect(b"not an image.img"), Format::Unknown);
    }
    #[test]
    fn bounded_region() {
        let mut c = Cursor::new(vec![1, 2, 3, 4]);
        let mut r = Region::new(&mut c, 1, 2).unwrap();
        let mut b = Vec::new();
        r.read_to_end(&mut b).unwrap();
        assert_eq!(b, vec![2, 3]);
        assert!(r.seek(SeekFrom::Start(3)).is_err());
    }
    #[test]
    fn malformed_inputs_never_panic() {
        for n in [0, 1, 8, 40, 256, 4096] {
            for fmt in [
                Format::Boot,
                Format::VendorBoot,
                Format::Vbmeta,
                Format::Super,
                Format::Gpt,
                Format::Sparse,
                Format::Dtbo,
            ] {
                let mut c = Cursor::new(vec![0; n]);
                assert!(inspect(&mut c, &fmt).is_err());
            }
        }
    }
    #[test]
    fn boot_v4_sizes() {
        let mut b = vec![0; 4096];
        b[..8].copy_from_slice(b"ANDROID!");
        b[20..24].copy_from_slice(&1584u32.to_le_bytes());
        b[40..44].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            inspect(&mut Cursor::new(b.clone()), &Format::Boot).unwrap()["header_version"],
            4
        );
        b[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(inspect(&mut Cursor::new(b), &Format::Boot).is_err());
    }
    #[test]
    fn avb_rollback() {
        let mut b = vec![0; 256];
        b[..4].copy_from_slice(b"AVB0");
        b[112..120].copy_from_slice(&42u64.to_be_bytes());
        let m = inspect(&mut Cursor::new(b), &Format::Vbmeta).unwrap();
        assert_eq!(m["rollback_index"], 42);
        assert_eq!(m["cryptographic_signature_verified"], false);
    }
    #[test]
    fn mica_vendor_boot_2048_byte_pages() {
        let mut b = vec![0; 4096];
        b[..8].copy_from_slice(b"VNDRBOOT");
        b[8..12].copy_from_slice(&4u32.to_le_bytes());
        b[12..16].copy_from_slice(&2048u32.to_le_bytes());
        b[2096..2100].copy_from_slice(&2128u32.to_le_bytes());
        b[2120..2124].copy_from_slice(&108u32.to_le_bytes());
        let metadata = inspect(&mut Cursor::new(b), &Format::VendorBoot).unwrap();
        assert_eq!(metadata["page_size"], 2048);
    }
    #[test]
    fn gzip_kernel_architecture_is_bounded() {
        use std::io::Write;
        let mut kernel = vec![0; 1024];
        kernel[56..60].copy_from_slice(b"ARM\x64");
        kernel[64..85].copy_from_slice(b"Linux version 6.1.128");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&kernel).unwrap();
        let compressed = gz.finish().unwrap();
        let mut boot = vec![0; 8192];
        boot[..8].copy_from_slice(b"ANDROID!");
        boot[8..12].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
        boot[20..24].copy_from_slice(&1584u32.to_le_bytes());
        boot[40..44].copy_from_slice(&4u32.to_le_bytes());
        boot[4096..4096 + compressed.len()].copy_from_slice(&compressed);
        let metadata = inspect(&mut Cursor::new(boot), &Format::Boot).unwrap();
        assert_eq!(metadata["kernel_architecture"], "aarch64");
    }
    #[test]
    fn avb_chain_partition_field_offsets() {
        let mut b = vec![0; 360];
        b[..4].copy_from_slice(b"AVB0");
        b[20..28].copy_from_slice(&104u64.to_be_bytes());
        b[104..112].copy_from_slice(&104u64.to_be_bytes());
        b[256..264].copy_from_slice(&4u64.to_be_bytes());
        b[264..272].copy_from_slice(&88u64.to_be_bytes());
        b[272..276].copy_from_slice(&3u32.to_be_bytes());
        b[276..280].copy_from_slice(&6u32.to_be_bytes());
        b[280..284].copy_from_slice(&2u32.to_be_bytes());
        b[348..354].copy_from_slice(b"system");
        let metadata = inspect(&mut Cursor::new(b), &Format::Vbmeta).unwrap();
        assert_eq!(metadata["descriptors"][0]["partition"], "system");
        assert_eq!(metadata["descriptors"][0]["rollback_index_location"], 3);
    }
}
