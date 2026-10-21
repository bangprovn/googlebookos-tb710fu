//! Read-only planning for signed replacements occupying one existing LP extent.
//! Execution must separately revalidate the physical GPT, device identity and
//! current device hashes, and obtain confirmation. This module never flashes.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalSuper {
    pub lun: u32,
    pub offset: u64,
    pub bytes: u64,
    pub sector_bytes: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Write {
    pub logical_partition: String,
    pub image: PathBuf,
    pub sha256: String,
    pub expected_previous_sha256: String,
    pub bytes: u64,
    pub lun: u32,
    pub start_sector: u64,
    pub sector_count: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub writes: Vec<Write>,
    pub resulting_super_sha256: String,
}
pub fn geometry(super_partition: &PhysicalSuper, offset: u64, bytes: u64) -> Result<(u64, u64)> {
    let sector = u64::from(super_partition.sector_bytes);
    ensure!(
        [512, 1024, 2048, 4096].contains(&sector)
            && super_partition.bytes > 0
            && super_partition.bytes.is_multiple_of(sector),
        "unsupported physical sector size/capacity"
    );
    ensure!(
        bytes > 0
            && offset
                .checked_add(bytes)
                .is_some_and(|end| end <= super_partition.bytes),
        "extent exceeds physical super"
    );
    let start = super_partition
        .offset
        .checked_add(offset)
        .context("physical address overflow")?;
    start.checked_add(bytes).context("physical end overflow")?;
    ensure!(
        start.is_multiple_of(sector)
            && bytes.is_multiple_of(sector)
            && super_partition.offset.is_multiple_of(sector),
        "unaligned physical update"
    );
    Ok((start / sector, bytes / sector))
}
pub fn plan(request: &crate::super_image::Request, physical: &PhysicalSuper) -> Result<Plan> {
    request.validate()?;
    ensure!(
        std::fs::metadata(&request.base.path)?.len() == physical.bytes,
        "physical capacity mismatch"
    );
    // Parse bounded LP metadata read-only. overlay_hash below verifies every
    // original byte against the pinned base before returning any plan. Avoid a
    // redundant full-image hash here; large super images otherwise need a third
    // pass in addition to calculating original/resulting digests together.
    let mut base = File::open(&request.base.path)?;
    let layout = gb_partition::super_metadata(&mut base, request.slot)?;
    let mut writes = Vec::new();
    for (name, input) in &request.replacements {
        let partition = layout
            .partitions
            .iter()
            .find(|p| &p.name == name)
            .context("LP destination absent")?;
        ensure!(
            partition.extents.len() == 1,
            "delta planning supports one contiguous extent; use full super assembly for scattered extents"
        );
        let extent = &partition.extents[0];
        ensure!(
            !extent.zero
                && extent.source == 0
                && extent.bytes == partition.bytes
                && std::fs::metadata(&input.path)?.len() == extent.bytes,
            "signed replacement must exactly fit one internal linear extent"
        );
        ensure!(
            gb_core::hash_file(&input.path)? == input.sha256,
            "replacement SHA256 mismatch"
        );
        gb_partition::avb_footer(&mut File::open(&input.path)?)?
            .context("signed partition footer required")?;
        for other in &layout.partitions {
            if &other.name == name {
                continue;
            }
            for e in &other.extents {
                if !e.zero && e.source == 0 {
                    let end = extent
                        .offset
                        .checked_add(extent.bytes)
                        .context("extent overflow")?;
                    let other_end = e
                        .offset
                        .checked_add(e.bytes)
                        .context("neighbor extent overflow")?;
                    ensure!(
                        end <= e.offset || other_end <= extent.offset,
                        "update overlaps another logical partition"
                    );
                }
            }
        }
        let (start_sector, sector_count) = geometry(physical, extent.offset, extent.bytes)?;
        base.seek(SeekFrom::Start(extent.offset))?;
        let previous = gb_core::hash_reader((&mut base).take(extent.bytes))?;
        writes.push(Write {
            logical_partition: name.clone(),
            image: input.path.clone(),
            sha256: input.sha256.clone(),
            expected_previous_sha256: previous,
            bytes: extent.bytes,
            lun: physical.lun,
            start_sector,
            sector_count,
        });
    }
    let mut overlays = Vec::new();
    for write in &writes {
        let offset = write
            .start_sector
            .checked_mul(u64::from(physical.sector_bytes))
            .and_then(|v| v.checked_sub(physical.offset))
            .context("invalid overlay address")?;
        overlays.push((offset, write));
    }
    let resulting_super_sha256 = overlay_hash(
        &mut base,
        physical.bytes,
        &request.base.sha256,
        &mut overlays,
    )?;
    Ok(Plan {
        writes,
        resulting_super_sha256,
    })
}

// Calculate the exact complete super checksum without creating another 20 GB
// file. Rehash every original byte and each replacement in the same pass so
// input changes between planning and digest computation fail closed.
pub(crate) fn overlay_hash(
    base: &mut File,
    bytes: u64,
    expected_base: &str,
    overlays: &mut [(u64, &Write)],
) -> Result<String> {
    overlays.sort_by_key(|(offset, _)| *offset);
    base.seek(SeekFrom::Start(0))?;
    let mut original = Sha256::new();
    let mut result = Sha256::new();
    let mut cursor = 0;
    for (offset, write) in overlays {
        ensure!(*offset >= cursor, "overlapping or out-of-order overlays");
        let end = offset
            .checked_add(write.bytes)
            .context("overlay end overflow")?;
        ensure!(end <= bytes, "overlay exceeds super");
        hash_exact(base, *offset - cursor, &mut original, Some(&mut result))?;
        let mut old = Sha256::new();
        hash_exact(base, write.bytes, &mut original, Some(&mut old))?;
        ensure!(
            format!("{:x}", old.finalize()) == write.expected_previous_sha256,
            "original extent changed"
        );
        let mut replacement = File::open(&write.image)?;
        ensure!(
            replacement.metadata()?.len() == write.bytes,
            "replacement size changed"
        );
        let mut new = Sha256::new();
        hash_exact(&mut replacement, write.bytes, &mut result, Some(&mut new))?;
        ensure!(
            format!("{:x}", new.finalize()) == write.sha256,
            "replacement changed during digest computation"
        );
        ensure!(
            replacement.metadata()?.len() == write.bytes,
            "replacement size changed"
        );
        cursor = end;
    }
    hash_exact(base, bytes - cursor, &mut original, Some(&mut result))?;
    ensure!(base.metadata()?.len() == bytes, "base size changed");
    ensure!(
        format!("{:x}", original.finalize()) == expected_base,
        "base changed during digest computation"
    );
    Ok(format!("{:x}", result.finalize()))
}

fn hash_exact(
    reader: &mut File,
    mut bytes: u64,
    primary: &mut Sha256,
    mut secondary: Option<&mut Sha256>,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024 * 1024];
    while bytes > 0 {
        gb_core::checkpoint()?;
        let count = bytes.min(buffer.len() as u64) as usize;
        reader
            .read_exact(&mut buffer[..count])
            .context("truncated overlay input")?;
        let chunk = &buffer[..count];
        primary.update(chunk);
        if let Some(other) = secondary.as_deref_mut() {
            other.update(chunk);
        }
        bytes -= count as u64;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sector_plan_does_not_round_into_neighbors() {
        let p = PhysicalSuper {
            lun: 0,
            offset: 4096,
            bytes: 16384,
            sector_bytes: 4096,
        };
        assert_eq!(geometry(&p, 4096, 8192).unwrap(), (2, 2));
        assert!(geometry(&p, 4097, 8192).is_err());
        assert!(geometry(&p, 4096, 8193).is_err());
        assert!(geometry(&p, 12288, 8192).is_err());
        assert!(geometry(&p, 0, 0).is_err());
    }
    #[test]
    fn physical_address_overflow_is_refused() {
        let p = PhysicalSuper {
            lun: 0,
            offset: u64::MAX - 4095,
            bytes: 16384,
            sector_bytes: 4096,
        };
        assert!(geometry(&p, 4096, 4096).is_err());
        let p = PhysicalSuper {
            sector_bytes: 0,
            ..p
        };
        assert!(geometry(&p, 0, 4096).is_err());
    }
    #[test]
    fn overlay_digest_matches_materialized_image_and_detects_changed_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let base_path = dir.path().join("super");
        let replacement = dir.path().join("replacement");
        std::fs::write(&base_path, b"aaaabbbbcccc").unwrap();
        std::fs::write(&replacement, b"DDDD").unwrap();
        let expected_base = gb_core::hash_file(&base_path).unwrap();
        let write = Write {
            logical_partition: "system_ext_a".into(),
            image: replacement.clone(),
            sha256: gb_core::hash_file(&replacement).unwrap(),
            expected_previous_sha256: gb_core::hash_reader(&b"bbbb"[..]).unwrap(),
            bytes: 4,
            lun: 0,
            start_sector: 0,
            sector_count: 0,
        };
        let mut base = File::open(&base_path).unwrap();
        let expected = gb_core::hash_reader(&b"aaaaDDDDcccc"[..]).unwrap();
        assert_eq!(
            overlay_hash(&mut base, 12, &expected_base, &mut [(4, &write)]).unwrap(),
            expected
        );
        assert!(
            overlay_hash(
                &mut base,
                12,
                &expected_base,
                &mut [(4, &write), (4, &write)]
            )
            .is_err()
        );
        std::fs::write(&replacement, b"EEEE").unwrap();
        assert!(overlay_hash(&mut base, 12, &expected_base, &mut [(4, &write)]).is_err());
        std::fs::write(&replacement, b"DDDD").unwrap();
        std::fs::write(&base_path, b"zaaabbbbcccc").unwrap();
        assert!(overlay_hash(&mut base, 12, &expected_base, &mut [(4, &write)]).is_err());
        std::fs::write(&base_path, b"aaaabbb").unwrap();
        assert!(overlay_hash(&mut base, 12, &expected_base, &mut [(4, &write)]).is_err());
    }
}
