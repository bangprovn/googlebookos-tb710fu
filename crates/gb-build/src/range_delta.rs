//! Stage bounded relative partition ranges and prove complete-image reconstruction.
//! There are no device addresses or firmware-write operations in this module.
use anyhow::{Context, Result, ensure};
use gb_core::{hash_file, separate_from_input};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub offset: u64,
    pub bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub source: Input,
    pub candidate: Input,
    pub sector_bytes: u32,
    pub max_write_bytes: u64,
    pub ranges: Vec<Range>,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [&mut r.source.path, &mut r.candidate.path] {
            if p.is_relative() {
                *p = parent.join(&p);
            }
        }
        Ok(r)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    /// Relative to the beginning of this logical partition, never a device address.
    pub offset: u64,
    pub bytes: u64,
    pub file: String,
    pub sha256: String,
    pub expected_previous_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub source_sha256: String,
    pub resulting_partition_sha256: String,
    pub partition_bytes: u64,
    pub sector_bytes: u32,
    pub total_write_bytes: u64,
    pub segments: Vec<Segment>,
    pub complete_partition_reconstruction_verified: bool,
    pub relative_offsets_only: bool,
    pub firmware_written: bool,
    pub runtime_verified: bool,
}
fn ranges(r: &Request, bytes: u64) -> Result<Vec<Range>> {
    ensure!(
        r.schema_version == 1
            && [512, 1024, 2048, 4096].contains(&r.sector_bytes)
            && !r.ranges.is_empty()
            && r.ranges.len() <= 256,
        "invalid range plan request"
    );
    let sector = u64::from(r.sector_bytes);
    let mut sorted = r.ranges.clone();
    sorted.sort_by_key(|p| p.offset);
    let mut end = 0;
    let mut total = 0u64;
    ensure!(
        bytes > 0 && bytes.is_multiple_of(sector),
        "unaligned partition length"
    );
    for p in &sorted {
        ensure!(
            p.bytes > 0
                && p.offset >= end
                && p.offset.is_multiple_of(sector)
                && p.bytes.is_multiple_of(sector),
            "overlapping, empty or unaligned ranges"
        );
        end = p.offset.checked_add(p.bytes).context("range overflow")?;
        ensure!(end <= bytes, "range exceeds logical partition");
        total = total.checked_add(p.bytes).context("range total overflow")?;
    }
    ensure!(
        total <= r.max_write_bytes && total <= bytes,
        "range write budget exceeded"
    );
    Ok(sorted)
}
fn regular(p: &Input) -> Result<u64> {
    let m = std::fs::symlink_metadata(&p.path)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && p.sha256.len() == 64
            && p.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "pinned regular image required"
    );
    Ok(m.len())
}
pub fn stage(r: &Request, output: &Path) -> Result<Report> {
    ensure!(!output.exists(), "range output already exists");
    let bytes = regular(&r.source)?;
    ensure!(
        regular(&r.candidate)? == bytes,
        "candidate partition size differs"
    );
    let ranges = ranges(r, bytes)?;
    for p in [&r.source, &r.candidate] {
        separate_from_input(&p.path, output)?;
    }
    ensure!(
        hash_file(&r.candidate.path)? == r.candidate.sha256,
        "candidate SHA256 differs"
    );
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = tempfile::tempdir_in(parent)?;
    let total = ranges.iter().map(|p| p.bytes).sum::<u64>();
    ensure!(
        fs2::available_space(temporary.path())?
            > total
                .checked_add(64 * 1024 * 1024)
                .context("disk budget overflow")?,
        "insufficient segment staging space"
    );
    let mut source = File::open(&r.source.path)?;
    let mut candidate = File::open(&r.candidate.path)?;
    let mut writes = Vec::new();
    let mut segments = Vec::new();
    for (i, p) in ranges.iter().enumerate() {
        let name = format!("segment-{i:03}.bin");
        let path = temporary.path().join(&name);
        ensure!(
            gb_core::copy_stream(
                gb_partition::Region::new(&mut candidate, p.offset, p.bytes)?,
                File::create(&path)?
            )? == p.bytes,
            "segment source truncated"
        );
        File::open(&path)?.sync_all()?;
        let sha256 = hash_file(&path)?;
        let previous =
            gb_core::hash_reader(gb_partition::Region::new(&mut source, p.offset, p.bytes)?)?;
        writes.push(crate::delta::Write {
            logical_partition: "relative_partition_range".into(),
            image: path,
            sha256: sha256.clone(),
            expected_previous_sha256: previous.clone(),
            bytes: p.bytes,
            lun: 0,
            start_sector: p.offset / u64::from(r.sector_bytes),
            sector_count: p.bytes / u64::from(r.sector_bytes),
        });
        segments.push(Segment {
            offset: p.offset,
            bytes: p.bytes,
            file: name,
            sha256,
            expected_previous_sha256: previous,
        });
    }
    let mut overlays: Vec<_> = ranges
        .iter()
        .zip(&writes)
        .map(|(p, w)| (p.offset, w))
        .collect();
    let projected =
        crate::delta::overlay_hash(&mut source, bytes, &r.source.sha256, &mut overlays)?;
    ensure!(
        projected == r.candidate.sha256,
        "selected ranges do not reconstruct the complete candidate partition"
    );
    // Rehashing these small staged files is included in overlay_hash. No device is opened.
    let report = Report {
        schema_version: 1,
        source_sha256: r.source.sha256.clone(),
        resulting_partition_sha256: projected,
        partition_bytes: bytes,
        sector_bytes: r.sector_bytes,
        total_write_bytes: total,
        segments,
        complete_partition_reconstruction_verified: true,
        relative_offsets_only: true,
        firmware_written: false,
        runtime_verified: false,
    };
    gb_core::write_json(&temporary.path().join("range-plan.json"), &report)?;
    gb_core::publish_directory(temporary.path(), output)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(dir: &Path) -> Request {
        let a = vec![b'a'; 2048];
        let mut b = a.clone();
        b[600] = b'z';
        b[1800] = b'#';
        let source = dir.join("source");
        let candidate = dir.join("candidate");
        std::fs::write(&source, &a).unwrap();
        std::fs::write(&candidate, &b).unwrap();
        Request {
            schema_version: 1,
            source: Input {
                path: source,
                sha256: gb_core::digest(&a),
            },
            candidate: Input {
                path: candidate,
                sha256: gb_core::digest(&b),
            },
            sector_bytes: 512,
            max_write_bytes: 1024,
            ranges: vec![
                Range {
                    offset: 512,
                    bytes: 512,
                },
                Range {
                    offset: 1536,
                    bytes: 512,
                },
            ],
        }
    }
    #[test]
    fn staged_ranges_reconstruct_complete_partition_and_preserve_source() {
        let d = tempfile::tempdir().unwrap();
        let r = fixture(d.path());
        let out = d.path().join("out");
        let result = stage(&r, &out).unwrap();
        assert_eq!(result.total_write_bytes, 1024);
        assert!(
            result.complete_partition_reconstruction_verified
                && result.relative_offsets_only
                && !result.firmware_written
        );
        let mut restored = std::fs::read(&r.source.path).unwrap();
        for s in &result.segments {
            let b = std::fs::read(out.join(&s.file)).unwrap();
            restored[s.offset as usize..(s.offset + s.bytes) as usize].copy_from_slice(&b);
        }
        assert_eq!(restored, std::fs::read(&r.candidate.path).unwrap());
        assert_eq!(hash_file(&r.source.path).unwrap(), r.source.sha256);
        assert!(stage(&r, &out).is_err());
    }
    #[test]
    fn rejects_uncovered_changes_bad_pins_geometry_and_budgets() {
        let d = tempfile::tempdir().unwrap();
        let mut r = fixture(d.path());
        r.ranges.pop();
        assert!(stage(&r, &d.path().join("missing-range")).is_err());
        assert!(!d.path().join("missing-range").exists());
        r = fixture(d.path());
        r.source.sha256 = "0".repeat(64);
        assert!(stage(&r, &d.path().join("bad-source")).is_err());
        r = fixture(d.path());
        r.candidate.sha256 = "0".repeat(64);
        assert!(stage(&r, &d.path().join("bad-candidate")).is_err());
        r = fixture(d.path());
        r.ranges[1].offset = 512;
        assert!(ranges(&r, 2048).is_err());
        r = fixture(d.path());
        r.ranges[0].offset = 513;
        assert!(ranges(&r, 2048).is_err());
        r = fixture(d.path());
        r.max_write_bytes = 512;
        assert!(ranges(&r, 2048).is_err());
        r = fixture(d.path());
        r.ranges[1].bytes = u64::MAX;
        assert!(ranges(&r, 2048).is_err());
    }
}
