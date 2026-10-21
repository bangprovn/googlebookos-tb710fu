//! Fixed-layout LP image assembly. No partition resizing or physical writes.
use anyhow::{Context, Result, ensure};
use gb_core::{checkpoint, copy_stream, hash_file, write_json};
use gb_partition::super_metadata;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub base: gb_avb::Input,
    pub slot: u32,
    pub replacements: BTreeMap<String, gb_avb::Input>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub source_sha256: String,
    pub image_sha256: String,
    pub image_bytes: u64,
    pub replacements: BTreeMap<String, String>,
    pub unchanged_ranges_verified: bool,
    pub layout_unchanged: bool,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for input in std::iter::once(&mut r.base).chain(r.replacements.values_mut()) {
            if input.path.is_relative() {
                input.path = parent.join(&input.path);
            }
        }
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && !self.replacements.is_empty(),
            "invalid super assembly request"
        );
        let sha = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            sha(&self.base.sha256) && self.replacements.values().all(|i| sha(&i.sha256)),
            "super inputs require SHA256 pins"
        );
        for name in self.replacements.keys() {
            ensure!(
                [
                    "system",
                    "system_a",
                    "system_b",
                    "system_ext",
                    "system_ext_a",
                    "system_ext_b",
                    "product",
                    "product_a",
                    "product_b"
                ]
                .contains(&name.as_str()),
                "hardware partitions cannot be replaced by the userspace assembler"
            );
        }
        Ok(())
    }
}
fn unchanged(source: &mut File, image: &mut File, start: u64, size: u64) -> Result<()> {
    source.seek(SeekFrom::Start(start))?;
    image.seek(SeekFrom::Start(start))?;
    let mut a = vec![0; 1024 * 1024];
    let mut b = vec![0; a.len()];
    let mut left = size;
    while left > 0 {
        checkpoint()?;
        let n = left.min(a.len() as u64) as usize;
        source.read_exact(&mut a[..n])?;
        image.read_exact(&mut b[..n])?;
        ensure!(
            a[..n] == b[..n],
            "preserved super bytes changed in range at {start}"
        );
        left -= n as u64;
    }
    Ok(())
}
pub fn build(request: &Request, out: &Path) -> Result<Report> {
    request.validate()?;
    gb_core::separate_from_input(&request.base.path, out)?;
    ensure!(
        hash_file(&request.base.path)? == request.base.sha256,
        "base super SHA256 mismatch"
    );
    let size = std::fs::metadata(&request.base.path)?.len();
    ensure!(
        fs2::available_space(out)?
            > size
                .checked_add(256 * 1024 * 1024)
                .context("super staging estimate overflow")?,
        "insufficient super staging space"
    );
    let mut source = File::open(&request.base.path)?;
    let original = super_metadata(&mut source, request.slot)?;
    let mut extents = Vec::new();
    for (name, input) in &request.replacements {
        gb_core::separate_from_input(&input.path, out)?;
        ensure!(
            hash_file(&input.path)? == input.sha256,
            "replacement partition SHA256 mismatch"
        );
        let partition = original
            .partitions
            .iter()
            .find(|p| p.name == *name)
            .context("logical destination missing")?;
        ensure!(
            partition.bytes > 0
                && partition.bytes == std::fs::metadata(&input.path)?.len()
                && partition.extents.iter().all(|e| !e.zero && e.source == 0),
            "replacement must exactly fit existing internal extents"
        );
        gb_partition::avb_footer(&mut File::open(&input.path)?)?
            .context("signed logical partition footer required")?;
        for extent in &partition.extents {
            extents.push((extent.offset, extent.bytes));
        }
    }
    extents.sort_unstable();
    ensure!(
        extents.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0),
        "replacement extents overlap"
    );
    let image = out.join("super.img");
    copy_stream(File::open(&request.base.path)?, File::create(&image)?)?;
    let mut destination = OpenOptions::new().read(true).write(true).open(&image)?;
    for (name, input) in &request.replacements {
        let partition = original
            .partitions
            .iter()
            .find(|p| p.name == *name)
            .context("logical destination disappeared")?;
        let mut replacement = File::open(&input.path)?;
        for extent in &partition.extents {
            destination.seek(SeekFrom::Start(extent.offset))?;
            ensure!(
                copy_stream((&mut replacement).take(extent.bytes), &mut destination)?
                    == extent.bytes,
                "replacement extent truncated"
            );
        }
        // Hash the complete logical sequence through the already existing extractor,
        // using a streaming hash writer rather than materializing a second image.
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        struct Sink<'a>(&'a mut sha2::Sha256);
        impl std::io::Write for Sink<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.update(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        gb_partition::extract_logical(
            &mut destination,
            request.slot,
            name,
            &mut Sink(&mut hasher),
        )?;
        ensure!(
            format!("{:x}", hasher.finalize()) == input.sha256,
            "assembled logical partition checksum differs"
        );
        ensure!(
            hash_file(&input.path)? == input.sha256,
            "replacement changed during super assembly"
        );
    }
    destination.sync_all()?;
    let after = super_metadata(&mut destination, request.slot)?;
    ensure!(
        serde_json::to_vec(&original)? == serde_json::to_vec(&after)?,
        "LP allocation metadata changed"
    );
    let mut cursor = 0;
    for (start, length) in &extents {
        unchanged(&mut source, &mut destination, cursor, *start - cursor)?;
        cursor = start
            .checked_add(*length)
            .context("super extent overflow")?;
    }
    ensure!(cursor <= size, "extent exceeds super");
    unchanged(&mut source, &mut destination, cursor, size - cursor)?;
    ensure!(
        hash_file(&request.base.path)? == request.base.sha256,
        "original super changed during assembly"
    );
    let report = Report {
        schema_version: 1,
        status: "assembled_super_pending_boot_chain_and_runtime_validation".into(),
        bootable: false,
        runtime_verified: false,
        source_sha256: request.base.sha256.clone(),
        image_sha256: hash_file(&image)?,
        image_bytes: size,
        replacements: request
            .replacements
            .iter()
            .map(|(name, i)| (name.clone(), i.sha256.clone()))
            .collect(),
        unchanged_ranges_verified: true,
        layout_unchanged: true,
    };
    write_json(&out.join("super-report.json"), &report)?;
    Ok(report)
}
