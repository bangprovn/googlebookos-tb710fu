//! Bounded read-only inspection of A/B OTA preconditions and source-image hashes.
//! OTA_ZIP NEW_REPORT_JSON. Does not extract partitions or apply operations.
use anyhow::{Context, Result, ensure};
use prost::Message;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};

// Partial wire schema from system/update_engine/update_metadata.proto, Android 17.
// Operation bodies, signatures, dynamic layout and unknown fields are not validated.
#[derive(Clone, PartialEq, Message)]
struct PartitionInfo {
    #[prost(uint64, optional, tag = "1")]
    size: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "2")]
    hash: Option<Vec<u8>>,
}
#[derive(Clone, PartialEq, Message)]
struct Partition {
    #[prost(string, required, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "6")]
    old: Option<PartitionInfo>,
    #[prost(message, optional, tag = "7")]
    new: Option<PartitionInfo>,
}
#[derive(Clone, PartialEq, Message)]
struct Manifest {
    #[prost(uint32, optional, tag = "3")]
    block_size: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    minor_version: Option<u32>,
    #[prost(message, repeated, tag = "13")]
    partitions: Vec<Partition>,
}
#[derive(Serialize)]
struct ImageInfo {
    bytes: Option<u64>,
    sha256: Option<String>,
}
#[derive(Serialize)]
struct Update {
    name: String,
    old: Option<ImageInfo>,
    new: Option<ImageInfo>,
}
fn image_info(value: Option<PartitionInfo>) -> Result<Option<ImageInfo>> {
    value
        .map(|info| {
            ensure!(
                info.hash.as_ref().is_none_or(|hash| hash.len() == 32),
                "invalid partition SHA256 length"
            );
            Ok(ImageInfo {
                bytes: info.size,
                sha256: info
                    .hash
                    .map(|hash| hash.iter().map(|b| format!("{b:02x}")).collect()),
            })
        })
        .transpose()
}
fn manifest(reader: &mut impl Read, payload_bytes: u64) -> Result<(Manifest, String)> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    ensure!(
        &header[..4] == b"CrAU" && u64::from_be_bytes(header[4..12].try_into()?) == 2,
        "only A/B payload version 2 is supported"
    );
    let len = u64::from_be_bytes(header[12..20].try_into()?);
    let sig = u32::from_be_bytes(header[20..24].try_into()?) as u64;
    ensure!(
        len > 0 && len <= 4 * 1024 * 1024 && sig <= 1024 * 1024 && 24 + len + sig <= payload_bytes,
        "payload metadata exceeds bounded input"
    );
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data)?;
    let decoded = Manifest::decode(data.as_slice())?;
    let block = decoded.block_size.unwrap_or(4096);
    ensure!(
        block.is_power_of_two() && (512..=65536).contains(&block),
        "invalid payload block size"
    );
    ensure!(
        !decoded.partitions.is_empty() && decoded.partitions.len() <= 256,
        "payload partition count exceeds limits"
    );
    let mut names = BTreeSet::new();
    for p in &decoded.partitions {
        ensure!(
            !p.name.is_empty()
                && p.name.len() <= 128
                && p.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && names.insert(&p.name),
            "unsafe or duplicate payload partition name"
        );
    }
    Ok((decoded, gb_core::digest(&data)))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 2, "expected OTA_ZIP NEW_REPORT_JSON");
    let input = Path::new(&args[0]);
    let out = Path::new(&args[1]);
    ensure!(!out.exists(), "report destination already exists");
    gb_core::separate_from_input(input, out)?;
    let source_sha256 = gb_core::hash_file(input)?;
    let mut zip = zip::ZipArchive::new(File::open(input)?)?;
    ensure!(zip.len() <= 4096, "OTA ZIP member count exceeds limits");
    let mut names = BTreeSet::new();
    for i in 0..zip.len() {
        let e = zip.by_index(i)?;
        gb_core::safe_relative(Path::new(e.name().trim_end_matches('/')))?;
        ensure!(
            !e.name().contains('\\') && names.insert(e.name().to_string()),
            "unsafe or duplicate ZIP entry"
        );
    }
    let mut metadata = BTreeMap::new();
    {
        let entry = zip.by_name("META-INF/com/android/metadata")?;
        ensure!(entry.size() <= 65536, "OTA text metadata too large");
        let declared_size = entry.size();
        let mut text = String::new();
        entry.take(65537).read_to_string(&mut text)?;
        ensure!(
            text.len() <= 65536 && text.len() as u64 == declared_size,
            "OTA text metadata length mismatch"
        );
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let (key, value) = line.split_once('=').context("invalid OTA metadata line")?;
            ensure!(
                !key.is_empty()
                    && metadata
                        .insert(key.to_string(), value.to_string())
                        .is_none(),
                "duplicate OTA metadata key"
            );
        }
    }
    ensure!(
        metadata.get("ota-type").map(String::as_str) == Some("AB"),
        "not an A/B OTA ZIP"
    );
    let (decoded, manifest_sha256) = {
        let mut payload = zip.by_name("payload.bin")?;
        let size = payload.size();
        manifest(&mut payload, size)?
    };
    let block_size = decoded.block_size.unwrap_or(4096);
    let minor_version = decoded.minor_version.unwrap_or(0);
    let partitions = decoded
        .partitions
        .into_iter()
        .map(|p| {
            Ok(Update {
                name: p.name,
                old: image_info(p.old)?,
                new: image_info(p.new)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        gb_core::hash_file(input)? == source_sha256,
        "OTA source changed during inspection"
    );
    let report = serde_json::json!({"schema_version":1,"status":"ota_preconditions_inspected_only","source_sha256":source_sha256,"payload_version":2,"manifest_sha256":manifest_sha256,"block_size":block_size,"minor_version":minor_version,"incremental":minor_version != 0,"metadata":metadata,"partitions":partitions,"package_signature_verified":false,"payload_operations_validated":false,"source_images_verified":false,"firmware_written":false,"runtime_verified":false,"limitations":["Pre/post fingerprints do not prove applicability to a port","Exact original partition images and boot/security constraints remain required","Unknown protobuf fields, operation bodies and signatures are not validated"]});
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(file.as_file_mut(), &report)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(out)?;
    println!(
        "Inspected {} OTA partitions; no update applied",
        report["partitions"]
            .as_array()
            .context("partitions report")?
            .len()
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn payload(len: u64) -> Vec<u8> {
        let mut bytes = b"CrAU".to_vec();
        bytes.extend(2u64.to_be_bytes());
        bytes.extend(len.to_be_bytes());
        bytes.extend(0u32.to_be_bytes());
        bytes
    }
    #[test]
    fn oversized_or_truncated_metadata_is_rejected_before_allocation() {
        assert!(manifest(&mut payload(u64::MAX).as_slice(), u64::MAX).is_err());
        assert!(manifest(&mut payload(10).as_slice(), 24).is_err());
        assert!(manifest(&mut payload(10).as_slice(), 34).is_err());
    }
    #[test]
    fn partition_paths_and_duplicate_names_are_rejected() {
        for names in [vec!["../boot"], vec!["system", "system"]] {
            let data = Manifest {
                block_size: Some(4096),
                minor_version: Some(9),
                partitions: names
                    .into_iter()
                    .map(|name| Partition {
                        name: name.into(),
                        old: None,
                        new: None,
                    })
                    .collect(),
            }
            .encode_to_vec();
            let mut bytes = payload(data.len() as u64);
            bytes.extend(data);
            assert!(manifest(&mut bytes.as_slice(), bytes.len() as u64).is_err());
        }
    }
}
