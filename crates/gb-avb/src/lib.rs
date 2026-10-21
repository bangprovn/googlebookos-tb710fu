//! Standard authorized-key AVB assembly. Never disables verification or alters device rollback state.
use anyhow::{Context, Result, ensure};
use gb_core::{copy_stream, digest, hash_file, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
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
pub struct Key {
    pub input: Input,
    pub public_key_sha256: String,
    pub algorithm: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    pub name: String,
    pub image: Input,
    pub partition_bytes: u64,
    pub hashtree: bool,
    pub properties_from: Option<Input>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    #[serde(default)]
    pub allow_init_boot_diagnostics: bool,
    #[serde(default)]
    pub allow_kernel_boot_adaptation: bool,
    #[serde(default, skip_serializing_if = "disabled")]
    pub allow_hardware_filesystem_adaptation: bool,
    pub root_template: Input,
    pub system_template: Input,
    pub root_key: Key,
    pub system_key: Key,
    pub partitions: Vec<Partition>,
    pub tool: PathBuf,
    pub sandbox: gb_tools::Sandbox,
}
fn disabled(value: &bool) -> bool {
    !*value
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub avb_flags: u32,
    pub rollback_indices_changed: bool,
    pub root_rollback_index: u64,
    pub system_rollback_index: u64,
    pub checksums: std::collections::BTreeMap<String, String>,
    pub key_public_sha256: Vec<String>,
    pub tool: serde_json::Value,
    pub limitations: Vec<String>,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = parent.join(&*p);
            }
        };
        for input in [
            &mut r.root_template,
            &mut r.system_template,
            &mut r.root_key.input,
            &mut r.system_key.input,
        ] {
            resolve(&mut input.path);
        }
        for p in &mut r.partitions {
            resolve(&mut p.image.path);
            if let Some(i) = &mut p.properties_from {
                resolve(&mut i.path);
            }
        }
        resolve(&mut r.tool);
        r.validate()?;
        Ok(r)
    }
    pub fn inputs(&self) -> Vec<&Input> {
        let mut v = vec![
            &self.root_template,
            &self.system_template,
            &self.root_key.input,
            &self.system_key.input,
        ];
        for p in &self.partitions {
            v.push(&p.image);
            if let Some(i) = &p.properties_from {
                v.push(i);
            }
        }
        v
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && !self.partitions.is_empty(),
            "invalid AVB assembly request"
        );
        self.sandbox.validate()?;
        let sha = |v: &str| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            self.inputs().iter().all(|i| sha(&i.sha256)),
            "all AVB inputs must be SHA256 pinned"
        );
        for key in [&self.root_key, &self.system_key] {
            ensure!(
                sha(&key.public_key_sha256)
                    && ["SHA256_RSA2048", "SHA256_RSA4096"].contains(&key.algorithm.as_str()),
                "explicit authorized RSA signing key identity required"
            );
        }
        let mut names = BTreeSet::new();
        for p in &self.partitions {
            ensure!(
                (["system", "system_ext", "product", "vendor_boot"].contains(&p.name.as_str())
                    || (self.allow_hardware_filesystem_adaptation
                        && ["vendor", "odm"].contains(&p.name.as_str()))
                    || (self.allow_init_boot_diagnostics && p.name == "init_boot")
                    || (self.allow_kernel_boot_adaptation && p.name == "boot"))
                    && names.insert(&p.name)
                    && p.partition_bytes > 0
                    && p.partition_bytes.is_multiple_of(4096),
                "invalid/duplicate signed partition request"
            );
            ensure!(
                p.hashtree != boot_partition(&p.name),
                "unexpected boot/filesystem descriptor type"
            );
        }
        Ok(())
    }
}
fn root_partition(name: &str) -> bool {
    boot_partition(name) || ["vendor", "odm"].contains(&name)
}
fn boot_partition(name: &str) -> bool {
    ["boot", "vendor_boot", "init_boot"].contains(&name)
}
fn be64(b: &[u8], i: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        b.get(i..i + 8).context("truncated AVB field")?.try_into()?,
    ))
}
fn be32(b: &[u8], i: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        b.get(i..i + 4).context("truncated AVB field")?.try_into()?,
    ))
}
#[derive(Debug)]
struct Descriptor {
    tag: u64,
    name: Option<String>,
    bytes: Vec<u8>,
}
fn require_hardware_parent(root: &[Descriptor], system: &[Descriptor], name: &str) -> Result<()> {
    let found: Vec<_> = root
        .iter()
        .filter(|d| d.name.as_deref() == Some(name))
        .collect();
    ensure!(
        found.len() == 1
            && found[0].tag == 1
            && !system.iter().any(|d| d.name.as_deref() == Some(name)),
        "hardware filesystem requires exactly one existing root hashtree descriptor; chained or relocated descriptors need a separate adapter"
    );
    let d = &found[0].bytes;
    ensure!(
        be32(d, 16)? == 1
            && be32(d, 44)? == 4096
            && be32(d, 48)? == 4096
            && be32(d, 116)? == 0
            && d.get(72..104)
                .is_some_and(|s| s.starts_with(b"sha256\0") && s[7..].iter().all(|v| *v == 0)),
        "unsupported hardware hashtree version, block sizes, flags or algorithm"
    );
    Ok(())
}
fn descriptors(path: &Path) -> Result<(Vec<u8>, Vec<Descriptor>)> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    ensure!(len >= 256, "truncated AVB source");
    let magic = gb_partition::read_at(&mut f, 0, 4)?;
    let offset = if magic == b"AVB0" {
        0
    } else {
        let footer = gb_partition::read_at(
            &mut f,
            len.checked_sub(64).context("missing AVB footer")?,
            64,
        )?;
        ensure!(&footer[..4] == b"AVBf", "required AVB footer absent");
        be64(&footer, 20)?
    };
    let header = gb_partition::read_at(&mut f, offset, 256)?;
    ensure!(&header[..4] == b"AVB0", "invalid AVB header");
    gb_partition::avb(&mut f, offset)?;
    let aux = offset
        .checked_add(256)
        .and_then(|v| v.checked_add(be64(&header, 12).ok()?))
        .context("AVB auxiliary address overflow")?;
    let start = aux
        .checked_add(be64(&header, 96)?)
        .context("AVB descriptor address overflow")?;
    let bytes = be64(&header, 104)?;
    ensure!(bytes <= 16 * 1024 * 1024, "AVB descriptor budget exceeded");
    let body = gb_partition::read_at(&mut f, start, bytes as usize)?;
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let tag = be64(&body, pos)?;
        let size = be64(&body, pos + 8)?
            .checked_add(16)
            .context("descriptor size overflow")? as usize;
        let end = pos.checked_add(size).context("descriptor overflow")?;
        let bytes = body.get(pos..end).context("truncated descriptor")?.to_vec();
        let name = match tag {
            1 => Some((180, be32(&bytes, 104)? as usize)),
            2 => Some((132, be32(&bytes, 56)? as usize)),
            4 => Some((92, be32(&bytes, 20)? as usize)),
            _ => None,
        };
        let name = name
            .map(|(start, len)| -> Result<String> {
                let text = std::str::from_utf8(
                    bytes
                        .get(start..start + len)
                        .context("descriptor name out of bounds")?,
                )?;
                ensure!(
                    !text.is_empty()
                        && text
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
                    "invalid AVB partition name"
                );
                Ok(text.to_owned())
            })
            .transpose()?;
        result.push(Descriptor { tag, name, bytes });
        pos = end;
    }
    Ok((header, result))
}
fn prop_key(d: &Descriptor) -> Result<Option<String>> {
    if d.tag != 0 {
        return Ok(None);
    }
    let n = be64(&d.bytes, 16)? as usize;
    let key = std::str::from_utf8(
        d.bytes
            .get(32..32 + n)
            .context("property key out of bounds")?,
    )?;
    Ok(Some(key.into()))
}
fn require_build_properties(
    partition: &str,
    previous: &BTreeSet<String>,
    replacement: &BTreeSet<String>,
) -> Result<()> {
    let prefix = format!("com.android.build.{partition}.");
    for key in previous.iter().filter(|key| key.starts_with(&prefix)) {
        ensure!(
            replacement.contains(key),
            "AVB property source for {partition} omits existing build property {key}; use the original property-bearing image, not a repacked hashtree-only leaf"
        );
    }
    Ok(())
}
// Unsigned temporary transport container for exact retained descriptors. Only the
// configured avbtool produces final signatures; this is never a device artifact.
fn transport(path: &Path, descriptors: &[Descriptor]) -> Result<()> {
    let payload = descriptors
        .iter()
        .flat_map(|d| d.bytes.iter().copied())
        .collect::<Vec<_>>();
    let aux = (payload.len() + 63) & !63;
    let mut h = vec![0; 256];
    h[..4].copy_from_slice(b"AVB0");
    h[4..8].copy_from_slice(&1u32.to_be_bytes());
    h[20..28].copy_from_slice(&(aux as u64).to_be_bytes());
    h[104..112].copy_from_slice(&(payload.len() as u64).to_be_bytes());
    let mut bytes = h;
    bytes.extend_from_slice(&payload);
    bytes.resize(256 + aux, 0);
    std::fs::write(path, bytes)?;
    Ok(())
}
fn copy_filesystem(input: &Path, output: &Path, hashtree: bool, name: &str) -> Result<()> {
    let mut file = File::open(input)?;
    let size = if hashtree {
        let prefix = gb_partition::read_at(&mut file, 0, 8192)?;
        let format = gb_partition::detect(&prefix);
        ensure!(
            matches!(format, gb_core::Format::Erofs | gb_core::Format::Ext4),
            "raw EROFS or ext4 filesystem required for hashtree signing"
        );
        let info = gb_partition::inspect(&mut file, &format)?;
        info["filesystem_bytes"]
            .as_u64()
            .context("filesystem size missing")?
    } else {
        let prefix = gb_partition::read_at(&mut file, 0, 8192)?;
        if name == "init_boot" {
            ensure!(
                gb_partition::detect(&prefix) == gb_core::Format::Boot
                    && u32::from_le_bytes(prefix[8..12].try_into()?) == 0
                    && u32::from_le_bytes(prefix[40..44].try_into()?) == 4,
                "diagnostic signing requires kernel-free init_boot v4"
            );
        } else if name == "boot" {
            let info = gb_partition::inspect(&mut file, &gb_core::Format::Boot)?;
            ensure!(
                info["header_version"] == 4
                    && info["ramdisk_bytes"] == 0
                    && info["signature_bytes"] == 0
                    && info["kernel_bytes"]
                        .as_u64()
                        .is_some_and(|v| v > 0 && v <= 64 * 1024 * 1024),
                "kernel signing requires kernel-only boot v4 without GKI signature"
            );
        } else {
            ensure!(
                gb_partition::detect(&prefix) == gb_core::Format::VendorBoot,
                "vendor_boot format required"
            );
        }
        file.metadata()?.len()
    };
    file = File::open(input)?;
    copy_stream(file.take(size), File::create(output)?)?;
    Ok(())
}
pub fn build(request: &Request, out: &Path) -> Result<Report> {
    request.validate()?;
    let inputs = request.inputs();
    for input in &inputs {
        gb_core::separate_from_input(&input.path, out)?;
        ensure!(
            hash_file(&input.path)? == input.sha256,
            "AVB source SHA256 mismatch: {}",
            input.path.display()
        );
    }
    let paths: Vec<_> = inputs.iter().map(|i| i.path.as_path()).collect();
    let tool = gb_tools::host_tool(&request.tool, &paths)?;
    let identity = gb_tools::identity(&tool, &request.sandbox)?;
    let scratch = tempfile::tempdir()?;
    let mut pubkeys = Vec::new();
    for (label, key) in [("root", &request.root_key), ("system", &request.system_key)] {
        gb_tools::run(
            &request.sandbox,
            &tool,
            vec![
                "extract_public_key".into(),
                "--key".into(),
                "/input.img".into(),
                "--output".into(),
                format!("/output/{label}.pub"),
            ],
            &key.input.path,
            scratch.path(),
            Duration::from_secs(30),
        )?;
        let public = scratch.path().join(format!("{label}.pub"));
        ensure!(
            hash_file(&public)? == key.public_key_sha256,
            "authorized signing public key differs"
        );
        pubkeys.push(public);
    }
    let (root_header, mut root) = descriptors(&request.root_template.path)?;
    let (system_header, mut system) = descriptors(&request.system_template.path)?;
    for p in request
        .partitions
        .iter()
        .filter(|p| ["vendor", "odm"].contains(&p.name.as_str()))
    {
        require_hardware_parent(&root, &system, &p.name)?;
    }
    // A chained boot partition keeps its root descriptor and rollback location.
    // Currently only a boot chain using the explicitly configured root key is
    // supported; a different boot signer requires a separate key adapter.
    let boot_signing = if let Some(partition) = request.partitions.iter().find(|p| p.name == "boot")
    {
        let chains: Vec<_> = root
            .iter()
            .filter(|d| d.name.as_deref() == Some("boot"))
            .collect();
        ensure!(
            chains.len() == 1 && chains[0].tag == 4,
            "kernel adaptation requires exactly one retained boot chain descriptor"
        );
        let chain = &chains[0].bytes;
        let name_len = be32(chain, 20)? as usize;
        let key_len = be32(chain, 24)? as usize;
        ensure!(
            be32(chain, 16)? > 0,
            "boot chain requires a distinct rollback location"
        );
        let key_start = 92usize
            .checked_add(name_len)
            .context("boot chain key offset overflow")?;
        let key_end = key_start
            .checked_add(key_len)
            .context("boot chain key size overflow")?;
        ensure!(
            chain
                .get(key_start..key_end)
                .context("truncated boot chain key")?
                == std::fs::read(&pubkeys[0])?,
            "boot chain signer differs from explicitly configured root key"
        );
        let source = partition
            .properties_from
            .as_ref()
            .context("chained boot requires its original signed footer template")?;
        let (header, entries) = descriptors(&source.path)?;
        ensure!(
            be32(&header, 28)? == 2 && be32(&header, 120)? == 0,
            "boot template must use SHA256_RSA4096 with verification enabled"
        );
        ensure!(
            entries
                .iter()
                .filter(|d| d.tag == 2 && d.name.as_deref() == Some("boot"))
                .count()
                == 1
                && entries
                    .iter()
                    .all(|d| d.tag == 0 || (d.tag == 2 && d.name.as_deref() == Some("boot"))),
            "unsupported boot template descriptors"
        );
        ensure!(
            request.root_key.algorithm == "SHA256_RSA4096",
            "chained kernel boot signing requires explicitly configured RSA4096 key"
        );
        let props = scratch.path().join("boot-properties.img");
        let entries: Vec<_> = entries.into_iter().filter(|d| d.tag == 0).collect();
        transport(&props, &entries)?;
        Some((header, props))
    } else {
        None
    };
    let previous_properties: BTreeSet<String> = root
        .iter()
        .chain(&system)
        .map(prop_key)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let mut property_sources = BTreeMap::new();
    for partition in &request.partitions {
        let selected = if let Some(source) = &partition.properties_from {
            descriptors(&source.path)?
                .1
                .into_iter()
                .filter(|descriptor| descriptor.tag == 0)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let keys = selected
            .iter()
            .map(prop_key)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        require_build_properties(&partition.name, &previous_properties, &keys)?;
        property_sources.insert(partition.name.as_str(), selected);
    }
    ensure!(
        be32(&root_header, 120)? == 0 && be32(&system_header, 120)? == 0,
        "source AVB verification flags must be zero"
    );
    let changed: BTreeSet<_> = request
        .partitions
        .iter()
        .filter(|p| p.name != "boot")
        .map(|p| p.name.as_str())
        .collect();
    for list in [&mut root, &mut system] {
        list.retain(|d| !d.name.as_deref().is_some_and(|n| changed.contains(n)));
        let mut retained = Vec::new();
        for d in list.drain(..) {
            let key = prop_key(&d)?;
            let replaced = key.as_deref().is_some_and(|k| {
                changed
                    .iter()
                    .any(|p| k.starts_with(&format!("com.android.build.{p}.")))
            });
            if !replaced {
                retained.push(d)
            }
        }
        *list = retained;
    }
    for p in &request.partitions {
        if p.name == "boot" {
            continue;
        }
        if let Some(selected) = property_sources.remove(p.name.as_str()) {
            if root_partition(&p.name) {
                root.extend(selected)
            } else {
                system.extend(selected)
            }
        }
    }
    let root_transport = scratch.path().join("root-transfer.img");
    let system_transport = scratch.path().join("system-transfer.img");
    transport(&root_transport, &root)?;
    transport(&system_transport, &system)?;
    let mut generated = Vec::new();
    for p in &request.partitions {
        let file = out.join(format!("{}.img", p.name));
        copy_filesystem(&p.image.path, &file, p.hashtree, &p.name)?;
        let mut args = vec![
            if p.hashtree {
                "add_hashtree_footer"
            } else {
                "add_hash_footer"
            }
            .into(),
            "--image".into(),
            format!("/output/{}.img", p.name),
            "--partition_size".into(),
            p.partition_bytes.to_string(),
            "--partition_name".into(),
            p.name.clone(),
            "--hash_algorithm".into(),
            "sha256".into(),
            "--salt".into(),
            digest(format!("{}:{}", p.name, p.image.sha256).as_bytes()),
            "--algorithm".into(),
            "NONE".into(),
        ];
        if p.hashtree {
            args.extend([
                "--block_size".into(),
                "4096".into(),
                "--do_not_generate_fec".into(),
            ]);
        }
        if p.name == "boot" {
            let (header, props) = boot_signing
                .as_ref()
                .context("boot signing context absent")?;
            let end = args.len();
            ensure!(
                args[end - 2] == "--algorithm" && args[end - 1] == "NONE",
                "unexpected leaf signing arguments"
            );
            args[end - 1] = request.root_key.algorithm.clone();
            args.extend([
                "--key".into(),
                "/inputs/boot.key".into(),
                "--rollback_index".into(),
                be64(header, 112)?.to_string(),
                "--rollback_index_location".into(),
                be32(header, 124)?.to_string(),
                "--flags".into(),
                "0".into(),
                "--include_descriptors_from_image".into(),
                "/inputs/boot-properties.img".into(),
            ]);
            gb_tools::run_mounted(
                &request.sandbox,
                &tool,
                args,
                gb_tools::Inputs {
                    primary: &p.image.path,
                    extra: &[
                        gb_tools::ReadOnlyInput {
                            name: "boot.key",
                            path: &request.root_key.input.path,
                        },
                        gb_tools::ReadOnlyInput {
                            name: "boot-properties.img",
                            path: props,
                        },
                    ],
                    source_date_epoch: Some(0),
                },
                out,
                Duration::from_secs(1200),
            )?;
        } else {
            gb_tools::run(
                &request.sandbox,
                &tool,
                args,
                &p.image.path,
                out,
                Duration::from_secs(1200),
            )?;
        }
        ensure!(
            std::fs::metadata(&file)?.len() == p.partition_bytes,
            "signed partition geometry differs"
        );
        gb_partition::avb_footer(&mut File::open(&file)?)?
            .context("generated AVB footer absent")?;
        generated.push(file);
    }
    let mut extras = vec![
        gb_tools::ReadOnlyInput {
            name: "root.key",
            path: &request.root_key.input.path,
        },
        gb_tools::ReadOnlyInput {
            name: "system.key",
            path: &request.system_key.input.path,
        },
        gb_tools::ReadOnlyInput {
            name: "root-template.img",
            path: &root_transport,
        },
        gb_tools::ReadOnlyInput {
            name: "system-template.img",
            path: &system_transport,
        },
    ];
    for (name, header, key) in [
        ("vbmeta", &root_header, &request.root_key),
        ("vbmeta_system", &system_header, &request.system_key),
    ] {
        let mut args = vec![
            "make_vbmeta_image".into(),
            "--output".into(),
            format!("/output/{name}.img"),
            "--padding_size".into(),
            "65536".into(),
            "--algorithm".into(),
            key.algorithm.clone(),
            "--key".into(),
            if name == "vbmeta" {
                "/inputs/root.key"
            } else {
                "/inputs/system.key"
            }
            .into(),
            "--rollback_index".into(),
            be64(header, 112)?.to_string(),
            "--rollback_index_location".into(),
            be32(header, 124)?.to_string(),
            "--flags".into(),
            "0".into(),
            "--include_descriptors_from_image".into(),
            if name == "vbmeta" {
                "/inputs/root-template.img"
            } else {
                "/inputs/system-template.img"
            }
            .into(),
        ];
        for p in &request.partitions {
            if p.name != "boot" && (name == "vbmeta") == root_partition(&p.name) {
                args.extend([
                    "--include_descriptors_from_image".into(),
                    format!("/output/{}.img", p.name),
                ]);
            }
        }
        gb_tools::run_mounted(
            &request.sandbox,
            &tool,
            args,
            gb_tools::Inputs {
                primary: &request.root_template.path,
                extra: &extras,
                source_date_epoch: Some(0),
            },
            out,
            Duration::from_secs(60),
        )?;
        let info = gb_partition::avb(&mut File::open(out.join(format!("{name}.img")))?, 0)?;
        ensure!(
            info["flags"] == 0 && info["rollback_index"].as_u64() == Some(be64(header, 112)?),
            "generated AVB flags/rollback differ"
        );
    }
    extras.clear();
    for input in &inputs {
        ensure!(
            hash_file(&input.path)? == input.sha256,
            "AVB source changed during assembly"
        );
    }
    let mut checksums = std::collections::BTreeMap::new();
    for path in generated
        .iter()
        .chain([out.join("vbmeta.img"), out.join("vbmeta_system.img")].iter())
    {
        checksums.insert(
            path.file_name()
                .context("missing output name")?
                .to_str()
                .context("non UTF8 output")?
                .into(),
            hash_file(path)?,
        );
    }
    let report=Report{schema_version:1,status:"signed_images_pending_chain_validation_and_super_assembly".into(),bootable:false,runtime_verified:false,avb_flags:0,rollback_indices_changed:false,root_rollback_index:be64(&root_header,112)?,system_rollback_index:be64(&system_header,112)?,checksums,key_public_sha256:vec![request.root_key.public_key_sha256.clone(),request.system_key.public_key_sha256.clone()],tool:identity,limitations:vec!["Full descriptor/data-chain verification, device boot acceptance and runtime testing remain required".into(),"Configured source rollback indices retained; device-enforced minima remain unknown".into(),"New filesystem hashtrees omit optional FEC; verification remains enabled".into()]};
    write_json(&out.join("avb-report.json"), &report)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashtree_only_source_cannot_silently_drop_parent_build_properties() {
        let previous = [
            "com.android.build.system_ext.fingerprint",
            "com.android.build.system_ext.os_version",
            "com.android.build.system_ext.security_patch",
            "com.android.build.product.fingerprint",
        ]
        .map(String::from)
        .into_iter()
        .collect();
        assert!(require_build_properties("system_ext", &previous, &BTreeSet::new()).is_err());
        let mut supplied = [
            "com.android.build.system_ext.fingerprint",
            "com.android.build.system_ext.os_version",
        ]
        .map(String::from)
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert!(require_build_properties("system_ext", &previous, &supplied).is_err());
        supplied.insert("com.android.build.system_ext.security_patch".into());
        require_build_properties("system_ext", &previous, &supplied).unwrap();
        // A partition with no previous build properties needs no invented ones.
        require_build_properties("init_boot", &previous, &BTreeSet::new()).unwrap();
    }
    #[test]
    fn init_boot_requires_explicit_diagnostic_scope_and_kernel_partition_is_refused() {
        let input = || Input {
            path: PathBuf::from("fixture-never-opened"),
            sha256: "00".repeat(32),
        };
        let mut request = Request {
            schema_version: 1,
            allow_init_boot_diagnostics: false,
            allow_kernel_boot_adaptation: false,
            allow_hardware_filesystem_adaptation: false,
            root_template: input(),
            system_template: input(),
            root_key: Key {
                input: input(),
                public_key_sha256: "00".repeat(32),
                algorithm: "SHA256_RSA4096".into(),
            },
            system_key: Key {
                input: input(),
                public_key_sha256: "00".repeat(32),
                algorithm: "SHA256_RSA2048".into(),
            },
            partitions: vec![Partition {
                name: "init_boot".into(),
                image: input(),
                partition_bytes: 8388608,
                hashtree: false,
                properties_from: None,
            }],
            tool: PathBuf::from("fixture-tool-never-executed"),
            sandbox: gb_tools::Sandbox::default(),
        };
        assert!(request.validate().is_err());
        request.allow_init_boot_diagnostics = true;
        assert!(request.validate().is_ok());
        request.partitions[0].name = "boot".into();
        assert!(request.validate().is_err());
        request.allow_kernel_boot_adaptation = true;
        assert!(request.validate().is_ok());
        request.partitions[0].hashtree = true;
        assert!(request.validate().is_err());
        request.partitions[0].name = "vendor".into();
        assert!(request.validate().is_err());
        request.allow_hardware_filesystem_adaptation = true;
        assert!(request.validate().is_ok());
        request.partitions[0].hashtree = false;
        assert!(request.validate().is_err());
    }
    #[test]
    fn hardware_parent_must_retain_root_route_and_supported_verity_semantics() {
        let mut bytes = vec![0; 180];
        for (at, value) in [(16, 1u32), (44, 4096), (48, 4096)] {
            bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
        }
        bytes[72..79].copy_from_slice(b"sha256\0");
        let descriptor = |bytes: Vec<u8>| Descriptor {
            tag: 1,
            name: Some("vendor".into()),
            bytes,
        };
        require_hardware_parent(&[descriptor(bytes.clone())], &[], "vendor").unwrap();
        assert!(require_hardware_parent(&[], &[descriptor(bytes.clone())], "vendor").is_err());
        assert!(
            require_hardware_parent(
                &[descriptor(bytes.clone()), descriptor(bytes.clone())],
                &[],
                "vendor"
            )
            .is_err()
        );
        let mut chain = descriptor(bytes.clone());
        chain.tag = 4;
        assert!(require_hardware_parent(&[chain], &[], "vendor").is_err());
        bytes[119] = 1;
        assert!(require_hardware_parent(&[descriptor(bytes)], &[], "vendor").is_err());
        assert!(root_partition("vendor") && !boot_partition("vendor"));
    }
    #[test]
    fn unsigned_transport_retains_descriptor_bytes_and_stays_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("d.img");
        let d = Descriptor {
            tag: 0,
            name: None,
            bytes: vec![0; 16],
        };
        transport(&p, &[d]).unwrap();
        let (_, list) = descriptors(&p).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].bytes, vec![0; 16]);
        let info = gb_partition::avb(&mut File::open(p).unwrap(), 0).unwrap();
        assert_eq!(info["algorithm_type"], 0);
        assert_eq!(info["cryptographic_signature_verified"], false);
    }
}
