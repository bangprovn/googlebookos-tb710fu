//! Offline, selected userspace reconstruction through the mature Android OTA tool.
//! No postinstall execution, device writes, signing, or port-compatibility claim.
//!
//! Run `cargo run -p gb-firmware --example reconstruct_ota -- REQUEST.toml NEW_OUTPUT`.
//! A request selects only `system`, `product`, and/or `system_ext`; each source
//! image and expected output must match the incremental payload's full-image
//! size and SHA-256. Example request shape (replace every illustrative pin):
//!
//! ```text
//! schema_version = 1
//! timeout_seconds = 600
//! [ota]
//! path = "inputs/update.zip"
//! bytes = 1234
//! sha256 = "<64 lowercase hex characters>"
//! [tool]
//! path = "tools/bin/ota_extractor"
//! bytes = 1234
//! sha256 = "<64 lowercase hex characters>"
//! [sandbox]
//! backend = "docker"
//! image = "sha256:<immutable local image digest>"
//! [[partitions]]
//! name = "system"
//! [partitions.source]
//! path = "inputs/original-system.img"
//! bytes = 4096
//! sha256 = "<64 lowercase hex characters>"
//! [partitions.expected]
//! bytes = 4096
//! sha256 = "<payload-declared new image SHA-256>"
//! ```
//!
//! Paths resolve against the request file. The configured host tool and Docker
//! image must already be trusted and available; the tool's runtime dependency
//! identity is recorded. Source firmware is mounted read-only, and extraction
//! runs with the existing bounded sandbox adapter. Publication requires exact
//! selected filenames and full output hashes. These integrity checks do not
//! authenticate the OTA publisher: verify package signatures separately before
//! trusting a donor. Returned images still need device-specific adaptations.
use anyhow::{Context, Result, ensure};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub path: PathBuf,
    #[serde(flatten)]
    pub content: Content,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Userspace {
    System,
    Product,
    SystemExt,
}
impl Userspace {
    pub fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Product => "product",
            Self::SystemExt => "system_ext",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Partition {
    pub name: Userspace,
    pub source: Input,
    pub expected: Content,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub ota: Input,
    pub tool: Input,
    pub partitions: Vec<Partition>,
    pub timeout_seconds: u64,
    pub sandbox: gb_tools::Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let file = gb_core::open_regular_file(path, OpenOptions::new().read(true))?;
        let mut text = String::new();
        file.take(65_537).read_to_string(&mut text)?;
        ensure!(
            text.len() <= 65_536,
            "reconstruction request exceeds byte limit"
        );
        let mut value: Self = toml::from_str(&text)?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in std::iter::once(&mut value.ota.path)
            .chain(std::iter::once(&mut value.tool.path))
            .chain(value.partitions.iter_mut().map(|p| &mut p.source.path))
        {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && (1..=1800).contains(&self.timeout_seconds),
            "invalid reconstruction schema or deadline"
        );
        self.sandbox.validate()?;
        ensure!(
            !self.partitions.is_empty() && self.partitions.len() <= 3,
            "select one to three userspace partitions"
        );
        let mut names = BTreeSet::new();
        for p in &self.partitions {
            ensure!(names.insert(p.name), "duplicate selected partition");
            validate_content(&p.source.content)?;
            validate_content(&p.expected)?;
        }
        validate_content(&self.ota.content)?;
        validate_content(&self.tool.content)?;
        Ok(())
    }
}
fn validate_content(c: &Content) -> Result<()> {
    ensure!(
        c.bytes > 0
            && c.bytes <= 32 * 1024 * 1024 * 1024
            && c.sha256.len() == 64
            && c.sha256
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "invalid content size or SHA256"
    );
    Ok(())
}
fn verified(input: &Input) -> Result<()> {
    let mut file = gb_core::open_regular_file(&input.path, OpenOptions::new().read(true))?;
    ensure!(
        file.metadata()?.len() == input.content.bytes
            && gb_core::hash_reader(&mut file)? == input.content.sha256,
        "pinned input differs: {}",
        input.path.display()
    );
    Ok(())
}
#[derive(Clone, PartialEq, Message)]
struct Info {
    #[prost(uint64, optional, tag = "1")]
    size: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "2")]
    hash: Option<Vec<u8>>,
}
#[derive(Clone, PartialEq, Message)]
struct Update {
    #[prost(string, required, tag = "1")]
    name: String,
    #[prost(message, optional, tag = "6")]
    old: Option<Info>,
    #[prost(message, optional, tag = "7")]
    new: Option<Info>,
}
#[derive(Clone, PartialEq, Message)]
struct Manifest {
    #[prost(uint32, optional, tag = "3")]
    block_size: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    minor: Option<u32>,
    #[prost(message, repeated, tag = "13")]
    partitions: Vec<Update>,
}
fn matches(info: Option<&Info>, content: &Content) -> bool {
    info.is_some_and(|p| {
        p.size == Some(content.bytes)
            && p.hash.as_ref().is_some_and(|h| {
                h.len() == 32
                    && h.iter().map(|v| format!("{v:02x}")).collect::<String>() == content.sha256
            })
    })
}
/// Decode only bounded preconditions. Operation bodies/unknown fields remain the
/// external tool's responsibility; a matching configured donor hash is mandatory.
fn envelope(request: &Request) -> Result<(u64, u32)> {
    let file = gb_core::open_regular_file(&request.ota.path, OpenOptions::new().read(true))?;
    let mut zip = zip::ZipArchive::new(file)?;
    ensure!(zip.len() <= 4096, "ZIP entry budget");
    let mut names = BTreeSet::new();
    for i in 0..zip.len() {
        let e = zip.by_index(i)?;
        gb_core::safe_relative(Path::new(e.name().trim_end_matches('/')))?;
        ensure!(
            !e.name().contains('\\') && names.insert(e.name().to_owned()),
            "duplicate or unsafe ZIP entry"
        );
    }
    let mut e = zip.by_name("payload.bin")?;
    ensure!(
        e.compression() == zip::CompressionMethod::Stored && e.size() == e.compressed_size(),
        "payload must be stored without compression"
    );
    let offset = e.data_start();
    let size = e.size();
    ensure!(
        offset
            .checked_add(size)
            .is_some_and(|v| v <= request.ota.content.bytes),
        "payload exceeds ZIP"
    );
    let mut header = [0u8; 24];
    e.read_exact(&mut header)?;
    ensure!(
        &header[..4] == b"CrAU" && u64::from_be_bytes(header[4..12].try_into()?) == 2,
        "only payload v2 supported"
    );
    let length = u64::from_be_bytes(header[12..20].try_into()?);
    let signatures = u32::from_be_bytes(header[20..24].try_into()?) as u64;
    ensure!(
        length > 0
            && length <= 4 * 1024 * 1024
            && signatures <= 1024 * 1024
            && 24 + length + signatures <= size,
        "payload metadata budget"
    );
    let mut data = vec![0; length as usize];
    e.read_exact(&mut data)?;
    let m = Manifest::decode(data.as_slice())?;
    ensure!(
        m.block_size == Some(4096)
            && m.minor.is_some_and(|n| (1..=10).contains(&n))
            && !m.partitions.is_empty()
            && m.partitions.len() <= 256,
        "unsupported incremental metadata"
    );
    let mut found = BTreeMap::new();
    for p in &m.partitions {
        ensure!(
            !p.name.is_empty()
                && p.name.len() <= 128
                && p.name
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'_')
                && found.insert(p.name.as_str(), p).is_none(),
            "unsafe or duplicate partition"
        );
    }
    for p in &request.partitions {
        let item = found
            .get(p.name.name())
            .context("selected partition absent")?;
        ensure!(
            matches(item.old.as_ref(), &p.source.content)
                && matches(item.new.as_ref(), &p.expected),
            "selected old/new manifest precondition differs: {}",
            p.name.name()
        );
    }
    Ok((offset, m.minor.context("minor version missing")?))
}
fn verify_outputs(request: &Request, output: &Path) -> Result<BTreeMap<String, Content>> {
    let expected: BTreeSet<_> = request
        .partitions
        .iter()
        .map(|p| format!("{}.img", p.name.name()))
        .collect();
    let actual = std::fs::read_dir(output)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 output"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        actual == expected,
        "tool emitted unexpected/missing output entries"
    );
    let mut results = BTreeMap::new();
    for p in &request.partitions {
        let name = format!("{}.img", p.name.name());
        verified(&Input {
            path: output.join(&name),
            content: p.expected.clone(),
        })?;
        results.insert(name, p.expected.clone());
    }
    Ok(results)
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub payload_minor_version: u32,
    pub outputs: BTreeMap<String, Content>,
    pub configured_inputs_verified: bool,
    pub manifest_preconditions_verified: bool,
    pub inputs_unchanged: bool,
    pub tool: serde_json::Value,
    pub invocation: gb_core::ToolResult,
    pub package_signature_verified: bool,
    pub firmware_written: bool,
    pub postinstall_executed: bool,
    pub port_adaptations_applied: bool,
    pub runtime_verified: bool,
}
pub fn reconstruct(request: &Request, destination: &Path) -> Result<Report> {
    request.validate()?;
    ensure!(
        std::fs::symlink_metadata(destination)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "destination already exists or unavailable"
    );
    let inputs: Vec<_> = std::iter::once(&request.ota)
        .chain(std::iter::once(&request.tool))
        .chain(request.partitions.iter().map(|p| &p.source))
        .collect();
    for input in &inputs {
        gb_core::separate_from_input(&input.path, destination)?;
        verified(input)?;
    }
    let (offset, minor) = envelope(request)?;
    // Select by input role: path-based filtering could discard a firmware
    // source that aliases the tool, allowing its unsandboxed version probe.
    let input_paths: Vec<_> = std::iter::once(request.ota.path.as_path())
        .chain(request.partitions.iter().map(|p| p.source.path.as_path()))
        .collect();
    let tool = gb_tools::host_tool(&request.tool.path, &input_paths)?;
    let identity = gb_tools::identity(&tool, &request.sandbox)?;
    ensure!(
        identity["binary_sha256"].as_str() == Some(request.tool.content.sha256.as_str()),
        "tool identity changed"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let stage = tempfile::Builder::new()
        .prefix(".ota-userspace-")
        .tempdir_in(parent)?;
    let images = stage.path().join("images");
    std::fs::create_dir(&images)?;
    let bytes = request
        .partitions
        .iter()
        .try_fold(256 * 1024 * 1024u64, |a, p| {
            a.checked_add(p.expected.bytes)
                .context("disk estimate overflow")
        })?;
    ensure!(
        fs2::available_space(stage.path())? > bytes,
        "insufficient staging disk space"
    );
    let names: Vec<_> = request
        .partitions
        .iter()
        .map(|p| format!("{}.img", p.name.name()))
        .collect();
    let extra: Vec<_> = request
        .partitions
        .iter()
        .zip(&names)
        .map(|(p, n)| gb_tools::ReadOnlyInput {
            name: n.as_str(),
            path: &p.source.path,
        })
        .collect();
    let selected = request
        .partitions
        .iter()
        .map(|p| p.name.name())
        .collect::<Vec<_>>()
        .join(",");
    let invocation = gb_tools::run_mounted(
        &request.sandbox,
        &tool,
        vec![
            "--payload=/input.img".into(),
            format!("--payload_offset={offset}"),
            "--input_dir=/inputs".into(),
            "--output_dir=/output".into(),
            format!("--partitions={selected}"),
            "--single_thread=true".into(),
        ],
        gb_tools::Inputs {
            primary: &request.ota.path,
            extra: &extra,
            source_date_epoch: Some(0),
        },
        &images,
        Duration::from_secs(request.timeout_seconds),
    )?;
    let outputs = verify_outputs(request, &images)?;
    for input in &inputs {
        verified(input)?;
    }
    ensure!(
        gb_tools::identity(&tool, &request.sandbox)? == identity,
        "tool/runtime identity changed"
    );
    let report = Report {
        schema_version: 1,
        status: "selected_donor_userspace_reconstructed_not_adapted".into(),
        payload_minor_version: minor,
        outputs,
        configured_inputs_verified: true,
        manifest_preconditions_verified: true,
        inputs_unchanged: true,
        tool: identity,
        invocation,
        package_signature_verified: false,
        firmware_written: false,
        postinstall_executed: false,
        port_adaptations_applied: false,
        runtime_verified: false,
    };
    gb_core::write_json(&stage.path().join("reconstruction-report.json"), &report)?;
    for entry in std::fs::read_dir(&images)? {
        File::open(entry?.path())?.sync_all()?;
    }
    File::open(&images)?.sync_all()?;
    gb_core::publish_directory(stage.path(), destination)?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn content(bytes: &[u8]) -> Content {
        Content {
            bytes: bytes.len() as u64,
            sha256: gb_core::digest(bytes),
        }
    }
    fn input(path: PathBuf, bytes: &[u8]) -> Input {
        std::fs::write(&path, bytes).unwrap();
        Input {
            path,
            content: content(bytes),
        }
    }
    fn hash_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
            .collect()
    }
    fn info(c: &Content) -> Info {
        Info {
            size: Some(c.bytes),
            hash: Some(hash_bytes(&c.sha256)),
        }
    }
    fn zip_payload(path: &Path, manifest: &[u8], blob: &[u8]) {
        let mut payload = b"CrAU".to_vec();
        payload.extend(2u64.to_be_bytes());
        payload.extend((manifest.len() as u64).to_be_bytes());
        payload.extend(0u32.to_be_bytes());
        payload.extend(manifest);
        payload.extend(blob);
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        zip.start_file(
            "payload.bin",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(&payload).unwrap();
        zip.finish().unwrap();
    }
    fn fixture() -> (tempfile::TempDir, Request, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let old = vec![b'a'; 8192];
        let mut new = old.clone();
        new[4096..].fill(b'c');
        let source = input(dir.path().join("system-source.img"), &old);
        let expected = content(&new);
        let manifest = Manifest {
            block_size: Some(4096),
            minor: Some(9),
            partitions: vec![Update {
                name: "system".into(),
                old: Some(info(&source.content)),
                new: Some(info(&expected)),
            }],
        };
        let path = dir.path().join("ota.zip");
        zip_payload(&path, &manifest.encode_to_vec(), b"");
        let ota = Input {
            content: content(&std::fs::read(&path).unwrap()),
            path,
        };
        let tool = input(dir.path().join("sdk-tool"), b"test host tool placeholder");
        let request = Request {
            schema_version: 1,
            ota,
            tool,
            partitions: vec![Partition {
                name: Userspace::System,
                source,
                expected,
            }],
            timeout_seconds: 30,
            sandbox: gb_tools::Sandbox::Docker {
                image: format!("sha256:{}", "a".repeat(64)),
            },
        };
        (dir, request, new)
    }
    #[test]
    fn firmware_tool_alias_is_refused_before_any_tool_version_probe() {
        for alias_ota in [true, false] {
            let (dir, mut request, _) = fixture();
            request.tool = if alias_ota {
                request.ota.clone()
            } else {
                request.partitions[0].source.clone()
            };
            let destination = dir.path().join("published");
            let error = reconstruct(&request, &destination).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("refusing to execute a tool from firmware input")
            );
            assert!(!destination.exists());
        }
    }
    #[test]
    fn toml_request_resolves_relative_inputs_and_rejects_oversized_configuration() {
        let (dir, mut request, _) = fixture();
        request.ota.path = "ota.zip".into();
        request.tool.path = "sdk-tool".into();
        request.partitions[0].source.path = "system-source.img".into();
        let path = dir.path().join("request.toml");
        std::fs::write(&path, toml::to_string(&request).unwrap()).unwrap();
        let parsed = Request::read(&path).unwrap();
        assert_eq!(parsed.ota.path, dir.path().join("ota.zip"));
        assert_eq!(parsed.tool.path, dir.path().join("sdk-tool"));
        assert_eq!(
            parsed.partitions[0].source.path,
            dir.path().join("system-source.img")
        );
        std::fs::write(&path, "#".repeat(65_537)).unwrap();
        assert!(Request::read(&path).is_err());
    }
    #[test]
    fn typed_userspace_pins_and_request_bounds_are_strict() {
        let (_dir, mut r, _) = fixture();
        r.validate().unwrap();
        let json = serde_json::to_value(&r).unwrap();
        let _: Request = serde_json::from_value(json.clone()).unwrap();
        for field in ["boot", "vendor", "../../system"] {
            let mut value = json.clone();
            value["partitions"][0]["name"] = serde_json::json!(field);
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
        let mut value = json;
        value["ota"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(value).is_err());
        r.partitions.push(r.partitions[0].clone());
        assert!(r.validate().is_err());
        r.partitions.pop();
        r.timeout_seconds = 0;
        assert!(r.validate().is_err());
        r.timeout_seconds = 1801;
        assert!(r.validate().is_err());
        r.timeout_seconds = 30;
        r.partitions[0].expected.sha256 = "A".repeat(64);
        assert!(r.validate().is_err());
    }
    #[test]
    fn decoded_manifest_must_match_both_selected_full_image_preconditions() {
        let (_dir, mut r, _) = fixture();
        assert_eq!(envelope(&r).unwrap().1, 9);
        r.partitions[0].source.content.sha256 = "0".repeat(64);
        assert!(envelope(&r).is_err());
        let (_dir, mut r, _) = fixture();
        r.partitions[0].expected.bytes += 1;
        assert!(envelope(&r).is_err());
        let (dir, mut r, _) = fixture();
        let malformed = Manifest {
            block_size: Some(4096),
            minor: Some(9),
            partitions: vec![Update {
                name: "../system".into(),
                old: None,
                new: None,
            }],
        };
        zip_payload(&r.ota.path, &malformed.encode_to_vec(), b"");
        r.ota.content = content(&std::fs::read(&r.ota.path).unwrap());
        assert!(envelope(&r).is_err());
        let duplicate = dir.path().join("duplicate.zip");
        let mut zip = zip::ZipWriter::new(File::create(&duplicate).unwrap());
        for name in ["payload.bin", "payload.bim"] {
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"invalid").unwrap();
        }
        zip.finish().unwrap();
        let bytes = std::fs::read(&duplicate).unwrap();
        let bytes = bytes
            .windows(11)
            .enumerate()
            .filter_map(|(i, w)| (w == b"payload.bim").then_some(i))
            .collect::<Vec<_>>()
            .into_iter()
            .fold(bytes, |mut data, i| {
                data[i + 10] = b'n';
                data
            });
        std::fs::write(&duplicate, bytes).unwrap();
        r.ota.path = duplicate;
        r.ota.content = content(&std::fs::read(&r.ota.path).unwrap());
        assert!(envelope(&r).is_err());
    }
    #[test]
    fn output_namespace_full_hash_and_existing_destination_fail_closed() {
        let (dir, r, new) = fixture();
        let out = dir.path().join("images");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("system.img"), &new).unwrap();
        verify_outputs(&r, &out).unwrap();
        std::fs::write(out.join("other.img"), b"extra").unwrap();
        assert!(verify_outputs(&r, &out).is_err());
        std::fs::remove_file(out.join("other.img")).unwrap();
        std::fs::write(out.join("system.img"), vec![0; new.len()]).unwrap();
        assert!(verify_outputs(&r, &out).is_err());
        assert!(reconstruct(&r, &out).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_input_and_output_are_never_accepted_as_regular_images() {
        use std::os::unix::fs::symlink;
        let (dir, r, new) = fixture();
        let path = dir.path().join("link.img");
        symlink(&r.partitions[0].source.path, &path).unwrap();
        assert!(
            verified(&Input {
                path,
                content: r.partitions[0].source.content.clone()
            })
            .is_err()
        );
        let out = dir.path().join("images");
        std::fs::create_dir(&out).unwrap();
        let actual = dir.path().join("actual.img");
        std::fs::write(&actual, new).unwrap();
        symlink(&actual, out.join("system.img")).unwrap();
        assert!(verify_outputs(&r, &out).is_err());
    }
    #[test]
    fn oversized_or_truncated_payload_envelopes_do_not_allocate_unbounded_memory() {
        let (_dir, mut r, _) = fixture();
        let mut data = b"CrAU".to_vec();
        data.extend(2u64.to_be_bytes());
        data.extend(u64::MAX.to_be_bytes());
        data.extend(0u32.to_be_bytes());
        let mut zip = zip::ZipWriter::new(File::create(&r.ota.path).unwrap());
        zip.start_file(
            "payload.bin",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(&data).unwrap();
        zip.finish().unwrap();
        r.ota.content = content(&std::fs::read(&r.ota.path).unwrap());
        assert!(envelope(&r).is_err());
    }
    #[derive(Clone, PartialEq, Message)]
    struct Extent {
        #[prost(uint64, optional, tag = "1")]
        start: Option<u64>,
        #[prost(uint64, optional, tag = "2")]
        blocks: Option<u64>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Op {
        #[prost(int32, required, tag = "1")]
        kind: i32,
        #[prost(uint64, optional, tag = "2")]
        offset: Option<u64>,
        #[prost(uint64, optional, tag = "3")]
        length: Option<u64>,
        #[prost(message, repeated, tag = "4")]
        source: Vec<Extent>,
        #[prost(message, repeated, tag = "6")]
        destination: Vec<Extent>,
        #[prost(bytes = "vec", optional, tag = "8")]
        data_hash: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "9")]
        source_hash: Option<Vec<u8>>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct FullUpdate {
        #[prost(string, required, tag = "1")]
        name: String,
        #[prost(message, optional, tag = "6")]
        old: Option<Info>,
        #[prost(message, optional, tag = "7")]
        new: Option<Info>,
        #[prost(message, repeated, tag = "8")]
        operations: Vec<Op>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct FullManifest {
        #[prost(uint32, optional, tag = "3")]
        block_size: Option<u32>,
        #[prost(uint32, optional, tag = "12")]
        minor: Option<u32>,
        #[prost(message, repeated, tag = "13")]
        partitions: Vec<FullUpdate>,
    }
    #[test]
    #[ignore = "requires the explicitly cached Android ota_extractor and immutable local Docker image"]
    fn actual_android_extractor_applies_tiny_source_copy_and_replace_without_firmware_execution() {
        let (dir, mut r, new) = fixture();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let tool = root.join("artifacts/tools/otatools-16373615/bin/ota_extractor");
        r.tool = Input {
            content: content(&std::fs::read(&tool).unwrap()),
            path: tool,
        };
        r.sandbox = gb_tools::Sandbox::Docker {
            image: "sha256:a3a951af78a89cb1a771c97cc70c7573663f751a444d728ed9048c1f20ab40c5".into(),
        };
        let extent = |start| Extent {
            start: Some(start),
            blocks: Some(1),
        };
        let operations = vec![
            Op {
                kind: 4,
                offset: None,
                length: None,
                source: vec![extent(0)],
                destination: vec![extent(0)],
                data_hash: None,
                source_hash: Some(hash_bytes(&gb_core::digest(&new[..4096]))),
            },
            Op {
                kind: 0,
                offset: Some(0),
                length: Some(4096),
                source: vec![],
                destination: vec![extent(1)],
                data_hash: Some(hash_bytes(&gb_core::digest(&new[4096..]))),
                source_hash: None,
            },
        ];
        let full = FullManifest {
            block_size: Some(4096),
            minor: Some(9),
            partitions: vec![FullUpdate {
                name: "system".into(),
                old: Some(info(&r.partitions[0].source.content)),
                new: Some(info(&r.partitions[0].expected)),
                operations,
            }],
        };
        zip_payload(&r.ota.path, &full.encode_to_vec(), &new[4096..]);
        r.ota.content = content(&std::fs::read(&r.ota.path).unwrap());
        let destination = dir.path().join("published");
        let report = reconstruct(&r, &destination).unwrap();
        assert_eq!(
            std::fs::read(destination.join("images/system.img")).unwrap(),
            new
        );
        assert!(
            !report.firmware_written
                && !report.postinstall_executed
                && !report.package_signature_verified
                && !report.port_adaptations_applied
        );
        assert!(report.manifest_preconditions_verified && report.inputs_unchanged);
    }
}
