//! Deterministic, streaming ROM distribution assets. No flashing or signing.
use anyhow::{Context, Result, ensure};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use gb_core::{
    checkpoint, hash_file, hash_reader, open_regular_file, publish_directory, write_json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const PARTITIONS: &[&str] = &[
    "boot",
    "init_boot",
    "vendor_boot",
    "system",
    "product",
    "system_ext",
    "vendor",
    "vbmeta",
    "vbmeta_system",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub id: String,
    pub device: String,
    pub source_commit: String,
    pub images: BTreeMap<String, Image>,
    /// Reviewed public fields only; input paths never enter the release manifest.
    pub metadata: serde_json::Value,
    pub documents: BTreeMap<String, Image>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Asset {
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
    pub image_bytes: u64,
    pub image_sha256: String,
    pub roundtrip_verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub id: String,
    pub device: String,
    pub source_commit: String,
    pub status: String,
    pub images: BTreeMap<String, Asset>,
    pub metadata: serde_json::Value,
    pub firmware_flashed: bool,
    pub clean_install_tested_by_packager: bool,
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 256 * 1024)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for input in r.images.values_mut().chain(r.documents.values_mut()) {
            if input.path.is_relative() {
                input.path = parent.join(&input.path);
            }
        }
        r.validate()?;
        Ok(r)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && label(&self.id) && label(&self.device),
            "invalid release identity"
        );
        ensure!(
            self.source_commit.len() == 40
                && self.source_commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "source commit must be a full Git commit ID"
        );
        ensure!(
            self.images.len() == PARTITIONS.len()
                && PARTITIONS.iter().all(|p| self.images.contains_key(*p)),
            "release must contain exactly the nine supported ROM partitions; userdata and device identity partitions are forbidden"
        );
        ensure!(self.documents.len() <= 8, "too many release documents");
        for name in self.documents.keys() {
            ensure!(
                [
                    "INSTALL.md",
                    "KNOWN_ISSUES.md",
                    "LICENSE",
                    "NOTICE.md",
                    "VALIDATION.json"
                ]
                .contains(&name.as_str()),
                "unsupported public document name"
            );
        }
        ensure!(self.metadata.is_object(), "metadata must be an object");
        for input in self.images.values().chain(self.documents.values()) {
            ensure!(
                digest_valid(&input.sha256) && input.bytes > 0,
                "input needs a SHA256 pin and a nonzero size"
            );
        }
        ensure!(
            self.documents.values().all(|i| i.bytes <= 256 * 1024),
            "release document exceeds budget"
        );
        Ok(())
    }
}

fn open(input: &Image) -> Result<File> {
    let file = open_regular_file(&input.path, OpenOptions::new().read(true))?;
    ensure!(
        file.metadata()?.len() == input.bytes,
        "pinned input size differs"
    );
    Ok(file)
}

fn compress(input: &Image, path: &Path) -> Result<Asset> {
    let mut source = open(input)?;
    let output = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut gzip = GzBuilder::new().mtime(0).write(output, Compression::new(6));
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        checkpoint()?;
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("input byte count overflow")?;
        ensure!(bytes <= input.bytes, "input grew during compression");
        hash.update(&buffer[..n]);
        gzip.write_all(&buffer[..n])?;
    }
    ensure!(
        bytes == input.bytes
            && format!("{:x}", hash.finalize()) == input.sha256.to_ascii_lowercase(),
        "pinned input checksum differs"
    );
    gzip.finish()?.sync_all()?;
    ensure!(
        hash_reader(GzDecoder::new(File::open(path)?))? == input.sha256.to_ascii_lowercase(),
        "compressed image roundtrip differs"
    );
    let size = fs::metadata(path)?.len();
    ensure!(
        size < 2_000_000_000,
        "compressed asset exceeds release upload budget; split packaging is required"
    );
    Ok(Asset {
        filename: path
            .file_name()
            .context("asset filename missing")?
            .to_str()
            .context("non-UTF8 asset name")?
            .into(),
        bytes: size,
        sha256: hash_file(path)?,
        image_bytes: input.bytes,
        image_sha256: input.sha256.to_ascii_lowercase(),
        roundtrip_verified: true,
    })
}

pub fn prepare(request: &Request, destination: &Path) -> Result<Report> {
    request.validate()?;
    ensure!(!destination.exists(), "release destination already exists");
    for input in request.images.values().chain(request.documents.values()) {
        gb_core::separate_from_input(&input.path, destination)?;
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let total = request
        .images
        .values()
        .try_fold(512 * 1024 * 1024_u64, |n, i| {
            n.checked_add(i.bytes).context("release size overflow")
        })?;
    ensure!(
        fs2::available_space(parent)? > total,
        "insufficient release staging space"
    );
    let staging = tempfile::tempdir_in(parent)?;
    let mut images = BTreeMap::new();
    for (name, input) in &request.images {
        let path = staging.path().join(format!("{name}.img.gz"));
        images.insert(name.clone(), compress(input, &path)?);
    }
    for (name, input) in &request.documents {
        let mut data = Vec::new();
        open(input)?.take(input.bytes + 1).read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 == input.bytes
                && gb_core::digest(&data) == input.sha256.to_ascii_lowercase(),
            "release document checksum differs"
        );
        std::str::from_utf8(&data).context("release documents must be UTF8")?;
        fs::write(staging.path().join(name), data)?;
    }
    let report = Report {
        schema_version: 1,
        id: request.id.clone(),
        device: request.device.clone(),
        source_commit: request.source_commit.clone(),
        status: "images_packaged_and_roundtrip_verified".into(),
        images,
        metadata: request.metadata.clone(),
        firmware_flashed: false,
        clean_install_tested_by_packager: false,
    };
    write_json(&staging.path().join("manifest.json"), &report)?;
    let raw = report
        .images
        .iter()
        .map(|(name, a)| format!("{}  {name}.img\n", a.image_sha256))
        .collect::<String>();
    fs::write(staging.path().join("IMAGES_SHA256SUMS"), raw)?;
    let mut paths = fs::read_dir(staging.path())?
        .map(|e| e.map(|x| x.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    let mut sums = String::new();
    for path in paths {
        sums.push_str(&format!(
            "{}  {}\n",
            hash_file(&path)?,
            path.file_name()
                .context("missing filename")?
                .to_str()
                .context("non-UTF8 filename")?
        ));
    }
    fs::write(staging.path().join("SHA256SUMS"), sums)?;
    publish_directory(staging.path(), destination)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &Path) -> Request {
        let data = b"small synthetic image fixture\n";
        let path = dir.join("input");
        fs::write(&path, data).unwrap();
        let image = Image {
            path,
            sha256: gb_core::digest(data),
            bytes: data.len() as u64,
        };
        Request {
            schema_version: 1,
            id: "test-alpha1".into(),
            device: "test-tablet".into(),
            source_commit: "a".repeat(40),
            images: PARTITIONS
                .iter()
                .map(|s| (s.to_string(), image.clone()))
                .collect(),
            metadata: serde_json::json!({"runtime_verified":false}),
            documents: BTreeMap::new(),
        }
    }
    #[test]
    fn deterministic_assets_roundtrip_and_do_not_expose_input_paths() {
        let dir = tempfile::tempdir().unwrap();
        let r = fixture(dir.path());
        let a = dir.path().join("one");
        let b = dir.path().join("two");
        prepare(&r, &a).unwrap();
        prepare(&r, &b).unwrap();
        assert_eq!(
            fs::read(a.join("SHA256SUMS")).unwrap(),
            fs::read(b.join("SHA256SUMS")).unwrap()
        );
        assert!(
            !fs::read_to_string(a.join("manifest.json"))
                .unwrap()
                .contains(dir.path().to_str().unwrap())
        );
        assert!(prepare(&r, &a).is_err());
    }
    #[test]
    fn checksum_failure_leaves_no_partial_release() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = fixture(dir.path());
        r.images.get_mut("boot").unwrap().sha256 = "0".repeat(64);
        let dest = dir.path().join("out");
        assert!(prepare(&r, &dest).is_err());
        assert!(!dest.exists());
    }
    #[test]
    fn refuses_extra_partitions_and_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = fixture(dir.path());
        r.images.insert("userdata".into(), r.images["boot"].clone());
        assert!(r.validate().is_err());
        r.images.remove("userdata");
        r.id = "../escape".into();
        assert!(r.validate().is_err());
        r.id = "okay".into();
        r.documents
            .insert("../keys".into(), r.images["boot"].clone());
        assert!(r.validate().is_err());
    }
}
