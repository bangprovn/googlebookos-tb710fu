//! Versioned declarative profiles; observations never silently become verified facts.
use anyhow::{Context, Result, ensure};
use gb_core::safe_relative;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Observed,
    Assumption,
    Unknown,
    UserReported,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact<T> {
    pub status: EvidenceStatus,
    pub value: Option<T>,
    pub evidence: Option<String>,
}
impl<T> Fact<T> {
    pub fn validate(&self) -> Result<()> {
        match self.status {
            EvidenceStatus::Observed => ensure!(
                self.value.is_some()
                    && self.evidence.as_ref().is_some_and(|e| !e.trim().is_empty()),
                "observed fact requires a value and evidence"
            ),
            EvidenceStatus::Unknown => ensure!(
                self.value.is_none(),
                "unknown fact must not contain a value"
            ),
            EvidenceStatus::Assumption | EvidenceStatus::UserReported => ensure!(
                self.value.is_some(),
                "assumed/user-reported fact requires a value"
            ),
        }
        Ok(())
    }
    pub fn observed(&self) -> Option<&T> {
        if self.status == EvidenceStatus::Observed {
            self.value.as_ref()
        } else {
            None
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub codename: String,
    pub manufacturer: Fact<String>,
    pub architecture: Fact<String>,
    pub soc_vendor: Fact<String>,
    pub soc_model: Fact<String>,
    pub base_android: Fact<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootChain {
    pub bootloader_locked: Fact<bool>,
    pub strategy: Fact<String>,
    pub test_key_acceptance: Fact<bool>,
    pub rollback_requirement: Fact<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub device: Device,
    pub firmware: Firmware,
    pub boot: BootChain,
    #[serde(default)]
    pub features: BTreeMap<String, Fact<bool>>,
    #[serde(default)]
    pub graphics: Graphics,
    #[serde(default)]
    pub external_prerequisites: Vec<String>,
}
/// Numeric graphics observations are metadata, not Boolean capability claims.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Graphics {
    #[serde(default)]
    pub guest_image_import_format: Option<Fact<u32>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firmware {
    pub input: PathBuf,
    pub completeness: String,
    pub preserve_partitions: Vec<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Donor {
    pub schema_version: u32,
    pub codename: String,
    pub input: PathBuf,
    pub sha256: Option<String>,
    pub recovery_member: Option<String>,
    pub raw_sha256: Option<String>,
    pub reference: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Donor,
    Target,
    Build,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transform {
    ExtractFilesystem {
        source: Source,
        input: PathBuf,
        output: PathBuf,
        sha256: String,
        tool: PathBuf,
        #[serde(default)]
        sandbox: gb_tools::Sandbox,
    },
    Copy {
        source: Source,
        input: PathBuf,
        output: PathBuf,
        sha256: String,
    },
    ExtractZipMember {
        source: Source,
        member: String,
        output: PathBuf,
        sha256: String,
    },
    ExtractGptPartition {
        source: Source,
        input: Option<PathBuf>,
        partition: String,
        output: PathBuf,
        sha256: Option<String>,
    },
    ExtractLogicalPartition {
        source: Source,
        input: PathBuf,
        partition: String,
        #[serde(default)]
        slot: u32,
        output: PathBuf,
        sha256: Option<String>,
    },
    SparseToRaw {
        source: Source,
        input: PathBuf,
        output: PathBuf,
        sha256: String,
        tool: PathBuf,
        #[serde(default)]
        sandbox: gb_tools::Sandbox,
    },
    Overlay {
        partition: String,
        source: Source,
        input: PathBuf,
        output: PathBuf,
        sha256: String,
        replaces_sha256: Option<String>,
    },
}
impl Transform {
    pub fn output(&self) -> &Path {
        match self {
            Self::ExtractFilesystem { output, .. }
            | Self::Copy { output, .. }
            | Self::ExtractZipMember { output, .. }
            | Self::ExtractGptPartition { output, .. }
            | Self::ExtractLogicalPartition { output, .. }
            | Self::SparseToRaw { output, .. }
            | Self::Overlay { output, .. } => output,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TransformManifest {
    pub schema_version: u32,
    pub id: String,
    pub revision: u32,
    pub donor_fingerprint: Option<String>,
    pub target_fingerprint: Option<String>,
    #[serde(default)]
    pub operations: Vec<Transform>,
    #[serde(default)]
    pub publish: Vec<PathBuf>,
}
pub fn read_toml<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T> {
    toml::from_str(
        &std::fs::read_to_string(p).with_context(|| format!("configuration {}", p.display()))?,
    )
    .with_context(|| format!("parse configuration {}", p.display()))
}
pub fn profile(p: &Path) -> Result<Profile> {
    let mut x: Profile = read_toml(p)?;
    ensure!(x.schema_version == 1, "unsupported device schema");
    x.device.manufacturer.validate()?;
    x.device.architecture.validate()?;
    x.device.soc_vendor.validate()?;
    x.device.soc_model.validate()?;
    x.device.base_android.validate()?;
    x.boot.bootloader_locked.validate()?;
    x.boot.strategy.validate()?;
    x.boot.test_key_acceptance.validate()?;
    x.boot.rollback_requirement.validate()?;
    for fact in x.features.values() {
        fact.validate()?;
    }
    if let Some(format) = &x.graphics.guest_image_import_format {
        format.validate()?;
    }

    ensure!(!x.device.codename.is_empty(), "device codename required");
    if x.firmware.input.is_relative() {
        x.firmware.input = p.parent().unwrap_or(Path::new(".")).join(&x.firmware.input);
    }
    ensure!(
        matches!(
            x.firmware.completeness.as_str(),
            "complete" | "partial_capture" | "partition_subset"
        ),
        "invalid firmware completeness"
    );
    Ok(x)
}
pub fn donor(p: &Path) -> Result<Donor> {
    let mut x: Donor = read_toml(p)?;
    ensure!(x.schema_version == 1, "unsupported donor schema");
    if x.input.is_relative() {
        x.input = p.parent().unwrap_or(Path::new(".")).join(&x.input);
    }
    Ok(x)
}
pub fn transforms(p: Option<&Path>) -> Result<TransformManifest> {
    let x = match p {
        Some(p) => read_toml(p)?,
        None => TransformManifest {
            schema_version: 1,
            id: "inspection_only".into(),
            revision: 1,
            ..Default::default()
        },
    };
    ensure!(
        x.schema_version == 1 && x.revision > 0,
        "unsupported transformation schema/revision"
    );
    let mut outputs = std::collections::BTreeSet::new();
    for op in &x.operations {
        safe_relative(op.output())?;
        ensure!(
            outputs.insert(op.output()),
            "duplicate transformation output"
        );
        match op {
            Transform::ExtractFilesystem { input, .. }
            | Transform::Copy { input, .. }
            | Transform::SparseToRaw { input, .. }
            | Transform::ExtractLogicalPartition { input, .. }
            | Transform::Overlay { input, .. } => safe_relative(input)?,
            Transform::ExtractZipMember { member, .. } => safe_relative(Path::new(member))?,
            Transform::ExtractGptPartition {
                input: Some(input), ..
            } => safe_relative(input)?,
            _ => {}
        }
    }
    for p in &x.publish {
        safe_relative(p)?;
        ensure!(
            x.operations.iter().any(|op| p.starts_with(op.output())),
            "publish path not produced by transformation"
        );
    }
    Ok(x)
}
pub fn resolve(name: &Path, dir: &str) -> PathBuf {
    if name.exists() {
        name.to_owned()
    } else {
        Path::new(dir).join(name).with_extension("toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assumptions_not_verified() {
        let f = Fact {
            status: EvidenceStatus::UserReported,
            value: Some(true),
            evidence: Some("owner reports test key boot".into()),
        };
        assert!(f.observed().is_none());
    }
    #[test]
    fn examples_parse() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(profile(&root.join("devices/lenovo-tb710fu.toml")).is_ok());
        assert!(donor(&root.join("donors/mica.toml")).is_ok());
    }
    #[test]
    fn numeric_graphics_metadata_remains_typed_and_evidenced() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let original = std::fs::read_to_string(root.join("devices/lenovo-tb710fu.toml")).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device.toml");
        std::fs::write(&path, &original).unwrap();
        let parsed = profile(&path).unwrap();
        assert_eq!(
            parsed
                .graphics
                .guest_image_import_format
                .unwrap()
                .observed(),
            Some(&875708993)
        );
        let without_evidence = original
            .lines()
            .map(|line| {
                if line.starts_with("guest_image_import_format =") {
                    "guest_image_import_format = { status = \"observed\", value = 875708993 }"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, without_evidence).unwrap();
        assert!(profile(&path).is_err());
        std::fs::write(&path, original.replace("[graphics]", "")).unwrap();
        assert!(profile(&path).is_err());
    }
}
