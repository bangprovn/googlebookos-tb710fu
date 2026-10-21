//! EDL subprocess boundary. The programmer is an explicit external prerequisite.
use crate::{checked_json, digest_ok, write_json};
use anyhow::{Context, Result, ensure};
use gb_core::{hash_file, run_tool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

pub const CLIENT_COMMIT: &str = "2f8e89a848afaaef68997fcbcb5b178d958d497b";
pub const PROGRAMMER_SHA256: &str =
    "87f8f12681b556258a5c30df95595d4b9fa624e34f0181f25840fdb80b208dc5";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub serial: String,
    pub sector_bytes: u64,
    pub luns: u32,
    pub memory: String,
    pub product: String,
}
impl Identity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.memory == "ufs"
                && self.sector_bytes == 4096
                && (1..=8).contains(&self.luns)
                && !self.serial.is_empty()
                && self.serial != "0"
                && self.serial.len() <= 64
                && self
                    .serial
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "unsupported UFS identity"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub lun: u32,
    pub start_sector: u64,
    pub sectors: u64,
}
impl Range {
    pub fn bytes(&self) -> Result<u64> {
        ensure!(
            self.lun < 8
                && self.start_sector < (1 << 40)
                && self.sectors > 0
                && self.sectors <= (1 << 32)
                && self
                    .start_sector
                    .checked_add(self.sectors)
                    .is_some_and(|n| n < (1 << 40)),
            "invalid EDL range"
        );
        self.sectors
            .checked_mul(4096)
            .context("sector range overflow")
    }
}
/// Injectable transport: offline tests use a disk-backed implementation, never USB.
pub trait Device {
    fn identity(&self) -> Result<Identity>;
    fn tools(&self) -> Result<Value>;
    fn read(&self, range: &Range, destination: &Path) -> Result<()>;
    fn digest(&self, range: &Range) -> Result<String>;
    /// A successful program must include a matching device-side digest.
    fn program(&self, range: &Range, source: &Path, sha256: &str) -> Result<()>;
    fn reset(&self) -> Result<()>;
}
#[derive(Debug, Clone)]
pub struct Edl {
    pub python: PathBuf,
    pub client: PathBuf,
    pub loader: PathBuf,
    pub libusb: Option<PathBuf>,
    pub serial: String,
}
impl Edl {
    pub fn validate_tools(&self) -> Result<Value> {
        let client = fs::canonicalize(&self.client)?;
        ensure!(
            client.join("edl.py").is_file(),
            "--edl-client must name the bkerler/edl checkout directory"
        );
        let git = |args: &[&str]| -> Result<String> {
            let mut all = vec!["-C".to_owned(), client.display().to_string()];
            all.extend(args.iter().map(|s| s.to_string()));
            Ok(run_tool(Path::new("git"), &all, Duration::from_secs(15))?
                .stdout
                .trim()
                .to_owned())
        };
        ensure!(
            git(&["rev-parse", "HEAD"])? == CLIENT_COMMIT,
            "EDL checkout must be pinned to {CLIENT_COMMIT}"
        );
        ensure!(
            git(&["status", "--porcelain"])?.is_empty(),
            "EDL checkout has modifications or untracked files; use a clean trusted checkout"
        );
        ensure!(
            fs::symlink_metadata(&self.loader)?.file_type().is_file()
                && hash_file(&self.loader)? == PROGRAMMER_SHA256,
            "programmer differs from the qualified TB710FU stock xbl_s_devprg_ns.melf"
        );
        Ok(
            json!({"transport":"edl", "edl_commit":CLIENT_COMMIT,"loader_sha256":PROGRAMMER_SHA256,
            "bridge_sha256":format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(include_bytes!("../../../scripts/install/edl_bridge.py"))),
            "python":run_tool(&self.python, &["--version".into()], Duration::from_secs(10))?.stdout,
            "libusb":self.libusb}),
        )
    }
    fn call(&self, mut request: Value) -> Result<Value> {
        self.validate_tools()?;
        let temp = tempfile::tempdir()?;
        let bridge = temp.path().join("edl_bridge.py");
        fs::write(
            &bridge,
            include_bytes!("../../../scripts/install/edl_bridge.py"),
        )?;
        request["client"] = json!(fs::canonicalize(&self.client)?);
        request["loader"] = json!(fs::canonicalize(&self.loader)?);
        request["libusb"] = json!(self.libusb);
        request["serial"] = json!(self.serial);
        let input = temp.path().join("request.json");
        let output = temp.path().join("response.json");
        write_json(&input, &request)?;
        let result = run_tool(
            &self.python,
            &[
                "-I".into(),
                bridge.display().to_string(),
                input.display().to_string(),
                output.display().to_string(),
            ],
            Duration::from_secs(900),
        )
        .context("EDL operation failed; no automatic retry or reset is performed")?;
        ensure!(
            output.is_file(),
            "EDL client exited without a verified result: {} {}",
            result.stdout,
            result.stderr
        );
        let response: Value = checked_json(&output)?;
        ensure!(
            response["schema_version"] == 1 && response["ok"] == true,
            "invalid EDL response"
        );
        let id: Identity = serde_json::from_value(response["identity"].clone())?;
        id.validate()?;
        ensure!(
            request["operation"] == "probe" || id.serial == self.serial,
            "wrong storage serial"
        );
        Ok(response)
    }
    pub fn probe(&self) -> Result<Identity> {
        Ok(serde_json::from_value(
            self.call(json!({"operation":"probe"}))?["identity"].clone(),
        )?)
    }
    fn range_request(&self, op: &str, range: &Range) -> Result<Value> {
        range.bytes()?;
        ensure!(!self.serial.is_empty(), "explicit UFS serial required");
        Ok(
            json!({"operation":op,"lun":range.lun,"start_sector":range.start_sector,"sectors":range.sectors}),
        )
    }
}
impl Device for Edl {
    fn identity(&self) -> Result<Identity> {
        let id = self.probe()?;
        ensure!(
            id.serial == self.serial,
            "connected tablet has a different UFS serial"
        );
        Ok(id)
    }
    fn tools(&self) -> Result<Value> {
        self.validate_tools()
    }
    fn read(&self, range: &Range, destination: &Path) -> Result<()> {
        ensure!(
            range.bytes()? <= 128 * 1024 * 1024 && !destination.exists(),
            "invalid bounded readback destination"
        );
        let mut r = self.range_request("read", range)?;
        // Parent exists; do not canonicalize a not-yet-created output file.
        r["path"] = json!(
            fs::canonicalize(destination.parent().context("output parent")?)?
                .join(destination.file_name().context("output name")?)
        );
        self.call(r)?;
        ensure!(
            fs::symlink_metadata(destination)?.file_type().is_file()
                && fs::metadata(destination)?.len() == range.bytes()?,
            "short EDL readback"
        );
        Ok(())
    }
    fn digest(&self, range: &Range) -> Result<String> {
        let r = self.call(self.range_request("digest", range)?)?;
        let hash = r["sha256"].as_str().context("missing digest")?;
        ensure!(digest_ok(hash), "invalid device digest");
        Ok(hash.into())
    }
    fn program(&self, range: &Range, source: &Path, sha256: &str) -> Result<()> {
        ensure!(
            fs::symlink_metadata(source)?.file_type().is_file()
                && fs::metadata(source)?.len() == range.bytes()?
                && digest_ok(sha256),
            "invalid program input"
        );
        let mut r = self.range_request("program", range)?;
        r["path"] = json!(fs::canonicalize(source)?);
        r["sha256"] = json!(sha256);
        ensure!(
            self.call(r)?["sha256"] == sha256,
            "device digest differs after programming"
        );
        Ok(())
    }
    fn reset(&self) -> Result<()> {
        self.call(json!({"operation":"reset"}))?;
        Ok(())
    }
}
