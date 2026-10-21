//! Shared evidence models, streaming digests and bounded host-tool execution.
pub mod tool_log;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub static CANCELLED: AtomicBool = AtomicBool::new(false);
pub fn checkpoint() -> Result<()> {
    ensure!(!CANCELLED.load(Ordering::Relaxed), "operation cancelled");
    Ok(())
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn hash_reader(mut r: impl Read) -> Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        checkpoint()?;
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
pub fn hash_file(path: &Path) -> Result<String> {
    hash_reader(File::open(path).with_context(|| format!("open {}", path.display()))?)
}
/// Open a regular file with the caller's read/write/create/truncate settings.
/// Unix custom flags are reserved for O_NOFOLLOW and O_NONBLOCK: the final path
/// component cannot be followed if replaced by a symlink, and a FIFO cannot
/// block the open before its file type is rejected. The opened descriptor is
/// checked directly. This does not confine traversal of ancestor directories.
pub fn open_regular_file(path: &Path, options: &mut std::fs::OpenOptions) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(path)
            .with_context(|| format!("open regular file {}", path.display()))?;
        ensure!(
            file.metadata()?.file_type().is_file(),
            "opened file must be regular: {}",
            path.display()
        );
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, options);
        bail!("no-follow regular-file opening requires a host adapter for this platform")
    }
}
pub fn copy_stream(mut r: impl Read, mut w: impl Write) -> Result<u64> {
    let mut total = 0;
    let mut buf = vec![0; 1024 * 1024];
    loop {
        checkpoint()?;
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}
pub fn safe_relative(path: &Path) -> Result<()> {
    ensure!(!path.as_os_str().is_empty(), "empty relative path");
    ensure!(
        path.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe relative path: {}",
        path.display()
    );
    Ok(())
}
/// Resolve existing ancestors (including links) without creating a destination.
fn destination_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            other => {
                resolved.push(other.as_os_str());
                match std::fs::symlink_metadata(&resolved) {
                    Ok(_) => resolved = resolved.canonicalize()?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(resolved)
}
/// A cache, scratch directory or report must never overlap source firmware.
pub fn separate_from_input(input: &Path, writable: &Path) -> Result<()> {
    let input = input.canonicalize()?;
    let writable = destination_path(writable)?;
    ensure!(
        !writable.starts_with(&input) && !input.starts_with(&writable),
        "writable destination overlaps source firmware: {}",
        writable.display()
    );
    Ok(())
}
pub fn separate_destinations(first: &Path, second: &Path) -> Result<()> {
    let first = destination_path(first)?;
    let second = destination_path(second)?;
    ensure!(
        !first.starts_with(&second) && !second.starts_with(&first),
        "writable destinations overlap"
    );
    Ok(())
}
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temp, value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Zip,
    Gpt,
    Sparse,
    Super,
    Ext4,
    Erofs,
    Boot,
    VendorBoot,
    Dtbo,
    Vbmeta,
    OtaPayload,
    Elf,
    Gzip,
    Lz4,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub format: Format,
    pub metadata: serde_json::Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub path: String,
    pub key: String,
    pub value: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VintfDocument {
    pub path: String,
    pub kind: String,
    pub role: Option<String>,
    pub level: Option<String>,
    pub hals: Vec<Hal>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hal {
    pub name: String,
    pub format: String,
    pub optional: bool,
    pub versions: Vec<String>,
    pub interfaces: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLibrary {
    pub path: String,
    pub architecture: String,
    pub soname: Option<String>,
    pub needed: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApexPackage {
    pub path: String,
    pub name: String,
    pub version: i64,
    pub version_name: String,
    pub compressed: bool,
    pub package_sha256: String,
    pub original_apex_sha256: Option<String>,
    pub payload_sha256: String,
    pub payload_format: Format,
    pub public_key_sha256: String,
    pub provide_native_libs: Vec<String>,
    pub require_native_libs: Vec<String>,
    pub jni_libs: Vec<String>,
    pub bootstrap: bool,
    pub signatures_verified: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Inventory {
    pub properties: Vec<Property>,
    pub vintf: Vec<VintfDocument>,
    pub native_libraries: Vec<NativeLibrary>,
    pub framework: Vec<String>,
    pub apex: Vec<String>,
    #[serde(default)]
    pub apex_packages: Vec<ApexPackage>,
    #[serde(default)]
    pub metadata_text: BTreeMap<String, String>,
    pub selinux: Vec<String>,
    pub init: Vec<String>,
    pub permissions: Vec<String>,
    pub modules: Vec<String>,
    pub symlinks: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    pub schema_version: u32,
    pub inspector_version: String,
    pub source_sha256: String,
    pub artifacts: Vec<Artifact>,
    pub inventory: Inventory,
    pub limitations: Vec<String>,
}
impl FirmwareManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported firmware manifest schema"
        );
        let valid_hash = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            valid_hash(&self.source_sha256),
            "invalid manifest source SHA256"
        );
        let mut paths = std::collections::BTreeSet::new();
        for artifact in &self.artifacts {
            safe_relative(Path::new(&artifact.path))?;
            ensure!(valid_hash(&artifact.sha256), "invalid artifact SHA256");
            ensure!(
                paths.insert(artifact.path.as_str()),
                "duplicate manifest artifact path"
            );
        }
        for path in self
            .inventory
            .properties
            .iter()
            .map(|p| p.path.as_str())
            .chain(self.inventory.vintf.iter().map(|v| v.path.as_str()))
            .chain(
                self.inventory
                    .native_libraries
                    .iter()
                    .map(|l| l.path.as_str()),
            )
        {
            ensure!(
                paths.contains(path),
                "inventory evidence path missing from artifact records: {path}"
            );
        }
        for list in [
            &self.inventory.framework,
            &self.inventory.apex,
            &self.inventory.selinux,
            &self.inventory.init,
            &self.inventory.permissions,
            &self.inventory.modules,
        ] {
            for path in list {
                ensure!(
                    paths.contains(path.as_str()),
                    "inventory category path missing from artifact records: {path}"
                );
            }
        }
        for path in self.inventory.symlinks.keys() {
            safe_relative(Path::new(path))?;
        }
        for package in &self.inventory.apex_packages {
            let artifact = self
                .artifacts
                .iter()
                .find(|a| a.path == package.path)
                .context("APEX metadata has no package artifact")?;
            ensure!(
                artifact.sha256 == package.package_sha256
                    && valid_hash(&package.payload_sha256)
                    && valid_hash(&package.public_key_sha256),
                "APEX evidence digest mismatch"
            );
        }
        for (path, text) in &self.inventory.metadata_text {
            let artifact = self
                .artifacts
                .iter()
                .find(|a| a.path == *path)
                .context("text evidence lacks artifact record")?;
            ensure!(
                artifact.sha256 == digest(text.as_bytes()) && artifact.bytes == text.len() as u64,
                "text evidence digest/length mismatch: {path}"
            );
        }
        Ok(())
    }
    pub fn property(&self, key: &str) -> Option<&str> {
        let mut vals = self
            .inventory
            .properties
            .iter()
            .filter(|p| p.key == key)
            .map(|p| p.value.as_str());
        let v = vals.next()?;
        vals.all(|x| x == v).then_some(v)
    }
    pub fn architecture(&self) -> Option<&str> {
        self.property("ro.product.cpu.abi").map(|a| match a {
            "arm64-v8a" => "aarch64",
            "armeabi-v7a" => "arm",
            "x86_64" => "x86_64",
            _ => a,
        })
    }
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= max_bytes,
        "JSON input must be a bounded regular file: {}",
        path.display()
    );
    Ok(serde_json::from_reader(
        File::open(path)?.take(
            max_bytes
                .checked_add(1)
                .context("JSON size limit overflow")?,
        ),
    )?)
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Compatible,
    PatchRequired,
    ImplementationRequired,
    Unsupported,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub feature: String,
    pub state: State,
    pub evidence: Vec<String>,
    pub runtime_verified: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub schema_version: u32,
    pub donor_sha256: String,
    pub target_sha256: String,
    pub findings: Vec<Finding>,
    pub bootable: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub stderr_filtered_lines: u64,
    #[serde(default)]
    pub stderr_truncated: bool,
}
#[derive(Debug)]
pub struct ToolFailure {
    pub result: ToolResult,
}
impl std::fmt::Display for ToolFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host tool failed: {}",
            serde_json::to_string(&self.result)
                .unwrap_or_else(|_| "diagnostic serialization unavailable".into())
        )
    }
}
impl std::error::Error for ToolFailure {}
/// Runs only host-installed tools. Output is drained but retained up to 64 KiB per stream.
/// Linux process groups are killed on timeout/cancellation, including grandchildren.
pub fn run_tool(program: &Path, args: &[String], timeout: Duration) -> Result<ToolResult> {
    run_tool_filtered(program, args, timeout, None)
}
pub fn run_tool_filtered(
    program: &Path,
    args: &[String],
    timeout: Duration,
    stderr_filter: Option<fn(&str) -> bool>,
) -> Result<ToolResult> {
    run_tool_stdout_budget(program, args, timeout, stderr_filter, 65536)
}
/// Retain a larger bounded stdout receipt, such as Android's Vulkan JSON.
/// Stderr remains limited to 64 KiB. Callers needing a complete receipt must
/// reject output reaching the budget, since it may have been truncated.
pub fn run_tool_with_stdout_budget(
    program: &Path,
    args: &[String],
    timeout: Duration,
    budget: usize,
) -> Result<ToolResult> {
    ensure!(
        (1..=4 * 1024 * 1024).contains(&budget),
        "stdout budget outside 1..4 MiB"
    );
    run_tool_stdout_budget(program, args, timeout, None, budget)
}
fn run_tool_stdout_budget(
    program: &Path,
    args: &[String],
    timeout: Duration,
    stderr_filter: Option<fn(&str) -> bool>,
    stdout_budget: usize,
) -> Result<ToolResult> {
    checkpoint()?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("SOURCE_DATE_EPOCH", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("execute host tool {}", program.display()))?;
    fn drain(mut r: impl Read, budget: usize) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut b = [0; 8192];
        loop {
            let n = r.read(&mut b)?;
            if n == 0 {
                break;
            }
            let keep = n.min(budget.saturating_sub(out.len()));
            out.extend_from_slice(&b[..keep]);
        }
        Ok(out)
    }
    let stdout = child.stdout.take().context("child stdout unavailable")?;
    let stderr = child.stderr.take().context("child stderr unavailable")?;
    let o = std::thread::spawn(move || drain(stdout, stdout_budget));
    let e = std::thread::spawn(move || drain_lines(stderr, stderr_filter));
    let start = Instant::now();
    let status = loop {
        if CANCELLED.load(Ordering::Relaxed) || start.elapsed() > timeout {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = o.join();
            let _ = e.join();
            bail!(
                "host tool {} timed out or cancelled after {:?}",
                program.display(),
                start.elapsed()
            );
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Kill leaked descendants before joining pipes; host tools must not daemonize.
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let diagnostics = e
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    let result = ToolResult {
        program: program.display().to_string(),
        args: args.to_vec(),
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(
            &o.join()
                .map_err(|_| anyhow::anyhow!("stdout reader failed"))??,
        )
        .into_owned(),
        stderr: String::from_utf8_lossy(&diagnostics.0).into_owned(),
        stderr_filtered_lines: diagnostics.1,
        stderr_truncated: diagnostics.2,
    };
    if !status.success() {
        return Err(ToolFailure { result }.into());
    }
    Ok(result)
}
/// Filter bounded complete diagnostic lines while draining the entire pipe. An
/// overlong/invalid-UTF8 line is never filtered and explicitly marks truncation.
fn drain_lines(
    mut reader: impl Read,
    filter: Option<fn(&str) -> bool>,
) -> std::io::Result<(Vec<u8>, u64, bool)> {
    let mut out = Vec::new();
    let mut line = Vec::new();
    let mut skipped = 0;
    let mut truncated = false;
    let mut overflow = false;
    let mut chunk = [0; 8192];
    let finish = |line: &mut Vec<u8>,
                  overflow: &mut bool,
                  out: &mut Vec<u8>,
                  skipped: &mut u64,
                  truncated: &mut bool| {
        let ignored = !*overflow
            && std::str::from_utf8(line)
                .ok()
                .is_some_and(|text| filter.is_some_and(|f| f(text.trim_end_matches('\n'))));
        if ignored {
            *skipped += 1;
        } else {
            let keep = line.len().min(65536usize.saturating_sub(out.len()));
            out.extend_from_slice(&line[..keep]);
            *truncated |= *overflow || keep < line.len();
        }
        line.clear();
        *overflow = false;
    };
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        for byte in &chunk[..n] {
            if line.len() < 8192 {
                line.push(*byte);
            } else {
                overflow = true;
            }
            if *byte == b'\n' {
                finish(
                    &mut line,
                    &mut overflow,
                    &mut out,
                    &mut skipped,
                    &mut truncated,
                );
            }
        }
    }
    if !line.is_empty() || overflow {
        finish(
            &mut line,
            &mut overflow,
            &mut out,
            &mut skipped,
            &mut truncated,
        );
    }
    Ok((out, skipped, truncated))
}

/// Atomic directory publication which never replaces an existing destination.
pub fn publish_directory(staging: &Path, destination: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let src = CString::new(staging.as_os_str().as_bytes())?;
        let dst = CString::new(destination.as_os_str().as_bytes())?;
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                src.as_ptr(),
                libc::AT_FDCWD,
                dst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        ensure!(
            result == 0,
            "atomic artifact publication failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (staging, destination);
        bail!("atomic no-replace publication requires a host adapter for this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn regular_file_opener_preserves_explicit_access_and_creation_settings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("lock");
        let mut file = open_regular_file(
            &path,
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true),
        )
        .unwrap();
        file.write_all(b"existing lock contents").unwrap();
        drop(file);
        let mut file = open_regular_file(
            &path,
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false),
        )
        .unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"existing lock contents");
        assert!(
            open_regular_file(
                &path,
                std::fs::OpenOptions::new().write(true).create_new(true)
            )
            .is_err()
        );
        drop(file);
        let file = open_regular_file(
            &path,
            std::fs::OpenOptions::new().write(true).truncate(true),
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
    #[cfg(unix)]
    #[test]
    fn regular_file_opener_refuses_final_symlinks_without_truncation_or_creation() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("stock.img");
        let missing = temp.path().join("missing.img");
        std::fs::write(&original, b"original firmware").unwrap();
        for (index, target) in [&original, &missing].into_iter().enumerate() {
            let link = temp.path().join(format!("link-{index}"));
            std::os::unix::fs::symlink(target, &link).unwrap();
            assert!(
                open_regular_file(
                    &link,
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                )
                .is_err()
            );
            assert!(
                std::fs::symlink_metadata(link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        assert_eq!(std::fs::read(original).unwrap(), b"original firmware");
        assert!(!missing.exists());
    }
    #[cfg(unix)]
    #[test]
    fn regular_file_opener_rejects_directories_and_fifo_without_blocking() {
        use std::os::unix::{ffi::OsStrExt, fs::FileTypeExt};

        let temp = tempfile::tempdir().unwrap();
        assert!(open_regular_file(temp.path(), std::fs::OpenOptions::new().read(true)).is_err());
        let fifo = temp.path().join("receipt.fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // This creates a private FIFO, never a device node.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let owned = fifo.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let refused =
                open_regular_file(&owned, std::fs::OpenOptions::new().read(true)).is_err();
            sender.send(refused).unwrap();
        });
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
        thread.join().unwrap();
        assert!(
            std::fs::symlink_metadata(fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }
    #[test]
    fn manifest_evidence_requires_records_and_bounded_json() {
        let mut m = FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "0".repeat(64),
            artifacts: vec![],
            inventory: Inventory::default(),
            limitations: vec![],
        };
        m.inventory.properties.push(Property {
            path: "system/build.prop".into(),
            key: "ro.build.version.release".into(),
            value: "17".into(),
        });
        assert!(m.validate().is_err());
        m.artifacts.push(Artifact {
            path: "system/build.prop".into(),
            bytes: 1,
            sha256: "1".repeat(64),
            format: Format::Unknown,
            metadata: serde_json::json!({}),
        });
        assert!(m.validate().is_ok());
        m.artifacts.push(m.artifacts[0].clone());
        assert!(m.validate().is_err());
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("large.json");
        std::fs::write(&p, b"{\"x\":123}").unwrap();
        assert!(read_json::<serde_json::Value>(&p, 4).is_err());
        assert!(read_json::<serde_json::Value>(&p, 32).is_ok());
    }
    #[test]
    fn diagnostics_after_warning_flood_and_overlong_lines_are_retained() {
        let mut input = "expected warning\n".repeat(10000);
        input.push_str("actual extraction error\n");
        let (bytes, skipped, truncated) =
            drain_lines(input.as_bytes(), Some(|s| s == "expected warning")).unwrap();
        assert_eq!(skipped, 10000);
        assert!(!truncated);
        assert_eq!(bytes, b"actual extraction error\n");
        let input = format!("{}\nactual error\n", "x".repeat(128 * 1024));
        let (bytes, skipped, truncated) = drain_lines(input.as_bytes(), Some(|_| true)).unwrap();
        assert!(truncated);
        assert_eq!(skipped, 1);
        assert_eq!(bytes.len(), 8192);
    }
    #[test]
    fn source_isolation_resolves_future_paths_and_links() {
        let t = tempfile::tempdir().unwrap();
        let input = t.path().join("stock");
        std::fs::create_dir(&input).unwrap();
        assert!(separate_from_input(&input, &input.join("new/cache")).is_err());
        assert!(separate_from_input(&input, t.path()).is_err());
        assert!(separate_from_input(&input, &t.path().join("cache")).is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&input, t.path().join("alias")).unwrap();
            assert!(separate_from_input(&input, &t.path().join("alias/new/report.json")).is_err());
        }
        assert!(!input.join("new").exists());
        assert!(
            separate_destinations(&t.path().join("new"), &t.path().join("new/report.json"))
                .is_err()
        );
        assert!(separate_destinations(&t.path().join("new.json"), &t.path().join("new")).is_ok());
    }
    #[test]
    fn paths_and_hashes() {
        assert!(safe_relative(Path::new("../bad")).is_err());
        assert!(safe_relative(Path::new("/bad")).is_err());
        assert!(safe_relative(Path::new("system/etc/a")).is_ok());
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn tool_timeout() {
        let now = Instant::now();
        assert!(
            run_tool(
                Path::new("/bin/sleep"),
                &["5".into()],
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(now.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn stdout_budget_is_bounded_and_does_not_change_default_limit() {
        let command = ["-c".into(), "printf '%070000d' 0".into()];
        let run = |budget| {
            run_tool_with_stdout_budget(
                Path::new("/bin/sh"),
                &command,
                Duration::from_secs(2),
                budget,
            )
        };
        assert_eq!(run(100000).unwrap().stdout.len(), 70000);
        assert_eq!(run(128).unwrap().stdout.len(), 128);
        assert_eq!(
            run_tool(Path::new("/bin/sh"), &command, Duration::from_secs(2))
                .unwrap()
                .stdout
                .len(),
            65536
        );
        assert!(run(0).is_err());
        assert!(run(4 * 1024 * 1024 + 1).is_err());
    }
    #[test]
    fn tool_failure_and_output() {
        assert!(run_tool(Path::new("/bin/false"), &[], Duration::from_secs(1)).is_err());
        assert_eq!(
            run_tool(
                Path::new("/bin/echo"),
                &["ok".into()],
                Duration::from_secs(1)
            )
            .unwrap()
            .stdout,
            "ok\n"
        );
    }
}
