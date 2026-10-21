//! Owner development instrumentation, separately signed from the original Terminal APK.
//! Building does not install, change firmware, or imply a working Terminal VM.
use crate::rro::PinnedFile;
use anyhow::{Context, Result, ensure};
use gb_core::{checkpoint, digest, hash_file, publish_directory, write_json};
use gb_tools::{Inputs, ReadOnlyInput, Sandbox};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const RECEIVER: &str = include_str!("terminal_probe/PayloadReceiver.java");
const PROBE: &str = include_str!("terminal_probe/TerminalProbe.java");
const RUNTIME_INSPECTION: &str = include_str!("terminal_probe/RuntimeInspection.java");
const CONSOLE_INSPECTION: &str = include_str!("terminal_probe/ConsoleInspection.java");
const STARTUP_OBSERVATION: &str = include_str!("terminal_probe/StartupObservation.java");
const IMMUTABLE_BOOT_CONFIG: &str = include_str!("terminal_probe/ImmutableBootConfig.java");
const CACHE_ADVISOR: &str = include_str!("terminal_probe/CacheAdvisor.java");
const CACHE_TEST: &str = include_str!("terminal_probe/CacheAdvisorTest.java");
const TOOLS: &[&str] = &[
    "android",
    "aapt2",
    "java",
    "javac",
    "launcher",
    "security",
    "r8",
    "apksigner",
    "zipalign",
    "key",
    "certificate",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestMode {
    #[default]
    DiagnosticShell,
    NormalConsole,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeAction {
    #[default]
    StageGuest,
    /// Read fixed process/VMM metadata, then exit before app-private storage.
    InspectRuntime,
    /// Exercise the installed AVF PTY JNI under the target UID without a VM or CE files.
    InspectConsole,
    /// Bounded diagnostic: launch the original app with an already staged profile.
    ObserveStartup,
    /// Use identical, pinned boot files from read-only system_ext with the existing guest disks.
    ObserveImmutableStartup,
    /// Observe the original default app launch, requiring its normal VM config and memory cap.
    ObserveDefaultStartup,
    /// Restore the default ttyd console after an owner diagnostic selected raw serial.
    /// Changes one preference only; never starts a guest or imports payloads.
    RestoreDefaultConsole,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub android_user: u32,
    pub donor_fingerprint: String,
    pub memory_mib: u32,
    pub port: u16,
    pub payloads: BTreeMap<String, Payload>,
    #[serde(default)]
    pub guest_mode: GuestMode,
    #[serde(default)]
    pub action: ProbeAction,
    /// A new attempt retains any failed unpublished staging directory.
    #[serde(default)]
    pub staging_attempt: u16,
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 64
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid profile ID"
        );
        ensure!(
            self.android_user < 1000
                && (64..=2048).contains(&self.memory_mib)
                && self.port >= 1024
                && self.staging_attempt <= 999,
            "invalid profile bounds"
        );
        ensure!(
            !self.donor_fingerprint.is_empty()
                && self.donor_fingerprint.len() <= 512
                && !self.donor_fingerprint.chars().any(char::is_control),
            "invalid fingerprint"
        );
        ensure!(
            self.payloads
                .keys()
                .map(String::as_str)
                .eq(["initrd", "instance", "kernel", "rootfs"]),
            "exactly four fixed payload IDs required"
        );
        for payload in self.payloads.values() {
            ensure!(
                (1..=4 * 1024 * 1024 * 1024).contains(&payload.bytes)
                    && payload.sha256.len() == 64
                    && payload
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid payload size/checksum"
            );
        }
        if self.action == ProbeAction::ObserveImmutableStartup {
            for id in ["kernel", "initrd"] {
                ensure!(
                    self.payloads.get(id).context("missing boot payload")?.bytes
                        <= 64 * 1024 * 1024,
                    "immutable boot inspection supports kernel/initrd up to 64 MiB each"
                );
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub manifest: Manifest,
    pub tools: BTreeMap<String, PinnedFile>,
    #[serde(default)]
    pub cache_advisor: Option<PinnedFile>,
    pub sandbox: Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for f in r.tools.values_mut() {
            if f.path.is_relative() {
                f.path = parent.join(&f.path);
            }
        }
        if let Some(f) = &mut r.cache_advisor
            && f.path.is_relative()
        {
            f.path = parent.join(&f.path);
        }
        r.validate()?;
        Ok(r)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.tools.len() == TOOLS.len()
                && TOOLS.iter().all(|k| self.tools.contains_key(*k)),
            "unexpected probe schema/tools"
        );
        self.manifest.validate()?;
        self.sandbox.validate()
    }
}
pub(crate) fn zip_classes(root: &Path, path: &Path) -> Result<()> {
    fn collect(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for item in fs::read_dir(dir)? {
            let p = item?.path();
            let kind = fs::symlink_metadata(&p)?.file_type();
            if kind.is_dir() {
                collect(root, &p, files)?;
            } else {
                ensure!(
                    kind.is_file() && p.extension().is_some_and(|e| e == "class"),
                    "unexpected compiler output"
                );
                files.push(p.strip_prefix(root)?.to_path_buf());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();
    ensure!(
        !files.is_empty() && files.len() < 64,
        "invalid class inventory"
    );
    let mut writer = zip::ZipWriter::new(fs::File::create(path)?);
    for file in files {
        writer.start_file(
            file.to_str().context("class path encoding")?,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )?;
        std::io::copy(&mut fs::File::open(root.join(file))?, &mut writer)?;
    }
    writer.finish()?.sync_all()?;
    Ok(())
}
pub fn build(r: &Request, destination: &Path) -> Result<serde_json::Value> {
    r.validate()?;
    ensure!(!destination.exists(), "probe output exists");
    for f in r.tools.values() {
        f.verify()?;
        gb_core::separate_from_input(&f.path, destination)?;
    }
    if let Some(native) = &r.cache_advisor {
        ensure!(
            (64..=2 * 1024 * 1024).contains(&fs::metadata(&native.path)?.len()),
            "native advisor size"
        );
        native.verify()?;
        gb_core::separate_from_input(&native.path, destination)?;
        let mut header = [0; 20];
        fs::File::open(&native.path)?.read_exact(&mut header)?;
        ensure!(
            &header[..6] == b"\x7fELF\x02\x01"
                && [2, 3].contains(&u16::from_le_bytes([header[16], header[17]]))
                && u16::from_le_bytes([header[18], header[19]]) == 183,
            "native advisor must be a pinned owner-built ARM64 ELF"
        );
    }
    let tool = |name: &str| -> &Path { &r.tools[name].path };
    let java = tool("java").canonicalize()?;
    let runtime = java.parent().and_then(Path::parent).context("JDK layout")?;
    ensure!(
        runtime.join("bin/java") == java
            && runtime.join("bin/javac").canonicalize()? == tool("javac").canonicalize()?
            && runtime.join("lib/libjava.so").is_file(),
        "use one complete JDK"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = tempfile::Builder::new()
        .prefix(".gb-terminal-probe-")
        .tempdir_in(parent)?;
    let source = tmp.path().join("source");
    let output = tmp.path().join("output");
    fs::create_dir_all(source.join("assets"))?;
    fs::create_dir_all(source.join("java-home/conf/security"))?;
    fs::create_dir_all(output.join("classes"))?;
    fs::create_dir(output.join("dex"))?;
    fs::write(source.join("PayloadReceiver.java"), RECEIVER)?;
    fs::write(source.join("TerminalProbe.java"), PROBE)?;
    fs::write(source.join("RuntimeInspection.java"), RUNTIME_INSPECTION)?;
    fs::write(source.join("ConsoleInspection.java"), CONSOLE_INSPECTION)?;
    fs::write(source.join("StartupObservation.java"), STARTUP_OBSERVATION)?;
    fs::write(
        source.join("ImmutableBootConfig.java"),
        IMMUTABLE_BOOT_CONFIG,
    )?;
    fs::write(source.join("CacheAdvisor.java"), CACHE_ADVISOR)?;
    fs::write(source.join("CacheAdvisorTest.java"), CACHE_TEST)?;
    fs::copy(
        tool("security"),
        source.join("java-home/conf/security/java.security"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/inputs/java-runtime/lib", source.join("java-home/lib"))?;
    let mut manifest = serde_json::to_value(&r.manifest)?;
    if let Some(native) = &r.cache_advisor {
        manifest["cache_advisor_sha256"] = native.sha256.clone().into();
    }
    write_json(&source.join("assets/payload-manifest.json"), &manifest)?;
    fs::write(
        source.join("AndroidManifest.xml"),
        r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.googlebook.port.terminalprobe" android:versionCode="1"><uses-sdk android:minSdkVersion="28" android:targetSdkVersion="37"/><uses-permission android:name="android.permission.INTERNET"/><application android:label="Googlebook owner VM diagnostics" android:testOnly="true" android:hasCode="true" android:allowBackup="false" android:extractNativeLibs="true" android:defaultToDeviceProtectedStorage="true"><receiver android:name=".CacheAdvisorTest" android:exported="true" android:directBootAware="true" android:permission="android.permission.DUMP"/></application><instrumentation android:name=".TerminalProbe" android:targetPackage="com.android.virtualization.terminal" android:functionalTest="true"/></manifest>"#,
    )?;
    let mut receipts = Vec::new();
    let mut run = |name: &str, args: &[&str], signing: bool| -> Result<String> {
        checkpoint()?;
        let mut extras = vec![
            ReadOnlyInput {
                name: "android.jar",
                path: tool("android"),
            },
            ReadOnlyInput {
                name: "resources",
                path: &source,
            },
            ReadOnlyInput {
                name: "java-runtime",
                path: runtime,
            },
        ];
        for k in ["security", "r8", "apksigner"] {
            extras.push(ReadOnlyInput {
                name: k,
                path: tool(k),
            });
        }
        if signing {
            for k in ["key", "certificate"] {
                extras.push(ReadOnlyInput {
                    name: k,
                    path: tool(k),
                });
            }
        }
        let receipt = gb_tools::run_mounted(
            &r.sandbox,
            tool(name),
            args.iter().map(|s| s.to_string()).collect(),
            Inputs {
                primary: tool("android"),
                extra: &extras,
                source_date_epoch: Some(0),
            },
            &output,
            Duration::from_secs(120),
        )?;
        ensure!(
            !receipt.stderr_truncated && receipt.stdout.len() < 65536,
            "truncated tool receipt"
        );
        let stdout = receipt.stdout.clone();
        receipts.push(receipt);
        Ok(stdout)
    };
    run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/javac",
            "-J-Djava.home=/inputs/resources/java-home",
            "-J-Djava.security.properties==/inputs/security",
            "-proc:none",
            "-source",
            "8",
            "-target",
            "8",
            "-bootclasspath",
            "/input.img",
            "-d",
            "/output/classes",
            "/inputs/resources/PayloadReceiver.java",
            "/inputs/resources/TerminalProbe.java",
            "/inputs/resources/RuntimeInspection.java",
            "/inputs/resources/ConsoleInspection.java",
            "/inputs/resources/StartupObservation.java",
            "/inputs/resources/ImmutableBootConfig.java",
            "/inputs/resources/CacheAdvisor.java",
            "/inputs/resources/CacheAdvisorTest.java",
        ],
        false,
    )?;
    zip_classes(&output.join("classes"), &output.join("classes.jar"))?;
    run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-cp",
            "/inputs/r8",
            "com.android.tools.r8.D8",
            "--release",
            "--min-api",
            "28",
            "--lib",
            "/inputs/android.jar",
            "--output",
            "/output/dex",
            "/output/classes.jar",
        ],
        false,
    )?;
    run(
        "aapt2",
        &[
            "link",
            "-I",
            "/input.img",
            "--manifest",
            "/inputs/resources/AndroidManifest.xml",
            "-A",
            "/inputs/resources/assets",
            "-o",
            "/output/unsigned.apk",
        ],
        false,
    )?;
    let dex = output.join("dex/classes.dex");
    ensure!(
        fs::metadata(&dex)?.len() <= 1024 * 1024,
        "unexpected DEX size"
    );
    let mut apk = zip::ZipWriter::new_append(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(output.join("unsigned.apk"))?,
    )?;
    apk.start_file(
        "classes.dex",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    std::io::copy(&mut fs::File::open(dex)?, &mut apk)?;
    if let Some(native) = &r.cache_advisor {
        apk.start_file(
            "lib/arm64-v8a/libgb_cache_advisor.so",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755),
        )?;
        std::io::copy(&mut fs::File::open(&native.path)?, &mut apk)?;
    }
    apk.finish()?.sync_all()?;
    run(
        "zipalign",
        &["-f", "4", "/output/unsigned.apk", "/output/aligned.apk"],
        false,
    )?;
    run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-jar",
            "/inputs/apksigner",
            "sign",
            "--key",
            "/inputs/key",
            "--cert",
            "/inputs/certificate",
            "--v1-signing-enabled",
            "false",
            "--v2-signing-enabled",
            "true",
            "--v3-signing-enabled",
            "false",
            "--v4-signing-enabled",
            "false",
            "--out",
            "/output/terminal-probe.apk",
            "/output/aligned.apk",
        ],
        true,
    )?;
    let verification = run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-jar",
            "/inputs/apksigner",
            "verify",
            "--verbose",
            "--print-certs",
            "/output/terminal-probe.apk",
        ],
        false,
    )?;
    ensure!(
        verification.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "signature verification failed"
    );
    for f in r.tools.values() {
        f.verify()?;
    }
    if let Some(native) = &r.cache_advisor {
        native.verify()?;
    }
    let report = serde_json::json!({"schema_version":1, "status":"owner_development_instrumentation_built", "apk_sha256":hash_file(&output.join("terminal-probe.apk"))?, "request":r, "receiver_source_sha256":digest(RECEIVER.as_bytes()), "probe_source_sha256":digest(PROBE.as_bytes()), "runtime_inspection_source_sha256":digest(RUNTIME_INSPECTION.as_bytes()), "console_inspection_source_sha256":digest(CONSOLE_INSPECTION.as_bytes()), "startup_observation_source_sha256":digest(STARTUP_OBSERVATION.as_bytes()), "immutable_boot_config_source_sha256":digest(IMMUTABLE_BOOT_CONFIG.as_bytes()), "cache_advisor_source_sha256":digest(CACHE_ADVISOR.as_bytes()), "cache_test_source_sha256":digest(CACHE_TEST.as_bytes()), "commands":receipts, "signature_verification":verification, "java_identity":gb_tools::identity(&java,&r.sandbox)?, "runtime_verified":false, "requires_debug_build_and_root_instrumentation_caller":true, "original_terminal_apk_modified":false});
    for file in ["unsigned.apk", "aligned.apk", "classes.jar"] {
        fs::remove_file(output.join(file))?;
    }
    for dir in ["classes", "dex"] {
        fs::remove_dir_all(output.join(dir))?;
    }
    write_json(&output.join("probe-report.json"), &report)?;
    checkpoint()?;
    publish_directory(&output, destination)?;
    Ok(report)
}

/// Send a fixed payload to an explicitly established localhost ADB forward.
/// This never selects a device or creates an ADB forward itself.
pub fn send_payload(port: u16, id: &str, path: &Path, expected: &Payload) -> Result<String> {
    ensure!(
        ["kernel", "initrd", "rootfs", "instance"].contains(&id),
        "invalid payload ID"
    );
    ensure!(
        port >= 1024
            && fs::symlink_metadata(path)?.is_file()
            && fs::metadata(path)?.len() == expected.bytes
            && hash_file(path)? == expected.sha256,
        "payload identity differs"
    );
    let mut socket = TcpStream::connect_timeout(
        &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
        Duration::from_secs(5),
    )?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.write_all(b"GBPF1\n")?;
    socket.write_all(&[id.len() as u8])?;
    socket.write_all(id.as_bytes())?;
    socket.write_all(&expected.bytes.to_be_bytes())?;
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut file = fs::File::open(path)?;
    let mut left = expected.bytes;
    let mut buffer = vec![0; 1024 * 1024];
    while left > 0 {
        checkpoint()?;
        let count = usize::try_from(left.min(buffer.len() as u64))?;
        file.read_exact(&mut buffer[..count])?;
        let mut sent = 0;
        while sent < count {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .context("total payload transfer deadline")?;
            socket.set_write_timeout(Some(remaining.min(Duration::from_secs(30))))?;
            let n = socket.write(&buffer[sent..count])?;
            ensure!(n > 0, "receiver closed during transfer");
            sent += n;
        }
        left -= count as u64;
    }
    socket.write_all(b"GBEND\n")?;
    socket.flush()?;
    let mut length = [0; 2];
    socket.read_exact(&mut length)?;
    let size = u16::from_be_bytes(length) as usize;
    ensure!(size <= 128, "oversized receiver response");
    let mut ack = vec![0; size];
    socket.read_exact(&mut ack)?;
    let ack = String::from_utf8(ack)?;
    ensure!(
        ack == format!("OK {id} {}", expected.sha256),
        "receiver did not verify payload"
    );
    Ok(ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn probe_actions_preserve_legacy_staging_and_reject_unknown_operations() {
        let mut value = serde_json::json!({
            "id":"owned-diagnostic", "android_user":11,
            "donor_fingerprint":"donor/device:17/build", "memory_mib":512,
            "port":38601, "payloads":{}
        });
        let old: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(old.action, ProbeAction::StageGuest);
        assert_eq!(old.staging_attempt, 0);
        value["action"] = "inspect_runtime".into();
        let read_only: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(read_only.action, ProbeAction::InspectRuntime);
        value["action"] = "inspect_console".into();
        let console: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(console.action, ProbeAction::InspectConsole);
        value["action"] = "observe_startup".into();
        let observer: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(observer.action, ProbeAction::ObserveStartup);
        value["action"] = "observe_immutable_startup".into();
        let immutable: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(immutable.action, ProbeAction::ObserveImmutableStartup);
        value["action"] = "observe_default_startup".into();
        let normal: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(normal.action, ProbeAction::ObserveDefaultStartup);
        value["action"] = "restore_default_console".into();
        let restored: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(restored.action, ProbeAction::RestoreDefaultConsole);
        value["action"] = "inspect_and_stage".into();
        assert!(serde_json::from_value::<Manifest>(value).is_err());
    }
    #[test]
    fn manifest_rejects_paths_and_missing_payloads() {
        let mut m = Manifest {
            id: "../x".into(),
            android_user: 11,
            donor_fingerprint: "donor/device:17/build".into(),
            memory_mib: 512,
            guest_mode: GuestMode::DiagnosticShell,
            action: ProbeAction::StageGuest,
            staging_attempt: 0,
            port: 38601,
            payloads: ["kernel", "initrd", "rootfs", "instance"]
                .into_iter()
                .map(|id| {
                    (
                        id.into(),
                        Payload {
                            bytes: 1,
                            sha256: "a".repeat(64),
                        },
                    )
                })
                .collect(),
        };
        assert!(m.validate().is_err());
        m.id = "owned-diagnostic".into();
        m.validate().unwrap();
        m.staging_attempt = 999;
        m.validate().unwrap();
        m.staging_attempt = 1000;
        assert!(m.validate().is_err());
        m.staging_attempt = 0;
        m.action = ProbeAction::ObserveImmutableStartup;
        for id in ["kernel", "initrd"] {
            m.payloads.get_mut(id).unwrap().bytes = 64 * 1024 * 1024;
            m.validate().unwrap();
            m.payloads.get_mut(id).unwrap().bytes += 1;
            assert!(m.validate().is_err());
            m.payloads.get_mut(id).unwrap().bytes = 1;
        }
        m.payloads.remove("instance");
        assert!(m.validate().is_err());
    }
    #[test]
    fn sender_rejects_changed_source_before_connection() -> Result<()> {
        let t = tempfile::tempdir()?;
        let f = t.path().join("payload");
        fs::write(&f, b"a")?;
        assert!(
            send_payload(
                38601,
                "kernel",
                &f,
                &Payload {
                    bytes: 1,
                    sha256: "a".repeat(64)
                }
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn native_advisor_wrong_architecture_is_rejected_before_build_tools() -> Result<()> {
        let t = tempfile::tempdir()?;
        let dummy = t.path().join("pinned");
        fs::write(&dummy, b"trusted fixture")?;
        let input = PinnedFile {
            path: dummy,
            sha256: digest(b"trusted fixture"),
        };
        let native = t.path().join("wrong-architecture");
        let mut bytes = [0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16] = 3;
        bytes[18] = 40;
        fs::write(&native, bytes)?;
        let r = Request {
            schema_version: 1,
            manifest: Manifest {
                id: "fixture".into(),
                android_user: 11,
                donor_fingerprint: "fixture".into(),
                memory_mib: 512,
                port: 38601,
                guest_mode: GuestMode::DiagnosticShell,
                action: ProbeAction::StageGuest,
                staging_attempt: 0,
                payloads: ["kernel", "initrd", "instance", "rootfs"]
                    .into_iter()
                    .map(|id| {
                        (
                            id.into(),
                            Payload {
                                bytes: 1,
                                sha256: "a".repeat(64),
                            },
                        )
                    })
                    .collect(),
            },
            tools: TOOLS
                .iter()
                .map(|name| (name.to_string(), input.clone()))
                .collect(),
            cache_advisor: Some(PinnedFile {
                path: native.clone(),
                sha256: hash_file(&native)?,
            }),
            sandbox: Sandbox::Bubblewrap,
        };
        let output = t.path().join("output");
        assert!(
            build(&r, &output)
                .unwrap_err()
                .to_string()
                .contains("ARM64 ELF")
        );
        assert!(!output.exists());
        Ok(())
    }
}
