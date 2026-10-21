//! Bounded owned-code Android operations, distinct from HAL/library inventories.
//! The probe runs as shell; it cannot qualify owner-authenticated keys or panels.
use crate::rro::PinnedFile;
use anyhow::{Context, Result, ensure};
use gb_tools::{Inputs, ReadOnlyInput, Sandbox};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

const SOURCE: &str = include_str!("functional_probe/AndroidFunctionalProbe.java");
const TOOLS: &[&str] = &["android", "java", "javac", "launcher", "security", "r8"];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    pub schema_version: u32,
    pub tools: BTreeMap<String, PinnedFile>,
    pub sandbox: Sandbox,
}
impl BuildRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in r.tools.values_mut() {
            if p.path.is_relative() {
                p.path = parent.join(&p.path);
            }
        }
        r.validate()?;
        Ok(r)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.tools.len() == TOOLS.len()
                && TOOLS.iter().all(|k| self.tools.contains_key(*k)),
            "unexpected functional-probe tools/schema"
        );
        self.sandbox.validate()
    }
}

pub fn build(r: &BuildRequest, destination: &Path) -> Result<serde_json::Value> {
    build_owned_sources(
        r,
        destination,
        &[("AndroidFunctionalProbe.java", SOURCE)],
        Some(2000),
    )
}

/// Compile the shell-owned, explicit-crop scalar probe. This does not contact a device.
pub fn build_guest_display_probe(
    r: &BuildRequest,
    destination: &Path,
) -> Result<serde_json::Value> {
    build_owned_sources(
        r,
        destination,
        &[
            (
                "GuestDisplayProbe.java",
                include_str!("guest_display_probe/GuestDisplayProbe.java"),
            ),
            (
                "PatternContract.java",
                include_str!("guest_display_probe/PatternContract.java"),
            ),
        ],
        Some(2000),
    )
}

/// Compile only repository-owned static sources. Never pass extracted firmware
/// source or binaries here; native SDK tools still run inside the host sandbox.
pub(crate) fn build_owned_sources(
    r: &BuildRequest,
    destination: &Path,
    sources: &[(&'static str, &'static str)],
    required_uid: Option<u32>,
) -> Result<serde_json::Value> {
    r.validate()?;
    ensure!(
        !sources.is_empty() && sources.len() <= 12,
        "owned source count budget"
    );
    let mut source_hashes = BTreeMap::new();
    for (name, text) in sources {
        ensure!(
            name.ends_with(".java")
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.".contains(&b))
                && text.len() <= 65536,
            "owned Java source name/size budget"
        );
        ensure!(
            source_hashes
                .insert(*name, gb_core::digest(text.as_bytes()))
                .is_none(),
            "duplicate source name"
        );
    }
    ensure!(!destination.exists(), "output already exists");
    for p in r.tools.values() {
        p.verify()?;
        gb_core::separate_from_input(&p.path, destination)?;
    }
    let tool = |name: &str| r.tools[name].path.as_path();
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
    let temp = tempfile::Builder::new()
        .prefix(".gb-functional-")
        .tempdir_in(parent)?;
    let source = temp.path().join("source");
    let output = temp.path().join("output");
    fs::create_dir_all(source.join("java-home/conf/security"))?;
    fs::create_dir_all(output.join("classes"))?;
    fs::create_dir(output.join("dex"))?;
    for (name, text) in sources {
        fs::write(source.join(name), text)?;
    }
    fs::copy(
        tool("security"),
        source.join("java-home/conf/security/java.security"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/inputs/java-runtime/lib", source.join("java-home/lib"))?;
    let mut receipts = Vec::new();
    let mut run = |args: &[&str]| -> Result<String> {
        gb_core::checkpoint()?;
        let extras = [
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
            ReadOnlyInput {
                name: "security",
                path: tool("security"),
            },
            ReadOnlyInput {
                name: "r8",
                path: tool("r8"),
            },
        ];
        let receipt = gb_tools::run_mounted(
            &r.sandbox,
            tool("launcher"),
            args.iter().map(|v| (*v).into()).collect(),
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
    let java_version = run(&[
        "/inputs/java-runtime/bin/java",
        "-Djava.home=/inputs/resources/java-home",
        "-Djava.security.properties==/inputs/security",
        "--version",
    ])?;
    let d8_version = run(&[
        "/inputs/java-runtime/bin/java",
        "-Djava.home=/inputs/resources/java-home",
        "-Djava.security.properties==/inputs/security",
        "-cp",
        "/inputs/r8",
        "com.android.tools.r8.D8",
        "--version",
    ])?;
    ensure!(
        [&java_version, &d8_version]
            .iter()
            .all(|s| !s.trim().is_empty() && s.len() < 4096),
        "tool version budget"
    );
    let source_paths: Vec<_> = sources
        .iter()
        .map(|(name, _)| format!("/inputs/resources/{name}"))
        .collect();
    let mut javac_args = vec![
        "/inputs/java-runtime/bin/javac",
        "-J-Djava.home=/inputs/resources/java-home",
        "-J-Djava.security.properties==/inputs/security",
        "-proc:none",
        "-source",
        "8",
        "-target",
        "8",
        "-bootclasspath",
        "/inputs/android.jar",
        "-d",
        "/output/classes",
    ];
    javac_args.extend(source_paths.iter().map(String::as_str));
    run(&javac_args)?;
    crate::terminal_probe::zip_classes(&output.join("classes"), &output.join("classes.jar"))?;
    run(&[
        "/inputs/java-runtime/bin/java",
        "-Djava.home=/inputs/resources/java-home",
        "-Djava.security.properties==/inputs/security",
        "-cp",
        "/inputs/r8",
        "com.android.tools.r8.D8",
        "--release",
        "--min-api",
        "31",
        "--lib",
        "/inputs/android.jar",
        "--output",
        "/output/dex",
        "/output/classes.jar",
    ])?;
    let dex = output.join("dex/classes.dex");
    ensure!(
        fs::symlink_metadata(&dex)?.is_file() && fs::metadata(&dex)?.len() <= 128 * 1024,
        "DEX type/size budget"
    );
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("probe.jar"))?;
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "classes.dex",
        zip::write::SimpleFileOptions::default()
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644),
    )?;
    std::io::copy(&mut fs::File::open(dex)?, &mut zip)?;
    zip.finish()?.sync_all()?;
    for p in r.tools.values() {
        p.verify()?;
    }
    let report = serde_json::json!({"schema_version":1,"status":"built_not_device_verified",
        "source_sha256":gb_core::digest(sources[0].1.as_bytes()),"source_files_sha256":source_hashes,"probe_jar_sha256":gb_core::hash_file(&output.join("probe.jar"))?,
        "tools":r.tools,"tool_versions":{"java":java_version,"d8":d8_version},"commands":receipts,
        "required_uid":required_uid,"runtime_verified":false,"firmware_written":false});
    gb_core::write_json(&output.join("build-report.json"), &report)?;
    gb_core::publish_directory(&output, destination)?;
    Ok(report)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub schema_version: u32,
    pub adb: PinnedFile,
    pub probe: PinnedFile,
    pub build_report: PinnedFile,
    pub serial: String,
    pub fingerprint: String,
    pub android_user: u32,
}
impl RunRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        for p in [&mut r.adb, &mut r.probe, &mut r.build_report] {
            if p.path.is_relative() {
                p.path = path.parent().unwrap_or(Path::new(".")).join(&p.path);
            }
        }
        ensure!(
            r.schema_version == 1
                && !r.serial.is_empty()
                && r.serial.len() <= 64
                && r.serial
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !r.fingerprint.is_empty()
                && r.fingerprint.len() < 512
                && r.android_user <= 32,
            "invalid device identity/schema"
        );
        Ok(r)
    }
}

pub fn parse_response(text: &str) -> Result<serde_json::Value> {
    ensure!(text.len() <= 65536, "probe response budget");
    let lines: Vec<_> = text
        .lines()
        .filter_map(|s| s.strip_prefix("GB_ANDROID_FUNCTIONAL:"))
        .collect();
    ensure!(
        lines.len() == 1,
        "expected exactly one direct probe response"
    );
    let value: serde_json::Value = serde_json::from_str(lines[0])?;
    ensure!(
        value["schema_version"] == 1
            && value["uid"] == 2000
            && value["probe"] == "owned_android_functional_v1"
            && value["full_port_verified"] == false
            && value["user_content_collected"] == false,
        "wrong probe identity/scope"
    );
    for k in ["graphics", "keystore"] {
        ensure!(
            matches!(value[k]["state"].as_str(), Some("compatible" | "unknown")),
            "missing operation verdict"
        );
    }
    Ok(value)
}

pub fn run(r: &RunRequest, destination: &Path) -> Result<serde_json::Value> {
    ensure!(!destination.exists(), "report already exists");
    r.adb.verify()?;
    r.probe.verify()?;
    r.build_report.verify()?;
    let provenance: serde_json::Value = gb_core::read_json(&r.build_report.path, 65536)?;
    ensure!(
        provenance["status"] == "built_not_device_verified"
            && provenance["source_sha256"] == gb_core::digest(SOURCE.as_bytes())
            && provenance["probe_jar_sha256"] == r.probe.sha256,
        "probe build/source provenance mismatch"
    );
    gb_core::separate_from_input(&r.probe.path, destination)?;
    let call = |args: Vec<String>, timeout: u64| -> Result<String> {
        let mut all = vec!["-s".into(), r.serial.clone()];
        all.extend(args);
        let receipt = gb_core::run_tool(&r.adb.path, &all, Duration::from_secs(timeout))?;
        ensure!(
            !receipt.stderr_truncated && receipt.stdout.len() < 65536,
            "truncated ADB receipt"
        );
        Ok(receipt.stdout.trim().to_string())
    };
    let shell = |command: String| call(vec!["shell".into(), command], 15);
    let identity = || -> Result<String> {
        ensure!(
            shell("getprop ro.serialno".into())? == r.serial
                && shell("getprop ro.build.fingerprint".into())? == r.fingerprint
                && shell("id -u".into())? == "2000"
                && shell("getenforce".into())? == "Enforcing"
                && shell("am get-current-user".into())? == r.android_user.to_string(),
            "device identity/SELinux guard"
        );
        let boot = shell("cat /proc/sys/kernel/random/boot_id".into())?;
        ensure!(
            boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid boot identity"
        );
        Ok(boot)
    };
    let boot = identity()?;
    let nonce = gb_core::digest(
        format!(
            "{}:{}:{}",
            boot,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        )
        .as_bytes(),
    );
    let run_id = &nonce[..32];
    let remote = format!("/data/local/tmp/gb-functional-{run_id}.jar");
    let command = |mode: &str| {
        format!(
            "CLASSPATH={remote} timeout -s KILL 45 /system/bin/app_process64 /system/bin org.googlebook.port.functional.AndroidFunctionalProbe {mode} {run_id}"
        )
    };
    ensure!(
        shell(format!("if test -e {remote}; then echo exists; fi"))?.is_empty(),
        "remote output exists"
    );
    // Persist the owned namespace before execution so interrupted runs can be cleaned up.
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let context_path = destination.with_extension("context.json");
    ensure!(!context_path.exists(), "invocation context already exists");
    gb_core::write_json(
        &context_path,
        &serde_json::json!({"run_id":run_id,"remote":remote,"serial":r.serial,"boot_id":boot,
            "probe_sha256":r.probe.sha256,"local_probe":r.probe.path,
            "cleanup_command":command("cleanup"),"restage_verified_jar_if_remote_absent":true}),
    )?;
    call(
        vec![
            "push".into(),
            r.probe.path.to_string_lossy().into_owned(),
            remote.clone(),
        ],
        30,
    )?;
    let mut verified_on_device = false;
    let attempt = (|| -> Result<serde_json::Value> {
        shell(format!("chmod 0400 {remote}"))?;
        ensure!(
            shell(format!("sha256sum {remote}"))?
                .split_whitespace()
                .next()
                == Some(r.probe.sha256.as_str()),
            "device JAR hash mismatch"
        );
        verified_on_device = true;
        parse_response(&call(vec!["shell".into(), command("run")], 55)?)
    })();
    // Even the cleanup entry point must never execute a corrupt/unverified JAR.
    let cleanup = if verified_on_device {
        call(vec!["shell".into(), command("cleanup")], 55)
    } else {
        Err(anyhow::anyhow!(
            "cleanup execution skipped: device JAR not verified"
        ))
    };
    let removed = shell(format!("rm -- {remote} && test ! -e {remote}"));
    let after = identity();
    let cleanup_verified = cleanup.as_ref().is_ok_and(|s| {
        s.lines()
            .any(|l| l == format!("GB_ANDROID_FUNCTIONAL_CLEANUP:{run_id}"))
    }) && removed.is_ok();
    let operations = attempt.as_ref().ok();
    let passed = cleanup_verified
        && after.as_ref().is_ok_and(|s| s == &boot)
        && operations.is_some_and(|v| {
            v["graphics"]["state"] == "compatible" && v["keystore"]["state"] == "compatible"
        });
    let report = serde_json::json!({"schema_version":1,"status":if passed {"bounded_operations_passed"} else {"needs_diagnosis"},
        "serial":r.serial,"boot_id":boot,"run_id":run_id,"host_boot_unchanged":after.as_ref().is_ok_and(|s|s==&boot),
        "probe_jar_sha256":r.probe.sha256,"operations":operations,"cleanup_verified":cleanup_verified,
        "execution_error":attempt.err().map(|e|e.to_string()),"full_port_verified":false,"firmware_written":false,
        "scope":"Shell UID only; Android pbuffer graphics and fresh unauthed keystore keys, not guest GPU/panel or owner attestation"});
    gb_core::write_json(destination, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_unique_direct_typed_response_not_command_echo() {
        let good = r#"GB_ANDROID_FUNCTIONAL:{"schema_version":1,"probe":"owned_android_functional_v1","uid":2000,"full_port_verified":false,"user_content_collected":false,"graphics":{"state":"compatible"},"keystore":{"state":"unknown"}}"#;
        assert!(parse_response(good).is_ok());
        assert!(parse_response(&format!("echo {good}")).is_err());
        assert!(parse_response(&format!("{good}\n{good}")).is_err());
        assert!(parse_response(&good.replace("2000", "1000")).is_err());
        assert!(parse_response(&good.replace("unknown", "made_up_success")).is_err());
        assert!(parse_response(&"x".repeat(65537)).is_err());
    }
}
