//! Build the bounded host for a verified owner-stock Qualcomm framework service.
//! Publication is offline; domain/IPC policy and actual client operations remain gates.
use crate::rro::PinnedFile;
use anyhow::{Context, Result, ensure};
use gb_tools::{Inputs, ReadOnlyInput, Sandbox};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, time::Duration};

const SOURCE: &str = include_str!("service_host/QesdSysHost.java");
const TOOLS: &[&str] = &[
    "android",
    "java",
    "javac",
    "launcher",
    "security",
    "r8",
    "apksigner",
];
const APK_SHA: &str = "e7de3d389b3a04b7cba5ae7007cc3e7e30091e9d5e17573e171039e5165570a8";
const CERT_SHA: &str = "564ad1edeb43af8005176c0011a6f964db8d83be49715ab8a74bd5c2130c3cdb";
const RUNTIME_SHA: &str = "268e91f7c10a63f5823510b169066526cbdef00253f1214c063634c5067583d8";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub stock_apk: PinnedFile,
    pub service_contexts: PinnedFile,
    pub android_runtime: PinnedFile,
    pub tools: BTreeMap<String, PinnedFile>,
    pub sandbox: Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = gb_core::read_json(path, 65536)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in r.tools.values_mut().chain([
            &mut r.stock_apk,
            &mut r.service_contexts,
            &mut r.android_runtime,
        ]) {
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
                && self.stock_apk.sha256 == APK_SHA
                && self.android_runtime.sha256 == RUNTIME_SHA,
            "only the inspected TB710FU IQesdSys v4 stock APK is supported"
        );
        ensure!(
            self.tools.len() == TOOLS.len() && TOOLS.iter().all(|k| self.tools.contains_key(*k)),
            "unexpected service-host tools"
        );
        self.sandbox.validate()
    }
}
fn verify_signer(text: &str) -> Result<()> {
    ensure!(
        text.lines()
            .any(|l| l == "Verified using v3 scheme (APK Signature Scheme v3): true"),
        "stock APK v3 signature not verified"
    );
    ensure!(
        text.lines().any(|l| l == "Number of signers: 1"),
        "expected exactly one signer"
    );
    let certificates: Vec<_> = text
        .lines()
        .filter(|l| l.contains("Signer: certificate SHA-256 digest:"))
        .collect();
    ensure!(
        certificates.len() == 1 && certificates[0].ends_with(CERT_SHA),
        "unexpected stock APK signer"
    );
    Ok(())
}
fn map_context(input: &str) -> Result<String> {
    ensure!(
        input.len() <= 128 * 1024 && !input.contains('\0'),
        "context map budget/type"
    );
    let selector = "vendor.qti.qesdsys.IQesdSys/default";
    let old = "u:object_r:vendor_qesdk_service:s0";
    let mut count = 0;
    let mut output = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(selector) {
            ensure!(
                fields.next() == Some(old) && fields.next().is_none(),
                "unexpected QesdSys context rule"
            );
            count += 1;
            output.push_str(&line.replace(old, "u:object_r:gb_qesdsys_service:s0"));
        } else {
            output.push_str(line);
        }
    }
    ensure!(
        count == 1,
        "expected exactly one original QesdSys context selector"
    );
    Ok(output)
}
fn private_runtime(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    ensure!(
        input.len() >= 64
            && input.len() <= 16 * 1024 * 1024
            && &input[..6] == b"\x7fELF\x02\x01"
            && u16::from_le_bytes([input[16], input[17]]) == 3
            && u16::from_le_bytes([input[18], input[19]]) == 183,
        "runtime must be a bounded ARM64 shared ELF"
    );
    let original = b"dalvik.vm.usejit\0";
    let replacement = b"dalvik.vm.gbjit\0\0";
    let offsets: Vec<_> = input
        .windows(original.len())
        .enumerate()
        .filter_map(|(i, b)| (b == original).then_some(i))
        .collect();
    ensure!(
        offsets.len() == 1 && original.len() == replacement.len(),
        "runtime property lookup is not unique or same-sized"
    );
    let offset = offsets[0];
    let mut output = input.to_vec();
    output[offset..offset + original.len()].copy_from_slice(replacement);
    Ok((output, offset))
}
pub fn build(r: &Request, destination: &Path) -> Result<serde_json::Value> {
    r.validate()?;
    ensure!(!destination.exists(), "service-host output exists");
    for p in r
        .tools
        .values()
        .chain([&r.stock_apk, &r.service_contexts, &r.android_runtime])
    {
        p.verify()?;
        gb_core::separate_from_input(&p.path, destination)?;
    }
    ensure!(
        fs::metadata(&r.stock_apk.path)?.len() <= 1024 * 1024,
        "stock APK inspection budget"
    );
    ensure!(
        fs::metadata(&r.service_contexts.path)?.len() <= 128 * 1024,
        "context map budget"
    );
    let service_contexts = map_context(&fs::read_to_string(&r.service_contexts.path)?)?;
    ensure!(
        fs::metadata(&r.android_runtime.path)?.len() <= 16 * 1024 * 1024,
        "runtime size budget"
    );
    let (runtime_copy, runtime_offset) = private_runtime(&fs::read(&r.android_runtime.path)?)?;
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
        .prefix(".gb-service-host-")
        .tempdir_in(parent)?;
    let source = temp.path().join("source");
    let output = temp.path().join("output");
    fs::create_dir_all(source.join("java-home/conf/security"))?;
    fs::create_dir_all(output.join("classes"))?;
    fs::create_dir(output.join("dex"))?;
    fs::write(output.join("system_ext_service_contexts"), service_contexts)?;
    fs::write(output.join("libandroid_runtime.so"), runtime_copy)?;
    fs::write(source.join("QesdSysHost.java"), SOURCE)?;
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
            ReadOnlyInput {
                name: "apksigner",
                path: tool("apksigner"),
            },
            ReadOnlyInput {
                name: "stock.apk",
                path: &r.stock_apk.path,
            },
        ];
        let result = gb_tools::run_mounted(
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
            !result.stderr_truncated && result.stdout.len() < 65536,
            "truncated host build receipt"
        );
        let stdout = result.stdout.clone();
        receipts.push(result);
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
    let apksigner_version = run(&[
        "/inputs/java-runtime/bin/java",
        "-Djava.home=/inputs/resources/java-home",
        "-Djava.security.properties==/inputs/security",
        "-jar",
        "/inputs/apksigner",
        "version",
    ])?;
    ensure!(
        [&java_version, &d8_version, &apksigner_version]
            .iter()
            .all(|v| !v.trim().is_empty() && v.len() < 4096),
        "missing or oversized tool version"
    );
    let signature = run(&[
        "/inputs/java-runtime/bin/java",
        "-Djava.home=/inputs/resources/java-home",
        "-Djava.security.properties==/inputs/security",
        "-jar",
        "/inputs/apksigner",
        "verify",
        "--verbose",
        "--print-certs",
        "/inputs/stock.apk",
    ])?;
    verify_signer(&signature)?;
    run(&[
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
        "/inputs/resources/QesdSysHost.java",
    ])?;
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
        fs::symlink_metadata(&dex)?.is_file() && fs::metadata(&dex)?.len() <= 65536,
        "host dex budget/type"
    );
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("host.jar"))?;
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "classes.dex",
        zip::write::SimpleFileOptions::default()
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644),
    )?;
    std::io::copy(&mut fs::File::open(dex)?, &mut zip)?;
    zip.finish()?.sync_all()?;
    for p in r
        .tools
        .values()
        .chain([&r.stock_apk, &r.service_contexts, &r.android_runtime])
    {
        p.verify()?;
    }
    let report = serde_json::json!({"schema_version":1,"status":"host_built_runtime_gates_pending", "adapter":"tb710fu_qesdsys_v4",
        "stock_apk_sha256":APK_SHA,"stock_apk_signer_sha256":CERT_SHA,"stock_apk_v3_verified":true,
        "stock_apk_changed":false,"apk_installed":false,"apk_resigned":false,"source_sha256":gb_core::digest(SOURCE.as_bytes()),
        "service_contexts_original_sha256":r.service_contexts.sha256,
        "service_contexts_output_sha256":gb_core::hash_file(&output.join("system_ext_service_contexts"))?,
        "context_override_scope":"IQesdSys/default only; typed provider migration; original vendor neverallow unchanged",
        "private_runtime":{"source_sha256":RUNTIME_SHA,"output_sha256":gb_core::hash_file(&output.join("libandroid_runtime.so"))?,
            "property_offset":runtime_offset,"original_property":"dalvik.vm.usejit","private_property":"dalvik.vm.gbjit",
            "same_length_literal_only":true,"global_runtime_replaced":false,"global_property_modified":false,"runtime_flag_precedence_verified":false},
        "host_jar_sha256":gb_core::hash_file(&output.join("host.jar"))?,"required_uid":1000,"required_selinux_domain":"gb_qesdsys",
        "required_interface_version":4,"runtime_verified":false,"client_operations_verified":false,
        "tools":r.tools,"tool_versions":{"java":java_version,"d8":d8_version,"apksigner":apksigner_version},
        "commands":receipts,"pending":["device policy/link validation","init/VINTF integration","physical service creation","real client operations"]});
    gb_core::write_json(&output.join("host-report.json"), &report)?;
    gb_core::checkpoint()?;
    gb_core::publish_directory(&output, destination)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_patch_preserves_every_other_byte_and_refuses_wrong_arch_or_ambiguous_literals() {
        let mut input = vec![0; 128];
        input[..6].copy_from_slice(b"\x7fELF\x02\x01");
        input[16] = 3;
        input[18] = 183;
        input.extend_from_slice(b"dalvik.vm.usejit\0");
        input.extend_from_slice(b"untouched trailer");
        let (out, offset) = private_runtime(&input).unwrap();
        assert_eq!(offset, 128);
        assert_eq!(input.len(), out.len());
        assert_eq!(&input[..offset], &out[..offset]);
        assert_eq!(&input[offset + 17..], &out[offset + 17..]);
        assert_eq!(&out[offset..offset + 17], b"dalvik.vm.gbjit\0\0");
        assert!(private_runtime(&input[..50]).is_err());
        let mut wrong = input.clone();
        wrong[18] = 62;
        assert!(private_runtime(&wrong).is_err());
        let mut duplicate = input;
        duplicate.extend_from_slice(b"dalvik.vm.usejit\0");
        assert!(private_runtime(&duplicate).is_err());
    }
    #[test]
    fn changes_only_one_known_interface_label_and_refuses_ambiguous_or_foreign_maps() {
        let rule = "vendor.qti.qesdsys.IQesdSys/default     u:object_r:vendor_qesdk_service:s0\n";
        let original = format!(
            "# retained comment\n{rule}unrelated/default u:object_r:unrelated_service:s0\n"
        );
        assert_eq!(
            map_context(&original).unwrap(),
            original.replace(
                "u:object_r:vendor_qesdk_service:s0",
                "u:object_r:gb_qesdsys_service:s0"
            )
        );
        assert!(map_context(&(rule.to_owned() + rule)).is_err());
        assert!(map_context("unrelated/default u:object_r:unrelated_service:s0\n").is_err());
        assert!(map_context(&rule.replace("vendor_qesdk_service", "foreign_service")).is_err());
        assert!(map_context(&(rule.trim_end().to_owned() + " extra\n")).is_err());
    }
    #[test]
    fn refuses_unverified_multiple_or_wrong_signers() {
        let valid = format!(
            "Verified using v3 scheme (APK Signature Scheme v3): true\nNumber of signers: 1\nV3.0 Signer: certificate SHA-256 digest: {CERT_SHA}\n"
        );
        assert!(verify_signer(&valid).is_ok());
        assert!(verify_signer(&valid.replace(": true", ": false")).is_err());
        assert!(verify_signer(&valid.replace("signers: 1", "signers: 2")).is_err());
        assert!(verify_signer(&valid.replace(CERT_SHA, &"0".repeat(64))).is_err());
        assert!(verify_signer(&(valid.clone() + &valid)).is_err());
    }
}
