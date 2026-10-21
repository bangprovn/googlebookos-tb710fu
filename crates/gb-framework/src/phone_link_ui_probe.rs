//! Owned native Phone Link fixed-label observations, never discovery proof.
use crate::{functional_probe, hardware_probe::BuildRequest};
use anyhow::{Context, Result, ensure};
use gb_tools::{Inputs, ReadOnlyInput};
use std::{fs, path::Path, time::Duration};
mod record;
pub use record::{
    PhoneLinkUiCounts, PhoneLinkUiQueryStatus, PhoneLinkUiReport, PhoneLinkUiSample,
    PhoneLinkUiStatus, inspect_phone_link_ui,
};
pub const TARGET_APK_SHA256: &str =
    "518884a1bf141dd2f83308b5833a729c36f4db59456d19554e9f0ab43008e82f";
pub const WHITELIST_SHA256: &str =
    "49a64b6d977e51e64c97c7b1232fbc9be80c8ef9ac6750e15f18b8a9a8ef4061";
const SOURCE: &str = include_str!("phone_link_ui_probe/PhoneLinkUiProbe.java");
const PACKAGE: &str = "org.googlebook.port.phonelinkui";
const MANIFEST: &str = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.googlebook.port.phonelinkui" android:versionCode="1">
<uses-sdk android:minSdkVersion="31" android:targetSdkVersion="36"/>
<application android:label="Googlebook Phone Link UI observations" android:debuggable="true" android:testOnly="true" android:allowBackup="false" android:hasCode="true"/>
<instrumentation android:name=".PhoneLinkUiProbe" android:targetPackage="org.googlebook.port.phonelinkui" android:functionalTest="true"/>
</manifest>"#;

// Same pinned toolchain, isolated compilation and APK assembly boundaries as the
// owned hardware probe. This routine accepts only the static source above, and
// never instruments/replaces/executes the Google-signed target APK.
pub fn build(r: &BuildRequest, destination: &Path) -> Result<serde_json::Value> {
    let names = ["aapt2", "zipalign", "apksigner", "key", "certificate"];
    ensure!(
        r.schema_version == 1
            && r.apk_tools.len() == names.len()
            && names.iter().all(|k| r.apk_tools.contains_key(*k)),
        "unexpected APK tools/schema"
    );
    r.java.sandbox.validate()?;
    ensure!(!destination.exists(), "output exists");
    for p in r.apk_tools.values().chain(r.java.tools.values()) {
        p.verify()?;
        gb_core::separate_from_input(&p.path, destination)?;
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = tempfile::Builder::new()
        .prefix(".gb-phone-link-ui-")
        .tempdir_in(parent)?;
    let output = temp.path().join("output");
    let resources = temp.path().join("resources");
    fs::create_dir_all(&output)?;
    fs::create_dir_all(resources.join("java-home/conf/security"))?;
    let sources = [("PhoneLinkUiProbe.java", SOURCE)];
    let manifest = MANIFEST;
    let apk_filename = "phone-link-ui-probe.apk";
    let sandbox_apk = "/output/phone-link-ui-probe.apk";
    let java_report =
        functional_probe::build_owned_sources(&r.java, &output.join("java"), &sources, None)?;
    fs::write(resources.join("AndroidManifest.xml"), manifest)?;
    fs::copy(
        &r.java.tools["security"].path,
        resources.join("java-home/conf/security/java.security"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/inputs/java-runtime/lib", resources.join("java-home/lib"))?;
    let java = r.java.tools["java"].path.canonicalize()?;
    let runtime = java.parent().and_then(Path::parent).context("JDK layout")?;
    let tool = |name: &str| r.apk_tools[name].path.as_path();
    let mut receipts = Vec::new();
    let mut run = |name: &str, args: &[&str], signing: bool| -> Result<String> {
        let program = if name == "launcher" {
            r.java.tools[name].path.as_path()
        } else {
            tool(name)
        };
        let mut extra = vec![
            ReadOnlyInput {
                name: "resources",
                path: &resources,
            },
            ReadOnlyInput {
                name: "java-runtime",
                path: runtime,
            },
            ReadOnlyInput {
                name: "security",
                path: &r.java.tools["security"].path,
            },
            ReadOnlyInput {
                name: "apksigner",
                path: tool("apksigner"),
            },
        ];
        if signing {
            extra.push(ReadOnlyInput {
                name: "key",
                path: tool("key"),
            });
            extra.push(ReadOnlyInput {
                name: "certificate",
                path: tool("certificate"),
            });
        }
        let receipt = gb_tools::run_mounted(
            &r.java.sandbox,
            program,
            args.iter().map(|s| (*s).into()).collect(),
            Inputs {
                primary: &r.java.tools["android"].path,
                extra: &extra,
                source_date_epoch: Some(0),
            },
            &output,
            Duration::from_secs(120),
        )?;
        ensure!(
            !receipt.stderr_truncated && receipt.stdout.len() < 65536,
            "APK tool receipt budget"
        );
        let text = receipt.stdout.clone();
        receipts.push(receipt);
        Ok(text)
    };
    let aapt_version = run("aapt2", &["version"], false)?;
    run(
        "aapt2",
        &[
            "link",
            "-I",
            "/input.img",
            "--manifest",
            "/inputs/resources/AndroidManifest.xml",
            "-o",
            "/output/unsigned.apk",
        ],
        false,
    )?;
    let mut source = zip::ZipArchive::new(fs::File::open(output.join("java/probe.jar"))?)?;
    let mut dex = source.by_name("classes.dex")?;
    ensure!(dex.size() <= 128 * 1024, "DEX budget");
    let mut apk = zip::ZipWriter::new_append(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(output.join("unsigned.apk"))?,
    )?;
    apk.start_file(
        "classes.dex",
        zip::write::SimpleFileOptions::default()
            .last_modified_time(zip::DateTime::default())
            .compression_method(zip::CompressionMethod::Stored),
    )?;
    std::io::copy(&mut dex, &mut apk)?;
    apk.finish()?.sync_all()?;
    run(
        "zipalign",
        &["-f", "4", "/output/unsigned.apk", "/output/aligned.apk"],
        false,
    )?;
    let signer_version = run(
        "launcher",
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/security",
            "-jar",
            "/inputs/apksigner",
            "version",
        ],
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
            sandbox_apk,
            "/output/aligned.apk",
        ],
        true,
    )?;
    let signature = run(
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
            sandbox_apk,
        ],
        false,
    )?;
    ensure!(
        signature.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "APK signature not verified"
    );
    for p in r.apk_tools.values().chain(r.java.tools.values()) {
        p.verify()?;
    }
    let zipalign_identity = gb_tools::identity(tool("zipalign"), &r.java.sandbox)?;
    let mut report = serde_json::json!({"schema_version":1,
        "status":"owned_phone_link_ui_apk_built_not_runtime_verified",
        "package":PACKAGE,
        "apk_sha256":gb_core::hash_file(&output.join(apk_filename))?,"manifest_sha256":gb_core::digest(manifest.as_bytes()),
        "java_build":java_report,"tools":r.apk_tools,"tool_versions":{"aapt2":aapt_version,"apksigner":signer_version},"zipalign_identity":zipalign_identity,"signature_verification":signature,"commands":receipts,"firmware_written":false,"runtime_verified":false});
    report["phone_link_ui_source_sha256"] = gb_core::digest(SOURCE.as_bytes()).into();
    report["expected_target_apk_sha256"] = TARGET_APK_SHA256.into();
    report["whitelist_sha256"] = WHITELIST_SHA256.into();
    gb_core::write_json(&output.join("build-report.json"), &report)?;
    gb_core::publish_directory(&output, destination)?;
    Ok(report)
}
