//! Boolean framework overlays, built and signed by trusted, sandboxed SDK tools.
//! Publication is offline; partition policy, precedence and runtime require separate checks.
use anyhow::{Context, Result, ensure};
use gb_core::{checkpoint, hash_file, publish_directory, separate_from_input, write_json};
use gb_tools::{Inputs, ReadOnlyInput, Sandbox};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    pub path: PathBuf,
    pub sha256: String,
}
impl PinnedFile {
    pub(crate) fn verify(&self) -> Result<()> {
        ensure!(
            self.sha256.len() == 64 && self.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid input checksum"
        );
        ensure!(
            fs::symlink_metadata(&self.path)?.is_file(),
            "input must be a regular file"
        );
        ensure!(
            hash_file(&self.path)? == self.sha256.to_lowercase(),
            "checksum mismatch: {}",
            self.path.display()
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub package: String,
    pub sdk: u32,
    pub priority: u32,
    pub booleans: BTreeMap<String, bool>,
    pub framework: PinnedFile,
    pub aapt2: PinnedFile,
    pub java: PinnedFile,
    pub java_launcher: PinnedFile,
    pub java_security: PinnedFile,
    pub apksigner: PinnedFile,
    pub key: PinnedFile,
    pub certificate: PinnedFile,
    pub sandbox: Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        ensure!(
            fs::metadata(path)?.len() <= 65536,
            "overlay request too large"
        );
        let mut request: Self = toml::from_str(&fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for file in request.files_mut() {
            if file.path.is_relative() {
                file.path = parent.join(&file.path);
            }
        }
        request.validate()?;
        Ok(request)
    }
    fn files_mut(&mut self) -> [&mut PinnedFile; 8] {
        [
            &mut self.framework,
            &mut self.aapt2,
            &mut self.java,
            &mut self.java_launcher,
            &mut self.java_security,
            &mut self.apksigner,
            &mut self.key,
            &mut self.certificate,
        ]
    }
    fn files(&self) -> [&PinnedFile; 8] {
        [
            &self.framework,
            &self.aapt2,
            &self.java,
            &self.java_launcher,
            &self.java_security,
            &self.apksigner,
            &self.key,
            &self.certificate,
        ]
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && (29..=99).contains(&self.sdk)
                && (1..=999).contains(&self.priority),
            "invalid overlay schema, SDK or priority"
        );
        ensure!(
            self.package.starts_with("org.googlebook.port.")
                && self.package.len() <= 200
                && self.package.split('.').all(identifier),
            "use a distinct org.googlebook.port package with valid identifiers"
        );
        ensure!(
            !self.booleans.is_empty()
                && self.booleans.len() <= 64
                && self
                    .booleans
                    .keys()
                    .all(|k| k.starts_with("config_") && identifier(k)),
            "overlay requires bounded config boolean names"
        );
        self.sandbox.validate()?;
        Ok(())
    }
    fn xml(&self) -> Result<(String, String)> {
        self.validate()?;
        let manifest = format!(
            "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"{}\" android:versionCode=\"1\" android:versionName=\"1\"><uses-sdk android:minSdkVersion=\"{}\" android:targetSdkVersion=\"{}\"/><application android:hasCode=\"false\"/><overlay android:targetPackage=\"android\" android:isStatic=\"true\" android:priority=\"{}\"/></manifest>\n",
            self.package, self.sdk, self.sdk, self.priority
        );
        let values = self
            .booleans
            .iter()
            .map(|(key, value)| format!("  <bool name=\"{key}\">{value}</bool>\n"))
            .collect::<String>();
        Ok((manifest, format!("<resources>\n{values}</resources>\n")))
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn build(request: &Request, destination: &Path) -> Result<serde_json::Value> {
    request.validate()?;
    ensure!(!destination.exists(), "overlay destination already exists");
    for file in request.files() {
        file.verify()?;
        separate_from_input(&file.path, destination)?;
    }
    // Resolve the Java launcher before sandbox mounting (usually a /etc/alternatives link).
    let java = request.java.path.canonicalize()?;
    let java_runtime = java
        .parent()
        .and_then(Path::parent)
        .context("Java runtime layout")?;
    ensure!(
        java_runtime.join("bin/java") == java && java_runtime.join("lib/libjava.so").is_file(),
        "configure a host JDK with bin/java and lib/libjava.so"
    );
    let launcher = request.java_launcher.path.canonicalize()?;
    let aapt2 = request.aapt2.path.canonicalize()?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = tempfile::Builder::new()
        .prefix(".gb-rro-")
        .tempdir_in(parent)?;
    let source = temp.path().join("source");
    let output = temp.path().join("published");
    fs::create_dir_all(source.join("res/values"))?;
    fs::create_dir(&output)?;
    let (manifest, values) = request.xml()?;
    fs::write(source.join("AndroidManifest.xml"), manifest)?;
    fs::write(source.join("res/values/config.xml"), values)?;
    // Distribution JDKs often link conf/security outside their runtime tree.
    // Supply the pinned security configuration without exposing host /etc.
    let java_home = source.join("java-home");
    fs::create_dir_all(java_home.join("conf/security"))?;
    fs::copy(
        &request.java_security.path,
        java_home.join("conf/security/java.security"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/inputs/java-runtime/lib", java_home.join("lib"))?;
    let extras = [
        ReadOnlyInput {
            name: "resources",
            path: &source,
        },
        ReadOnlyInput {
            name: "apksigner",
            path: &request.apksigner.path,
        },
        ReadOnlyInput {
            name: "key",
            path: &request.key.path,
        },
        ReadOnlyInput {
            name: "certificate",
            path: &request.certificate.path,
        },
        ReadOnlyInput {
            name: "java-security",
            path: &request.java_security.path,
        },
        ReadOnlyInput {
            name: "java-runtime",
            path: java_runtime,
        },
    ];
    let mut receipts = Vec::new();
    let mut run = |tool: &Path, args: &[&str]| -> Result<String> {
        checkpoint()?;
        let result = gb_tools::run_mounted(
            &request.sandbox,
            tool,
            args.iter().map(|s| s.to_string()).collect(),
            Inputs {
                primary: &request.framework.path,
                extra: &extras,
                source_date_epoch: Some(0),
            },
            &output,
            Duration::from_secs(60),
        )?;
        ensure!(
            result.stdout.len() < 65536 && !result.stderr_truncated,
            "tool diagnostic output incomplete"
        );
        let stdout = result.stdout.clone();
        receipts.push(result);
        Ok(stdout)
    };
    run(
        &aapt2,
        &[
            "compile",
            "--dir",
            "/inputs/resources/res",
            "-o",
            "/output/resources.zip",
        ],
    )?;
    run(
        &aapt2,
        &[
            "link",
            "-I",
            "/input.img",
            "--manifest",
            "/inputs/resources/AndroidManifest.xml",
            "-o",
            "/output/unsigned.apk",
            "/output/resources.zip",
        ],
    )?;
    run(
        &launcher,
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/java-security",
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
            "/output/overlay.apk",
            "/output/unsigned.apk",
        ],
    )?;
    let verification = run(
        &launcher,
        &[
            "/inputs/java-runtime/bin/java",
            "-Djava.home=/inputs/resources/java-home",
            "-Djava.security.properties==/inputs/java-security",
            "-jar",
            "/inputs/apksigner",
            "verify",
            "--verbose",
            "--print-certs",
            "/output/overlay.apk",
        ],
    )?;
    ensure!(
        verification.contains("Verified using v2 scheme (APK Signature Scheme v2): true"),
        "APK v2 signature not verified"
    );
    let resources = run(&aapt2, &["dump", "resources", "/output/overlay.apk"])?;
    for (name, value) in &request.booleans {
        ensure!(
            resources
                .lines()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair[0].trim_end().ends_with(&format!("bool/{name}"))
                    && pair[1].trim() == format!("() {value}")),
            "compiled overlay boolean missing or incorrect: {name}"
        );
    }
    let apk = output.join("overlay.apk");
    validate_archive(&apk)?;
    for file in request.files() {
        file.verify()?;
    }
    let report = serde_json::json!({"schema_version":1,"status":"offline_overlay_built_and_signature_verified","request":request,"overlay_sha256":hash_file(&apk)?,"aapt2_identity":gb_tools::identity(&aapt2,&request.sandbox)?,"java_identity":gb_tools::identity(&java,&request.sandbox)?,"java_launcher_identity":gb_tools::identity(&launcher,&request.sandbox)?,"commands":receipts,"requires_partition_policy_and_precedence_validation":true,"runtime_verified":false});
    fs::remove_file(output.join("unsigned.apk"))?;
    fs::remove_file(output.join("resources.zip"))?;
    fs::copy(
        source.join("AndroidManifest.xml"),
        output.join("AndroidManifest.xml"),
    )?;
    fs::copy(
        source.join("res/values/config.xml"),
        output.join("config.xml"),
    )?;
    write_json(&output.join("overlay-report.json"), &report)?;
    checkpoint()?;
    publish_directory(&output, destination)?;
    Ok(report)
}
fn validate_archive(path: &Path) -> Result<()> {
    ensure!(
        fs::metadata(path)?.len() <= 4 * 1024 * 1024,
        "overlay APK too large"
    );
    let mut archive = zip::ZipArchive::new(fs::File::open(path)?)?;
    ensure!(
        archive.len() == 2,
        "overlay must contain only a manifest and resources"
    );
    for name in ["AndroidManifest.xml", "resources.arsc"] {
        let file = archive
            .by_name(name)
            .context("overlay archive entry missing")?;
        ensure!(
            file.is_file()
                && file.size() <= 4 * 1024 * 1024
                && file.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
            "invalid overlay entry"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_cannot_inject_xml_or_paths() {
        for name in [
            "",
            "../resource",
            "a\"/><application",
            "a:b",
            "a.b",
            "0value",
        ] {
            assert!(!identifier(name));
        }
        assert!(identifier("config_experimental_designateMainUser"));
    }
    #[test]
    fn changed_input_is_rejected_before_tools_run() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("framework.apk");
        fs::write(&path, b"original")?;
        let input = PinnedFile {
            sha256: hash_file(&path)?,
            path: path.clone(),
        };
        input.verify()?;
        fs::write(path, b"modified")?;
        assert!(input.verify().is_err());
        Ok(())
    }
    #[test]
    fn code_bearing_overlay_is_rejected() -> Result<()> {
        use std::io::Write;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bad.apk");
        let mut zip = zip::ZipWriter::new(fs::File::create(&path)?);
        for name in ["AndroidManifest.xml", "resources.arsc", "classes.dex"] {
            zip.start_file(name, zip::write::SimpleFileOptions::default())?;
            zip.write_all(b"fixture")?;
        }
        zip.finish()?;
        assert!(validate_archive(&path).is_err());
        Ok(())
    }
}
