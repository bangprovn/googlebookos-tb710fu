//! Matched, artifact-only Tips constructor containment. No APK signing or device operations.
use anyhow::{Context, Result, ensure};
use gb_tools::{Inputs, ReadOnlyInput, Sandbox};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

const INPUT_SHA: &str = "5e4d4c6336e18a3228b4ac4960ea5ecddcc556865d530db7a7094903f62695ba";
const INPUT_DEX_SHA: &str = "d4478840b79533666b3aa60dac477e38c4bd3b34435f5b94d6cf98de3a6d2644";
const SOURCES: &[(&str, &str)] = &[
    (
        "LazyClient.java",
        include_str!("serviceability_client/LazyClient.java"),
    ),
    (
        "PatchClient.java",
        include_str!("serviceability_client/PatchClient.java"),
    ),
];
const CONTROLS: &[(&str, &str)] = &[
    ("builder.rs", include_str!("serviceability_client.rs")),
    (
        "example.rs",
        include_str!("../examples/serviceability_client.rs"),
    ),
    (
        "host_tests.py",
        include_str!("serviceability_client/host_tests.py"),
    ),
    ("README.md", include_str!("serviceability_client/README.md")),
];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    pub path: PathBuf,
    pub sha256: String,
}
impl PinnedFile {
    fn verify(&self) -> Result<()> {
        ensure!(
            self.sha256.len() == 64
                && self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                && fs::symlink_metadata(&self.path)?.is_file(),
            "invalid pinned regular file"
        );
        ensure!(
            gb_core::hash_file(&self.path)? == self.sha256,
            "pinned checksum mismatch"
        );
        Ok(())
    }
}

fn zip_helper(root: &Path, destination: &Path) -> Result<()> {
    fn collect(root: &Path, dir: &Path, files: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
        ensure!(depth <= 8, "compiler directory depth");
        for item in fs::read_dir(dir)? {
            let path = item?.path();
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_dir() {
                collect(root, &path, files, depth + 1)?;
            } else {
                ensure!(
                    kind.is_file()
                        && path.extension().is_some_and(|e| e == "class")
                        && fs::metadata(&path)?.len() <= 65536
                        && files.len() < 16,
                    "helper class budget"
                );
                files.push(path.strip_prefix(root)?.to_owned());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    collect(root, root, &mut files, 0)?;
    files.sort();
    ensure!(!files.is_empty(), "no compiled helper classes");
    let mut writer = zip::ZipWriter::new(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?,
    );
    for file in files {
        writer.start_file(
            file.to_str().context("class path")?,
            zip::write::SimpleFileOptions::default().last_modified_time(zip::DateTime::default()),
        )?;
        std::io::copy(&mut fs::File::open(root.join(file))?, &mut writer)?;
    }
    writer.finish()?.sync_all()?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    pub schema_version: u32,
    pub input: PinnedFile,
    pub tools: BTreeMap<String, PinnedFile>,
    pub sandbox: Sandbox,
}

impl BuildRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let mut request: Self = gb_core::read_json(path, 65536)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for pin in std::iter::once(&mut request.input).chain(request.tools.values_mut()) {
            if pin.path.is_relative() {
                pin.path = parent.join(&pin.path);
            }
        }
        request.validate()?;
        Ok(request)
    }
    fn validate(&self) -> Result<()> {
        let tools = [
            "android", "java", "javac", "launcher", "security", "r8", "jadx",
        ];
        ensure!(
            self.schema_version == 1 && self.input.sha256 == INPUT_SHA,
            "only matched installed serviceability client is supported"
        );
        ensure!(
            self.tools.len() == tools.len() && tools.iter().all(|k| self.tools.contains_key(*k)),
            "unexpected build tool set"
        );
        self.sandbox.validate()
    }
}

pub fn build(request: &BuildRequest, destination: &Path) -> Result<serde_json::Value> {
    request.validate()?;
    ensure!(!destination.exists(), "refusing existing output");
    for pin in std::iter::once(&request.input).chain(request.tools.values()) {
        pin.verify()?;
        gb_core::separate_from_input(&pin.path, destination)?;
    }
    ensure!(
        fs::metadata(&request.input.path)?.len() == 47482,
        "matched JAR size"
    );
    let mut archive = zip::ZipArchive::new(fs::File::open(&request.input.path)?)?;
    ensure!(archive.len() == 2, "unexpected shared-JAR entries");
    let mut original = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        ensure!(
            matches!(entry.name(), "classes.dex" | "META-INF/MANIFEST.MF")
                && entry.size() <= 256 * 1024,
            "unexpected shared-JAR entry"
        );
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes)?;
        ensure!(
            original.insert(entry.name().to_string(), bytes).is_none(),
            "duplicate JAR entry"
        );
    }
    ensure!(
        gb_core::digest(&original["classes.dex"]) == INPUT_DEX_SHA,
        "matched DEX digest"
    );
    let tool = |name: &str| request.tools[name].path.as_path();
    let java = tool("java").canonicalize()?;
    let runtime = java.parent().and_then(Path::parent).context("JDK layout")?;
    ensure!(
        runtime.join("bin/java") == java
            && runtime.join("bin/javac").canonicalize()? == tool("javac").canonicalize()?,
        "complete matched JDK required"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".gb-serviceability-")
        .tempdir_in(parent)?;
    let source = staging.path().join("source");
    let output = staging.path().join("output");
    fs::create_dir_all(source.join("java-home/conf/security"))?;
    for directory in ["helper-classes", "patch-classes", "dex"] {
        fs::create_dir_all(output.join(directory))?;
    }
    fs::copy(
        tool("security"),
        source.join("java-home/conf/security/java.security"),
    )?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/inputs/java-runtime/lib", source.join("java-home/lib"))?;
    let mut source_pins = BTreeMap::new();
    for (name, text) in SOURCES {
        fs::write(source.join(name), text)?;
        source_pins.insert(*name, gb_core::digest(text.as_bytes()));
    }
    // Snapshots survive successful publication for independent source-at-build review.
    fs::create_dir(output.join("source"))?;
    for (name, _) in SOURCES {
        fs::copy(source.join(name), output.join("source").join(name))?;
    }
    let mut control_pins = BTreeMap::new();
    for (name, text) in CONTROLS {
        fs::write(output.join("source").join(name), text)?;
        control_pins.insert(*name, gb_core::digest(text.as_bytes()));
    }
    let mut commands = Vec::new();
    let mut run = |args: &[&str]| -> Result<String> {
        gb_core::checkpoint()?;
        let extra = [
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
                name: "jadx",
                path: tool("jadx"),
            },
        ];
        let receipt = gb_tools::run_mounted(
            &request.sandbox,
            tool("launcher"),
            args.iter().map(|s| (*s).into()).collect(),
            Inputs {
                primary: &request.input.path,
                extra: &extra,
                source_date_epoch: Some(0),
            },
            &output,
            Duration::from_secs(120),
        )?;
        ensure!(
            !receipt.stderr_truncated && receipt.stdout.len() < 65536,
            "tool output budget"
        );
        let stdout = receipt.stdout.clone();
        commands.push(receipt);
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
        "/output/helper-classes",
        "/inputs/resources/LazyClient.java",
    ])?;
    zip_helper(&output.join("helper-classes"), &output.join("helper.jar"))?;
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
        "/output/helper.jar",
    ])?;
    run(&[
        "/inputs/java-runtime/bin/javac",
        "-J-Djava.home=/inputs/resources/java-home",
        "-J-Djava.security.properties==/inputs/security",
        "-proc:none",
        "--release",
        "17",
        "-cp",
        "/inputs/jadx",
        "-d",
        "/output/patch-classes",
        "/inputs/resources/PatchClient.java",
    ])?;
    let patch_result = run(&[
        "/inputs/java-runtime/bin/java",
        "-Djava.home=/inputs/resources/java-home",
        "-Djava.security.properties==/inputs/security",
        "-cp",
        "/output/patch-classes:/inputs/jadx",
        "PatchClient",
        "/input.img",
        "/output/dex/classes.dex",
        "/output/classes.dex",
    ])?;
    let result_dex = output.join("classes.dex");
    ensure!(
        fs::metadata(&result_dex)?.len() <= 512 * 1024,
        "candidate DEX size budget"
    );
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("serviceability-client.jar"))?;
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in &original {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .last_modified_time(zip::DateTime::default())
                .unix_permissions(0o644),
        )?;
        if name == "classes.dex" {
            std::io::copy(&mut fs::File::open(&result_dex)?, &mut zip)?;
        } else {
            std::io::Write::write_all(&mut zip, bytes)?;
        }
    }
    zip.finish()?.sync_all()?;
    for pin in std::iter::once(&request.input).chain(request.tools.values()) {
        pin.verify()?;
    }
    let report = serde_json::json!({
        "schema_version":1,"status":"built_not_runtime_verified","scope":"Tips-only constructor containment",
        "input":request.input,"sources":source_pins,"control_sources":control_pins,"tools":request.tools,"sandbox":request.sandbox,
        "java_version":java_version,"d8_version":d8_version,"commands":commands,"patch_result":patch_result,
        "candidate_sha256":gb_core::hash_file(&output.join("serviceability-client.jar"))?,
        "candidate_bytes":fs::metadata(output.join("serviceability-client.jar"))?.len(),
        "preserved_before_sha256":gb_core::hash_file(&output.join("classes.dex.preserved-before.dex"))?,
        "preserved_after_sha256":gb_core::hash_file(&output.join("classes.dex.preserved-after.dex"))?,
        "full_before_sha256":gb_core::hash_file(&output.join("classes.dex.full-before.dex"))?,
        "full_reversed_sha256":gb_core::hash_file(&output.join("classes.dex.full-reversed.dex"))?,
        "runtime_verified":false,"perks_supported":false,"firmware_written":false,"signed_apk_modified":false,
        "limits":["Only asynchronous service callbacks are deadline-bounded; Context.bindService and synchronous Binder RPCs have no new interruptible deadline.",
            "Main-thread first acquisition is explicitly refused; existing ready service calls retain original synchronous RPC behavior.",
            "Successful bindings remain for manager/process lifetime, preserving listener ownership; no new close API.",
            "Failed/closed attempts unbind both connections independently; unexpected unbind failures are propagated/suppressed explicitly, not proof of transport cleanup.",
            "Original non-Tips constructor bytecode is retained; no manufactured/null/empty identity fallback.",
            "Original Tips failure UI may show generic retry rather than accurate unsupported capability."]
    });
    gb_core::write_json(&output.join("build-report.json"), &report)?;
    gb_core::publish_directory(&output, destination)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matched_input_and_exact_tool_set_only() {
        let request = BuildRequest {
            schema_version: 1,
            input: PinnedFile {
                path: "absent".into(),
                sha256: "0".repeat(64),
            },
            tools: BTreeMap::new(),
            sandbox: Sandbox::default(),
        };
        assert!(request.validate().is_err());
    }
}
