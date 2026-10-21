//! Read-only APK manifest/resource inspection with pinned, sandboxed aapt2.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pinned {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    apk: Pinned,
    aapt2: Pinned,
    shell: Pinned,
    sandbox: gb_tools::Sandbox,
}
fn verify(p: &Pinned) -> Result<()> {
    ensure!(
        p.sha256.len() == 64 && p.sha256.bytes().all(|v| v.is_ascii_hexdigit()),
        "invalid SHA256"
    );
    ensure!(
        fs::symlink_metadata(&p.path)?.is_file(),
        "input must be a regular file"
    );
    ensure!(
        gb_core::hash_file(&p.path)? == p.sha256.to_lowercase(),
        "input/tool checksum mismatch"
    );
    Ok(())
}
fn validate_apk(path: &Path) -> Result<(usize, bool)> {
    ensure!(
        fs::metadata(path)?.len() <= 256 * 1024 * 1024,
        "APK exceeds inspection budget"
    );
    let mut zip = zip::ZipArchive::new(fs::File::open(path)?)?;
    ensure!(!zip.is_empty() && zip.len() <= 200_000, "APK entry budget");
    let mut names = BTreeSet::new();
    let mut expanded = 0u64;
    for index in 0..zip.len() {
        let member = zip.by_index(index)?;
        gb_core::safe_relative(Path::new(member.name()))?;
        ensure!(
            names.insert(member.name().to_owned()),
            "duplicate APK member"
        );
        expanded = expanded
            .checked_add(member.size())
            .context("APK expanded-size overflow")?;
        ensure!(expanded <= 1024 * 1024 * 1024, "APK expanded-size budget");
        if member.name() == "AndroidManifest.xml" {
            ensure!(
                !member.is_dir() && member.size() <= 1024 * 1024,
                "manifest budget/type"
            );
        }
    }
    ensure!(
        names.contains("AndroidManifest.xml"),
        "not an APK: AndroidManifest.xml missing"
    );
    Ok((zip.len(), names.contains("resources.arsc")))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: inspect_apk_metadata REQUEST.json NEW_OUTPUT"
    );
    let request: Request = gb_core::read_json(Path::new(&args[0]), 65536)?;
    let destination = PathBuf::from(&args[1]);
    ensure!(!destination.exists(), "output already exists");
    request.sandbox.validate()?;
    for p in [&request.apk, &request.aapt2, &request.shell] {
        verify(p)?;
    }
    gb_core::separate_from_input(&request.apk.path, &destination)?;
    let (entries, resource_table_present) = validate_apk(&request.apk.path)?;
    let aapt2 = gb_tools::host_tool(&request.aapt2.path, &[&request.apk.path])?;
    let shell = gb_tools::host_tool(&request.shell.path, &[&request.apk.path])?;
    let temp = tempfile::tempdir_in(destination.parent().unwrap_or(Path::new(".")))?;
    let output = temp.path().join("output");
    fs::create_dir(&output)?;
    // Trusted fixed script, never firmware-supplied shell text. File output avoids
    // the common subprocess stdout retention cap; RLIMIT_FSIZE bounds each file.
    let script = "set -eu\nulimit -f 16384\n/inputs/aapt2 version > /output/aapt2-version.txt 2>&1\n/inputs/aapt2 dump xmltree /input.img --file AndroidManifest.xml > /output/manifest.txt\n/inputs/aapt2 dump resources /input.img > /output/resources.txt\n";
    let result = gb_tools::run_mounted(
        &request.sandbox,
        &shell,
        vec!["-c".into(), script.into()],
        gb_tools::Inputs {
            primary: &request.apk.path,
            extra: &[gb_tools::ReadOnlyInput {
                name: "aapt2",
                path: &aapt2,
            }],
            source_date_epoch: Some(0),
        },
        &output,
        Duration::from_secs(60),
    )?;
    ensure!(
        !result.stderr_truncated,
        "APK inspection diagnostics truncated"
    );
    let mut files = serde_json::Map::new();
    for name in ["manifest.txt", "resources.txt", "aapt2-version.txt"] {
        let p = output.join(name);
        let bytes = fs::metadata(&p)?.len();
        ensure!(
            bytes <= 16 * 1024 * 1024
                && (bytes > 0 || (name == "resources.txt" && !resource_table_present)),
            "APK metadata output budget/type: {name}, bytes={bytes}"
        );
        files.insert(
            name.into(),
            serde_json::json!({"bytes":bytes,"sha256":gb_core::hash_file(&p)?}),
        );
    }
    for p in [&request.apk, &request.aapt2, &request.shell] {
        verify(p)?;
    }
    let report = serde_json::json!({"schema_version":1,"status":"static_apk_metadata_inspected",
        "apk_sha256":request.apk.sha256,"zip_entries":entries,"resource_table_present":resource_table_present,"read_only":true,
        "apk_signature_verified":false,"runtime_verified":false,"files":files,
        "aapt2_identity":gb_tools::identity(&aapt2,&request.sandbox)?,
        "shell_identity":gb_tools::identity(&shell,&request.sandbox)?,"command":result});
    gb_core::write_json(&output.join("inspection-report.json"), &report)?;
    gb_core::checkpoint()?;
    gb_core::publish_directory(&output, &destination)?;
    println!(
        "APK manifest/resources inspected read-only; signature and runtime remain unverified."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn archive(names: &[&str]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut zip = zip::ZipWriter::new(file.reopen().unwrap());
        for name in names {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"fixture metadata, never executed").unwrap();
        }
        zip.finish().unwrap();
        file
    }
    #[test]
    fn reject_non_apk_and_unsafe_members_before_invoking_tools() {
        assert!(validate_apk(archive(&["payload.bin"]).path()).is_err());
        assert!(validate_apk(archive(&["AndroidManifest.xml", "../outside"]).path()).is_err());
        assert_eq!(
            validate_apk(archive(&["AndroidManifest.xml", "classes.dex"]).path()).unwrap(),
            (2, false)
        );
        let bad = tempfile::NamedTempFile::new().unwrap();
        assert!(validate_apk(bad.path()).is_err());
    }
}
