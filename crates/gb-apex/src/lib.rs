//! Read-only APEX/cAPEX container decoding. No hook, signature or payload execution.
use anyhow::{Context, Result, ensure};
use gb_core::{ApexPackage, Format, copy_stream, digest, hash_file, safe_relative};
use gb_partition::{ReadSeek, avb_footer, detect, read_at};
use prost::Message;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

// Wire fields follow platform/system/apex/proto/apex_manifest.proto (Android 17).
// Unknown fields are skipped by Prost; their omission is not a compatibility claim.
#[derive(Clone, PartialEq, Message)]
pub struct Manifest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(int64, tag = "2")]
    pub version: i64,
    #[prost(string, tag = "3")]
    pub pre_install_hook: String,
    #[prost(string, tag = "4")]
    pub post_install_hook: String,
    #[prost(string, tag = "5")]
    pub version_name: String,
    #[prost(string, repeated, tag = "7")]
    pub provide_native_libs: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    pub require_native_libs: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    pub jni_libs: Vec<String>,
    #[prost(bool, tag = "15")]
    pub vendor_bootstrap: bool,
    #[prost(bool, tag = "16")]
    pub bootstrap: bool,
}
pub struct Extracted {
    pub package: ApexPackage,
    pub payload: tempfile::NamedTempFile,
    pub manifest: Manifest,
    pub avb_metadata: Option<serde_json::Value>,
}
pub fn check_payload_manifest(bytes: &[u8], expected: &Manifest) -> Result<()> {
    let actual = Manifest::decode(bytes)?;
    ensure!(
        actual.name == expected.name
            && actual.version == expected.version
            && actual.provide_native_libs == expected.provide_native_libs
            && actual.require_native_libs == expected.require_native_libs,
        "APEX payload manifest identity/dependencies differ from container"
    );
    Ok(())
}
fn preflight(r: &mut dyn ReadSeek) -> Result<(Manifest, Vec<u8>, bool)> {
    r.seek(SeekFrom::Start(0))?;
    let mut zip = zip::ZipArchive::new(r)?;
    ensure!(zip.len() <= 256, "APEX container entry limit exceeded");
    let mut names = BTreeSet::new();
    let mut expanded = 0u64;
    for i in 0..zip.len() {
        let e = zip.by_index(i)?;
        safe_relative(Path::new(e.name().trim_end_matches('/')))?;
        ensure!(
            !e.name().contains('\\') && names.insert(e.name().to_owned()),
            "unsafe or duplicate APEX member"
        );
        ensure!(
            e.unix_mode().is_none_or(|mode| mode & 0o170000 != 0o120000),
            "APEX member symlink refused"
        );
        expanded = expanded
            .checked_add(e.size())
            .context("APEX expansion overflow")?;
        ensure!(
            expanded <= 16 * 1024 * 1024 * 1024,
            "APEX expansion limit exceeded"
        );
    }
    let bytes = small_member(&mut zip, "apex_manifest.pb")?;
    let m = Manifest::decode(bytes.as_slice()).context("invalid APEX manifest protobuf")?;
    ensure!(
        !m.name.is_empty()
            && m.name.len() <= 255
            && m.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'),
        "invalid APEX mount name"
    );
    ensure!(m.version >= 0, "negative APEX version");
    ensure!(
        m.pre_install_hook.is_empty() && m.post_install_hook.is_empty(),
        "APEX install hooks require a separate reviewed adapter; never executed by inspection"
    );
    let key = small_member(&mut zip, "apex_pubkey")?;
    ensure!(!key.is_empty(), "empty APEX public key");
    let compressed = names.contains("original_apex");
    ensure!(
        compressed != names.contains("apex_payload.img"),
        "APEX must have exactly one payload or original_apex member"
    );
    Ok((m, key, compressed))
}
fn small_member<R: Read + Seek>(zip: &mut zip::ZipArchive<R>, name: &str) -> Result<Vec<u8>> {
    let mut entry = zip
        .by_name(name)
        .with_context(|| format!("APEX missing {name}"))?;
    ensure!(
        !entry.is_dir() && entry.size() <= 1024 * 1024,
        "APEX metadata member exceeds limit"
    );
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == entry.size(),
        "APEX metadata size mismatch"
    );
    Ok(bytes)
}
fn extract_member(
    r: &mut dyn ReadSeek,
    name: &str,
    scratch: &Path,
) -> Result<tempfile::NamedTempFile> {
    r.seek(SeekFrom::Start(0))?;
    let mut zip = zip::ZipArchive::new(r)?;
    let mut entry = zip.by_name(name)?;
    ensure!(
        entry.size() > 0 && fs2::available_space(scratch)? > entry.size() + 256 * 1024 * 1024,
        "insufficient space for APEX member"
    );
    let mut out = tempfile::NamedTempFile::new_in(scratch)?;
    ensure!(
        copy_stream(&mut entry, &mut out)? == entry.size(),
        "APEX member size mismatch"
    );
    out.as_file().sync_all()?;
    Ok(out)
}
pub fn extract(
    r: &mut dyn ReadSeek,
    path: &str,
    source_sha256: &str,
    scratch: &Path,
) -> Result<Extracted> {
    let (outer, key, compressed) = preflight(r)?;
    let mut original = None;
    let (manifest, key, payload, original_sha) = if compressed {
        let file = extract_member(r, "original_apex", scratch)?;
        let sha = hash_file(file.path())?;
        original = Some(file);
        let inner = original.as_mut().context("original APEX staging")?;
        let (m, inner_key, nested) = preflight(inner.as_file_mut())?;
        ensure!(!nested, "nested compressed APEX refused");
        ensure!(
            m.name == outer.name
                && m.version == outer.version
                && key == inner_key
                && m.provide_native_libs == outer.provide_native_libs
                && m.require_native_libs == outer.require_native_libs,
            "compressed/original APEX identity, key or dependency metadata differs"
        );
        let payload = extract_member(inner.as_file_mut(), "apex_payload.img", scratch)?;
        (m, inner_key, payload, Some(sha))
    } else {
        let payload = extract_member(r, "apex_payload.img", scratch)?;
        (outer, key, payload, None)
    };
    let payload_sha256 = hash_file(payload.path())?;
    let mut f = File::open(payload.path())?;
    let len = f.metadata()?.len();
    let format = detect(&read_at(&mut f, 0, len.min(8192) as usize)?);
    ensure!(
        matches!(format, Format::Erofs | Format::Ext4),
        "unsupported APEX payload filesystem {format:?}; no guessed extraction"
    );
    let avb_metadata = avb_footer(&mut f)?;
    let package = ApexPackage {
        path: path.into(),
        name: manifest.name.clone(),
        version: manifest.version,
        version_name: manifest.version_name.clone(),
        compressed,
        package_sha256: source_sha256.into(),
        original_apex_sha256: original_sha,
        payload_sha256,
        payload_format: format,
        public_key_sha256: digest(&key),
        provide_native_libs: manifest.provide_native_libs.clone(),
        require_native_libs: manifest.require_native_libs.clone(),
        jni_libs: manifest.jni_libs.clone(),
        bootstrap: manifest.bootstrap || manifest.vendor_bootstrap,
        signatures_verified: false,
    };
    drop(original);
    Ok(Extracted {
        package,
        payload,
        manifest,
        avb_metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    fn payload() -> Vec<u8> {
        let mut b = vec![0; 4096];
        b[1024..1028].copy_from_slice(&0xe0f5e1e2u32.to_le_bytes());
        b
    }
    fn container(m: &Manifest, key: &[u8], body: (&str, &[u8])) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(Cursor::new(vec![]));
        for (name, data) in [
            ("apex_manifest.pb", m.encode_to_vec().as_slice()),
            ("apex_pubkey", key),
            body,
        ] {
            z.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap().into_inner()
    }
    #[test]
    fn normal_and_compressed_identity_and_no_signature_claim() {
        let t = tempfile::tempdir().unwrap();
        let m = Manifest {
            name: "com.android.test".into(),
            version: 7,
            provide_native_libs: vec!["libtest.so".into()],
            ..Default::default()
        };
        let raw = container(&m, b"public-key", ("apex_payload.img", &payload()));
        let capex = container(&m, b"public-key", ("original_apex", &raw));
        let extracted = extract(
            &mut Cursor::new(capex),
            "system/apex/test.capex",
            &digest(b"test"),
            t.path(),
        )
        .unwrap();
        assert!(extracted.package.compressed);
        assert!(!extracted.package.signatures_verified);
        assert_eq!(extracted.package.name, m.name);
        let bad = container(&m, b"different-key", ("original_apex", &raw));
        assert!(extract(&mut Cursor::new(bad), "bad", &digest(b"bad"), t.path()).is_err());
    }
    #[test]
    fn traversal_and_install_hooks_refused() {
        let t = tempfile::tempdir().unwrap();
        let m = Manifest {
            name: "com.android.test".into(),
            ..Default::default()
        };
        let bad = container(&m, b"key", ("../escape", b"bad"));
        assert!(extract(&mut Cursor::new(bad), "bad", &digest(b"bad"), t.path()).is_err());
        let m = Manifest {
            pre_install_hook: "do-not-run".into(),
            ..m
        };
        let bad = container(&m, b"key", ("apex_payload.img", &payload()));
        assert!(extract(&mut Cursor::new(bad), "bad", &digest(b"bad"), t.path()).is_err());
        assert!(!t.path().join("escape").exists());
    }
}
