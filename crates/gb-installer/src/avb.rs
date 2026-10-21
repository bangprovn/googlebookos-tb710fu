//! Re-sign AVB metadata through the AOSP tool; preserve payloads and descriptors.
use anyhow::{Context, Result, ensure};
use gb_core::{digest, run_tool};
use gb_partition::read_at;
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

fn u64_at(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        b.get(at..at + 8)
            .context("truncated AVB integer")?
            .try_into()?,
    ))
}
#[derive(Clone, Debug)]
pub struct Metadata {
    pub offset: u64,
    pub blob: Vec<u8>,
    pub info: Value,
    pub public_key: Vec<u8>,
    pub public_key_metadata: Vec<u8>,
    pub descriptor_bytes: Vec<u8>,
}
impl Metadata {
    pub fn read(path: &Path) -> Result<Self> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        ensure!(len >= 256, "truncated AVB image");
        let prefix = read_at(&mut f, 0, 4)?;
        let (offset, footer_size) = if prefix == b"AVB0" {
            (0, None)
        } else {
            let footer = read_at(
                &mut f,
                len.checked_sub(64).context("missing AVB footer")?,
                64,
            )?;
            ensure!(&footer[..4] == b"AVBf", "image has no AVB footer");
            let offset = u64_at(&footer, 20)?;
            let size = u64_at(&footer, 28)?;
            ensure!(
                u64_at(&footer, 12)? <= offset
                    && offset.checked_add(size).is_some_and(|n| n <= len - 64),
                "invalid AVB footer geometry"
            );
            (offset, Some(size))
        };
        let info = gb_partition::avb(&mut f, offset)?;
        ensure!(
            info["flags"] == 0 && [1, 2].contains(&info["algorithm_type"].as_u64().unwrap_or(0)),
            "only verification-enabled SHA256_RSA2048/4096 metadata is supported"
        );
        let h = read_at(&mut f, offset, 256)?;
        let auth = u64_at(&h, 12)?;
        let size = 256_u64
            .checked_add(auth)
            .and_then(|x| x.checked_add(u64_at(&h, 20).ok()?))
            .context("AVB size overflow")?;
        ensure!(
            size <= 1024 * 1024
                && offset.checked_add(size).is_some_and(|n| n <= len)
                && footer_size.is_none_or(|n| n == size),
            "unsupported AVB container size"
        );
        let blob = read_at(&mut f, offset, size as usize)?;
        let section = |start: usize, size: usize| -> Result<Vec<u8>> {
            let off = 256_u64
                .checked_add(auth)
                .and_then(|n| n.checked_add(u64_at(&h, start).ok()?))
                .context("AVB offset overflow")?;
            let end = off
                .checked_add(u64_at(&h, size)?)
                .context("AVB field overflow")?;
            Ok(blob
                .get(usize::try_from(off)?..usize::try_from(end)?)
                .context("AVB field out of bounds")?
                .to_vec())
        };
        Ok(Self {
            offset,
            public_key: section(64, 72)?,
            public_key_metadata: section(80, 88)?,
            descriptor_bytes: section(96, 104)?,
            blob,
            info,
        })
    }
    pub fn index(&self) -> Result<u64> {
        self.info["rollback_index"]
            .as_u64()
            .context("missing rollback index")
    }
    pub fn chains(&self) -> Result<std::collections::BTreeMap<String, u64>> {
        let mut out = std::collections::BTreeMap::new();
        for d in self.info["descriptors"]
            .as_array()
            .context("missing AVB descriptors")?
        {
            if d["tag"] == 4 {
                let name = d["partition"].as_str().context("missing chain partition")?;
                let location = d["rollback_index_location"]
                    .as_u64()
                    .context("missing chain location")?;
                ensure!(
                    (1..32).contains(&location) && out.insert(name.into(), location).is_none(),
                    "invalid duplicate chain"
                );
            }
        }
        Ok(out)
    }
}
#[derive(Clone, Debug)]
pub struct Tools {
    pub python: PathBuf,
    pub avbtool: PathBuf,
    pub openssl: PathBuf,
}
impl Tools {
    pub fn avb(&self, args: &[String]) -> Result<()> {
        ensure!(
            gb_core::hash_file(&self.avbtool)?
                == "e5a664a38db623da00f080219bc0ee60a640a9dc4a872803616fae4938ac749b",
            "avbtool source differs from the reviewed AOSP version"
        );
        let mut all = vec!["-I".into(), self.avbtool.to_string_lossy().into_owned()];
        all.extend_from_slice(args);
        run_tool(&self.python, &all, Duration::from_secs(60))?;
        Ok(())
    }
    pub fn verify(&self, meta: &Metadata, key: &Path, scratch: &Path) -> Result<()> {
        let public = scratch.join("key.avbpubkey");
        self.avb(&[
            "extract_public_key".into(),
            "--key".into(),
            key.display().to_string(),
            "--output".into(),
            public.display().to_string(),
        ])?;
        ensure!(
            fs::read(public)? == meta.public_key,
            "configured signing key does not match image/chain key"
        );
        let pem = scratch.join("public.pem");
        run_tool(
            &self.openssl,
            &[
                "pkey".into(),
                "-in".into(),
                key.display().to_string(),
                "-pubout".into(),
                "-out".into(),
                pem.display().to_string(),
            ],
            Duration::from_secs(10),
        )?;
        self.verify_pem(meta, &pem, scratch)
    }
    /// Check a device readback's signature without needing the OEM private key.
    /// This verifies self-consistency, not OEM trust or protected rollback state.
    pub fn verify_embedded(&self, meta: &Metadata, scratch: &Path) -> Result<()> {
        let bits = u32::from_be_bytes(
            meta.public_key
                .get(..4)
                .context("missing AVB public key")?
                .try_into()?,
        );
        let expected = if meta.info["algorithm_type"] == 1 {
            2048
        } else {
            4096
        };
        ensure!(
            bits == expected && meta.public_key.len() == 8 + 2 * (bits as usize / 8),
            "invalid AVB RSA public key geometry"
        );
        let modulus = &meta.public_key[8..8 + bits as usize / 8];
        let config = format!(
            "asn1=SEQUENCE:pubkeyinfo\n[pubkeyinfo]\nalgorithm=SEQUENCE:rsa_alg\npubkey=BITWRAP,SEQUENCE:rsapubkey\n[rsa_alg]\nalgorithm=OID:rsaEncryption\nparameter=NULL\n[rsapubkey]\nn=INTEGER:0x{}\ne=INTEGER:65537\n",
            hex(modulus)
        );
        let conf = scratch.join("public.asn1");
        let der = scratch.join("public.der");
        let pem = scratch.join("embedded.pem");
        fs::write(&conf, config)?;
        run_tool(
            &self.openssl,
            &[
                "asn1parse".into(),
                "-genconf".into(),
                conf.display().to_string(),
                "-out".into(),
                der.display().to_string(),
                "-noout".into(),
            ],
            Duration::from_secs(10),
        )?;
        run_tool(
            &self.openssl,
            &[
                "pkey".into(),
                "-pubin".into(),
                "-inform".into(),
                "DER".into(),
                "-in".into(),
                der.display().to_string(),
                "-out".into(),
                pem.display().to_string(),
            ],
            Duration::from_secs(10),
        )?;
        self.verify_pem(meta, &pem, scratch)
    }
    fn verify_pem(&self, meta: &Metadata, pem: &Path, scratch: &Path) -> Result<()> {
        let h = &meta.blob[..256];
        let auth = usize::try_from(u64_at(h, 12)?)?;
        let signature_offset = 256 + usize::try_from(u64_at(h, 48)?)?;
        let signature_size = usize::try_from(u64_at(h, 56)?)?;
        let signature = meta
            .blob
            .get(
                signature_offset
                    ..signature_offset
                        .checked_add(signature_size)
                        .context("signature overflow")?,
            )
            .context("signature out of bounds")?;
        let mut signed = h.to_vec();
        signed.extend_from_slice(&meta.blob[256 + auth..]);
        // OpenSSL verifies the signature; also check AVB's stored digest field.
        let digest_offset = 256 + usize::try_from(u64_at(h, 32)?)?;
        ensure!(
            u64_at(h, 40)? == 32
                && meta
                    .blob
                    .get(digest_offset..digest_offset + 32)
                    .is_some_and(|b| hex(b) == digest(&signed)),
            "AVB authentication digest mismatch"
        );
        fs::write(scratch.join("signed.bin"), signed)?;
        fs::write(scratch.join("signature.bin"), signature)?;
        run_tool(
            &self.openssl,
            &[
                "dgst".into(),
                "-sha256".into(),
                "-verify".into(),
                pem.display().to_string(),
                "-signature".into(),
                scratch.join("signature.bin").display().to_string(),
                scratch.join("signed.bin").display().to_string(),
            ],
            Duration::from_secs(10),
        )?;
        Ok(())
    }
    pub fn resign(&self, input: &Path, output: &Path, key: &Path, index: u64) -> Result<()> {
        ensure!(!output.exists(), "refusing to replace an existing image");
        let original = Metadata::read(input)?;
        let scratch = tempfile::tempdir()?;
        self.verify(&original, key, scratch.path())?;
        let source = scratch.path().join("template.img");
        fs::write(&source, &original.blob)?;
        let result = scratch.path().join("new.img");
        let mut args = vec![
            "make_vbmeta_image".into(),
            "--output".into(),
            result.display().to_string(),
            "--algorithm".into(),
            if original.info["algorithm_type"] == 1 {
                "SHA256_RSA2048"
            } else {
                "SHA256_RSA4096"
            }
            .into(),
            "--key".into(),
            key.display().to_string(),
            "--rollback_index".into(),
            index.to_string(),
            "--rollback_index_location".into(),
            original.info["rollback_index_location"].to_string(),
            "--flags".into(),
            "0".into(),
            "--include_descriptors_from_image".into(),
            source.display().to_string(),
            "--internal_release_string".into(),
            original.info["release_string"]
                .as_str()
                .context("missing release string")?
                .into(),
        ];
        if !original.public_key_metadata.is_empty() {
            let p = scratch.path().join("pkmd.bin");
            fs::write(&p, &original.public_key_metadata)?;
            args.extend(["--public_key_metadata".into(), p.display().to_string()]);
        }
        self.avb(&args)?;
        let new = Metadata::read(&result)?;
        self.verify(&new, key, scratch.path())?;
        ensure!(
            new.index()? == index
                && new.blob.len() == original.blob.len()
                && new.public_key == original.public_key
                && new.public_key_metadata == original.public_key_metadata
                && canonical_descriptors(&new.descriptor_bytes)?
                    == canonical_descriptors(&original.descriptor_bytes)?
                && new.info["rollback_index_location"] == original.info["rollback_index_location"]
                && new.blob[4..12] == original.blob[4..12],
            "re-signing changed AVB layout, descriptors, key, version or location"
        );
        let parent = output.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        let mut source = File::open(input)?;
        std::io::copy(&mut source, &mut temp)?;
        temp.seek(SeekFrom::Start(original.offset))?;
        temp.write_all(&new.blob)?;
        temp.as_file().sync_all()?;
        ensure!(
            payload_equal(input, temp.path())?,
            "personalization changed image payload bytes"
        );
        temp.persist_noclobber(output).map_err(|e| e.error)?;
        Ok(())
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

/// Only bytes inside the AVB metadata region may differ during personalization.
pub fn payload_equal(first: &Path, second: &Path) -> Result<bool> {
    let m = Metadata::read(first)?;
    let a = File::open(first)?;
    let b = File::open(second)?;
    if a.metadata()?.len() != b.metadata()?.len() {
        return Ok(false);
    }
    let mut a = a;
    let mut b = b;
    let mut off = 0_u64;
    let mut x = [0_u8; 65536];
    let mut y = [0_u8; 65536];
    loop {
        let n = a.read(&mut x)?;
        if n == 0 {
            break;
        }
        b.read_exact(&mut y[..n])?;
        for i in 0..n {
            let pos = off + i as u64;
            if (pos < m.offset || pos >= m.offset + m.blob.len() as u64) && x[i] != y[i] {
                return Ok(false);
            }
        }
        off += n as u64;
    }
    Ok(true)
}

// avbtool sorts hash descriptors after properties. Compare complete descriptor
// multisets; reject conflicting duplicate properties whose order could matter.
fn canonical_descriptors(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    let mut properties = std::collections::BTreeMap::new();
    let mut pos = 0_usize;
    while pos < bytes.len() {
        let tag = u64_at(bytes, pos)?;
        ensure!(tag <= 4, "unknown AVB descriptor type");
        let size = usize::try_from(u64_at(bytes, pos + 8)?)?
            .checked_add(16)
            .context("descriptor size overflow")?;
        let end = pos.checked_add(size).context("descriptor end overflow")?;
        let d = bytes.get(pos..end).context("truncated descriptor")?;
        if tag == 0 {
            let n = usize::try_from(u64_at(d, 16)?)?;
            let key = d
                .get(32..32_usize.checked_add(n).context("property key overflow")?)
                .context("property key bounds")?;
            if let Some(previous) = properties.insert(key.to_vec(), d.to_vec()) {
                ensure!(previous == d, "conflicting duplicate AVB properties");
            }
        }
        result.push(d.to_vec());
        pos = end;
    }
    result.sort();
    Ok(result)
}
