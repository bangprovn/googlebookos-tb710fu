//! Device-bound installation. Preparation reads firmware; flashing is explicit.
pub mod avb;
pub mod edl;
pub mod layout;
use anyhow::{Context, Result, ensure};
use avb::{Metadata, Tools};
use edl::Device;
use flate2::read::GzDecoder;
use gb_core::{checkpoint, hash_file, run_tool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    time::Duration,
};

pub const PARTITIONS: &[&str] = &[
    "system",
    "product",
    "system_ext",
    "vendor",
    "boot",
    "init_boot",
    "vendor_boot",
    "vbmeta_system",
    "vbmeta",
];
pub const PERSONALIZED: &[&str] = &["vbmeta", "vbmeta_system", "boot"];
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Deserialize)]
pub struct Asset {
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
    pub image_bytes: u64,
    pub image_sha256: String,
    pub roundtrip_verified: bool,
}
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub device: String,
    pub images: BTreeMap<String, Asset>,
    pub metadata: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollback {
    pub location: u64,
    pub value: u64,
    pub source: String,
    pub protected_floor: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub status: String,
    pub device: String,
    pub serial: String,
    pub slot: String,
    pub layout: layout::Layout,
    pub writes: BTreeMap<String, edl::Range>,
    pub images: BTreeMap<String, Image>,
    pub backups: BTreeMap<String, Image>,
    pub rollback: BTreeMap<String, Rollback>,
    pub tools: Value,
    pub firmware_written: bool,
    pub runtime_verified: bool,
    pub limitations: Vec<String>,
}
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut t, value)?;
    t.write_all(b"\n")?;
    t.as_file().sync_all()?;
    t.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn checked_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file()
            && fs::metadata(path)?.len() <= 256 * 1024,
        "invalid metadata file"
    );
    Ok(serde_json::from_reader(File::open(path)?)?)
}
fn digest_ok(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn unpack(package: &Path, destination: &Path, name: &str, a: &Asset) -> Result<Image> {
    ensure!(
        a.filename == format!("{name}.img.gz")
            && a.roundtrip_verified
            && digest_ok(&a.sha256)
            && digest_ok(&a.image_sha256)
            && a.image_bytes > 0
            && a.image_bytes <= 16 * 1024 * 1024 * 1024,
        "invalid release image declaration"
    );
    let source = package.join(&a.filename);
    ensure!(
        fs::symlink_metadata(&source)?.file_type().is_file()
            && fs::metadata(&source)?.len() == a.bytes
            && hash_file(&source)? == a.sha256,
        "compressed image integrity check failed: {name}"
    );
    let filename = format!("{name}.img");
    let mut out = File::create(destination.join(&filename))?;
    let mut input = GzDecoder::new(File::open(source)?);
    let mut h = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        checkpoint()?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size = size.checked_add(n as u64).context("image size overflow")?;
        ensure!(
            size <= a.image_bytes,
            "decompressed image exceeds declared size"
        );
        out.write_all(&buffer[..n])?;
        h.update(&buffer[..n]);
    }
    ensure!(
        size == a.image_bytes && format!("{:x}", h.finalize()) == a.image_sha256,
        "raw image integrity check failed: {name}"
    );
    out.sync_all()?;
    Ok(Image {
        filename,
        bytes: size,
        sha256: a.image_sha256.clone(),
    })
}
fn unchanged_descriptors(candidate: &Metadata, target: &Metadata, modified: &[&str]) -> Result<()> {
    let descriptors = |m: &Metadata| -> Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for d in m.info["descriptors"]
            .as_array()
            .context("missing descriptors")?
        {
            if let Some(name) = d["partition"].as_str() {
                ensure!(
                    out.insert(
                        name.into(),
                        d["sha256"].as_str().context("descriptor digest")?.into()
                    )
                    .is_none(),
                    "duplicate partition descriptor"
                );
            }
        }
        Ok(out)
    };
    let c = descriptors(candidate)?;
    let t = descriptors(target)?;
    for (name, hash) in &c {
        if !modified.contains(&name.as_str()) {
            ensure!(
                t.get(name) == Some(hash),
                "retained {name} descriptor differs from the device; stock base is incompatible"
            );
        }
    }
    for name in t.keys() {
        ensure!(
            c.contains_key(name) || modified.contains(&name.as_str()),
            "device has an unsupported retained partition {name}"
        );
    }
    Ok(())
}
pub fn select_rollback(
    candidate: &BTreeMap<String, Metadata>,
    target: &BTreeMap<String, Metadata>,
) -> Result<BTreeMap<String, Rollback>> {
    ensure!(
        PERSONALIZED
            .iter()
            .all(|n| candidate.contains_key(*n) && target.contains_key(*n)),
        "missing AVB chain image"
    );
    ensure!(
        candidate["vbmeta"].info["rollback_index_location"] == 0
            && target["vbmeta"].info["rollback_index_location"] == 0,
        "unsupported root rollback location"
    );
    let chains = candidate["vbmeta"].chains()?;
    ensure!(
        chains == target["vbmeta"].chains()?,
        "target AVB chain locations differ"
    );
    ensure!(
        chains
            .keys()
            .all(|n| ["boot", "recovery", "vbmeta_system"].contains(&n.as_str()))
            && chains.contains_key("boot")
            && chains.contains_key("vbmeta_system"),
        "unsupported AVB chain layout"
    );
    let locations: BTreeSet<_> = chains.values().collect();
    ensure!(
        locations.len() == chains.len(),
        "AVB chain locations overlap"
    );
    unchanged_descriptors(
        &candidate["vbmeta"],
        &target["vbmeta"],
        &[
            "boot",
            "init_boot",
            "vendor_boot",
            "vendor",
            "vbmeta_system",
        ],
    )?;
    unchanged_descriptors(
        &candidate["vbmeta_system"],
        &target["vbmeta_system"],
        &["system", "product", "system_ext"],
    )?;
    let mut out = BTreeMap::new();
    for name in PERSONALIZED {
        let c = &candidate[*name];
        let t = &target[*name];
        ensure!(
            c.info["rollback_index_location"] == t.info["rollback_index_location"],
            "target header rollback location differs: {name}"
        );
        out.insert(
            (*name).into(),
            Rollback {
                location: if *name == "vbmeta" { 0 } else { chains[*name] },
                value: t.index()?,
                source: format!("readback:{name}_a"),
                protected_floor: None,
            },
        );
    }
    Ok(out)
}
pub struct Prepare<'a> {
    pub package: &'a Path,
    pub work: &'a Path,
    pub device: &'a dyn Device,
    pub tools: &'a Tools,
    pub root_key: &'a Path,
    pub system_key: &'a Path,
}
pub fn prepare(r: Prepare<'_>) -> Result<Plan> {
    ensure!(
        !r.work.exists(),
        "work directory already exists; keep existing plans/backups intact"
    );
    for input in [
        r.package,
        r.root_key,
        r.system_key,
        r.tools.avbtool.as_path(),
    ] {
        gb_core::separate_from_input(input, r.work)?;
    }
    let manifest: Manifest = checked_json(&r.package.join("manifest.json"))?;
    ensure!(
        manifest.schema_version == 1
            && manifest.device == "TB710FU"
            && manifest.images.len() == 9
            && PARTITIONS.iter().all(|n| manifest.images.contains_key(*n))
            && manifest.metadata["installation"]["requires_device_personalization"] == true,
        "release is not a device-personalized TB710FU template package; old ready-to-flash packages are refused"
    );
    let tool_identity = r.device.tools()?;
    let identity = r.device.identity()?;
    identity.validate()?;
    let parent = r
        .work
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let bytes = manifest
        .images
        .values()
        .try_fold(512 * 1024 * 1024_u64, |a, b| {
            a.checked_add(b.image_bytes)
                .context("disk requirement overflow")
        })?;
    ensure!(
        fs2::available_space(parent)? > bytes,
        "insufficient free disk space for staging and readbacks"
    );
    let staging = tempfile::tempdir_in(parent)?;
    let images = staging.path().join("images");
    let backups = staging.path().join("device-backup");
    fs::create_dir(&images)?;
    fs::create_dir(&backups)?;
    let layout = layout::capture(r.device, &backups)?;
    ensure!(
        layout.identity == identity,
        "device identity changed during discovery"
    );
    let mut target = BTreeMap::new();
    let mut backup_images = BTreeMap::new();
    for name in PERSONALIZED {
        let p = backups.join(format!("{name}.img"));
        let range = &layout.partitions[*name];
        ensure!(
            range.bytes()?
                <= if *name == "boot" {
                    128 * 1024 * 1024
                } else {
                    1024 * 1024
                },
            "AVB readback exceeds bound"
        );
        r.device.read(range, &p)?;
        target.insert((*name).into(), Metadata::read(&p)?);
        backup_images.insert(
            (*name).into(),
            Image {
                filename: format!("{name}.img"),
                bytes: fs::metadata(&p)?.len(),
                sha256: hash_file(&p)?,
            },
        );
    }
    let signature_scratch = tempfile::tempdir_in(staging.path())?;
    for metadata in target.values() {
        r.tools
            .verify_embedded(metadata, signature_scratch.path())?;
    }
    verify_chain_keys(&target)?;
    verify_device_fingerprint(&target["boot"])?;
    let mut output = BTreeMap::new();
    let mut candidate = BTreeMap::new();
    for name in PARTITIONS {
        eprintln!("Checking and unpacking {name}");
        let image = unpack(r.package, &images, name, &manifest.images[*name])?;
        let metadata = Metadata::read(&images.join(&image.filename))?;
        ensure!(
            metadata.index()? == 0,
            "release contains a non-neutral AVB template; refusing to import its rollback index"
        );
        if PERSONALIZED.contains(name) {
            candidate.insert((*name).into(), metadata);
        }
        output.insert((*name).into(), image);
    }
    let rollback = select_rollback(&candidate, &target)?;
    verify_chain_keys(&candidate)?;
    for name in PERSONALIZED {
        let path = images.join(format!("{name}.img"));
        let signed = images.join(format!("{name}.signed.img"));
        r.tools.resign(
            &path,
            &signed,
            if *name == "vbmeta_system" {
                r.system_key
            } else {
                r.root_key
            },
            rollback[*name].value,
        )?;
        ensure!(
            avb::payload_equal(&path, &signed)?,
            "personalization altered partition payload"
        );
        fs::remove_file(&path)?;
        fs::rename(&signed, &path)?;
        output.get_mut(*name).context("missing output")?.sha256 = hash_file(&path)?;
    }
    let writes = layout::writes(&layout, &output)?;
    let plan = Plan {
        schema_version:2, status:"prepared_not_flashed".into(),device:"TB710FU".into(),serial:identity.serial,
        slot:"a".into(),layout,writes,images:output,backups:backup_images,rollback,
        tools:json!({"edl":tool_identity,"python":run_tool(&r.tools.python,&["--version".into()],Duration::from_secs(10))?.stdout,
            "avbtool_sha256":hash_file(&r.tools.avbtool)?,"openssl":run_tool(&r.tools.openssl,&["version".into()],Duration::from_secs(10))?.stdout}),
        firmware_written:false,runtime_verified:false,
        limitations:vec![
            "Indices are copied separately from this device's signed AVB images, not protected rollback storage.".into(),
            "Protected rollback floors and OEM boot acceptance remain unverified. No floor is lowered, erased, disabled or incremented.".into(),
            "EDL only: qualified stock programmer, current slot A, matching stock base and unchanged GPT/LP layout required. No bootloader-state or signature-acceptance bypass is implemented.".into(),
            "Readbacks here cover GPT, LP metadata and three AVB images; they are not a complete stock backup.".into(),
            "The EDL method has worked on the development tablet; this public installer has not been qualified on a second tablet or on native Windows/macOS USB.".into(),
        ],
    };
    write_json(&staging.path().join("install-plan.json"), &plan)?;
    drop(signature_scratch);
    let path = staging.keep();
    fs::rename(&path, r.work).inspect_err(|_| {
        let _ = fs::remove_dir_all(&path);
    })?;
    Ok(plan)
}
fn verify_chain_keys(m: &BTreeMap<String, Metadata>) -> Result<()> {
    let d = &m["vbmeta"].descriptor_bytes;
    let mut pos = 0;
    while pos < d.len() {
        let tag = u64::from_be_bytes(d[pos..pos + 8].try_into()?);
        let size = usize::try_from(u64::from_be_bytes(d[pos + 8..pos + 16].try_into()?))? + 16;
        let e = d.get(pos..pos + size).context("chain descriptor bounds")?;
        if tag == 4 {
            let n = u32::from_be_bytes(e[20..24].try_into()?) as usize;
            let k = u32::from_be_bytes(e[24..28].try_into()?) as usize;
            let name = std::str::from_utf8(&e[92..92 + n])?;
            if let Some(child) = m.get(name) {
                ensure!(
                    e.get(92 + n..92 + n + k) == Some(child.public_key.as_slice()),
                    "AVB chain key mismatch: {name}"
                );
            }
        }
        pos += size;
    }
    Ok(())
}
pub fn load_plan(work: &Path) -> Result<Plan> {
    let p: Plan = checked_json(&work.join("install-plan.json"))?;
    ensure!(
        p.schema_version == 2
            && p.device == "TB710FU"
            && p.slot == "a"
            && p.status == "prepared_not_flashed"
            && !p.firmware_written
            && p.images.len() == 9
            && PARTITIONS.iter().all(|n| p.images.contains_key(*n))
            && p.backups.len() == 3
            && PERSONALIZED.iter().all(|n| p.backups.contains_key(*n))
            && p.rollback.len() == 3
            && PERSONALIZED.iter().all(|n| p.rollback.contains_key(*n)),
        "invalid installation plan"
    );
    p.layout.identity.validate()?;
    ensure!(
        p.serial == p.layout.identity.serial && p.writes == layout::writes(&p.layout, &p.images)?,
        "invalid EDL identity or write map"
    );
    ensure!(
        p.layout.guards.len() <= 34 && !p.layout.guards.is_empty(),
        "invalid metadata guards"
    );
    for g in &p.layout.guards {
        ensure!(
            g.filename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && !g.filename.contains("..")
                && digest_ok(&g.sha256),
            "unsafe metadata guard"
        );
        g.range.bytes()?;
    }
    for (n, i) in p.images.iter().chain(p.backups.iter()) {
        ensure!(
            i.filename == format!("{n}.img") && digest_ok(&i.sha256) && i.bytes > 0,
            "unsafe image plan entry"
        );
    }
    Ok(p)
}
/// Offline preview, with no transport calls or implicit resets.
pub fn commands(plan: &Plan, work: &Path) -> Vec<Value> {
    PARTITIONS.iter().map(|n|json!({"operation":"program_and_verify_sha256","partition":format!("{n}_a"),
        "range":plan.writes[*n],"image":work.join("images").join(format!("{n}.img")),"sha256":plan.images[*n].sha256})).collect()
}

pub fn flash(
    work: &Path,
    device: &dyn Device,
    confirm: impl FnOnce(&Plan) -> Result<bool>,
) -> Result<()> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(work.join(".install-lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("another installer owns this work directory")?;
    let plan = load_plan(work)?;
    ensure!(
        !work.join("flash-journal.json").exists(),
        "a prior flash attempt exists; inspect the journal and recover manually rather than replaying it"
    );
    ensure!(
        device.tools()? == plan.tools["edl"],
        "EDL tools changed since preparation"
    );
    ensure!(
        device.identity()? == plan.layout.identity,
        "wrong UFS identity"
    );
    for (n, i) in &plan.images {
        let p = work.join("images").join(&i.filename);
        ensure!(
            fs::symlink_metadata(&p)?.file_type().is_file()
                && fs::metadata(&p)?.len() == i.bytes
                && hash_file(&p)? == i.sha256,
            "prepared image changed: {n}"
        );
    }
    let check = tempfile::tempdir_in(work)?;
    let current_layout = layout::capture(device, check.path())?;
    ensure!(
        current_layout == plan.layout
            && layout::writes(&current_layout, &plan.images)? == plan.writes,
        "GPT/LP mapping changed since preparation"
    );
    for name in PERSONALIZED {
        let saved = work.join("device-backup").join(format!("{name}.img"));
        ensure!(
            hash_file(&saved)? == plan.backups[*name].sha256,
            "saved AVB readback changed"
        );
        // One bounded readback per AVB partition, instead of a multi-gigabyte verification pass.
        let p = check.path().join(format!("{name}.img"));
        device.read(&current_layout.partitions[*name], &p)?;
        ensure!(
            hash_file(&p)? == plan.backups[*name].sha256,
            "device AVB state changed since preparation"
        );
        let current = Metadata::read(&saved)?;
        let prepared = Metadata::read(&work.join("images").join(format!("{name}.img")))?;
        ensure!(
            current.index()? == prepared.index()? && current.index()? == plan.rollback[*name].value,
            "prepared rollback differs from device readback"
        );
    }
    ensure!(confirm(&plan)?, "flash cancelled; no firmware written");
    let mut journal = json!({"schema_version":2,"transport":"edl","serial":plan.serial,
        "plan_sha256":hash_file(&work.join("install-plan.json"))?,"status":"in_progress","completed":[],"pending":null,"automatic_reboot":false});
    write_json(&work.join("flash-journal.json"), &journal)?;
    for name in PARTITIONS {
        checkpoint()?;
        journal["pending"] = json!({"partition":format!("{name}_a"),"range":plan.writes[*name],"sha256":plan.images[*name].sha256});
        write_json(&work.join("flash-journal.json"), &journal)?;
        eprintln!("EDL program and device SHA-256: {name}_a");
        device.program(&plan.writes[*name], &work.join("images").join(format!("{name}.img")), &plan.images[*name].sha256)
            .context("EDL write/digest failed; leave the tablet in EDL and inspect flash-journal.json; no automatic reset or retry")?;
        let completed = journal["pending"].clone();
        journal["completed"]
            .as_array_mut()
            .context("journal array")?
            .push(completed);
        journal["pending"] = Value::Null;
        write_json(&work.join("flash-journal.json"), &journal)?;
    }
    journal["status"] = json!("written_digest_verified_pending_recovery_and_runtime_validation");
    write_json(&work.join("flash-journal.json"), &journal)?;
    Ok(())
}
/// Reset is separate from flashing and only available for a fully verified plan.
pub fn reset(work: &Path, device: &dyn Device) -> Result<()> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(work.join(".install-lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)?;
    let p = load_plan(work)?;
    let j: Value = checked_json(&work.join("flash-journal.json"))?;
    ensure!(
        j["status"] == "written_digest_verified_pending_recovery_and_runtime_validation"
            && j["plan_sha256"] == hash_file(&work.join("install-plan.json"))?
            && j["serial"] == p.serial
            && j["pending"].is_null()
            && j["completed"]
                .as_array()
                .is_some_and(|a| a.len() == PARTITIONS.len()),
        "reset requires this plan's completed verified flash"
    );
    ensure!(
        device.tools()? == p.tools["edl"] && device.identity()? == p.layout.identity,
        "device or tools differ"
    );
    device.reset()
}

pub const STOCK_BOOT_FINGERPRINT: &str =
    "Lenovo/TB710FU/TB710FU:15/AQ3A.250129.001/ZUI_17.5.04.059_260327_ROW:user/release-keys";
fn verify_device_fingerprint(boot: &Metadata) -> Result<()> {
    let d = &boot.descriptor_bytes;
    let mut pos = 0;
    let mut values = BTreeSet::new();
    while pos < d.len() {
        let tag = u64::from_be_bytes(d.get(pos..pos + 8).context("descriptor tag")?.try_into()?);
        let size = usize::try_from(u64::from_be_bytes(
            d.get(pos + 8..pos + 16)
                .context("descriptor size")?
                .try_into()?,
        ))?
        .checked_add(16)
        .context("descriptor overflow")?;
        let e = d
            .get(pos..pos.checked_add(size).context("descriptor overflow")?)
            .context("descriptor bounds")?;
        if tag == 0 {
            let key_len = usize::try_from(u64::from_be_bytes(
                e.get(16..24).context("property key length")?.try_into()?,
            ))?;
            let value_len = usize::try_from(u64::from_be_bytes(
                e.get(24..32).context("property value length")?.try_into()?,
            ))?;
            let end = 32_usize.checked_add(key_len).context("property overflow")?;
            let start = end.checked_add(1).context("property overflow")?;
            let value_end = start.checked_add(value_len).context("property overflow")?;
            let key = e.get(32..end).context("property key bounds")?;
            let value = e.get(start..value_end).context("property value bounds")?;
            if key == b"com.android.build.boot.fingerprint" {
                values.insert(std::str::from_utf8(value)?.to_owned());
            }
        }
        pos += size;
    }
    ensure!(
        values.len() == 1 && values.contains(STOCK_BOOT_FINGERPRINT),
        "device boot fingerprint is not the qualified TB710FU ZUI base"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata(index: u64) -> Metadata {
        Metadata {
            offset: 0,
            blob: vec![],
            info: json!({"rollback_index":index,"rollback_index_location":0,"descriptors":[]}),
            public_key: vec![],
            public_key_metadata: vec![],
            descriptor_bytes: vec![],
        }
    }
    #[test]
    fn indices_are_copied_per_chain_location_without_increment() {
        let mut c: BTreeMap<String, Metadata> = PERSONALIZED
            .iter()
            .map(|n| ((*n).into(), metadata(0)))
            .collect();
        let chains = json!([{"tag":4,"partition":"boot","rollback_index_location":1,"sha256":"boot-key"},{"tag":4,"partition":"recovery","rollback_index_location":2,"sha256":"recovery-key"},{"tag":4,"partition":"vbmeta_system","rollback_index_location":3,"sha256":"system-key"}]);
        c.get_mut("vbmeta").unwrap().info["descriptors"] = chains;
        let mut t = c.clone();
        for (name, index) in [("vbmeta", 42), ("boot", 7), ("vbmeta_system", 61)] {
            t.get_mut(name).unwrap().info["rollback_index"] = json!(index);
        }
        let result = select_rollback(&c, &t).unwrap();
        assert_eq!(result["vbmeta"].value, 42);
        assert_eq!(result["boot"].value, 7);
        assert_eq!(result["vbmeta_system"].value, 61);
        assert_eq!(result["vbmeta_system"].location, 3);
        assert!(result.values().all(|r| r.protected_floor.is_none()));
        t.get_mut("vbmeta").unwrap().info["descriptors"][1]["sha256"] =
            json!("different-stock-recovery");
        assert!(select_rollback(&c, &t).is_err());
    }
    #[test]
    fn malformed_avb_input_returns_an_error() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("bad.img");
        for len in [0, 1, 64, 255, 4096] {
            fs::write(&p, vec![0; len]).unwrap();
            assert!(Metadata::read(&p).is_err());
        }
    }
}
