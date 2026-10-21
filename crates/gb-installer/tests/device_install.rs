//! Real AOSP/OpenSSL signing with a simulated USB backend. Never uses real USB.
#![cfg(unix)]
use gb_core::hash_file;
use gb_installer::{
    Prepare,
    avb::{Metadata, Tools},
    edl::{Device, Identity, Range},
};
use serde_json::json;
use std::{
    cell::RefCell,
    io::{Read, Seek, SeekFrom},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

fn run(program: &str, args: &[String]) {
    let o = Command::new(program).args(args).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}
fn avb(script: &Path, args: &[String]) {
    let mut a = vec![script.display().to_string()];
    a.extend_from_slice(args);
    run("python3", &a);
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    package: PathBuf,
    work: PathBuf,
    edl: Disk,
    tools: Tools,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().to_owned();
        let package = root.join("package");
        let device = root.join("device");
        let work = root.join("work");
        fs::create_dir(&package).unwrap();
        fs::create_dir(&device).unwrap();
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../third_party/avb/avbtool.py")
            .canonicalize()
            .unwrap();
        let key = root.join("key.pem");
        let pubkey = root.join("key.pub");
        run(
            "openssl",
            &[
                "genrsa".into(),
                "-out".into(),
                key.display().to_string(),
                "2048".into(),
            ],
        );
        avb(
            &script,
            &[
                "extract_public_key".into(),
                "--key".into(),
                key.display().to_string(),
                "--output".into(),
                pubkey.display().to_string(),
            ],
        );
        for name in gb_installer::PARTITIONS {
            let image = root.join(format!("{name}.img"));
            if ["vbmeta", "vbmeta_system"].contains(name) {
                let mut a = vec![
                    "make_vbmeta_image".into(),
                    "--output".into(),
                    image.display().to_string(),
                    "--algorithm".into(),
                    "SHA256_RSA2048".into(),
                    "--key".into(),
                    key.display().to_string(),
                    "--padding_size".into(),
                    "4096".into(),
                ];
                if *name == "vbmeta" {
                    for (n, l) in [("boot", 1), ("recovery", 2), ("vbmeta_system", 3)] {
                        a.extend([
                            "--chain_partition".into(),
                            format!("{n}:{l}:{}", pubkey.display()),
                        ]);
                    }
                }
                avb(&script, &a);
            } else {
                fs::write(&image, vec![17_u8; 4096]).unwrap();
                avb(
                    &script,
                    &[
                        "add_hash_footer".into(),
                        "--image".into(),
                        image.display().to_string(),
                        "--partition_name".into(),
                        (*name).into(),
                        "--partition_size".into(),
                        "131072".into(),
                        "--algorithm".into(),
                        "SHA256_RSA2048".into(),
                        "--key".into(),
                        key.display().to_string(),
                        "--prop".into(),
                        format!(
                            "com.android.build.boot.fingerprint:{}",
                            gb_installer::STOCK_BOOT_FINGERPRINT
                        ),
                        "--salt".into(),
                        "11".into(),
                    ],
                );
            }
        }
        let tools = Tools {
            python: "python3".into(),
            avbtool: script,
            openssl: "openssl".into(),
        };
        for (name, index) in [("vbmeta", 42), ("vbmeta_system", 61), ("boot", 7)] {
            tools
                .resign(
                    &root.join(format!("{name}.img")),
                    &device.join(format!("{name}.img")),
                    &key,
                    index,
                )
                .unwrap();
        }
        let mut entries = serde_json::Map::new();
        for name in gb_installer::PARTITIONS {
            let image = root.join(format!("{name}.img"));
            let gz = package.join(format!("{name}.img.gz"));
            let data = fs::read(&image).unwrap();
            let mut enc = flate2::GzBuilder::new()
                .mtime(0)
                .write(fs::File::create(&gz).unwrap(), flate2::Compression::fast());
            enc.write_all(&data).unwrap();
            enc.finish().unwrap();
            entries.insert((*name).into(),json!({"filename":format!("{name}.img.gz"),"bytes":fs::metadata(&gz).unwrap().len(),"sha256":hash_file(&gz).unwrap(),"image_bytes":data.len(),"image_sha256":hash_file(&image).unwrap(),"roundtrip_verified":true}));
        }
        fs::write(package.join("manifest.json"),serde_json::to_vec_pretty(&json!({"schema_version":1,"device":"TB710FU","images":entries,"metadata":{"installation":{"requires_device_personalization":true}}})).unwrap()).unwrap();
        let edl = Disk::new(&root);
        Self {
            _temp: t,
            root,
            package,
            work,
            edl,
            tools,
            key,
        }
    }
    fn prepare(&self) -> anyhow::Result<gb_installer::Plan> {
        gb_installer::prepare(Prepare {
            package: &self.package,
            work: &self.work,
            device: &self.edl,
            tools: &self.tools,
            root_key: &self.key,
            system_key: &self.key,
        })
    }
    fn calls(&self) -> Vec<String> {
        self.edl.calls.borrow().clone()
    }
}

#[derive(Debug)]
struct Disk {
    root: PathBuf,
    calls: RefCell<Vec<String>>,
}
impl Disk {
    fn new(root: &Path) -> Self {
        let mut disk = vec![0_u8; 4 * 1024 * 1024];
        let entries = gpt_entries();
        disk[2 * 4096..2 * 4096 + entries.len()].copy_from_slice(&entries);
        disk[1019 * 4096..1019 * 4096 + entries.len()].copy_from_slice(&entries);
        disk[4096..8192].copy_from_slice(&gpt_header(false, &entries));
        disk[1023 * 4096..1024 * 4096].copy_from_slice(&gpt_header(true, &entries));
        let lp = lp_prefix();
        disk[128 * 4096..128 * 4096 + lp.len()].copy_from_slice(&lp);
        for (name, sector) in [("boot", 512), ("vbmeta_system", 640), ("vbmeta", 641)] {
            let bytes = fs::read(root.join("device").join(format!("{name}.img"))).unwrap();
            disk[sector * 4096..sector * 4096 + bytes.len()].copy_from_slice(&bytes);
        }
        fs::write(root.join("lun.img"), disk).unwrap();
        Self {
            root: root.into(),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn marker(&self, name: &str) -> bool {
        self.root.join(name).exists()
    }
    fn change(&self, offset: u64) {
        use std::io::{Seek, Write};
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root.join("lun.img"))
            .unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        let mut byte = [0];
        f.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&byte).unwrap();
    }
}
impl Device for Disk {
    fn tools(&self) -> anyhow::Result<serde_json::Value> {
        Ok(json!({"transport":"simulated_edl"}))
    }
    fn identity(&self) -> anyhow::Result<Identity> {
        anyhow::ensure!(!self.marker("wrong-device"), "wrong UFS serial");
        Ok(Identity {
            serial: "TESTUFS".into(),
            sector_bytes: 4096,
            luns: 1,
            memory: "ufs".into(),
            product: "fixture".into(),
        })
    }
    fn read(&self, r: &Range, out: &Path) -> anyhow::Result<()> {
        self.calls.borrow_mut().push("read".into());
        self.identity()?;
        anyhow::ensure!(!self.marker("no-read"), "read NACK");
        let mut f = fs::File::open(self.root.join("lun.img"))?;
        f.seek(SeekFrom::Start(r.start_sector * 4096))?;
        let mut bytes = vec![0; r.bytes()? as usize];
        f.read_exact(&mut bytes)?;
        fs::write(out, bytes)?;
        Ok(())
    }
    fn digest(&self, r: &Range) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};
        let mut f = fs::File::open(self.root.join("lun.img"))?;
        f.seek(SeekFrom::Start(r.start_sector * 4096))?;
        let mut bytes = vec![0; r.bytes()? as usize];
        f.read_exact(&mut bytes)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    fn program(&self, r: &Range, source: &Path, expected: &str) -> anyhow::Result<()> {
        self.identity()?;
        self.calls
            .borrow_mut()
            .push(source.file_name().unwrap().to_str().unwrap().into());
        anyhow::ensure!(
            !(source.file_name().unwrap() == "product.img" && self.marker("fail-product")),
            "program NACK"
        );
        let bytes = fs::read(source)?;
        anyhow::ensure!(bytes.len() as u64 == r.bytes()?, "range mismatch");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(self.root.join("lun.img"))?;
        f.seek(SeekFrom::Start(r.start_sector * 4096))?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        anyhow::ensure!(
            !self.marker("bad-digest") && self.digest(r)? == expected,
            "device digest mismatch"
        );
        Ok(())
    }
    fn reset(&self) -> anyhow::Result<()> {
        self.calls.borrow_mut().push("reset".into());
        Ok(())
    }
}
fn le32(b: &mut [u8], p: usize, v: u32) {
    b[p..p + 4].copy_from_slice(&v.to_le_bytes())
}
fn le64(b: &mut [u8], p: usize, v: u64) {
    b[p..p + 8].copy_from_slice(&v.to_le_bytes())
}
fn gpt_entries() -> Vec<u8> {
    let mut t = vec![0; 128 * 128];
    for (i, (name, start, n)) in [
        ("super", 128, 256),
        ("boot_a", 512, 32),
        ("boot_b", 544, 32),
        ("init_boot_a", 576, 32),
        ("vendor_boot_a", 608, 32),
        ("vbmeta_system_a", 640, 1),
        ("vbmeta_a", 641, 1),
        ("userdata", 700, 32),
    ]
    .iter()
    .enumerate()
    {
        let e = &mut t[i * 128..(i + 1) * 128];
        e[0] = 1;
        e[16] = i as u8 + 1;
        le64(e, 32, *start);
        le64(e, 40, start + n - 1);
        if *name == "boot_a" {
            le64(e, 48, 1 << 50)
        }
        for (j, c) in name.encode_utf16().enumerate() {
            e[56 + j * 2..58 + j * 2].copy_from_slice(&c.to_le_bytes());
        }
    }
    t
}
fn gpt_header(backup: bool, table: &[u8]) -> Vec<u8> {
    let mut h = vec![0; 4096];
    h[..8].copy_from_slice(b"EFI PART");
    le32(&mut h, 8, 0x10000);
    le32(&mut h, 12, 92);
    le64(&mut h, 24, if backup { 1023 } else { 1 });
    le64(&mut h, 32, if backup { 1 } else { 1023 });
    le64(&mut h, 40, 6);
    le64(&mut h, 48, 1018);
    h[56] = 1;
    le64(&mut h, 72, if backup { 1019 } else { 2 });
    le32(&mut h, 80, 128);
    le32(&mut h, 84, 128);
    le32(&mut h, 88, crc32fast::hash(table));
    let crc = crc32fast::hash(&h[..92]);
    le32(&mut h, 16, crc);
    h
}
fn lp_prefix() -> Vec<u8> {
    lp_prefix_flags(1)
}
fn lp_prefix_flags(flags: u32) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = vec![0; 28672];
    let mut g = vec![0; 52];
    le32(&mut g, 0, 0x616c4467);
    le32(&mut g, 4, 52);
    le32(&mut g, 40, 4096);
    le32(&mut g, 44, 2);
    le32(&mut g, 48, 4096);
    let hash = Sha256::digest(&g);
    g[8..40].copy_from_slice(&hash);
    out[4096..4148].copy_from_slice(&g);
    out[8192..8244].copy_from_slice(&g);
    let mut t = vec![0; 4 * 52 + 4 * 24 + 48 + 64];
    for (i, name) in ["system_a", "product_a", "system_ext_a", "vendor_a"]
        .iter()
        .enumerate()
    {
        let e = &mut t[i * 52..(i + 1) * 52];
        e[..name.len()].copy_from_slice(name.as_bytes());
        le32(e, 36, 1);
        le32(e, 40, i as u32);
        le32(e, 44, 1);
    }
    for i in 0..4 {
        let e = &mut t[208 + i * 24..208 + (i + 1) * 24];
        le64(e, 0, 256);
        le64(e, 12, 64 + i as u64 * 256);
    }
    t[304..311].copy_from_slice(b"default");
    le64(&mut t, 344, 1024 * 1024);
    le64(&mut t, 352, 64);
    le32(&mut t, 360, 4096);
    le64(&mut t, 368, 1024 * 1024);
    t[376..381].copy_from_slice(b"super");
    let mut h = vec![0; 256];
    le32(&mut h, 0, 0x414c5030);
    h[4..6].copy_from_slice(&10_u16.to_le_bytes());
    h[6..8].copy_from_slice(&2_u16.to_le_bytes());
    le32(&mut h, 8, 256);
    le32(&mut h, 128, flags);
    le32(&mut h, 44, t.len() as u32);
    h[48..80].copy_from_slice(&Sha256::digest(&t));
    for (o, start, count, size) in [
        (80, 0, 4, 52),
        (92, 208, 4, 24),
        (104, 304, 1, 48),
        (116, 352, 1, 64),
    ] {
        le32(&mut h, o, start);
        le32(&mut h, o + 4, count);
        le32(&mut h, o + 8, size);
    }
    let hash = Sha256::digest(&h);
    h[12..44].copy_from_slice(&hash);
    let mut slot = vec![0; 4096];
    slot[..256].copy_from_slice(&h);
    slot[256..256 + t.len()].copy_from_slice(&t);
    for i in 0..4 {
        out[12288 + i * 4096..12288 + (i + 1) * 4096].copy_from_slice(&slot);
    }
    out
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated EDL only"]
fn signed_personalization_preview_and_partial_failure_are_device_bound() {
    let f = Fixture::new();
    let plan = f.prepare().unwrap();
    for (name, index) in [("vbmeta", 42), ("vbmeta_system", 61), ("boot", 7)] {
        let p = f.work.join("images").join(format!("{name}.img"));
        assert_eq!(Metadata::read(&p).unwrap().index().unwrap(), index);
        assert_eq!(plan.rollback[name].value, index);
        assert!(gb_installer::avb::payload_equal(&f.root.join(format!("{name}.img")), &p).unwrap());
    }
    assert!(f.calls().iter().all(|a| a == "read"));
    let before = f.calls().len();
    let o = Command::new(env!("CARGO_BIN_EXE_gb-install"))
        .args([
            "flash",
            "--work",
            f.work.to_str().unwrap(),
            "--serial",
            "TESTUFS",
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(before, f.calls().len());
    assert!(gb_installer::flash(&f.work, &f.edl, |_| Ok(false)).is_err());
    assert!(!f.work.join("flash-journal.json").exists());
    fs::write(f.root.join("fail-product"), b"").unwrap();
    assert!(gb_installer::flash(&f.work, &f.edl, |_| Ok(true)).is_err());
    let count = f.calls().len();
    assert!(gb_installer::flash(&f.work, &f.edl, |_| Ok(true)).is_err());
    assert_eq!(count, f.calls().len());
    let j: serde_json::Value =
        serde_json::from_slice(&fs::read(f.work.join("flash-journal.json")).unwrap()).unwrap();
    assert_eq!(j["status"], "in_progress");
    assert_eq!(j["completed"].as_array().unwrap().len(), 1);
    assert_eq!(j["pending"]["partition"], "product_a");
    assert!(gb_installer::reset(&f.work, &f.edl).is_err());
    assert!(!f.calls().contains(&"reset".into()));
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated EDL only"]
fn unknown_device_bad_metadata_and_corruption_fail_without_writes() {
    let f = Fixture::new();
    for marker in ["wrong-device", "no-read"] {
        fs::write(f.root.join(marker), b"").unwrap();
        assert!(f.prepare().is_err());
        assert!(!f.work.exists());
        fs::remove_file(f.root.join(marker)).unwrap();
    }
    let disk = fs::read(f.root.join("lun.img")).unwrap();
    // Primary CRC, backup header, LP slot disagreement, signed AVB rollback corruption.
    for offset in [
        4096 + 16,
        1023 * 4096 + 16,
        128 * 4096 + 12288 + 4096 + 40,
        641 * 4096 + 119,
    ] {
        f.edl.change(offset);
        assert!(f.prepare().is_err(), "offset {offset}");
        assert!(!f.work.exists());
        fs::write(f.root.join("lun.img"), &disk).unwrap();
    }
    let p = f.package.join("manifest.json");
    let original = fs::read(&p).unwrap();
    let mut m: serde_json::Value = serde_json::from_slice(&original).unwrap();
    m["images"]["system"]["filename"] = json!("../escape.img.gz");
    fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
    assert!(f.prepare().is_err());
    fs::write(&p, original).unwrap();
    fs::write(f.package.join("system.img.gz"), b"bad archive").unwrap();
    assert!(f.prepare().is_err());
    assert!(f.calls().iter().all(|a| a == "read"));
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated EDL only"]
fn full_edl_flash_verifies_nine_ranges_and_preserves_retained_bytes() {
    let f = Fixture::new();
    let before = fs::read(f.root.join("lun.img")).unwrap();
    let p = f.prepare().unwrap();
    gb_installer::flash(&f.work, &f.edl, |_| Ok(true)).unwrap();
    let flashed: Vec<_> = f
        .calls()
        .into_iter()
        .filter(|s| s.ends_with(".img"))
        .collect();
    assert_eq!(
        flashed,
        gb_installer::PARTITIONS
            .iter()
            .map(|n| format!("{n}.img"))
            .collect::<Vec<_>>()
    );
    let mut expected = before;
    for n in gb_installer::PARTITIONS {
        let r = &p.writes[*n];
        let bytes = fs::read(f.work.join("images").join(format!("{n}.img"))).unwrap();
        expected[r.start_sector as usize * 4096..r.start_sector as usize * 4096 + bytes.len()]
            .copy_from_slice(&bytes);
    }
    assert_eq!(fs::read(f.root.join("lun.img")).unwrap(), expected);
    let j: serde_json::Value =
        serde_json::from_slice(&fs::read(f.work.join("flash-journal.json")).unwrap()).unwrap();
    assert_eq!(
        j["status"],
        "written_digest_verified_pending_recovery_and_runtime_validation"
    );
    assert_eq!(j["automatic_reboot"], false);
    assert!(!f.calls().contains(&"reset".into()));
    gb_installer::reset(&f.work, &f.edl).unwrap();
    assert_eq!(f.calls().last().unwrap(), "reset");
}
#[test]
#[ignore = "requires host Python3 and OpenSSL; simulated EDL only"]
fn changed_layout_and_failed_device_digest_stop_before_further_writes() {
    let f = Fixture::new();
    f.prepare().unwrap();
    let disk = fs::read(f.root.join("lun.img")).unwrap();
    f.edl.change(4096 + 16);
    assert!(gb_installer::flash(&f.work, &f.edl, |_| Ok(true)).is_err());
    assert!(!f.work.join("flash-journal.json").exists());
    fs::write(f.root.join("lun.img"), disk).unwrap();
    fs::write(f.root.join("bad-digest"), b"").unwrap();
    assert!(gb_installer::flash(&f.work, &f.edl, |_| Ok(true)).is_err());
    let writes: Vec<_> = f
        .calls()
        .into_iter()
        .filter(|s| s.ends_with(".img"))
        .collect();
    assert_eq!(writes, vec!["system.img"]);
    assert!(gb_installer::reset(&f.work, &f.edl).is_err());
}
#[test]
fn gpt_lp_mapping_checks_primary_backup_active_slot_and_image_sizes() {
    // Parser-only fixture does not require signing tools or USB.
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join("device")).unwrap();
    for n in ["boot", "vbmeta", "vbmeta_system"] {
        fs::write(
            t.path().join("device").join(format!("{n}.img")),
            vec![0; 4096],
        )
        .unwrap();
    }
    let d = Disk::new(t.path());
    let out = tempfile::tempdir().unwrap();
    let l = gb_installer::layout::capture(&d, out.path()).unwrap();
    assert_eq!(l.partitions["system"].start_sector, 136);
    assert_eq!(l.partitions["vbmeta"].start_sector, 641);
    assert_eq!(l.guards.len(), 6);
    let mut images = std::collections::BTreeMap::new();
    for n in gb_installer::PARTITIONS {
        images.insert(
            (*n).into(),
            gb_installer::Image {
                filename: format!("{n}.img"),
                bytes: l.partitions[*n].bytes().unwrap(),
                sha256: "a".repeat(64),
            },
        );
    }
    assert!(gb_installer::layout::writes(&l, &images).is_ok());
    images.get_mut("system").unwrap().bytes -= 4096;
    assert!(gb_installer::layout::writes(&l, &images).is_err());
    let disk = fs::read(t.path().join("lun.img")).unwrap();
    for offset in [
        4096 + 16,
        1023 * 4096 + 16,
        128 * 4096 + 8192 + 8,
        128 * 4096 + 12288 + 4096,
    ] {
        d.change(offset);
        let tmp = tempfile::tempdir().unwrap();
        assert!(gb_installer::layout::capture(&d, tmp.path()).is_err());
        fs::write(t.path().join("lun.img"), &disk).unwrap();
    }
}

#[test]
fn virtual_ab_header_is_supported_but_active_overlays_are_blocked() {
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join("device")).unwrap();
    for n in ["boot", "vbmeta", "vbmeta_system"] {
        fs::write(
            t.path().join("device").join(format!("{n}.img")),
            vec![0; 4096],
        )
        .unwrap();
    }
    let d = Disk::new(t.path());
    for flags in [2, 3, 4] {
        let lp = lp_prefix_flags(flags);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(t.path().join("lun.img"))
            .unwrap();
        f.seek(SeekFrom::Start(128 * 4096)).unwrap();
        f.write_all(&lp).unwrap();
        let out = tempfile::tempdir().unwrap();
        let error = gb_installer::layout::capture(&d, out.path()).unwrap_err();
        assert!(error.to_string().contains("LP overlays"), "{error:#}");
    }
}
