//! Exercises the public CLI against small recovery fixtures; never accesses hardware.
use gb_core::{digest, hash_file};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output},
};
use zip::write::SimpleFileOptions;
fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gb"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}
fn raw_disk() -> Vec<u8> {
    let mut image = vec![0; 128 * 512];
    let mut table = vec![0; 128 * 128];
    for (i, name, start) in [(0, "boot_a", 40u64), (1, "vbmeta_a", 48u64)] {
        let e = &mut table[i * 128..(i + 1) * 128];
        e[0] = 1;
        e[16] = i as u8 + 1;
        e[32..40].copy_from_slice(&start.to_le_bytes());
        e[40..48].copy_from_slice(&(start + 7).to_le_bytes());
        for (j, c) in name.encode_utf16().enumerate() {
            e[56 + j * 2..58 + j * 2].copy_from_slice(&c.to_le_bytes());
        }
    }
    let mut h = vec![0; 92];
    h[..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    h[24..32].copy_from_slice(&1u64.to_le_bytes());
    h[32..40].copy_from_slice(&127u64.to_le_bytes());
    h[40..48].copy_from_slice(&34u64.to_le_bytes());
    h[48..56].copy_from_slice(&126u64.to_le_bytes());
    h[72..80].copy_from_slice(&2u64.to_le_bytes());
    h[80..84].copy_from_slice(&128u32.to_le_bytes());
    h[84..88].copy_from_slice(&128u32.to_le_bytes());
    h[88..92].copy_from_slice(&crc32fast::hash(&table).to_le_bytes());
    let crc = crc32fast::hash(&h);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    image[512..604].copy_from_slice(&h);
    image[1024..1024 + table.len()].copy_from_slice(&table);
    let boot = &mut image[40 * 512..48 * 512];
    boot[..8].copy_from_slice(b"ANDROID!");
    boot[20..24].copy_from_slice(&1584u32.to_le_bytes());
    boot[40..44].copy_from_slice(&4u32.to_le_bytes());
    image[48 * 512..48 * 512 + 4].copy_from_slice(b"AVB0");
    image[48 * 512 + 112..48 * 512 + 120].copy_from_slice(&7u64.to_be_bytes());
    image
}
fn zip(path: &Path, entries: &[(&str, &[u8])]) {
    let mut z = zip::ZipWriter::new(fs::File::create(path).unwrap());
    for (name, bytes) in entries {
        z.start_file(
            *name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        z.write_all(bytes).unwrap();
    }
    z.finish().unwrap();
}
fn fixture(root: &Path) {
    fs::create_dir(root.join("target-tree")).unwrap();
    fs::write(
        root.join("target-tree/build.prop"),
        b"ro.product.cpu.abi=arm64-v8a\nro.build.version.release=16\n",
    )
    .unwrap();
    let disk = raw_disk();
    zip(
        &root.join("donor.zip"),
        &[
            ("recovery.bin", &disk),
            (
                "system/build.prop",
                b"ro.product.cpu.abi=arm64-v8a\nro.build.version.release=17\n",
            ),
        ],
    );
    fs::write(
        root.join("donor.toml"),
        format!(
            "schema_version=1\ncodename='fixture'\ninput='donor.zip'\nsha256='{}'\n",
            hash_file(&root.join("donor.zip")).unwrap()
        ),
    )
    .unwrap();
    let original = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devices/example-tablet.toml"),
    )
    .unwrap();
    fs::write(
        root.join("device.toml"),
        original.replace("../artifacts/inputs/example-stock", "target-tree"),
    )
    .unwrap();
    fs::write(root.join("transforms.toml"),format!("schema_version=1\nid='fixture-extraction'\nrevision=1\npublish=['boot.img']\n[[operations]]\nkind='extract_zip_member'\nsource='donor'\nmember='recovery.bin'\noutput='disk.raw'\nsha256='{}'\n[[operations]]\nkind='extract_gpt_partition'\nsource='build'\ninput='disk.raw'\npartition='boot_a'\noutput='boot.img'\n",digest(&disk))).unwrap();
}
#[test]
fn destinations_inside_stock_firmware_are_refused_without_mutation() {
    let t = tempfile::tempdir().unwrap();
    fixture(t.path());
    let before = gb_firmware::input_digest(&t.path().join("target-tree")).unwrap();
    for args in [
        vec![
            "--cache",
            "target-tree/cache",
            "firmware",
            "inspect",
            "target-tree",
        ],
        vec![
            "firmware",
            "inspect",
            "target-tree",
            "--out",
            "target-tree/report.json",
        ],
        vec![
            "port",
            "build",
            "--donor",
            "donor.toml",
            "--device",
            "device.toml",
            "--output",
            "target-tree/artifacts",
        ],
    ] {
        let r = run(t.path(), &args);
        assert_eq!(r.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&r.stderr).contains("overlaps source firmware"));
        assert_eq!(
            gb_firmware::input_digest(&t.path().join("target-tree")).unwrap(),
            before
        );
    }
}
#[test]
fn end_to_end_extract_cache_offline_validate_and_block_flash() {
    let t = tempfile::tempdir().unwrap();
    fixture(t.path());
    let before = hash_file(&t.path().join("donor.zip")).unwrap();
    let args = [
        "port",
        "build",
        "--donor",
        "donor.toml",
        "--device",
        "device.toml",
        "--transforms",
        "transforms.toml",
        "--output",
        "out-a",
        "--incremental",
    ];
    let a = run(t.path(), &args);
    assert_eq!(
        a.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&a.stderr)
    );
    let report: Value = serde_json::from_slice(&a.stdout).unwrap();
    assert_eq!(report["status"], "blocked_rom_assembly");
    assert_eq!(report["bootable"], false);
    assert!(
        report["stages"]
            .as_object()
            .unwrap()
            .values()
            .all(|s| s["cache_hit"] == false)
    );
    assert!(!t.path().join("out-a/processed/disk.raw").exists());
    assert_eq!(
        fs::read(t.path().join("out-a/processed/boot.img")).unwrap(),
        raw_disk()[40 * 512..48 * 512]
    );
    let mut args = args;
    args[9] = "out-b";
    let b = run(t.path(), &args);
    assert_eq!(
        b.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&b.stderr)
    );
    let cached: Value = serde_json::from_slice(&b.stdout).unwrap();
    assert!(
        cached["stages"]
            .as_object()
            .unwrap()
            .values()
            .all(|s| s["cache_hit"] == true)
    );
    assert_eq!(
        hash_file(&t.path().join("out-a/processed/boot.img")).unwrap(),
        hash_file(&t.path().join("out-b/processed/boot.img")).unwrap()
    );
    assert_eq!(before, hash_file(&t.path().join("donor.zip")).unwrap());
    let check = run(
        t.path(),
        &["port", "test", "--offline", "--artifact", "out-a"],
    );
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let checked: Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(checked["runtime_verified"], false);
    let flash = run(
        t.path(),
        &[
            "flash",
            "plan",
            "--device",
            "device.toml",
            "--artifact",
            "out-a",
        ],
    );
    assert_eq!(flash.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&flash.stderr).contains("not an assembled bootable ROM"));
    fs::write(t.path().join("out-a/processed/boot.img"), b"corrupted").unwrap();
    assert_eq!(
        run(
            t.path(),
            &["port", "test", "--offline", "--artifact", "out-a"]
        )
        .status
        .code(),
        Some(1)
    );
}
#[test]
fn archive_traversal_rejected_without_writing_destination() {
    let t = tempfile::tempdir().unwrap();
    zip(
        &t.path().join("bad.zip"),
        &[("../escaped", b"not firmware")],
    );
    let out = run(t.path(), &["firmware", "inspect", "bad.zip"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unsafe relative path"));
    assert!(!t.path().join("escaped").exists());
}
#[test]
fn bad_checksums_and_gpt_crc_fail_closed() {
    let t = tempfile::tempdir().unwrap();
    fixture(t.path());
    let mut disk = raw_disk();
    disk[600] ^= 1;
    fs::write(t.path().join("broken.img"), disk).unwrap();
    let out = run(t.path(), &["firmware", "inspect", "broken.img"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("CRC mismatch"));
    let manifest = fs::read_to_string(t.path().join("transforms.toml")).unwrap();
    fs::write(
        t.path().join("transforms.toml"),
        manifest.replace(&digest(&raw_disk()), &"0".repeat(64)),
    )
    .unwrap();
    let out = run(
        t.path(),
        &[
            "port",
            "build",
            "--donor",
            "donor.toml",
            "--device",
            "device.toml",
            "--transforms",
            "transforms.toml",
            "--output",
            "bad-output",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!t.path().join("bad-output").exists());
}

#[test]
fn clean_room_publication_is_reproducible() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for root in [a.path(), b.path()] {
        fixture(root);
        let result = run(
            root,
            &[
                "port",
                "build",
                "--donor",
                "donor.toml",
                "--device",
                "device.toml",
                "--transforms",
                "transforms.toml",
                "--output",
                "out",
            ],
        );
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(
        fs::read(a.path().join("out/SHA256SUMS")).unwrap(),
        fs::read(b.path().join("out/SHA256SUMS")).unwrap()
    );
}

#[test]
fn changed_inputs_invalidate_cache_and_destination_is_preserved() {
    let t = tempfile::tempdir().unwrap();
    fixture(t.path());
    let args = [
        "port",
        "build",
        "--donor",
        "donor.toml",
        "--device",
        "device.toml",
        "--output",
        "first",
        "--incremental",
    ];
    assert_eq!(run(t.path(), &args).status.code(), Some(2));
    fs::write(
        t.path().join("target-tree/build.prop"),
        b"ro.product.cpu.abi=arm64-v8a\nro.build.version.release=17\n",
    )
    .unwrap();
    let mut second = args;
    second[7] = "second";
    let output = run(t.path(), &second);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["stages"]["donor_inspection"]["cache_hit"], true);
    assert_eq!(report["stages"]["target_inspection"]["cache_hit"], false);
    assert_eq!(report["stages"]["compatibility"]["cache_hit"], false);
    let before = fs::read(t.path().join("first/SHA256SUMS")).unwrap();
    assert_eq!(run(t.path(), &args).status.code(), Some(1));
    assert_eq!(before, fs::read(t.path().join("first/SHA256SUMS")).unwrap());
}
