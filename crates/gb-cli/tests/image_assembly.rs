//! Real host-tool regression; only creates disposable local filesystem fixtures.
use gb_core::hash_file;
use gb_image::{assemble, import, metadata};
use std::{
    fs,
    path::Path,
    process::Command,
    time::{Duration, SystemTime},
};

fn checked(command: &mut Command) {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "requires GB_TEST_MKFS, GB_TEST_FSCK, GB_TEST_DUMP, GB_TEST_SANDBOX_IMAGE and mke2fs/debugfs"]
fn ext4_import_preserves_binary_metadata_and_cache_rejects_changed_sources() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    let donor_tree = path.join("donor");
    fs::create_dir_all(donor_tree.join("apex")).unwrap();
    fs::write(
        donor_tree.join("apex/original.bin"),
        b"donor retained bytes",
    )
    .unwrap();
    let stock_tree = path.join("stock");
    fs::create_dir(&stock_tree).unwrap();
    fs::write(
        stock_tree.join("retained.bin"),
        b"original target ABI fixture",
    )
    .unwrap();
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1230768000);
    for p in [
        &donor_tree,
        &donor_tree.join("apex"),
        &donor_tree.join("apex/original.bin"),
        &stock_tree.join("retained.bin"),
    ] {
        fs::File::open(p)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(time))
            .unwrap();
    }
    let donor = path.join("donor.img");
    let mkfs = std::env::var("GB_TEST_MKFS").unwrap();
    checked(
        Command::new(&mkfs)
            .args([
                "--mkfs-time",
                "--preserve-mtime",
                "-T1230768000",
                "-U00000000-0000-0000-0000-000000000123",
            ])
            .arg(&donor)
            .arg(&donor_tree),
    );
    let stock = path.join("stock.img");
    fs::File::create(&stock)
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    checked(
        Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-d"])
            .arg(&stock_tree)
            .arg(&stock),
    );
    // Editing an explicitly created test image never changes a device or source firmware.
    let label = path.join("label.bin");
    let cap = path.join("cap.bin");
    fs::write(&label, b"u:object_r:system_file:s0\0").unwrap();
    let capability = vec![0, 0, 0, 2, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    fs::write(&cap, &capability).unwrap();
    for cmd in [
        "set_inode_field /retained.bin uid 123456".into(),
        "set_inode_field /retained.bin gid 2345".into(),
        format!(
            "ea_set -f {} /retained.bin security.selinux",
            label.display()
        ),
        format!(
            "ea_set -f {} /retained.bin security.capability",
            cap.display()
        ),
    ] {
        let r = Command::new("debugfs")
            .args(["-w", "-R", &cmd])
            .arg(&stock)
            .output()
            .unwrap();
        assert!(r.status.success());
        assert!(
            String::from_utf8_lossy(&r.stderr)
                .lines()
                .all(|l| l.starts_with("debugfs ")),
            "{}",
            String::from_utf8_lossy(&r.stderr)
        );
    }
    let source_sha = hash_file(&stock).unwrap();
    let sha = hash_file(&stock_tree.join("retained.bin")).unwrap();
    let mut request = assemble::Request {
        schema_version: 1,
        id: "fixture".into(),
        revision: 1,
        partition: "system_ext".into(),
        input: donor.clone(),
        sha256: hash_file(&donor).unwrap(),
        max_bytes: 16 * 1024 * 1024,
        compression_cluster_bytes: None,
        patches: vec![],
        imports: vec![import::Request {
            image: stock.clone(),
            image_sha256: source_sha.clone(),
            source_path: "retained.bin".into(),
            destination: "apex/retained.bin".into(),
            sha256: sha.clone(),
            debugfs: "/usr/sbin/debugfs".into(),
            checker: "/usr/sbin/e2fsck".into(),
            apex_name: None,
        }],
        additions: vec![],
        directories: vec![],
        mkfs: mkfs.into(),
        fsck: std::env::var("GB_TEST_FSCK").unwrap().into(),
        dump: std::env::var("GB_TEST_DUMP").unwrap().into(),
        sandbox: gb_tools::Sandbox::Docker {
            image: std::env::var("GB_TEST_SANDBOX_IMAGE").unwrap(),
        },
    };
    let config = path.join("assemble.toml");
    let write_config =
        |r: &assemble::Request| fs::write(&config, toml::to_string(r).unwrap()).unwrap();
    let run = |out: &str, cache: &str| {
        Command::new(env!("CARGO_BIN_EXE_gb"))
            .current_dir(path)
            .env("RUST_LOG", "info")
            .args(["--cache", cache, "port", "assemble-partition"])
            .arg(&config)
            .args(["--output", out])
            .output()
            .unwrap()
    };
    write_config(&request);
    let first = run("one", "cache");
    assert_eq!(
        first.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: assemble::Report = serde_json::from_slice(&first.stdout).unwrap();
    assert!(!report.bootable && !report.runtime_verified && !report.avb_signed);
    assert_eq!(report.imports.len(), 1);
    let actual = metadata::inventory(&path.join("one/partition.img")).unwrap();
    let m = &actual["/apex/retained.bin"].metadata;
    assert_eq!((m.uid, m.gid, m.mtime), (123456, 2345, 1230768000));
    assert_eq!(m.xattrs["security.capability"], capability);
    assert_eq!(m.xattrs["security.selinux"], fs::read(label).unwrap());
    assert_eq!(report.imports[0].sha256, sha);
    let second = run("two", "cache");
    assert_eq!(second.status.code(), Some(2));
    let log = String::from_utf8_lossy(&second.stderr);
    assert!(
        log.contains("ext4_file_import") && log.contains("cache_hit=true"),
        "{log}"
    );
    assert_eq!(
        hash_file(&path.join("two/partition.img")).unwrap(),
        report.image_sha256
    );
    assert_eq!(first.stdout, second.stdout);
    let clean = run("clean", "new-cache");
    assert_eq!(
        clean.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_eq!(
        hash_file(&path.join("clean/partition.img")).unwrap(),
        report.image_sha256
    );
    request.imports[0].destination = "apex/original.bin".into();
    write_config(&request);
    let conflict = run("conflict", "cache");
    assert_eq!(conflict.status.code(), Some(1));
    assert!(!path.join("conflict").exists());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("destination already exists"));
    request.imports[0].destination = "apex/retained.bin".into();
    request.imports[0].image_sha256 = "0".repeat(64);
    write_config(&request);
    assert_eq!(run("mismatch", "cache").status.code(), Some(1));
    assert!(!path.join("mismatch").exists());
    assert_eq!(hash_file(&stock).unwrap(), source_sha);
    assert_eq!(hash_file(&donor).unwrap(), request.sha256);
    assert!(Path::new(&config).exists());
}
