//! Optional real-tool integration tests; fixtures contain no device firmware.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};
fn super_image(payload: &[u8]) -> Vec<u8> {
    let bytes = (payload.len() as u64).div_ceil(512) * 512;
    let mut image = vec![0; 32768 + bytes as usize];
    let mut g = vec![0; 52];
    g[..4].copy_from_slice(&0x616c4467u32.to_le_bytes());
    g[4..8].copy_from_slice(&52u32.to_le_bytes());
    g[40..44].copy_from_slice(&4096u32.to_le_bytes());
    g[44..48].copy_from_slice(&2u32.to_le_bytes());
    g[48..52].copy_from_slice(&4096u32.to_le_bytes());
    let sha = Sha256::digest(&g);
    g[8..40].copy_from_slice(&sha);
    image[4096..4148].copy_from_slice(&g);
    let mut t = vec![0; 188];
    t[..8].copy_from_slice(b"system_a");
    t[44..48].copy_from_slice(&1u32.to_le_bytes());
    t[52..60].copy_from_slice(&(bytes / 512).to_le_bytes());
    t[64..72].copy_from_slice(&64u64.to_le_bytes());
    t[76..83].copy_from_slice(b"default");
    t[124..132].copy_from_slice(&64u64.to_le_bytes());
    t[140..148].copy_from_slice(&(image.len() as u64).to_le_bytes());
    let mut h = vec![0; 128];
    h[..4].copy_from_slice(&0x414c5030u32.to_le_bytes());
    h[4..6].copy_from_slice(&10u16.to_le_bytes());
    h[8..12].copy_from_slice(&128u32.to_le_bytes());
    h[44..48].copy_from_slice(&(t.len() as u32).to_le_bytes());
    h[48..80].copy_from_slice(&Sha256::digest(&t));
    for (base, start, count, size) in [
        (80, 0u32, 1u32, 52u32),
        (92, 52, 1, 24),
        (104, 76, 1, 48),
        (116, 124, 1, 64),
    ] {
        h[base..base + 4].copy_from_slice(&start.to_le_bytes());
        h[base + 4..base + 8].copy_from_slice(&count.to_le_bytes());
        h[base + 8..base + 12].copy_from_slice(&size.to_le_bytes());
    }
    let sha = Sha256::digest(&h);
    h[12..44].copy_from_slice(&sha);
    image[12288..12416].copy_from_slice(&h);
    image[12416..12416 + t.len()].copy_from_slice(&t);
    image[32768..32768 + payload.len()].copy_from_slice(payload);
    image
}
fn fixture(root: &Path) {
    fs::create_dir_all(root.join("tree/etc/vintf")).unwrap();
    fs::write(
        root.join("tree/build.prop"),
        "ro.product.cpu.abi=arm64-v8a\nro.build.version.release=16\n",
    )
    .unwrap();
    fs::write(root.join("tree/etc/vintf/manifest.xml"), "<manifest type='device' target-level='8'><hal format='aidl'><name>android.hardware.power</name><version>5</version><fqname>IPower/default</fqname></hal></manifest>").unwrap();
    std::os::unix::fs::symlink("/etc/shadow", root.join("tree/absolute-link")).unwrap();
    std::os::unix::fs::symlink("build.prop", root.join("tree/local-link")).unwrap();
}
fn check(root: &Path, tool: &str, checker: Option<&str>) {
    let image =
        std::env::var("GB_TEST_SANDBOX_IMAGE").expect("set immutable local Docker image ID");
    let run = |out: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gb"));
        command.current_dir(root).args([
            "firmware",
            "inventory",
            "super.img",
            "--partitions",
            "system_a",
            "--tool",
            tool,
            "--sandbox-image",
            &image,
            "--out",
            out,
        ]);
        if let Some(checker) = checker {
            command.args(["--check-tool", checker]);
        }
        command.output().unwrap()
    };
    let first = run("one.json");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let m: Value = serde_json::from_slice(&fs::read(root.join("one.json")).unwrap()).unwrap();
    assert_eq!(
        m["inventory"]["symlinks"]["system_a/absolute-link"],
        "/etc/shadow"
    );
    assert_eq!(m["inventory"]["vintf"][0]["level"], "8");
    assert_eq!(m["inventory"]["properties"].as_array().unwrap().len(), 2);
    assert_eq!(m["artifacts"].as_array().unwrap().len(), 2);
    let second = run("two.json");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        fs::read(root.join("one.json")).unwrap(),
        fs::read(root.join("two.json")).unwrap()
    );
    assert!(!root.join("tree/etc/shadow").exists());
    let objects = root.join(".gb-cache/objects");
    let object = fs::read_dir(&objects)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(object.join("manifest.json"), "corrupt").unwrap();
    let third = run("three.json");
    assert!(
        third.status.success(),
        "{}",
        String::from_utf8_lossy(&third.stderr)
    );
    assert_eq!(
        fs::read(root.join("one.json")).unwrap(),
        fs::read(root.join("three.json")).unwrap()
    );
}
#[test]
#[ignore = "requires mkfs.erofs, mke2fs, Docker and GB_TEST_SANDBOX_IMAGE"]
fn selected_text_collection_for_ext4_and_erofs_is_verified_and_cached() {
    let sandbox = std::env::var("GB_TEST_SANDBOX_IMAGE").unwrap();
    for ext4 in [false, true] {
        let t = tempfile::tempdir().unwrap();
        fixture(t.path());
        let image = t.path().join("fs.img");
        let result = if ext4 {
            let f = fs::File::create(&image).unwrap();
            f.set_len(16 * 1024 * 1024).unwrap();
            Command::new("mke2fs")
                .args(["-q", "-F", "-t", "ext4", "-d"])
                .arg(t.path().join("tree"))
                .arg(&image)
                .output()
                .unwrap()
        } else {
            Command::new("mkfs.erofs")
                .args(["-T", "0"])
                .arg(&image)
                .arg(t.path().join("tree"))
                .output()
                .unwrap()
        };
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let scratch = t.path().join("scratch");
        let mut m = gb_firmware::inspect_firmware(
            &t.path().join("tree"),
            &scratch,
            &gb_firmware::Limits::default(),
        )
        .unwrap();
        gb_firmware::filesystem::prefix(&mut m, "system_a");
        m.inventory.metadata_text.clear();
        fs::write(t.path().join("base.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        let config = format!(
            "schema_version=1\nbase_manifest='base.json'\n[[images]]\npartition='system_a'\ninput='fs.img'\nsha256='{}'\n[tools]\nerofs='/usr/bin/fsck.erofs'\next4='/usr/sbin/debugfs'\nchecker='/usr/sbin/e2fsck'\n[tools.sandbox]\nbackend='docker'\nimage='{}'\n",
            gb_core::hash_file(&image).unwrap(),
            sandbox
        );
        fs::write(t.path().join("collect.toml"), config).unwrap();
        let run = |out: &str| {
            Command::new(env!("CARGO_BIN_EXE_gb"))
                .current_dir(t.path())
                .args(["firmware", "collect-text", "collect.toml", "--out", out])
                .output()
                .unwrap()
        };
        let one = run("one.json");
        assert!(
            one.status.success(),
            "{}",
            String::from_utf8_lossy(&one.stderr)
        );
        let a: Value =
            serde_json::from_slice(&fs::read(t.path().join("one.json")).unwrap()).unwrap();
        assert!(
            a["inventory"]["metadata_text"]["system_a/etc/vintf/manifest.xml"]
                .as_str()
                .unwrap()
                .contains("android.hardware.power")
        );
        assert_eq!(a["source_sha256"], m.source_sha256);
        let two = run("two.json");
        assert!(two.status.success());
        assert_eq!(
            fs::read(t.path().join("one.json")).unwrap(),
            fs::read(t.path().join("two.json")).unwrap()
        );
        let stage = fs::read_dir(t.path().join(".gb-cache/objects"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(stage.join("text.json"), "corrupt").unwrap();
        let rebuilt = run("rebuilt.json");
        assert!(rebuilt.status.success());
        assert_eq!(
            fs::read(t.path().join("one.json")).unwrap(),
            fs::read(t.path().join("rebuilt.json")).unwrap()
        );
        for artifact in &mut m.artifacts {
            if artifact.path.ends_with("manifest.xml") {
                artifact.sha256 = "0".repeat(64);
            }
        }
        fs::write(t.path().join("base.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        let bad = run("bad.json");
        assert_eq!(bad.status.code(), Some(1));
        assert!(!t.path().join("bad.json").exists());
    }
}
#[test]
#[ignore = "requires mkfs.erofs, Docker and GB_TEST_SANDBOX_IMAGE"]
fn erofs_real_extraction_symlinks_cache_and_corruption() {
    let t = tempfile::tempdir().unwrap();
    fixture(t.path());
    let image = t.path().join("fs.img");
    let result = Command::new("mkfs.erofs")
        .args(["-T", "0"])
        .arg(&image)
        .arg(t.path().join("tree"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    fs::write(
        t.path().join("super.img"),
        super_image(&fs::read(image).unwrap()),
    )
    .unwrap();
    check(t.path(), "/usr/bin/fsck.erofs", None);
}
#[test]
#[ignore = "requires mke2fs, debugfs, e2fsck, Docker and GB_TEST_SANDBOX_IMAGE"]
fn ext4_real_readonly_check_extraction_symlinks_and_cache() {
    let t = tempfile::tempdir().unwrap();
    fixture(t.path());
    let image = t.path().join("fs.img");
    let result = Command::new("mke2fs")
        .args(["-t", "ext4", "-F", "-q", "-d"])
        .arg(t.path().join("tree"))
        .arg(&image)
        .arg("8192")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    fs::write(
        t.path().join("super.img"),
        super_image(&fs::read(image).unwrap()),
    )
    .unwrap();
    check(t.path(), "/usr/sbin/debugfs", Some("/usr/sbin/e2fsck"));
}
