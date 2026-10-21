//! Real mature-tool integration; explicitly opt in with an immutable sandbox ID.
use gb_image::ext4_patch::{Input, Patch, Request, build};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
fn tool(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join(name))
        .find(|p| p.is_file())
        .expect("required host tool absent")
        .canonicalize()
        .unwrap()
}
fn pin(path: &Path) -> Input {
    Input {
        path: path.into(),
        sha256: gb_core::hash_file(path).unwrap(),
    }
}
fn run(name: &str, args: &[&str]) {
    let result = Command::new(tool(name)).args(args).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "requires mke2fs/debugfs/e2fsck and GB_EXT4_TEST_SANDBOX immutable local Docker image"]
fn real_ext4_metadata_deltas_reproducibility_and_refusals() {
    let sandbox =
        std::env::var("GB_EXT4_TEST_SANDBOX").expect("explicit immutable sandbox required");
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("root");
    fs::create_dir_all(root.join("etc/init")).unwrap();
    let before = vec![b'a'; 10000];
    fs::write(root.join("etc/init/test.rc"), &before).unwrap();
    fs::write(root.join("etc/init/hard-a"), b"hardlink\n").unwrap();
    fs::hard_link(root.join("etc/init/hard-a"), root.join("etc/init/hard-b")).unwrap();
    std::os::unix::fs::symlink("test.rc", root.join("etc/init/link.rc")).unwrap();
    let image = t.path().join("source.img");
    fs::File::create(&image)
        .unwrap()
        .set_len(16 * 1024 * 1024)
        .unwrap();
    run(
        "mke2fs",
        &[
            "-q",
            "-t",
            "ext4",
            "-O",
            "^has_journal",
            "-b",
            "4096",
            "-F",
            "-d",
            root.to_str().unwrap(),
            image.to_str().unwrap(),
        ],
    );
    let commands = t.path().join("metadata.txt");
    fs::write(&commands,"ea_set /etc/init/test.rc security.selinux u:object_r:vendor_configs_file:s0\nset_inode_field /etc/init/test.rc uid 1234\nset_inode_field /etc/init/test.rc gid 2000\nset_inode_field /etc/init/test.rc mtime @1230768000\n").unwrap();
    run(
        "debugfs",
        &[
            "-w",
            "-f",
            commands.to_str().unwrap(),
            image.to_str().unwrap(),
        ],
    );
    let original_sha = gb_core::hash_file(&image).unwrap();
    let replacement = t.path().join("replacement.rc");
    let mut after = before.clone();
    after[4095] = b'#';
    after[4096] = b'#';
    fs::write(&replacement, &after).unwrap();
    let r = Request {
        schema_version: 1,
        id: "ext4-real-fixture".into(),
        revision: 1,
        partition: "vendor".into(),
        image: pin(&image),
        max_image_bytes: 16 * 1024 * 1024,
        debugfs: pin(&tool("debugfs")),
        checker: pin(&tool("e2fsck")),
        patches: vec![Patch {
            path: "etc/init/test.rc".into(),
            original_sha256: gb_core::digest(&before),
            replacement: pin(&replacement),
        }],
        sandbox: gb_tools::Sandbox::Docker { image: sandbox },
    };
    let a = build(&r, &t.path().join("a")).unwrap();
    let b = build(&r, &t.path().join("b")).unwrap();
    assert_eq!(a.image_sha256, b.image_sha256);
    assert_eq!(a.changes.len(), 2);
    assert!(a.unrelated_image_bytes_identical && a.filesystem_metadata_bytes_preserved);
    assert_eq!(
        (
            a.files[0].metadata.uid,
            a.files[0].metadata.gid,
            a.files[0].metadata.mtime
        ),
        (1234, 2000, 1230768000)
    );
    assert_eq!(
        a.files[0].metadata.xattrs["security.selinux"],
        b"u:object_r:vendor_configs_file:s0"
    );
    assert_eq!(gb_core::hash_file(&image).unwrap(), original_sha);
    assert!(!a.avb_signed && !a.bootable && !a.runtime_verified);
    assert!(build(&r, &t.path().join("a")).is_err());
    let mut bad = r.clone();
    bad.image.sha256 = "0".repeat(64);
    assert!(build(&bad, &t.path().join("bad-pin")).is_err());
    assert!(!t.path().join("bad-pin").exists());
    bad = r.clone();
    bad.patches[0].path = "etc/init/link.rc".into();
    assert!(build(&bad, &t.path().join("symlink")).is_err());
    assert!(!t.path().join("symlink").exists());
    bad = r.clone();
    bad.patches[0].path = "etc/init/hard-a".into();
    bad.patches[0].original_sha256 = gb_core::digest(b"hardlink\n");
    assert!(build(&bad, &t.path().join("hardlink")).is_err());
    assert!(!t.path().join("hardlink").exists());
    assert_eq!(gb_core::hash_file(&image).unwrap(), original_sha);
}
