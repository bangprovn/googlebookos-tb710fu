//! Real sandbox/compiler validation; no firmware or device is touched.
use gb_core::{Artifact, FirmwareManifest, Format, digest};
use std::{fs, path::Path, process::Command};
fn put(m: &mut FirmwareManifest, path: &str, text: &str) {
    m.artifacts.push(Artifact {
        path: path.into(),
        bytes: text.len() as u64,
        sha256: digest(text.as_bytes()),
        format: Format::Unknown,
        metadata: serde_json::json!({}),
    });
    m.inventory.metadata_text.insert(path.into(), text.into());
}
fn fixture(root: &Path, violation: bool) {
    let base = FirmwareManifest {
        schema_version: 1,
        inspector_version: "fixture".into(),
        source_sha256: "0".repeat(64),
        artifacts: vec![],
        inventory: Default::default(),
        limitations: vec![],
    };
    let mut d = base.clone();
    let mut t = base;
    put(
        &mut d,
        "system_a/system/etc/selinux/plat_sepolicy.cil",
        r#"
(handleunknown deny)
(class file (read))
(classorder (file))
(sid kernel)
(sidorder (kernel))
(type kernel_t)
(type file_t)
(role r)
(roletype r kernel_t)
(user u)
(userrole u r)
(sensitivity s0)
(sensitivityorder (s0))
(level l0 (s0))
(levelrange lr (l0 l0))
(userlevel u l0)
(userrange u lr)
(context kernel_context (u r kernel_t lr))
(sidcontext kernel kernel_context)
(allow kernel_t file_t (file (read)))
(neverallow file_t kernel_t (file (read)))
"#,
    );
    put(&mut d, "system_a/system/etc/selinux/mapping/34.0.cil", "");
    put(
        &mut d,
        "system_a/system/etc/selinux/plat_file_contexts",
        "/system/bin/fixture -- u:object_r:file_t:s0\n",
    );
    put(
        &mut t,
        "vendor_a/etc/selinux/plat_sepolicy_vers.txt",
        "34.0\n",
    );
    put(&mut t, "vendor_a/etc/selinux/plat_pub_versioned.cil", "");
    put(
        &mut t,
        "vendor_a/etc/selinux/vendor_file_contexts",
        "/vendor/bin/fixture -- u:object_r:vendor_hardware_t:s0\n",
    );
    put(
        &mut t,
        "vendor_a/etc/selinux/vendor_sepolicy.cil",
        if violation {
            "(neverallow kernel_t file_t (file (read)))"
        } else {
            "(type vendor_hardware_t)"
        },
    );
    d.source_sha256 = digest(&serde_json::to_vec(&d).unwrap());
    t.source_sha256 = digest(&serde_json::to_vec(&t).unwrap());
    fs::write(root.join("donor.json"), serde_json::to_vec(&d).unwrap()).unwrap();
    fs::write(root.join("target.json"), serde_json::to_vec(&t).unwrap()).unwrap();
    fs::write(root.join("recipe.toml"),"schema_version=1\nid='compiler-fixture'\nrevision=1\n[partitions.system]\ndonor='system_a'\ntarget='system_a'\n").unwrap();
}
#[test]
#[ignore = "requires GB_TEST_SECILC, GB_TEST_FCONTEXT and GB_TEST_SANDBOX_IMAGE"]
fn real_context_checker_accepts_known_labels_and_rejects_unknown_types() {
    let secilc = std::env::var("GB_TEST_SECILC").unwrap();
    let checker = std::env::var("GB_TEST_FCONTEXT").unwrap();
    let image = std::env::var("GB_TEST_SANDBOX_IMAGE").unwrap();
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let compiled = Command::new(env!("CARGO_BIN_EXE_gb"))
        .current_dir(root.path())
        .args([
            "compat",
            "selinux",
            "--donor",
            "donor.json",
            "--target",
            "target.json",
            "--recipe",
            "recipe.toml",
            "--tool",
            &secilc,
            "--sandbox-image",
            &image,
            "--kernel-policy-version",
            "33",
            "--policy-version",
            "30",
            "--out",
            "policy.json",
        ])
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let p: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("policy.json")).unwrap()).unwrap();
    let policy = format!(
        ".gb-cache/objects/{}/sepolicy",
        p["artifact_cache_key"].as_str().unwrap()
    );
    let check = |out: &str| {
        Command::new(env!("CARGO_BIN_EXE_gb"))
            .current_dir(root.path())
            .args([
                "--cache",
                "context-cache",
                "compat",
                "contexts",
                "--donor",
                "donor.json",
                "--target",
                "target.json",
                "--recipe",
                "recipe.toml",
                "--policy-report",
                "policy.json",
                "--policy-file",
                &policy,
                "--tool",
                &checker,
                "--sandbox-image",
                &image,
                "--out",
                out,
            ])
            .output()
            .unwrap()
    };
    let good = check("contexts.json");
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("contexts.json")).unwrap()).unwrap();
    assert_eq!(report["state"], "compatible");
    assert_eq!(report["runtime_verified"], false);
    assert_eq!(report["strict_policy_audit_passed"], true);
    assert!(report["tool"]["library_mounts"]["libpcre2.so"].is_object());
    let repeat = check("repeat.json");
    assert!(repeat.status.success());
    assert_eq!(
        fs::read(root.path().join("contexts.json")).unwrap(),
        fs::read(root.path().join("repeat.json")).unwrap()
    );
    let mut target: FirmwareManifest =
        serde_json::from_slice(&fs::read(root.path().join("target.json")).unwrap()).unwrap();
    let path = "vendor_a/etc/selinux/vendor_file_contexts";
    target.artifacts.retain(|a| a.path != path);
    put(
        &mut target,
        path,
        "/vendor/bin/fixture -- u:object_r:unavailable_type:s0\n",
    );
    target.source_sha256 = digest(&serde_json::to_vec(&target).unwrap());
    fs::write(
        root.path().join("target.json"),
        serde_json::to_vec(&target).unwrap(),
    )
    .unwrap();
    let bad = check("bad.json");
    assert_eq!(
        bad.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("bad.json")).unwrap()).unwrap();
    assert_eq!(report["state"], "patch_required");
    assert_ne!(report["file_contexts_check"]["exit_code"], 0);
    assert!(
        report["file_contexts_check"]["stderr"]
            .as_str()
            .unwrap()
            .contains("unavailable_type")
    );
}
#[test]
#[ignore = "requires GB_TEST_SECILC trusted host tool and GB_TEST_SANDBOX_IMAGE local immutable Docker image"]
fn real_compiler_neverallow_and_incremental_cache_are_enforced() {
    let tool = std::env::var("GB_TEST_SECILC").expect("set trusted secilc path");
    let image =
        std::env::var("GB_TEST_SANDBOX_IMAGE").expect("set immutable local sandbox image ID");
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let run = |out: &str| {
        Command::new(env!("CARGO_BIN_EXE_gb"))
            .current_dir(root.path())
            .args([
                "compat",
                "selinux",
                "--donor",
                "donor.json",
                "--target",
                "target.json",
                "--recipe",
                "recipe.toml",
                "--tool",
                &tool,
                "--sandbox-image",
                &image,
                "--kernel-policy-version",
                "33",
                "--policy-version",
                "33",
                "--out",
                out,
            ])
            .output()
            .unwrap()
    };
    let first = run("one.json");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let one: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("one.json")).unwrap()).unwrap();
    assert_eq!(one["state"], "compatible");
    assert_eq!(one["binary_policy"]["policy_version"], 33);
    assert_eq!(one["neverallow_checks_enabled"], true);
    assert_eq!(one["bootable"], false);
    assert_eq!(one["runtime_verified"], false);
    let second = run("two.json");
    assert!(second.status.success());
    assert_eq!(
        fs::read(root.path().join("one.json")).unwrap(),
        fs::read(root.path().join("two.json")).unwrap()
    );
    let objects = root.path().join(".gb-cache/objects");
    let stage = fs::read_dir(&objects)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        stage.file_name().unwrap().to_str().unwrap(),
        one["artifact_cache_key"].as_str().unwrap()
    );
    assert_eq!(
        gb_core::hash_file(&stage.join("sepolicy")).unwrap(),
        one["binary_policy"]["sha256"].as_str().unwrap()
    );
    fs::write(stage.join("sepolicy"), "corrupt").unwrap();
    let rebuilt = run("rebuilt.json");
    assert!(rebuilt.status.success());
    assert_eq!(
        fs::read(root.path().join("one.json")).unwrap(),
        fs::read(root.path().join("rebuilt.json")).unwrap()
    );
    fixture(root.path(), true);
    let failed = run("failed.json");
    assert_eq!(
        failed.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    let failed: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("failed.json")).unwrap()).unwrap();
    assert_eq!(failed["state"], "patch_required");
    assert!(failed["binary_policy"].is_null());
    assert!(
        failed["result"]["stderr"]
            .as_str()
            .unwrap()
            .contains("neverallow")
    );
    assert_eq!(failed["android_init_link_check"]["state"], "compatible");
    assert_eq!(
        failed["android_init_link_check"]["neverallow_checks_enabled"],
        false
    );
    assert!(
        failed["android_init_link_check"]["result"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "-N")
    );
    for entry in fs::read_dir(&objects).unwrap() {
        let dir = entry.unwrap().path();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("report.json")).unwrap()).unwrap();
        if report["state"] == "patch_required" {
            assert!(!dir.join("sepolicy").exists());
        }
    }
}
