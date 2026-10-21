use gb_core::{Artifact, FirmwareManifest, Format, Inventory, NativeLibrary};
use std::{fs, path::Path, process::Command};
fn manifest(partition: &str, donor: bool) -> FirmwareManifest {
    FirmwareManifest {
        schema_version: 1,
        inspector_version: "test".into(),
        source_sha256: "0".repeat(64),
        artifacts: vec![
            Artifact {
                path: format!("{partition}/framework/services.jar"),
                bytes: 1,
                sha256: if donor { "1" } else { "2" }.repeat(64),
                format: Format::Zip,
                metadata: serde_json::json!({}),
            },
            Artifact {
                path: if donor {
                    "system_b/lib64/client.so"
                } else {
                    "system_a/lib64/old-only.so"
                }
                .into(),
                bytes: 1,
                sha256: "3".repeat(64),
                format: Format::Elf,
                metadata: serde_json::json!({}),
            },
        ],
        inventory: Inventory {
            native_libraries: vec![NativeLibrary {
                path: if donor {
                    "system_b/lib64/client.so"
                } else {
                    "system_a/lib64/old-only.so"
                }
                .into(),
                architecture: "aarch64".into(),
                soname: Some(if donor { "client.so" } else { "old-only.so" }.into()),
                needed: if donor {
                    vec!["old-only.so".into()]
                } else {
                    vec![]
                },
            }],
            ..Default::default()
        },
        limitations: vec![],
    }
}
#[test]
fn public_plan_reports_real_loss_and_refuses_vendor_recipe() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    fs::write(
        root.join("donor.json"),
        serde_json::to_vec(&manifest("system_b", true)).unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("target.json"),
        serde_json::to_vec(&manifest("system_a", false)).unwrap(),
    )
    .unwrap();
    let text = "schema_version=1\nid='test'\nrevision=1\n[partitions.system]\ndonor='system_b'\ntarget='system_a'\n";
    fs::write(root.join("recipe.toml"), text).unwrap();
    let profile = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devices/example-tablet.toml");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_gb"))
            .current_dir(root)
            .args([
                "port",
                "integration-plan",
                "--donor-manifest",
                "donor.json",
                "--target-manifest",
                "target.json",
                "--recipe",
                "recipe.toml",
                "--device",
            ])
            .arg(&profile)
            .output()
            .unwrap()
    };
    let good = run();
    assert_eq!(
        good.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&good.stdout).unwrap();
    assert_eq!(report["unresolved_dependency_candidates"], 1);
    assert_eq!(report["components"][0]["comparison"], "changed");
    assert!(
        report["preserve_target_partitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "system_dlkm")
    );
    assert_eq!(report["bootable"], false);
    fs::write(
        root.join("recipe.toml"),
        format!("{text}[partitions.vendor]\ndonor='vendor_a'\ntarget='vendor_a'\n"),
    )
    .unwrap();
    let bad = run();
    assert_eq!(bad.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("hardware partition replacement refused")
    );
}
