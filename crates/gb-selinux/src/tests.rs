use super::*;
use gb_core::{Artifact, Format};
use gb_framework::PartitionPair;
use std::collections::BTreeMap;
fn manifest() -> FirmwareManifest {
    FirmwareManifest {
        schema_version: 1,
        inspector_version: "test".into(),
        source_sha256: "0".repeat(64),
        artifacts: vec![],
        inventory: Default::default(),
        limitations: vec![],
    }
}
fn put(m: &mut FirmwareManifest, path: &str, content: &str) {
    m.artifacts.push(Artifact {
        path: path.into(),
        bytes: content.len() as u64,
        sha256: digest(content.as_bytes()),
        format: Format::Unknown,
        metadata: serde_json::json!({}),
    });
    m.inventory
        .metadata_text
        .insert(path.into(), content.into());
}
fn setup() -> (FirmwareManifest, FirmwareManifest, Recipe) {
    let mut d = manifest();
    let mut t = manifest();
    put(
        &mut d,
        "system_a/system/etc/selinux/plat_sepolicy.cil",
        "(type platform_t)",
    );
    put(
        &mut d,
        "system_a/system/etc/selinux/mapping/34.0.cil",
        "(typeattribute platform_34_0)",
    );
    put(
        &mut d,
        "vendor_a/etc/selinux/vendor_sepolicy.cil",
        "(type wrong_donor_hardware_t)",
    );
    put(
        &mut t,
        "vendor_a/etc/selinux/plat_sepolicy_vers.txt",
        "34.0\n",
    );
    put(
        &mut t,
        "vendor_a/etc/selinux/plat_pub_versioned.cil",
        "(typeattribute platform_34_0)",
    );
    put(
        &mut t,
        "vendor_a/etc/selinux/vendor_sepolicy.cil",
        "(type retained_hardware_t)",
    );
    let r = Recipe {
        schema_version: 1,
        id: "test".into(),
        revision: 1,
        partitions: BTreeMap::from([(
            "system".into(),
            PartitionPair {
                donor: "system_a".into(),
                target: "system_a".into(),
            },
        )]),
        donor_fingerprint: None,
        target_fingerprint: None,
        donor_source_sha256: None,
        target_source_sha256: None,
        retain_target_apex: vec![],
        vintf_merges: vec![],
        context_patches: vec![],
    };
    (d, t, r)
}
#[test]
fn selects_target_hardware_and_declared_mapping_without_donor_vendor() {
    let (d, t, r) = setup();
    let s = select(
        &d,
        &t,
        &r,
        Options {
            kernel_policy_version: 33,
            policy_version: 30,
        },
    )
    .unwrap();
    assert_eq!(s.vendor_mapping_version, "34.0");
    assert_eq!(s.genfs_labels_version, 202404);
    assert!(s.genfs_uses_android_default);
    assert_eq!(s.units.len(), 4);
    assert!(
        select(
            &d,
            &t,
            &r,
            Options {
                kernel_policy_version: 30,
                policy_version: 31
            }
        )
        .is_err()
    );
    assert!(
        !s.units
            .iter()
            .any(|u| u.source == Source::Donor && u.path.starts_with("vendor"))
    );
    assert!(
        s.units.iter().any(
            |u| u.source == Source::Target && u.sha256 == digest(b"(type retained_hardware_t)")
        )
    );
}
#[test]
fn refuses_missing_mapping_ambiguous_hardware_and_permissive_domains() {
    let (d, t, mut r) = setup();
    let opt = Options {
        kernel_policy_version: 33,
        policy_version: 30,
    };
    r.donor_source_sha256 = Some("1".repeat(64));
    assert!(select(&d, &t, &r, opt).is_err());
    let (d, mut t, r) = setup();
    put(
        &mut t,
        "vendor_b/etc/selinux/plat_sepolicy_vers.txt",
        "34.0\n",
    );
    assert!(select(&d, &t, &r, opt).is_err());
    let (mut d, t, r) = setup();
    d.artifacts.retain(|a| !a.path.ends_with("34.0.cil"));
    d.inventory
        .metadata_text
        .retain(|p, _| !p.ends_with("34.0.cil"));
    assert!(select(&d, &t, &r, opt).is_err());
    let (mut d, t, r) = setup();
    let path = "system_a/system/etc/selinux/plat_sepolicy.cil";
    d.artifacts.retain(|a| a.path != path);
    put(
        &mut d,
        path,
        "(type platform_t)\n(typepermissive platform_t)",
    );
    assert!(select(&d, &t, &r, opt).is_err());
}
#[test]
fn newer_genfs_requires_the_matching_donor_labels() {
    let (mut d, mut t, r) = setup();
    put(
        &mut t,
        "vendor_a/etc/selinux/genfs_labels_version.txt",
        "202504\n",
    );
    let opt = Options {
        kernel_policy_version: 33,
        policy_version: 30,
    };
    assert!(select(&d, &t, &r, opt).is_err());
    put(
        &mut d,
        "system_a/system/etc/selinux/plat_sepolicy_genfs_202504.cil",
        "; labels are declared by the compiler input\n",
    );
    let s = select(&d, &t, &r, opt).unwrap();
    assert!(!s.genfs_uses_android_default);
    assert!(s.units.last().unwrap().path.ends_with("genfs_202504.cil"));
}
#[test]
fn output_header_requires_kernel_policy_magic_and_requested_version() {
    let temp = tempfile::tempdir().unwrap();
    let p = temp.path().join("policy");
    let mut data = vec![0; 32];
    data[..4].copy_from_slice(&0xf97cff8cu32.to_le_bytes());
    data[4..8].copy_from_slice(&8u32.to_le_bytes());
    data[8..16].copy_from_slice(b"SE Linux");
    data[16..20].copy_from_slice(&33u32.to_le_bytes());
    std::fs::write(&p, &data).unwrap();
    assert_eq!(policy_header(&p, 33).unwrap().policy_version, 33);
    assert!(policy_header(&p, 32).is_err());
    data[0] = 0;
    std::fs::write(&p, data).unwrap();
    assert!(policy_header(&p, 33).is_err());
    std::fs::write(&p, b"short").unwrap();
    assert!(policy_header(&p, 33).is_err());
}
