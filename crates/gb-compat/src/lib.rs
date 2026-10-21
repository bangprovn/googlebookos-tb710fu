//! Conservative compatibility evidence: presence or telemetry is not boot success.
pub mod gunyah_memory;
pub mod gunyah_stage;
pub mod host_egl;
pub mod host_vulkan;
use gb_config::Profile;
use gb_core::{CompatibilityReport, Finding, FirmwareManifest, State};

fn finding(feature: &str, state: State, evidence: Vec<String>) -> Finding {
    Finding {
        feature: feature.into(),
        state,
        evidence,
        runtime_verified: false,
    }
}
fn architecture(m: &FirmwareManifest) -> Option<String> {
    let normalize = |value| match value {
        "arm64-v8a" => "aarch64",
        "armeabi-v7a" | "armeabi" => "arm",
        value => value,
    };
    let userspace = m
        .inventory
        .properties
        .iter()
        .filter(|p| p.key == "ro.product.cpu.abi")
        .map(|p| normalize(p.value.as_str()))
        .collect::<std::collections::BTreeSet<_>>();
    let userspace = match userspace.len() {
        0 => None,
        1 => userspace.first().copied(),
        // A firmware inventory may include both supported widths. That is not
        // a cross-family conflict, and the wider ABI still needs a wide kernel.
        _ if userspace.iter().all(|a| ["arm", "aarch64"].contains(a)) => Some("aarch64"),
        _ if userspace.iter().all(|a| ["x86", "x86_64"].contains(a)) => Some("x86_64"),
        _ => return None,
    };
    let kernels = m
        .artifacts
        .iter()
        .filter(|a| a.format == gb_core::Format::Boot)
        .filter_map(|a| {
            a.metadata
                .get("kernel_architecture")
                .and_then(|v| v.as_str())
        })
        .map(normalize)
        .collect::<std::collections::BTreeSet<_>>();
    let kernel = match kernels.len() {
        0 => None,
        1 => kernels.first().copied(),
        _ => return None,
    };
    match (userspace, kernel) {
        (Some(abi), Some(kernel))
            if abi == kernel || matches!((abi, kernel), ("arm", "aarch64") | ("x86", "x86_64")) =>
        {
            // A32 on A64 is possible; this does not verify CONFIG_COMPAT or
            // operation. The finding remains a static architecture check.
            Some(abi.into())
        }
        (Some(_), Some(_)) => None,
        (Some(abi), None) => Some(abi.into()),
        (None, Some(kernel)) => Some(kernel.into()),
        (None, None) => None,
    }
}
pub fn check(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    profile: Option<&Profile>,
) -> CompatibilityReport {
    let mut f = Vec::new();
    let da = architecture(donor);
    let ta = architecture(target);
    f.push(match (&da, &ta) {
        (Some(a), Some(b)) if a == b => finding(
            "architecture",
            State::Compatible,
            vec![format!(
                "Donor and target inspected architecture: {a}; static property/kernel evidence only, not loader, kernel compat-mode or runtime validation"
            )],
        ),
        (Some(a), Some(b)) => finding(
            "architecture",
            State::Unsupported,
            vec![format!("Donor {a} differs from target {b}")],
        ),
        _ => finding(
            "architecture",
            State::Unknown,
            vec!["Inspected userspace/boot-kernel architecture evidence missing or conflicting".into()],
        ),
    });
    let android = match (
        donor.property("ro.build.version.release"),
        target.property("ro.build.version.release"),
    ) {
        (Some(a), Some(b)) if a != b => finding(
            "android_framework_vendor_boundary",
            State::PatchRequired,
            vec![format!(
                "Donor Android {a}, target Android {b}; check FCM, binder ABI, kernel and vendor API requirements"
            )],
        ),
        (Some(a), Some(_)) => finding(
            "android_framework_vendor_boundary",
            State::Unknown,
            vec![format!(
                "Both report Android {a}; this does not prove vendor compatibility"
            )],
        ),
        _ => finding(
            "android_framework_vendor_boundary",
            State::Unknown,
            vec!["Complete donor/target build properties not available".into()],
        ),
    };
    f.push(android);
    let boot_versions = |m: &FirmwareManifest| {
        m.artifacts
            .iter()
            .filter(|a| a.format == gb_core::Format::Boot)
            .filter_map(|a| a.metadata.get("header_version").and_then(|v| v.as_u64()))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let db = boot_versions(donor);
    let tb = boot_versions(target);
    f.push(finding("boot_header",if db.is_empty()||tb.is_empty(){State::Unknown}else if db==tb {State::Compatible}else{State::PatchRequired},vec![format!("Inspected donor versions {db:?}, target versions {tb:?}; this check covers header structure only")]));
    let matrix = donor
        .inventory
        .vintf
        .iter()
        .filter(|d| d.kind == "compatibility-matrix" && d.role.as_deref() == Some("framework"))
        .count();
    let device = target
        .inventory
        .vintf
        .iter()
        .filter(|d| d.kind == "manifest" && d.role.as_deref() == Some("device"))
        .count();
    f.push(finding("vintf",State::Unknown,vec![format!("{matrix} donor framework matrices, {device} target device declarations; FCM selection, HAL versions/instances and runtime kernel requirements need checkvintf") ]));
    let desktop = donor
        .inventory
        .vintf
        .iter()
        .filter(|d| {
            d.kind == "compatibility-matrix"
                && d.role.as_deref() == Some("framework")
                && d.level.is_none()
        })
        .flat_map(|d| {
            d.hals
                .iter()
                .filter(|h| !h.optional && h.name.contains("desktop"))
        })
        .map(|h| (&h.name, &h.format))
        .collect::<std::collections::BTreeSet<_>>();
    let declared = target
        .inventory
        .vintf
        .iter()
        .filter(|d| d.kind == "manifest" && d.role.as_deref() == Some("device"))
        .flat_map(|d| d.hals.iter().map(|h| (&h.name, &h.format)))
        .collect::<std::collections::BTreeSet<_>>();
    let missing_desktop = desktop
        .difference(&declared)
        .map(|(name, format)| format!("{name} ({format})"))
        .collect::<Vec<_>>();
    f.push(finding("desktop_vendor_interfaces", if missing_desktop.is_empty() {State::Unknown} else {State::ImplementationRequired},
        vec![format!("{} required desktop HAL name/format pairs in donor device-specific framework matrices",desktop.len()),
        format!("Declarations absent from inspected target device manifests: {}",missing_desktop.join(", ")),
        "This is a static declaration gap: integrate or adapt the required services; SKU selection, vendor APEX fragments, versions/instances and runtime operation still need validation".into()]));
    let domains = [
        ("kernel_gki_kmi", "/modules/"),
        ("gpu_egl_vulkan_gralloc_hwc", "graphics"),
        ("display_external_display", "composer"),
        ("touch_keyboard_stylus", "input"),
        ("audio_routing", "audio"),
        ("camera_provider", "camera"),
        ("wifi", "wifi"),
        ("bluetooth", "bluetooth"),
        ("usb_host_type_c", "usb"),
        ("sensors_rotation", "sensors"),
        ("power_thermal_suspend", "power"),
        ("storage_encryption_key_management", "keymint"),
        ("hardware_keystore_attestation", "keymint"),
        ("framework_vendor_binder", "binder"),
        ("google_services_permissions", "google"),
        ("apex_bootclasspath_system_server", "apex"),
        ("selinux_policy", "selinux"),
        ("avb_rollback_signing", "vbmeta"),
    ];
    for (feature, needle) in domains {
        let paths = target
            .artifacts
            .iter()
            .filter(|a| a.path.contains(needle))
            .map(|a| a.path.clone())
            .take(4)
            .collect::<Vec<_>>();
        let mut evidence = vec![
            "Runtime behavior and complete cross-partition compatibility not validated".into(),
        ];
        if !paths.is_empty() {
            evidence.push(format!("Inventory evidence only: {}", paths.join(", ")));
        }
        f.push(finding(feature, State::Unknown, evidence));
    }
    let hardware = |path: &str| {
        let p = path.split('/').next().unwrap_or("");
        let role = p
            .strip_suffix("_a")
            .or_else(|| p.strip_suffix("_b"))
            .unwrap_or(p);
        ["vendor", "odm", "vendor_dlkm", "odm_dlkm"].contains(&role)
    };
    let pool = donor
        .inventory
        .native_libraries
        .iter()
        .filter(|l| !hardware(&l.path))
        .chain(
            target
                .inventory
                .native_libraries
                .iter()
                .filter(|l| hardware(&l.path)),
        )
        .collect::<Vec<_>>();
    let available = pool
        .iter()
        .flat_map(|l| {
            l.soname
                .iter()
                .map(String::as_str)
                .chain(l.path.rsplit('/').next().filter(|p| p.ends_with(".so")))
                .map(|name| (l.architecture.as_str(), name))
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut unresolved = Vec::new();
    for library in &pool {
        for name in &library.needed {
            if !available.contains(&(library.architecture.as_str(), name.as_str())) {
                unresolved.push(format!(
                    "{} needs {} ({})",
                    library.path, name, library.architecture
                ));
            }
        }
    }
    f.push(finding("native_library_dependencies",State::Unknown,vec![format!("{} unresolved architecture-matched provider edges in proposed donor userspace + target vendor/ODM inventory; first candidates: {:?}",unresolved.len(),unresolved.iter().take(30).collect::<Vec<_>>()),
        "Discarded target system and donor vendor libraries are excluded; linker namespaces, symbols, library symlinks and APEX contents still require validation".into()]));
    let mut blockers = vec![
        "No validated image assembly/signing recipe for target".into(),
        "No physical runtime validation of Googlebook desktop or hardware".into(),
        "Complete donor/target VINTF, SELinux, ABI and boot-chain validation required".into(),
    ];
    if donor.inventory.framework.is_empty() {
        blockers
            .push("Donor framework inventory unavailable; extract donor filesystem images".into());
    }
    if !missing_desktop.is_empty() {
        blockers.push(format!(
            "Desktop vendor-interface integration required for {} missing declaration pairs",
            missing_desktop.len()
        ));
    }
    if let Some(p) = profile {
        if p.firmware.completeness != "complete" {
            blockers.push(format!(
                "Target firmware input is {}; obtain exact stock partition images",
                p.firmware.completeness
            ));
        }
        if p.boot.strategy.observed().is_none() {
            blockers.push("Flash strategy has not been verified; user-reported EDL/test-key behavior remains unverified".into());
        }
        blockers.extend(p.external_prerequisites.iter().cloned());
        if let (Some(profile_arch), Some(target_arch)) =
            (p.device.architecture.observed(), ta.as_ref())
            && profile_arch != target_arch
        {
            blockers.push("Device profile architecture conflicts with firmware inspection".into());
            f.push(finding(
                "device_profile_architecture",
                State::Unsupported,
                vec![format!("Profile {profile_arch}, firmware {target_arch}")],
            ));
        }
    }
    CompatibilityReport {
        schema_version: 1,
        donor_sha256: donor.source_sha256.clone(),
        target_sha256: target.source_sha256.clone(),
        findings: f,
        bootable: false,
        blockers,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use gb_core::{Inventory, Property};
    fn m(arch: &str, android: &str) -> FirmwareManifest {
        FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "hash".into(),
            artifacts: vec![],
            inventory: Inventory {
                properties: vec![
                    Property {
                        path: "build.prop".into(),
                        key: "ro.product.cpu.abi".into(),
                        value: arch.into(),
                    },
                    Property {
                        path: "build.prop".into(),
                        key: "ro.build.version.release".into(),
                        value: android.into(),
                    },
                ],
                ..Default::default()
            },
            limitations: vec![],
        }
    }
    fn boot_kernel(manifest: &mut FirmwareManifest, architecture: &str) {
        manifest.artifacts.push(gb_core::Artifact {
            path: "boot.img".into(),
            bytes: 4096,
            sha256: "hash".into(),
            format: gb_core::Format::Boot,
            metadata: serde_json::json!({"kernel_architecture": architecture}),
        });
    }

    #[test]
    fn conflicting_userspace_architectures_are_not_hidden_by_kernel_fallback() {
        let donor = m("arm64-v8a", "17");
        let mut target = m("arm64-v8a", "16");
        target.inventory.properties.push(Property {
            path: "other/build.prop".into(),
            key: "ro.product.cpu.abi".into(),
            value: "x86_64".into(),
        });
        boot_kernel(&mut target, "aarch64");
        let report = check(&donor, &target, None);
        assert_eq!(report.findings[0].state, State::Unknown);
        assert!(!report.findings[0].runtime_verified);
    }

    #[test]
    fn userspace_abi_does_not_override_conflicting_or_narrower_kernel() {
        let donor = m("arm64-v8a", "17");
        for kernel in ["x86_64", "arm"] {
            let mut target = m("arm64-v8a", "16");
            boot_kernel(&mut target, kernel);
            let report = check(&donor, &target, None);
            assert_eq!(report.findings[0].state, State::Unknown, "{kernel}");
            assert!(!report.bootable);
        }
    }

    #[test]
    fn mixed_arm_abis_and_a32_userspace_on_a64_kernel_are_not_conflicts() {
        let donor = m("arm64-v8a", "17");
        let mut target = m("arm64-v8a", "16");
        target.inventory.properties.push(Property {
            path: "build.prop".into(),
            key: "ro.product.cpu.abilist".into(),
            value: "arm64-v8a,armeabi-v7a,armeabi".into(),
        });
        boot_kernel(&mut target, "aarch64");
        assert_eq!(
            check(&donor, &target, None).findings[0].state,
            State::Compatible
        );
        target.inventory.properties.push(Property {
            path: "other/build.prop".into(),
            key: "ro.product.cpu.abi".into(),
            value: "armeabi-v7a".into(),
        });
        assert_eq!(
            check(&donor, &target, None).findings[0].state,
            State::Compatible
        );

        let donor = m("armeabi-v7a", "17");
        let mut target = m("armeabi-v7a", "16");
        boot_kernel(&mut target, "aarch64");
        assert_eq!(
            check(&donor, &target, None).findings[0].state,
            State::Compatible
        );
    }

    #[test]
    fn missing_userspace_abi_can_use_only_consistent_boot_kernel_evidence() {
        let donor = m("arm64-v8a", "17");
        let mut target = m("arm64-v8a", "16");
        target
            .inventory
            .properties
            .retain(|p| p.key != "ro.product.cpu.abi");
        boot_kernel(&mut target, "aarch64");
        let report = check(&donor, &target, None);
        assert_eq!(report.findings[0].state, State::Compatible);
        assert!(report.findings.iter().all(|f| !f.runtime_verified));
        target.artifacts[0].format = gb_core::Format::Elf;
        assert_eq!(
            check(&donor, &target, None).findings[0].state,
            State::Unknown
        );
    }

    #[test]
    fn desktop_service_declaration_gap_is_not_hardware_success() {
        let mut donor = m("arm64-v8a", "17");
        let mut target = m("arm64-v8a", "16");
        let hal = gb_core::Hal {
            name: "com.android.desktop.power".into(),
            format: "aidl".into(),
            optional: false,
            versions: vec!["1".into()],
            interfaces: vec!["IDesktopPowerChargeControl/default".into()],
        };
        donor.inventory.vintf.push(gb_core::VintfDocument {
            path: "system/etc/vintf/compatibility_matrix.device.xml".into(),
            kind: "compatibility-matrix".into(),
            role: Some("framework".into()),
            level: None,
            hals: vec![hal.clone()],
        });
        let report = check(&donor, &target, None);
        let finding = report
            .findings
            .iter()
            .find(|f| f.feature == "desktop_vendor_interfaces")
            .unwrap();
        assert_eq!(finding.state, State::ImplementationRequired);
        assert!(!finding.runtime_verified);
        target.inventory.vintf.push(gb_core::VintfDocument {
            path: "vendor/etc/vintf/manifest.xml".into(),
            kind: "manifest".into(),
            role: Some("device".into()),
            level: Some("8".into()),
            hals: vec![hal],
        });
        let report = check(&donor, &target, None);
        assert_eq!(
            report
                .findings
                .iter()
                .find(|f| f.feature == "desktop_vendor_interfaces")
                .unwrap()
                .state,
            State::Unknown
        );
    }
    #[test]
    fn android16_is_not_auto_rejected_or_approved() {
        let r = check(&m("arm64-v8a", "17"), &m("arm64-v8a", "16"), None);
        assert_eq!(r.findings[0].state, State::Compatible);
        assert_eq!(r.findings[1].state, State::PatchRequired);
        assert!(!r.bootable);
        assert!(r.findings.iter().all(|f| !f.runtime_verified));
    }
    #[test]
    fn same_android_does_not_prove_compat() {
        let r = check(&m("arm64-v8a", "17"), &m("arm64-v8a", "17"), None);
        assert_eq!(r.findings[1].state, State::Unknown);
    }
    #[test]
    fn abi_mismatch_is_unsupported() {
        assert_eq!(
            check(&m("x86_64", "17"), &m("arm64-v8a", "16"), None).findings[0].state,
            State::Unsupported
        );
    }
}
