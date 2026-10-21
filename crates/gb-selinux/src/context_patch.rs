//! Exact, source-guarded context adjustments for retained hardware ownership.
use anyhow::{Context, Result, ensure};
use gb_core::{FirmwareManifest, digest};
use gb_framework::{ContextPatchOperation, Recipe};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureObservation {
    pub sha256: String,
    pub data: serde_json::Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub reason: String,
    pub operation: ContextPatchOperation,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overlay {
    pub path: String,
    pub original_sha256: String,
    pub output_sha256: String,
    pub content: String,
    pub actions: Vec<Action>,
}
pub fn generate(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
    observation: Option<&FeatureObservation>,
) -> Result<Vec<Overlay>> {
    donor.validate()?;
    target.validate()?;
    recipe.check_sources(donor, target)?;
    let mut overlays: BTreeMap<String, Overlay> = BTreeMap::new();
    for patch in &recipe.context_patches {
        let original = donor
            .inventory
            .metadata_text
            .get(&patch.donor_path)
            .context("context patch text absent")?;
        ensure!(
            digest(original.as_bytes()) == patch.donor_sha256,
            "context patch original digest condition failed"
        );
        let overlay = overlays
            .entry(patch.donor_path.clone())
            .or_insert_with(|| Overlay {
                path: patch.donor_path.clone(),
                original_sha256: patch.donor_sha256.clone(),
                output_sha256: String::new(),
                content: original.clone(),
                actions: vec![],
            });
        match &patch.operation {
            ContextPatchOperation::RemoveExactRule {
                rule,
                target_path_absent,
                absent_target_feature,
            } => {
                if let Some(path) = target_path_absent {
                    let part = path.split('/').next().context("absent file partition")?;
                    ensure!(
                        target
                            .artifacts
                            .iter()
                            .any(|a| a.path.starts_with(&format!("{part}/"))),
                        "target hardware partition inventory absent"
                    );
                    ensure!(
                        !target.artifacts.iter().any(|a| a.path == *path)
                            && !target.inventory.symlinks.contains_key(path),
                        "context removal condition failed: target file/link exists"
                    );
                }
                if let Some(feature) = absent_target_feature {
                    let observation =
                        observation.context("complete target feature observation required")?;
                    ensure!(
                        observation.sha256.len() == 64
                            && observation.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                            && observation
                                .data
                                .get("schema_version")
                                .and_then(|v| v.as_u64())
                                == Some(1),
                        "invalid feature observation schema/digest"
                    );
                    ensure!(
                        observation.data.get("source").and_then(|v| v.as_str())
                            == Some("read_only_adb")
                            && observation
                                .data
                                .get("complete_declared_feature_listing")
                                .and_then(|v| v.as_bool())
                                == Some(true),
                        "feature evidence is not a complete stock observation"
                    );
                    let fingerprint = observation
                        .data
                        .get("properties")
                        .and_then(|v| v.get("ro.build.fingerprint"))
                        .and_then(|v| v.as_str())
                        .context("feature observation fingerprint absent")?;
                    if target
                        .inventory
                        .properties
                        .iter()
                        .any(|p| p.key == "ro.build.fingerprint")
                    {
                        ensure!(
                            target.property("ro.build.fingerprint").is_some(),
                            "ambiguous target fingerprint evidence"
                        );
                    }
                    let target_fingerprint = target
                        .property("ro.build.fingerprint")
                        .or_else(|| target.property("ro.system.build.fingerprint"));
                    ensure!(
                        !fingerprint.is_empty() && target_fingerprint == Some(fingerprint),
                        "target feature observation fingerprint differs from firmware"
                    );
                    let features = observation
                        .data
                        .get("declared_features")
                        .and_then(|v| v.as_object())
                        .context("declared feature data absent")?;
                    ensure!(
                        !features.is_empty() && !features.contains_key(feature),
                        "target declared-feature absence condition failed"
                    );
                }
                let count = overlay
                    .content
                    .lines()
                    .filter(|l| l.trim() == rule.trim())
                    .count();
                ensure!(count == 1, "context removal requires one exact rule");
                overlay.content = overlay
                    .content
                    .split_inclusive('\n')
                    .filter(|l| l.trim() != rule.trim())
                    .collect();
            }
            ContextPatchOperation::UseTargetLabel {
                target_path,
                target_sha256,
                selector,
            } => {
                let map_kind = super::contexts::kind(&patch.donor_path);
                ensure!(
                    matches!(
                        map_kind,
                        Some(
                            super::contexts::Kind::Service
                                | super::contexts::Kind::Hwservice
                                | super::contexts::Kind::Vndservice
                                | super::contexts::Kind::TeeService
                        )
                    ) && super::contexts::kind(target_path) == map_kind,
                    "target label operation requires matching service-map kinds"
                );
                let stock = target
                    .inventory
                    .metadata_text
                    .get(target_path)
                    .context("target label text absent")?;
                ensure!(
                    digest(stock.as_bytes()) == *target_sha256,
                    "target label input digest condition failed"
                );
                let entries: Vec<_> = stock
                    .lines()
                    .filter(|l| l.split_whitespace().next() == Some(selector))
                    .collect();
                ensure!(
                    entries.len() == 1 && entries[0].split_whitespace().count() == 2,
                    "target context selector absent/ambiguous"
                );
                let count = overlay
                    .content
                    .lines()
                    .filter(|l| l.split_whitespace().next() == Some(selector))
                    .count();
                ensure!(count == 1, "donor context selector absent/ambiguous");
                let mut content = String::new();
                for line in overlay.content.split_inclusive('\n') {
                    if line.split_whitespace().next() == Some(selector) {
                        content.push_str(entries[0]);
                        content.push('\n');
                    } else {
                        content.push_str(line);
                    }
                }
                overlay.content = content;
            }
        }
        overlay.actions.push(Action {
            reason: patch.reason.clone(),
            operation: patch.operation.clone(),
        });
    }
    for overlay in overlays.values_mut() {
        overlay.output_sha256 = digest(overlay.content.as_bytes());
        ensure!(
            overlay.output_sha256 != overlay.original_sha256,
            "context patch made no content change"
        );
    }
    Ok(overlays.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gb_core::{Artifact, Format, Property};
    use gb_framework::{ContextPatch, PartitionPair};
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
    fn setup() -> (FirmwareManifest, FirmwareManifest, Recipe) {
        let mut d = FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "0".repeat(64),
            artifacts: vec![],
            inventory: Default::default(),
            limitations: vec![],
        };
        let mut t = d.clone();
        put(
            &mut d,
            "system_a/system/etc/selinux/plat_service_contexts",
            "desktop u:object_r:desktop_service:s0\nstrongbox u:object_r:old_service:s0\n",
        );
        put(
            &mut t,
            "vendor_a/etc/selinux/vendor_service_contexts",
            "strongbox u:object_r:stock_service:s0\n",
        );
        put(
            &mut t,
            "system_a/system/build.prop",
            "ro.system.build.fingerprint=stock\n",
        );
        t.inventory.properties.push(Property {
            path: "system_a/system/build.prop".into(),
            key: "ro.system.build.fingerprint".into(),
            value: "stock".into(),
        });
        let path = "system_a/system/etc/selinux/plat_service_contexts";
        let target = "vendor_a/etc/selinux/vendor_service_contexts";
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
            donor_source_sha256: Some(d.source_sha256.clone()),
            target_source_sha256: Some(t.source_sha256.clone()),
            retain_target_apex: vec![],
            vintf_merges: vec![],
            context_patches: vec![ContextPatch {
                donor_path: path.into(),
                donor_sha256: digest(d.inventory.metadata_text[path].as_bytes()),
                reason: "retained hardware".into(),
                operation: ContextPatchOperation::UseTargetLabel {
                    target_path: target.into(),
                    target_sha256: digest(t.inventory.metadata_text[target].as_bytes()),
                    selector: "strongbox".into(),
                },
            }],
        };
        (d, t, r)
    }
    #[test]
    fn exact_stock_label_overlay_preserves_other_rules_and_original_bytes() {
        let (d, t, r) = setup();
        let o = generate(&d, &t, &r, None).unwrap();
        assert_eq!(o.len(), 1);
        assert!(
            o[0].content
                .contains("desktop u:object_r:desktop_service:s0")
        );
        assert!(
            o[0].content
                .contains("strongbox u:object_r:stock_service:s0")
        );
        assert!(d.inventory.metadata_text[&o[0].path].contains("old_service"));
        assert_eq!(o[0].output_sha256, digest(o[0].content.as_bytes()));
        let mut wrong = r;
        wrong.context_patches[0].donor_sha256 = "1".repeat(64);
        assert!(generate(&d, &t, &wrong, None).is_err());
    }
    #[test]
    fn removals_require_actual_absence_and_matching_complete_feature_evidence() {
        let (d, mut t, mut r) = setup();
        r.context_patches[0].operation = ContextPatchOperation::RemoveExactRule {
            rule: "strongbox u:object_r:old_service:s0".into(),
            target_path_absent: Some("vendor_a/bin/unused".into()),
            absent_target_feature: Some("android.hardware.telephony".into()),
        };
        assert!(generate(&d, &t, &r, None).is_err());
        let mut observation = FeatureObservation {
            sha256: "2".repeat(64),
            data: serde_json::json!({"schema_version":1,"source":"read_only_adb","complete_declared_feature_listing":true,"properties":{"ro.build.fingerprint":"stock"},"declared_features":{"android.hardware.touchscreen":0}}),
        };
        assert!(
            !generate(&d, &t, &r, Some(&observation)).unwrap()[0]
                .content
                .contains("strongbox")
        );
        observation.data["declared_features"]["android.hardware.telephony"] = serde_json::json!(0);
        assert!(generate(&d, &t, &r, Some(&observation)).is_err());
        observation.data["declared_features"]
            .as_object_mut()
            .unwrap()
            .remove("android.hardware.telephony");
        observation.data["properties"]["ro.build.fingerprint"] = serde_json::json!("other");
        assert!(generate(&d, &t, &r, Some(&observation)).is_err());
        observation.data["properties"]["ro.build.fingerprint"] = serde_json::json!("stock");
        put(&mut t, "vendor_a/bin/unused", "present");
        assert!(generate(&d, &t, &r, Some(&observation)).is_err());
    }
}
