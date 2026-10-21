//! Narrow, guarded XML additions. Original donor nodes are never removed.
use anyhow::{Context, Result, ensure};
use gb_core::{FirmwareManifest, digest};
use gb_framework::{Recipe, VintfMergeOperation};
use roxmltree::{Document, Node};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overlay {
    pub donor_path: String,
    pub target_path: String,
    pub donor_sha256: String,
    pub target_sha256: String,
    pub device_extension_sha256: BTreeMap<String, String>,
    pub output_sha256: String,
    pub added_nodes: usize,
    pub content: String,
}
fn document(text: &str) -> Result<Document<'_>> {
    ensure!(text.len() <= 16 * 1024 * 1024, "VINTF text exceeds limit");
    let doc = Document::parse(text).context("VINTF XML parsing (DTD disabled)")?;
    ensure!(doc.descendants().count() <= 100_000, "VINTF node limit");
    for n in doc.descendants() {
        ensure!(n.ancestors().count() <= 64, "VINTF depth limit");
        ensure!(
            n.tag_name().namespace().is_none(),
            "namespaced VINTF is unsupported"
        );
    }
    Ok(doc)
}
fn canonical(node: Node<'_, '_>) -> String {
    let mut result = format!("<{}", node.tag_name().name());
    let mut attrs: Vec<_> = node.attributes().map(|a| (a.name(), a.value())).collect();
    attrs.sort();
    for (name, value) in attrs {
        result.push_str(&format!(" {name}={value:?}"));
    }
    result.push('>');
    for child in node.children() {
        if child.is_element() {
            result.push_str(&canonical(child));
        } else if child.is_text() {
            result.push_str(child.text().unwrap_or("").trim());
        }
    }
    result.push_str(&format!("</{}>", node.tag_name().name()));
    result
}
fn child_text<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|n| n.has_tag_name(name))
        .and_then(|n| n.text())
}
fn identifier(s: &str) -> Result<&str> {
    ensure!(
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "unsupported HAL identifier"
    );
    Ok(s)
}
fn device_hal(node: Node<'_, '_>, selected: &[String]) -> Result<String> {
    ensure!(
        node.attribute("format") == Some("aidl") && node.attributes().len() == 1,
        "only ordinary AIDL device extensions are supported"
    );
    let name = identifier(child_text(node, "name").context("HAL name absent")?)?;
    ensure!(
        name.starts_with("vendor.") && selected.iter().any(|n| n == name),
        "unselected or non-vendor device extension"
    );
    let version = child_text(node, "version").unwrap_or("1").parse::<u32>()?;
    ensure!(version > 0, "invalid AIDL version");
    let mut interfaces = BTreeSet::new();
    for child in node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "name" | "version" => (),
            "fqname" => {
                let (interface, instance) = child
                    .text()
                    .context("empty HAL fqname")?
                    .split_once('/')
                    .context("AIDL fqname requires interface/instance")?;
                interfaces.insert((
                    identifier(interface)?.to_string(),
                    identifier(instance)?.to_string(),
                ));
            }
            "interface" => {
                let interface =
                    identifier(child_text(child, "name").context("interface name absent")?)?;
                for instance in child.children().filter(|n| n.is_element()) {
                    ensure!(
                        ["name", "instance"].contains(&instance.tag_name().name()),
                        "unsupported device interface declaration"
                    );
                    if instance.has_tag_name("instance") {
                        interfaces.insert((
                            interface.to_string(),
                            identifier(instance.text().context("empty instance")?)?.to_string(),
                        ));
                    }
                }
            }
            _ => anyhow::bail!("unsupported device HAL child"),
        }
    }
    ensure!(!interfaces.is_empty(), "device HAL has no instances");
    let mut output =
        format!("<hal format=\"aidl\"><name>{name}</name><version>{version}</version>");
    for (interface, instance) in interfaces {
        output.push_str(&format!(
            "<interface><name>{interface}</name><instance>{instance}</instance></interface>"
        ));
    }
    output.push_str("</hal>");
    Ok(output)
}
pub fn generate(
    donor: &FirmwareManifest,
    target: &FirmwareManifest,
    recipe: &Recipe,
) -> Result<Vec<Overlay>> {
    recipe.check_sources(donor, target)?;
    let mut overlays = Vec::new();
    for merge in &recipe.vintf_merges {
        let old = donor
            .inventory
            .metadata_text
            .get(&merge.donor_path)
            .context("donor merge XML absent")?;
        let stock = target
            .inventory
            .metadata_text
            .get(&merge.target_path)
            .context("target merge XML absent")?;
        ensure!(
            digest(old.as_bytes()) == merge.donor_sha256
                && digest(stock.as_bytes()) == merge.target_sha256,
            "VINTF XML fingerprint condition failed"
        );
        let d = document(old)?;
        let t = document(stock)?;
        let dr = d.root_element();
        let tr = t.root_element();
        ensure!(
            dr.attribute("type") == Some("framework")
                && tr.attribute("type") == Some("framework")
                && dr.tag_name() == tr.tag_name(),
            "VINTF merge requires matching framework roots"
        );
        let nodes: Vec<_> = match &merge.operation {
            VintfMergeOperation::RetainedVndk { version } => {
                ensure!(
                    dr.has_tag_name("manifest"),
                    "VNDK merge requires framework manifest"
                );
                let name = format!("com.android.vndk.v{version}");
                let keep = recipe
                    .retain_target_apex
                    .iter()
                    .find(|p| p.name == name)
                    .context("VNDK declaration requires retained target APEX")?;
                let packages: Vec<_> = target
                    .inventory
                    .apex_packages
                    .iter()
                    .filter(|p| p.name == name)
                    .collect();
                ensure!(
                    packages.len() == 1 && packages[0].package_sha256 == keep.sha256,
                    "retained VNDK APEX checksum/identity mismatch"
                );
                let version = version.to_string();
                let nodes: Vec<_> = tr
                    .children()
                    .filter(|n| {
                        n.has_tag_name("vendor-ndk")
                            && child_text(*n, "version") == Some(version.as_str())
                    })
                    .collect();
                ensure!(
                    nodes.len() == 1,
                    "missing or ambiguous stock VNDK declaration"
                );
                ensure!(
                    !dr.children().any(|n| n.has_tag_name("vendor-ndk")
                        && child_text(n, "version") == Some(version.as_str())),
                    "VNDK version already declared; merge unnecessary or conflicting"
                );
                nodes
            }
            VintfMergeOperation::HalDeclarations { names, .. } => {
                ensure!(
                    dr.has_tag_name("compatibility-matrix")
                        && dr.attribute("level").is_none()
                        && tr.attribute("level").is_none(),
                    "HAL additions require device-specific framework matrices"
                );
                for name in names {
                    ensure!(
                        tr.children()
                            .any(|n| n.has_tag_name("hal") && child_text(n, "name") == Some(name)),
                        "stock HAL selector missing: {name}"
                    );
                }
                tr.children()
                    .filter(|n| {
                        n.has_tag_name("hal")
                            && child_text(*n, "name")
                                .is_some_and(|name| names.iter().any(|s| s == name))
                    })
                    .collect()
            }
        };
        let mut seen: BTreeSet<_> = dr
            .children()
            .filter(|n| n.is_element())
            .map(canonical)
            .collect();
        let mut additions = String::new();
        let mut added_nodes = 0;
        for node in nodes {
            if seen.insert(canonical(node)) {
                additions.push_str("\n    ");
                additions.push_str(&stock[node.range()]);
                additions.push('\n');
                added_nodes += 1;
            }
        }
        let mut device_extension_sha256 = BTreeMap::new();
        if let VintfMergeOperation::HalDeclarations {
            names,
            device_extensions,
        } = &merge.operation
        {
            for extension in device_extensions {
                let text = target
                    .inventory
                    .metadata_text
                    .get(&extension.path)
                    .context("device extension XML absent")?;
                ensure!(
                    digest(text.as_bytes()) == extension.sha256,
                    "device extension checksum mismatch"
                );
                let doc = document(text)?;
                let root = doc.root_element();
                ensure!(
                    root.has_tag_name("manifest") && root.attribute("type") == Some("device"),
                    "device manifest fragment required"
                );
                let hals: Vec<_> = root.children().filter(|n| n.is_element()).collect();
                ensure!(
                    !hals.is_empty() && hals.iter().all(|n| n.has_tag_name("hal")),
                    "unsupported device manifest fragment"
                );
                for node in hals {
                    let xml = device_hal(node, names)?;
                    let parsed = document(&xml)?;
                    if seen.insert(canonical(parsed.root_element())) {
                        additions.push_str(&format!("\n    {xml}\n"));
                        added_nodes += 1;
                    }
                }
                device_extension_sha256.insert(extension.path.clone(), extension.sha256.clone());
            }
        }
        ensure!(added_nodes > 0, "VINTF merge adds no new declarations");
        let closing = format!("</{}>", dr.tag_name().name());
        let close = old[..dr.range().end]
            .rfind(&closing)
            .context("explicit VINTF closing tag required")?;
        let content = format!("{}{}{}", &old[..close], additions, &old[close..]);
        document(&content)?;
        overlays.push(Overlay {
            donor_path: merge.donor_path.clone(),
            target_path: merge.target_path.clone(),
            donor_sha256: merge.donor_sha256.clone(),
            target_sha256: merge.target_sha256.clone(),
            device_extension_sha256,
            output_sha256: digest(content.as_bytes()),
            added_nodes,
            content,
        });
    }
    Ok(overlays)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gb_framework::{PartitionPair, VintfMerge};
    use std::collections::BTreeMap;
    fn setup() -> (FirmwareManifest, FirmwareManifest, Recipe) {
        let path = "system_a/system/etc/vintf/compatibility_matrix.device.xml";
        let d = "<compatibility-matrix version=\"9.0\" type=\"framework\"><hal format=\"aidl\"><name>desktop</name></hal></compatibility-matrix>";
        let t = "<compatibility-matrix version=\"9.0\" type=\"framework\"><hal format=\"aidl\"><name>tablet</name><interface><name>IInput</name><instance>default</instance></interface></hal><hal format=\"aidl\"><name>tablet</name><interface><name>IInput</name><instance>default</instance></interface></hal></compatibility-matrix>";
        let mut donor = FirmwareManifest {
            schema_version: 1,
            inspector_version: "test".into(),
            source_sha256: "0".repeat(64),
            artifacts: vec![],
            inventory: Default::default(),
            limitations: vec![],
        };
        donor.inventory.metadata_text.insert(path.into(), d.into());
        let mut target = donor.clone();
        target.inventory.metadata_text.insert(path.into(), t.into());
        let recipe = Recipe {
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
            context_patches: vec![],
            vintf_merges: vec![VintfMerge {
                donor_path: path.into(),
                target_path: path.into(),
                donor_sha256: digest(d.as_bytes()),
                target_sha256: digest(t.as_bytes()),
                operation: VintfMergeOperation::HalDeclarations {
                    names: vec!["tablet".into()],
                    device_extensions: vec![],
                },
            }],
        };
        (donor, target, recipe)
    }
    #[test]
    fn deterministic_additions_preserve_desktop_and_deduplicate_stock() {
        let (d, t, r) = setup();
        let first = generate(&d, &t, &r).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&generate(&d, &t, &r).unwrap()).unwrap()
        );
        assert_eq!(first[0].added_nodes, 1);
        assert!(first[0].content.contains("<name>desktop</name>"));
        assert!(first[0].content.contains("<name>tablet</name>"));
        assert!(
            !d.inventory
                .metadata_text
                .values()
                .next()
                .unwrap()
                .contains("tablet")
        );
    }
    #[test]
    fn guards_hash_selectors_and_hardware_destinations() {
        let (d, t, mut r) = setup();
        r.vintf_merges[0].target_sha256 = "0".repeat(64);
        assert!(generate(&d, &t, &r).is_err());
        let (_, _, mut r) = setup();
        r.vintf_merges[0].operation = VintfMergeOperation::HalDeclarations {
            names: vec!["missing".into()],
            device_extensions: vec![],
        };
        assert!(generate(&d, &t, &r).is_err());
        r.vintf_merges[0].donor_path = "vendor_a/etc/vintf/manifest.xml".into();
        assert!(r.validate().is_err());
    }
    #[test]
    fn vndk_requires_the_matching_retained_snapshot_and_xml_is_bounded() {
        let (d, t, mut r) = setup();
        r.vintf_merges[0].operation = VintfMergeOperation::RetainedVndk { version: 34 };
        assert!(generate(&d, &t, &r).is_err());
        assert!(document("<!DOCTYPE manifest [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><manifest>&x;</manifest>").is_err());
        assert!(document("<manifest xmlns='unexpected'/>").is_err());
        assert!(document(&format!("{}{}", "<n>".repeat(65), "</n>".repeat(65))).is_err());
    }
    #[test]
    fn device_extension_versions_are_exact_and_guarded() {
        let (d, mut t, mut r) = setup();
        let path = "vendor_a/etc/vintf/manifest/input.xml";
        let xml = "<manifest type=\"device\"><hal format=\"aidl\"><name>vendor.tablet</name><version>5</version><fqname>IInput/default</fqname></hal></manifest>";
        t.inventory.metadata_text.insert(path.into(), xml.into());
        let donor_matrix = d.inventory.metadata_text.values().next().unwrap();
        let stock_matrix = "<compatibility-matrix type=\"framework\"><hal format=\"aidl\"><name>vendor.tablet</name><version>3</version></hal></compatibility-matrix>";
        let merge = &mut r.vintf_merges[0];
        t.inventory
            .metadata_text
            .insert(merge.target_path.clone(), stock_matrix.into());
        merge.target_sha256 = digest(stock_matrix.as_bytes());
        merge.donor_sha256 = digest(donor_matrix.as_bytes());
        merge.operation = VintfMergeOperation::HalDeclarations {
            names: vec!["vendor.tablet".into()],
            device_extensions: vec![gb_framework::DeviceHalExtension {
                path: path.into(),
                sha256: digest(xml.as_bytes()),
            }],
        };
        let result = generate(&d, &t, &r).unwrap();
        assert!(result[0].content.contains("<version>5</version>"));
        assert!(result[0].content.contains("<version>3</version>"));
        assert_eq!(
            result[0].device_extension_sha256[path],
            digest(xml.as_bytes())
        );
        t.inventory
            .metadata_text
            .insert(path.into(), xml.replace("<version>5", "<version>6"));
        assert!(generate(&d, &t, &r).is_err());
    }
}
