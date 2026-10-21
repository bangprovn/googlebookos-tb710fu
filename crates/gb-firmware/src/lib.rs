//! Streaming normalization of recovery ZIPs, raw images and extracted trees.
pub mod abi;
pub mod analysis;
pub mod elf;
pub mod filesystem;
pub mod kernel_modules;
pub mod ota_reconstruct;
pub mod runpath;
pub mod text_collection;
use anyhow::{Context, Result, bail, ensure};
use gb_core::{
    Artifact, FirmwareManifest, Format, Hal, Inventory, Property, VintfDocument, checkpoint,
    copy_stream, digest, hash_file, hash_reader, safe_relative, separate_from_input,
};
use gb_partition::{ReadSeek, Region, avb_footer, detect, gpt, inspect, read_at, super_metadata};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Seek, SeekFrom},
    path::Path,
};

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_expanded_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
    pub apex_tools: Option<filesystem::FilesystemTools>,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_expanded_bytes: 512 * 1024 * 1024 * 1024,
            max_entries: 200_000,
            max_depth: 8,
            apex_tools: None,
        }
    }
}
struct Scanner<'a> {
    result: FirmwareManifest,
    // Physical extracted-tree entries only. Nested ZIP/GPT/super/APEX records
    // enrich the inventory but must not change the identity of the source tree.
    source_rows: Vec<String>,
    limits: &'a Limits,
    entries: usize,
    expanded: u64,
    apex_depth: usize,
    scratch: &'a Path,
}
/// Never mounts images or executes binaries from firmware. ZIP member names are validated
/// even though members are staged into generated temporary filenames.
/// `source_sha256` identifies input bytes: the file digest, or the canonical
/// physical-file/symlink tree digest used by `input_digest`. Derived container
/// members remain independently hashed artifacts, outside that source identity.
pub fn inspect_firmware(input: &Path, scratch: &Path, limits: &Limits) -> Result<FirmwareManifest> {
    let meta = fs::symlink_metadata(input)
        .with_context(|| format!("firmware input {}", input.display()))?;
    ensure!(
        !meta.file_type().is_symlink(),
        "firmware input must not be a symlink"
    );
    separate_from_input(input, scratch)?;
    fs::create_dir_all(scratch)?;
    let mut s = Scanner {
        result: FirmwareManifest {
            schema_version: 1,
            inspector_version: env!("CARGO_PKG_VERSION").into(),
            source_sha256: String::new(),
            artifacts: Vec::new(),
            inventory: Inventory::default(),
            limitations: Vec::new(),
        },
        source_rows: Vec::new(),
        limits,
        entries: 0,
        expanded: 0,
        apex_depth: 0,
        scratch,
    };
    if meta.is_dir() {
        s.directory(input, input, 0)?;
        s.source_rows.sort();
        s.result.source_sha256 = digest(s.source_rows.join("").as_bytes());
        if input.join("capture.json").exists() {
            s.result.limitations.push("Input is a live partial capture; partition images and complete filesystem evidence unavailable".into());
        }
    } else {
        ensure!(
            meta.is_file(),
            "firmware input must be a regular file or directory"
        );
        let mut f = File::open(input)?;
        let b = read_at(&mut f, 0, meta.len().min(8192) as usize)?;
        ensure!(
            detect(&b) != Format::Unknown,
            "unknown or encrypted firmware container; extraction refused"
        );
        s.image(&mut f, "input", 0)?;
        s.result.source_sha256 = s
            .result
            .artifacts
            .first()
            .context("empty inspection")?
            .sha256
            .clone();
    }
    s.result.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    reindex_categories(&mut s.result);
    s.result
        .inventory
        .properties
        .sort_by(|a, b| (&a.path, &a.key).cmp(&(&b.path, &b.key)));
    s.result.inventory.vintf.sort_by(|a, b| a.path.cmp(&b.path));
    s.result
        .inventory
        .native_libraries
        .sort_by(|a, b| a.path.cmp(&b.path));
    s.result
        .limitations
        .push("Static inspection only; no hardware feature has been runtime verified".into());
    s.result.limitations.sort();
    s.result.limitations.dedup();
    Ok(s.result)
}
/// Derive path categories from existing artifact records. This adds no content
/// analysis and does not claim to re-verify the source firmware or package trust.
pub fn is_metadata_text(name: &str) -> bool {
    let basename = name.rsplit('/').next().unwrap_or(name);
    (name.contains("/vintf/") && name.ends_with(".xml"))
        || (name.contains("/init/") && name.ends_with(".rc"))
        || (name.contains("/selinux/")
            && (name.ends_with(".cil")
                || basename.ends_with("_version")
                || basename.ends_with("_contexts")
                || [
                    "plat_sepolicy_vers.txt",
                    "genfs_labels_version.txt",
                    "mac_permissions.xml",
                ]
                .iter()
                .any(|suffix| basename.ends_with(suffix))))
        || [
            "apexkeys.txt",
            "ld.config.txt",
            "linker.config.json",
            "init.environ.rc",
        ]
        .contains(&basename)
        || basename.starts_with("public.libraries")
        || basename.starts_with("fstab.")
}
/// Add captured text only when it matches an existing image artifact exactly.
/// The source-image identity is unchanged: this adds evidence, not firmware.
pub fn attach_text(manifest: &mut FirmwareManifest, path: &str, bytes: &[u8]) -> Result<()> {
    gb_core::safe_relative(Path::new(path))?;
    ensure!(
        is_metadata_text(path) && bytes.len() <= 16 * 1024 * 1024,
        "not bounded supported text metadata"
    );
    let artifact = manifest
        .artifacts
        .iter()
        .find(|a| a.path == path)
        .context("text path absent from image inventory")?;
    ensure!(
        artifact.bytes == bytes.len() as u64 && artifact.sha256 == digest(bytes),
        "captured text does not match inspected image"
    );
    let text = std::str::from_utf8(bytes).context("non-UTF8 metadata")?;
    let other = manifest
        .inventory
        .metadata_text
        .iter()
        .filter(|(p, _)| p.as_str() != path)
        .map(|(_, t)| t.len())
        .sum::<usize>();
    ensure!(
        other
            .checked_add(bytes.len())
            .is_some_and(|n| n <= 32 * 1024 * 1024),
        "metadata text aggregate limit exceeded"
    );
    manifest
        .inventory
        .metadata_text
        .insert(path.into(), text.into());
    Ok(())
}
pub fn reindex_categories(manifest: &mut FirmwareManifest) {
    let in_dir = |name: &str, dir: &str| {
        name.rsplit_once('/')
            .is_some_and(|(parent, _)| parent.split('/').any(|part| part == dir))
    };
    let paths = |select: &dyn Fn(&str) -> bool| {
        let mut paths = manifest
            .artifacts
            .iter()
            .map(|a| a.path.as_str())
            .filter(|p| select(p))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        paths
    };
    manifest.inventory.framework = paths(&|p| in_dir(p, "framework"));
    manifest.inventory.apex = paths(&|p| p.ends_with(".apex") || p.ends_with(".capex"));
    manifest.inventory.selinux =
        paths(&|p| in_dir(p, "selinux") || p.ends_with("/sepolicy") || p == "sepolicy");
    manifest.inventory.init = paths(&|p| in_dir(p, "init") && p.ends_with(".rc"));
    manifest.inventory.permissions = paths(&|p| in_dir(p, "permissions") && p.ends_with(".xml"));
    manifest.inventory.modules = paths(&|p| p.ends_with(".ko"));
}
impl Scanner<'_> {
    fn entry(&mut self) -> Result<()> {
        checkpoint()?;
        self.entries += 1;
        ensure!(
            self.entries <= self.limits.max_entries,
            "firmware entry limit exceeded"
        );
        Ok(())
    }
    fn directory(&mut self, root: &Path, dir: &Path, depth: usize) -> Result<()> {
        self.directory_named(root, dir, depth, "")
    }
    fn directory_named(
        &mut self,
        root: &Path,
        dir: &Path,
        depth: usize,
        prefix: &str,
    ) -> Result<()> {
        ensure!(depth <= 64, "extracted tree depth limit exceeded");
        let mut paths = fs::read_dir(dir)?
            .map(|e| e.map(|x| x.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        for p in paths {
            self.entry()?;
            let m = fs::symlink_metadata(&p)?;
            let relative = p
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 firmware path")?
                .to_string();
            let name = if prefix.is_empty() {
                relative
            } else {
                format!("{prefix}/{relative}")
            };
            if m.file_type().is_symlink() {
                let target = fs::read_link(&p)?;
                let target = target.to_str().context("non-UTF8 link")?;
                if prefix.is_empty() {
                    self.source_rows
                        .push(format!("symlink\0{name}\0{target}\n"));
                }
                self.result.inventory.symlinks.insert(name, target.into());
            } else if m.is_dir() {
                self.directory_named(root, &p, depth + 1, prefix)?;
            } else if m.is_file() {
                let mut f = File::open(&p)?;
                let physical_artifact = self.result.artifacts.len();
                self.image(&mut f, &name, 0)?;
                if prefix.is_empty() {
                    // image() appends the source record before derived members;
                    // reuse that streamed digest rather than rereading the file.
                    let artifact = &self.result.artifacts[physical_artifact];
                    self.source_rows.push(format!(
                        "file\0{}\0{}\0{}\n",
                        artifact.path, artifact.bytes, artifact.sha256
                    ));
                }
            } else {
                bail!("special firmware file refused: {}", p.display());
            }
        }
        Ok(())
    }
    fn image(&mut self, r: &mut dyn ReadSeek, name: &str, depth: usize) -> Result<()> {
        self.entry()?;
        ensure!(
            depth <= self.limits.max_depth,
            "container nesting limit exceeded"
        );
        let len = r.seek(SeekFrom::End(0))?;
        let prefix = read_at(r, 0, len.min(8192) as usize)?;
        let fmt = detect(&prefix);
        let package = [".apex", ".capex", ".apk", ".jar"]
            .iter()
            .any(|suffix| name.ends_with(suffix));
        let mut metadata = inspect(r, &fmt).with_context(|| format!("inspect {name} ({fmt:?})"))?;
        if package && fmt == Format::Zip {
            metadata["package_contents_analyzed"] = json!(false);
        }
        if fmt != Format::Vbmeta
            && let Some(footer) = avb_footer(r)?
        {
            metadata["avb_footer"] = footer;
        }
        r.seek(SeekFrom::Start(0))?;
        let sha = hash_reader(&mut *r)?;
        let artifact_index = self.result.artifacts.len();
        self.result.artifacts.push(Artifact {
            path: name.into(),
            bytes: len,
            sha256: sha,
            format: fmt.clone(),
            metadata,
        });
        self.classify(name, r, len)?;
        if package
            && fmt == Format::Zip
            && (name.ends_with(".apex") || name.ends_with(".capex"))
            && let Some(tools) = &self.limits.apex_tools
        {
            let sha = self.result.artifacts[artifact_index].sha256.clone();
            let extracted = gb_apex::extract(r, name, &sha, self.scratch)
                .with_context(|| format!("APEX {name}"))?;
            self.expanded = self
                .expanded
                .checked_add(extracted.payload.as_file().metadata()?.len())
                .context("APEX expansion overflow")?;
            ensure!(
                self.expanded <= self.limits.max_expanded_bytes
                    && self.apex_depth < self.limits.max_depth,
                "APEX expansion/nesting budget exceeded"
            );
            let tree = tempfile::tempdir_in(self.scratch)?;
            filesystem::extract_tree(extracted.payload.path(), tree.path(), tools)?;
            let manifest_path = tree.path().join("apex_manifest.pb");
            ensure!(
                manifest_path.is_file()
                    && !fs::symlink_metadata(&manifest_path)?
                        .file_type()
                        .is_symlink(),
                "APEX payload lacks regular manifest"
            );
            use std::io::Read;
            let mut payload_manifest = Vec::new();
            File::open(&manifest_path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut payload_manifest)?;
            ensure!(
                payload_manifest.len() <= 1024 * 1024,
                "APEX payload manifest too large"
            );
            gb_apex::check_payload_manifest(&payload_manifest, &extracted.manifest)?;
            self.result.artifacts[artifact_index].metadata["apex_avb"] =
                serde_json::to_value(extracted.avb_metadata)?;
            self.result.inventory.apex_packages.push(extracted.package);
            // Reuse this scanner so entry, expansion and nesting limits span all payloads.
            self.apex_depth += 1;
            self.directory_named(tree.path(), tree.path(), 0, &format!("{name}/payload"))?;
            self.apex_depth -= 1;
        }
        if package && fmt == Format::Zip {
            return Ok(());
        }
        match fmt {
            Format::Zip=>self.archive(r,name,depth+1)?,
            Format::Gpt=>{
                let table=gpt(r)?;self.result.limitations.push("GPT primary header/table CRC checked; backup GPT has not been validated".into());
                for p in table.partitions {let mut region=Region::new(r,p.offset,p.bytes)?;let child=format!("{name}/gpt/{}",p.name);self.image(&mut region,&child,depth+1)?;}
            },
            Format::Super=>{
                let lp=super_metadata(r,0)?;
                self.result.limitations.push("Super metadata slot 0 checked; other slots and backups require liblp validation".into());
                for p in lp.partitions {if p.bytes==0 {continue;} let child=format!("{name}/logical/{}",p.name);
                    if p.extents.len()==1 && !p.extents[0].zero && p.extents[0].source==0 {let e=&p.extents[0];let mut region=Region::new(r,e.offset,e.bytes)?;self.image(&mut region,&child,depth+1)?;}
                    else {self.result.limitations.push(format!("{child}: discontiguous/zero/external extents need lpunpack; metadata inspected only"));}
                }
            },
            Format::Erofs|Format::Ext4=>self.result.limitations.push("Filesystem images recognized; inventories require explicit sandboxed filesystem extraction".into()),
            Format::Sparse=>self.result.limitations.push("Sparse structure checked; use sparse_to_raw transformation before filesystem inspection".into()),
            Format::OtaPayload=>self.result.limitations.push("OTA payload recognized; protobuf operation decoding/extraction is not implemented".into()),
            _=>{}
        }
        Ok(())
    }
    fn archive(&mut self, r: &mut dyn ReadSeek, parent: &str, depth: usize) -> Result<()> {
        r.seek(SeekFrom::Start(0))?;
        let mut z = zip::ZipArchive::new(r).context("invalid ZIP central directory")?;
        ensure!(
            z.len() <= self.limits.max_entries,
            "ZIP entry limit exceeded"
        );
        let mut names = BTreeSet::new();
        // Preflight all entries before creating extraction files.
        for i in 0..z.len() {
            let e = z.by_index(i)?;
            let n = e.name().trim_end_matches('/');
            safe_relative(Path::new(n))?;
            ensure!(!e.name().contains('\\'), "ZIP backslash path refused");
            ensure!(names.insert(e.name().to_string()), "duplicate ZIP member");
            ensure!(
                e.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
                "ZIP symlinks refused"
            );
            self.expanded = self
                .expanded
                .checked_add(e.size())
                .context("ZIP expanded size overflow")?;
            ensure!(
                self.expanded <= self.limits.max_expanded_bytes,
                "ZIP decompression budget exceeded"
            );
        }
        for i in 0..z.len() {
            let mut e = z.by_index(i).context("encrypted/unsupported ZIP member")?;
            if e.is_dir() {
                continue;
            }
            let child = format!("{parent}/zip/{}", e.name());
            let mut tmp = tempfile::tempfile_in(self.scratch)?;
            let actual = copy_zip_member(&mut e, &mut tmp)
                .with_context(|| format!("decompress and CRC check {child}"))?;
            tmp.seek(SeekFrom::Start(0))?;
            // Package ZIPs are inventoried without recursively treating their contents as firmware.
            if child.ends_with(".apex")
                || child.ends_with(".capex")
                || child.ends_with(".apk")
                || child.ends_with(".jar")
            {
                self.entry()?;
                // Package names control recursion only; their bytes determine
                // the artifact format just as for physical extracted files.
                let format = detect(&read_at(&mut tmp, 0, actual.min(8192) as usize)?);
                let mut metadata = inspect(&mut tmp, &format)
                    .with_context(|| format!("inspect {child} ({format:?})"))?;
                if format == Format::Zip {
                    metadata["package_contents_analyzed"] = json!(false);
                }
                tmp.seek(SeekFrom::Start(0))?;
                let sha = hash_reader(&mut tmp)?;
                self.result.artifacts.push(Artifact {
                    path: child.clone(),
                    bytes: actual,
                    sha256: sha,
                    format,
                    metadata,
                });
                self.classify(&child, &mut tmp, actual)?;
            } else {
                self.image(&mut tmp, &child, depth)?;
            }
        }
        Ok(())
    }
    fn classify(&mut self, name: &str, r: &mut dyn ReadSeek, len: u64) -> Result<()> {
        let inv = &mut self.result.inventory;
        if is_metadata_text(name) {
            ensure!(
                len <= 16 * 1024 * 1024,
                "text metadata exceeds per-file limit"
            );
            let text = String::from_utf8(read_at(r, 0, len as usize)?)
                .context("non-UTF8 text metadata")?;
            let total = inv.metadata_text.values().map(String::len).sum::<usize>();
            ensure!(
                total
                    .checked_add(text.len())
                    .is_some_and(|n| n <= 32 * 1024 * 1024),
                "text metadata aggregate limit exceeded"
            );
            inv.metadata_text.insert(name.into(), text);
        }
        if name.ends_with(".prop") {
            ensure!(len <= 16 * 1024 * 1024, "property file too large");
            let b = read_at(r, 0, len as usize)?;
            let text = std::str::from_utf8(&b).context("invalid UTF8 property file")?;
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    inv.properties.push(Property {
                        path: name.into(),
                        key: k.trim().into(),
                        value: v.trim().into(),
                    });
                }
            }
        }
        if name.contains("/vintf/") && name.ends_with(".xml") {
            ensure!(len <= 16 * 1024 * 1024, "VINTF XML too large");
            let b = read_at(r, 0, len as usize)?;
            inv.vintf.push(
                parse_vintf(name, std::str::from_utf8(&b)?)
                    .with_context(|| format!("VINTF document {name}"))?,
            );
        }
        if name.contains("/framework/") {
            inv.framework.push(name.into());
        }
        if name.ends_with(".apex") || name.ends_with(".capex") {
            inv.apex.push(name.into());
        }
        if name.contains("/selinux/") || name.ends_with("/sepolicy") {
            inv.selinux.push(name.into());
        }
        if name.contains("/init/") && name.ends_with(".rc") {
            inv.init.push(name.into());
        }
        if name.contains("/permissions/") && name.ends_with(".xml") {
            inv.permissions.push(name.into());
        }
        if name.ends_with(".ko") {
            inv.modules.push(name.into());
        }
        let prefix = read_at(r, 0, len.min(4) as usize)?;
        if prefix == b"\x7fELF" {
            match elf::inspect_native(r, name) {
                Ok(library) => inv.native_libraries.push(library),
                Err(error) if error.downcast_ref::<elf::UnsupportedMachine>().is_some() => {
                    self.result.limitations.push(format!(
                        "{name}: {error}; preserved as an artifact, not an Android library provider"
                    ));
                }
                Err(error)
                    if error.downcast_ref::<elf::ExternalSegments>().is_some()
                        && name
                            .split('/')
                            .any(|part| ["firmware", "firmware_mnt"].contains(&part)) =>
                {
                    self.result.limitations.push(format!("{name}: peripheral ELF header references external program segments; not classified as a userspace library and not reconstructed"));
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("native ELF metadata {name}"));
                }
            }
        }
        Ok(())
    }
}
fn copy_zip_member(
    member: &mut zip::read::ZipFile<'_>,
    output: impl std::io::Write,
) -> Result<u64> {
    let expected = member.size();
    // Central-directory sizes are untrusted. Bound staging as well as the
    // declared aggregate budget, allowing only one sentinel byte on failure.
    // For an exact-size member (including empty), that extra read reaches the
    // decoder's real EOF and preserves the ZIP reader's CRC validation.
    let limit = expected
        .checked_add(1)
        .context("ZIP member size overflow")?;
    let mut bounded = std::io::Read::take(&mut *member, limit);
    let actual = copy_stream(&mut bounded, output)?;
    ensure!(actual == expected, "ZIP decompressed size mismatch");
    Ok(actual)
}
pub fn parse_vintf(path: &str, text: &str) -> Result<VintfDocument> {
    let d =
        roxmltree::Document::parse(text).context("invalid VINTF XML (DTD/entities disabled)")?;
    let root = d.root_element();
    let kind = root.tag_name().name();
    ensure!(
        kind == "manifest" || kind == "compatibility-matrix",
        "unsupported VINTF root element"
    );
    let mut hals = Vec::new();
    for h in root.children().filter(|n| n.has_tag_name("hal")) {
        let field = |tag: &str| {
            h.children()
                .find(|n| n.has_tag_name(tag))
                .and_then(|n| n.text())
                .map(str::to_owned)
        };
        let name = field("name").context("HAL declaration has no name")?;
        let format = h.attribute("format").unwrap_or("hidl");
        let versions = h
            .children()
            .filter(|n| n.has_tag_name("version"))
            .filter_map(|n| n.text().map(str::to_owned))
            .collect();
        let mut interfaces = Vec::new();
        for i in h.children().filter(|n| n.has_tag_name("interface")) {
            let iface = i
                .children()
                .find(|n| n.has_tag_name("name"))
                .and_then(|n| n.text());
            let iface = if format == "native" {
                iface.unwrap_or("")
            } else {
                iface.context("HAL interface has no name")?
            };
            for inst in i
                .children()
                .filter(|n| n.has_tag_name("instance") || n.has_tag_name("regex-instance"))
            {
                interfaces.push(format!(
                    "{iface}/{}{}",
                    if inst.has_tag_name("regex-instance") {
                        "regex:"
                    } else {
                        ""
                    },
                    inst.text().context("empty HAL instance")?
                ));
            }
        }
        interfaces.extend(
            h.children()
                .filter(|n| n.has_tag_name("fqname"))
                .filter_map(|n| n.text().map(str::to_owned)),
        );
        hals.push(Hal {
            name,
            format: format.into(),
            optional: h.attribute("optional") == Some("true"),
            versions,
            interfaces,
        });
    }
    Ok(VintfDocument {
        path: path.into(),
        kind: kind.into(),
        role: root.attribute("type").map(str::to_owned),
        level: root
            .attribute("target-level")
            .or(root.attribute("level"))
            .map(str::to_owned),
        hals,
    })
}
/// Source digest used by build cache; physical paths, file contents, and symlink
/// targets are included. Container-derived inventory entries are not tree files.
pub fn input_digest(input: &Path) -> Result<String> {
    if input.is_file() {
        ensure!(
            !fs::symlink_metadata(input)?.file_type().is_symlink(),
            "symlink input refused"
        );
        return hash_file(input);
    }
    let mut rows = Vec::new();
    fn visit(root: &Path, p: &Path, rows: &mut Vec<String>, depth: usize) -> Result<()> {
        ensure!(depth <= 64, "tree nesting too deep");
        for e in fs::read_dir(p)? {
            let e = e?;
            let m = e.file_type()?;
            let path = e.path();
            let rel = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 tree path")?
                .to_string();
            if m.is_symlink() {
                rows.push(format!(
                    "symlink\0{rel}\0{}\n",
                    fs::read_link(&path)?.to_str().context("non-UTF8 link")?
                ));
            } else if m.is_dir() {
                visit(root, &path, rows, depth + 1)?;
            } else if m.is_file() {
                rows.push(format!(
                    "file\0{rel}\0{}\0{}\n",
                    e.metadata()?.len(),
                    hash_file(&path)?
                ));
            } else {
                bail!("special input file refused");
            }
        }
        Ok(())
    }
    visit(input, input, &mut rows, 0)?;
    rows.sort();
    Ok(digest(rows.join("").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zip_fixture(method: zip::CompressionMethod, payload: &[u8]) -> Vec<u8> {
        use std::io::{Cursor, Write};

        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "payload.bin",
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(payload).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn zip_central(bytes: &[u8]) -> usize {
        bytes
            .windows(4)
            .rposition(|signature| signature == b"PK\x01\x02")
            .unwrap()
    }

    #[test]
    fn zip_declared_small_deflate_is_rejected_with_bounded_staging() {
        use std::io::Cursor;

        for declared in [0u32, 1] {
            let mut bytes = zip_fixture(zip::CompressionMethod::Deflated, &vec![b'x'; 64 * 1024]);
            let central = zip_central(&bytes);
            bytes[central + 24..central + 28].copy_from_slice(&declared.to_le_bytes());
            let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
            let mut member = archive.by_index(0).unwrap();
            assert_eq!(member.size(), declared as u64);
            let mut output = Vec::new();
            let error = copy_zip_member(&mut member, &mut output).unwrap_err();
            assert!(error.to_string().contains("ZIP decompressed size mismatch"));
            assert!(
                output.len() <= declared as usize + 1,
                "malformed ZIP must not materialize its full undeclared expansion: {}",
                output.len()
            );
        }
    }

    #[test]
    fn zip_exact_size_and_empty_members_preserve_bytes_and_crc_checks() {
        use std::io::Cursor;

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            for payload in [
                b"".as_slice(),
                b"raw or compressed firmware fixture".as_slice(),
            ] {
                let bytes = zip_fixture(method, payload);
                let mut archive = zip::ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
                let mut output = Vec::new();
                assert_eq!(
                    copy_zip_member(&mut archive.by_index(0).unwrap(), &mut output).unwrap(),
                    payload.len() as u64
                );
                assert_eq!(output, payload);

                let mut bad_crc = bytes;
                let central = zip_central(&bad_crc);
                bad_crc[central + 16] ^= 1;
                let mut archive = zip::ZipArchive::new(Cursor::new(bad_crc)).unwrap();
                let mut output = Vec::new();
                assert!(copy_zip_member(&mut archive.by_index(0).unwrap(), &mut output).is_err());
                assert!(output.len() <= payload.len());
            }
        }
    }

    #[test]
    fn zip_bounded_extraction_keeps_aggregate_budget_and_failed_staging_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("firmware.zip");
        let scratch = temp.path().join("scratch");
        let bytes = zip_fixture(zip::CompressionMethod::Deflated, b"firmware bytes");
        fs::write(&input, &bytes).unwrap();
        let mut limits = Limits {
            max_expanded_bytes: 14,
            ..Limits::default()
        };
        let manifest = inspect_firmware(&input, &scratch, &limits).unwrap();
        assert_eq!(manifest.artifacts[1].bytes, 14);
        limits.max_expanded_bytes = 13;
        assert!(inspect_firmware(&input, &scratch, &limits).is_err());

        let mut malformed = bytes;
        let central = zip_central(&malformed);
        malformed[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
        fs::write(&input, malformed).unwrap();
        let error = inspect_firmware(&input, &scratch, &limits).unwrap_err();
        assert!(format!("{error:#}").contains("ZIP decompressed size mismatch"));
        assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
    }

    #[test]
    fn archived_package_formats_follow_signatures_not_suffixes() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.zip");
        let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
        for suffix in ["apk", "jar", "apex", "capex"] {
            for (stem, bytes) in [
                ("unknown", b"not a package".as_slice()),
                ("compressed", b"\x1f\x8bopaque fixture".as_slice()),
            ] {
                archive
                    .start_file(
                        format!("system/{stem}.{suffix}"),
                        zip::write::SimpleFileOptions::default(),
                    )
                    .unwrap();
                archive.write_all(bytes).unwrap();
            }
        }
        archive.finish().unwrap();

        let manifest =
            inspect_firmware(&path, &temp.path().join("scratch"), &Limits::default()).unwrap();
        for suffix in ["apk", "jar", "apex", "capex"] {
            for (stem, expected) in [("unknown", Format::Unknown), ("compressed", Format::Gzip)] {
                let artifact = manifest
                    .artifacts
                    .iter()
                    .find(|a| a.path == format!("input/zip/system/{stem}.{suffix}"))
                    .unwrap();
                assert_eq!(artifact.format, expected, "{}", artifact.path);
                assert!(artifact.metadata.get("package_contents_analyzed").is_none());
            }
        }
    }

    #[test]
    fn archived_package_zip_contents_remain_unexpanded() {
        use std::io::{Cursor, Write};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.zip");
        let mut package = zip::ZipWriter::new(Cursor::new(Vec::new()));
        package
            .start_file("build.prop", zip::write::SimpleFileOptions::default())
            .unwrap();
        package
            .write_all(b"ro.build.version.release=999\n")
            .unwrap();
        let package = package.finish().unwrap().into_inner();
        let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
        for suffix in ["apk", "jar", "apex", "capex"] {
            archive
                .start_file(
                    format!("system/package.{suffix}"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            archive.write_all(&package).unwrap();
        }
        archive.finish().unwrap();

        let manifest =
            inspect_firmware(&path, &temp.path().join("scratch"), &Limits::default()).unwrap();
        for suffix in ["apk", "jar", "apex", "capex"] {
            let artifact = manifest
                .artifacts
                .iter()
                .find(|a| a.path == format!("input/zip/system/package.{suffix}"))
                .unwrap();
            assert_eq!(artifact.format, Format::Zip);
            assert_eq!(artifact.metadata["package_contents_analyzed"], false);
            assert_eq!(artifact.sha256, digest(&package));
        }
        assert_eq!(manifest.artifacts.len(), 5);
        assert_eq!(manifest.property("ro.build.version.release"), None);
    }

    #[test]
    fn archived_package_sparse_metadata_does_not_expand_blocks() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.zip");
        // Forty encoded bytes describe four TiB of holes, never materialized.
        let mut sparse = Vec::new();
        sparse.extend_from_slice(&0xed26ff3au32.to_le_bytes());
        for value in [1u16, 0, 28, 12] {
            sparse.extend_from_slice(&value.to_le_bytes());
        }
        for value in [4096u32, 1 << 30, 1, 0] {
            sparse.extend_from_slice(&value.to_le_bytes());
        }
        sparse.extend_from_slice(&0xcac3u16.to_le_bytes());
        sparse.extend_from_slice(&0u16.to_le_bytes());
        sparse.extend_from_slice(&(1u32 << 30).to_le_bytes());
        sparse.extend_from_slice(&12u32.to_le_bytes());
        assert_eq!(sparse.len(), 40);
        let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
        archive
            .start_file(
                "system/payload.apex",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(&sparse).unwrap();
        archive.finish().unwrap();

        let mut limits = Limits {
            max_expanded_bytes: 40,
            ..Limits::default()
        };
        let manifest = inspect_firmware(&path, &temp.path().join("scratch"), &limits).unwrap();
        let artifact = &manifest.artifacts[1];
        assert_eq!(artifact.format, Format::Sparse);
        assert_eq!(artifact.bytes, 40);
        assert_eq!(artifact.metadata["expanded_bytes"], 1u64 << 42);
        limits.max_expanded_bytes = 39;
        let error =
            inspect_firmware(&path, &temp.path().join("other-scratch"), &limits).unwrap_err();
        assert!(error.to_string().contains("decompression budget exceeded"));
    }

    #[test]
    fn extracted_tree_identity_excludes_derived_container_inventory() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let tree = temp.path().join("tree");
        fs::create_dir(&tree).unwrap();
        let mut archive = zip::ZipWriter::new(File::create(tree.join("firmware.zip")).unwrap());
        archive
            .start_file(
                "system/build.prop",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"ro.build.version.release=16\n").unwrap();
        archive.finish().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("firmware.zip", tree.join("firmware-link")).unwrap();

        let expected = input_digest(&tree).unwrap();
        let manifest =
            inspect_firmware(&tree, &temp.path().join("scratch"), &Limits::default()).unwrap();
        manifest.validate().unwrap();
        assert!(manifest.artifacts.iter().any(|a| a.path == "firmware.zip"));
        assert!(
            manifest
                .artifacts
                .iter()
                .any(|a| a.path == "firmware.zip/zip/system/build.prop")
        );
        assert_eq!(manifest.property("ro.build.version.release"), Some("16"));
        assert_eq!(
            manifest.source_sha256, expected,
            "source identity must cover physical files and links, not derived ZIP members"
        );
    }

    #[test]
    fn normalization_is_deterministic() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("tree");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("framework")).unwrap();
        fs::write(root.join("framework/services.jar"), b"inventory fixture").unwrap();
        fs::write(
            root.join("build.prop"),
            "ro.build.version.release=16\nro.product.cpu.abi=arm64-v8a\n",
        )
        .unwrap();
        let scratch = t.path().join("scratch");
        let m = inspect_firmware(&root, &scratch, &Limits::default()).unwrap();
        assert_eq!(m.property("ro.build.version.release"), Some("16"));
        assert_eq!(m.architecture(), Some("aarch64"));
        assert_eq!(m.inventory.framework, vec!["framework/services.jar"]);
        assert_eq!(m.source_sha256, input_digest(&root).unwrap());
        let again = inspect_firmware(&root, &scratch, &Limits::default()).unwrap();
        assert_eq!(
            serde_json::to_vec(&m).unwrap(),
            serde_json::to_vec(&again).unwrap()
        );
    }
    #[test]
    fn unknown_container_rejected() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("image.zip");
        fs::write(&p, b"encrypted maybe").unwrap();
        let error =
            inspect_firmware(&p, &t.path().join("scratch"), &Limits::default()).unwrap_err();
        assert!(error.to_string().contains("unknown or encrypted"));
    }
    #[test]
    fn vintf_roles_and_instances() {
        let m=parse_vintf("vendor/etc/vintf/manifest.xml",r#"<manifest version="1.0" type="device" target-level="202504"><hal format="aidl"><name>android.hardware.foo</name><version>2</version><interface><name>IFoo</name><instance>default</instance></interface></hal></manifest>"#).unwrap();
        assert_eq!(m.role.as_deref(), Some("device"));
        assert_eq!(m.hals[0].interfaces, vec!["IFoo/default"]);
    }
    #[test]
    fn xml_entities_rejected() {
        assert!(
            parse_vintf(
                "a",
                "<!DOCTYPE manifest [<!ENTITY x 'bad'>]><manifest>&x;</manifest>"
            )
            .is_err()
        );
    }
    #[test]
    fn native_hal_allows_unnamed_interface() {
        let m = parse_vintf("system/etc/vintf/compatibility_matrix.xml", r#"<compatibility-matrix type="framework"><hal format="native"><name>mapper</name><version>5.0</version><interface><regex-instance>.*</regex-instance></interface></hal></compatibility-matrix>"#).unwrap();
        assert_eq!(m.hals[0].name, "mapper");
        assert_eq!(m.hals[0].format, "native");
        assert_eq!(m.hals[0].interfaces, vec!["/regex:.*"]);
    }
    #[test]
    fn attached_text_requires_original_image_digest_and_preserves_source_identity() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("tree");
        fs::create_dir_all(root.join("vendor/etc/selinux")).unwrap();
        let path = "vendor/etc/selinux/plat_sepolicy_vers.txt";
        fs::write(root.join(path), "34.0\n").unwrap();
        let mut m = inspect_firmware(&root, &t.path().join("scratch"), &Limits::default()).unwrap();
        let source = m.source_sha256.clone();
        m.inventory.metadata_text.clear();
        attach_text(&mut m, path, b"34.0\n").unwrap();
        m.validate().unwrap();
        assert_eq!(m.source_sha256, source);
        assert!(attach_text(&mut m, path, b"202604\n").is_err());
        assert!(attach_text(&mut m, "../escape", b"34.0\n").is_err());
        assert!(attach_text(&mut m, "vendor/lib64/not-text.so", b"data").is_err());
    }
}
