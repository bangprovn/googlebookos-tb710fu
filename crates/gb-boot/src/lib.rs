//! Guarded first-stage mount adaptation; preserve target DTB and boot metadata.
use anyhow::{Context, Result, ensure};
use gb_core::{Format, digest, hash_file, safe_relative, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
pub mod diagnostic;
pub mod kernel;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub input: PathBuf,
    pub sha256: String,
    pub fstab_path: String,
    pub fstab_sha256: String,
    pub erofs_partitions: BTreeSet<String>,
    pub unpack: PathBuf,
    pub pack: PathBuf,
    pub lz4: PathBuf,
    pub sandbox: gb_tools::Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [&mut r.input, &mut r.unpack, &mut r.pack, &mut r.lz4] {
            if p.is_relative() {
                *p = parent.join(&*p);
            }
        }
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        let sha = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        ensure!(
            self.schema_version == 1 && sha(&self.sha256) && sha(&self.fstab_sha256),
            "boot adaptation requires pinned image and fstab"
        );
        safe_relative(Path::new(&self.fstab_path))?;
        ensure!(
            !self.erofs_partitions.is_empty()
                && self
                    .erofs_partitions
                    .iter()
                    .all(|p| ["system", "system_ext", "product"].contains(&p.as_str())),
            "only declared userspace mounts may be adapted"
        );
        self.sandbox.validate()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub avb_signed: bool,
    pub source_sha256: String,
    pub image_sha256: String,
    pub image_bytes: u64,
    pub fstab_before_sha256: String,
    pub fstab_after_sha256: String,
    pub erofs_partitions: BTreeSet<String>,
    pub dtb_sha256: String,
    pub bootconfig_sha256: String,
    pub unchanged_cpio_entries: usize,
    pub ramdisk_data_format_flags_removed: bool,
    pub tools: Vec<serde_json::Value>,
}
fn fstab(text: &str, partitions: &BTreeSet<String>) -> Result<String> {
    let mut found = BTreeSet::new();
    let mut result = String::new();
    for line in text.split_inclusive('\n') {
        let tokens: Vec<_> = line.split_whitespace().collect();
        if tokens.first().is_some_and(|p| partitions.contains(*p)) {
            ensure!(
                tokens.len() == 5 && tokens[2] == "ext4" && found.insert(tokens[0].to_owned()),
                "expected one original ext4 entry for each userspace partition"
            );
            let flags: BTreeSet<_> = tokens[4].split(',').collect();
            ensure!(
                flags.contains("first_stage_mount")
                    && flags.contains("logical")
                    && flags.contains("slotselect")
                    && flags.iter().any(|v| v.starts_with("avb=")),
                "first-stage logical/slot/AVB requirements missing"
            );
            result.push_str(&format!(
                "{}\t{}\terofs\tro\t{}\n",
                tokens[0], tokens[1], tokens[4]
            ));
        } else if tokens.len() == 5 && ["/data", "/metadata"].contains(&tokens[1]) {
            let flags = tokens[4]
                .split(',')
                .filter(|v| *v != "formattable")
                .collect::<Vec<_>>()
                .join(",");
            result.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                tokens[0], tokens[1], tokens[2], tokens[3], flags
            ));
        } else {
            result.push_str(line);
        }
    }
    ensure!(
        &found == partitions,
        "requested first-stage mounts are absent"
    );
    Ok(result)
}
fn number(b: &[u8], field: usize) -> Result<u32> {
    let start = 6 + field * 8;
    u32::from_str_radix(
        std::str::from_utf8(b.get(start..start + 8).context("truncated newc header")?)?,
        16,
    )
    .context("invalid newc hexadecimal field")
}
fn aligned(n: usize) -> Result<usize> {
    n.checked_add(3)
        .map(|v| v & !3)
        .context("newc offset overflow")
}
fn patch_cpio(source: &[u8], request: &Request) -> Result<(Vec<u8>, String, usize)> {
    ensure!(
        source.len() <= 128 * 1024 * 1024,
        "ramdisk expansion limit exceeded"
    );
    let mut output = Vec::new();
    let mut offset = 0;
    let mut names = BTreeSet::new();
    let mut patched = false;
    let mut unchanged = 0;
    let mut after = String::new();
    let mut trailer = false;
    while offset < source.len() {
        let h = source
            .get(offset..offset + 110)
            .context("truncated cpio header")?;
        ensure!(
            &h[..6] == b"070701" || &h[..6] == b"070702",
            "unsupported ramdisk container"
        );
        let name_len = number(h, 11)? as usize;
        let size = number(h, 6)? as usize;
        ensure!(
            (1..=4097).contains(&name_len) && names.len() < 100_000,
            "cpio name/entry limit exceeded"
        );
        let name_start = offset + 110;
        let name_end = name_start
            .checked_add(name_len)
            .context("cpio name overflow")?;
        let raw = source
            .get(name_start..name_end)
            .context("truncated cpio name")?;
        ensure!(
            raw.last() == Some(&0) && !raw[..raw.len() - 1].contains(&0),
            "invalid cpio name terminator"
        );
        let name = std::str::from_utf8(&raw[..raw.len() - 1])?;
        let body_start = aligned(name_end)?;
        let body_end = body_start.checked_add(size).context("cpio body overflow")?;
        let end = aligned(body_end)?;
        let body = source
            .get(body_start..body_end)
            .context("truncated cpio data")?;
        ensure!(end <= source.len(), "truncated cpio alignment");
        if &h[..6] == b"070702" {
            ensure!(
                body.iter().fold(0u32, |s, b| s.wrapping_add(*b as u32)) == number(h, 12)?,
                "cpio CRC mismatch"
            );
        }
        if name == "TRAILER!!!" {
            ensure!(
                size == 0 && source[end..].iter().all(|b| *b == 0),
                "multiple or nonzero trailing ramdisk archives are unsupported"
            );
            output.extend_from_slice(&source[offset..end]);
            trailer = true;
            break;
        }
        if name != "." {
            safe_relative(Path::new(name))?;
        }
        ensure!(names.insert(name.to_owned()), "duplicate cpio entry");
        if name == request.fstab_path {
            ensure!(
                number(h, 1)? & 0o170000 == 0o100000
                    && number(h, 4)? == 1
                    && digest(body) == request.fstab_sha256,
                "fstab metadata or original digest guard failed"
            );
            let replacement = fstab(std::str::from_utf8(body)?, &request.erofs_partitions)?;
            let mut header = h.to_vec();
            header[54..62].copy_from_slice(format!("{:08x}", replacement.len()).as_bytes());
            if &h[..6] == b"070702" {
                header[102..110].copy_from_slice(
                    format!(
                        "{:08x}",
                        replacement
                            .as_bytes()
                            .iter()
                            .fold(0u32, |s, b| s.wrapping_add(*b as u32))
                    )
                    .as_bytes(),
                );
            }
            output.extend_from_slice(&header);
            output.extend_from_slice(raw);
            output.resize(aligned(output.len())?, 0);
            output.extend_from_slice(replacement.as_bytes());
            output.resize(aligned(output.len())?, 0);
            after = digest(replacement.as_bytes());
            patched = true;
        } else {
            output.extend_from_slice(&source[offset..end]);
            unchanged += 1;
        }
        offset = end;
    }
    ensure!(trailer && patched, "complete ramdisk/fstab entry required");
    let padding = (512 - output.len() % 512) % 512;
    output.resize(output.len() + padding, 0);
    Ok((output, after, unchanged))
}
fn args(text: &str) -> Result<Vec<String>> {
    let fields: Vec<_> = text
        .strip_suffix('\0')
        .context("unpacker must provide NUL-separated arguments")?
        .split('\0')
        .collect();
    ensure!(
        fields.len().is_multiple_of(2),
        "unexpected unpacker argument list"
    );
    let allowed = [
        "--header_version",
        "--pagesize",
        "--base",
        "--kernel_offset",
        "--ramdisk_offset",
        "--tags_offset",
        "--dtb_offset",
        "--vendor_cmdline",
        "--board",
        "--dtb",
        "--vendor_bootconfig",
        "--ramdisk_type",
        "--ramdisk_name",
        "--vendor_ramdisk_fragment",
    ];
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for pair in fields.chunks_exact(2) {
        ensure!(
            allowed.contains(&pair[0]) && seen.insert(pair[0]),
            "unsupported/duplicate boot argument"
        );
        if pair[0] == "--vendor_ramdisk_fragment" {
            ensure!(
                pair[1] == "/output/vendor_ramdisk00",
                "single target ramdisk fragment required"
            );
        }
        result.extend(pair.iter().map(|v| v.to_string()));
    }
    ensure!(
        seen.contains("--dtb")
            && seen.contains("--vendor_bootconfig")
            && seen.contains("--vendor_ramdisk_fragment"),
        "required target boot components absent"
    );
    Ok(result)
}
fn hardware_header(input: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut file = File::open(input)?;
    let mut header = gb_partition::read_at(&mut file, 0, 2128)?;
    let read =
        |i: usize| -> Result<u64> { Ok(u32::from_le_bytes(header[i..i + 4].try_into()?) as u64) };
    let page = read(12)?;
    ensure!(
        page.is_power_of_two() && (2048..=65536).contains(&page),
        "invalid vendor_boot page alignment"
    );
    let aligned = |n: u64| -> Result<u64> {
        Ok(n.checked_add(page - 1).context("boot offset overflow")? & !(page - 1))
    };
    let table_offset = aligned(2128)? + aligned(read(24)?)? + aligned(read(2100)?)?;
    ensure!(
        read(2112)? == 108 && read(2116)? == 1 && read(2120)? == 108,
        "single exact vendor ramdisk table required"
    );
    let mut table = gb_partition::read_at(&mut file, table_offset, 108)?;
    header[24..28].fill(0);
    table[..4].fill(0);
    Ok((header, table))
}
pub fn build(request: &Request, out: &Path) -> Result<Report> {
    request.validate()?;
    gb_core::separate_from_input(&request.input, out)?;
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "vendor_boot input SHA256 mismatch"
    );
    let original = gb_partition::inspect(&mut File::open(&request.input)?, &Format::VendorBoot)?;
    ensure!(
        original["header_version"] == 4
            && original["fragments"]
                .as_array()
                .is_some_and(|f| f.len() == 1),
        "only verified single-fragment vendor_boot v4 is supported"
    );
    let original_header = hardware_header(&request.input)?;
    let mut tools = Vec::new();
    for tool in [&request.unpack, &request.pack, &request.lz4] {
        let t = gb_tools::host_tool(tool, &[&request.input])?;
        tools.push(gb_tools::identity(&t, &request.sandbox)?);
    }
    let unpack = gb_tools::run(
        &request.sandbox,
        &request.unpack,
        vec![
            "--boot_img".into(),
            "/input.img".into(),
            "--out".into(),
            "/output".into(),
            "--format".into(),
            "mkbootimg".into(),
            "-0".into(),
        ],
        &request.input,
        out,
        Duration::from_secs(60),
    )?;
    let mut pack_args = args(&unpack.stdout)?;
    let ramdisk = out.join("vendor_ramdisk00");
    let dtb = hash_file(&out.join("dtb"))?;
    let bootconfig = hash_file(&out.join("bootconfig"))?;
    let scratch = tempfile::tempdir()?;
    let magic = gb_partition::read_at(&mut File::open(&ramdisk)?, 0, 4)?;
    ensure!(
        magic == [2, 33, 76, 24],
        "target ramdisk must use recognized legacy LZ4"
    );
    gb_tools::run(
        &request.sandbox,
        &request.lz4,
        vec![
            "-d".into(),
            "/input.img".into(),
            "/output/ramdisk.cpio".into(),
        ],
        &ramdisk,
        scratch.path(),
        Duration::from_secs(60),
    )?;
    let raw = scratch.path().join("ramdisk.cpio");
    ensure!(
        std::fs::metadata(&raw)?.len() <= 128 * 1024 * 1024,
        "ramdisk expansion limit exceeded"
    );
    let bytes = std::fs::read(&raw)?;
    let (patched, after, unchanged) = patch_cpio(&bytes, request)?;
    std::fs::write(&raw, &patched)?;
    let compressed = tempfile::tempdir()?;
    gb_tools::run(
        &request.sandbox,
        &request.lz4,
        vec![
            "-l".into(),
            "-12".into(),
            "/input.img".into(),
            "/output/ramdisk.lz4".into(),
        ],
        &raw,
        compressed.path(),
        Duration::from_secs(120),
    )?;
    std::fs::copy(compressed.path().join("ramdisk.lz4"), &ramdisk)?;
    pack_args.extend(["--vendor_boot".into(), "/output/vendor_boot.img".into()]);
    gb_tools::run(
        &request.sandbox,
        &request.pack,
        pack_args,
        &request.input,
        out,
        Duration::from_secs(60),
    )?;
    let image = out.join("vendor_boot.img");
    let rebuilt = gb_partition::inspect(&mut File::open(&image)?, &Format::VendorBoot)?;
    for field in [
        "header_version",
        "page_size",
        "cmdline",
        "dtb_bytes",
        "bootconfig_bytes",
    ] {
        ensure!(
            rebuilt[field] == original[field],
            "target vendor_boot field {field} changed"
        );
    }
    ensure!(
        hardware_header(&image)? == original_header,
        "vendor_boot hardware addresses/table/board IDs changed"
    );
    let verify = tempfile::tempdir()?;
    gb_tools::run(
        &request.sandbox,
        &request.unpack,
        vec![
            "--boot_img".into(),
            "/input.img".into(),
            "--out".into(),
            "/output".into(),
        ],
        &image,
        verify.path(),
        Duration::from_secs(60),
    )?;
    ensure!(
        hash_file(&verify.path().join("dtb"))? == dtb
            && hash_file(&verify.path().join("bootconfig"))? == bootconfig
            && hash_file(&verify.path().join("vendor_ramdisk00"))? == hash_file(&ramdisk)?,
        "repacked boot component differs"
    );
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "original vendor_boot changed"
    );
    let report = Report {
        schema_version: 1,
        status: "unsigned_vendor_boot_candidate".into(),
        bootable: false,
        runtime_verified: false,
        avb_signed: false,
        source_sha256: request.sha256.clone(),
        image_sha256: hash_file(&image)?,
        image_bytes: std::fs::metadata(&image)?.len(),
        fstab_before_sha256: request.fstab_sha256.clone(),
        fstab_after_sha256: after,
        erofs_partitions: request.erofs_partitions.clone(),
        dtb_sha256: dtb,
        bootconfig_sha256: bootconfig,
        unchanged_cpio_entries: unchanged,
        ramdisk_data_format_flags_removed: true,
        tools,
    };
    // Decoded components were temporary working data, not published boot artifacts.
    let links = out.join("vendor-ramdisk-by-name");
    if links.is_dir() {
        for entry in std::fs::read_dir(&links)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_symlink()
                    && std::fs::read_link(entry.path())? == Path::new("../vendor_ramdisk00"),
                "unexpected unpacker fragment alias"
            );
            std::fs::remove_file(entry.path())?;
        }
        std::fs::remove_dir(links)?;
    }
    let alias = out.join("vendor_ramdisk");
    if std::fs::symlink_metadata(&alias).is_ok() {
        ensure!(
            std::fs::read_link(&alias)? == Path::new("vendor_ramdisk00"),
            "unexpected unpacker ramdisk alias"
        );
        std::fs::remove_file(alias)?;
    }
    for name in ["dtb", "bootconfig", "vendor_ramdisk00"] {
        std::fs::remove_file(out.join(name))?;
    }
    write_json(&out.join("boot-report.json"), &report)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mount_adaptation_preserves_avb_and_hardware_mounts() {
        let s = "# original\nsystem /system ext4 ro,barrier=1 wait,slotselect,avb=vbmeta_system,logical,first_stage_mount\nvendor /vendor ext4 ro wait,slotselect,avb=vbmeta,logical,first_stage_mount\n";
        let p = BTreeSet::from(["system".into()]);
        let changed = fstab(s, &p).unwrap();
        assert!(changed.contains("system\t/system\terofs\tro\twait,slotselect,avb=vbmeta_system,logical,first_stage_mount"));

        assert!(changed.contains(s.lines().last().unwrap()));
        let data = "userdata /data f2fs rw wait,check,formattable,fileencryption=aes-256-xts
";
        let trial = fstab(&(s.to_owned() + data), &p).unwrap();
        assert!(trial.contains("fileencryption=aes-256-xts"));
        assert!(!trial.contains("formattable"));
        assert!(fstab(&s.replace("avb=vbmeta_system,", ""), &p).is_err());
        assert!(fstab(&(s.to_owned() + s), &p).is_err());
    }
    #[test]
    fn unpacker_arguments_never_accept_shell_or_extra_components() {
        assert!(args("--vendor_boot\0/malicious\0").is_err());
        assert!(args("--dtb\0a").is_err());
    }
}
