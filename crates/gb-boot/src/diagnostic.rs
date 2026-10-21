//! Explicit temporary init_boot instrumentation; no kernel or policy replacement.
use anyhow::{Context, Result, ensure};
use gb_core::{digest, hash_file, safe_relative, write_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub input: PathBuf,
    pub sha256: String,
    pub original_init_sha256: String,
    pub logger: PathBuf,
    pub logger_sha256: String,
    pub unpack: PathBuf,
    pub pack: PathBuf,
    pub lz4: PathBuf,
    pub sandbox: gb_tools::Sandbox,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for p in [
            &mut r.input,
            &mut r.logger,
            &mut r.unpack,
            &mut r.pack,
            &mut r.lz4,
        ] {
            if p.is_relative() {
                *p = parent.join(&*p);
            }
        }
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unknown init diagnostic schema");
        for sha in [
            &self.sha256,
            &self.original_init_sha256,
            &self.logger_sha256,
        ] {
            ensure!(
                sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                "diagnostic inputs must be SHA256 pinned"
            );
        }
        self.sandbox.validate()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub bootable: bool,
    pub runtime_verified: bool,
    pub source_sha256: String,
    pub image_sha256: String,
    pub image_bytes: u64,
    pub retained_init_sha256: String,
    pub logger_sha256: String,
    pub unchanged_cpio_entries: usize,
    pub original_header_preserved_except_ramdisk_length: bool,
    pub output_file: String,
    pub policy_unchanged: bool,
    pub tools: Vec<serde_json::Value>,
    pub limitations: Vec<String>,
}
struct Entry<'a> {
    name: &'a str,
    header: &'a [u8],
    body: &'a [u8],
    raw: &'a [u8],
}
fn entries(source: &[u8]) -> Result<Vec<Entry<'_>>> {
    ensure!(
        source.len() <= 128 * 1024 * 1024,
        "ramdisk expansion limit exceeded"
    );
    let mut offset = 0;
    let mut result = Vec::new();
    let mut names = BTreeMap::new();
    loop {
        let header = source
            .get(offset..offset + 110)
            .context("truncated newc header")?;
        ensure!(
            &header[..6] == b"070701" || &header[..6] == b"070702",
            "unsupported ramdisk archive"
        );
        let len = super::number(header, 11)? as usize;
        let size = super::number(header, 6)? as usize;
        ensure!(
            (1..=4097).contains(&len) && result.len() < 100000,
            "newc name/entry limit exceeded"
        );
        let name_start = offset + 110;
        let name_end = name_start.checked_add(len).context("newc name overflow")?;
        let raw_name = source
            .get(name_start..name_end)
            .context("truncated newc name")?;
        ensure!(
            raw_name.last() == Some(&0) && !raw_name[..len - 1].contains(&0),
            "invalid newc name"
        );
        let name = std::str::from_utf8(&raw_name[..len - 1])?;
        let begin = super::aligned(name_end)?;
        let end = begin.checked_add(size).context("newc data overflow")?;
        let next = super::aligned(end)?;
        ensure!(next <= source.len(), "truncated newc alignment");
        let body = &source[begin..end];
        if &header[..6] == b"070702" {
            ensure!(
                body.iter().fold(0u32, |s, b| s.wrapping_add(*b as u32))
                    == super::number(header, 12)?,
                "newc CRC mismatch"
            );
        }
        let directory = super::number(header, 1)? & 0o170000 == 0o040000 && body.is_empty();
        if let Some(previous_directory) = names.insert(name, directory) {
            // mkbootfs may repeat empty directory records while combining input
            // trees. Preserve their exact order/metadata; duplicate files and
            // directory/file collisions remain unsupported.
            ensure!(
                previous_directory && directory,
                "duplicate non-directory newc entry: {name}"
            );
        }
        if name == "TRAILER!!!" {
            ensure!(
                size == 0 && source[next..].iter().all(|b| *b == 0),
                "multiple/trailing newc archives refused"
            );
            result.push(Entry {
                name,
                header,
                body,
                raw: &source[offset..next],
            });
            break;
        }
        if name != "." {
            safe_relative(Path::new(name))?;
        }
        result.push(Entry {
            name,
            header,
            body,
            raw: &source[offset..next],
        });
        offset = next;
    }
    Ok(result)
}
fn append(
    out: &mut Vec<u8>,
    header: &[u8],
    name: &str,
    body: &[u8],
    inode: Option<u32>,
) -> Result<()> {
    let mut h = header.to_vec();
    h[54..62].copy_from_slice(format!("{:08x}", u32::try_from(body.len())?).as_bytes());
    h[94..102].copy_from_slice(format!("{:08x}", u32::try_from(name.len() + 1)?).as_bytes());
    if let Some(inode) = inode {
        h[6..14].copy_from_slice(format!("{inode:08x}").as_bytes());
    }
    if &h[..6] == b"070702" {
        h[102..110].copy_from_slice(
            format!(
                "{:08x}",
                body.iter().fold(0u32, |s, b| s.wrapping_add(*b as u32))
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(&h);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.resize(super::aligned(out.len())?, 0);
    out.extend_from_slice(body);
    out.resize(super::aligned(out.len())?, 0);
    Ok(())
}
fn instrument(source: &[u8], logger: &[u8], original_sha: &str) -> Result<(Vec<u8>, usize)> {
    let parsed = entries(source)?;
    let original = parsed
        .iter()
        .find(|e| e.name == "init")
        .context("original init missing")?;
    ensure!(
        super::number(original.header, 1)? & 0o170000 == 0o100000
            && super::number(original.header, 4)? == 1
            && digest(original.body) == original_sha,
        "original init type/link/digest guard failed"
    );
    ensure!(
        !parsed.iter().any(|e| e.name == "init.gb-original"),
        "instrumentation destination already exists"
    );
    let binary = goblin::elf::Elf::parse(logger)?;
    ensure!(
        binary.header.e_machine == 183
            && binary.is_64
            && binary.little_endian
            && binary.interpreter.is_none()
            && binary.libraries.is_empty()
            && binary.program_headers.iter().any(|p| p.p_type
                == goblin::elf::program_header::PT_LOAD
                && p.p_flags & goblin::elf::program_header::PF_X != 0
                && p.p_vaddr <= binary.entry
                && p.p_vaddr
                    .checked_add(p.p_memsz)
                    .is_some_and(|end| binary.entry < end)),
        "logger must be static ARM64 ELF"
    );
    let original_binary = goblin::elf::Elf::parse(original.body)?;
    ensure!(
        original_binary.header.e_machine == 183 && original_binary.is_64,
        "retained init must be ARM64 ELF"
    );
    let inode = parsed
        .iter()
        .map(|e| super::number(e.header, 0))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .context("newc inode space exhausted")?;
    let mut out = Vec::new();
    let mut unchanged = 0;
    for e in &parsed {
        if e.name == "init" {
            append(&mut out, e.header, "init.gb-original", e.body, None)?;
            append(&mut out, e.header, "init", logger, Some(inode))?;
        } else {
            out.extend_from_slice(e.raw);
            unchanged += usize::from(e.name != "TRAILER!!!");
        }
    }
    out.resize(out.len() + ((512 - out.len() % 512) % 512), 0);
    let checked = entries(&out)?;
    ensure!(
        checked.len() == parsed.len() + 1,
        "unexpected instrumentation entry count"
    );
    let before: Vec<_> = parsed
        .iter()
        .filter(|e| e.name != "init" && e.name != "TRAILER!!!")
        .collect();
    let after: Vec<_> = checked
        .iter()
        .filter(|e| e.name != "init" && e.name != "init.gb-original" && e.name != "TRAILER!!!")
        .collect();
    ensure!(
        before.len() == after.len() && before.iter().zip(after).all(|(a, b)| a.raw == b.raw),
        "unrelated ramdisk records changed or reordered"
    );
    ensure!(
        checked
            .iter()
            .find(|e| e.name == "init.gb-original")
            .map(|e| digest(e.body))
            == Some(original_sha.to_string()),
        "original init changed"
    );
    Ok((out, unchanged))
}
fn pack_args(text: &str) -> Result<Vec<String>> {
    let fields: Vec<_> = text
        .strip_suffix('\0')
        .context("NUL-separated unpacker output required")?
        .split('\0')
        .collect();
    ensure!(
        fields.len().is_multiple_of(2),
        "malformed unpacker arguments"
    );
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for p in fields.chunks_exact(2) {
        ensure!(
            [
                "--header_version",
                "--pagesize",
                "--base",
                "--kernel_offset",
                "--ramdisk_offset",
                "--tags_offset",
                "--cmdline",
                "--board",
                "--os_version",
                "--os_patch_level",
                "--kernel",
                "--ramdisk"
            ]
            .contains(&p[0])
                && seen.insert(p[0]),
            "unexpected/duplicate init_boot argument"
        );
        if p[0] == "--kernel" {
            ensure!(p[1] == "/output/kernel", "unexpected kernel path");
        }
        if p[0] == "--ramdisk" {
            ensure!(p[1] == "/output/ramdisk", "unexpected ramdisk path");
        }
        result.extend(p.iter().map(|s| s.to_string()));
    }
    ensure!(
        seen.contains("--ramdisk") && seen.contains("--header_version"),
        "required boot arguments missing"
    );
    Ok(result)
}
fn header(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut h = gb_partition::read_at(&mut f, 0, 1584)?;
    ensure!(
        &h[..8] == b"ANDROID!"
            && u32::from_le_bytes(h[8..12].try_into()?) == 0
            && u32::from_le_bytes(h[40..44].try_into()?) == 4
            && u32::from_le_bytes(h[1580..1584].try_into()?) == 0,
        "only kernel-free init_boot v4 without GKI signature is supported"
    );
    h[12..16].fill(0);
    Ok(h)
}
fn unpack_init(
    input: &Path,
    unpack: &Path,
    lz4: &Path,
    sandbox: &gb_tools::Sandbox,
    out: &Path,
) -> Result<(Vec<String>, Vec<u8>, bool)> {
    let unpack = gb_tools::run(
        sandbox,
        unpack,
        vec![
            "--boot_img".into(),
            "/input.img".into(),
            "--out".into(),
            "/output".into(),
            "--format".into(),
            "mkbootimg".into(),
            "-0".into(),
        ],
        input,
        out,
        Duration::from_secs(60),
    )?;
    let args = pack_args(&unpack.stdout)?;
    let ramdisk = out.join("ramdisk");
    if out.join("kernel").exists() {
        ensure!(
            std::fs::metadata(out.join("kernel"))?.len() == 0,
            "diagnostics cannot replace a kernel"
        );
    }
    let magic = gb_partition::read_at(&mut File::open(&ramdisk)?, 0, 4)?;
    let scratch = tempfile::tempdir()?;
    let gzip = magic[..2] == [0x1f, 0x8b];
    let mut raw = Vec::new();
    if gzip {
        flate2::read::GzDecoder::new(File::open(&ramdisk)?)
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
    } else {
        ensure!(magic == [2, 33, 76, 24], "unknown init ramdisk compression");
        gb_tools::run(
            sandbox,
            lz4,
            vec![
                "-d".into(),
                "/input.img".into(),
                "/output/ramdisk.cpio".into(),
            ],
            &ramdisk,
            scratch.path(),
            Duration::from_secs(60),
        )?;
        ensure!(
            std::fs::metadata(scratch.path().join("ramdisk.cpio"))?.len() <= 128 * 1024 * 1024,
            "expanded ramdisk exceeds budget"
        );
        raw = std::fs::read(scratch.path().join("ramdisk.cpio"))?;
    }
    Ok((args, raw, gzip))
}
pub fn inspect(
    input: &Path,
    unpack: &Path,
    lz4: &Path,
    sandbox: &gb_tools::Sandbox,
) -> Result<serde_json::Value> {
    header(input)?;
    ensure!(
        std::fs::metadata(input)?.len() <= 64 * 1024 * 1024,
        "init_boot size limit exceeded"
    );
    let source_sha = hash_file(input)?;
    let out = tempfile::tempdir()?;
    let (_, raw, gzip) = unpack_init(input, unpack, lz4, sandbox, out.path())?;
    let parsed = entries(&raw)?;
    let init = parsed
        .iter()
        .find(|e| e.name == "init")
        .context("init entry missing")?;
    let elf = goblin::elf::Elf::parse(init.body)?;
    ensure!(elf.header.e_machine == 183, "original init is not ARM64");
    ensure!(
        hash_file(input)? == source_sha,
        "source init_boot changed during inspection"
    );
    Ok(
        serde_json::json!({"schema_version":1,"source_sha256":source_sha,"original_init_sha256":digest(init.body),"original_init_bytes":init.body.len(),"archive_entries":parsed.len()-1,"ramdisk_compression":if gzip {"gzip"} else {"legacy_lz4"},"runtime_verified":false}),
    )
}
pub fn build(request: &Request, out: &Path) -> Result<Report> {
    request.validate()?;
    for (input, sha) in [
        (&request.input, &request.sha256),
        (&request.logger, &request.logger_sha256),
    ] {
        gb_core::separate_from_input(input, out)?;
        ensure!(
            hash_file(input)? == *sha,
            "diagnostic input checksum mismatch"
        );
    }
    ensure!(
        std::fs::metadata(&request.input)?.len() <= 64 * 1024 * 1024
            && std::fs::metadata(&request.logger)?.len() <= 4 * 1024 * 1024,
        "diagnostic input size limit exceeded"
    );
    let before = header(&request.input)?;
    let mut tools = Vec::new();
    for tool in [&request.unpack, &request.pack, &request.lz4] {
        tools.push(gb_tools::identity(
            &gb_tools::host_tool(tool, &[&request.input, &request.logger])?,
            &request.sandbox,
        )?);
    }
    let (mut args, raw, gzip) = unpack_init(
        &request.input,
        &request.unpack,
        &request.lz4,
        &request.sandbox,
        out,
    )?;
    let ramdisk = out.join("ramdisk");
    let scratch = tempfile::tempdir()?;
    let (patched, unchanged) = instrument(
        &raw,
        &std::fs::read(&request.logger)?,
        &request.original_init_sha256,
    )?;
    if gzip {
        let mut encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(File::create(&ramdisk)?, flate2::Compression::best());
        encoder.write_all(&patched)?;
        encoder.finish()?;
    } else {
        let raw_path = scratch.path().join("ramdisk.cpio");
        std::fs::write(&raw_path, &patched)?;
        gb_tools::run(
            &request.sandbox,
            &request.lz4,
            vec![
                "-l".into(),
                "-12".into(),
                "/input.img".into(),
                "/output/ramdisk.lz4".into(),
            ],
            &raw_path,
            scratch.path(),
            Duration::from_secs(60),
        )?;
        std::fs::copy(scratch.path().join("ramdisk.lz4"), &ramdisk)?;
    }
    args.extend(["--output".into(), "/output/init_boot.img".into()]);
    gb_tools::run(
        &request.sandbox,
        &request.pack,
        args,
        &request.input,
        out,
        Duration::from_secs(60),
    )?;
    let image = out.join("init_boot.img");
    ensure!(
        header(&image)? == before,
        "protected init_boot header changed"
    );
    ensure!(
        std::fs::metadata(&image)?.len() + 262144 < std::fs::metadata(&request.input)?.len(),
        "instrumented image exceeds source capacity with AVB reserve"
    );
    ensure!(
        hash_file(&request.input)? == request.sha256,
        "source init_boot changed"
    );
    let report = Report {
        schema_version: 1,
        status: "unsigned_temporary_init_boot_diagnostics".into(),
        bootable: false,
        runtime_verified: false,
        source_sha256: request.sha256.clone(),
        image_sha256: hash_file(&image)?,
        image_bytes: std::fs::metadata(&image)?.len(),
        retained_init_sha256: request.original_init_sha256.clone(),
        logger_sha256: request.logger_sha256.clone(),
        unchanged_cpio_entries: unchanged,
        original_header_preserved_except_ramdisk_length: true,
        output_file: "/metadata/gb-port/first-stage.log".into(),
        policy_unchanged: true,
        tools,
        limitations: vec![
            "Requires metadata to mount before logs can persist".into(),
            "Logging may stop when SELinux policy loads; no policy permissions are relaxed".into(),
            "Temporary diagnostics are not proof of a working desktop or hardware".into(),
        ],
    };
    // Only publication artifacts remain; unpacker files are not extracted on host.
    for e in std::fs::read_dir(out)? {
        let e = e?;
        if e.file_name() != "init_boot.img" {
            ensure!(
                e.file_type()?.is_file(),
                "unexpected unpacker directory/symlink"
            );
            std::fs::remove_file(e.path())?;
        }
    }
    write_json(&out.join("diagnostic-report.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(records: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, (name, mode, body)) in records
            .iter()
            .chain(std::iter::once(&("TRAILER!!!", 0, &[][..])))
            .enumerate()
        {
            let mut header = b"070701".to_vec();
            for value in [
                i as u32,
                *mode,
                0,
                0,
                1,
                0,
                body.len() as u32,
                0,
                0,
                0,
                0,
                (name.len() + 1) as u32,
                0,
            ] {
                header.extend_from_slice(format!("{value:08x}").as_bytes());
            }
            append(&mut out, &header, name, body, None).unwrap();
        }
        out
    }
    #[test]
    fn duplicate_directories_are_preserved_but_duplicate_files_are_refused() {
        let source = archive(&[
            ("dev", 0o040755, b""),
            ("dev", 0o040700, b""),
            ("init", 0o100750, b"original"),
        ]);
        let parsed = entries(&source).unwrap();
        assert_eq!(parsed.iter().filter(|e| e.name == "dev").count(), 2);
        assert!(
            entries(&archive(&[
                ("init", 0o100750, b"a"),
                ("init", 0o100750, b"b")
            ]))
            .is_err()
        );
        assert!(entries(&archive(&[("dev", 0o040755, b""), ("dev", 0o100600, b"b")])).is_err());
    }
    #[test]
    fn unsafe_truncated_and_trailing_archives_are_refused() {
        assert!(entries(&archive(&[("../init", 0o100750, b"a")])).is_err());
        let source = archive(&[("init", 0o100750, b"a")]);
        assert!(entries(&source[..source.len() - 2]).is_err());
        let mut concatenated = source.clone();
        concatenated.extend_from_slice(&source);
        assert!(entries(&concatenated).is_err());
    }
    #[test]
    fn original_init_digest_mismatch_blocks_transformation() {
        let source = archive(&[("init", 0o100750, b"a")]);
        assert!(instrument(&source, b"not an ELF", &digest(b"different")).is_err());
    }
}
