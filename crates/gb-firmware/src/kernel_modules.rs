//! Static ARM64 kernel-module CRC preflight. Does not establish runtime or signature trust.
use anyhow::{Context, Result, ensure};
use goblin::elf::{
    Elf,
    header::{EM_AARCH64, ET_REL},
    section_header::SHN_ABS,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub sha256: String,
    pub vermagic: String,
    pub imports: BTreeMap<String, u32>,
    pub exports: BTreeMap<String, u32>,
    pub signature_bytes: Option<u32>,
}

fn name(bytes: &[u8]) -> Result<String> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .context("unterminated module symbol")?;
    let value = std::str::from_utf8(&bytes[..end])?;
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.$".contains(&b)),
        "invalid module symbol name"
    );
    Ok(value.into())
}

fn versions(bytes: &[u8]) -> Result<BTreeMap<String, u32>> {
    ensure!(
        !bytes.is_empty() && bytes.len().is_multiple_of(64) && bytes.len() <= 64 * 100_000,
        "invalid ARM64 modversion record array"
    );
    let mut out = BTreeMap::new();
    for entry in bytes.chunks_exact(64) {
        let crc = u64::from_le_bytes(entry[..8].try_into()?);
        ensure!(crc <= u32::MAX.into(), "module CRC exceeds 32 bits");
        ensure!(
            out.insert(name(&entry[8..])?, crc as u32).is_none(),
            "duplicate module version symbol"
        );
    }
    Ok(out)
}

// CONFIG_EXTENDED_MODVERSIONS separates little-endian u32 CRCs from NUL
// terminated names. Linux modpost emits an extra C string terminator after
// the final explicit name terminator; that byte is not another symbol.
fn extended_versions(crcs: &[u8], names: &[u8]) -> Result<BTreeMap<String, u32>> {
    ensure!(
        !crcs.is_empty() && crcs.len().is_multiple_of(4) && crcs.len() <= 4 * 100_000,
        "invalid extended module CRC array"
    );
    ensure!(
        !names.is_empty() && names.len() <= 16 * 1024 * 1024,
        "invalid extended module name array"
    );
    let mut remaining = names;
    let mut out = BTreeMap::new();
    for crc in crcs.chunks_exact(4) {
        let symbol = name(remaining)?;
        remaining = &remaining[symbol.len() + 1..];
        ensure!(
            out.insert(symbol, u32::from_le_bytes(crc.try_into()?))
                .is_none(),
            "duplicate extended module version symbol"
        );
    }
    ensure!(
        remaining.is_empty() || remaining == [0],
        "extended module name/CRC counts differ"
    );
    Ok(out)
}

fn import_versions(
    basic: Option<&[u8]>,
    crcs: Option<&[u8]>,
    names: Option<&[u8]>,
) -> Result<BTreeMap<String, u32>> {
    let basic = basic.map(versions).transpose()?;
    match (crcs, names) {
        (Some(crcs), Some(names)) => {
            let extended = extended_versions(crcs, names)?;
            if let Some(basic) = basic {
                // modpost omits long names from the basic table. Its entries
                // must still agree with the complete extended table.
                ensure!(
                    basic
                        .iter()
                        .all(|(name, crc)| extended.get(name) == Some(crc))
                        && extended
                            .iter()
                            .filter(|(name, _)| name.len() < 56)
                            .all(|(name, crc)| basic.get(name) == Some(crc)),
                    "basic and extended module versions disagree"
                );
            }
            Ok(extended)
        }
        (None, None) => basic.context("module version sections absent"),
        _ => anyhow::bail!("incomplete extended module version sections"),
    }
}

pub fn inspect(path: &Path) -> Result<Module> {
    const LIMIT: u64 = 64 * 1024 * 1024;
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= LIMIT,
        "module must be a regular non-symlink file under 64 MiB"
    );
    let mut bytes = Vec::new();
    File::open(path)?.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "module grew past size budget");
    let elf = Elf::parse(&bytes).context("invalid module ELF")?;
    ensure!(
        elf.is_64
            && elf.little_endian
            && elf.header.e_machine == EM_AARCH64
            && elf.header.e_type == ET_REL,
        "requires little-endian ARM64 relocatable module"
    );
    let section = |wanted: &str| -> Result<Option<&[u8]>> {
        let rows: Vec<_> = elf
            .section_headers
            .iter()
            .filter(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(wanted))
            .collect();
        ensure!(rows.len() <= 1, "duplicate module section {wanted}");
        let Some(s) = rows.first() else {
            return Ok(None);
        };
        let start = usize::try_from(s.sh_offset)?;
        let size = usize::try_from(s.sh_size)?;
        Ok(Some(
            bytes
                .get(start..start.checked_add(size).context("module section overflow")?)
                .context("truncated module section")?,
        ))
    };
    let modinfo = section(".modinfo")?.context("module .modinfo absent")?;
    ensure!(
        modinfo.len() <= 1024 * 1024,
        "module metadata exceeds budget"
    );
    let magic: Vec<_> = modinfo
        .split(|b| *b == 0)
        .filter_map(|s| s.strip_prefix(b"vermagic="))
        .collect();
    ensure!(magic.len() == 1, "missing/duplicate vermagic");
    let vermagic = std::str::from_utf8(magic[0])?.to_owned();
    ensure!(
        !vermagic.is_empty() && vermagic.len() <= 1024 && !vermagic.chars().any(char::is_control),
        "invalid vermagic"
    );
    let imports = import_versions(
        section("__versions")?,
        section("__version_ext_crcs")?,
        section("__version_ext_names")?,
    )?;
    ensure!(
        imports.contains_key("module_layout"),
        "module_layout CRC absent"
    );
    ensure!(elf.syms.len() <= 1_000_000, "module symbol budget exceeded");
    let mut exports = BTreeMap::new();
    for sym in &elf.syms {
        if let Some(symbol) = elf
            .strtab
            .get_at(sym.st_name)
            .and_then(|s| s.strip_prefix("__crc_"))
        {
            let crc = if sym.st_shndx == SHN_ABS as usize {
                u32::try_from(sym.st_value).context("export CRC exceeds 32 bits")?
            } else {
                let s = elf
                    .section_headers
                    .get(sym.st_shndx)
                    .context("CRC section index invalid")?;
                ensure!(
                    matches!(
                        elf.shdr_strtab.get_at(s.sh_name),
                        Some("__kcrctab" | "__kcrctab_gpl")
                    ),
                    "unsupported exported CRC section"
                );
                ensure!(
                    sym.st_value.checked_add(4).is_some_and(|v| v <= s.sh_size),
                    "CRC exceeds section bounds"
                );
                let start = usize::try_from(
                    s.sh_offset
                        .checked_add(sym.st_value)
                        .context("CRC offset overflow")?,
                )?;
                u32::from_le_bytes(
                    bytes
                        .get(start..start.checked_add(4).context("CRC end overflow")?)
                        .context("truncated export CRC")?
                        .try_into()?,
                )
            };
            ensure!(
                !symbol.is_empty() && exports.insert(symbol.into(), crc).is_none(),
                "invalid/duplicate module export"
            );
        }
    }
    const MARKER: &[u8] = b"~Module signature appended~\n";
    let signature_bytes = if bytes.ends_with(MARKER) {
        let end = bytes.len() - MARKER.len();
        let header = bytes
            .get(
                end.checked_sub(12)
                    .context("truncated module signature header")?..end,
            )
            .context("truncated module signature")?;
        let len = u32::from_be_bytes(header[8..12].try_into()?);
        ensure!(
            header[2] == 2 && len > 0 && len as usize <= end - 12,
            "invalid PKCS7 module signature bounds/type"
        );
        Some(len)
    } else {
        None
    };
    Ok(Module {
        sha256: gb_core::digest(&bytes),
        vermagic,
        imports,
        exports,
        signature_bytes,
    })
}

pub fn symvers(text: &str) -> Result<BTreeMap<String, u32>> {
    ensure!(
        text.len() <= 16 * 1024 * 1024,
        "Module.symvers exceeds 16 MiB budget"
    );
    let mut out = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let row: Vec<_> = line.split_whitespace().collect();
        ensure!((4..=5).contains(&row.len()), "malformed Module.symvers row");
        // Rebuilt common modules are not necessarily installed. Only the kernel
        // and the explicitly inspected retained modules can provide symbols.
        if row[2] != "vmlinux" {
            continue;
        }
        let crc = u32::from_str_radix(
            row[0]
                .strip_prefix("0x")
                .context("CRC requires 0x prefix")?,
            16,
        )?;
        ensure!(
            out.insert(row[1].into(), crc).is_none(),
            "duplicate Module.symvers symbol"
        );
    }
    ensure!(!out.is_empty(), "empty Module.symvers");
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub module: String,
    pub symbol: String,
    pub expected_crc: u32,
    pub available_crc: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub static_crc_match: bool,
    pub runtime_verified: bool,
    pub signatures_verified: bool,
    pub modules: BTreeMap<String, Module>,
    pub mismatches: Vec<Finding>,
    pub vermagic_mismatches: Vec<String>,
    pub release_differences: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn compare(
    kernel: BTreeMap<String, u32>,
    modules: BTreeMap<String, Module>,
    kernel_vermagic: &str,
) -> Result<Report> {
    ensure!(
        !modules.is_empty() && modules.len() <= 4096 && kernel_vermagic.contains(" modversions "),
        "module set and full MODVERSIONS kernel vermagic required"
    );
    let mut available = kernel;
    for module in modules.values() {
        for (symbol, crc) in &module.exports {
            if let Some(previous) = available.insert(symbol.clone(), *crc) {
                ensure!(
                    previous == *crc,
                    "conflicting providers for module symbol {symbol}"
                );
            }
        }
    }
    let mut mismatches = Vec::new();
    let mut vermagic_mismatches = Vec::new();
    let mut release_differences = Vec::new();
    for (path, module) in &modules {
        // Linux same_magic ignores only the release prefix when __versions exists.
        if module.vermagic.split_once(' ').map(|v| v.1)
            != kernel_vermagic.split_once(' ').map(|v| v.1)
        {
            vermagic_mismatches.push(path.clone());
        }
        if module.vermagic.split_once(' ').map(|v| v.0)
            != kernel_vermagic.split_once(' ').map(|v| v.0)
        {
            release_differences.push(path.clone());
        }
        for (symbol, expected) in &module.imports {
            if available.get(symbol) != Some(expected) {
                mismatches.push(Finding {
                    module: path.clone(),
                    symbol: symbol.clone(),
                    expected_crc: *expected,
                    available_crc: available.get(symbol).copied(),
                });
            }
        }
    }
    Ok(Report {
        schema_version:1,static_crc_match:mismatches.is_empty() && vermagic_mismatches.is_empty(),runtime_verified:false,signatures_verified:false,
        modules,mismatches,vermagic_mismatches,release_differences,
        limitations:vec!["CRC and release preflight only; does not prove CFI behavior, semantic KMI, runtime loading or signature trust".into(),"Every retained module provider must be included; module load ordering is not validated".into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_corrupt_version_records() {
        assert!(versions(&[]).is_err());
        assert!(versions(&[0; 63]).is_err());
        let mut row = [0; 64];
        row[..8].copy_from_slice(&0x1234_u64.to_le_bytes());
        row[8..12].copy_from_slice(b"foo\0");
        assert_eq!(versions(&row).unwrap()["foo"], 0x1234);
        assert!(versions(&[row, row].concat()).is_err());
        row[8..].fill(b'a');
        assert!(versions(&row).is_err());
        row[8..].fill(0);
        row[8] = b'x';
        row[7] = 1;
        assert!(versions(&row).is_err());
    }
    #[test]
    fn reads_extended_versions_with_modposts_final_string_terminator() {
        let long = format!("_R{}", "x".repeat(80));
        let names = format!("module_layout\0{long}\0\0");
        let crcs = [7_u32.to_le_bytes(), 9_u32.to_le_bytes()].concat();
        let imports = extended_versions(&crcs, names.as_bytes()).unwrap();
        assert_eq!(imports["module_layout"], 7);
        assert_eq!(imports[&long], 9);
        // Tooling may supply exact NUL-terminated records without the C array's
        // additional terminator. Both carry the same two symbols.
        assert_eq!(
            imports,
            extended_versions(&crcs, &names.as_bytes()[..names.len() - 1]).unwrap()
        );
        assert_eq!(
            import_versions(None, Some(&crcs), Some(names.as_bytes())).unwrap(),
            imports
        );
    }
    #[test]
    fn rejects_ambiguous_and_truncated_extended_versions() {
        let crc = 7_u32.to_le_bytes();
        for (crcs, names) in [
            (&[][..], &b"x\0"[..]),
            (&crc[..3], &b"x\0"[..]),
            (&crc[..], &b"x"[..]),
            (&crc[..], &b"\0"[..]),
            (&crc[..], &b"x\0y\0"[..]),
            (&crc[..], &b"x\0\0\0"[..]),
            (&crc[..], &b"x/invalid\0"[..]),
        ] {
            assert!(extended_versions(crcs, names).is_err());
        }
        assert!(extended_versions(&[crc, crc].concat(), b"x\0x\0\0").is_err());
        assert!(extended_versions(&[crc, crc].concat(), b"x\0").is_err());
        assert!(extended_versions(&vec![0; 400_004], b"x\0").is_err());
    }
    #[test]
    fn refuses_partial_or_conflicting_basic_and_extended_tables() {
        let mut basic = [0; 64];
        basic[..8].copy_from_slice(&7_u64.to_le_bytes());
        basic[8..22].copy_from_slice(b"module_layout\0");
        let long = format!("_R{}", "x".repeat(80));
        let names = format!("module_layout\0{long}\0\0");
        let crcs = [7_u32.to_le_bytes(), 9_u32.to_le_bytes()].concat();
        assert_eq!(
            import_versions(Some(&basic), Some(&crcs), Some(names.as_bytes()))
                .unwrap()
                .len(),
            2
        );
        basic[0] = 8;
        assert!(import_versions(Some(&basic), Some(&crcs), Some(names.as_bytes())).is_err());
        basic[0] = 7;
        assert!(
            import_versions(Some(&basic), Some(&crcs), Some(b"module_layout\0short\0\0")).is_err()
        );
        assert!(import_versions(Some(&basic), Some(&crcs), None).is_err());
        assert!(import_versions(Some(&basic), None, Some(names.as_bytes())).is_err());
        assert!(import_versions(None, None, None).is_err());
        assert_eq!(import_versions(Some(&basic), None, None).unwrap().len(), 1);
    }
    #[test]
    fn checks_provider_crc_and_release_without_runtime_claims() {
        let module = Module {
            sha256: "test".into(),
            vermagic: "6.1-test SMP modversions aarch64".into(),
            imports: BTreeMap::from([("kernel_fn".into(), 7), ("vendor_fn".into(), 9)]),
            exports: BTreeMap::from([("vendor_fn".into(), 9)]),
            signature_bytes: None,
        };
        let set = BTreeMap::from([("test.ko".into(), module)]);
        let good = compare(
            BTreeMap::from([("kernel_fn".into(), 7)]),
            set.clone(),
            "6.1-test SMP modversions aarch64",
        )
        .unwrap();
        assert!(good.static_crc_match);
        assert!(!good.runtime_verified && !good.signatures_verified);
        let release_only = compare(
            BTreeMap::from([("kernel_fn".into(), 7)]),
            set.clone(),
            "other SMP modversions aarch64",
        )
        .unwrap();
        assert!(release_only.static_crc_match);
        assert_eq!(release_only.release_differences.len(), 1);
        let bad = compare(
            BTreeMap::from([("kernel_fn".into(), 8)]),
            set,
            "other modversions aarch64",
        )
        .unwrap();
        assert!(!bad.static_crc_match);
        assert_eq!(bad.mismatches.len(), 1);
        assert_eq!(bad.vermagic_mismatches.len(), 1);
    }
    #[test]
    fn symvers_rejects_duplicates_and_malformed_rows() {
        assert_eq!(
            symvers("0x1234\tfoo\tvmlinux\tEXPORT_SYMBOL\t\n").unwrap()["foo"],
            0x1234
        );
        assert!(symvers("0x1 foo vmlinux EXPORT_SYMBOL\n0x1 foo vmlinux EXPORT_SYMBOL\n").is_err());
        assert!(symvers("foo bar").is_err());
        assert!(symvers("").is_err());
    }
}
