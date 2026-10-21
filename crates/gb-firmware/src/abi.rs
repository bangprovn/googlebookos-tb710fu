//! Static ELF symbol preflight for an explicitly isolated native dependency set.
//! This does not model linker namespaces, relocations or semantic ABI compatibility.
use anyhow::{Context, Result, ensure};
use goblin::elf::{Elf, section_header::SHN_UNDEF, sym::*};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Symbol {
    pub name: String,
    pub version: Option<String>,
    pub default_version: bool,
    pub weak: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    pub path: String,
    pub sha256: String,
    pub machine: u16,
    pub soname: String,
    pub needed: Vec<String>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingSymbol {
    pub consumer: String,
    pub symbol: Symbol,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub static_symbols_resolved: bool,
    pub runtime_verified: bool,
    pub objects: Vec<Object>,
    pub missing_dependencies: BTreeMap<String, Vec<String>>,
    pub missing_symbols: Vec<MissingSymbol>,
    pub limitations: Vec<String>,
}

pub fn inspect(path: &Path) -> Result<Object> {
    const LIMIT: u64 = 64 * 1024 * 1024;
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= LIMIT,
        "ELF input exceeds bounded regular-file limit"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "ELF grew beyond input limit");
    let elf = Elf::parse(&bytes).context("invalid bounded ELF input")?;
    ensure!(
        elf.dynsyms.len() <= 200_000,
        "ELF dynamic symbol budget exceeded"
    );
    let string = |index| -> Result<String> {
        let value = elf
            .dynstrtab
            .get_at(index)
            .context("invalid ELF symbol/version string")?;
        ensure!(value.len() <= 8192, "ELF symbol string exceeds budget");
        Ok(value.into())
    };
    let mut imports_versions = BTreeMap::new();
    if let Some(section) = &elf.verneed {
        for need in section.iter() {
            let versions: Vec<_> = need.iter().collect();
            ensure!(
                versions.len() == usize::from(need.vn_cnt),
                "truncated ELF required versions"
            );
            for v in versions {
                ensure!(
                    imports_versions
                        .insert(v.vna_other & 0x7fff, string(v.vna_name)?)
                        .is_none(),
                    "duplicate ELF required version index"
                );
            }
        }
    }
    let mut exports_versions = BTreeMap::new();
    if let Some(section) = &elf.verdef {
        for definition in section.iter() {
            let versions: Vec<_> = definition.iter().collect();
            ensure!(
                versions.len() == usize::from(definition.vd_cnt),
                "truncated ELF provided versions"
            );
            let first = versions.first().context("empty ELF provided version")?;
            ensure!(
                exports_versions
                    .insert(definition.vd_ndx & 0x7fff, string(first.vda_name)?)
                    .is_none(),
                "duplicate ELF provided version index"
            );
        }
    }
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    for (index, symbol) in elf.dynsyms.iter().enumerate() {
        if symbol.st_name == 0
            || ![STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE].contains(&symbol.st_bind())
        {
            continue;
        }
        let undefined = symbol.st_shndx == SHN_UNDEF as usize;
        if !undefined && ![STV_DEFAULT, STV_PROTECTED].contains(&symbol.st_visibility()) {
            continue;
        }
        let version = elf
            .versym
            .as_ref()
            .map(|s| {
                s.get_at(index)
                    .context("truncated ELF symbol version array")
            })
            .transpose()?;
        if version.as_ref().is_some_and(|v| v.is_local()) {
            continue;
        }
        let version_name = if let Some(v) = version.as_ref().filter(|v| v.version() > 1) {
            let map = if undefined {
                &imports_versions
            } else {
                &exports_versions
            };
            Some(
                map.get(&v.version())
                    .context("unresolved ELF symbol version index")?
                    .clone(),
            )
        } else {
            None
        };
        let record = Symbol {
            name: string(symbol.st_name)?,
            version: version_name,
            default_version: version.is_none_or(|v| !v.is_hidden()),
            weak: symbol.st_bind() == STB_WEAK,
        };
        if undefined {
            imports.push(record);
        } else {
            exports.push(record);
        }
    }
    imports.sort();
    exports.sort();
    Ok(Object {
        path: path.display().to_string(),
        sha256: gb_core::digest(&bytes),
        machine: elf.header.e_machine,
        soname: elf.soname.map(str::to_owned).unwrap_or(
            path.file_name()
                .context("ELF filename absent")?
                .to_string_lossy()
                .into_owned(),
        ),
        needed: elf.libraries.iter().map(|s| (*s).into()).collect(),
        imports,
        exports,
    })
}

fn provides(export: &Symbol, import: &Symbol) -> bool {
    export.name == import.name
        && match &import.version {
            Some(version) => export.version.as_ref() == Some(version),
            None => export.default_version,
        }
}

/// `objects` must be the single intended loader scope, including runtime providers.
pub fn evaluate(objects: Vec<Object>) -> Result<Report> {
    ensure!(
        !objects.is_empty() && objects.len() <= 256,
        "invalid native dependency scope size"
    );
    let machine = objects[0].machine;
    ensure!(
        objects
            .iter()
            .map(|o| o.imports.len() + o.exports.len())
            .sum::<usize>()
            <= 500_000,
        "native scope symbol budget exceeded"
    );
    let mut names = BTreeSet::new();
    for object in &objects {
        ensure!(
            object.machine == machine && names.insert(object.soname.clone()),
            "mixed architectures or ambiguous native provider SONAME"
        );
    }
    let mut missing_dependencies = BTreeMap::new();
    let mut exports: BTreeMap<&str, Vec<&Symbol>> = BTreeMap::new();
    for symbol in objects.iter().flat_map(|o| &o.exports) {
        exports.entry(&symbol.name).or_default().push(symbol);
    }
    let mut missing_symbols = Vec::new();
    for object in &objects {
        let missing: Vec<_> = object
            .needed
            .iter()
            .filter(|n| !names.contains(*n))
            .cloned()
            .collect();
        if !missing.is_empty() {
            missing_dependencies.insert(object.path.clone(), missing);
        }
        for symbol in object.imports.iter().filter(|s| !s.weak) {
            if !exports
                .get(symbol.name.as_str())
                .is_some_and(|candidates| candidates.iter().any(|e| provides(e, symbol)))
            {
                missing_symbols.push(MissingSymbol {
                    consumer: object.path.clone(),
                    symbol: symbol.clone(),
                });
            }
        }
    }
    Ok(Report {
        schema_version: 1, static_symbols_resolved: missing_dependencies.is_empty() && missing_symbols.is_empty(), runtime_verified: false,
        objects, missing_dependencies, missing_symbols,
        limitations: vec!["Checks an explicitly supplied isolated loader scope; namespace visibility and actual load order require separate validation".into(), "Matching dynamic symbol names and GNU versions does not prove relocation, data layout, protocol, security policy or semantic ABI compatibility".into(), "No firmware binary is executed; physical service startup and hardware functionality remain unverified".into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn symbol(version: Option<&str>) -> Symbol {
        Symbol {
            name: "required".into(),
            version: version.map(str::to_owned),
            default_version: true,
            weak: false,
        }
    }
    fn object(name: &str) -> Object {
        Object {
            path: name.into(),
            sha256: "a".repeat(64),
            machine: 183,
            soname: name.into(),
            needed: vec![],
            imports: vec![],
            exports: vec![],
        }
    }
    #[test]
    fn missing_versions_dependencies_and_nondefault_exports_are_not_compatible() {
        let mut consumer = object("service");
        consumer.needed.push("library.so".into());
        consumer.imports.push(symbol(Some("V2")));
        let mut library = object("library.so");
        library.exports.push(symbol(Some("V1")));
        assert!(
            !evaluate(vec![consumer.clone(), library.clone()])
                .unwrap()
                .static_symbols_resolved
        );
        library.exports[0].version = Some("V2".into());
        assert!(
            evaluate(vec![consumer.clone(), library.clone()])
                .unwrap()
                .static_symbols_resolved
        );
        consumer.imports[0].version = None;
        library.exports[0].default_version = false;
        assert!(
            !evaluate(vec![consumer.clone(), library])
                .unwrap()
                .static_symbols_resolved
        );
        consumer.imports[0].weak = true;
        let report = evaluate(vec![consumer]).unwrap();
        assert!(report.missing_symbols.is_empty());
        assert!(!report.missing_dependencies.is_empty());
    }
    #[test]
    fn duplicate_providers_mixed_architectures_and_bad_elf_fail_closed() {
        assert!(evaluate(vec![object("same"), object("same")]).is_err());
        let mut other = object("other");
        other.machine = 62;
        assert!(evaluate(vec![object("one"), other]).is_err());
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), b"not ELF").unwrap();
        assert!(inspect(temp.path()).is_err());
    }
}
