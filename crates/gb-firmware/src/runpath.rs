//! Explicit, isolated ELF RUNPATH updates using a pinned mature host tool.
use anyhow::{Context, Result, ensure};
use goblin::elf::{
    Elf,
    program_header::{PT_GNU_STACK, PT_LOAD},
    section_header::{SHF_EXECINSTR, SHT_NOTE},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub input: PathBuf,
    pub sha256: String,
    pub destination: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub tool: PathBuf,
    pub tool_sha256: String,
    pub sandbox: gb_tools::Sandbox,
    pub runpath: String,
    pub files: Vec<Input>,
}
#[derive(Debug, Serialize)]
pub struct Output {
    pub destination: String,
    pub source_sha256: String,
    pub sha256: String,
    pub bytes: u64,
    pub original_runpaths: Vec<String>,
    pub runpath: String,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub firmware_written: bool,
    pub runtime_verified: bool,
    pub tool: serde_json::Value,
    pub files: Vec<Output>,
    pub limitations: Vec<String>,
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    machine: u16,
    entry: u64,
    interpreter: Option<String>,
    align: u64,
    code: BTreeMap<String, (u64, String)>,
    notes: BTreeMap<String, String>,
    stack_flags: Vec<u32>,
    runpaths: Vec<String>,
    rpaths: Vec<String>,
}
fn snapshot(path: &Path) -> Result<Snapshot> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "native patch ELF budget exceeded"
    );
    let e = Elf::parse(&bytes)?;
    ensure!(
        e.header.e_machine == 183 && e.is_64 && e.little_endian,
        "native RUNPATH adapter currently requires little-endian ARM64 ELF"
    );
    let align = e
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .map(|p| p.p_align)
        .max()
        .context("ELF LOAD segments absent")?;
    ensure!(
        align.is_power_of_two() && (4096..=65536).contains(&align),
        "unsupported native LOAD alignment"
    );
    let mut code = BTreeMap::new();
    let mut notes = BTreeMap::new();
    for s in &e.section_headers {
        if s.sh_flags & u64::from(SHF_EXECINSTR) == 0 && s.sh_type != SHT_NOTE {
            continue;
        }
        let name = e
            .shdr_strtab
            .get_at(s.sh_name)
            .context("native section name absent")?
            .to_owned();
        let end = s
            .sh_offset
            .checked_add(s.sh_size)
            .context("native section overflow")?;
        let data = bytes
            .get(usize::try_from(s.sh_offset)?..usize::try_from(end)?)
            .context("native section exceeds file")?;
        if s.sh_flags & u64::from(SHF_EXECINSTR) != 0 {
            ensure!(
                code.insert(name.clone(), (s.sh_addr, gb_core::digest(data)))
                    .is_none(),
                "ambiguous executable section"
            );
        }
        if s.sh_type == SHT_NOTE {
            ensure!(
                notes.insert(name, gb_core::digest(data)).is_none(),
                "ambiguous ELF note section"
            );
        }
    }
    ensure!(
        !code.is_empty(),
        "cannot verify native code without executable sections"
    );
    Ok(Snapshot {
        machine: e.header.e_machine,
        entry: e.entry,
        interpreter: e.interpreter.map(str::to_owned),
        align,
        code,
        notes,
        stack_flags: e
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_GNU_STACK)
            .map(|p| p.p_flags)
            .collect(),
        runpaths: e.runpaths.iter().map(|p| (*p).into()).collect(),
        rpaths: e.rpaths.iter().map(|p| (*p).into()).collect(),
    })
}
pub fn patch(request: &Request, out: &Path) -> Result<Report> {
    ensure!(
        !out.exists() && !request.files.is_empty() && request.files.len() <= 256,
        "invalid native patch output/budget"
    );
    request.sandbox.validate()?;
    let prefix = request
        .runpath
        .strip_prefix('/')
        .context("RUNPATH must be an explicit absolute device path")?;
    gb_core::safe_relative(Path::new(prefix))?;
    ensure!(
        prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b)),
        "unsafe or multi-directory RUNPATH"
    );
    let inputs: Vec<_> = request.files.iter().map(|f| f.input.as_path()).collect();
    let tool = gb_tools::host_tool(&request.tool, &inputs)?;
    ensure!(
        gb_core::hash_file(&tool)? == request.tool_sha256,
        "native patch tool digest mismatch"
    );
    let tool_id = gb_tools::identity(&tool, &request.sandbox)?;
    let parent = out.parent().unwrap_or(Path::new("."));
    let stage = tempfile::tempdir_in(parent)?;
    let selected = stage.path().join("selected");
    std::fs::create_dir(&selected)?;
    let mut names = std::collections::BTreeSet::new();
    let mut files = Vec::new();
    for (index, input) in request.files.iter().enumerate() {
        gb_core::checkpoint()?;
        gb_core::separate_from_input(&input.input, out)?;
        gb_core::safe_relative(Path::new(&input.destination))?;
        ensure!(
            names.insert(&input.destination),
            "duplicate native patch destination"
        );
        let before = snapshot(&input.input)?;
        let original = crate::abi::inspect(&input.input)?;
        ensure!(
            original.sha256 == input.sha256,
            "native patch source digest mismatch"
        );
        let work = stage.path().join(format!("file-{index}"));
        std::fs::create_dir(&work)?;
        gb_tools::run(
            &request.sandbox,
            &tool,
            vec![
                "--page-size".into(),
                before.align.to_string(),
                "--set-rpath".into(),
                request.runpath.clone(),
                "--output".into(),
                "/output/payload".into(),
                "/input.img".into(),
            ],
            &input.input,
            &work,
            Duration::from_secs(30),
        )?;
        let payload = work.join("payload");
        let mut after = snapshot(&payload)?;
        let patched = crate::abi::inspect(&payload)?;
        ensure!(
            after.runpaths == [request.runpath.clone()] && after.rpaths.is_empty(),
            "native patch did not set exact RUNPATH"
        );
        after.runpaths = before.runpaths.clone();
        after.rpaths = before.rpaths.clone();
        ensure!(
            after == before
                && original.machine == patched.machine
                && original.needed == patched.needed
                && original.soname == patched.soname
                && original.imports == patched.imports
                && original.exports == patched.exports,
            "native patch altered protected code/entry/interpreter/notes/alignment/stack/dependency/symbol metadata"
        );
        ensure!(
            gb_core::hash_file(&input.input)? == input.sha256,
            "native patch source changed during processing"
        );
        let destination = selected.join(&input.destination);
        std::fs::create_dir_all(
            destination
                .parent()
                .context("native output parent absent")?,
        )?;
        std::fs::copy(&payload, destination)?;
        files.push(Output {
            destination: input.destination.clone(),
            source_sha256: input.sha256.clone(),
            sha256: patched.sha256,
            bytes: std::fs::metadata(&payload)?.len(),
            original_runpaths: before.runpaths,
            runpath: request.runpath.clone(),
        });
    }
    ensure!(
        gb_core::hash_file(&tool)? == request.tool_sha256,
        "native patch tool changed"
    );
    let report = Report { schema_version: 1, firmware_written: false, runtime_verified: false, tool: tool_id, files, limitations: vec!["Original ELF code bytes/addresses, notes, entry, interpreter, alignment, stack flags, dependency names and versioned symbols are preserved; runtime linker/service behavior is unverified".into(), "Preserved upstream build IDs describe the original object; transformed objects are identified by SHA256".into()] };
    gb_core::write_json(&selected.join("runpath-report.json"), &report)?;
    std::fs::rename(selected, out)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bad_elf_and_dynamic_search_path_injection_are_rejected() {
        let t = tempfile::tempdir().unwrap();
        let input = t.path().join("bad");
        std::fs::write(&input, b"bad ELF").unwrap();
        assert!(snapshot(&input).is_err());
        let mut request = Request {
            tool: "patchelf".into(),
            tool_sha256: "a".repeat(64),
            sandbox: gb_tools::Sandbox::Bubblewrap,
            runpath: "/isolated:/untrusted".into(),
            files: vec![Input {
                input,
                sha256: "b".repeat(64),
                destination: "lib/test.so".into(),
            }],
        };
        assert!(
            patch(&request, &t.path().join("output"))
                .unwrap_err()
                .to_string()
                .contains("multi-directory")
        );
        request.runpath = "/../escape".into();
        assert!(patch(&request, &t.path().join("output")).is_err());
    }
}
