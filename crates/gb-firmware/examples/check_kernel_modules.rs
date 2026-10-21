//! MODULE_SYMVERS MODULE_TREE FULL_KERNEL_VERMAGIC NEW_REPORT_JSON
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, fs, path::Path};

fn collect(
    root: &Path,
    path: &Path,
    modules: &mut BTreeMap<String, gb_firmware::kernel_modules::Module>,
    depth: usize,
    entries: &mut usize,
) -> Result<()> {
    ensure!(
        depth <= 32 && *entries <= 100_000,
        "module tree exceeds traversal budget"
    );
    for entry in fs::read_dir(path)? {
        *entries += 1;
        ensure!(*entries <= 100_000, "module tree exceeds entry budget");
        let entry = entry?;
        let ty = entry.file_type()?;
        let path = entry.path();
        if ty.is_dir() {
            collect(root, &path, modules, depth + 1, entries)?;
        } else if path.extension().is_some_and(|v| v == "ko") {
            ensure!(
                ty.is_file() && modules.len() < 4096,
                "module symlink or count budget exceeded"
            );
            modules.insert(
                path.strip_prefix(root)?
                    .to_str()
                    .context("module path must be UTF8")?
                    .into(),
                gb_firmware::kernel_modules::inspect(&path)?,
            );
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        a.len() == 4,
        "expected MODULE_SYMVERS MODULE_TREE FULL_KERNEL_VERMAGIC NEW_REPORT_JSON"
    );
    let output = Path::new(&a[3]);
    ensure!(!output.exists(), "report exists");
    let meta = fs::symlink_metadata(&a[0])?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 16 * 1024 * 1024,
        "invalid Module.symvers input"
    );
    let kernel = gb_firmware::kernel_modules::symvers(&fs::read_to_string(&a[0])?)?;
    let root = Path::new(&a[1]);
    ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "module root must be directory"
    );
    gb_core::separate_from_input(root, output)?;
    let mut modules = BTreeMap::new();
    collect(root, root, &mut modules, 0, &mut 0)?;
    let report = gb_firmware::kernel_modules::compare(
        kernel,
        modules,
        a[2].to_str().context("release must be UTF8")?,
    )?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    file.sync_all()?;
    println!(
        "modules={} static_crc_match={} signature_trust=false runtime_verified=false",
        report.modules.len(),
        report.static_crc_match
    );
    ensure!(
        report.static_crc_match,
        "module static preflight failed; inspect report"
    );
    Ok(())
}
