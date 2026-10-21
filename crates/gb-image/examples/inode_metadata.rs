//! Read-only EROFS metadata lookup. IMAGE SHA256 ABSOLUTE_IMAGE_PATH.
//! A trailing slash selects that directory and its descendants.
use anyhow::{Context, Result, ensure};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(a.len() == 3, "expected IMAGE SHA256 ABSOLUTE_IMAGE_PATH");
    let p = Path::new(&a[0]);
    let sha = a[1].to_str().context("SHA must be UTF8")?;
    let m = std::fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink(),
        "regular image required"
    );
    ensure!(gb_core::hash_file(p)? == sha, "image SHA256 differs");
    let all = gb_image::metadata::inventory(p)?;
    let path = a[2].to_str().context("path must be UTF8")?;
    if path.ends_with('/') {
        let entries: std::collections::BTreeMap<_, _> = all
            .iter()
            .filter(|(p, _)| *p == path.trim_end_matches('/') || p.starts_with(path))
            .collect();
        ensure!(!entries.is_empty(), "directory absent");
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        let entry = all.get(path).context("image path absent")?;
        println!("{}", serde_json::to_string_pretty(entry)?);
    }
    ensure!(gb_core::hash_file(p)? == sha, "image changed");
    Ok(())
}
