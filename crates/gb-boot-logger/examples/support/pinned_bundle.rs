//! Bounded inventory for a private immutable native dependency tree.
use std::{collections::BTreeSet, fs, io, path::Path};

pub struct Entry<'a> {
    pub path: &'a str,
    pub bytes: u64,
    pub digest: &'a str,
}

pub fn parse(input: &str) -> io::Result<Vec<Entry<'_>>> {
    if input.len() > 32768 || !input.ends_with('\n') {
        return Err(io::Error::other(
            "invalid bundle inventory size/termination",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    let mut entries = Vec::new();
    for line in input.lines() {
        let columns: Vec<_> = line.split(' ').collect();
        if columns.len() != 3 {
            return Err(io::Error::other("invalid bundle inventory columns"));
        }
        let (digest, bytes, path) = (columns[0], columns[1], columns[2]);
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
            || path.len() > 255
            || path.split('/').count() > 8
            || path == "bundle.sha256"
            || path
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || !seen.insert(path)
        {
            return Err(io::Error::other("invalid or duplicate bundle path/digest"));
        }
        let bytes: u64 = bytes.parse().map_err(io::Error::other)?;
        if bytes == 0 || bytes > 64 * 1024 * 1024 {
            return Err(io::Error::other("bundle file exceeds budget"));
        }
        total = total
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("bundle size overflow"))?;
        entries.push(Entry {
            path,
            bytes,
            digest,
        });
        if entries.len() > 128 || total > 1024 * 1024 * 1024 {
            return Err(io::Error::other("bundle inventory exceeds budget"));
        }
    }
    if entries.is_empty() {
        return Err(io::Error::other("empty bundle inventory"));
    }
    Ok(entries)
}

/// Refuse unpinned files, symlinks and special nodes, including unused libraries.
/// The inventory itself must have been verified separately on a read-only FS.
pub fn verify_tree(root: &Path, entries: &[Entry<'_>]) -> io::Result<()> {
    let mut files: BTreeSet<_> = entries.iter().map(|e| e.path.to_owned()).collect();
    files.insert("bundle.sha256".into());
    let mut directories = BTreeSet::new();
    directories.insert(String::new());
    for file in &files {
        let mut parent = Path::new(file).parent();
        while let Some(path) = parent {
            directories.insert(
                path.to_str()
                    .ok_or_else(|| io::Error::other("bundle encoding"))?
                    .to_owned(),
            );
            parent = path.parent();
        }
    }
    fn walk(
        root: &Path,
        relative: &str,
        files: &mut BTreeSet<String>,
        dirs: &mut BTreeSet<String>,
    ) -> io::Result<()> {
        if !dirs.remove(relative) {
            return Err(io::Error::other("unexpected bundle directory"));
        }
        let path = root.join(relative);
        if !fs::symlink_metadata(&path)?.is_dir() {
            return Err(io::Error::other("bundle directory is not a directory"));
        }
        for item in fs::read_dir(path)? {
            let item = item?;
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| io::Error::other("bundle name encoding"))?;
            let child = if relative.is_empty() {
                name.to_owned()
            } else {
                format!("{relative}/{name}")
            };
            let kind = item.file_type()?;
            if kind.is_dir() {
                walk(root, &child, files, dirs)?;
            } else if !kind.is_file() || !files.remove(&child) {
                return Err(io::Error::other("unexpected bundle file or special node"));
            }
        }
        Ok(())
    }
    walk(root, "", &mut files, &mut directories)?;
    if !files.is_empty() || !directories.is_empty() {
        return Err(io::Error::other("bundle inventory entries missing"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line(path: &str) -> String {
        format!("{} 1 {path}\n", "a".repeat(64))
    }
    #[test]
    fn refuses_ambiguous_paths_hashes_and_budgets() {
        for path in ["../a", "/a", "a//b", "a/./b", "a/../b", "a b", "a\\b", ""] {
            assert!(parse(&line(path)).is_err(), "{path}");
        }
        assert!(parse(&(line("a") + &line("a"))).is_err());
        assert!(parse(&line("a").replace(" 1 ", " 0 ")).is_err());
        assert!(parse(&line("a").replace(" 1 ", " 67108865 ")).is_err());
        assert!(parse(&line("a").replace('a', "g")).is_err());
        assert!(parse(line("a").trim_end()).is_err());
        assert!(parse("").is_err());
        assert!(
            parse(
                &(0..129)
                    .map(|n| line(&format!("lib/{n}")))
                    .collect::<String>()
            )
            .is_err()
        );
    }
    #[test]
    fn refuses_unpinned_missing_and_symlinked_dependencies() {
        let root = tempfile::tempdir().unwrap();
        let text = line("runtime/lib64/libtest.so");
        let entries = parse(&text).unwrap();
        assert_eq!(entries[0].bytes, 1);
        assert_eq!(entries[0].digest, "a".repeat(64));
        fs::create_dir_all(root.path().join("runtime/lib64")).unwrap();
        fs::write(root.path().join("bundle.sha256"), &text).unwrap();
        let library = root.path().join(entries[0].path);
        fs::write(&library, b"x").unwrap();
        assert!(verify_tree(root.path(), &entries).is_ok());
        fs::write(root.path().join("runtime/lib64/extra.so"), b"x").unwrap();
        assert!(verify_tree(root.path(), &entries).is_err());
        fs::remove_file(root.path().join("runtime/lib64/extra.so")).unwrap();
        fs::remove_file(&library).unwrap();
        assert!(verify_tree(root.path(), &entries).is_err());
        std::os::unix::fs::symlink("/etc/passwd", &library).unwrap();
        assert!(verify_tree(root.path(), &entries).is_err());
        fs::remove_file(&library).unwrap();
        fs::remove_dir(root.path().join("runtime/lib64")).unwrap();
        std::os::unix::fs::symlink("/tmp", root.path().join("runtime/lib64")).unwrap();
        assert!(verify_tree(root.path(), &entries).is_err());
    }
}
