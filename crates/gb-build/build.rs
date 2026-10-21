use sha2::{Digest, Sha256};
use std::{fs, path::Path};
fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    fn walk(p: &Path, files: &mut Vec<std::path::PathBuf>) {
        for e in fs::read_dir(p).expect("workspace source directory") {
            let p = e.expect("source entry").path();
            if p.is_dir() {
                walk(&p, files)
            } else if p.extension().is_some_and(|e| e == "rs" || e == "toml") {
                files.push(p)
            }
        }
    }
    walk(&root.join("crates"), &mut files);
    files.extend([root.join("Cargo.toml"), root.join("Cargo.lock")]);
    files.sort();
    let mut h = Sha256::new();
    for p in files {
        println!("cargo:rerun-if-changed={}", p.display());
        h.update(
            p.strip_prefix(&root)
                .expect("workspace path")
                .to_string_lossy()
                .as_bytes(),
        );
        h.update(fs::read(p).expect("source read"));
    }
    println!("cargo:rustc-env=GB_ENGINE_DIGEST={h:x}", h = h.finalize());
}
