use super::*;
use std::process::Command;

struct Fixture {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    out: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let fixture = Self {
            repo,
            out: dir.path().join("public"),
            _dir: dir,
        };
        fixture.git(&["init", "-q"]);
        fixture.git(&["config", "user.name", "PRIVATE_AUTHOR"]);
        fixture.git(&["config", "user.email", "PRIVATE_EMAIL@example.invalid"]);
        fixture.put("src/main.rs", b"fn main() {}\n");
        fixture.put("README.md", b"Public source fixture\n");
        fixture.commit();
        fixture
    }
    fn git(&self, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "test Git fixture operation failed");
        output.stdout
    }
    fn put(&self, name: &str, bytes: &[u8]) {
        let file = self.repo.join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
    fn commit(&self) {
        self.git(&["add", "--all"]);
        self.git(&["commit", "-q", "-m", "private fixture commit metadata"]);
    }
    fn request(&self) -> Request {
        Request {
            schema_version: 1,
            root: self.repo.clone(),
            include_roots: vec!["src".into()],
            include_files: vec!["README.md".into()],
            exclude_paths: Vec::new(),
            deny_literals_file: None,
        }
    }
    fn refused(&self, request: &Request) -> String {
        let error = export(request, &self.out).unwrap_err().to_string();
        assert!(!self.out.exists());
        assert_eq!(
            fs::read_dir(self._dir.path()).unwrap().count(),
            1,
            "temporary export residue"
        );
        error
    }
}

#[test]
fn exports_only_committed_selected_text_deterministically_without_history_or_host_identity() {
    let fixture = Fixture::new();
    fixture.put("private-untracked.txt", b"PRIVATE_CONTENT");
    let one = export(&fixture.request(), &fixture.out).unwrap();
    let other = fixture._dir.path().join("second");
    let two = export(&fixture.request(), &other).unwrap();
    assert_eq!(one, two);
    assert_eq!(
        fs::read(fixture.out.join(LEDGER)).unwrap(),
        fs::read(other.join(LEDGER)).unwrap()
    );
    assert_eq!(
        one.files
            .iter()
            .map(|e| e.path.as_str())
            .collect::<Vec<_>>(),
        ["README.md", "src/main.rs"]
    );
    assert_eq!(
        fs::read(fixture.out.join("src/main.rs")).unwrap(),
        b"fn main() {}\n"
    );
    let ledger = serde_json::to_string(&one).unwrap();
    for private in [
        "PRIVATE",
        "@example.invalid",
        fixture.repo.to_str().unwrap(),
    ] {
        assert!(!ledger.contains(private));
    }
    assert!(!fixture.out.join(".git").exists());
    assert!(!fixture.out.join("private-untracked.txt").exists());
    assert!(!one.automatic_privacy_or_licensing_certification);
    assert_eq!(
        one.file_ledger_sha256,
        gb_core::digest(&serde_json::to_vec(&one.files).unwrap())
    );
}

#[test]
fn dirty_selected_worktree_staged_addition_and_index_refused_but_unselected_dirty_allowed() {
    let fixture = Fixture::new();
    fixture.put("README.md", b"changed\n");
    fixture.refused(&fixture.request());
    fixture.git(&["checkout", "--", "README.md"]);
    fixture.put("src/new.rs", b"// uncommitted\n");
    fixture.git(&["add", "src/new.rs"]);
    fixture.refused(&fixture.request());
    fixture.git(&["reset", "-q", "HEAD", "--", "src/new.rs"]);
    fixture.put("README.md", b"staged\n");
    fixture.git(&["add", "README.md"]);
    fixture.put("README.md", b"Public source fixture\n");
    fixture.refused(&fixture.request());
    fixture.git(&["reset", "-q", "HEAD", "--", "README.md"]);
    fixture.put("unselected.md", b"old\n");
    fixture.commit();
    fixture.put("unselected.md", b"PRIVATE_DIRTY\n");
    export(&fixture.request(), &fixture.out).unwrap();
    assert!(!fixture.out.join("unselected.md").exists());
}

#[test]
fn raw_committed_byte_check_cannot_be_laundered_by_git_text_normalization() {
    let fixture = Fixture::new();
    fixture.put(".gitattributes", b"README.md text\n");
    fixture.commit();
    fixture.put("README.md", b"Public source fixture\r\n");
    fixture.git(&["diff", "--exit-code", "--", "README.md"]);
    assert!(
        fixture
            .refused(&fixture.request())
            .contains("committed raw bytes")
    );
}

#[test]
fn denies_unsafe_policy_paths_existing_outputs_and_overlapping_destinations() {
    for bad in [
        "../src",
        "/src",
        "src/../README.md",
        "src//x",
        "src/",
        "src\\x",
        "src\nprivate",
    ] {
        let fixture = Fixture::new();
        let mut request = fixture.request();
        request.include_roots = vec![bad.into()];
        fixture.refused(&request);
    }
    let fixture = Fixture::new();
    fs::create_dir(&fixture.out).unwrap();
    assert!(export(&fixture.request(), &fixture.out).is_err());
    assert_eq!(fs::read_dir(&fixture.out).unwrap().count(), 0);
    assert!(export(&fixture.request(), &fixture.repo.join("export")).is_err());
    assert!(export(&fixture.request(), fixture.repo.parent().unwrap()).is_err());
}

#[test]
fn private_binary_and_unknown_extension_content_never_publishes_or_echoes_values() {
    for (name, bytes) in [
        ("src/payload.rs", b"// binary\0PRIVATE".as_slice()),
        (
            "src/key.txt",
            b"-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n",
        ),
        (
            "src/auth.txt",
            format!(
                "Authorization: {} {}\n",
                "Bearer", "PRIVATE_TOKEN_0123456789"
            )
            .as_bytes(),
        ),
        ("src/payload.apk", b"ordinary text"),
        ("src/payload.unknown", b"ordinary text"),
        ("src/data.patch", b"GIT binary patch\nPRIVATE\n"),
        ("src/nonutf8.rs", b"\xffPRIVATE"),
    ] {
        let fixture = Fixture::new();
        fixture.put(name, bytes);
        fixture.commit();
        assert!(!fixture.refused(&fixture.request()).contains("PRIVATE"));
    }
    for path in [
        "src/keys/example.txt",
        "src/private-fixtures/test.rs",
        "src/artifacts/report.json",
        "src/logs/trace.txt",
    ] {
        let fixture = Fixture::new();
        fixture.put(path, b"ordinary text");
        fixture.commit();
        fixture.refused(&fixture.request());
    }
}

#[test]
fn explicit_exclusions_allow_known_private_subtrees_and_private_literals_stay_private() {
    let fixture = Fixture::new();
    fixture.put("src/private-fixtures/fixture.rs", b"PRIVATE\n");
    fixture.commit();
    let mut request = fixture.request();
    request.exclude_paths = vec!["src/private-fixtures".into()];
    export(&request, &fixture.out).unwrap();
    assert!(!fixture.out.join("src/private-fixtures").exists());
    let fixture = Fixture::new();
    let secret = "TEST_ONLY_PIN_123456";
    fixture.put("src/secret.rs", format!("// {secret}\n").as_bytes());
    fixture.commit();
    let deny = fixture._dir.path().join("private-deny-literals");
    fs::write(&deny, format!("{secret}\n")).unwrap();
    let mut request = fixture.request();
    request.deny_literals_file = Some(deny);
    let error = export(&request, &fixture.out).unwrap_err().to_string();
    assert!(!error.contains(secret));
    assert!(!error.contains("private-deny-literals"));
    assert!(!fixture.out.exists());
    assert_eq!(fs::read_dir(fixture._dir.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn tracked_symlinks_parent_symlinks_and_dangling_output_links_refused() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    symlink("../README.md", fixture.repo.join("src/link.rs")).unwrap();
    fixture.commit();
    fixture.refused(&fixture.request());
    let fixture = Fixture::new();
    fs::rename(fixture.repo.join("src"), fixture.repo.join("original-src")).unwrap();
    symlink("original-src", fixture.repo.join("src")).unwrap();
    fixture.refused(&fixture.request());
    let fixture = Fixture::new();
    symlink("missing", &fixture.out).unwrap();
    assert!(export(&fixture.request(), &fixture.out).is_err());
    assert!(
        fs::symlink_metadata(&fixture.out)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn executable_mode_normalizes_and_special_worktree_bits_do_not_leak() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.put("src/run.sh", b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(
        fixture.repo.join("src/run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fixture.commit();
    fs::set_permissions(
        fixture.repo.join("src/run.sh"),
        fs::Permissions::from_mode(0o6755),
    )
    .unwrap();
    let result = export(&fixture.request(), &fixture.out).unwrap();
    assert_eq!(
        result
            .files
            .iter()
            .find(|e| e.path == "src/run.sh")
            .unwrap()
            .mode,
        0o755
    );
    assert_eq!(
        fs::metadata(fixture.out.join("src/run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(fixture.out.join(LEDGER))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        fs::metadata(fixture.out.join("src"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    let fixture = Fixture::new();
    fs::set_permissions(
        fixture.repo.join("src/main.rs"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fixture.refused(&fixture.request());
}

#[test]
fn bounded_reader_and_policy_count_refuse_without_large_allocations() {
    let fixture = Fixture::new();
    fixture.put("bounded.txt", b"12345");
    assert!(read_text(&fixture.repo.join("bounded.txt"), 4).is_err());
    assert_eq!(
        read_text(&fixture.repo.join("bounded.txt"), 5).unwrap(),
        b"12345"
    );
    let mut request = fixture.request();
    request.exclude_paths = vec!["x".into(); MAX_FILES];
    fixture.refused(&request);
}

#[test]
fn request_unknown_fields_missing_selection_and_untracked_explicit_files_refused() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.include_roots.clear();
    request.include_files.clear();
    fixture.refused(&request);
    let mut request = fixture.request();
    request.include_files.push("untracked.rs".into());
    fixture.put("untracked.rs", b"// private untracked\n");
    fixture.refused(&request);
    let mut value = serde_json::to_value(fixture.request()).unwrap();
    value["send_private"] = true.into();
    assert!(serde_json::from_value::<Request>(value).is_err());
}
