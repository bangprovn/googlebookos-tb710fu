//! Bounded head/tail excerpts from completed host-tool logs.
//! An excerpt preserves diagnostics, not proof that an omitted event never occurred.
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub const MAX_RETAINED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Excerpt {
    pub source_bytes: u64,
    pub retained_source_bytes: usize,
    pub omitted_source_bytes: u64,
    pub truncated: bool,
    pub lossy_utf8: bool,
    pub text: String,
}

/// Read at most `limit` source bytes, splitting retention between head and tail
/// for larger logs. Refuse nonregular files and observable concurrent writes.
/// UTF-8 replacement and the omission marker can enlarge the returned string
/// beyond `limit`, but memory remains bounded independently of source size.
pub fn capture(path: &Path, limit: usize) -> Result<Excerpt> {
    ensure!(
        (2..=MAX_RETAINED_BYTES).contains(&limit),
        "log retention must be between 2 bytes and 8 MiB"
    );
    crate::checkpoint()?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "tool log must be a regular file");
    let source_bytes = before.len();
    let retained = source_bytes.min(limit as u64) as usize;
    let truncated = source_bytes > limit as u64;
    let head_bytes = if truncated { limit / 2 } else { retained };
    let mut head = vec![0; head_bytes];
    file.read_exact(&mut head)?;
    let mut tail = Vec::new();
    if truncated {
        crate::checkpoint()?;
        let tail_bytes = limit - head_bytes;
        file.seek(SeekFrom::End(-(tail_bytes as i64)))?;
        tail.resize(tail_bytes, 0);
        file.read_exact(&mut tail)?;
    }
    let after = file.metadata()?;
    ensure!(
        after.len() == source_bytes && before.modified()? == after.modified()?,
        "tool log changed while capturing; wait for its writer to finish"
    );
    crate::checkpoint()?;
    let lossy_utf8 = std::str::from_utf8(&head).is_err() || std::str::from_utf8(&tail).is_err();
    let omitted_source_bytes = source_bytes - retained as u64;
    let mut text = String::from_utf8_lossy(&head).into_owned();
    if truncated {
        text.push_str(&format!(
            "\n[... {omitted_source_bytes} source bytes omitted ...]\n"
        ));
        text.push_str(&String::from_utf8_lossy(&tail));
    }
    Ok(Excerpt {
        source_bytes,
        retained_source_bytes: retained,
        omitted_source_bytes,
        truncated,
        lossy_utf8,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn small_complete_log_retains_errors_and_acknowledgments() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"warning\nACK\n").unwrap();
        let result = capture(file.path(), 128).unwrap();
        assert!(!result.truncated && !result.lossy_utf8);
        assert_eq!(result.omitted_source_bytes, 0);
        assert_eq!(result.text, "warning\nACK\n");
    }

    #[test]
    fn large_sparse_log_keeps_head_and_tail_with_explicit_omission() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(64 * 1024 * 1024).unwrap();
        file.write_all(b"storage identity\n").unwrap();
        file.seek(SeekFrom::Start(1024)).unwrap();
        file.write_all(b"middle diagnostic").unwrap();
        file.seek(SeekFrom::End(-14)).unwrap();
        file.write_all(b"write complete").unwrap();
        let result = capture(file.path(), 512).unwrap();
        assert!(result.truncated);
        assert_eq!(result.retained_source_bytes, 512);
        assert_eq!(result.omitted_source_bytes, 64 * 1024 * 1024 - 512);
        assert!(result.text.starts_with("storage identity\n"));
        assert!(result.text.ends_with("write complete"));
        assert!(!result.text.contains("middle diagnostic"));
        assert!(result.text.len() < 1024);
    }

    #[test]
    fn invalid_utf8_is_explicit_and_limits_are_enforced() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0xff, b'a']).unwrap();
        assert!(capture(file.path(), 2).unwrap().lossy_utf8);
        for limit in [0, 1, MAX_RETAINED_BYTES + 1] {
            assert!(capture(file.path(), limit).is_err());
        }
        let directory = tempfile::tempdir().unwrap();
        assert!(capture(directory.path(), 128).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_logs_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let link = directory.path().join("link");
        std::fs::write(&source, b"ACK").unwrap();
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(capture(&link, 128).is_err());
    }
}
