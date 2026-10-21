// SPDX-License-Identifier: GPL-2.0-or-later
// Owner diagnostic coordination only. No memory, firmware or privileged operations.
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::time::{Duration, Instant};

fn read_token(dir: &File, name: &'static [u8], uid: u32) -> io::Result<String> {
    // SAFETY: name is a static NUL-terminated single component; dir remains open.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr().cast(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != uid
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() != 65
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid owned gate token file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(66).read_to_end(&mut bytes)?;
    if bytes.len() != 65 || bytes[64] != b'\n' || !bytes[..64].iter().all(|c| c.is_ascii_hexdigit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid gate token encoding",
        ));
    }
    // All token bytes were checked as ASCII above.
    String::from_utf8(bytes[..64].to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Optional request: absent means ordinary preparation. A present request must
/// get a matching release before deadline, or the caller must refuse VM startup.
/// The directory fd anchors both reads, avoiding path replacement races.
pub fn coordinate<F>(path: &Path, uid: u32, timeout: Duration, ready: F) -> io::Result<bool>
where
    F: FnOnce(&str),
{
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = dir.metadata()?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid owned gate directory",
        ));
    }
    let token = match read_token(&dir, b"prepin.request\0", uid) {
        Ok(token) => token,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match read_token(&dir, b"prepin.resume\0", uid) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "preexisting gate release",
            ));
        }
    }
    ready(&token);
    let started = Instant::now();
    loop {
        match read_token(&dir, b"prepin.resume\0", uid) {
            Ok(release) if release == token => return Ok(true),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stale gate release",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if started.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pre-pin coordination deadline",
            ));
        }
        std::thread::sleep(
            Duration::from_millis(25).min(timeout.saturating_sub(started.elapsed())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn token(path: &Path, value: &str) {
        std::fs::write(path, format!("{value}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn setup() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn optional_request_and_matching_release_are_distinct() {
        let d = setup();
        let uid = d.path().metadata().unwrap().uid();
        assert!(
            !coordinate(d.path(), uid, Duration::ZERO, |_| panic!(
                "absent request announced"
            ))
            .unwrap()
        );
        let value = "a".repeat(64);
        token(&d.path().join("prepin.request"), &value);
        let p = d.path().join("prepin.resume");
        assert!(
            coordinate(d.path(), uid, Duration::from_secs(1), |s| {
                assert_eq!(s, value);
                token(&p, s);
            })
            .unwrap()
        );
    }
    #[test]
    fn stale_malformed_symlink_and_hardlink_files_refuse() {
        let d = setup();
        let uid = d.path().metadata().unwrap().uid();
        let request = d.path().join("prepin.request");
        let release = d.path().join("prepin.resume");
        token(&request, &"a".repeat(64));
        token(&release, &"b".repeat(64));
        assert!(coordinate(d.path(), uid, Duration::ZERO, |_| {}).is_err());
        std::fs::remove_file(&release).unwrap();
        assert_eq!(
            coordinate(d.path(), uid, Duration::ZERO, |_| {})
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        std::fs::hard_link(&request, &release).unwrap();
        assert!(
            coordinate(d.path(), uid, Duration::ZERO, |_| panic!(
                "hardlink accepted"
            ))
            .is_err()
        );
        std::fs::remove_file(&release).unwrap();
        std::fs::remove_file(&request).unwrap();
        token(&release, &"a".repeat(64));
        symlink(&release, &request).unwrap();
        assert!(
            coordinate(d.path(), uid, Duration::ZERO, |_| panic!(
                "symlink accepted"
            ))
            .is_err()
        );
        std::fs::remove_file(&request).unwrap();
        token(&request, "invalid");
        assert!(
            coordinate(d.path(), uid, Duration::ZERO, |_| panic!(
                "malformed token accepted"
            ))
            .is_err()
        );
    }
    #[test]
    fn directory_owner_mode_and_symlink_are_checked() {
        let d = setup();
        let uid = d.path().metadata().unwrap().uid();
        assert!(coordinate(d.path(), uid.wrapping_add(1), Duration::ZERO, |_| {}).is_err());
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(coordinate(d.path(), uid, Duration::ZERO, |_| {}).is_err());
        let link = d.path().join("linked");
        symlink(d.path(), &link).unwrap();
        assert!(coordinate(&link, uid, Duration::ZERO, |_| {}).is_err());
    }
}
