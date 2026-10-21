//! Bounded diagnostic for an owned staging file, not a global cache flush.
//! FILE EXPECTED_BYTES. Never changes file bytes; a successful hint may be ignored.
use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
fn advise(path: &Path, expected: u64) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments or memory effects.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.len() != expected
        || expected == 0
        || expected > 8 * 1024 * 1024 * 1024
    {
        return Err(io::Error::other(
            "expected one owned regular staging file with pinned length",
        ));
    }
    file.sync_all()?;
    // SAFETY: the descriptor remains live and the zero offset/length selects
    // the entire opened regular file. This is advisory and changes no bytes.
    let result = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err(io::Error::other("expected FILE EXPECTED_BYTES"));
    }
    let bytes = args[1]
        .to_str()
        .ok_or_else(|| io::Error::other("size encoding"))?
        .parse::<u64>()
        .map_err(|_| io::Error::other("invalid size"))?;
    advise(Path::new(&args[0]), bytes)?;
    println!(
        "{{\"schema_version\":1,\"status\":\"owned_file_cache_hint_submitted\",\"file_bytes\":{bytes},\"contents_changed\":false,\"cache_eviction_verified\":false}}"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_bytes_and_rejects_symlinks_links_and_wrong_size() -> io::Result<()> {
        let d = tempfile::tempdir()?;
        let f = d.path().join("guest");
        std::fs::write(&f, b"owned fixture")?;
        advise(&f, 13)?;
        assert_eq!(std::fs::read(&f)?, b"owned fixture");
        assert!(advise(&f, 12).is_err());
        let link = d.path().join("symlink");
        std::os::unix::fs::symlink(&f, &link)?;
        assert!(advise(&link, 13).is_err());
        use std::os::unix::ffi::OsStrExt;
        let fifo = d.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes())?;
        // SAFETY: name is a live NUL-terminated path in the private test directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(advise(&fifo, 13).is_err());
        std::fs::hard_link(&f, d.path().join("hardlink"))?;
        assert!(advise(&f, 13).is_err());
        Ok(())
    }
}
