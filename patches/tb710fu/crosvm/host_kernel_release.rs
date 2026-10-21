//! Kernel release detection without depending on procfs visibility or permissions.
use std::{ffi::CStr, io, mem::MaybeUninit};

pub(crate) fn release_pre_6_6(release: &str) -> io::Result<bool> {
    let mut fields = release.trim().split('.');
    let major = fields.next().and_then(|v| v.parse::<u32>().ok());
    let minor = fields.next().and_then(|v| v.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => Ok((major, minor) < (6, 6)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid kernel release",
        )),
    }
}

pub(crate) fn pre_6_6() -> io::Result<bool> {
    let mut name = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname receives a valid, writable buffer of the platform's utsname type.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful uname initializes the structure and NUL-terminates release.
    let name = unsafe { name.assume_init() };
    let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
    release_pre_6_6(
        release
            .to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 kernel release"))?,
    )
}
