//! A private /dev/kmsg cursor, supplied read-only by Android init's `file` option.
//! Unlike READ_ALL snapshots, records have sequence numbers and are read once.
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    os::fd::{AsRawFd, FromRawFd},
};

pub struct Stream(File);

impl Stream {
    pub fn from_init() -> io::Result<Self> {
        let raw = std::env::var("ANDROID_FILE__dev_kmsg")
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .filter(|&fd| fd >= 3)
            .ok_or_else(|| io::Error::other("init did not supply read-only /dev/kmsg"))?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        validate_descriptor(stat.st_mode, stat.st_rdev, flags)?;
        // Take a duplicate, then prevent the original or duplicate from leaking
        // into the retained logcat child. No global device mode/capability change.
        let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(duplicate) };
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
            || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // Only this reader advances: this does not clear the kernel ring or
        // affect logd/dmesg. Capture runtime events rather than replaying boot.
        file.seek(SeekFrom::End(0))?;
        Ok(Self(file))
    }

    pub fn drain(&mut self) -> io::Result<Vec<u8>> {
        drain(&mut self.0)
    }
}

fn drain(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 16384];
    // Bound each turn even if writers continuously fill the ring or a signal
    // storm interrupts reads. The outer collector owns deadline/total budgets.
    for _ in 0..8 {
        if output.len() >= 64 * 1024 {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => output.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => {
                output.extend_from_slice(b"\n[kernel stream overrun: records lost]\n");
            }
            Err(e) => return Err(e),
        }
    }
    Ok(output)
}

fn validate_descriptor(mode: libc::mode_t, device: libc::dev_t, flags: i32) -> io::Result<()> {
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || mode & libc::S_IFMT != libc::S_IFCHR
        || libc::major(device) != 1
        || libc::minor(device) != 11
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "init descriptor is not a read-only kernel message device",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_writable_descriptors_regular_files_and_other_devices() {
        let device = libc::makedev(1, 11);
        assert!(validate_descriptor(libc::S_IFCHR, device, libc::O_RDONLY).is_ok());
        for flags in [libc::O_WRONLY, libc::O_RDWR, -1] {
            assert!(validate_descriptor(libc::S_IFCHR, device, flags).is_err());
        }
        assert!(validate_descriptor(libc::S_IFREG, device, libc::O_RDONLY).is_err());
        assert!(validate_descriptor(libc::S_IFCHR, libc::makedev(1, 3), libc::O_RDONLY).is_err());
    }

    #[test]
    fn records_overrun_and_keeps_reading_without_replaying_history() {
        struct Reader(usize);
        impl Read for Reader {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                match self.0 {
                    1 => Err(io::Error::from_raw_os_error(libc::EINTR)),
                    2 => Err(io::Error::from_raw_os_error(libc::EPIPE)),
                    3 => {
                        let record = b"3,42,1000,-;new kernel failure\n";
                        out[..record.len()].copy_from_slice(record);
                        Ok(record.len())
                    }
                    _ => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }
        let mut reader = Reader(0);
        let output = drain(&mut reader).unwrap();
        assert!(output.starts_with(b"\n[kernel stream overrun: records lost]\n"));
        assert!(output.ends_with(b"3,42,1000,-;new kernel failure\n"));
        assert!(drain(&mut reader).unwrap().is_empty());
    }

    #[test]
    fn continuous_kernel_storm_yields_within_per_turn_budget() {
        struct Storm(usize);
        impl Read for Storm {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                out.fill(b'x');
                Ok(out.len())
            }
        }
        let mut reader = Storm(0);
        assert_eq!(drain(&mut reader).unwrap().len(), 64 * 1024);
        assert_eq!(reader.0, 4);
    }
}
