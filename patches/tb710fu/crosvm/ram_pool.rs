// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit optional in-tree RAM supply. This is not a stock Gunyah ioctl.
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

const WINDOWS: [u64; 2] = [506 << 20, 2042 << 20];
#[cfg(test)]
const WINDOW_BYTES: u64 = WINDOWS[1];
const MAX_PAGES: u32 = 1024; // pool2GiB maximum, units of2MiB
const CONTROL: libc::c_ulong = 0xc0204717;
const PIN_WINDOW: libc::c_ulong = 0xc0204718;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Request {
    vm_fd: i32,
    flags: u32,
    memory_size: u64,
    available_2m: u32,
    served_2m: u32,
    held_2m: u32,
    reserved: u32,
}
const _: [(); 32] = [(); std::mem::size_of::<Request>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PinRequest {
    vm_fd: i32,
    flags: u32,
    memory_size: u64,
    userspace_addr: u64,
    pinned_pages: u32,
    reserved: u32,
}
const _: [(); 32] = [(); std::mem::size_of::<PinRequest>()];

fn pin_scope(fd: i32, addr: u64, bytes: u64) -> bool {
    fd >= 0 && addr != 0 && addr & 4095 == 0 && WINDOWS.contains(&bytes)
        && addr.checked_add(bytes).is_some()
}

fn pin_receipt(r: &PinRequest, fd: i32, addr: u64, bytes: u64) -> io::Result<()> {
    if !pin_scope(fd, addr, bytes) || r.vm_fd != fd || r.flags != 0
        || r.memory_size != bytes || r.userspace_addr != addr || r.reserved != 0
        || r.pinned_pages as u64 != bytes >> 12 {
        return Err(invalid());
    }
    Ok(())
}

/// Kernel retains the writable FOLL_LONGTERM pin until the real VM's normal
/// teardown, including on copy/firmware failure. No unpin ioctl or new syscall
/// permission is needed in the original app's inherited seccomp sandbox.
pub fn pin_window(vm_fd: i32, addr: u64, bytes: u64) -> io::Result<()> {
    if !pin_scope(vm_fd, addr, bytes) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "RAM-window scope"));
    }
    let file = File::open("/dev/gunyah_share")?;
    let mut r = PinRequest { vm_fd, memory_size: bytes, userspace_addr: addr,
        ..PinRequest::default() };
    // SAFETY: r is the exact32byte in/out ABI; file is an owned live fd.
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), PIN_WINDOW as _, &mut r) };
    if ret < 0 { return Err(io::Error::last_os_error()); }
    if ret != 0 { return Err(invalid()); }
    pin_receipt(&r, vm_fd, addr, bytes)
}

#[derive(Debug)]
pub struct Stats {
    pub available_2m: u32,
    pub served_2m: u32,
    pub held_2m: u32,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid RAM-pool receipt")
}

fn receipt(r: &Request, fd: i32, bytes: u64, query: bool) -> io::Result<Stats> {
    if r.vm_fd != fd
        || r.flags != u32::from(query)
        || !WINDOWS.contains(&bytes)
        || r.memory_size != bytes
        || r.reserved != 0
        || r.held_2m > MAX_PAGES
        || r.available_2m > r.held_2m
        || r.served_2m > r.held_2m
        || r.available_2m + r.served_2m > r.held_2m
        || (!query && r.available_2m < (bytes >> 21) as u32)
    {
        return Err(invalid());
    }
    Ok(Stats {
        available_2m: r.available_2m,
        served_2m: r.served_2m,
        held_2m: r.held_2m,
    })
}

pub fn control(vm_fd: i32, bytes: u64, query: bool) -> io::Result<Stats> {
    if vm_fd < 0 || !WINDOWS.contains(&bytes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RAM-pool scope",
        ));
    }
    let file = File::open("/dev/gunyah_share")?;
    let mut r = Request {
        vm_fd,
        memory_size: bytes,
        flags: u32::from(query),
        ..Request::default()
    };
    // SAFETY: r is the exact32byte in/out ABI; file is an owned live fd.
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), CONTROL as _, &mut r) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret != 0 {
        return Err(invalid());
    }
    receipt(&r, vm_fd, bytes, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_scope_and_receipt_are_exact() {
        for bytes in WINDOWS {
            let r = PinRequest { vm_fd: 11, memory_size: bytes, userspace_addr: 0x10000000,
                pinned_pages: (bytes >> 12) as u32, ..PinRequest::default() };
            assert!(pin_receipt(&r, 11, r.userspace_addr, bytes).is_ok());
            for field in 0..6 {
                let mut bad = r;
                match field {
                    0 => bad.vm_fd += 1, 1 => bad.flags = 1,
                    2 => bad.memory_size -= 4096, 3 => bad.userspace_addr += 4096,
                    4 => bad.pinned_pages -= 1, _ => bad.reserved = 1,
                }
                assert!(pin_receipt(&bad, 11, r.userspace_addr, bytes).is_err());
            }
        }
        for (fd, addr, bytes) in [(-1, 4096, WINDOWS[0]), (11, 0, WINDOWS[0]),
            (11, 4097, WINDOWS[0]), (11, u64::MAX - 4095, WINDOWS[0]),
            (11, 4096, WINDOWS[0] - 4096)] {
            assert_eq!(pin_window(fd, addr, bytes).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn rejects_mutated_inputs_and_impossible_pool_counts() {
        let valid = Request {
            vm_fd: 11,
            memory_size: WINDOW_BYTES,
            available_2m: 1024,
            held_2m: 1024,
            ..Request::default()
        };
        assert!(receipt(&valid, 11, WINDOW_BYTES, false).is_ok());
        for field in 0..8 {
            let mut bad = valid;
            match field {
                0 => bad.vm_fd = 12,
                1 => bad.flags = 1,
                2 => bad.memory_size -= 4096,
                3 => bad.reserved = 1,
                4 => bad.held_2m = MAX_PAGES + 1,
                5 => bad.available_2m = 1020,
                6 => bad.served_2m = 1,
                _ => bad.available_2m = u32::MAX,
            }
            assert!(receipt(&bad, 11, WINDOW_BYTES, false).is_err());
        }
        let query = Request {
            flags: 1,
            available_2m: 3,
            served_2m: 1021,
            ..valid
        };
        let s = receipt(&query, 11, WINDOW_BYTES, true).unwrap();
        assert_eq!((s.available_2m, s.served_2m, s.held_2m), (3, 1021, 1024));
        let small = Request {
            memory_size: WINDOWS[0],
            available_2m: 771,
            served_2m: 253,
            ..query
        };
        assert!(receipt(&small, 11, WINDOWS[0], true).is_ok());
        assert!(receipt(&small, 11, WINDOWS[1], true).is_err());
        let small_bind = Request {
            flags: 0,
            served_2m: 0,
            ..small
        };
        assert!(receipt(&small_bind, 11, WINDOWS[0], false).is_ok());
    }

    #[test]
    fn bad_scope_never_opens_a_device() {
        assert_eq!(
            control(-1, WINDOW_BYTES, false).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            control(11, WINDOW_BYTES - 4096, false).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
