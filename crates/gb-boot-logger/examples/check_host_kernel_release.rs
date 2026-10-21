//! Exercises the actual VMM helper; no firmware, device or credential access.
#[path = "../../../patches/tb710fu/crosvm/host_kernel_release.rs"]
mod host_kernel_release;

fn main() -> std::io::Result<()> {
    println!("host_pre_6_6={}", host_kernel_release::pre_6_6()?);
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::host_kernel_release::{pre_6_6, release_pre_6_6};

    #[test]
    fn identifies_release_even_when_file_opening_is_forbidden() {
        for (release, expected) in [
            ("6.1.128-android14-11-g5c2cea985a84-ab13606743", true),
            ("5.15.200", true),
            ("6.5.99", true),
            ("6.6.0", false),
            ("6.12.50-android", false),
            ("7.0.0", false),
        ] {
            assert_eq!(release_pre_6_6(release).unwrap(), expected);
        }
        for release in ["", "6", "6.bad.1", "4294967296.1.0", "x.6.0"] {
            assert!(release_pre_6_6(release).is_err());
        }
        let expected = pre_6_6().unwrap();
        // A separate child avoids changing the test runner's syscall permissions.
        // It uses no Rust locks or output after fork and exits through _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut filter = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 3,
                    jf: 0,
                    k: libc::SYS_open as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 2,
                    jf: 0,
                    k: libc::SYS_openat as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 1,
                    jf: 0,
                    k: libc::SYS_openat2 as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
                },
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            // SAFETY: fixed valid prctl arguments and a live BPF buffer; child-only restrictions.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0
                {
                    libc::_exit(41);
                }
                let fd = libc::open(c"/proc/sys/kernel/osrelease".as_ptr(), libc::O_RDONLY);
                if fd >= 0 || *libc::__errno_location() != libc::EACCES {
                    libc::_exit(42);
                }
                match pre_6_6() {
                    Ok(actual) if actual == expected => libc::_exit(0),
                    _ => libc::_exit(43),
                }
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "file-open denial must not change host detection"
        );
    }
}
