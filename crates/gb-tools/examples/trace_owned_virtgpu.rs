//! Launch one SHA-256-pinned owned probe and observe two virtgpu ioctl structs.
//! Never attaches to an existing process or records exec arguments, registers,
//! memory contents, syscall paths or unrelated ioctls. Linux 5.3+, 64-bit LE.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::{fs::OpenOptionsExt, io::AsRawFd, process::CommandExt},
    path::Path,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

const GET_SYSCALL_INFO: u32 = 0x420e;
const GETPARAM: u64 = 0xc0106443;
const CREATE_BLOB: u64 = 0xc030644a;
const LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Fields {
    Getparam {
        param: u64,
        value: Option<u64>,
    },
    CreateBlob {
        blob_mem: u32,
        blob_flags: u32,
        size: u64,
        blob_id: u64,
        bo_handle: Option<u32>,
        resource_handle: Option<u32>,
    },
}

#[derive(Debug, Serialize)]
struct Event {
    fd: i32,
    ioctl_return: i64,
    #[serde(flatten)]
    fields: Fields,
}

struct Pending {
    fd: i32,
    address: usize,
    value_address: usize,
    fields: Fields,
}

fn u32_at(b: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        b[offset..offset + 4]
            .try_into()
            .expect("fixed internal buffer"),
    )
}
fn u64_at(b: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        b[offset..offset + 8]
            .try_into()
            .expect("fixed internal buffer"),
    )
}

fn trace(request: impl Into<i64>, pid: i32, address: usize, data: usize) -> Result<i64> {
    let request = request.into();
    // All requests operate only on the child launched below. No user-supplied PID.
    let ret = unsafe {
        libc::ptrace(
            request as _,
            pid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    ensure!(
        ret != -1,
        "ptrace {request:#x}: {}",
        std::io::Error::last_os_error()
    );
    Ok(ret)
}

fn read_owned<const N: usize>(pid: i32, address: usize) -> Result<[u8; N]> {
    ensure!(address != 0 && N <= 48, "invalid owned ioctl read budget");
    let mut bytes = [0; N];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: N,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: N,
    };
    let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    ensure!(
        read == N as isize,
        "owned ioctl struct read failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(bytes)
}

fn entry(pid: i32, args: &[u64; 6]) -> Result<Option<Pending>> {
    if !matches!(args[1], GETPARAM | CREATE_BLOB) {
        return Ok(None);
    }
    // ioctl's fd argument is a signed 32-bit int, even in the 64-bit ABI.
    let fd = args[0] as u32 as i32;
    let address = usize::try_from(args[2])?;
    let (fields, value_address) = match args[1] {
        GETPARAM => {
            let b = read_owned::<16>(pid, address)?;
            (
                Fields::Getparam {
                    param: u64_at(&b, 0),
                    value: None,
                },
                usize::try_from(u64_at(&b, 8))?,
            )
        }
        CREATE_BLOB => {
            let b = read_owned::<48>(pid, address)?;
            (
                Fields::CreateBlob {
                    blob_mem: u32_at(&b, 0),
                    blob_flags: u32_at(&b, 4),
                    size: u64_at(&b, 16),
                    blob_id: u64_at(&b, 40),
                    bo_handle: None,
                    resource_handle: None,
                },
                0,
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(Pending {
        fd,
        address,
        value_address,
        fields,
    }))
}

fn exit(pid: i32, mut p: Pending, result: i64) -> Result<Event> {
    if result == 0 {
        match &mut p.fields {
            Fields::Getparam { value, .. } => {
                *value = Some(u64_at(&read_owned::<8>(pid, p.value_address)?, 0))
            }
            Fields::CreateBlob {
                bo_handle,
                resource_handle,
                ..
            } => {
                let b = read_owned::<48>(pid, p.address)?;
                *bo_handle = Some(u32_at(&b, 8));
                *resource_handle = Some(u32_at(&b, 12));
            }
        }
    }
    Ok(Event {
        fd: p.fd,
        ioctl_return: result,
        fields: p.fields,
    })
}

struct OwnedChild(Child, bool);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.1 {
            let pid = self.0.id() as i32;
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = trace(libc::PTRACE_CONT, pid, 0, 0);
            let end = Instant::now() + Duration::from_secs(1);
            while Instant::now() < end {
                let mut status = 0;
                let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if got == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                    break;
                }
                if got < 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    program_sha256: String,
    scope: &'static str,
    guest_auth_argv_collected: bool,
    child_exit_code: Option<i32>,
    child_signal: Option<i32>,
    events: Vec<Event>,
}

fn run(input: &Path, expected: &str) -> Result<Report> {
    ensure!(
        cfg!(all(
            target_os = "linux",
            target_endian = "little",
            target_pointer_width = "64"
        )),
        "requires Linux 64-bit little endian"
    );
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase SHA-256 required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(input)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= LIMIT,
        "owned probe must be a bounded regular ELF"
    );
    let mut bytes = Vec::new();
    (&mut file).take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT && gb_core::digest(&bytes) == expected,
        "owned probe SHA-256 mismatch"
    );
    ensure!(
        bytes.get(..6) == Some(b"\x7fELF\x02\x01"),
        "requires a 64-bit LE ELF probe"
    );
    let mut cmd = Command::new(format!("/proc/self/fd/{}", file.as_raw_fd()));
    cmd.arg("--venus").process_group(0);
    unsafe {
        cmd.pre_exec(|| {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(cmd.spawn().context("launch owned probe")?, false);
    let pid = i32::try_from(child.0.id())?;
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut configured = false;
    let mut pending = None;
    let mut report = Report {
        schema_version: 1,
        program_sha256: expected.into(),
        scope: "Only GETPARAM and CREATE_BLOB metadata from the launched owned probe's main thread; no existing-process attach",
        guest_auth_argv_collected: false,
        child_exit_code: None,
        child_signal: None,
        events: Vec::new(),
    };
    loop {
        ensure!(
            Instant::now() < deadline,
            "owned probe trace exceeded 25 seconds"
        );
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == 0 {
            thread::sleep(Duration::from_millis(1));
            continue;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            child.1 = true;
            report.child_exit_code = libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status));
            report.child_signal = libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status));
            break;
        }
        ensure!(
            libc::WIFSTOPPED(status),
            "unexpected owned-child wait status"
        );
        if !configured {
            ensure!(
                libc::WSTOPSIG(status) == libc::SIGTRAP,
                "expected owned exec stop"
            );
            trace(
                libc::PTRACE_SETOPTIONS,
                pid,
                0,
                (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL) as usize,
            )?;
            configured = true;
        } else if libc::WSTOPSIG(status) == (libc::SIGTRAP | 0x80) {
            let mut info = [0_u8; 128];
            let length = trace(
                GET_SYSCALL_INFO,
                pid,
                info.len(),
                info.as_mut_ptr() as usize,
            )?;
            ensure!(length >= 24, "short PTRACE_GET_SYSCALL_INFO response");
            match info[0] {
                1 => {
                    ensure!(length >= 80, "short syscall entry");
                    pending = None;
                    if u64_at(&info, 24) == libc::SYS_ioctl as u64 {
                        let args = std::array::from_fn(|i| u64_at(&info, 32 + i * 8));
                        pending = entry(pid, &args)?;
                    }
                }
                2 => {
                    ensure!(length >= 33, "short syscall exit");
                    if let Some(p) = pending.take() {
                        ensure!(
                            report.events.len() < 1024,
                            "owned ioctl event budget exceeded"
                        );
                        report.events.push(exit(pid, p, u64_at(&info, 24) as i64)?);
                    }
                }
                _ => anyhow::bail!("unsupported syscall stop kind"),
            }
        } else {
            let signal = libc::WSTOPSIG(status);
            trace(libc::PTRACE_SYSCALL, pid, 0, signal as usize)?;
            continue;
        }
        trace(libc::PTRACE_SYSCALL, pid, 0, 0)?;
    }
    Ok(report)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 3,
        "expected OWNED_PROBE SHA256 NEW_REPORT_JSON"
    );
    // Reserve output before starting; never overwrite a previous report.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args[2])?;
    let result = run(
        Path::new(&args[0]),
        args[1].to_str().context("SHA-256 must be UTF-8")?,
    );
    match result {
        Ok(report) => serde_json::to_writer_pretty(&mut output, &report)?,
        Err(error) => {
            serde_json::to_writer_pretty(
                &mut output,
                &serde_json::json!({"schema_version":1,"status":"trace_failed","error":error.to_string(),"runtime_verified":false}),
            )?;
            output.sync_all()?;
            return Err(error);
        }
    }
    output.sync_all()?;
    Ok(())
}
