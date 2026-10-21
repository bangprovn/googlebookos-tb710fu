//! Temporary first-stage diagnostic wrapper; executes the exact retained init.
//! The collector never mounts/formats a partition or changes SELinux policy.
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod kernel;
mod kmsg;
mod snapshot;

const CAPTURE_LIMIT: usize = 1024 * 1024;
const ORIGINAL_INIT: &str = "/init.gb-original";

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaptureMode {
    FirstStage,
    BootService,
    VmService,
}
impl CaptureMode {
    fn filename(self) -> &'static str {
        match self {
            Self::FirstStage => "first-stage.log",
            Self::BootService => "second-stage.log",
            Self::VmService => "vm-runtime.log",
        }
    }
}
// The first hardware capture ended immediately after metadata mounted. A
// 500 ms interval can miss the entire subsequent mount/policy transition.
// Poll quickly during that bounded window, then reduce the syscall rate.
fn capture_interval(elapsed: Duration) -> Duration {
    if elapsed < Duration::from_secs(5) {
        Duration::from_millis(10)
    } else {
        Duration::from_millis(100)
    }
}
fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}
fn fd(result: i32) -> io::Result<File> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(result) })
    }
}

/// Uses directory FDs and exclusive, no-follow creation. Replacing the owned log
/// cannot truncate an existing symlink/hardlink target such as an encryption key.
struct Sink {
    directory: File,
    file: File,
    temporary: CString,
    published: bool,
    remaining: usize,
    final_name: CString,
}
impl Sink {
    #[cfg(test)]
    fn new(parent: &OsStr) -> io::Result<Self> {
        let parent =
            CString::new(parent.as_bytes()).map_err(|_| io::Error::other("NUL in directory"))?;
        let parent = fd(unsafe {
            libc::open(
                parent.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        })?;
        Self::from_directory(parent)
    }
    fn from_directory(parent: File) -> io::Result<Self> {
        Self::from_named_directory(parent, "first-stage.log", CAPTURE_LIMIT)
    }
    fn from_named_directory(parent: File, name: &str, limit: usize) -> io::Result<Self> {
        if name.is_empty()
            || name.contains('/')
            || name == "."
            || name == ".."
            || limit == 0
            || limit > 4 * CAPTURE_LIMIT
        {
            return Err(io::Error::other("invalid diagnostic sink"));
        }
        let final_name = cstr(name)?;
        let directory_name = cstr("gb-port")?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), directory_name.as_ptr(), 0o700) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
        {
            return Err(io::Error::last_os_error());
        }
        let directory = fd(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                directory_name.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        })?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(directory.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.st_uid != unsafe { libc::getuid() } || stat.st_mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "diagnostic directory ownership/mode mismatch",
            ));
        }
        let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut space) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if (space.f_bavail as u128) * (space.f_frsize as u128) < (limit * 2 + 65536) as u128 {
            return Err(io::Error::other("insufficient diagnostic filesystem space"));
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for attempt in 0..256 {
            let temporary = cstr(&format!(".first-stage-{timestamp}-{}-{attempt}", unsafe {
                libc::getpid()
            }))?;
            let opened = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if opened >= 0 {
                return Ok(Self {
                    directory,
                    file: fd(opened)?,
                    temporary,
                    published: false,
                    remaining: limit,
                    final_name,
                });
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(io::Error::last_os_error());
            }
        }
        Err(io::Error::other("diagnostic staging names exhausted"))
    }
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let n = data.len().min(self.remaining);
        if n == 0 {
            return Ok(());
        }
        self.file.write_all(&data[..n])?;
        self.remaining -= n;
        self.file.sync_all()?;
        if !self.published {
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    self.temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    self.final_name.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.directory.sync_all()?;
            self.published = true;
        }
        Ok(())
    }
    fn append_capped(&mut self, data: &[u8], budget: &mut usize) -> io::Result<()> {
        let count = data.len().min(*budget).min(self.remaining);
        self.append(&data[..count])?;
        *budget -= count;
        Ok(())
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        if !self.published {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), self.temporary.as_ptr(), 0);
            }
        }
    }
}

fn filesystem_type(file: &File) -> io::Result<u64> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_type as u64)
}
fn metadata_directory(proc_directory: &File) -> io::Result<File> {
    // Follow the trusted original PID 1's current root, not the child's old
    // ramdisk root after switch_root. The held proc FD remains valid when moved.
    let name = cstr("1/root/metadata")?;
    let directory = fd(unsafe {
        libc::openat(
            proc_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })?;
    if filesystem_type(&directory)? != 0xf2f52010 {
        return Err(io::Error::other(
            "metadata is not a mounted F2FS filesystem",
        ));
    }
    Ok(directory)
}
fn current_metadata_directory() -> io::Result<File> {
    let name = cstr("/metadata")?;
    let directory = fd(unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    })?;
    if filesystem_type(&directory)? != 0xf2f52010 {
        return Err(io::Error::other("metadata is not mounted F2FS"));
    }
    Ok(directory)
}
fn collect(mode: CaptureMode) -> io::Result<()> {
    let service = mode != CaptureMode::FirstStage;
    // Default SIGALRM terminates only this child even if a filesystem call stalls.
    unsafe {
        libc::alarm(120);
    }
    let started = Instant::now();
    let proc_name = cstr("/proc")?;
    let proc_directory = if service {
        None
    } else {
        Some(loop {
            let opened = fd(unsafe {
                libc::open(
                    proc_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            });
            if let Ok(directory) = opened
                && filesystem_type(&directory)? == 0x9fa0
            {
                break directory;
            }
            if started.elapsed() > Duration::from_secs(115) {
                return Err(io::Error::other("proc mount not observed"));
            }
            std::thread::sleep(Duration::from_millis(1));
        })
    };
    let mut sink = loop {
        let directory = if let Some(proc_directory) = &proc_directory {
            metadata_directory(proc_directory)
        } else {
            current_metadata_directory()
        };
        if let Ok(directory) = directory {
            break if service {
                Sink::from_named_directory(directory, mode.filename(), 4 * CAPTURE_LIMIT)?
            } else {
                Sink::from_directory(directory)?
            };
        }
        if started.elapsed() > Duration::from_secs(115) {
            return Err(io::Error::other("metadata mount not observed"));
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    sink.append(if mode == CaptureMode::VmService {
        b"GB_VM_RUNTIME_DIAGNOSTICS_V2\nScope: on-demand read-only kernel record stream and bounded device logcat snapshots; no VM launch, property capability changes or device reset.\nKernel stream starts at current end; sequence numbers/timestamps retained; no ring clearing.\nKernel budget: 1 MiB; total: 4 MiB; deadline: 120 seconds; output: vm-runtime.log.\n"
    } else if service {
        b"GB_BOOT_DIAGNOSTICS_SERVICE_V2\nScope: incremental kernel and bounded device logcat snapshots; dedicated SELinux domain; enforcing retained.\nKernel budget: 1 MiB; remaining capture capacity reserved for logcat and control records.\n"
    } else {
        b"GB_BOOT_DIAGNOSTICS_V2\nScope: first-stage kernel/init logs; no SELinux or AVB changes.\nSampling: 10 ms for first 5 seconds, then 100 ms; unchanged snapshots do not write.\n"
    })?;
    let mut previous = Vec::new();
    let mut buffer = vec![0u8; 262144];
    let mut kernel_available = true;
    let mut stream = if mode == CaptureMode::VmService {
        match kmsg::Stream::from_init() {
            Ok(stream) => {
                sink.append(b"\n[kernel stream ready]\n")?;
                Some(stream)
            }
            Err(error) => {
                sink.append(format!("\n[kernel stream unavailable: {error}]\n").as_bytes())?;
                kernel_available = false;
                None
            }
        }
    } else {
        None
    };
    let mut kernel_budget = if service {
        CAPTURE_LIMIT
    } else {
        sink.remaining
    };
    let mut last_logcat: Option<Duration> = None;
    while started.elapsed() < Duration::from_secs(115) && sink.remaining > 0 {
        if let Some(stream) = stream
            .as_mut()
            .filter(|_| kernel_available && kernel_budget > 0)
        {
            match stream.drain() {
                Ok(records) => {
                    sink.append_capped(&records, &mut kernel_budget)?;
                    if kernel_budget == 0 {
                        sink.append(b"\n[kernel budget reached; logcat capture continues]\n")?;
                    }
                }
                Err(error) => {
                    sink.append(format!("\n[kernel stream stopped: {error}]\n").as_bytes())?;
                    kernel_available = false;
                }
            }
        }
        let n = if mode != CaptureMode::VmService && kernel_available && kernel_budget > 0 {
            unsafe { libc::klogctl(3, buffer.as_mut_ptr().cast(), buffer.len() as i32) }
        } else {
            0
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            sink.append(format!("\n[collector stopped: kernel log access: {error}]\n").as_bytes())?;
            if !service {
                return Ok(());
            }
            kernel_available = false;
        }
        if service
            && last_logcat.map_or_else(
                || started.elapsed() >= Duration::from_secs(1),
                |last| started.elapsed().saturating_sub(last) >= Duration::from_secs(5),
            )
        {
            last_logcat = Some(started.elapsed());
            let result = snapshot::run(
                std::process::Command::new("/system/bin/logcat").args([
                    "-b",
                    "all",
                    "-d",
                    "-t",
                    "500",
                    "-v",
                    "threadtime",
                ]),
                Duration::from_secs(2),
                128 * 1024,
            );
            match result {
                Ok(snapshot) => {
                    sink.append(
                        format!(
                            "\n[logcat snapshot at {:.3}s: exit={:?}, timeout={}, truncated={}]\n",
                            started.elapsed().as_secs_f64(),
                            snapshot.status,
                            snapshot.timed_out,
                            snapshot.truncated
                        )
                        .as_bytes(),
                    )?;
                    sink.append(&snapshot.bytes)?;
                }
                Err(error) => {
                    sink.append(format!("\n[logcat unavailable: {error}]\n").as_bytes())?
                }
            }
        }
        if mode == CaptureMode::VmService {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        if n < 0 || !kernel_available || kernel_budget == 0 {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let current = &buffer[..n as usize];
        let overlap = kernel::overlap(&previous, current);
        if overlap == 0 && !previous.is_empty() && !current.is_empty() {
            sink.append_capped(
                b"\n[kernel ring gap: overlap unavailable]\n",
                &mut kernel_budget,
            )?;
        }
        sink.append_capped(&current[overlap..], &mut kernel_budget)?;
        if kernel_budget == 0 && service {
            sink.append(b"\n[kernel budget reached; logcat capture continues]\n")?;
        }
        previous.clear();
        previous.extend_from_slice(current);
        std::thread::sleep(capture_interval(started.elapsed()));
    }
    sink.append(b"\n[collector deadline/output limit reached]\n")?;
    Ok(())
}
fn main() -> ExitCode {
    if std::env::args_os().nth(1).as_deref() == Some(OsStr::new("--describe")) {
        println!(
            "GB_BOOT_DIAGNOSTICS_V2: original_init={ORIGINAL_INIT}; output=/metadata/gb-port/first-stage.log; max_bytes={CAPTURE_LIMIT}; max_seconds=120; early_poll_ms=10; steady_poll_ms=100; policy_unchanged=true"
        );
        return ExitCode::SUCCESS;
    }
    let mode = match std::env::args_os().nth(1).as_deref() {
        Some(arg) if arg == OsStr::new("--service") => CaptureMode::BootService,
        Some(arg) if arg == OsStr::new("--vm-service") => CaptureMode::VmService,
        _ => CaptureMode::FirstStage,
    };
    if mode != CaptureMode::FirstStage {
        if !cfg!(target_arch = "aarch64") {
            eprintln!("Device diagnostic service requires the ARM64 build.");
            return ExitCode::FAILURE;
        }
        return match collect(mode) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Device diagnostic collection failed: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if unsafe { libc::getpid() } != 1 {
        eprintln!("This wrapper may only run as device PID 1; use --describe for inspection.");
        return ExitCode::FAILURE;
    }
    let arguments: io::Result<Vec<CString>> = std::env::args_os()
        .map(|a| CString::new(a.as_bytes()).map_err(|_| io::Error::other("invalid init argument")))
        .collect();
    let arguments = match arguments {
        Ok(a) => a,
        Err(_) => return ExitCode::FAILURE,
    };
    let original = match cstr(ORIGINAL_INIT) {
        Ok(p) => p,
        Err(_) => return ExitCode::FAILURE,
    };
    // Do not alter mount namespaces, arguments, environment or the original PID 1.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let status = if collect(CaptureMode::FirstStage).is_ok() {
            0
        } else {
            74
        };
        unsafe {
            libc::_exit(status);
        }
    }
    // Failure to fork is nonfatal: boot the exact retained init without a log.
    let mut argv: Vec<_> = arguments.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    unsafe {
        libc::execv(original.as_ptr(), argv.as_ptr());
    }
    eprintln!(
        "Cannot execute retained init: {}",
        io::Error::last_os_error()
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_capture_preserves_boot_evidence_and_publishes_before_exit() {
        let root = tempfile::tempdir().unwrap();
        let mut first = Sink::new(root.path().as_os_str()).unwrap();
        first.append(b"retained early boot evidence").unwrap();
        let mut boot = Sink::from_named_directory(
            File::open(root.path()).unwrap(),
            CaptureMode::BootService.filename(),
            4 * CAPTURE_LIMIT,
        )
        .unwrap();
        boot.append(b"retained boot service evidence").unwrap();
        let mut vm = Sink::from_named_directory(
            File::open(root.path()).unwrap(),
            CaptureMode::VmService.filename(),
            4 * CAPTURE_LIMIT,
        )
        .unwrap();
        vm.append(b"partial VM diagnosis before a disconnect")
            .unwrap();
        // Read while the collector is still alive: a host/device interruption
        // must not leave the only evidence in an unpublished staging name.
        for (name, expected) in [
            (
                "first-stage.log",
                b"retained early boot evidence".as_slice(),
            ),
            (
                "second-stage.log",
                b"retained boot service evidence".as_slice(),
            ),
            (
                "vm-runtime.log",
                b"partial VM diagnosis before a disconnect".as_slice(),
            ),
        ] {
            assert_eq!(
                std::fs::read(root.path().join("gb-port").join(name)).unwrap(),
                expected
            );
        }
    }
    #[test]
    fn kernel_storm_leaves_capacity_for_all_bounded_logcat_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let mut sink =
            Sink::from_named_directory(parent, "second-stage.log", 4 * CAPTURE_LIMIT).unwrap();
        sink.append(b"service marker\n").unwrap();
        let mut kernel_budget = CAPTURE_LIMIT;
        let storm = vec![b'k'; 4 * CAPTURE_LIMIT];
        sink.append_capped(&storm, &mut kernel_budget).unwrap();
        sink.append_capped(&storm, &mut kernel_budget).unwrap();
        assert_eq!(kernel_budget, 0);
        assert!(sink.remaining > 2 * CAPTURE_LIMIT);
        let snapshot = vec![b'l'; 128 * 1024];
        for _ in 0..23 {
            sink.append(b"logcat snapshot\n").unwrap();
            sink.append(&snapshot).unwrap();
        }
        sink.append(b"collector deadline\n").unwrap();
        let output = std::fs::read(root.path().join("gb-port/second-stage.log")).unwrap();
        assert!(output.ends_with(b"collector deadline\n"));
        let start = b"service marker\n".len();
        assert!(
            output[start..start + CAPTURE_LIMIT]
                .iter()
                .all(|&b| b == b'k')
        );
        assert!(output[start + CAPTURE_LIMIT..].starts_with(b"logcat snapshot\n"));
        assert!(output.len() < 4 * CAPTURE_LIMIT);
    }
    #[test]
    fn empty_snapshot_does_not_publish_a_staging_file() {
        let root = tempfile::tempdir().unwrap();
        let mut sink = Sink::new(root.path().as_os_str()).unwrap();
        sink.append(b"").unwrap();
        assert!(!sink.published);
        assert_eq!(sink.remaining, CAPTURE_LIMIT);
        assert!(!root.path().join("gb-port/first-stage.log").exists());
        sink.append(b"first snapshot").unwrap();
        assert!(sink.published);
    }
    #[test]
    fn owned_log_replacement_does_not_truncate_a_hardlinked_key() {
        let root = tempfile::tempdir().unwrap();
        let mut sink = Sink::new(root.path().as_os_str()).unwrap();
        let key = root.path().join("key");
        std::fs::write(&key, b"key must remain intact").unwrap();
        std::fs::hard_link(&key, root.path().join("gb-port/first-stage.log")).unwrap();
        sink.append(b"kernel diagnostics").unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), b"key must remain intact");
        assert_eq!(
            std::fs::read(root.path().join("gb-port/first-stage.log")).unwrap(),
            b"kernel diagnostics"
        );
    }
    #[test]
    fn diagnostic_directory_symlink_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(other.path(), root.path().join("gb-port")).unwrap();
        assert!(Sink::new(root.path().as_os_str()).is_err());
        assert_eq!(std::fs::read_dir(other.path()).unwrap().count(), 0);
    }
    #[test]
    fn output_remains_bounded_and_published_before_child_exit() {
        let root = tempfile::tempdir().unwrap();
        let mut sink = Sink::new(root.path().as_os_str()).unwrap();
        sink.append(&vec![b'x'; CAPTURE_LIMIT + 100]).unwrap();
        sink.append(b"extra").unwrap();
        assert_eq!(
            std::fs::metadata(root.path().join("gb-port/first-stage.log"))
                .unwrap()
                .len(),
            CAPTURE_LIMIT as u64
        );
        assert_eq!(
            std::fs::read_dir(root.path().join("gb-port"))
                .unwrap()
                .count(),
            1
        );
    }
}
