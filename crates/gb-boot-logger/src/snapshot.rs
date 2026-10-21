//! Bounded device logcat snapshots. No shell or firmware executable runs on the host.
use std::{
    io::{self, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub status: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
}

pub fn run(command: &mut Command, timeout: Duration, limit: usize) -> io::Result<Snapshot> {
    let parent = unsafe { libc::getpid() };
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    // Ensure the alarm-bounded collector cannot leave a logcat process behind.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::other("collector parent exited"));
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdout absent"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("stderr absent"))?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let started = Instant::now();
        let mut bytes = Vec::new();
        let mut ended = [false; 2];
        let mut status = None;
        let mut buffer = [0u8; 4096];
        let mut truncated = false;
        loop {
            for (i, stream) in [&mut stdout as &mut dyn Read, &mut stderr as &mut dyn Read]
                .into_iter()
                .enumerate()
            {
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            ended[i] = true;
                            break;
                        }
                        Ok(n) => {
                            let count = n.min(limit.saturating_sub(bytes.len()));
                            bytes.extend_from_slice(&buffer[..count]);
                            if count < n {
                                truncated = true;
                                break;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            let timed_out = started.elapsed() >= timeout;
            if (status.is_some() && ended.iter().all(|x| *x)) || timed_out || truncated {
                return Ok(Snapshot {
                    bytes,
                    status: status.and_then(|s| s.code()),
                    timed_out,
                    truncated,
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Bound both process execution and cleanup; the parent alarm is the final
    // device-side bound if an OS call stalls. No blocking wait on untrusted output.
    let _ = child.kill();
    let cleanup = Instant::now();
    while cleanup.elapsed() < Duration::from_secs(1) {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hung_snapshot_is_terminated_with_bounded_output() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf diagnostic; exec sleep 30"]);
        let start = Instant::now();
        let result = run(&mut cmd, Duration::from_millis(80), 100).unwrap();
        assert!(result.timed_out);
        assert_eq!(result.bytes, b"diagnostic");
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn continuous_output_cannot_exceed_capture_limit() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "while :; do printf '0123456789'; done"]);
        let result = run(&mut cmd, Duration::from_secs(1), 64).unwrap();
        assert_eq!(result.bytes.len(), 64);
        assert!(result.truncated);
    }
}
