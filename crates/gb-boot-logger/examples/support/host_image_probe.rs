//! Optional immutable diagnostic, executed before the selected original VMM.
//! No VM argv/environment/FD contents are passed to the owned child.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const DRIVER: &str = "/system_ext/lib64/gb-runtime-v1/libvulkan_freedreno.so";
const CAPTURE_LIMIT: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Passed {
    schema_version: u32,
    status: String,
    source_udmabuf_gpu_copy: bool,
    source_bytes: u64,
    source_stride: u64,
    cpu_frame_copy_used: bool,
    rounds_verified: u32,
    pixels_verified: u32,
    maximum_channel_error: u32,
    allocation_bytes: u64,
    ahb_stride_pixels: u32,
    ahb_usage: u64,
    gpu_vulkan_clear: bool,
    cpu_ahb_mapping_used: bool,
    foreign_ownership_and_fence_wait: bool,
    egl_image_reused: bool,
    before_and_after_cpu_texture_controls: bool,
    ahb_sharing_verified: bool,
    guest_integration_verified: bool,
    original_vmm_namespace_verified: bool,
    owner_content_read: bool,
    full_port_verified: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failed {
    schema_version: u32,
    status: String,
    stage: String,
    code: i32,
    rounds_verified: u32,
    ahb_sharing_verified: bool,
    guest_integration_verified: bool,
    full_port_verified: bool,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Receipt {
    Pass(Passed),
    Fail(Failed),
}

fn domain(input: &str) -> Option<&str> {
    let domain = input.strip_prefix("u:r:")?.split_once(':')?.0;
    (!domain.is_empty()
        && domain.len() <= 96
        && domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    .then_some(domain)
}

/// Immutable bundle verification is also performed by the mount worker.
fn verify(path: &Path, expected: &str) -> io::Result<()> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::other("invalid build-time probe pin"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the descriptor and output buffer are valid.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatvfs initialized stat on success.
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
        || unsafe { stat.assume_init() }.f_flag & libc::ST_RDONLY == 0
    {
        return Err(io::Error::other("probe is not an immutable bounded file"));
    }
    let mut hash = Sha256::new();
    let mut bytes = [0; 8192];
    let mut count = 0;
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        count += n;
        if count > 1024 * 1024 {
            return Err(io::Error::other("probe grew beyond budget"));
        }
        hash.update(&bytes[..n]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err(io::Error::other("probe hash mismatch"));
    }
    Ok(())
}

struct Capture {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
fn nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: fcntl does not take ownership of the valid pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn drain(reader: &mut impl Read, output: &mut Vec<u8>) -> io::Result<()> {
    let mut buffer = [0; 2048];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                if output.len() + n >= CAPTURE_LIMIT {
                    return Err(io::Error::other("owned probe output budget"));
                }
                output.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}
fn capture(command: &mut Command, timeout: Duration) -> io::Result<Capture> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdout pipe"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("stderr pipe"))?;
        nonblocking(stdout.as_raw_fd())?;
        nonblocking(stderr.as_raw_fd())?;
        let mut result = Capture {
            code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        loop {
            if started.elapsed() >= timeout {
                return Err(io::Error::other("owned probe deadline"));
            }
            drain(&mut stdout, &mut result.stdout)?;
            drain(&mut stderr, &mut result.stderr)?;
            if let Some(status) = child.try_wait()? {
                drain(&mut stdout, &mut result.stdout)?;
                drain(&mut stderr, &mut result.stderr)?;
                result.code = status.code();
                return Ok(result);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        // Never block the original VMM on an uninterruptible GPU operation.
        for _ in 0..100 {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    result
}

fn summary(capture: &Capture, uid: u32, own_domain: &str) -> Option<String> {
    let stderr = std::str::from_utf8(&capture.stderr).ok()?;
    let context = format!(
        "GB_AHB_CONTEXT uid={uid} domain={own_domain} fds_closed=1 caps_dropped=1 no_new_privs=1"
    );
    if stderr
        .lines()
        .filter(|s| s.starts_with("GB_AHB_CONTEXT "))
        .count()
        != 1
        || !stderr.lines().any(|s| s == context)
    {
        return None;
    }
    match serde_json::from_slice::<Receipt>(&capture.stdout).ok()? {
        Receipt::Pass(p) => {
            if capture.code != Some(0)
                || p.schema_version != 1
                || p.status != "vulkan_ahb_gles_sampling_verified"
                || !p.source_udmabuf_gpu_copy
                || p.cpu_frame_copy_used
                || p.cpu_ahb_mapping_used
                || !p.gpu_vulkan_clear
                || !p.foreign_ownership_and_fence_wait
                || !p.egl_image_reused
                || !p.before_and_after_cpu_texture_controls
                || !p.ahb_sharing_verified
                || p.guest_integration_verified
                || p.original_vmm_namespace_verified
                || p.owner_content_read
                || p.full_port_verified
                || p.rounds_verified != 2
                || p.pixels_verified != 2048
                || p.maximum_channel_error > 1
                || !(4096..=1024 * 1024).contains(&p.source_bytes)
                || !(128..=65536).contains(&p.source_stride)
                || !p.source_stride.is_multiple_of(4)
                || 31 * p.source_stride + 128 > p.source_bytes
                || !(4096..=1024 * 1024).contains(&p.allocation_bytes)
                || !(32..=8192).contains(&p.ahb_stride_pixels)
                || u64::from(p.ahb_stride_pixels) * 31 * 4 + 128 > p.allocation_bytes
                || p.ahb_usage & 768 != 768
                || p.ahb_usage & (1 << 14) != 0
            {
                return None;
            }
            Some(format!(
                "image_probe source=owned_udmabuf outcome=pass uid={uid} domain_same=true fds_closed=true caps_dropped=true pixels={} rounds={} max_error={} source_bytes={} source_stride={} ahb_bytes={} guest_verified=false",
                p.pixels_verified,
                p.rounds_verified,
                p.maximum_channel_error,
                p.source_bytes,
                p.source_stride,
                p.allocation_bytes
            ))
        }
        Receipt::Fail(p) => {
            if capture.code != Some(1)
                || p.schema_version != 1
                || p.status != "failed"
                || p.rounds_verified > 2
                || p.ahb_sharing_verified
                || p.guest_integration_verified
                || p.full_port_verified
                || p.stage.is_empty()
                || p.stage.len() > 96
                || !p
                    .stage
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return None;
            }
            Some(format!(
                "image_probe source=owned_udmabuf outcome=failed uid={uid} domain_same=true stage={} code={} rounds={} guest_verified=false",
                p.stage, p.code, p.rounds_verified
            ))
        }
    }
}

/// Off in normal builds. A diagnostic build explicitly pins its owned helper.
/// Failure produces bounded metadata and never prevents the original VMM exec.
pub fn run(base: &Path) -> String {
    let Some(pin) = option_env!("GB_HOST_IMAGE_PREFLIGHT_SHA256") else {
        return "image_probe outcome=disabled".into();
    };
    let helper = base.join("runtime/bin/gb-host-image-probe");
    let result = (|| -> io::Result<String> {
        verify(&helper, pin)?;
        let mut current = String::new();
        std::fs::File::open("/proc/self/attr/current")?
            .take(257)
            .read_to_string(&mut current)?;
        let own_domain = domain(&current).ok_or_else(|| io::Error::other("own domain"))?;
        // SAFETY: getuid has no input or side effects.
        let uid = unsafe { libc::getuid() };
        let mut command = Command::new(helper);
        command
            .env_clear()
            .current_dir("/")
            .env("LD_LIBRARY_PATH", "/system_ext/lib64/gb-runtime-v1")
            .env("MESA_SHADER_CACHE_DISABLE", "true")
            .args(["--driver", DRIVER, "--udmabuf-copy"]);
        let result = capture(&mut command, Duration::from_secs(28))?;
        summary(&result, uid, own_domain)
            .ok_or_else(|| io::Error::other("invalid owned probe receipt"))
    })();
    result.unwrap_or_else(|_| {
        "image_probe outcome=unverified diagnostic_error=true guest_verified=false".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_and_output_budget_terminate_owned_children() {
        let mut command = Command::new("/bin/sleep");
        command.arg("5");
        let started = Instant::now();
        assert!(capture(&mut command, Duration::from_millis(50)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(capture(&mut Command::new("/usr/bin/yes"), Duration::from_secs(2)).is_err());
    }
    #[test]
    fn captures_both_pipes_without_owner_environment() {
        let mut command = Command::new("/bin/sh");
        command
            .env_clear()
            .args(["-c", "printf owned; printf bounded >&2; exit 7"]);
        let result = capture(&mut command, Duration::from_secs(2)).unwrap();
        assert_eq!(result.code, Some(7));
        assert_eq!(result.stdout, b"owned");
        assert_eq!(result.stderr, b"bounded");
    }
    #[test]
    fn context_and_source_claims_cannot_be_upgraded() {
        let value = include_str!("../../../../tests/fixtures/ahb_sampling.example.json");
        let mut json: serde_json::Value = serde_json::from_str(value).unwrap();
        json["source_udmabuf_gpu_copy"] = true.into();
        json["source_bytes"] = 8192.into();
        json["source_stride"] = 256.into();
        let stderr=b"GB_AHB_CONTEXT uid=1110248 domain=priv_app_all_virtmgr_crosvm fds_closed=1 caps_dropped=1 no_new_privs=1\n".to_vec();
        let result = Capture {
            code: Some(0),
            stdout: serde_json::to_vec(&json).unwrap(),
            stderr,
        };
        assert!(
            summary(&result, 1110248, "priv_app_all_virtmgr_crosvm")
                .unwrap()
                .contains("outcome=pass")
        );
        assert!(summary(&result, 2000, "shell").is_none());
        for field in [
            "guest_integration_verified",
            "original_vmm_namespace_verified",
            "cpu_frame_copy_used",
        ] {
            let mut bad = json.clone();
            bad[field] = true.into();
            assert!(
                summary(
                    &Capture {
                        code: Some(0),
                        stdout: serde_json::to_vec(&bad).unwrap(),
                        stderr: result.stderr.clone()
                    },
                    1110248,
                    "priv_app_all_virtmgr_crosvm"
                )
                .is_none()
            );
        }
        assert_eq!(
            domain("u:r:priv_app_all_virtmgr_crosvm:s0:c1,c2"),
            Some("priv_app_all_virtmgr_crosvm")
        );
        assert!(domain("u:r:invalid\ndomain:s0").is_none());
    }
    #[test]
    fn diagnostic_is_off_without_an_explicit_build_pin() {
        if option_env!("GB_HOST_IMAGE_PREFLIGHT_SHA256").is_none() {
            assert_eq!(
                run(Path::new("/does-not-exist")),
                "image_probe outcome=disabled"
            );
        }
    }
}
