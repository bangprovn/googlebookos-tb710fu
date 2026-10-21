//! Guest-only guarded module loading. The kernel verifies signatures and CRCs;
//! finit_module flags are always zero. No device firmware or key policy writes.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    thread,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    kernel_release: String,
    kernel_config_sha256: String,
    module_path: String,
    module_sha256: String,
}

fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Profile {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported guest accept profile version"
        );
        ensure!(
            self.kernel_release.len() <= 128
                && !self.kernel_release.is_empty()
                && self
                    .kernel_release
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
            "invalid kernel release"
        );
        ensure!(
            sha(&self.module_sha256) && sha(&self.kernel_config_sha256),
            "invalid profile SHA-256"
        );
        let prefix = Path::new("/usr/local/lib/googlebook-port");
        let path = Path::new(&self.module_path);
        ensure!(
            path.starts_with(prefix)
                && path.file_name().is_some_and(|x| x == "gunyah_guest.ko")
                && path.components().all(|x| matches!(
                    x,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
            "module must reside in the managed guest directory"
        );
        Ok(())
    }
}

fn root_file(path: &Path, limit: u64) -> Result<(File, Vec<u8>)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= limit,
        "managed guest file metadata rejected"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "managed guest file exceeds budget"
    );
    Ok((file, bytes))
}

fn ready(device: &Path) -> bool {
    fs::read_to_string(device.join("status")).is_ok_and(|x| x.trim() == "0x0000000f")
        && fs::read_link(device.join("driver"))
            .is_ok_and(|x| x.file_name().is_some_and(|n| n == "gunyah_accept"))
        && fs::read_to_string("/sys/module/gunyah_guest/initstate")
            .is_ok_and(|x| x.trim() == "live")
}

#[derive(Serialize)]
struct Receipt {
    schema_version: u32,
    status: &'static str,
    kernel_release: String,
    kernel_config_sha256: String,
    module_file_sha256: String,
    module_loaded_this_invocation: bool,
    existing_loaded_image_provenance_verified: bool,
    runtime_binding_verified: bool,
    gpu_work_verified: bool,
    signature_enforcement_changed: bool,
    firmware_written: bool,
}

fn run(path: &Path) -> Result<Receipt> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "guest module loading requires root"
    );
    let (_, bytes) = root_file(path, 16384)?;
    let profile: Profile = serde_json::from_slice(&bytes)?;
    profile.validate()?;
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    ensure!(
        release.trim() == profile.kernel_release,
        "guest kernel release differs from profile"
    );
    let mut config = Vec::new();
    flate2::read::GzDecoder::new(File::open("/proc/config.gz")?)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut config)?;
    ensure!(
        config.len() <= 1024 * 1024 && gb_core::digest(&config) == profile.kernel_config_sha256,
        "guest kernel configuration differs from profile"
    );
    ensure!(
        Path::new("/sys/bus/auxiliary/devices/gunyah_rsc_mgr.gh_rm_core.0").exists()
            && Path::new("/dev/gunyah").exists(),
        "required built-in RM client missing"
    );
    let mut devices = Vec::new();
    for (count, entry) in fs::read_dir("/sys/bus/virtio/devices")?.enumerate() {
        ensure!(count < 256, "virtio device budget exceeded");
        let path = entry?.path();
        if fs::read_to_string(path.join("device"))?.trim() == "0x003c" {
            devices.push(path);
        }
    }
    ensure!(
        devices.len() == 1,
        "exactly one accept transport device required"
    );
    let (module, bytes) = root_file(Path::new(&profile.module_path), 16 * 1024 * 1024)?;
    ensure!(
        gb_core::digest(&bytes) == profile.module_sha256,
        "guest module SHA-256 differs from profile"
    );
    let existed = Path::new("/sys/module/gunyah_guest").exists();
    if !existed {
        ensure!(
            fs::read_to_string("/proc/sys/kernel/modules_disabled")?.trim() == "0",
            "guest module loading disabled"
        );
        ensure!(
            !devices[0].join("driver").exists(),
            "accept device already bound to another driver"
        );
        let parameters = c"";
        // Zero flags preserve the kernel's signature, vermagic and modversion checks.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_finit_module,
                module.as_raw_fd(),
                parameters.as_ptr(),
                0,
            )
        };
        ensure!(
            ret == 0,
            "finit_module rejected guest module: {}",
            std::io::Error::last_os_error()
        );
    }
    for _ in 0..100 {
        if ready(&devices[0]) {
            return Ok(Receipt {
                schema_version: 1,
                status: "ready",
                kernel_release: profile.kernel_release,
                kernel_config_sha256: profile.kernel_config_sha256,
                module_file_sha256: profile.module_sha256,
                module_loaded_this_invocation: !existed,
                existing_loaded_image_provenance_verified: false,
                runtime_binding_verified: true,
                gpu_work_verified: false,
                signature_enforcement_changed: false,
                firmware_written: false,
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
    anyhow::bail!("guest module did not bind a ready accept transport; no forced unload attempted")
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 1, "expected MANAGED_GUEST_PROFILE_JSON");
    let result = run(Path::new(&args[0])).context("guarded guest accept load");
    match result {
        Ok(receipt) => println!("{}", serde_json::to_string(&receipt)?),
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"status":"failed","error":format!("{error:#}"),"runtime_binding_verified":false,"firmware_written":false})
            );
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_unmanaged_paths_unknown_fields_and_bad_digests() {
        let mut value = serde_json::json!({"schema_version":1,"kernel_release":"6.12.93-exact",
            "kernel_config_sha256":"a".repeat(64),"module_path":"/usr/local/lib/googlebook-port/test/gunyah_guest.ko","module_sha256":"b".repeat(64)});
        let parse = |v: &serde_json::Value| -> Result<()> {
            serde_json::from_value::<Profile>(v.clone())?.validate()
        };
        assert!(parse(&value).is_ok());
        for path in [
            "/tmp/gunyah_guest.ko",
            "/usr/local/lib/googlebook-port/../../tmp/gunyah_guest.ko",
            "/usr/local/lib/googlebook-port/test/other.ko",
        ] {
            value["module_path"] = path.into();
            assert!(parse(&value).is_err());
        }
        value["module_path"] = "/usr/local/lib/googlebook-port/test/gunyah_guest.ko".into();
        value["module_sha256"] = "bad".into();
        assert!(parse(&value).is_err());
        value["module_sha256"] = "b".repeat(64).into();
        value["ignore_vermagic"] = true.into();
        assert!(parse(&value).is_err());
    }
}
