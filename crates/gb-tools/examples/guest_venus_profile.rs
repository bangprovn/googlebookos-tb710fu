//! Guest-only, reversible login profile for a qualified private Venus client.
//! Stock packages, Android firmware, kernel and security policy are read-only.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    time::Duration,
};

const STOCK: &str = "/usr/lib/aarch64-linux-gnu/libvulkan_virtio.so";
const BASE: &str = "/usr/local/lib/googlebook-port-venus-v1";
const LEGACY_BASE: &str = "/usr/local/lib/googlebook-port";
const LOGIN: &str = "/etc/profile.d/gb-venus-client-v1.sh";
const WSI_LOGIN: &str = "/etc/profile.d/gb-venus-wsi-v1.sh";
const MAX_LIBRARY: u64 = 16 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    guest_kernel_release: String,
    mesa_version: String,
    stock_library_sha256: String,
    library_sha256: String,
    copyright_sha256: String,
    command_pool_policy: String,
}

fn sha(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Profile {
    fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported profile schema");
        ensure!(
            self.command_pool_policy == "1m",
            "unsupported command pool policy"
        );
        for value in [&self.guest_kernel_release, &self.mesa_version] {
            ensure!(
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._+-:".contains(&b)),
                "invalid pinned kernel/package version"
            );
        }
        ensure!(
            sha(&self.stock_library_sha256)
                && sha(&self.library_sha256)
                && sha(&self.copyright_sha256),
            "invalid SHA-256"
        );
        ensure!(
            self.library_sha256 != self.stock_library_sha256,
            "adaptation equals stock"
        );
        Ok(())
    }

    fn destination(&self, base: &Path) -> PathBuf {
        base.join(format!("venus-client-{}", self.library_sha256))
    }
}

fn read_file(path: &Path, limit: u64, owner: Option<u32>) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= limit
            && owner.is_none_or(|uid| meta.uid() == uid),
        "file metadata rejected: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeds budget");
    Ok(bytes)
}

fn directory(path: &Path, owner: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == owner && meta.mode() & 0o022 == 0,
        "directory ownership/mode rejected: {}",
        path.display()
    );
    Ok(())
}

fn public_directory(path: &Path, owner: u32) -> Result<()> {
    directory(path, owner)?;
    ensure!(
        fs::symlink_metadata(path)?.mode() & 0o005 == 0o005,
        "driver directory must be readable/traversable by normal users: {}",
        path.display()
    );
    Ok(())
}

fn create_public_base(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            sync_dir(path.parent().context("managed base parent")?)?;
        }
        Err(error) => return Err(error.into()),
    }
    public_directory(path, 0)
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all().context("sync directory")
}

fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    ensure!(
        ret == 0,
        "atomic publication failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn atomic_profile(path: &Path, content: &[u8], owner: u32) -> Result<bool> {
    directory(path.parent().context("profile parent")?, owner)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            ensure!(
                read_file(path, 16384, Some(owner))? == content,
                "existing login profile differs; preserving it"
            );
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("profile parent")?)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    temp.write_all(content)?;
    temp.as_file().sync_all()?;
    rename_noreplace(temp.path(), path)?;
    sync_dir(path.parent().context("profile parent")?)?;
    Ok(true)
}

fn install_profile(path: &Path, content: &[u8], legacy: &[u8], owner: u32) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        let previous = read_file(path, 16384, Some(owner))?;
        if previous != content {
            ensure!(
                previous == legacy,
                "existing login profile differs; preserving it"
            );
            // Only the exact earlier owned profile may be migrated. A crash
            // here leaves the original package as the normal-login fallback.
            fs::remove_file(path)?;
            sync_dir(path.parent().context("profile parent")?)?;
        }
    }
    atomic_profile(path, content, owner)?;
    Ok(())
}

fn login_content_v1(icd: &Path) -> Result<Vec<u8>> {
    let path = icd.to_str().context("non UTF-8 managed ICD path")?;
    ensure!(
        path.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "unsafe managed ICD path"
    );
    Ok(format!(
        "# Managed Googlebook guest Venus profile v1; remove this file to disable.\n\
         # Preserve explicit owner driver and pool selections.\n\
         if [ \"${{VK_DRIVER_FILES+x}}\" != x ] && [ \"${{VK_ICD_FILENAMES+x}}\" != x ]; then\n\
         \x20 export VK_DRIVER_FILES='{path}'\n\
         fi\n\
         if [ \"${{GB_VENUS_COMMAND_POOL_V1+x}}\" != x ]; then\n\
         \x20 export GB_VENUS_COMMAND_POOL_V1=1m\n\
         fi\n"
    )
    .into_bytes())
}

fn login_content(icd: &Path) -> Result<Vec<u8>> {
    let path = icd.to_str().context("non UTF-8 managed ICD path")?;
    ensure!(
        path.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "unsafe managed ICD path"
    );
    Ok(format!(
        "# Managed Googlebook guest Venus profile v2; remove this file to disable.\n\
         # Replace the observed stock CPU fallback pair; preserve other owner selections.\n\
         if {{ [ \"${{VK_DRIVER_FILES+x}}\" != x ] && [ \"${{VK_ICD_FILENAMES+x}}\" != x ]; }} ||\n\
         \x20 {{ [ \"${{VK_DRIVER_FILES-}}\" = /usr/share/vulkan/icd.d/lvp_icd.json ] &&\n\
         \x20 [ \"${{VK_ICD_FILENAMES-}}\" = /usr/share/vulkan/icd.d/lvp_icd.json ]; }}; then\n\
         \x20 export VK_DRIVER_FILES='{path}'\n\
         \x20 unset VK_ICD_FILENAMES\n\
         fi\n\
         if [ \"${{GB_VENUS_COMMAND_POOL_V1+x}}\" != x ]; then\n\
         \x20 export GB_VENUS_COMMAND_POOL_V1=1m\n\
         fi\n"
    )
    .into_bytes())
}

fn wsi_login_content(icd: &Path) -> Result<Vec<u8>> {
    let path = icd.to_str().context("non UTF-8 managed ICD path")?;
    ensure!(
        path.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "unsafe managed ICD path"
    );
    Ok(format!(
        "# Managed Googlebook guest Venus WSI copy profile v1; remove to disable.\n\
         # GPU rendering retained; copy completed frames instead of cross-driver DMA-BUF presentation.\n\
         # Preserve explicit owner WSI choices and all other driver selections.\n\
         if [ \"${{VK_DRIVER_FILES-}}\" = '{path}' ] &&\n\
         \x20 [ \"${{VK_ICD_FILENAMES+x}}\" != x ] &&\n\
         \x20 [ \"${{MESA_VK_WSI_DEBUG+x}}\" != x ]; then\n\
         \x20 export MESA_VK_WSI_DEBUG=sw\n\
         fi\n"
    )
    .into_bytes())
}

fn verify_payload(destination: &Path, profile: &Profile, owner: u32) -> Result<()> {
    public_directory(destination, owner)?;
    ensure!(
        gb_core::digest(&read_file(
            &destination.join("libvulkan_virtio.so"),
            MAX_LIBRARY,
            Some(owner)
        )?) == profile.library_sha256,
        "published library differs"
    );
    ensure!(
        gb_core::digest(&read_file(
            &destination.join("COPYRIGHT"),
            4 * 1024 * 1024,
            Some(owner)
        )?) == profile.copyright_sha256,
        "published copyright differs"
    );
    let expected = icd_content(destination)?;
    ensure!(
        read_file(&destination.join("virtio_icd.json"), 16384, Some(owner))? == expected,
        "published ICD differs"
    );
    let found: Profile = serde_json::from_slice(&read_file(
        &destination.join("profile.json"),
        16384,
        Some(owner),
    )?)?;
    ensure!(
        serde_json::to_value(found)? == serde_json::to_value(profile)?,
        "published profile differs"
    );
    Ok(())
}

fn icd_content(destination: &Path) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(
        &serde_json::json!({"file_format_version":"1.0.0",
        "ICD":{"api_version":"1.3.305","library_path":destination.join("libvulkan_virtio.so")}}),
    )?)
}

fn publish(
    base: &Path,
    profile: &Profile,
    library: &[u8],
    copyright: &[u8],
    owner: u32,
) -> Result<PathBuf> {
    public_directory(base, owner)?;
    ensure!(
        gb_core::digest(library) == profile.library_sha256
            && gb_core::digest(copyright) == profile.copyright_sha256,
        "input payload hash mismatch"
    );
    ensure!(
        library.len() >= 64
            && &library[..6] == b"\x7fELF\x02\x01"
            && u16::from_le_bytes([library[16], library[17]]) == 3
            && u16::from_le_bytes([library[18], library[19]]) == 183,
        "expected AArch64 shared ELF"
    );
    let destination = profile.destination(base);
    if fs::symlink_metadata(&destination).is_ok() {
        verify_payload(&destination, profile, owner)?;
        return Ok(destination);
    }
    let temp = tempfile::Builder::new()
        .prefix(".venus-client-stage-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(base)?;
    write_new(&temp.path().join("libvulkan_virtio.so"), library, 0o644)?;
    write_new(&temp.path().join("COPYRIGHT"), copyright, 0o644)?;
    write_new(
        &temp.path().join("virtio_icd.json"),
        &icd_content(&destination)?,
        0o644,
    )?;
    write_new(
        &temp.path().join("profile.json"),
        &serde_json::to_vec_pretty(profile)?,
        0o644,
    )?;
    sync_dir(temp.path())?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755))?;
    // The root-owned base and a process lock exclude concurrent publishers.
    ensure!(
        !destination.try_exists()?,
        "destination appeared while staging"
    );
    rename_noreplace(temp.path(), &destination)?;
    sync_dir(base)?;
    verify_payload(&destination, profile, owner)?;
    Ok(destination)
}

fn guest_preflight(profile: &Profile) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "guest profile installation requires root"
    );
    ensure!(
        std::env::consts::ARCH == "aarch64",
        "AArch64 guest required"
    );
    ensure!(
        fs::read_to_string("/proc/sys/kernel/osrelease")?.trim() == profile.guest_kernel_release,
        "guest kernel differs from profile"
    );
    ensure!(
        fs::read_to_string("/sys/module/gunyah_guest/initstate")?.trim() == "live",
        "qualified guest RM module not live"
    );
    let result = gb_core::run_tool(
        Path::new("/usr/bin/dpkg-query"),
        &[
            "-W".into(),
            "-f=${Version}".into(),
            "mesa-vulkan-drivers".into(),
        ],
        Duration::from_secs(10),
    )?;
    ensure!(
        result.stdout.trim() == profile.mesa_version,
        "Mesa package version differs"
    );
    ensure!(
        gb_core::digest(&read_file(Path::new(STOCK), MAX_LIBRARY, Some(0))?)
            == profile.stock_library_sha256,
        "stock driver differs; refusing adaptation"
    );
    for path in [
        "/usr",
        "/usr/local",
        "/usr/local/lib",
        "/etc",
        "/etc/profile.d",
    ] {
        public_directory(Path::new(path), 0)?;
    }
    Ok(())
}

fn run(action: &str, bundle: &Path) -> Result<serde_json::Value> {
    let profile: Profile =
        serde_json::from_slice(&read_file(&bundle.join("profile.json"), 16384, None)?)?;
    profile.validate()?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "guest profile operation requires root"
    );
    if action == "remove" || action == "wsi-remove" {
        // Disabling an exact owned login profile must remain possible after a
        // package/kernel update invalidates the installation prerequisites.
        directory(Path::new("/etc"), 0)?;
        directory(Path::new("/etc/profile.d"), 0)?;
    } else {
        guest_preflight(&profile)?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/run/lock/gb-venus-client-v1.lock")?;
    let meta = lock.metadata()?;
    ensure!(
        meta.uid() == 0 && meta.nlink() == 1 && meta.is_file() && meta.mode() & 0o077 == 0,
        "profile lock metadata rejected"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another profile operation is active"
    );
    let destination = profile.destination(Path::new(BASE));
    let content = login_content(&destination.join("virtio_icd.json"))?;
    if action.starts_with("wsi-") {
        let wsi_content = wsi_login_content(&destination.join("virtio_icd.json"))?;
        let status = match action {
            "wsi-install" | "wsi-check" => {
                public_directory(Path::new(BASE), 0)?;
                verify_payload(&destination, &profile, 0)?;
                ensure!(
                    read_file(Path::new(LOGIN), 16384, Some(0))? == content,
                    "qualified Venus login profile differs"
                );
                if action == "wsi-install" {
                    atomic_profile(Path::new(WSI_LOGIN), &wsi_content, 0)?;
                    "wsi_copy_installed_pending_new_login_validation"
                } else {
                    ensure!(
                        read_file(Path::new(WSI_LOGIN), 16384, Some(0))? == wsi_content,
                        "WSI profile differs"
                    );
                    "wsi_copy_files_verified_runtime_not_tested"
                }
            }
            "wsi-remove" => {
                ensure!(
                    read_file(Path::new(WSI_LOGIN), 16384, Some(0))? == wsi_content,
                    "WSI profile differs; preserving it"
                );
                fs::remove_file(WSI_LOGIN)?;
                sync_dir(Path::new("/etc/profile.d"))?;
                "wsi_copy_disabled_for_new_logins"
            }
            _ => anyhow::bail!("unsupported WSI action"),
        };
        return Ok(serde_json::json!({"schema_version":1,"status":status,
            "library_sha256":profile.library_sha256,"stock_library_written":false,
            "firmware_written":false,"security_policy_changed":false,"runtime_verified":false,
            "requires_new_login":true,"managed_directory":destination,
            "presentation_transport":"software_wsi_copy","software_gpu_selected":false}));
    }
    let legacy_private = login_content_v1(
        &profile
            .destination(Path::new(LEGACY_BASE))
            .join("virtio_icd.json"),
    )?;
    let legacy_public = login_content_v1(&destination.join("virtio_icd.json"))?;
    let legacy = if fs::symlink_metadata(LOGIN).is_ok()
        && read_file(Path::new(LOGIN), 16384, Some(0))? == legacy_public
    {
        legacy_public
    } else {
        legacy_private
    };
    let status = match action {
        "install" => {
            let library = read_file(&bundle.join("libvulkan_virtio.so"), MAX_LIBRARY, None)?;
            let copyright = read_file(&bundle.join("COPYRIGHT"), 4 * 1024 * 1024, None)?;
            if fs::symlink_metadata(LOGIN).is_ok() {
                ensure!(
                    {
                        let existing = read_file(Path::new(LOGIN), 16384, Some(0))?;
                        existing == content || existing == legacy
                    },
                    "existing login profile differs; preserving it"
                );
            }
            create_public_base(Path::new(BASE))?;
            publish(Path::new(BASE), &profile, &library, &copyright, 0)?;
            install_profile(Path::new(LOGIN), &content, &legacy, 0)?;
            "installed_pending_new_login_validation"
        }
        "check" => {
            public_directory(Path::new(BASE), 0)?;
            verify_payload(&destination, &profile, 0)?;
            ensure!(
                read_file(Path::new(LOGIN), 16384, Some(0))? == content,
                "login profile differs"
            );
            "installed_files_verified_runtime_not_tested"
        }
        "remove" => {
            ensure!(
                {
                    let existing = read_file(Path::new(LOGIN), 16384, Some(0))?;
                    existing == content || existing == legacy
                },
                "login profile differs; preserving it"
            );
            fs::remove_file(LOGIN)?;
            sync_dir(Path::new("/etc/profile.d"))?;
            "disabled_for_new_logins_payload_retained"
        }
        _ => anyhow::bail!("unsupported action"),
    };
    Ok(
        serde_json::json!({"schema_version":1,"status":status,"library_sha256":profile.library_sha256,
        "stock_library_written":false,"firmware_written":false,"security_policy_changed":false,
        "runtime_verified":false,"requires_new_login":true,"managed_directory":destination}),
    )
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: guest_venus_profile install|check|remove|wsi-install|wsi-check|wsi-remove BUNDLE_DIRECTORY"
    );
    let action = args[0].to_str().context("invalid action")?;
    ensure!(
        [
            "install",
            "check",
            "remove",
            "wsi-install",
            "wsi-check",
            "wsi-remove"
        ]
        .contains(&action),
        "unsupported action"
    );
    println!(
        "{}",
        serde_json::to_string(&run(action, Path::new(&args[1]))?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn private_tempdir() -> Result<tempfile::TempDir> {
        Ok(tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?)
    }

    fn sample() -> (Profile, Vec<u8>, Vec<u8>) {
        let mut library = vec![0; 64];
        library[..6].copy_from_slice(b"\x7fELF\x02\x01");
        library[16] = 3;
        library[18] = 183;
        let copyright = b"owned test license\n".to_vec();
        let profile = Profile {
            schema_version: 1,
            guest_kernel_release: "6.12-test".into(),
            mesa_version: "25.0.7-2+deb13u1".into(),
            stock_library_sha256: "a".repeat(64),
            library_sha256: gb_core::digest(&library),
            copyright_sha256: gb_core::digest(&copyright),
            command_pool_policy: "1m".into(),
        };
        (profile, library, copyright)
    }

    #[test]
    fn malformed_profile_and_payload_cannot_publish() -> Result<()> {
        let (mut p, library, copyright) = sample();
        p.validate()?;
        p.command_pool_policy = "8m".into();
        assert!(p.validate().is_err());
        p.command_pool_policy = "1m".into();
        p.mesa_version = "x; echo unsafe".into();
        assert!(p.validate().is_err());
        let (p, _, _) = sample();
        let base = private_tempdir()?;
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o755))?;
        assert!(
            publish(base.path(), &p, b"invalid", &copyright, unsafe {
                libc::geteuid()
            })
            .is_err()
        );
        assert!(!p.destination(base.path()).exists());
        assert_eq!(library.len(), 64);
        Ok(())
    }

    #[test]
    fn interrupted_install_resumes_without_touching_stock_or_owner_profile() -> Result<()> {
        let (p, library, copyright) = sample();
        let root = private_tempdir()?;
        let uid = unsafe { libc::geteuid() };
        let base = root.path().join("managed");
        fs::create_dir(&base)?;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755))?;
        let dest = publish(&base, &p, &library, &copyright, uid)?;
        // A stop here leaves only an unused immutable payload; stock is untouched.
        assert_eq!(publish(&base, &p, &library, &copyright, uid)?, dest);
        let login = root.path().join("login.sh");
        let content = login_content(&dest.join("virtio_icd.json"))?;
        assert!(atomic_profile(&login, &content, uid)?);
        assert!(!atomic_profile(&login, &content, uid)?);
        fs::write(&login, b"owner modified configuration\n")?;
        assert!(atomic_profile(&login, &content, uid).is_err());
        assert_eq!(fs::read(&login)?, b"owner modified configuration\n");
        fs::remove_file(&login)?;
        let other = root.path().join("other");
        fs::write(&other, b"untouched")?;
        symlink(&other, &login)?;
        assert!(atomic_profile(&login, &content, uid).is_err());
        assert_eq!(fs::read(&other)?, b"untouched");
        Ok(())
    }

    #[test]
    fn published_payload_tamper_or_symlink_is_rejected() -> Result<()> {
        let (p, library, copyright) = sample();
        let base = private_tempdir()?;
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o755))?;
        let uid = unsafe { libc::geteuid() };
        let dest = publish(base.path(), &p, &library, &copyright, uid)?;
        fs::write(dest.join("libvulkan_virtio.so"), b"tampered")?;
        assert!(publish(base.path(), &p, &library, &copyright, uid).is_err());
        fs::remove_file(dest.join("libvulkan_virtio.so"))?;
        let other = base.path().join("other");
        fs::write(&other, &library)?;
        symlink(&other, dest.join("libvulkan_virtio.so"))?;
        assert!(verify_payload(&dest, &p, uid).is_err());
        Ok(())
    }

    #[test]
    fn login_selection_preserves_explicit_owner_overrides() -> Result<()> {
        let root = private_tempdir()?;
        let login = root.path().join("profile.sh");
        fs::write(
            &login,
            login_content(Path::new("/managed/virtio_icd.json"))?,
        )?;
        let script =
            ". \"$1\"; echo \"${VK_DRIVER_FILES-unset}\"; echo \"$GB_VENUS_COMMAND_POOL_V1\"";
        let args = vec![
            "-u".into(),
            "VK_DRIVER_FILES".into(),
            "-u".into(),
            "VK_ICD_FILENAMES".into(),
            "-u".into(),
            "GB_VENUS_COMMAND_POOL_V1".into(),
        ];
        for (extra, expected) in [
            (vec![], "/managed/virtio_icd.json\n1m\n"),
            (
                vec![
                    "VK_DRIVER_FILES=/owner/driver.json",
                    "GB_VENUS_COMMAND_POOL_V1=owner",
                ],
                "/owner/driver.json\nowner\n",
            ),
            (vec!["VK_ICD_FILENAMES=/owner/legacy.json"], "unset\n1m\n"),
            (
                vec![
                    "VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json",
                    "VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json",
                ],
                "/managed/virtio_icd.json\n1m\n",
            ),
        ] {
            let mut command = args.clone();
            command.extend(extra.into_iter().map(String::from));
            command.extend([
                "/bin/sh".into(),
                "-c".into(),
                script.into(),
                "owned-profile-test".into(),
                login.to_string_lossy().into_owned(),
            ]);
            let output =
                gb_core::run_tool(Path::new("/usr/bin/env"), &command, Duration::from_secs(5))?;
            ensure!(output.stdout == expected, "login selection differs");
        }
        Ok(())
    }

    #[test]
    fn wsi_copy_is_scoped_to_the_managed_driver_and_preserves_owner_choices() -> Result<()> {
        let root = private_tempdir()?;
        let login = root.path().join("wsi.sh");
        fs::write(
            &login,
            wsi_login_content(Path::new("/managed/virtio_icd.json"))?,
        )?;
        for (extra, expected) in [
            (vec![], "unset\n"),
            (vec!["VK_DRIVER_FILES=/managed/virtio_icd.json"], "sw\n"),
            (vec!["VK_DRIVER_FILES=/owner/icd.json"], "unset\n"),
            (
                vec![
                    "VK_DRIVER_FILES=/managed/virtio_icd.json",
                    "MESA_VK_WSI_DEBUG=owner",
                ],
                "owner\n",
            ),
            (
                vec![
                    "VK_DRIVER_FILES=/managed/virtio_icd.json",
                    "MESA_VK_WSI_DEBUG=",
                ],
                "\n",
            ),
            (
                vec![
                    "VK_DRIVER_FILES=/managed/virtio_icd.json",
                    "VK_ICD_FILENAMES=/owner/legacy.json",
                ],
                "unset\n",
            ),
        ] {
            let mut args: Vec<String> = [
                "-u",
                "VK_DRIVER_FILES",
                "-u",
                "VK_ICD_FILENAMES",
                "-u",
                "MESA_VK_WSI_DEBUG",
            ]
            .into_iter()
            .map(String::from)
            .collect();
            args.extend(extra.into_iter().map(String::from));
            args.extend([
                "/bin/sh".into(),
                "-c".into(),
                ". \"$1\"; echo \"${MESA_VK_WSI_DEBUG-unset}\"".into(),
                "wsi-selection-test".into(),
                login.to_string_lossy().into_owned(),
            ]);
            let output =
                gb_core::run_tool(Path::new("/usr/bin/env"), &args, Duration::from_secs(5))?;
            ensure!(output.stdout == expected, "WSI selection differs");
        }
        assert!(wsi_login_content(Path::new("/unsafe'path")).is_err());
        Ok(())
    }

    #[test]
    fn public_payload_must_not_use_a_private_module_directory() -> Result<()> {
        let base = private_tempdir()?;
        let uid = unsafe { libc::geteuid() };
        assert!(directory(base.path(), uid).is_ok());
        assert!(public_directory(base.path(), uid).is_err());
        let (p, library, copyright) = sample();
        assert!(publish(base.path(), &p, &library, &copyright, uid).is_err());
        assert_eq!(fs::metadata(base.path())?.mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn migrate_only_the_exact_owned_legacy_profile() -> Result<()> {
        let base = private_tempdir()?;
        let uid = unsafe { libc::geteuid() };
        let path = base.path().join("profile.sh");
        let old = login_content(Path::new("/private/old/virtio_icd.json"))?;
        let new = login_content(Path::new("/public/new/virtio_icd.json"))?;
        atomic_profile(&path, &old, uid)?;
        install_profile(&path, &new, &old, uid)?;
        assert_eq!(fs::read(&path)?, new);
        fs::write(&path, b"owner changes\n")?;
        assert!(install_profile(&path, &new, &old, uid).is_err());
        assert_eq!(fs::read(&path)?, b"owner changes\n");
        Ok(())
    }
}
