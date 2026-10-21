//! Fixed owner diagnostic bind mount. Init starts this single-threaded worker
//! after APEX activation, in the default namespace; PID 1 never calls setns.
#[path = "support/pinned_bundle.rs"]
mod pinned_bundle;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

const MEMORY_SOURCE: &str = "/system_ext/gb-virt-bin-memory-v1";
const IRQ_SOURCE: &str = "/system_ext/gb-virt-bin-irq-v1";
const TERMINAL_SOURCE: &str = "/system_ext/gb-virt-bin-terminal-v1";
const RUNTIME_SOURCE: &str = "/system_ext/gb-virt-bin-runtime-v1";
const RUNTIME_LIBRARIES: &str = "/system_ext/lib64/gb-runtime-v1";
const RUNTIME_INVENTORY: &str = "7e5464f77bbf2ee1024463c3d9f17d82146d28faf3ff6e40a658d83ae56440c4";
const RUNTIME_INVENTORY_BYTES: u64 = 2437;
const TARGET: &str = "/apex/com.android.virt/bin";
const ADAPTER: &str = "6a344973665260a114e08ee86d100b7d550ef8efcc998bb1edcc839a6d940789";
const FULL: &str = "cc9f1e31025f2826ae050d025c363c885c0d055bff42c18701a2aa507c28fb52";
const MINIMAL: &str = "a4cf07e09e80e8c4febbc9dd52e3ed72988d3bef4bf6134d81757c967eb74110";
const IRQ_FULL: &str = "9335435b9f4f09a29580e2c0773f0e715b603f9f456a4bd05dd95c03b1d6c499";
const TERMINAL_ADAPTER: &str = "2d278834378c1fbcad7d4dad415ee95c4a3d94ca97a70c9de34f4e749e7ef463";

#[derive(Clone, Copy, Debug)]
enum Bundle {
    Memory,
    Irq,
    Terminal,
    Runtime,
}
impl Bundle {
    fn source(self) -> &'static str {
        match self {
            Self::Memory => MEMORY_SOURCE,
            Self::Irq => IRQ_SOURCE,
            Self::Terminal => TERMINAL_SOURCE,
            Self::Runtime => RUNTIME_SOURCE,
        }
    }
    fn mount_root(self) -> &'static str {
        match self {
            Self::Memory => "/gb-virt-bin-memory-v1",
            Self::Irq => "/gb-virt-bin-irq-v1",
            Self::Terminal => "/gb-virt-bin-terminal-v1",
            Self::Runtime => "/gb-virt-bin-runtime-v1",
        }
    }
}

fn verify(path: &Path, bytes: u64, digest: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the descriptor and output buffer are valid for this call.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatvfs successfully initialized stat.
    let readonly = unsafe { stat.assume_init() }.f_flag & libc::ST_RDONLY != 0;
    if !metadata.is_file() || metadata.len() != bytes || !readonly {
        return Err(io::Error::other("expected immutable pinned VMM file"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    let mut remaining = bytes;
    while remaining > 0 {
        let bound = remaining.min(buffer.len() as u64) as usize;
        let n = file.read(&mut buffer[..bound])?;
        if n == 0 {
            return Err(io::Error::other("truncated VMM"));
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if file.read(&mut buffer[..1])? != 0 || format!("{:x}", hash.finalize()) != digest {
        return Err(io::Error::other("VMM digest differs"));
    }
    Ok(())
}

fn owned_mount(mountinfo: &str, target: &str, bundle: Bundle) -> io::Result<bool> {
    let mut found = false;
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 || !fields.contains(&"-") {
            return Err(io::Error::other("invalid mountinfo"));
        }
        if fields[4] == target {
            if found || fields[3] != bundle.mount_root() {
                return Err(io::Error::other("foreign or stacked bin mount"));
            }
            found = true;
        }
    }
    Ok(found)
}

fn current_mount(target: &str, bundle: Bundle) -> io::Result<bool> {
    let mut input = Vec::new();
    fs::File::open("/proc/self/mountinfo")?
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.len() > 2 * 1024 * 1024 {
        return Err(io::Error::other("mountinfo bound"));
    }
    let text = std::str::from_utf8(&input).map_err(io::Error::other)?;
    owned_mount(text, target, bundle)
}

fn verify_target(target: &Path, mounted: bool, bundle: Bundle) -> io::Result<()> {
    match (mounted, bundle) {
        (true, Bundle::Memory) => {
            verify(&target.join("crosvm"), 623808, ADAPTER)?;
            verify(&target.join("crosvm_minimal"), 623808, ADAPTER)
        }
        (true, Bundle::Irq) => {
            verify(&target.join("crosvm"), 13417312, IRQ_FULL)?;
            verify(&target.join("crosvm_minimal"), 6260984, MINIMAL)
        }
        (true, Bundle::Terminal) => {
            verify(&target.join("crosvm"), 624320, TERMINAL_ADAPTER)?;
            verify(&target.join("crosvm_minimal"), 6260984, MINIMAL)
        }
        (true, Bundle::Runtime) => verify_runtime(target),
        (false, _) => {
            verify(&target.join("crosvm"), 13417312, FULL)?;
            verify(&target.join("crosvm_minimal"), 6260984, MINIMAL)
        }
    }
}

fn verify_runtime(root: &Path) -> io::Result<()> {
    let manifest = root.join("bundle.sha256");
    verify(&manifest, RUNTIME_INVENTORY_BYTES, RUNTIME_INVENTORY)?;
    let mut input = String::new();
    fs::File::open(manifest)?
        .take(32769)
        .read_to_string(&mut input)?;
    let entries = pinned_bundle::parse(&input)?;
    pinned_bundle::verify_tree(root, &entries)?;
    // The APEX linker namespace permits system_ext/lib64, not bin/runtime/lib64.
    // The separate private directory must contain precisely the same pinned
    // libraries; its inventory is derived from the authenticated main inventory.
    let inventory = runtime_library_inventory(&entries)?;
    let libraries = Path::new(RUNTIME_LIBRARIES);
    let digest = format!("{:x}", Sha256::digest(inventory.as_bytes()));
    verify(
        &libraries.join("bundle.sha256"),
        inventory.len() as u64,
        &digest,
    )?;
    let library_entries = pinned_bundle::parse(&inventory)?;
    pinned_bundle::verify_tree(libraries, &library_entries)?;
    for entry in library_entries {
        verify(&libraries.join(entry.path), entry.bytes, entry.digest)?;
    }
    for entry in entries {
        verify(&root.join(entry.path), entry.bytes, entry.digest)?;
    }
    Ok(())
}

fn runtime_library_inventory(entries: &[pinned_bundle::Entry<'_>]) -> io::Result<String> {
    const PREFIX: &str = "runtime/lib64/";
    const NAMES: [&str; 4] = [
        "libgfxstream_backend.so",
        "libvirglrenderer.so",
        "libvncserver.so",
        "libvulkan_freedreno.so",
    ];
    if entries
        .iter()
        .filter(|e| e.path.starts_with(PREFIX))
        .count()
        != NAMES.len()
    {
        return Err(io::Error::other("private library inventory count differs"));
    }
    let mut inventory = String::new();
    for name in NAMES {
        let path = format!("{PREFIX}{name}");
        let entry = entries
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| io::Error::other("required private library absent"))?;
        inventory.push_str(&format!("{} {} {name}\n", entry.digest, entry.bytes));
    }
    Ok(inventory)
}

fn run(enable: bool, bundle: Bundle) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other("init root worker required"));
    }
    let source = Path::new(bundle.source());
    verify_target(source, true, bundle)?;
    if matches!(bundle, Bundle::Memory) {
        verify(&source.join("gb-crosvm-real"), 13417312, FULL)?;
        verify(&source.join("gb-crosvm-minimal-real"), 6260984, MINIMAL)?;
    }
    if matches!(bundle, Bundle::Terminal) {
        verify(&source.join("gb-crosvm-real"), 13417312, IRQ_FULL)?;
    }
    let target = fs::canonicalize(TARGET)?;
    let target_text = target
        .to_str()
        .ok_or_else(|| io::Error::other("target encoding"))?;
    let mounted = current_mount(target_text, bundle)?;
    verify_target(&target, mounted, bundle)?;
    if mounted != enable {
        let destination = CString::new(target_text).map_err(io::Error::other)?;
        let source = CString::new(bundle.source()).map_err(io::Error::other)?;
        // SAFETY: fixed verified NUL-terminated paths. No remount, recursive
        // propagation change, lazy unmount, device write or executable launch.
        let result = unsafe {
            if enable {
                libc::mount(
                    source.as_ptr(),
                    destination.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            } else {
                libc::umount2(destination.as_ptr(), 0)
            }
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if current_mount(target_text, bundle)? != enable {
        return Err(io::Error::other("mount result differs"));
    }
    verify_target(&target, enable, bundle)?;
    println!(
        "gb-terminal-mount: bundle={bundle:?}; enabled={enable}; namespace={}",
        fs::read_link("/proc/self/ns/mnt")?.display()
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (enable, bundle) = match args.as_slice() {
        [mode] if mode == "enable" => (true, Bundle::Memory),
        [mode] if mode == "disable" => (false, Bundle::Memory),
        [mode] if mode == "enable-irq" => (true, Bundle::Irq),
        [mode] if mode == "disable-irq" => (false, Bundle::Irq),
        [mode] if mode == "enable-terminal" => (true, Bundle::Terminal),
        [mode] if mode == "disable-terminal" => (false, Bundle::Terminal),
        [mode] if mode == "enable-runtime" => (true, Bundle::Runtime),
        [mode] if mode == "disable-runtime" => (false, Bundle::Runtime),
        _ => {
            return Err(io::Error::other(
                "expected enable/disable, enable-irq/disable-irq, enable-terminal/disable-terminal or enable-runtime/disable-runtime; paths are fixed",
            ));
        }
    };
    run(enable, bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn external_libraries_are_derived_from_the_pinned_inventory() {
        let names = [
            "libgfxstream_backend.so",
            "libvirglrenderer.so",
            "libvncserver.so",
            "libvulkan_freedreno.so",
        ];
        let input = names
            .iter()
            .rev()
            .map(|name| format!("{} 7 runtime/lib64/{name}\n", "a".repeat(64)))
            .collect::<String>();
        let entries = pinned_bundle::parse(&input).unwrap();
        let inventory = runtime_library_inventory(&entries).unwrap();
        let external = pinned_bundle::parse(&inventory).unwrap();
        assert_eq!(external.iter().map(|e| e.path).collect::<Vec<_>>(), names);
        assert!(
            external
                .iter()
                .all(|e| e.bytes == 7 && e.digest == "a".repeat(64))
        );
        assert!(runtime_library_inventory(&entries[..2]).is_err());
        for unexpected in ["libother.so", "nested/libvncserver.so"] {
            let changed = input.replace(
                "runtime/lib64/libvncserver.so",
                &format!("runtime/lib64/{unexpected}"),
            );
            assert!(runtime_library_inventory(&pinned_bundle::parse(&changed).unwrap()).is_err());
        }
        let extra = format!("{input}{} 7 runtime/lib64/libother.so\n", "a".repeat(64));
        assert!(runtime_library_inventory(&pinned_bundle::parse(&extra).unwrap()).is_err());
    }
    #[test]
    fn refuses_foreign_stacked_and_malformed_mounts() {
        let target = "/apex/com.android.virt/bin";
        let own = "40 20 0:8 /gb-virt-bin-memory-v1 /apex/com.android.virt/bin ro - erofs /dev/block/dm-8 ro\n";
        assert!(owned_mount(own, target, Bundle::Memory).unwrap());
        assert!(!owned_mount("20 1 0:1 / / ro - erofs dm ro\n", target, Bundle::Memory).unwrap());
        assert!(
            owned_mount(
                &own.replace("/gb-virt-bin-memory-v1", "/other"),
                target,
                Bundle::Memory
            )
            .is_err()
        );
        assert!(owned_mount(&(own.to_owned() + own), target, Bundle::Memory).is_err());
        assert!(owned_mount("invalid", target, Bundle::Memory).is_err());
        assert!(owned_mount(own, target, Bundle::Irq).is_err());
        let irq = own.replace("/gb-virt-bin-memory-v1", "/gb-virt-bin-irq-v1");
        assert!(owned_mount(&irq, target, Bundle::Irq).unwrap());
        assert!(owned_mount(&irq, target, Bundle::Memory).is_err());
        let terminal = own.replace("/gb-virt-bin-memory-v1", "/gb-virt-bin-terminal-v1");
        assert!(owned_mount(&terminal, target, Bundle::Terminal).unwrap());
        assert!(owned_mount(&irq, target, Bundle::Terminal).is_err());
        assert!(owned_mount(&terminal, target, Bundle::Irq).is_err());
        let runtime = own.replace("/gb-virt-bin-memory-v1", "/gb-virt-bin-runtime-v1");
        assert!(owned_mount(&runtime, target, Bundle::Runtime).unwrap());
        assert!(owned_mount(&runtime, target, Bundle::Terminal).is_err());
        assert!(owned_mount(&terminal, target, Bundle::Runtime).is_err());
    }
}
