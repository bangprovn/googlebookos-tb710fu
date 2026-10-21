//! Fixed device-attribute setup in the existing ueventd domain, invoked by init.
//! No arguments, VM operation, policy change, relabel, or general path interface.
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, chown},
};

const NODE: &str = "/dev/gunyah_share";
const SYSFS: &str = "/sys/class/misc/gunyah_share/dev";
const VM_GROUP: u32 = 3013;

fn expected_rdev(text: &str) -> io::Result<u64> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let Some(minor) = text.strip_prefix("10:") else {
        return Err(io::Error::other("expected misc device major"));
    };
    if minor.is_empty() || minor.len() > 3 || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other("invalid misc device minor"));
    }
    let minor: u8 = minor.parse().map_err(io::Error::other)?;
    Ok((10 << 8) | u64::from(minor))
}

fn validate_node(meta: &fs::Metadata, rdev: u64) -> io::Result<()> {
    if !meta.file_type().is_char_device()
        || meta.rdev() != rdev
        || meta.uid() != 0
        || ![0, VM_GROUP].contains(&meta.gid())
        || ![0o600, 0o660].contains(&(meta.mode() & 0o7777))
    {
        return Err(io::Error::other(
            "unexpected runtime-sharing device attributes",
        ));
    }
    Ok(())
}

fn run() -> io::Result<()> {
    if std::env::args_os().len() != 1 {
        return Err(io::Error::other("no arguments accepted"));
    }
    let mut context = String::new();
    fs::File::open("/proc/self/attr/current")?
        .take(129)
        .read_to_string(&mut context)?;
    if context.trim_end_matches(['\0', '\n']) != "u:r:ueventd:s0" {
        return Err(io::Error::other("init-invoked ueventd domain required"));
    }
    let mut identity = String::new();
    fs::File::open(SYSFS)?
        .take(17)
        .read_to_string(&mut identity)?;
    let rdev = expected_rdev(&identity)?;
    let parent = fs::symlink_metadata("/dev")?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err(io::Error::other("trusted device directory required"));
    }
    // /dev is a root-owned non-writable directory, and the path is fixed.
    // symlink_metadata refuses a substituted symlink or non-character object.
    let before = fs::symlink_metadata(NODE)?;
    validate_node(&before, rdev)?;
    chown(NODE, Some(0), Some(VM_GROUP))?;
    fs::set_permissions(NODE, fs::Permissions::from_mode(0o660))?;
    let after = fs::symlink_metadata(NODE)?;
    validate_node(&after, rdev)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.gid() != VM_GROUP
        || after.mode() & 0o7777 != 0o660
    {
        return Err(io::Error::other(
            "runtime-sharing node changed during setup",
        ));
    }
    Ok(())
}

fn main() -> io::Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn misc_identity_is_bounded_and_exact() {
        assert_eq!(expected_rdev("10:120\n").unwrap(), 0xa78);
        assert_eq!(expected_rdev("10:255").unwrap(), 0xaff);
        for input in [
            "",
            "1:120",
            "10:",
            "10:256",
            "10:-1",
            "10: 1",
            "10:1\nextra",
            "10:0000",
        ] {
            assert!(expected_rdev(input).is_err(), "{input}");
        }
    }
    #[test]
    fn regular_files_and_symlink_substitutions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node");
        fs::write(&path, b"fixture").unwrap();
        assert!(validate_node(&fs::symlink_metadata(&path).unwrap(), 0xa78).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(validate_node(&fs::symlink_metadata(&path).unwrap(), 0xa78).is_err());
        assert!(validate_node(&fs::metadata("/dev/null").unwrap(), 0xa78).is_err());
    }
}
