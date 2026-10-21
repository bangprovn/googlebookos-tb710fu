//! Android VMM argv adapter for exact owner-selected 2 GiB Terminal profiles.
//! Executes an immutable sibling VMM without changing authentication or payloads.
use std::{ffi::OsString, os::unix::process::CommandExt, path::Path, process::Command};

const TERMINAL: &str = "crosvm_gb-terminal-normal-2g-v1";
const PROBE: &str = "crosvm_gb-memory-adapter-probe-";
const DEFAULT_TERMINAL: &str = "crosvm_debian";

fn selected(name: &str) -> bool {
    name == TERMINAL
        || name == DEFAULT_TERMINAL
        || name.strip_prefix(PROBE).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.len() <= 24 && suffix.bytes().all(|b| b.is_ascii_digit())
        })
}

fn value<'a>(args: &'a [OsString], key: &str) -> Result<&'a str, &'static str> {
    let mut found = None;
    for (index, arg) in args.iter().enumerate() {
        let Some(text) = arg.to_str() else { continue };
        let candidate = if text == key {
            Some(
                args.get(index + 1)
                    .and_then(|x| x.to_str())
                    .filter(|x| !x.starts_with("--"))
                    .ok_or("missing or invalid selected-profile option value")?,
            )
        } else {
            text.strip_prefix(key).and_then(|x| x.strip_prefix('='))
        };
        if let Some(candidate) = candidate
            && found.replace(candidate).is_some()
        {
            return Err("duplicate selected-profile option");
        }
    }
    found.ok_or("selected-profile option missing")
}

/// Unrelated invocations are byte-for-byte pass-through. Selected invocations
/// have a deliberately narrow, versioned contract; unexpected inputs fail shut.
fn adapt(args: &mut Vec<OsString>) -> Result<bool, &'static str> {
    let candidate = args.iter().enumerate().any(|(index, arg)| {
        arg.to_str().is_some_and(|text| {
            if text == "--name" {
                args.get(index + 1)
                    .and_then(|x| x.to_str())
                    .is_some_and(selected)
            } else {
                text.strip_prefix("--name=").is_some_and(selected)
            }
        })
    });
    if !candidate {
        return Ok(false);
    }
    let name = value(args, "--name")?;
    if !selected(name) || !args.iter().any(|a| a == "run") || args.iter().any(|a| a == "--") {
        return Err("unexpected selected-profile command");
    }
    if name == DEFAULT_TERMINAL {
        // Observed original default app: normal VM, exactly 2048 MiB, no
        // SWIOTLB option. Preserve its GPU, devices, disks, CPU and protection.
        if value(args, "--mem")? != "2048"
            || args.iter().any(|arg| {
                arg.to_str().is_some_and(|a| {
                    a == "--protected-vm"
                        || a.starts_with("--protected-vm=")
                        || a == "--swiotlb"
                        || a.starts_with("--swiotlb=")
                })
            })
        {
            return Err("default Terminal must remain unprotected2048MiB without SWIOTLB");
        }
    } else {
        // Qualified protected probes add 6 MiB SWIOTLB to a 2048 MiB guest.
        if !args.iter().any(|a| a == "--protected-vm")
            || value(args, "--mem")? != "2054"
            || value(args, "--swiotlb")? != "6"
        {
            return Err("selected protected profile must request 2048MiB plus6MiB SWIOTLB");
        }
    }
    let huge: Vec<_> = args
        .iter()
        .filter_map(|x| x.to_str())
        .filter(|x| *x == "--hugepages" || x.starts_with("--hugepages="))
        .collect();
    if huge.len() > 1
        || huge
            .iter()
            .any(|x| !["--hugepages", "--hugepages=true"].contains(x))
    {
        return Err("conflicting huge-page option in selected profile");
    }
    if huge.is_empty() {
        args.push("--hugepages".into());
    }
    Ok(true)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os();
    let argv0 = args.next().ok_or("argv0 missing")?;
    // AVF may rename argv0. Prefer the actual executable basename while keeping
    // that caller-provided argv0 unchanged for the real VMM.
    let executable = std::env::current_exe().unwrap_or_else(|_| Path::new(&argv0).to_path_buf());
    let variant = match executable.file_name().and_then(|x| x.to_str()) {
        Some("crosvm") => "full",
        Some("crosvm_minimal") => "minimal",
        _ => return Err("install only as crosvm or crosvm_minimal".into()),
    };
    let mut args: Vec<_> = args.collect();
    let changed = adapt(&mut args)?;
    if changed {
        eprintln!("gb-crosvm-memory-v2: variant={variant} selected_profile=true hugepages=true");
    }
    let real = if variant == "full" {
        "/apex/com.android.virt/bin/gb-crosvm-real"
    } else {
        "/apex/com.android.virt/bin/gb-crosvm-minimal-real"
    };
    // Preserve environment, argv0, working directory and inherited descriptors.
    // exec() returns only on failure. No shell or firmware binary runs on host.
    Err(Command::new(real).arg0(argv0).args(args).exec().into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("gb-crosvm-memory-v2: {error}");
        std::process::exit(126);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(name: &str) -> Vec<OsString> {
        [
            "--extended-status",
            "run",
            "--name",
            name,
            "--protected-vm",
            "--mem",
            "2054",
            "--swiotlb",
            "6",
            "/proc/self/fd/33",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    #[test]
    fn selects_only_known_owner_profiles() {
        assert!(selected(TERMINAL));
        assert!(selected(DEFAULT_TERMINAL));
        assert!(selected(&format!("{PROBE}123")));
        for name in [
            "linux",
            "crosvm_gb-terminal-normal-v1",
            PROBE,
            "crosvm_gb-memory-adapter-probe-test",
        ] {
            assert!(!selected(name));
        }
    }
    #[test]
    fn default_terminal_preserves_normal_mode_and_requires_exact_memory_contract() {
        let original: Vec<OsString> = [
            "--extended-status",
            "run",
            "--name",
            DEFAULT_TERMINAL,
            "--mem",
            "2048",
            "--gpu",
            "backend=virglrenderer",
            "/proc/self/fd/38",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let mut adapted = original.clone();
        assert_eq!(adapt(&mut adapted), Ok(true));
        assert_eq!(&adapted[..original.len()], &original);
        assert_eq!(adapted.last().unwrap(), "--hugepages");
        assert_eq!(adapt(&mut adapted), Ok(true));
        assert_eq!(adapted.len(), original.len() + 1);
        for extra in [
            vec!["--protected-vm"],
            vec!["--protected-vm=true"],
            vec!["--swiotlb=6"],
            vec!["--swiotlb", "6"],
            vec!["--mem=2048"],
            vec!["--hugepages=false"],
        ] {
            let mut invalid = original.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(adapt(&mut invalid).is_err());
        }
        for size in ["1024", "2054", "4096"] {
            let mut invalid = original.clone();
            invalid[5] = size.into();
            assert!(adapt(&mut invalid).is_err());
        }
    }
    #[test]
    fn adds_only_hugepages_and_is_idempotent() {
        let mut a = args(TERMINAL);
        let original = a.clone();
        assert_eq!(adapt(&mut a), Ok(true));
        assert_eq!(&a[..original.len()], &original);
        assert_eq!(a.last().unwrap(), "--hugepages");
        let once = a.clone();
        assert_eq!(adapt(&mut a), Ok(true));
        assert_eq!(a, once);
    }
    #[test]
    fn unrelated_and_non_utf8_arguments_are_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let mut a = args("linux");
        a.push(OsString::from_vec(vec![255, 254]));
        let original = a.clone();
        assert_eq!(adapt(&mut a), Ok(false));
        assert_eq!(a, original);
    }
    #[test]
    fn refuses_changed_size_protection_duplicates_and_conflicts() {
        for (from, to) in [
            ("2054", "4102"),
            ("6", "64"),
            ("--protected-vm", "--unprotected-vm"),
        ] {
            let mut a = args(TERMINAL);
            *a.iter_mut().find(|x| *x == from).unwrap() = to.into();
            assert!(adapt(&mut a).is_err());
        }
        for extra in [
            vec!["--mem", "2054"],
            vec!["--hugepages=false"],
            vec!["--hugepages", "--hugepages"],
            vec!["--"],
        ] {
            let mut a = args(TERMINAL);
            a.extend(extra.into_iter().map(OsString::from));
            assert!(adapt(&mut a).is_err());
        }
    }
    #[test]
    fn recognizes_equals_options() {
        let mut a: Vec<_> = [
            "run",
            "--name=crosvm_gb-terminal-normal-2g-v1",
            "--protected-vm",
            "--mem=2054",
            "--swiotlb=6",
            "--hugepages=true",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let original = a.clone();
        assert_eq!(adapt(&mut a), Ok(true));
        assert_eq!(a, original);
    }
}
