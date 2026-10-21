//! Scoped donor-argv bridge to a separately built host-accessible Gunyah backend.
//! Installation and input hashes are enforced by the image/bundle controller.
use std::{ffi::OsString, os::unix::process::CommandExt, process::Command};

#[path = "support/android_metadata_log.rs"]
mod android_metadata_log;
#[path = "support/host_image_probe.rs"]
mod host_image_probe;
#[path = "support/venus_gpu.rs"]
mod venus_gpu;

const DEFAULT: &str = "crosvm_debian";
const PROBE: &str = "crosvm_gb-runtime-share-probe-";

fn configure_image_bridge(command: &mut Command, private_venus: bool, name: Option<&str>) {
    // An inherited diagnostic flag must never change an unrelated VM profile.
    command.env_remove("GB_ANDROID_IMAGE_BRIDGE_V1");
    if private_venus && name == Some(DEFAULT) {
        command.env("GB_ANDROID_IMAGE_BRIDGE_V1", "diagnostic-linear-v1");
    }
}

fn selected(name: &str) -> bool {
    name == DEFAULT
        || name.strip_prefix(PROBE).is_some_and(|s| {
            !s.is_empty() && s.len() <= 24 && s.bytes().all(|b| b.is_ascii_digit())
        })
}

fn preferred_parcel(args: &[OsString]) -> Result<&'static str, &'static str> {
    if option(args, "--name")? == Some("crosvm_gb-runtime-share-probe-64")
        && option(args, "--mem")? != Some("2048")
    {
        return Err("64 MiB parcel diagnostic requires 2048 MiB guest RAM");
    }
    Ok(if option(args, "--mem")? == Some("2048") {
        "64"
    } else {
        "16"
    })
}

fn console_input_fd(args: &[OsString]) -> Result<i32, &'static str> {
    let mut result = None;
    for (i, arg) in args.iter().enumerate() {
        let Some(arg) = arg.to_str() else { continue };
        let spec = if arg == "--serial" {
            Some(
                args.get(i + 1)
                    .and_then(|s| s.to_str())
                    .ok_or("missing serial value")?,
            )
        } else {
            arg.strip_prefix("--serial=")
        };
        let Some(spec) = spec else { continue };
        let mut hardware = None;
        let mut number = None;
        let mut input = None;
        let mut kind = None;
        for field in spec.split(',') {
            if let Some((key, value)) = field.split_once('=') {
                let target = match key {
                    "hardware" => &mut hardware,
                    "num" => &mut number,
                    "input" => &mut input,
                    "type" => &mut kind,
                    _ => continue,
                };
                if target.replace(value).is_some() {
                    return Err("duplicate serial gate field");
                }
            }
        }
        if hardware != Some("virtio-console") || number != Some("1") || kind != Some("file") {
            continue;
        }
        let Some(input) = input else { continue };
        let raw = input
            .strip_prefix("/proc/self/fd/")
            .ok_or("gate input must be an inherited descriptor")?;
        if raw.is_empty() || raw.len() > 4 || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid gate input number");
        }
        let fd = raw
            .parse::<i32>()
            .map_err(|_| "invalid gate input number")?;
        if !(3..4096).contains(&fd) || result.replace(fd).is_some() {
            return Err("invalid or ambiguous inherited console input");
        }
    }
    result.ok_or("native diagnostic needs one inherited hvc0 input")
}

fn option<'a>(args: &'a [OsString], key: &str) -> Result<Option<&'a str>, &'static str> {
    let mut found = None;
    for (i, a) in args.iter().enumerate() {
        let Some(a) = a.to_str() else { continue };
        let v = if a == key {
            Some(
                args.get(i + 1)
                    .and_then(|v| v.to_str())
                    .filter(|v| !v.starts_with("--"))
                    .ok_or("missing option value")?,
            )
        } else {
            a.strip_prefix(key).and_then(|v| v.strip_prefix('='))
        };
        if let Some(v) = v
            && found.replace(v).is_some()
        {
            return Err("duplicate selected option");
        }
    }
    Ok(found)
}

fn replace_option(args: &mut [OsString], key: &str, value: &str) {
    for i in 0..args.len() {
        if args[i] == key {
            args[i + 1] = value.into();
            return;
        }
        if args[i]
            .to_str()
            .is_some_and(|a| a.starts_with(&format!("{key}=")))
        {
            args[i] = format!("{key}={value}").into();
            return;
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Adaptation {
    backend_selected: bool,
    reset_default_memory_applied: bool,
    mediated_display: bool,
    readonly_memslots_already_disabled: bool,
    its_allowance_not_implemented_by_gunyah: bool,
    private_venus: bool,
}

fn adapt(args: &mut Vec<OsString>) -> Result<Adaptation, &'static str> {
    // Only parse a strict contract after finding an exact selected name.
    let candidate = args.iter().enumerate().any(|(i, a)| {
        a.to_str().is_some_and(|a| {
            if a == "--name" {
                args.get(i + 1)
                    .and_then(|v| v.to_str())
                    .is_some_and(selected)
            } else {
                a.strip_prefix("--name=").is_some_and(selected)
            }
        })
    });
    if !candidate {
        return Ok(Adaptation::default());
    }
    let mut output = args.clone();
    let name = option(args, "--name")?.ok_or("selected name required")?;
    if args.len() > 1024 || args.iter().any(|a| a.len() > 65536) {
        return Err("selected argv exceeds budget");
    }
    if args.iter().filter(|a| *a == "run").count() != 1 {
        return Err("run command required");
    }
    let memory = option(args, "--mem")?.ok_or("memory required")?;
    // Fresh Terminal data restores the donor's 4096 MiB preference. Keep this
    // device policy in immutable firmware, independent of Android user IDs and
    // app-data seeders. Only the original default VM's exact donor allocation
    // is translated; diagnostic and unrelated VM contracts stay unchanged.
    let reset_default_memory_applied = name == DEFAULT && memory == "4096";
    if reset_default_memory_applied {
        replace_option(&mut output, "--mem", "2048");
    } else if !(memory == "2048" || (name != DEFAULT && memory == "512")) {
        return Err("selected memory must be 2048 MiB, or 512 MiB for a diagnostic probe");
    }
    if args.iter().any(|a| {
        a.to_str().is_some_and(|a| {
            a.starts_with("--protected-vm")
                || a.starts_with("--unprotected-vm-with-firmware")
                || a == "--swiotlb"
                || a.starts_with("--swiotlb=")
                || a.starts_with("--hugepages=")
        })
    }) {
        return Err("selected input must request ordinary host-accessible memory");
    }
    match option(args, "--hypervisor")? {
        Some("gunyah") => {}
        Some(_) => return Err("selected backend must be Gunyah"),
        None => output.push("--hypervisor=gunyah".into()),
    }
    let mut result = Adaptation {
        backend_selected: true,
        reset_default_memory_applied,
        ..Adaptation::default()
    };
    if let Some(display) = option(args, "--android-display-service")? {
        if name != DEFAULT {
            return Err("AVF display mediation requires the original default profile");
        }
        let cid_text =
            option(args, "--cid")?.ok_or("AVF display requires an explicit guest CID")?;
        let cid = cid_text
            .parse::<i32>()
            .ok()
            .filter(|cid| *cid >= 3 && cid.to_string() == cid_text)
            .ok_or("AVF display requires a canonical positive VM CID")?;
        // The legacy option selects a display label, not a VM identity. Only
        // --cid supplies identity for the private mica registration. Preserve
        // supported screen/transport ceilings while replacing just the label.
        let display = translate_display_selector(display, &cid.to_string())?;
        replace_option(&mut output, "--android-display-service", &display);
        result.mediated_display = true;
    }
    match option(args, "--irqchip")? {
        Some("kernel[allow-vgic-its=true]") | Some("kernel[allow-vgic-its=false]") => {
            // This is an allowance, not a requirement to provide ITS. Both donor
            // and fork Gunyah lack MSI support; the fork uses the older enum syntax.
            replace_option(&mut output, "--irqchip", "kernel");
            result.its_allowance_not_implemented_by_gunyah = true;
        }
        Some("kernel") | None => {}
        Some(_) => return Err("unsupported selected IRQ-controller request"),
    }
    let mut readonly_count = 0;
    for a in args.iter() {
        if a == "--force-disable-readonly-mem" {
            readonly_count += 1;
        } else if a
            .to_str()
            .is_some_and(|a| a.starts_with("--force-disable-readonly-mem="))
        {
            return Err("readonly workaround is a switch, not an option");
        }
    }
    if readonly_count > 1 {
        return Err("duplicate readonly workaround");
    }
    if readonly_count == 1 {
        // The donor documents this as KVM-only. Both Gunyah implementations
        // already return false for VmCap::ReadOnlyMemoryRegion. Preserve that
        // requested behavior instead of passing an unknown fork CLI option.
        output.retain(|a| a != "--force-disable-readonly-mem");
        result.readonly_memslots_already_disabled = true;
    }
    if name == DEFAULT {
        let gpu = option(args, "--gpu")?.ok_or("original profile GPU contract missing")?;
        let gpu = venus_gpu::parameters(gpu)?;
        replace_option(&mut output, "--gpu", &gpu);
        result.private_venus = true;
    }
    output.push("--protected-vm-pseudo-unprotected".into());
    if !args.iter().any(|a| a == "--hugepages") {
        output.push("--hugepages".into());
    }
    *args = output;
    Ok(result)
}

fn translate_display_selector(selector: &str, cid: &str) -> Result<String, &'static str> {
    if selector.is_empty() || selector.len() > 512 {
        return Err("legacy display selector exceeds its bounds");
    }
    let mut name = false;
    let mut screen = false;
    let mut transport = false;
    let mut output = Vec::new();
    for (index, field) in selector.split(',').enumerate() {
        let (key, value, bare) = if let Some((key, value)) = field.split_once('=') {
            (key, value, false)
        } else if index == 0 {
            ("name", field, true)
        } else {
            return Err("display selector has an unkeyed trailing field");
        };
        match key {
            "name" => {
                if name
                    || value.is_empty()
                    || value.len() > 256
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b))
                {
                    return Err("display selector has an invalid or duplicate label");
                }
                name = true;
                output.push(if bare {
                    cid.to_string()
                } else {
                    format!("name={cid}")
                });
            }
            "screen" => {
                if screen || !matches!(value, "gpu-0" | "simplefb") {
                    return Err("display selector has an unsupported or duplicate screen");
                }
                screen = true;
                output.push(field.to_string());
            }
            "transport-cap" => {
                if transport || !matches!(value, "auto" | "cpu" | "gpu" | "gpu-hw") {
                    return Err(
                        "display selector has an unsupported or duplicate transport ceiling",
                    );
                }
                transport = true;
                output.push(field.to_string());
            }
            _ => return Err("display selector has an unsupported field"),
        }
    }
    if !name {
        return Err("display selector requires one legacy label");
    }
    Ok(output.join(","))
}

fn display_contract_metadata(args: &[OsString]) -> String {
    fn count(args: &[OsString], key: &str) -> usize {
        args.iter()
            .filter(|v| {
                v.to_str().is_some_and(|s| {
                    s == key || s.strip_prefix(key).is_some_and(|v| v.starts_with('='))
                })
            })
            .count()
    }
    fn shape(value: Result<Option<&str>, &'static str>) -> &'static str {
        match value {
            Ok(None) => "absent",
            Err(_) => "missing_or_ambiguous",
            Ok(Some(v))
                if v.parse::<i32>()
                    .ok()
                    .is_some_and(|x| x >= 3 && x.to_string() == v) =>
            {
                "canonical_cid"
            }
            Ok(Some(v)) if v.contains(',') || v.contains('=') => "structured",
            Ok(Some(v))
                if !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b)) =>
            {
                "name"
            }
            Ok(Some(_)) => "other",
        }
    }
    let display = option(args, "--android-display-service");
    let cid = option(args, "--cid");
    format!(
        "gb-runtime-adapter: display_contract selector_count={} selector_shape={} selector_is_debian={} cid_count={} cid_shape={}",
        count(args, "--android-display-service"),
        shape(display),
        display == Ok(Some("debian")),
        count(args, "--cid"),
        shape(cid)
    )
}

fn main() {
    if let Err(e) = run() {
        android_metadata_log::emit(&format!("gb-runtime-adapter: {e}"));
        std::process::exit(125);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let base = exe.parent().ok_or("executable directory missing")?;
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    if option(&args, "--name").ok().flatten() == Some(DEFAULT) && args.len() <= 1024 {
        android_metadata_log::emit(&display_contract_metadata(&args));
    }
    let result = adapt(&mut args)?;
    if result.reset_default_memory_applied {
        android_metadata_log::emit(
            "gb-runtime-adapter: reset_default_memory_mib=4096 effective_memory_mib=2048 policy=tb710fu",
        );
    }
    let parcel = if result.backend_selected {
        preferred_parcel(&args)?
    } else {
        "16"
    };
    let coordinated = result.backend_selected
        && option(&args, "--name")? == Some("crosvm_gb-runtime-share-probe-64");
    let gate_fd = if coordinated {
        Some(console_input_fd(&args)?)
    } else {
        None
    };
    let variant = match exe.file_name().and_then(|s| s.to_str()) {
        Some("crosvm") => "crosvm",
        Some("crosvm_minimal") => "crosvm_minimal",
        _ => return Err("unexpected installed adapter name".into()),
    };
    let target = if result.backend_selected {
        base.join("runtime/bin/crosvm")
    } else {
        // Keep the retained adapter's basename: its own installation guard
        // distinguishes crosvm from crosvm_minimal. Its retained real VMM stays
        // at the original APEX-relative alias expected by the installed bundle.
        base.join("fallback").join(variant)
    };
    let mut command = Command::new(target);
    configure_image_bridge(&mut command, result.private_venus, option(&args, "--name")?);
    if result.private_venus && option(&args, "--name")? == Some(DEFAULT) {
        let diagnostic = host_image_probe::run(base);
        if diagnostic != "image_probe outcome=disabled" {
            android_metadata_log::emit(&format!("gb-runtime-adapter: {diagnostic}"));
        }
    }
    command
        .arg0(std::env::args_os().next().ok_or("argv0 missing")?)
        .args(args);
    // Allocation policy belongs to the selected original Terminal profile.
    command.env_remove("GB_VENUS_GUEST_VRAM_V1");
    command.env_remove("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1");
    if result.backend_selected {
        let mut libraries = base.join("runtime/lib64").into_os_string();
        if let Some(existing) = std::env::var_os("LD_LIBRARY_PATH") {
            libraries.push(":");
            libraries.push(existing);
        }
        command.env("LD_LIBRARY_PATH", libraries);
        // Prefer 16 MiB parcels. The paired ABI-v4 VMM retries a pre-transfer
        // E2BIG with smaller 2 MiB-aligned ranges, down to the 512-page bound.
        // The kernel's tighter span guard and byte quotas remain authoritative.
        command.env("DROIDVM_SHIM_PARCEL_MB", parcel);
        // Every selected profile has an explicit supported RAM size. Pool use
        // is independent of the optional native diagnostic input handshake.
        command.env("DROIDVM_RAM_POOL_REQUIRED", "1");
        if result.private_venus {
            command.env("ANDROID_EMU_VK_LOADER_PATH", venus_gpu::DRIVER);
            command.env("GB_VENUS_GUEST_VRAM_V1", "host");
            command.env("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1", "1");
            // The VMM udmabuf GPU option does not select Venus's allocator.
            // Use its existing shared-page allocator only for this profile.
            command.env("VKR_DEBUG", "udmabuf");
            android_metadata_log::emit(
                "gb-runtime-adapter: guest_vulkan=venus driver=private_turnip udmabuf=true memory_backing=host host_allocator=udmabuf existing_gles_preserved=true",
            );
        }
        if result.mediated_display {
            command.env("GB_AVF_DISPLAY_SERVICE", "mica_v17");
            android_metadata_log::emit(
                "gb-runtime-adapter: avf_display_service=mica_v17 cid_binding_verified=true",
            );
        } else {
            command.env_remove("GB_AVF_DISPLAY_SERVICE");
        }
        // Use only the console-input capability already supplied by AVF. No
        // filesystem lookup or path-search permission is needed by the gate.
        command.env_remove("DROIDVM_PREPIN_CONTROL_DIR");
        if let Some(fd) = gate_fd {
            command.env("DROIDVM_PREPIN_PIPE_FD", fd.to_string());
        } else {
            command.env_remove("DROIDVM_PREPIN_PIPE_FD");
        }
        android_metadata_log::emit(&format!(
            "gb-runtime-adapter: host_accessible=true readonly_memslots_disabled={} its_unimplemented={} memory_cap_mib=2048 runtime_parcel_mib={} handoff_abi=4 adaptive_min_parcel_mib=2 max_unaccepted_parcels=1",
            result.readonly_memslots_already_disabled,
            result.its_allowance_not_implemented_by_gunyah,
            parcel
        ));
    }
    // Never print argv: the opaque kernel parameters contain guest auth tokens.
    let error = command.exec();
    Err(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn image_bridge_selection_clears_unrelated_inherited_policies() {
        for (private, name, expected) in [
            (true, Some(DEFAULT), Some("diagnostic-linear-v1")),
            (false, Some(DEFAULT), None),
            (true, Some("crosvm_gb-runtime-share-probe-64"), None),
            (true, None, None),
        ] {
            let mut command = Command::new("/owned-not-executed");
            command.env(
                "GB_ANDROID_IMAGE_BRIDGE_V1",
                "unrelated-inherited-selection",
            );
            configure_image_bridge(&mut command, private, name);
            let value = command
                .get_envs()
                .find(|(key, _)| *key == "GB_ANDROID_IMAGE_BRIDGE_V1")
                .unwrap()
                .1;
            assert_eq!(value.and_then(|x| x.to_str()), expected);
        }
    }
    #[test]
    fn selects_only_the_explicit_inherited_hvc0_input() {
        let a = vec!["--serial=type=file,path=/proc/self/fd/33,hardware=serial,num=1".into(),
            "--serial=type=file,path=/proc/self/fd/33,input=/proc/self/fd/34,hardware=virtio-console,num=1,max-queue-sizes=[32,32]".into(),
            "--serial=type=sink,hardware=virtio-console,num=2".into()];
        assert_eq!(console_input_fd(&a).unwrap(), 34);
        let valid = "type=file,hardware=virtio-console,num=1,input=/proc/self/fd/34";
        assert_eq!(
            console_input_fd(&["--serial".into(), valid.into()]).unwrap(),
            34
        );
        for spec in [
            "type=file,hardware=virtio-console,num=1,input=/tmp/input",
            "type=file,hardware=virtio-console,num=1,input=/proc/self/fd/0",
            "type=file,hardware=virtio-console,num=1,input=/proc/self/fd/34,input=/proc/self/fd/35",
        ] {
            assert!(console_input_fd(&[format!("--serial={spec}").into()]).is_err());
        }
        assert!(
            console_input_fd(&[
                format!("--serial={valid}").into(),
                format!("--serial={valid}").into()
            ])
            .is_err()
        );
    }
    #[test]
    fn larger_parcels_apply_to_selected_2g_profiles() {
        for (name, memory, expected) in [
            ("crosvm_gb-runtime-share-probe-64", "2048", Some("64")),
            ("crosvm_gb-runtime-share-probe-64", "512", None),
            ("crosvm_gb-runtime-share-probe-1", "2048", Some("64")),
            ("crosvm_gb-runtime-share-probe-1", "512", Some("16")),
            (DEFAULT, "2048", Some("64")),
        ] {
            let a = vec![
                format!("--name={name}").into(),
                format!("--mem={memory}").into(),
            ];
            assert_eq!(preferred_parcel(&a).ok(), expected);
        }
    }
    fn args() -> Vec<OsString> {
        [
            "--extended-status",
            "run",
            "--name=crosvm_debian",
            "--mem=2048",
            "--irqchip=kernel[allow-vgic-its=true]",
            "--force-disable-readonly-mem",
            "--cpus=sve=[auto=true]",
            "--gpu=mode=gfxstream",
            "--params",
            "opaque-secret",
            "--net=tap-fd=12",
            "--block=path=/proc/self/fd/9",
        ]
        .map(OsString::from)
        .to_vec()
    }
    #[test]
    fn fresh_terminal_default_uses_2g_without_app_data_or_user_identity() {
        for split in [false, true] {
            let mut fresh = args();
            if split {
                fresh.splice(3..4, ["--mem".into(), "4096".into()]);
            } else {
                fresh[3] = "--mem=4096".into();
            }
            let result = adapt(&mut fresh).unwrap();
            assert!(result.reset_default_memory_applied);
            assert_eq!(option(&fresh, "--mem").unwrap(), Some("2048"));
            assert_eq!(preferred_parcel(&fresh).unwrap(), "64");
            let mut configured = args();
            assert!(!adapt(&mut configured).unwrap().reset_default_memory_applied);
            assert_eq!(option(&configured, "--mem").unwrap(), Some("2048"));
        }
    }
    #[test]
    fn reset_memory_policy_does_not_change_other_vm_contracts() {
        let mut unrelated = args();
        unrelated[2] = "--name=another-vm".into();
        unrelated[3] = "--mem=4096".into();
        let original = unrelated.clone();
        assert_eq!(adapt(&mut unrelated).unwrap(), Adaptation::default());
        assert_eq!(unrelated, original);
        for name in [
            "crosvm_gb-runtime-share-probe-1",
            "crosvm_gb-runtime-share-probe-64",
        ] {
            let mut probe = args();
            probe[2] = format!("--name={name}").into();
            probe[3] = "--mem=4096".into();
            let original = probe.clone();
            assert!(adapt(&mut probe).is_err());
            assert_eq!(probe, original);
        }
    }
    #[test]
    fn reset_memory_policy_rejects_ambiguous_or_invalid_requests_atomically() {
        for memory in [
            "",
            "04096",
            "+4096",
            "4096,hugepages=true",
            "8192",
            "512",
            "0",
        ] {
            let mut invalid = args();
            invalid[3] = format!("--mem={memory}").into();
            let original = invalid.clone();
            assert!(adapt(&mut invalid).is_err());
            assert_eq!(invalid, original);
        }
        for extra in ["--mem=4096", "--protected-vm", "--hypervisor=kvm"] {
            let mut invalid = args();
            invalid[3] = "--mem=4096".into();
            invalid.push(extra.into());
            let original = invalid.clone();
            assert!(adapt(&mut invalid).is_err());
            assert_eq!(invalid, original);
        }
    }
    #[test]
    fn display_contract_metadata_never_contains_option_values() {
        let mut input = args();
        input.extend(
            [
                "--cid=2048",
                "--android-display-service=fixture-private-selector",
            ]
            .map(OsString::from),
        );
        let text = display_contract_metadata(&input);
        assert!(text.contains("selector_shape=name") && text.contains("cid_shape=canonical_cid"));
        assert!(!text.contains("fixture-private-selector") && !text.contains("2048"));
        input.push("--android-display-service=other-private-value".into());
        assert!(
            display_contract_metadata(&input)
                .contains("selector_count=2 selector_shape=missing_or_ambiguous")
        );
    }
    #[test]
    fn display_registration_is_bound_to_the_original_profile_and_guest_cid() {
        let mut valid = args();
        valid.extend(["--cid=2048", "--android-display-service=2048"].map(OsString::from));
        assert!(adapt(&mut valid).unwrap().mediated_display);
        let mut named = args();
        named.extend(["--cid", "2048", "--android-display-service", "debian"].map(OsString::from));
        assert!(adapt(&mut named).unwrap().mediated_display);
        assert_eq!(
            option(&named, "--android-display-service").unwrap(),
            Some("2048")
        );
        for cid in ["", "2", "02048", "-1", "2147483648"] {
            let mut invalid = args();
            invalid.extend(
                [
                    format!("--cid={cid}"),
                    "--android-display-service=debian".into(),
                ]
                .map(OsString::from),
            );
            let before = invalid.clone();
            assert!(adapt(&mut invalid).is_err());
            assert_eq!(invalid, before);
        }
        let mut missing = args();
        missing.push("--android-display-service=debian".into());
        assert!(adapt(&mut missing).is_err());
        for display in [
            "",
            "has space",
            "name=",
            "name=x,name=y",
            "x,screen=other",
            "x,transport-cap=unknown",
            "x,unknown=1",
            "x\ny",
            "x,screen=gpu-0,screen=simplefb",
            "screen=gpu-0",
        ] {
            let mut invalid = args();
            invalid.push("--cid=2048".into());
            invalid.push(format!("--android-display-service={display}").into());
            let before = invalid.clone();
            assert!(adapt(&mut invalid).is_err());
            assert_eq!(invalid, before);
        }
        // Legacy labels may look numeric; none of them supplies VM identity.
        for label in [
            "debian",
            "other_vm",
            "0",
            "2",
            "02048",
            "2049",
            "-1",
            "2147483648",
            "android.crosvm.debian/0",
        ] {
            let mut input = args();
            input.extend(
                [
                    "--cid=2048".into(),
                    format!("--android-display-service={label}"),
                ]
                .map(OsString::from),
            );
            assert!(adapt(&mut input).unwrap().mediated_display);
            assert_eq!(
                option(&input, "--android-display-service").unwrap(),
                Some("2048")
            );
        }
        let mut structured = args();
        structured.extend(
            [
                "--cid=2048",
                "--android-display-service=name=legacy/0,screen=gpu-0,transport-cap=cpu",
            ]
            .map(OsString::from),
        );
        assert!(adapt(&mut structured).unwrap().mediated_display);
        assert_eq!(
            option(&structured, "--android-display-service").unwrap(),
            Some("name=2048,screen=gpu-0,transport-cap=cpu")
        );
        let mut duplicate = args();
        duplicate.extend(
            ["--cid=2048", "--cid=2049", "--android-display-service=2048"].map(OsString::from),
        );
        assert!(adapt(&mut duplicate).is_err());
        let mut native = args();
        native[2] = "--name=crosvm_gb-runtime-share-probe-1".into();
        native.extend(["--cid=2048", "--android-display-service=2048"].map(OsString::from));
        assert!(adapt(&mut native).is_err());
    }
    #[test]
    fn translates_known_gunyah_semantics_and_preserves_devices_and_opaque_bytes() {
        let mut a = args();
        a[9] = OsString::from_vec(vec![b'x', 0xff, b'y']);
        let secret = a[9].clone();
        let r = adapt(&mut a).unwrap();
        assert_eq!(
            r,
            Adaptation {
                backend_selected: true,
                reset_default_memory_applied: false,
                mediated_display: false,
                readonly_memslots_already_disabled: true,
                its_allowance_not_implemented_by_gunyah: true,
                private_venus: true
            }
        );
        assert_eq!(option(&a, "--irqchip").unwrap(), Some("kernel"));
        assert_eq!(option(&a, "--hypervisor").unwrap(), Some("gunyah"));
        for value in [
            "--cpus=sve=[auto=true]",
            "--gpu=mode=gfxstream,vulkan=true,udmabuf=true,context-types=virgl:virgl2:venus",
            "--net=tap-fd=12",
            "--block=path=/proc/self/fd/9",
            "--mem=2048",
            "--protected-vm-pseudo-unprotected",
            "--hugepages",
        ] {
            assert!(a.iter().any(|v| v == value));
        }
        assert!(a.contains(&secret));
    }
    #[test]
    fn unrelated_profiles_are_exact_passthrough() {
        for name in [
            "other",
            "crosvm_debian-extra",
            "crosvm_gb-runtime-share-probe-bad",
        ] {
            let mut a = args();
            a[2] = format!("--name={name}").into();
            let original = a.clone();
            assert!(!adapt(&mut a).unwrap().backend_selected);
            assert_eq!(a, original);
        }
    }
    #[test]
    fn refuses_changed_contract_without_partially_mutating_arguments() {
        for extra in [
            "--hypervisor=kvm",
            "--hypervisor=geniezone",
            "--protected-vm",
            "--protected-vm-pseudo-unprotected",
            "--swiotlb=6",
            "--mem=4096",
            "--name=crosvm_debian",
            "--force-disable-readonly-mem",
            "--hugepages=false",
        ] {
            let mut a = args();
            a.push(extra.into());
            let before = a.clone();
            assert!(adapt(&mut a).is_err(), "{extra}");
            assert_eq!(a, before);
        }
        let mut a = args();
        a[4] = "--irqchip=userspace".into();
        assert!(adapt(&mut a).is_err());
    }
    #[test]
    fn diagnostic_512_mib_and_split_options_are_explicit() {
        let mut a: Vec<_> = [
            "run",
            "--name",
            "crosvm_gb-runtime-share-probe-123",
            "--mem",
            "512",
            "--irqchip",
            "kernel",
            "--hypervisor=gunyah",
            "--hugepages",
        ]
        .map(OsString::from)
        .to_vec();
        assert!(adapt(&mut a).unwrap().backend_selected);
        assert_eq!(a.iter().filter(|v| *v == "--hugepages").count(), 1);
        let mut a = args();
        a[3] = "--mem=512".into();
        assert!(adapt(&mut a).is_err());
    }
}
