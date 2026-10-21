use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use gb_core::{FirmwareManifest, run_tool, separate_from_input, write_json};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Duration,
};
mod runtime;

#[derive(Parser)]
#[command(
    name = "gb",
    version,
    about = "Read-only Googlebook firmware inspection and reproducible offline processing"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".gb-cache")]
    cache: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Donor {
        #[command(subcommand)]
        command: InspectCommand,
    },
    Firmware {
        #[command(subcommand)]
        command: InspectCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Compat {
        #[command(subcommand)]
        command: CompatCommand,
    },
    Port {
        #[command(subcommand)]
        command: PortCommand,
    },
    Flash {
        #[command(subcommand)]
        command: FlashCommand,
    },
    Doctor,
}
#[derive(Subcommand)]
enum InspectCommand {
    CollectText {
        request: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    AttachText {
        input: PathBuf,
        /// Image-inventory path=captured host file; existing SHA256 must match.
        #[arg(long = "text", required = true)]
        texts: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Analyze {
        request: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    NormalizeManifest {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Inspect {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Layout {
        input: PathBuf,
        #[arg(long)]
        gpt_partition: Option<String>,
        #[arg(long, default_value_t = 0)]
        slot: u32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Inventory {
        input: PathBuf,
        #[arg(long)]
        gpt_partition: Option<String>,
        #[arg(long, default_value_t = 0)]
        slot: u32,
        #[arg(long, required = true, value_delimiter = ',')]
        partitions: Vec<String>,
        #[arg(long)]
        tool: PathBuf,
        /// Required for ext4: read-only e2fsck host tool.
        #[arg(long)]
        check_tool: Option<PathBuf>,
        /// Immutable local Docker image ID. Omit to use bubblewrap.
        #[arg(long)]
        sandbox_image: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum DeviceCommand {
    Detect {
        #[arg(long, conflicts_with = "adb")]
        from: Option<PathBuf>,
        #[arg(long, conflicts_with = "from")]
        adb: bool,
        #[arg(long)]
        serial: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
#[derive(Args)]
struct Inputs {
    #[arg(long)]
    donor: PathBuf,
    #[arg(long)]
    device: PathBuf,
}
#[derive(Subcommand)]
enum CompatCommand {
    /// Assess bounded host EGL/AHardwareBuffer receipts; performs no device actions.
    HostImages {
        capabilities: PathBuf,
        #[arg(long = "sampling")]
        sampling: Vec<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check explicit init service/exec process labels against a compiled policy.
    InitProcesses {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Contexts {
        #[arg(long)]
        donor: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        recipe: PathBuf,
        #[arg(long)]
        policy_report: PathBuf,
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        device_observation: Option<PathBuf>,
        #[arg(long)]
        overlay_output: Option<PathBuf>,
        #[arg(long)]
        tool: PathBuf,
        #[arg(long)]
        sandbox_image: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Selinux {
        #[arg(long)]
        donor: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        recipe: PathBuf,
        #[arg(long)]
        tool: PathBuf,
        #[arg(long)]
        sandbox_image: Option<String>,
        /// Target /sys/fs/selinux/policyvers; never inferred from Android release.
        #[arg(long)]
        kernel_policy_version: u32,
        /// Desired binary policy format, bounded by the kernel maximum.
        #[arg(long)]
        policy_version: u32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Vintf {
        #[arg(long)]
        donor: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        recipe: PathBuf,
        #[arg(long)]
        tool: PathBuf,
        #[arg(long)]
        sandbox_image: Option<String>,
        #[arg(long, requires = "kernel_version")]
        kernel_config: Option<PathBuf>,
        #[arg(long, requires = "kernel_config")]
        kernel_version: Option<String>,
        #[arg(long = "property")]
        properties: Vec<String>,
        /// Publish guarded XML overlays and their static validation receipt.
        #[arg(long)]
        overlay_output: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Check {
        #[command(flatten)]
        inputs: Inputs,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Manifests {
        #[arg(long)]
        donor: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        device: Option<PathBuf>,
        #[arg(long)]
        recipe: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum PortCommand {
    /// Validate pinned, completed Terminal soak observations offline.
    ValidateTerminalSoak {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    InspectInitBoot {
        input: PathBuf,
        #[arg(long)]
        unpack: PathBuf,
        #[arg(long)]
        lz4: PathBuf,
        #[arg(long)]
        sandbox_image: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    InstrumentInit {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Capture read-only diagnostics from one explicitly selected ADB device.
    ProbeBoot {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        expected_fingerprint: String,
        #[arg(long, default_value = "adb")]
        adb: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    AssembleSuper {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    SignImages {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    AdaptVendorBoot {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Repack a checksum-pinned kernel-only boot v4 image offline.
    AdaptKernelBoot {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build a signed static boolean framework resource overlay offline.
    BuildFrameworkOverlay {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    AssemblePartition {
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    IntegrationPlan {
        #[arg(long)]
        donor_manifest: PathBuf,
        #[arg(long)]
        target_manifest: PathBuf,
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        recipe: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Plan {
        #[command(flatten)]
        inputs: Inputs,
        #[arg(long)]
        transforms: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Build {
        #[command(flatten)]
        inputs: Inputs,
        #[arg(long)]
        transforms: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        incremental: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Test {
        #[arg(long)]
        device: Option<PathBuf>,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long, required = true)]
        offline: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum FlashCommand {
    Plan {
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
    },
}
fn emit<T: serde::Serialize>(value: &T, out: Option<&Path>) -> Result<()> {
    if let Some(out) = out {
        write_json(out, value)?;
    }
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn configs(inputs: &Inputs) -> Result<(gb_config::Donor, gb_config::Profile)> {
    Ok((
        gb_config::donor(&gb_config::resolve(&inputs.donor, "donors"))?,
        gb_config::profile(&gb_config::resolve(&inputs.device, "devices"))?,
    ))
}
fn protect_report(inputs: &Inputs, out: Option<&Path>) -> Result<()> {
    if let Some(out) = out {
        let (donor, profile) = configs(inputs)?;
        separate_from_input(&donor.input, out)?;
        separate_from_input(&profile.firmware.input, out)?;
    }
    Ok(())
}
fn inspect_pair(
    inputs: &Inputs,
    cache: &Path,
) -> Result<(
    gb_config::Donor,
    gb_config::Profile,
    FirmwareManifest,
    FirmwareManifest,
)> {
    let (d, p) = configs(inputs)?;
    let ds = gb_firmware::input_digest(&d.input)?;
    if let Some(want) = &d.sha256 {
        ensure!(
            want == &ds,
            "donor SHA256 verification failed: expected {want}, got {ds}"
        );
    }
    let ts = gb_firmware::input_digest(&p.firmware.input)?;
    if let Some(want) = &p.firmware.sha256 {
        ensure!(want == &ts, "target SHA256 verification failed");
    }
    let (dm, _) = gb_build::inspect_cached(&d.input, cache, true)?;
    let (tm, _) = gb_build::inspect_cached(&p.firmware.input, cache, true)?;
    Ok((d, p, dm, tm))
}
fn plan(inputs: &Inputs, transforms: Option<&Path>, cache: &Path) -> Result<Value> {
    let (_, p, d, t) = inspect_pair(inputs, cache)?;
    let transforms = gb_config::transforms(transforms)?;
    let report = gb_compat::check(&d, &t, Some(&p));
    Ok(
        json!({"schema_version":1,"status":"blocked_rom_assembly","bootable":false,"device":p.device.codename,"dag":gb_build::graph(),"transformations":transforms,"preserve_target_partitions":p.firmware.preserve_partitions,"compatibility":report,"destructive_commands":[],"flash_strategy":p.boot.strategy}),
    )
}
fn detected(m: &FirmwareManifest) -> Value {
    json!({"schema_version":1,"source_sha256":m.source_sha256,"model":m.property("ro.product.model"),"codename":m.property("ro.product.device"),"architecture":m.architecture(),"android":m.property("ro.build.version.release"),"soc":m.property("ro.soc.model"),"soc_vendor":m.property("ro.soc.manufacturer"),"bootloader_state":m.property("ro.boot.vbmeta.device_state"),"evidence_status":"observed_in_input","hardware_runtime_verified":false,"limitations":m.limitations})
}
fn adb_detect(serial: Option<&str>) -> Result<Value> {
    let mut args = Vec::new();
    if let Some(serial) = serial {
        ensure!(!serial.is_empty(), "empty ADB serial");
        args.extend(["-s".into(), serial.into()]);
    }
    let mut check = args.clone();
    check.push("get-state".into());
    let state = run_tool(Path::new("adb"), &check, Duration::from_secs(10))?;
    ensure!(
        state.stdout.trim() == "device",
        "ADB device is not authorized/online"
    );
    let mut values = serde_json::Map::new();
    for key in [
        "ro.product.model",
        "ro.product.device",
        "ro.product.manufacturer",
        "ro.soc.model",
        "ro.soc.manufacturer",
        "ro.product.cpu.abi",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.boot.vbmeta.device_state",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.slot_suffix",
    ] {
        let mut call = args.clone();
        call.extend(["shell".into(), "getprop".into(), key.into()]);
        let value = run_tool(Path::new("adb"), &call, Duration::from_secs(10))?;
        values.insert(key.into(), json!(value.stdout.trim()));
    }
    let mut call = args.clone();
    call.extend(["shell".into(), "uname".into(), "-a".into()]);
    let kernel = run_tool(Path::new("adb"), &call, Duration::from_secs(10))?;
    let mut call = args.clone();
    call.extend([
        "shell".into(),
        "pm".into(),
        "list".into(),
        "features".into(),
    ]);
    let features = run_tool(Path::new("adb"), &call, Duration::from_secs(10))?;
    ensure!(
        !features.stderr_truncated && features.stdout.len() < 65536,
        "feature listing truncated"
    );
    let mut declared_features = std::collections::BTreeMap::new();
    for line in features.stdout.lines() {
        let feature = line
            .trim()
            .strip_prefix("feature:")
            .context("unexpected package feature response")?;
        let (name, version) = feature.split_once('=').unwrap_or((feature, "0"));
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid reported feature name"
        );
        ensure!(
            declared_features
                .insert(
                    name.to_string(),
                    if let Some(hex) = version.strip_prefix("0x") {
                        u32::from_str_radix(hex, 16)?
                    } else {
                        version.parse::<u32>()?
                    }
                )
                .is_none(),
            "duplicate reported feature"
        );
    }
    ensure!(!declared_features.is_empty(), "empty feature listing");
    Ok(
        json!({"schema_version":1,"source":"read_only_adb","properties":values,"kernel":kernel.stdout.trim(),"declared_features":declared_features,"complete_declared_feature_listing":true,"hardware_runtime_verified":false,"limitations":["Reported boot state is not an AVB acceptance test","This ADB probe does not inspect partition images or enforced rollback indexes","Package feature declarations are not proof of hardware operation"]}),
    )
}
fn doctor() -> Result<Value> {
    let mut tools = Vec::new();
    for name in [
        "adb",
        "bwrap",
        "simg2img",
        "fsck.erofs",
        "debugfs",
        "lpunpack",
        "lpmake",
        "avbtool",
        "mkbootimg",
        "unpack_bootimg",
        "checkvintf",
        "qemu-system-aarch64",
    ] {
        let found = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|d| d.join(name))
            .find(|p| p.is_file());
        let value = if let Some(p) = found {
            let flag = if name == "fsck.erofs" {
                "-V"
            } else if name == "adb" {
                "version"
            } else {
                "--version"
            };
            let version = run_tool(&p, &[flag.into()], Duration::from_secs(5))
                .map(|r| format!("{}{}", r.stdout, r.stderr))
                .unwrap_or_else(|e| format!("Version probe unavailable: {e}"));
            json!({"name":name,"available":true,"binary_sha256":gb_core::hash_file(&p)?,"version":version})
        } else {
            json!({"name":name,"available":false})
        };
        tools.push(value);
    }
    Ok(
        json!({"schema_version":1,"host":std::env::consts::OS,"architecture":std::env::consts::ARCH,"engine_digest":gb_build::ENGINE_DIGEST,"tools":tools}),
    )
}
fn execute(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Port {
            command:
                PortCommand::InspectInitBoot {
                    input,
                    unpack,
                    lz4,
                    sandbox_image,
                    out,
                },
        } => {
            if let Some(out) = &out {
                separate_from_input(&input, out)?;
            }
            let sandbox = sandbox_image.map_or_else(gb_tools::Sandbox::default, |image| {
                gb_tools::Sandbox::Docker { image }
            });
            emit(
                &gb_boot::diagnostic::inspect(&input, &unpack, &lz4, &sandbox)?,
                out.as_deref(),
            )?;
            Ok(false)
        }
        Command::Port {
            command: PortCommand::InstrumentInit { request, output },
        } => {
            separate_from_input(&request, &output)?;
            separate_from_input(&request, &cli.cache)?;
            gb_core::separate_destinations(&cli.cache, &output)?;
            let request = gb_boot::diagnostic::Request::read(&request)?;
            for path in [&request.input, &request.logger] {
                separate_from_input(path, &output)?;
            }
            let (report, stage) = gb_build::init_diagnostic_cached(&request, &cli.cache)?;
            gb_build::publish_init_diagnostic(&stage, &output)?;
            emit(&report, None)?;
            Ok(true)
        }
        Command::Port {
            command:
                PortCommand::ProbeBoot {
                    serial,
                    expected_fingerprint,
                    adb,
                    out,
                },
        } => {
            ensure!(!out.exists(), "boot report destination already exists");
            if adb.exists() {
                separate_from_input(&adb, &out)?;
            } else {
                ensure!(adb.components().count() == 1, "ADB executable is missing");
            }
            let report = runtime::collect(&adb, &serial, &expected_fingerprint)?;
            let incomplete = !report.requested_system_observed;
            emit(&report, Some(&out))?;
            Ok(incomplete)
        }
        Command::Port {
            command: PortCommand::AssembleSuper { request, output },
        } => {
            separate_from_input(&request, &output)?;
            separate_from_input(&request, &cli.cache)?;
            gb_core::separate_destinations(&cli.cache, &output)?;
            let request = gb_build::super_image::Request::read(&request)?;
            for input in std::iter::once(&request.base).chain(request.replacements.values()) {
                separate_from_input(&input.path, &output)?;
            }
            let (report, stage) = gb_build::super_assemble_cached(&request, &cli.cache)?;
            gb_build::publish_super(&stage, &output)?;
            emit(&report, None)?;
            Ok(true)
        }
        Command::Port {
            command: PortCommand::SignImages { request, output },
        } => {
            separate_from_input(&request, &output)?;
            separate_from_input(&request, &cli.cache)?;
            gb_core::separate_destinations(&cli.cache, &output)?;
            let request = gb_avb::Request::read(&request)?;
            for input in request.inputs() {
                separate_from_input(&input.path, &output)?;
            }
            let (report, stage) = gb_build::avb_assemble_cached(&request, &cli.cache)?;
            gb_build::publish_avb(&stage, &output, &report)?;
            emit(&report, None)?;
            Ok(true)
        }
        Command::Port {
            command: PortCommand::AdaptVendorBoot { request, output },
        } => {
            separate_from_input(&request, &output)?;
            separate_from_input(&request, &cli.cache)?;
            gb_core::separate_destinations(&cli.cache, &output)?;
            let request = gb_boot::Request::read(&request)?;
            separate_from_input(&request.input, &output)?;
            let (report, stage) = gb_build::boot_adapt_cached(&request, &cli.cache)?;
            gb_build::publish_boot(&stage, &output)?;
            emit(&report, None)?;
            Ok(true)
        }
        Command::Port {
            command: PortCommand::ValidateTerminalSoak { request, output },
        } => {
            separate_from_input(&request, &output)?;
            let request = gb_framework::terminal_soak::Request::read(&request)?;
            let report = gb_framework::terminal_soak::inspect_to(&request, &output)?;
            emit(&report, None)?;
            Ok(false)
        }
        Command::Port {
            command: PortCommand::BuildFrameworkOverlay { request, output },
        } => {
            separate_from_input(&request, &output)?;
            let request = gb_framework::rro::Request::read(&request)?;
            emit(&gb_framework::rro::build(&request, &output)?, None)?;
            Ok(false)
        }
        Command::Port {
            command: PortCommand::AdaptKernelBoot { request, output },
        } => {
            separate_from_input(&request, &output)?;
            separate_from_input(&request, &cli.cache)?;
            gb_core::separate_destinations(&cli.cache, &output)?;
            let request = gb_boot::kernel::Request::read(&request)?;
            separate_from_input(&request.input, &output)?;
            separate_from_input(&request.kernel, &output)?;
            let (report, stage) = gb_build::kernel_boot_cached(&request, &cli.cache)?;
            gb_build::publish_kernel_boot(&stage, &output)?;
            emit(&report, None)?;
            Ok(true)
        }
        Command::Port {
            command: PortCommand::AssemblePartition { request, output },
        } => {
            separate_from_input(&request, &cli.cache)?;
            separate_from_input(&request, &output)?;
            gb_core::separate_destinations(&cli.cache, &output)?;
            let request = gb_image::assemble::Request::read(&request)?;
            separate_from_input(&request.input, &output)?;
            for patch in &request.patches {
                separate_from_input(&patch.input, &output)?;
            }
            for addition in &request.additions {
                separate_from_input(&addition.input, &output)?;
            }
            for import in &request.imports {
                separate_from_input(&import.image, &output)?;
            }
            let (report, stage) = gb_build::assemble_partition_cached(&request, &cli.cache)?;
            gb_build::publish_partition(&stage, &output)?;
            tracing::info!(
                key = stage.key,
                cache_hit = stage.cache_hit,
                "unsigned partition candidate published"
            );
            emit(&report, None)?;
            Ok(true)
        }
        Command::Compat {
            command:
                CompatCommand::HostImages {
                    capabilities,
                    sampling,
                    out,
                },
        } => {
            if let Some(out) = &out {
                separate_from_input(&capabilities, out)?;
                for input in &sampling {
                    separate_from_input(input, out)?;
                }
                ensure!(!out.exists(), "report exists");
            }
            let report = gb_compat::host_egl::inspect_files(&capabilities, &sampling)?;
            let incomplete = report.state != gb_core::State::Compatible;
            emit(&report, out.as_deref())?;
            Ok(incomplete)
        }
        Command::Compat {
            command: CompatCommand::InitProcesses { request, output },
        } => {
            separate_from_input(&request, &output)?;
            let request = gb_selinux::init_process::Request::read(&request)?;
            let report = gb_selinux::init_process::check(&request, &output)?;
            let failed = !report.all_explicit_contexts_valid;
            emit(&report, None)?;
            Ok(failed)
        }
        Command::Compat {
            command:
                CompatCommand::Contexts {
                    donor,
                    target,
                    recipe,
                    policy_report,
                    policy_file,
                    device_observation,
                    overlay_output,
                    tool,
                    sandbox_image,
                    out,
                },
        } => {
            for input in [
                &donor,
                &target,
                &recipe,
                &policy_report,
                &policy_file,
                &tool,
            ] {
                separate_from_input(input, &cli.cache)?;
                if let Some(out) = &out {
                    separate_from_input(input, out)?;
                }
                if let Some(destination) = &overlay_output {
                    separate_from_input(input, destination)?;
                }
            }
            if let Some(out) = &out {
                gb_core::separate_destinations(&cli.cache, out)?;
            }
            if let Some(destination) = &overlay_output {
                gb_core::separate_destinations(&cli.cache, destination)?;
                if let Some(out) = &out {
                    gb_core::separate_destinations(out, destination)?;
                }
            }
            let d = load_manifest(&donor)?;
            let t = load_manifest(&target)?;
            let recipe = gb_framework::Recipe::read(&recipe)?;
            let p: gb_selinux::Report = gb_core::read_json(&policy_report, 1024 * 1024)?;
            ensure!(
                p.schema_version == 1
                    && serde_json::to_vec(&gb_selinux::select(&d, &t, &recipe, p.options)?)?
                        == serde_json::to_vec(&p.selection)?,
                "policy report does not describe the selected CIL inputs"
            );
            let strict = p.state == gb_core::State::Compatible && p.neverallow_checks_enabled;
            let binary = if strict {
                p.binary_policy.as_ref()
            } else {
                p.android_init_link_check
                    .as_ref()
                    .filter(|l| l.state == gb_core::State::Compatible)
                    .and_then(|l| l.binary_policy.as_ref())
            }
            .context("a successfully linked policy is required for context validation")?;
            let policy = gb_selinux::contexts::PolicyReference {
                input: policy_file,
                sha256: binary.sha256.clone(),
                policy_version: binary.policy_version,
                policy_report_sha256: gb_core::hash_file(&policy_report)?,
                strict_audit_passed: strict,
            };
            let feature_observation = if let Some(input) = &device_observation {
                separate_from_input(input, &cli.cache)?;
                if let Some(out) = &out {
                    separate_from_input(input, out)?;
                }
                if let Some(destination) = &overlay_output {
                    separate_from_input(input, destination)?;
                }
                Some(gb_selinux::context_patch::FeatureObservation {
                    sha256: gb_core::hash_file(input)?,
                    data: gb_core::read_json(input, 1024 * 1024)?,
                })
            } else {
                None
            };
            let inputs = gb_selinux::contexts::Inputs {
                policy,
                feature_observation,
            };
            let sandbox = sandbox_image
                .map(|image| gb_tools::Sandbox::Docker { image })
                .unwrap_or_default();
            let (report, stage) =
                gb_build::contexts_cached(&d, &t, &recipe, &inputs, &tool, &sandbox, &cli.cache)?;
            if let Some(destination) = &overlay_output {
                gb_selinux::contexts::publish_overlays(&report, destination)?;
            }
            tracing::info!(
                key = stage.key,
                cache_hit = stage.cache_hit,
                "context validation stage verified"
            );
            let failed = report.state != gb_core::State::Compatible;
            emit(&report, out.as_deref())?;
            Ok(failed)
        }
        Command::Firmware {
            command: InspectCommand::CollectText { request, out },
        }
        | Command::Donor {
            command: InspectCommand::CollectText { request, out },
        } => {
            let request = gb_firmware::analysis::Request::read(&request)?;
            if let Some(out) = &out {
                separate_from_input(&request.base_manifest, out)?;
                gb_core::separate_destinations(&cli.cache, out)?;
                for image in &request.images {
                    separate_from_input(&image.input, out)?;
                }
            }
            let (manifest, stages) = gb_build::collect_text_cached(&request, &cli.cache)?;
            tracing::info!(stages=?stages.iter().map(|s|(&s.key,s.cache_hit)).collect::<Vec<_>>(),"metadata collection verified");
            emit(&manifest, out.as_deref())?;
            Ok(false)
        }
        Command::Compat {
            command:
                CompatCommand::Selinux {
                    donor,
                    target,
                    recipe,
                    tool,
                    sandbox_image,
                    kernel_policy_version,
                    policy_version,
                    out,
                },
        } => {
            for input in [&donor, &target, &recipe, &tool] {
                separate_from_input(input, &cli.cache)?;
                if let Some(out) = &out {
                    separate_from_input(input, out)?;
                }
            }
            if let Some(out) = &out {
                gb_core::separate_destinations(&cli.cache, out)?;
            }
            let d = load_manifest(&donor)?;
            let t = load_manifest(&target)?;
            let recipe = gb_framework::Recipe::read(&recipe)?;
            let sandbox = sandbox_image
                .map(|image| gb_tools::Sandbox::Docker { image })
                .unwrap_or_default();
            let (report, stage) = gb_build::selinux_cached(
                &d,
                &t,
                &recipe,
                gb_selinux::Options {
                    kernel_policy_version,
                    policy_version,
                },
                &tool,
                &sandbox,
                &cli.cache,
            )?;
            tracing::info!(
                key = stage.key,
                cache_hit = stage.cache_hit,
                "SELinux policy stage verified"
            );
            let failed = report.state != gb_core::State::Compatible;
            emit(&report, out.as_deref())?;
            Ok(failed)
        }
        Command::Firmware {
            command: InspectCommand::AttachText { input, texts, out },
        }
        | Command::Donor {
            command: InspectCommand::AttachText { input, texts, out },
        } => {
            if let Some(out) = &out {
                separate_from_input(&input, out)?;
            }
            let mut manifest = load_manifest(&input)?;
            let mut paths = std::collections::BTreeSet::new();
            for text in texts {
                let (path, file) = text
                    .split_once('=')
                    .context("text requires inventory-path=captured-file")?;
                ensure!(
                    paths.insert(path.to_string()),
                    "duplicate text evidence path"
                );
                let file = Path::new(file);
                if let Some(out) = &out {
                    separate_from_input(file, out)?;
                }
                ensure!(
                    std::fs::symlink_metadata(file)?.is_file()
                        && std::fs::metadata(file)?.len() <= 16 * 1024 * 1024,
                    "text evidence must be a bounded regular file"
                );
                let mut bytes = Vec::new();
                std::fs::File::open(file)?
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                gb_firmware::attach_text(&mut manifest, path, &bytes)?;
            }
            manifest.limitations.push("Additional captured text checked against existing image file SHA256 and length; source image identity unchanged, no runtime certification".into());
            manifest.validate()?;
            emit(&manifest, out.as_deref())?;
            Ok(false)
        }
        Command::Compat {
            command:
                CompatCommand::Vintf {
                    donor,
                    target,
                    recipe,
                    tool,
                    sandbox_image,
                    kernel_config,
                    kernel_version,
                    properties,
                    overlay_output,
                    out,
                },
        } => {
            for out in [&out, &overlay_output].into_iter().flatten() {
                for input in [&donor, &target, &recipe, &tool] {
                    separate_from_input(input, out)?;
                }
                if let Some(kernel) = &kernel_config {
                    separate_from_input(kernel, out)?;
                }
            }
            if let (Some(report), Some(overlays)) = (&out, &overlay_output) {
                gb_core::separate_destinations(report, overlays)?;
            }
            let d = load_manifest(&donor)?;
            let t = load_manifest(&target)?;
            let recipe = gb_framework::Recipe::read(&recipe)?;
            let sandbox = sandbox_image
                .map(|image| gb_tools::Sandbox::Docker { image })
                .unwrap_or_default();
            let mut props = std::collections::BTreeMap::new();
            for property in properties {
                let (k, v) = property
                    .split_once('=')
                    .context("property requires key=value")?;
                ensure!(
                    props.insert(k.into(), v.into()).is_none(),
                    "duplicate VINTF property"
                );
            }
            let kernel = kernel_version.as_deref().zip(kernel_config.as_deref());
            let report = gb_vintf::check(&d, &t, &recipe, &tool, &sandbox, props, kernel)?;
            if let Some(destination) = &overlay_output {
                gb_vintf::publish_overlays(&report, destination)?;
            }
            let failed = report.state != gb_core::State::Compatible;
            emit(&report, out.as_deref())?;
            Ok(failed)
        }
        Command::Firmware {
            command: InspectCommand::Analyze { request, out },
        }
        | Command::Donor {
            command: InspectCommand::Analyze { request, out },
        } => {
            let request = gb_firmware::analysis::Request::read(&request)?;
            if let Some(out) = &out {
                separate_from_input(&request.base_manifest, out)?;
                for image in &request.images {
                    separate_from_input(&image.input, out)?;
                }
            }
            let (manifest, stages) = gb_build::analyze_cached(&request, &cli.cache)?;
            tracing::info!(stages=?stages.iter().map(|s|(&s.key,s.cache_hit)).collect::<Vec<_>>(),"deep analysis verified");
            emit(&manifest, out.as_deref())?;
            Ok(false)
        }
        Command::Firmware {
            command: InspectCommand::NormalizeManifest { input, out },
        }
        | Command::Donor {
            command: InspectCommand::NormalizeManifest { input, out },
        } => {
            if let Some(out) = &out {
                separate_from_input(&input, out)?;
            }
            let mut manifest = load_manifest(&input)?;
            gb_firmware::reindex_categories(&mut manifest);
            manifest.limitations.push("Path categories rebuilt from existing artifact records; this operation does not re-verify source bytes or add content analysis".into());
            manifest.validate()?;
            emit(&manifest, out.as_deref())?;
            Ok(false)
        }
        Command::Port {
            command:
                PortCommand::IntegrationPlan {
                    donor_manifest,
                    target_manifest,
                    device,
                    recipe,
                    out,
                },
        } => {
            if let Some(out) = &out {
                for input in [&donor_manifest, &target_manifest, &recipe] {
                    separate_from_input(input, out)?;
                }
            }
            let donor = load_manifest(&donor_manifest)?;
            let target = load_manifest(&target_manifest)?;
            let profile = gb_config::profile(&gb_config::resolve(&device, "devices"))?;
            let recipe = gb_framework::Recipe::read(&recipe)?;
            emit(
                &gb_framework::plan(&donor, &target, &profile, &recipe)?,
                out.as_deref(),
            )?;
            Ok(true)
        }
        Command::Donor {
            command:
                InspectCommand::Layout {
                    input,
                    gpt_partition,
                    slot,
                    out,
                },
        }
        | Command::Firmware {
            command:
                InspectCommand::Layout {
                    input,
                    gpt_partition,
                    slot,
                    out,
                },
        } => {
            if let Some(out) = &out {
                separate_from_input(&input, out)?;
            }
            emit(
                &gb_firmware::filesystem::layout(&input, gpt_partition.as_deref(), slot)?,
                out.as_deref(),
            )?;
            Ok(false)
        }
        Command::Donor {
            command:
                InspectCommand::Inventory {
                    input,
                    gpt_partition,
                    slot,
                    partitions,
                    tool,
                    check_tool,
                    sandbox_image,
                    out,
                },
        }
        | Command::Firmware {
            command:
                InspectCommand::Inventory {
                    input,
                    gpt_partition,
                    slot,
                    partitions,
                    tool,
                    check_tool,
                    sandbox_image,
                    out,
                },
        } => {
            if let Some(out) = &out {
                separate_from_input(&input, out)?;
            }
            let sandbox = sandbox_image
                .map(|image| gb_tools::Sandbox::Docker { image })
                .unwrap_or_default();
            let request = gb_firmware::filesystem::InventoryRequest {
                gpt_partition,
                slot,
                partitions,
                tool,
                check_tool,
                sandbox,
            };
            let (manifest, stages) =
                gb_build::inventory_cached(&input, &request, &cli.cache, true)?;
            tracing::info!(stages = ?stages.iter().map(|s| (&s.key, s.cache_hit)).collect::<Vec<_>>(), "filesystem inventories verified");
            emit(&manifest, out.as_deref())?;
            Ok(false)
        }
        Command::Donor {
            command: InspectCommand::Inspect { input, out },
        }
        | Command::Firmware {
            command: InspectCommand::Inspect { input, out },
        } => {
            if let Some(out) = &out {
                separate_from_input(&input, out)?;
            }
            let (manifest, stage) = gb_build::inspect_cached(&input, &cli.cache, true)?;
            tracing::info!(cache_hit = stage.cache_hit, "firmware inspection complete");
            emit(&manifest, out.as_deref())?;
            Ok(false)
        }
        Command::Device {
            command:
                DeviceCommand::Detect {
                    from,
                    adb,
                    serial,
                    out,
                },
        } => {
            let report = if adb {
                adb_detect(serial.as_deref())?
            } else {
                let input = from.context("use --from FIRMWARE or --adb")?;
                if let Some(out) = &out {
                    separate_from_input(&input, out)?;
                }
                let (m, _) = gb_build::inspect_cached(&input, &cli.cache, true)?;
                detected(&m)
            };
            emit(&report, out.as_deref())?;
            Ok(false)
        }
        Command::Compat {
            command:
                CompatCommand::Manifests {
                    donor,
                    target,
                    device,
                    recipe,
                    out,
                },
        } => {
            if let Some(out) = &out {
                for input in [&donor, &target] {
                    separate_from_input(input, out)?;
                }
            }
            let mut d = load_manifest(&donor)?;
            let t = load_manifest(&target)?;
            ensure!(
                d.schema_version == 1 && t.schema_version == 1,
                "unsupported firmware manifest schema"
            );
            if let Some(recipe) = recipe {
                let recipe = gb_framework::Recipe::read(&recipe)?;
                recipe.check_sources(&d, &t)?;
                d = gb_framework::selected_donor(&d, &recipe)?;
            }
            let profile = device
                .map(|p| gb_config::profile(&gb_config::resolve(&p, "devices")))
                .transpose()?;
            let report = gb_compat::check(&d, &t, profile.as_ref());
            emit(&report, out.as_deref())?;
            Ok(!report.bootable)
        }
        Command::Compat {
            command: CompatCommand::Check { inputs, out },
        } => {
            protect_report(&inputs, out.as_deref())?;
            let (_, p, d, t) = inspect_pair(&inputs, &cli.cache)?;
            let report = gb_compat::check(&d, &t, Some(&p));
            emit(&report, out.as_deref())?;
            Ok(!report.bootable)
        }
        Command::Port {
            command:
                PortCommand::Plan {
                    inputs,
                    transforms,
                    out,
                },
        } => {
            protect_report(&inputs, out.as_deref())?;
            emit(
                &plan(&inputs, transforms.as_deref(), &cli.cache)?,
                out.as_deref(),
            )?;
            Ok(true)
        }
        Command::Port {
            command:
                PortCommand::Build {
                    inputs,
                    transforms,
                    output,
                    incremental,
                    dry_run,
                },
        } => {
            if dry_run {
                emit(&plan(&inputs, transforms.as_deref(), &cli.cache)?, None)?;
                return Ok(true);
            }
            let (d, p) = configs(&inputs)?;
            let t = gb_config::transforms(transforms.as_deref())?;
            let report = gb_build::build(&d, &p, &t, &cli.cache, &output, incremental)?;
            emit(&report, None)?;
            Ok(!report.bootable)
        }
        Command::Port {
            command:
                PortCommand::Test {
                    device,
                    artifact,
                    offline: _,
                    out,
                },
        } => {
            if let Some(out) = &out {
                separate_from_input(&artifact, out)?;
            }
            if let Some(d) = device {
                gb_config::profile(&gb_config::resolve(&d, "devices"))?;
            }
            emit(&gb_build::offline_validate(&artifact)?, out.as_deref())?;
            Ok(false)
        }
        Command::Flash {
            command: FlashCommand::Plan { device, artifact },
        } => {
            let p = gb_config::profile(&gb_config::resolve(&device, "devices"))?;
            emit(&gb_build::flash_plan(&p, &artifact)?, None)?;
            Ok(false)
        }
        Command::Doctor => {
            emit(&doctor()?, None)?;
            Ok(false)
        }
    }
}
fn load_manifest(path: &Path) -> Result<FirmwareManifest> {
    let manifest: FirmwareManifest = gb_core::read_json(path, 64 * 1024 * 1024)?;
    manifest.validate()?;
    Ok(manifest)
}
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = ctrlc::set_handler(|| gb_core::CANCELLED.store(true, Ordering::Relaxed)) {
        eprintln!("cannot configure build cancellation: {e}");
        std::process::exit(1);
    }
    let code = match execute(Cli::parse()) {
        Ok(false) => 0,
        Ok(true) => 2,
        Err(e) => {
            eprintln!(
                "{}",
                json!({"status":"error","message":e.to_string(),"causes":e.chain().skip(1).map(ToString::to_string).collect::<Vec<_>>()})
            );
            1
        }
    };
    std::process::exit(code);
}
