//! Offline validation of pinned, owned guest-soak observations, not presentation
//! or hardware-identity attestation. This module never contacts a device.
use crate::rro::PinnedFile;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub runner_result: PinnedFile,
    pub host_observation: PinnedFile,
    /// Ordered live1 through live20 observations; no directory discovery.
    pub liveness: Vec<PinnedFile>,
    pub android_boot_id: String,
    pub guest_boot_id: String,
    pub vmm_pid: u32,
    pub duration_seconds: u32,
    pub memory_mib: u32,
    pub disk_mib: u32,
}

impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut r: Self = serde_json::from_slice(&regular_bytes(path, 32 * 1024)?)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        for pin in [&mut r.runner_result, &mut r.host_observation]
            .into_iter()
            .chain(r.liveness.iter_mut())
        {
            if pin.path.is_relative() {
                pin.path = parent.join(&pin.path);
            }
        }
        r.validate()?;
        Ok(r)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.duration_seconds == 600
                && matches!(self.memory_mib, 512 | 768)
                && self.disk_mib == 64
                && self.vmm_pid > 1
                && uuid(&self.android_boot_id)
                && uuid(&self.guest_boot_id)
                && self.liveness.len() == 20,
            "expected 600-second, 512-or-768/64 MiB soak with exact boot/VM guards and 20 samples"
        );
        let mut paths = BTreeSet::new();
        for pin in self.pins() {
            ensure!(sha256(&pin.sha256), "invalid observation SHA-256");
            no_symlink_components(&pin.path)?;
            ensure!(
                paths.insert(fs::canonicalize(&pin.path)?),
                "duplicate observation path"
            );
        }
        Ok(())
    }

    fn pins(&self) -> impl Iterator<Item = &PinnedFile> {
        [&self.runner_result, &self.host_observation]
            .into_iter()
            .chain(self.liveness.iter())
    }
}

fn sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn no_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for part in path.components() {
        ensure!(part != Component::ParentDir, "parent traversal refused");
        current.push(part.as_os_str());
        ensure!(
            !fs::symlink_metadata(&current)?.file_type().is_symlink(),
            "symlink observation path refused"
        );
    }
    Ok(())
}

fn regular_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    no_symlink_components(path)?;
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && before.len() > 0 && before.len() <= limit,
        "bounded regular observation required"
    );
    // O_NONBLOCK prevents a raced FIFO from blocking analysis. Resolve flags
    // through libc so additional Linux host architectures use their own UAPI.
    #[cfg(target_os = "linux")]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("no-follow bounded observation reader currently requires Linux");
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        ensure!(
            opened.is_file()
                && opened.len() == before.len()
                && opened.dev() == before.dev()
                && opened.ino() == before.ino(),
            "observation changed while opening"
        );
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.len(),
            "observation size changed"
        );
        no_symlink_components(path)?;
        Ok(bytes)
    }
}

fn pinned(pin: &PinnedFile, limit: u64) -> Result<Value> {
    let bytes = regular_bytes(&pin.path, limit)?;
    ensure!(
        gb_core::digest(&bytes) == pin.sha256.to_ascii_lowercase(),
        "observation checksum mismatch"
    );
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(value.is_object(), "observation object required");
    Ok(value)
}

fn flag(v: &Value, field: &str, expected: bool) -> Result<()> {
    ensure!(
        v[field].as_bool() == Some(expected),
        "missing or incorrect {field} flag"
    );
    Ok(())
}

fn number(v: &Value, field: &str) -> Result<f64> {
    let n = v[field]
        .as_f64()
        .context(format!("missing {field} number"))?;
    ensure!(n.is_finite() && n >= 0.0, "invalid {field} number");
    Ok(n)
}

fn no_budget_flags(v: &Value) -> Result<()> {
    match v {
        Value::Object(o) => {
            for (key, value) in o {
                if matches!(key.as_str(), "output_over_budget" | "over_budget") {
                    ensure!(value == false, "observation exceeded output/trace budget");
                }
                no_budget_flags(value)?;
            }
        }
        Value::Array(a) => {
            for value in a {
                no_budget_flags(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn compute(v: &Value) -> Result<()> {
    ensure!(v["exit_code"] == 0, "compute child failed");
    flag(v, "timed_out", false)?;
    flag(v, "output_over_budget", false)?;
    let text = v["stdout"].as_str().context("compute JSON missing")?;
    ensure!(text.len() <= 4096, "compute JSON budget");
    let receipt: Value = serde_json::from_str(text)?;
    ensure!(
        receipt["schema_version"] == 1
            && receipt["status"] == "shader_readback_verified"
            && receipt["dispatches_verified"] == 3
            && receipt["words_verified_per_dispatch"] == 1024
            && receipt["fence_transitions_verified"] == 3,
        "actual three-dispatch shader/readback receipt required"
    );
    for name in [
        "venus_compute_verified",
        "shader_execution_verified",
        "custom_icd_explicit",
    ] {
        flag(&receipt, name, true)?;
    }
    for name in [
        "software_control",
        "presentation_verified",
        "physical_gpu_performance_verified",
    ] {
        flag(&receipt, name, false)?;
    }
    Ok(())
}

fn workload(v: &Value, r: &Request) -> Result<Value> {
    ensure!(v["exit_code"] == 0, "integrity workload child failed");
    flag(v, "output_over_budget", false)?;
    let stdout = v["stdout"].as_str().context("workload output missing")?;
    ensure!(stdout.len() <= 16384, "workload output budget");
    let receipts: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("GB_WORKLOAD_RESULT "))
        .collect();
    ensure!(
        receipts.len() == 1,
        "one actual workload JSON receipt required"
    );
    let w: Value = serde_json::from_str(receipts[0])?;
    ensure!(
        w["schema_version"] == 1
            && w["status"] == "passed"
            && w["memory_mib"] == r.memory_mib
            && w["disk_mib"] == r.disk_mib
            && w["rounds"].as_u64().is_some_and(|n| n >= 3)
            && number(&w, "seconds")? >= f64::from(r.duration_seconds)
            && number(&w, "seconds")? <= 900.0,
        "incomplete integrity workload"
    );
    flag(&w, "own_disposable_files_removed", true)?;
    for key in ["memory_sha256", "disk_sha256"] {
        ensure!(
            w[key].as_str().is_some_and(sha256),
            "invalid workload digest"
        );
    }
    Ok(w)
}

fn observations(r: &Request, result: &Value, host: &Value, samples: &[Value]) -> Result<Value> {
    r.validate()?;
    ensure!(
        result["schema_version"] == 1
            && result["guest_boot_id"] == r.guest_boot_id
            && host["schema_version"] == 1
            && host["android_boot_id"] == r.android_boot_id
            && host["vmm_pid"] == r.vmm_pid
            && host["selinux"] == "Enforcing"
            && host["crash_buffer_bytes"] == 0
            && result.get("status").is_none()
            && result.get("profile_error_stage").is_none(),
        "wrong runtime guards or failed runner"
    );
    for (value, names) in [
        (
            result,
            &[
                "same_guest_boot",
                "runtime_only_dropin_created",
                "runtime_only_dropin_removed",
                "prior_capabilities_recovered",
                "own_disposable_files_removed",
                "outer_storage_work_removed",
            ][..],
        ),
        (
            host,
            &[
                "android_boot_unchanged",
                "vm_identity_unchanged",
                "result_received",
            ][..],
        ),
    ] {
        for name in names {
            flag(value, name, true)?;
        }
    }
    for name in [
        "firmware_written",
        "persistent_configuration_changed",
        "installed",
        "presentation_verified",
        "full_port_verified",
    ] {
        flag(result, name, false)?;
    }
    flag(host, "firmware_written", false)?;
    flag(host, "presentation_verified", false)?;
    no_budget_flags(result)?;
    let fs = result["workload_preflight"]["filesystem_type"].as_str();
    ensure!(
        matches!(fs, Some("ext4" | "xfs" | "btrfs")),
        "disk-backed filesystem preflight required"
    );
    ensure!(
        number(&result["workload_preflight"], "memory_available_kib")? >= 1100.0 * 1024.0,
        "memory preflight failed"
    );
    let prior = result["prior_compositor_pid"]
        .as_u64()
        .context("prior compositor missing")?;
    let profile = result["profile_compositor_pid"]
        .as_u64()
        .context("profile compositor missing")?;
    let restored = result["restored_compositor_pid"]
        .as_u64()
        .context("restored compositor missing")?;
    ensure!(
        prior > 1 && profile > 1 && restored > 1 && prior != profile && profile != restored,
        "compositor restart/restore evidence missing"
    );
    let modifiers = result["capabilities_before"]["modifiers"]
        .as_array()
        .context("prior modifiers missing")?;
    ensure!(
        !modifiers.is_empty()
            && result["capabilities_after_recovery"]["modifiers"]
                == result["capabilities_before"]["modifiers"],
        "compositor capabilities were not restored"
    );
    let operations = result["unit_operations"]
        .as_array()
        .context("unit operations missing")?;
    ensure!(
        !operations.is_empty() && operations.iter().all(|v| v["returncode"] == 0),
        "compositor unit operation failed"
    );
    for stream in ["stdout", "stderr"] {
        flag(
            &result["controlled_compositor_stdio"][stream],
            "over_budget",
            false,
        )?;
        ensure!(
            number(&result["controlled_compositor_stdio"][stream], "bytes")? <= 65536.0,
            "controlled compositor log budget"
        );
    }
    compute(&result["compute"])?;
    compute(&result["post_window_compute"])?;
    let w = workload(&result["integrity_workload"], r)?;
    let window = &result["window"];
    ensure!(window["exit_code"] == -2, "planned cube SIGINT required");
    flag(window, "planned_stop", true)?;
    flag(window, "timed_out", false)?;
    flag(window, "output_over_budget", false)?;
    flag(&window["trace_capture"], "over_budget", false)?;
    ensure!(
        number(&window["trace_capture"], "raw_bytes")? <= 64.0 * 1024.0 * 1024.0,
        "trace processing budget"
    );
    let seconds = number(window, "seconds")?;
    ensure!(
        (f64::from(r.duration_seconds)..=900.0).contains(&seconds),
        "cube duration incomplete"
    );
    ensure!(samples.len() == 20, "20 liveness observations required");
    let mut previous = 0.0;
    let mut child_pid = None;
    for sample in samples {
        ensure!(
            sample["schema_version"] == 1 && sample["guest_boot_id"] == r.guest_boot_id,
            "liveness guest identity changed"
        );
        flag(sample, "alive", true)?;
        let pid = sample["child_pid"]
            .as_u64()
            .context("owned child PID missing")?;
        ensure!(
            pid > 1 && child_pid.is_none_or(|expected| pid == expected),
            "owned child PID changed"
        );
        child_pid = Some(pid);
        let elapsed = number(sample, "seconds")?;
        ensure!(
            elapsed > previous && elapsed <= seconds,
            "liveness samples not ordered within cube duration"
        );
        previous = elapsed;
    }
    ensure!(
        previous >= f64::from(r.duration_seconds),
        "last live sample precedes requested duration"
    );
    Ok(json!({
        "schema_version":1,"status":"bounded_api_and_integrity_observations_validated",
        "scope":"Offline validation of pinned owned-process observations; hashes bind input bytes, not hardware identity or attestation",
        "android_boot_id":r.android_boot_id,"guest_boot_id":r.guest_boot_id,"vmm_pid":r.vmm_pid,
        "owned_cube_pid":child_pid,"cube_seconds":seconds,"liveness_samples":samples.len(),
        "integrity_workload":{"seconds":w["seconds"],"rounds":w["rounds"],"memory_mib":r.memory_mib,"disk_mib":r.disk_mib},
        "compute_dispatches_verified_per_probe":3,"compute_words_per_dispatch":1024,
        "api_and_integrity_observations_verified":true,"cleanup_observations_verified":true,
        "presentation_verified":false,"full_port_verified":false,"memory_leak_absence_verified":false,
        "physical_disk_throughput_verified":false,"audio_verified":false,"hardware_identity_attested":false,
        "firmware_written":false,"persistent_configuration_changed":false,
        "input_sha256":{"runner_result":r.runner_result.sha256,"host_observation":r.host_observation.sha256,
          "liveness":r.liveness.iter().map(|pin| &pin.sha256).collect::<Vec<_>>()}
    }))
}

/// Reject incomplete or inconsistent evidence. This does not launch tests,
/// inspect screenshots, read original VMM arguments, or attest a device.
pub fn inspect(r: &Request) -> Result<Value> {
    r.validate()?;
    let result = pinned(&r.runner_result, 192 * 1024)?;
    let host = pinned(&r.host_observation, 16 * 1024)?;
    let samples = r
        .liveness
        .iter()
        .map(|pin| pinned(pin, 4096))
        .collect::<Result<Vec<_>>>()?;
    observations(r, &result, &host, &samples)
}

/// Atomically publish a narrow report without replacing an existing file.
pub fn inspect_to(r: &Request, destination: &Path) -> Result<Value> {
    for pin in r.pins() {
        gb_core::separate_from_input(&pin.path, destination)?;
    }
    ensure!(
        matches!(fs::symlink_metadata(destination), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "new report path required"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    no_symlink_components(parent)?;
    let report = inspect(r)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, &report)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(destination)
        .map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> (tempfile::TempDir, Request, Value, Value, Vec<Value>) {
        let dir = tempfile::tempdir().unwrap();
        let pin = |name: &str| {
            let path = dir.path().join(name);
            fs::write(&path, b"{} ").unwrap();
            PinnedFile {
                path,
                sha256: gb_core::digest(b"{} "),
            }
        };
        let r = Request {
            schema_version: 1,
            runner_result: pin("result"),
            host_observation: pin("host"),
            liveness: (1..=20).map(|n| pin(&format!("live{n}"))).collect(),
            android_boot_id: "00000000-0000-4000-8000-000000000001".into(),
            guest_boot_id: "00000000-0000-4000-8000-000000000002".into(),
            vmm_pid: 8846,
            duration_seconds: 600,
            memory_mib: 768,
            disk_mib: 64,
        };
        let compute = json!({"exit_code":0,"timed_out":false,"output_over_budget":false,"stdout":json!({"schema_version":1,"status":"shader_readback_verified","software_control":false,"venus_compute_verified":true,"shader_execution_verified":true,"dispatches_verified":3,"words_verified_per_dispatch":1024,"fence_transitions_verified":3,"presentation_verified":false,"physical_gpu_performance_verified":false,"custom_icd_explicit":true}).to_string()});
        let workload = json!({"schema_version":1,"status":"passed","memory_mib":768,"disk_mib":64,"seconds":600.3,"rounds":1000,"memory_sha256":"a".repeat(64),"disk_sha256":"b".repeat(64),"own_disposable_files_removed":true});
        let result = json!({"schema_version":1,"guest_boot_id":r.guest_boot_id,"firmware_written":false,"persistent_configuration_changed":false,"installed":false,"presentation_verified":false,"full_port_verified":false,"same_guest_boot":true,"runtime_only_dropin_created":true,"runtime_only_dropin_removed":true,"prior_capabilities_recovered":true,"own_disposable_files_removed":true,"outer_storage_work_removed":true,"workload_preflight":{"filesystem_type":"ext4","memory_available_kib":1500000},"prior_compositor_pid":100,"profile_compositor_pid":200,"restored_compositor_pid":300,"capabilities_before":{"modifiers":[{"fourcc":123,"modifier":0}]},"capabilities_after_recovery":{"modifiers":[{"fourcc":123,"modifier":0}]},"unit_operations":[{"returncode":0}],"controlled_compositor_stdio":{"stdout":{"over_budget":false,"bytes":0},"stderr":{"over_budget":false,"bytes":100}},"compute":compute,"post_window_compute":compute,"integrity_workload":{"exit_code":0,"output_over_budget":false,"stdout":format!("GB_WORKLOAD_RESULT {workload}\nGB_WORKLOAD_PASS\n")},"window":{"exit_code":-2,"planned_stop":true,"timed_out":false,"output_over_budget":false,"seconds":601.0,"trace_capture":{"over_budget":false,"raw_bytes":10000}}});
        let host = json!({"schema_version":1,"android_boot_id":r.android_boot_id,"vmm_pid":8846,"selinux":"Enforcing","crash_buffer_bytes":0,"android_boot_unchanged":true,"vm_identity_unchanged":true,"result_received":true,"firmware_written":false,"presentation_verified":false});
        let samples=(1..=20).map(|n|json!({"schema_version":1,"guest_boot_id":r.guest_boot_id,"child_pid":718,"alive":true,"seconds":n*30})).collect();
        (dir, r, result, host, samples)
    }

    #[test]
    fn accepts_bounded_observations_without_promoting_scope() {
        let (_dir, r, result, host, samples) = data();
        let report = observations(&r, &result, &host, &samples).unwrap();
        for k in [
            "presentation_verified",
            "full_port_verified",
            "memory_leak_absence_verified",
            "physical_disk_throughput_verified",
            "audio_verified",
            "hardware_identity_attested",
        ] {
            assert_eq!(report[k], false);
        }
    }

    #[test]
    fn accepts_explicit_512_mib_without_relaxing_other_requirements() {
        let (_dir, mut r, mut result, host, samples) = data();
        r.memory_mib = 512;
        let text = result["integrity_workload"]["stdout"].as_str().unwrap();
        let mut workload: Value = serde_json::from_str(
            text.lines()
                .next()
                .unwrap()
                .strip_prefix("GB_WORKLOAD_RESULT ")
                .unwrap(),
        )
        .unwrap();
        // A 512 MiB request cannot validate the old 768 MiB receipt.
        assert!(observations(&r, &result, &host, &samples).is_err());
        workload["memory_mib"] = json!(512);
        result["integrity_workload"]["stdout"] = json!(format!("GB_WORKLOAD_RESULT {workload}\n"));
        let report = observations(&r, &result, &host, &samples).unwrap();
        assert_eq!(report["integrity_workload"]["memory_mib"], 512);
        for memory in [0, 256, 513, 767, 769, 1024] {
            r.memory_mib = memory;
            assert!(observations(&r, &result, &host, &samples).is_err());
        }
        r.memory_mib = 512;
        for (field, value) in [
            ("seconds", json!(599.9)),
            ("disk_mib", json!(63)),
            ("own_disposable_files_removed", json!(false)),
        ] {
            let mut changed = result.clone();
            let mut receipt = workload.clone();
            receipt[field] = value;
            changed["integrity_workload"]["stdout"] =
                json!(format!("GB_WORKLOAD_RESULT {receipt}\n"));
            assert!(observations(&r, &changed, &host, &samples).is_err());
        }
        let mut changed = result.clone();
        changed["workload_preflight"]["memory_available_kib"] = json!(1100 * 1024 - 1);
        assert!(observations(&r, &changed, &host, &samples).is_err());
        let mut changed = result.clone();
        changed["window"]["seconds"] = json!(599.9);
        assert!(observations(&r, &changed, &host, &samples).is_err());
        let mut changed = result.clone();
        changed["window"]["exit_code"] = json!(0);
        assert!(observations(&r, &changed, &host, &samples).is_err());
        assert!(observations(&r, &result, &host, &samples[..19]).is_err());
    }

    #[test]
    fn rejects_failed_short_or_fabricated_workload() {
        let (_dir, r, result, host, samples) = data();
        for (key, value) in [
            ("status", json!("failed")),
            ("seconds", json!(599.9)),
            ("rounds", json!(2)),
            ("own_disposable_files_removed", json!(false)),
            ("memory_sha256", json!("not-a-hash")),
            ("memory_mib", json!(1024)),
        ] {
            let mut changed = result.clone();
            let text = changed["integrity_workload"]["stdout"].as_str().unwrap();
            let mut w: Value = serde_json::from_str(
                text.lines()
                    .next()
                    .unwrap()
                    .strip_prefix("GB_WORKLOAD_RESULT ")
                    .unwrap(),
            )
            .unwrap();
            w[key] = value;
            changed["integrity_workload"]["stdout"] = json!(format!("GB_WORKLOAD_RESULT {w}\n"));
            assert!(
                observations(&r, &changed, &host, &samples).is_err(),
                "{key}"
            );
        }
        let mut changed = result.clone();
        changed["integrity_workload"]["stdout"] = json!("GB_WORKLOAD_PASS");
        assert!(observations(&r, &changed, &host, &samples).is_err());
    }

    #[test]
    fn rejects_absent_software_or_incomplete_compute() {
        let (_dir, r, result, host, samples) = data();
        for probe in ["compute", "post_window_compute"] {
            let mut changed = result.clone();
            changed.as_object_mut().unwrap().remove(probe);
            assert!(observations(&r, &changed, &host, &samples).is_err());
            for (key, value) in [
                ("software_control", json!(true)),
                ("venus_compute_verified", json!(false)),
                ("words_verified_per_dispatch", json!(1023)),
                ("fence_transitions_verified", json!(2)),
            ] {
                let mut changed = result.clone();
                let mut c: Value =
                    serde_json::from_str(changed[probe]["stdout"].as_str().unwrap()).unwrap();
                c[key] = value;
                changed[probe]["stdout"] = json!(c.to_string());
                assert!(observations(&r, &changed, &host, &samples).is_err());
            }
        }
    }

    #[test]
    fn rejects_early_death_reordered_samples_reboots_and_budget_overflow() {
        let (_dir, r, result, host, samples) = data();
        for (key, value) in [
            ("alive", json!(false)),
            ("child_pid", json!(719)),
            ("guest_boot_id", json!("other")),
            ("seconds", json!(0)),
        ] {
            let mut s = samples.clone();
            s[10][key] = value;
            assert!(observations(&r, &result, &host, &s).is_err());
        }
        let mut h = host.clone();
        h["android_boot_unchanged"] = json!(false);
        assert!(observations(&r, &result, &h, &samples).is_err());
        let mut v = result.clone();
        v["window"]["trace_capture"]["over_budget"] = json!(true);
        assert!(observations(&r, &v, &host, &samples).is_err());
        let mut v = result.clone();
        v["window"]["seconds"] = json!(599);
        assert!(observations(&r, &v, &host, &samples).is_err());
    }

    #[test]
    fn rejects_cleanup_failures_policy_changes_and_memory_backed_storage() {
        let (_dir, r, result, host, samples) = data();
        for key in [
            "runtime_only_dropin_removed",
            "prior_capabilities_recovered",
            "outer_storage_work_removed",
            "own_disposable_files_removed",
        ] {
            let mut v = result.clone();
            v[key] = json!(false);
            assert!(observations(&r, &v, &host, &samples).is_err());
        }
        let mut v = result.clone();
        v["persistent_configuration_changed"] = json!(true);
        assert!(observations(&r, &v, &host, &samples).is_err());
        let mut v = result.clone();
        v["workload_preflight"]["filesystem_type"] = json!("tmpfs");
        assert!(observations(&r, &v, &host, &samples).is_err());
        let mut h = host.clone();
        h["selinux"] = json!("Permissive");
        assert!(observations(&r, &result, &h, &samples).is_err());
    }

    #[test]
    fn verifies_pins_bounds_symlinks_and_noclobber_publication() {
        let (dir, mut r, result, host, samples) = data();
        for (pin, value) in [&mut r.runner_result, &mut r.host_observation]
            .into_iter()
            .zip([&result, &host])
            .chain(r.liveness.iter_mut().zip(samples.iter()))
        {
            let bytes = serde_json::to_vec(value).unwrap();
            fs::write(&pin.path, &bytes).unwrap();
            pin.sha256 = gb_core::digest(&bytes);
        }
        let output = dir.path().join("validation.json");
        assert!(inspect_to(&r, &output).is_ok());
        assert!(inspect_to(&r, &output).is_err());
        fs::write(&r.liveness[0].path, b"changed").unwrap();
        assert!(inspect(&r).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("symlink");
            std::os::unix::fs::symlink(&r.runner_result.path, &link).unwrap();
            r.runner_result.path = link;
            assert!(inspect(&r).is_err());
        }
        let large = dir.path().join("large");
        fs::write(&large, vec![b' '; 4097]).unwrap();
        assert!(regular_bytes(&large, 4096).is_err());
    }
}
