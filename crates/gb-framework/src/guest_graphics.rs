//! Pinned, reversible guest client GL selection; no host GPU or Vulkan claims.
use crate::rro::PinnedFile;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path};

const SUFFIX: &str = "\n# Googlebook port: virgl clients v1; restore the pinned original to reverse.\n# Scope: automatic GLES driver selection; retain the donor Vulkan selection.\nunset MESA_LOADER_DRIVER_OVERRIDE LIBGL_ALWAYS_SOFTWARE GALLIUM_DRIVER\n";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub donor_fingerprint: String,
    pub target_vendor_fingerprint: String,
    pub enable_display: PinnedFile,
    pub shader_observation: PinnedFile,
}
impl Request {
    pub fn read(path: &Path) -> Result<Self> {
        let mut value: Self = gb_core::read_json(path, 16384)?;
        for input in [&mut value.enable_display, &mut value.shader_observation] {
            if input.path.is_relative() {
                input.path = path.parent().unwrap_or(Path::new(".")).join(&input.path);
            }
        }
        Ok(value)
    }
}

fn bounded(input: &PinnedFile, limit: u64) -> Result<String> {
    let meta = fs::symlink_metadata(&input.path)?;
    ensure!(
        meta.is_file() && meta.len() <= limit,
        "bounded regular input required"
    );
    let mut text = String::new();
    fs::File::open(&input.path)?
        .take(limit + 1)
        .read_to_string(&mut text)?;
    ensure!(
        text.len() as u64 <= limit && !text.contains('\0'),
        "invalid bounded text"
    );
    ensure!(
        gb_core::digest(text.as_bytes()) == input.sha256,
        "input hash mismatch"
    );
    Ok(text)
}

pub fn validate_shader(text: &str) -> Result<serde_json::Value> {
    ensure!(text.len() <= 4096, "shader receipt budget");
    let value: serde_json::Value = serde_json::from_str(text)?;
    let fields = [
        "state",
        "scope",
        "gl",
        "egl_version",
        "frames_verified",
        "pixels_per_frame",
        "max_channel_error",
        "renderer_reports_software",
        "physical_gpu_acceleration_verified",
        "android_scanout_verified",
        "guest_desktop_verified",
        "fixture_artifact_files_written",
        "mesa_shader_cache_disabled",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("shader object required"))?;
    ensure!(
        object.len() == fields.len() && object.keys().all(|k| fields.contains(&k.as_str())),
        "unexpected shader receipt fields; no content payloads accepted"
    );
    let gl = value["gl"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("GL identity required"))?;
    ensure!(
        gl.len() == 3
            && gl
                .keys()
                .all(|k| ["renderer", "vendor", "version"].contains(&k.as_str()))
            && gl.values().all(|v| v.as_str().is_some_and(|s| !s.is_empty()
                && s.len() <= 256
                && !s.chars().any(char::is_control))),
        "bounded GL identity required"
    );
    let renderer = value["gl"]["renderer"].as_str().unwrap_or("");
    ensure!(
        value["state"] == "compatible"
            && value["scope"] == "GLES2 surfaceless shader draw and RGBA8 readback only"
            && value["egl_version"] == "1.5"
            && renderer.starts_with("virgl (")
            && renderer.len() <= 256
            && !["llvmpipe", "softpipe", "swiftshader", "software"]
                .iter()
                .any(|s| renderer.to_ascii_lowercase().contains(s))
            && value["renderer_reports_software"] == false
            && value["frames_verified"]
                .as_u64()
                .is_some_and(|n| (16..=256).contains(&n))
            && value["pixels_per_frame"] == 256
            && value["max_channel_error"].as_u64().is_some_and(|n| n <= 2)
            && value["mesa_shader_cache_disabled"] == true
            && value["fixture_artifact_files_written"] == false
            && value["physical_gpu_acceleration_verified"] == false
            && value["android_scanout_verified"] == false
            && value["guest_desktop_verified"] == false,
        "actual bounded virgl shader/readback receipt required; no wider claims"
    );
    Ok(value)
}

fn patch(source: &str) -> Result<String> {
    ensure!(
        source.starts_with("#!/bin/bash\n")
            && source.ends_with('\n')
            && !source.contains("Googlebook port: virgl clients")
            && source
                .matches("export MESA_LOADER_DRIVER_OVERRIDE=zink\n")
                .count()
                == 1
            && source.matches("export LIBGL_ALWAYS_SOFTWARE=1\n").count() == 1
            && source
                .matches("export VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json\n")
                .count()
                == 1,
        "unexpected or already patched enable_display baseline"
    );
    Ok(format!("{source}{SUFFIX}"))
}

pub fn render(request: &Request, destination: &Path) -> Result<serde_json::Value> {
    ensure!(
        request.schema_version == 1 && !destination.exists(),
        "schema/output guard"
    );
    for fingerprint in [
        &request.donor_fingerprint,
        &request.target_vendor_fingerprint,
    ] {
        ensure!(
            !fingerprint.is_empty()
                && fingerprint.len() <= 512
                && !fingerprint.chars().any(char::is_control),
            "firmware condition required"
        );
    }
    for input in [&request.enable_display, &request.shader_observation] {
        gb_core::separate_from_input(&input.path, destination)?;
    }
    let original = bounded(&request.enable_display, 8192)?;
    let observation = bounded(&request.shader_observation, 4096)?;
    let shader = validate_shader(&observation)?;
    let patched = patch(&original)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let staging = tempfile::tempdir_in(parent)?;
    for (name, text) in [
        ("enable_display", &patched),
        ("enable_display.original", &original),
    ] {
        let file = staging.path().join(name);
        fs::write(&file, text)?;
        fs::File::open(&file)?.sync_all()?;
    }
    let report = serde_json::json!({"schema_version":1,"revision":1,
        "status":"guest_gl_client_candidate_requires_runtime_validation",
        "conditions":{"donor_fingerprint":request.donor_fingerprint,"target_vendor_fingerprint":request.target_vendor_fingerprint},
        "source_sha256":request.enable_display.sha256,"patched_sha256":gb_core::digest(patched.as_bytes()),
        "observation_sha256":request.shader_observation.sha256,"observed_shader":shader,
        "original_bytes_preserved_as_prefix":patched.starts_with(&original),
        "runtime_verified":false,"firmware_written":false,"guest_vulkan_hardware_verified":false,"full_port_verified":false,
        "scope":"Guest client GLES automatic driver selection only; no GPU model/version spoofing, Vulkan changes or library replacement",
        "apply_requirements":["Match both firmware conditions against the connected target","Require the exact original regular-file hash and preserve ownership/mode","Keep the supplied original for exact rollback","Verify a newly started client without per-command overrides and its windowed response"],
        "external_prerequisite":"Owner-provided donor guest script and applicable redistribution rights"});
    gb_core::write_json(&staging.path().join("report.json"), &report)?;
    ensure!(
        bounded(&request.enable_display, 8192)? == original
            && bounded(&request.shader_observation, 4096)? == observation,
        "input changed before publication"
    );
    gb_core::checkpoint()?;
    gb_core::publish_directory(staging.path(), destination)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation() -> serde_json::Value {
        serde_json::json!({"state":"compatible","scope":"GLES2 surfaceless shader draw and RGBA8 readback only","egl_version":"1.5","gl":{"renderer":"virgl (Adreno (TM) 750)","vendor":"Mesa","version":"OpenGL ES 3.2"},"renderer_reports_software":false,"frames_verified":16,"pixels_per_frame":256,"max_channel_error":0,"mesa_shader_cache_disabled":true,"fixture_artifact_files_written":false,"physical_gpu_acceleration_verified":false,"android_scanout_verified":false,"guest_desktop_verified":false})
    }
    #[test]
    fn refuses_cpu_enumeration_and_unverified_draw_or_scope_claims() {
        let good = observation();
        assert!(validate_shader(&good.to_string()).is_ok());
        for name in ["frames_verified", "pixels_per_frame"] {
            let mut v = good.clone();
            v[name] = 0.into();
            assert!(validate_shader(&v.to_string()).is_err());
        }
        for name in [
            "renderer_reports_software",
            "physical_gpu_acceleration_verified",
            "android_scanout_verified",
            "guest_desktop_verified",
            "fixture_artifact_files_written",
        ] {
            let mut v = good.clone();
            v[name] = true.into();
            assert!(validate_shader(&v.to_string()).is_err());
        }
        for renderer in [
            "zink (llvmpipe)",
            "Adreno 750",
            "virgl (llvmpipe)",
            "virgl (SoftPipe)",
        ] {
            let mut v = good.clone();
            v["gl"]["renderer"] = renderer.into();
            assert!(validate_shader(&v.to_string()).is_err());
        }
        let mut missing = good;
        missing["raw_pixels"] = "forbidden".into();
        assert!(validate_shader(&missing.to_string()).is_err());
        missing.as_object_mut().unwrap().remove("raw_pixels");
        missing.as_object_mut().unwrap().remove("max_channel_error");
        assert!(validate_shader(&missing.to_string()).is_err());
    }
    #[test]
    fn preserves_original_and_vulkan_and_refuses_ambiguous_or_repeat_patch() {
        let source = "#!/bin/bash\nexport MESA_LOADER_DRIVER_OVERRIDE=zink\nexport LIBGL_ALWAYS_SOFTWARE=1\nexport VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json\n";
        let patched = patch(source).unwrap();
        assert_eq!(patched.strip_suffix(SUFFIX), Some(source));
        assert!(patch(&patched).is_err());
        assert!(patch(&source.replace("=1\n", "=0\n")).is_err());
        assert!(patch(&(source.to_owned() + "export MESA_LOADER_DRIVER_OVERRIDE=zink\n")).is_err());
    }

    #[test]
    fn publishes_reversible_artifacts_and_refuses_changed_inputs_or_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let receipt = tmp.path().join("shader.json");
        let original = "#!/bin/bash\nexport MESA_LOADER_DRIVER_OVERRIDE=zink\nexport LIBGL_ALWAYS_SOFTWARE=1\nexport VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json\n";
        fs::write(&source, original).unwrap();
        fs::write(&receipt, observation().to_string()).unwrap();
        let pin = |p: &Path| PinnedFile {
            path: p.into(),
            sha256: gb_core::hash_file(p).unwrap(),
        };
        let request = Request {
            schema_version: 1,
            donor_fingerprint: "donor/fixture:17".into(),
            target_vendor_fingerprint: "vendor/fixture:16".into(),
            enable_display: pin(&source),
            shader_observation: pin(&receipt),
        };
        let out = tmp.path().join("candidate");
        let report = render(&request, &out).unwrap();
        assert_eq!(
            fs::read_to_string(out.join("enable_display.original")).unwrap(),
            original
        );
        assert_eq!(
            gb_core::hash_file(&out.join("enable_display")).unwrap(),
            report["patched_sha256"]
        );
        assert_eq!(fs::read_to_string(&source).unwrap(), original);
        assert!(render(&request, &out).is_err());
        fs::write(&source, "changed input\n").unwrap();
        let refused = tmp.path().join("refused");
        assert!(render(&request, &refused).is_err());
        assert!(!refused.exists());
    }
}
