//! Normalize bounded native-image witnesses. Caller-provided JSON is not device provenance.
use anyhow::{Context, Result, ensure};
use gb_core::State;
use serde::{Deserialize, Serialize};

pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EglExtensions {
    #[serde(rename = "EGL_EXT_image_dma_buf_import")]
    dma_buf: bool,
    #[serde(rename = "EGL_EXT_image_dma_buf_import_modifiers")]
    modifiers: bool,
    #[serde(rename = "EGL_ANDROID_image_native_buffer")]
    native_buffer: bool,
    #[serde(rename = "EGL_ANDROID_get_native_client_buffer")]
    native_client: bool,
    #[serde(rename = "EGL_ANDROID_native_fence_sync")]
    native_fence: bool,
    #[serde(rename = "EGL_KHR_fence_sync")]
    fence: bool,
    #[serde(rename = "EGL_KHR_surfaceless_context")]
    surfaceless: bool,
    #[serde(rename = "EGL_KHR_gl_texture_2D_image")]
    texture_image: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GlExtensions {
    #[serde(rename = "GL_OES_EGL_image")]
    image: bool,
    #[serde(rename = "GL_EXT_EGL_image_storage")]
    image_storage: bool,
    #[serde(rename = "GL_EXT_memory_object")]
    memory_object: bool,
    #[serde(rename = "GL_EXT_memory_object_fd")]
    memory_fd: bool,
    #[serde(rename = "GL_EXT_semaphore")]
    semaphore: bool,
    #[serde(rename = "GL_EXT_semaphore_fd")]
    semaphore_fd: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    schema_version: u32,
    status: String,
    uid: u32,
    egl_vendor: String,
    egl_version: String,
    gles_vendor: String,
    gles_renderer: String,
    gles_version: String,
    egl_extensions: EglExtensions,
    gles_extensions: GlExtensions,
    egl_create_image_entrypoint: bool,
    egl_native_client_buffer_entrypoint: bool,
    memory_import_verified: bool,
    gpu_rendering_verified: bool,
    original_vmm_namespace_verified: bool,
    owner_content_read: bool,
    full_port_verified: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sampling {
    schema_version: u32,
    status: String,
    source_udmabuf_gpu_copy: bool,
    #[serde(default)]
    source_vulkan_dmabuf_gpu_copy: bool,
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
struct FailedSampling {
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
enum SamplingReceipt {
    Passed(Sampling),
    Failed(FailedSampling),
}
#[derive(Debug, Serialize)]
pub struct Failure {
    pub state: State,
    pub stage: String,
    pub code: i32,
    pub rounds_before_failure: u32,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub state: State,
    pub scope: &'static str,
    pub reported_uid: u32,
    pub reported_gles_vendor: String,
    pub reported_gles_renderer: String,
    pub linux_dma_buf_import_advertised: bool,
    pub linux_dma_buf_modifiers_advertised: bool,
    pub android_native_buffer_import_advertised: bool,
    pub opaque_memory_fd_advertised: bool,
    pub semaphore_fd_advertised: bool,
    pub native_fence_advertised: bool,
    pub fence_advertised: bool,
    pub surfaceless_advertised: bool,
    pub gl_image_storage_advertised: bool,
    pub reported_direct_ahb_sampling_passes: usize,
    pub reported_udmabuf_gpu_copy_passes: usize,
    pub reported_vulkan_dmabuf_gpu_copy_passes: usize,
    pub failures: Vec<Failure>,
    pub source_sha256: Vec<String>,
    pub originating_device_verified: bool,
    pub original_vmm_namespace_verified: bool,
    pub guest_integration_verified: bool,
    pub native_presentation_verified: bool,
    pub full_port_verified: bool,
}
fn bounded<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    ensure!(
        text.len() < MAX_RECEIPT_BYTES,
        "native-image receipt reached capture budget"
    );
    serde_json::from_str(text).context("invalid native-image receipt")
}
fn text(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "invalid driver identity string"
    );
    Ok(())
}
fn validate_sampling(s: &Sampling) -> Result<()> {
    ensure!(
        ((s.schema_version == 1 && !s.source_vulkan_dmabuf_gpu_copy)
            || (s.schema_version == 2 && s.source_vulkan_dmabuf_gpu_copy))
            && s.status == "vulkan_ahb_gles_sampling_verified",
        "sampling protocol/status mismatch"
    );
    ensure!(
        !(s.source_udmabuf_gpu_copy && s.source_vulkan_dmabuf_gpu_copy),
        "source allocation kinds cannot both be true"
    );
    ensure!(
        !s.guest_integration_verified
            && !s.original_vmm_namespace_verified
            && !s.owner_content_read
            && !s.full_port_verified,
        "sampling receipt exceeds probe scope"
    );
    ensure!(
        s.rounds_verified == 2 && s.pixels_verified == 2048 && s.maximum_channel_error <= 1,
        "sampling pixels/rounds/tolerance incomplete"
    );
    ensure!(
        s.gpu_vulkan_clear
            && s.foreign_ownership_and_fence_wait
            && s.egl_image_reused
            && s.before_and_after_cpu_texture_controls
            && s.ahb_sharing_verified,
        "required GPU/control witnesses absent"
    );
    ensure!(
        !s.cpu_frame_copy_used && !s.cpu_ahb_mapping_used,
        "CPU-authored hardware-buffer result cannot qualify this GPU route"
    );
    ensure!(
        (4096..=1024 * 1024).contains(&s.allocation_bytes)
            && (32..=8192).contains(&s.ahb_stride_pixels),
        "AHB allocation budget"
    );
    ensure!(
        u64::from(s.ahb_stride_pixels) * 31 * 4 + 128 <= s.allocation_bytes,
        "AHB stride exceeds allocation"
    );
    ensure!(
        s.ahb_usage & 768 == 768 && s.ahb_usage & (1 << 14) == 0,
        "AHB usage lacks GPU access or includes protected access"
    );
    if s.source_udmabuf_gpu_copy || s.source_vulkan_dmabuf_gpu_copy {
        ensure!(
            (4096..=1024 * 1024).contains(&s.source_bytes)
                && (128..=65536).contains(&s.source_stride)
                && s.source_stride.is_multiple_of(4),
            "source DMA-BUF allocation/layout budget"
        );
        ensure!(
            31 * s.source_stride + 128 <= s.source_bytes,
            "source DMA-BUF stride exceeds allocation"
        );
    } else {
        ensure!(
            s.source_bytes == 0 && s.source_stride == 0,
            "direct AHB receipt claims a source copy layout"
        );
    }
    Ok(())
}
/// Validates reported bounded operations; it never executes a GPU/device tool or upgrades provenance.
pub fn inspect(capabilities: &str, sampling: &[&str]) -> Result<Report> {
    ensure!(sampling.len() <= 4, "native-image witness count budget");
    let c: Capabilities = bounded(capabilities)?;
    ensure!(
        c.schema_version == 1 && c.status == "host_egl_capability_advertisements",
        "capability protocol/status mismatch"
    );
    ensure!(
        !c.memory_import_verified
            && !c.gpu_rendering_verified
            && !c.original_vmm_namespace_verified
            && !c.owner_content_read
            && !c.full_port_verified,
        "advertisement receipt exceeds its scope"
    );
    for value in [
        &c.egl_vendor,
        &c.egl_version,
        &c.gles_vendor,
        &c.gles_renderer,
        &c.gles_version,
    ] {
        text(value)?;
    }
    ensure!(
        !c.egl_extensions.modifiers || c.egl_extensions.dma_buf,
        "EGL modifier import contradicts missing base import extension"
    );
    ensure!(
        (!c.gles_extensions.memory_fd || c.gles_extensions.memory_object)
            && (!c.gles_extensions.semaphore_fd || c.gles_extensions.semaphore),
        "FD extension contradicts missing base object extension"
    );
    let native = c.egl_extensions.native_buffer
        && c.egl_extensions.native_client
        && c.egl_extensions.texture_image
        && c.gles_extensions.image
        && c.egl_create_image_entrypoint
        && c.egl_native_client_buffer_entrypoint;
    let mut direct = 0;
    let mut copies = 0;
    let mut exported_copies = 0;
    let mut failures = Vec::new();
    let mut digests = vec![gb_core::digest(capabilities.as_bytes())];
    for source in sampling {
        let digest = gb_core::digest(source.as_bytes());
        ensure!(
            !digests.contains(&digest),
            "duplicate native-image witness cannot add confidence"
        );
        digests.push(digest);
        match bounded::<SamplingReceipt>(source)? {
            SamplingReceipt::Passed(s) => {
                validate_sampling(&s)?;
                ensure!(
                    native,
                    "AHB sampling contradicts declared native-image prerequisites"
                );
                if s.source_vulkan_dmabuf_gpu_copy {
                    exported_copies += 1;
                } else if s.source_udmabuf_gpu_copy {
                    copies += 1;
                } else {
                    direct += 1;
                }
            }
            SamplingReceipt::Failed(s) => {
                ensure!(
                    s.schema_version == 1
                        && s.status == "failed"
                        && s.rounds_verified <= 2
                        && !s.ahb_sharing_verified
                        && !s.guest_integration_verified
                        && !s.full_port_verified,
                    "failed sampling receipt contradicts scope"
                );
                ensure!(
                    !s.stage.is_empty()
                        && s.stage.len() <= 96
                        && s.stage
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "invalid failure stage"
                );
                failures.push(Failure {
                    state: State::Unknown,
                    stage: s.stage,
                    code: s.code,
                    rounds_before_failure: s.rounds_verified,
                });
            }
        }
    }
    let state = if c.egl_extensions.dma_buf {
        State::Unknown
    } else if direct + copies + exported_copies > 0 {
        State::ImplementationRequired
    } else {
        State::PatchRequired
    };
    Ok(Report {
        schema_version: 1,
        state,
        scope: "Validated caller-provided host advertisements and generated 32x32 image witnesses; originating device and guest integration unverified",
        reported_uid: c.uid,
        reported_gles_vendor: c.gles_vendor,
        reported_gles_renderer: c.gles_renderer,
        linux_dma_buf_import_advertised: c.egl_extensions.dma_buf,
        linux_dma_buf_modifiers_advertised: c.egl_extensions.modifiers,
        android_native_buffer_import_advertised: native,
        opaque_memory_fd_advertised: c.gles_extensions.memory_object && c.gles_extensions.memory_fd,
        semaphore_fd_advertised: c.gles_extensions.semaphore && c.gles_extensions.semaphore_fd,
        native_fence_advertised: c.egl_extensions.native_fence,
        fence_advertised: c.egl_extensions.fence,
        surfaceless_advertised: c.egl_extensions.surfaceless,
        gl_image_storage_advertised: c.gles_extensions.image_storage,
        reported_direct_ahb_sampling_passes: direct,
        reported_udmabuf_gpu_copy_passes: copies,
        reported_vulkan_dmabuf_gpu_copy_passes: exported_copies,
        failures,
        source_sha256: digests,
        originating_device_verified: false,
        original_vmm_namespace_verified: false,
        guest_integration_verified: false,
        native_presentation_verified: false,
        full_port_verified: false,
    })
}

/// Read bounded regular receipts without executing anything from their directories.
pub fn inspect_files(
    capabilities: &std::path::Path,
    sampling: &[std::path::PathBuf],
) -> Result<Report> {
    use std::io::Read;
    ensure!(sampling.len() <= 4, "native-image witness count budget");
    fn read(path: &std::path::Path) -> Result<String> {
        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        ensure!(file.metadata()?.is_file(), "regular receipt file required");
        let mut value = String::new();
        file.take(MAX_RECEIPT_BYTES as u64)
            .read_to_string(&mut value)?;
        ensure!(
            value.len() < MAX_RECEIPT_BYTES,
            "native-image receipt reached capture budget"
        );
        Ok(value)
    }
    let caps = read(capabilities)?;
    let samples: Vec<_> = sampling.iter().map(|p| read(p)).collect::<Result<_>>()?;
    inspect(
        &caps,
        &samples.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn caps() -> Value {
        json!({"schema_version":1,"status":"host_egl_capability_advertisements","uid":2000,"egl_vendor":"Android","egl_version":"1.5","gles_vendor":"example","gles_renderer":"example GPU","gles_version":"ES 3.2","egl_extensions":{"EGL_EXT_image_dma_buf_import":false,"EGL_EXT_image_dma_buf_import_modifiers":false,"EGL_ANDROID_image_native_buffer":true,"EGL_ANDROID_get_native_client_buffer":true,"EGL_ANDROID_native_fence_sync":true,"EGL_KHR_fence_sync":true,"EGL_KHR_surfaceless_context":true,"EGL_KHR_gl_texture_2D_image":true},"gles_extensions":{"GL_OES_EGL_image":true,"GL_EXT_EGL_image_storage":true,"GL_EXT_memory_object":true,"GL_EXT_memory_object_fd":true,"GL_EXT_semaphore":false,"GL_EXT_semaphore_fd":false},"egl_create_image_entrypoint":true,"egl_native_client_buffer_entrypoint":true,"memory_import_verified":false,"gpu_rendering_verified":false,"original_vmm_namespace_verified":false,"owner_content_read":false,"full_port_verified":false})
    }
    fn pass() -> Value {
        json!({"schema_version":1,"status":"vulkan_ahb_gles_sampling_verified","source_udmabuf_gpu_copy":false,"source_bytes":0,"source_stride":0,"cpu_frame_copy_used":false,"rounds_verified":2,"pixels_verified":2048,"maximum_channel_error":0,"allocation_bytes":8192,"ahb_stride_pixels":64,"ahb_usage":768,"gpu_vulkan_clear":true,"cpu_ahb_mapping_used":false,"foreign_ownership_and_fence_wait":true,"egl_image_reused":true,"before_and_after_cpu_texture_controls":true,"ahb_sharing_verified":true,"guest_integration_verified":false,"original_vmm_namespace_verified":false,"owner_content_read":false,"full_port_verified":false})
    }
    #[test]
    fn advertisements_cannot_qualify_native_presentation() {
        let report = inspect(&caps().to_string(), &[]).unwrap();
        assert_eq!(report.state, State::PatchRequired);
        assert!(!report.native_presentation_verified);
    }
    #[test]
    fn host_pixel_proof_leaves_guest_adaptation_required() {
        let report = inspect(&caps().to_string(), &[&pass().to_string()]).unwrap();
        assert_eq!(report.state, State::ImplementationRequired);
        assert_eq!(report.reported_direct_ahb_sampling_passes, 1);
        assert!(
            !report.originating_device_verified
                && !report.guest_integration_verified
                && !report.full_port_verified
        );
    }
    #[test]
    fn permission_failure_is_unknown_not_hardware_incompatibility() {
        let failure = json!({"schema_version":1,"status":"failed","stage":"udmabuf_open","code":13,"rounds_verified":0,"ahb_sharing_verified":false,"guest_integration_verified":false,"full_port_verified":false});
        let report = inspect(
            &caps().to_string(),
            &[&pass().to_string(), &failure.to_string()],
        )
        .unwrap();
        assert_eq!(report.reported_direct_ahb_sampling_passes, 1);
        assert_eq!(report.reported_udmabuf_gpu_copy_passes, 0);
        assert_eq!(report.failures[0].state, State::Unknown);
    }
    #[test]
    fn rejects_partial_or_cpu_authored_successes() {
        for (field, value) in [
            ("pixels_verified", json!(1024)),
            ("rounds_verified", json!(1)),
            ("cpu_ahb_mapping_used", json!(true)),
            ("cpu_frame_copy_used", json!(true)),
            ("before_and_after_cpu_texture_controls", json!(false)),
            ("foreign_ownership_and_fence_wait", json!(false)),
            ("maximum_channel_error", json!(2)),
        ] {
            let mut v = pass();
            v[field] = value;
            assert!(
                inspect(&caps().to_string(), &[&v.to_string()]).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn rejects_scope_escalation_and_missing_proof() {
        for field in [
            "guest_integration_verified",
            "original_vmm_namespace_verified",
            "full_port_verified",
            "owner_content_read",
        ] {
            let mut v = pass();
            v[field] = json!(true);
            assert!(inspect(&caps().to_string(), &[&v.to_string()]).is_err());
        }
        let mut v = pass();
        v.as_object_mut().unwrap().remove("egl_image_reused");
        assert!(inspect(&caps().to_string(), &[&v.to_string()]).is_err());
    }
    #[test]
    fn validates_copy_layout_and_ahb_access_constraints() {
        let mut v = pass();
        v["source_udmabuf_gpu_copy"] = json!(true);
        v["source_bytes"] = json!(8192);
        v["source_stride"] = json!(256);
        let report = inspect(&caps().to_string(), &[&v.to_string()]).unwrap();
        assert_eq!(report.reported_udmabuf_gpu_copy_passes, 1);
        for (field, value) in [
            ("source_stride", json!(65536)),
            ("allocation_bytes", json!(4096)),
            ("ahb_usage", json!(768 | (1 << 14))),
        ] {
            let mut bad = v.clone();
            bad[field] = value;
            assert!(inspect(&caps().to_string(), &[&bad.to_string()]).is_err());
        }
    }
    #[test]
    fn cpu_access_permission_is_not_cpu_authorship() {
        let mut v = pass();
        v["ahb_usage"] = json!(771);
        let report = inspect(&caps().to_string(), &[&v.to_string()]).unwrap();
        assert_eq!(report.reported_direct_ahb_sampling_passes, 1);
        v["cpu_ahb_mapping_used"] = json!(true);
        assert!(inspect(&caps().to_string(), &[&v.to_string()]).is_err());
    }
    #[test]
    fn exported_dmabuf_copy_does_not_qualify_guest_udmabuf() {
        let mut v = pass();
        v["schema_version"] = json!(2);
        v["source_vulkan_dmabuf_gpu_copy"] = json!(true);
        v["source_bytes"] = json!(8192);
        v["source_stride"] = json!(256);
        let report = inspect(&caps().to_string(), &[&v.to_string()]).unwrap();
        assert_eq!(report.reported_vulkan_dmabuf_gpu_copy_passes, 1);
        assert_eq!(report.reported_udmabuf_gpu_copy_passes, 0);
        assert_eq!(report.reported_direct_ahb_sampling_passes, 0);
        assert!(!report.guest_integration_verified);
        v["source_udmabuf_gpu_copy"] = json!(true);
        assert!(inspect(&caps().to_string(), &[&v.to_string()]).is_err());
        v["source_udmabuf_gpu_copy"] = json!(false);
        v["schema_version"] = json!(1);
        assert!(inspect(&caps().to_string(), &[&v.to_string()]).is_err());
        v["schema_version"] = json!(2);
        v["source_vulkan_dmabuf_gpu_copy"] = json!(false);
        assert!(inspect(&caps().to_string(), &[&v.to_string()]).is_err());
    }
    #[test]
    fn rejects_duplicate_fields_malformed_types_and_oversized_input() {
        let c = caps().to_string();
        assert!(inspect(&" ".repeat(MAX_RECEIPT_BYTES), &[]).is_err());
        let bad = c.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(inspect(&bad, &[]).is_err());
        let mut v = pass();
        v["pixels_verified"] = json!(true);
        assert!(inspect(&c, &[&v.to_string()]).is_err());
        assert!(inspect(&c, &["{}"; 5]).is_err());
        let witness = pass().to_string();
        assert!(inspect(&c, &[&witness, &witness]).is_err());
    }
    #[test]
    fn rejects_contradictory_extension_dependencies() {
        let mut c = caps();
        c["egl_extensions"]["EGL_EXT_image_dma_buf_import_modifiers"] = json!(true);
        assert!(inspect(&c.to_string(), &[]).is_err());
        let mut c = caps();
        c["gles_extensions"]["GL_EXT_memory_object"] = json!(false);
        assert!(inspect(&c.to_string(), &[]).is_err());
    }
    #[test]
    fn rejects_success_without_native_import_prerequisites() {
        let mut c = caps();
        c["egl_native_client_buffer_entrypoint"] = json!(false);
        assert!(inspect(&c.to_string(), &[&pass().to_string()]).is_err());
    }
}
