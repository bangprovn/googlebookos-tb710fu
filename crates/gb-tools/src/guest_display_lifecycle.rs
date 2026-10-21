//! Preparation for three capture-gated owned Vulkan swapchain generations.
//! This module prepares source only; it never contacts a device or launches a VM.
pub use crate::guest_display::BundleRequest;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const AGENT: &str = include_str!("guest_display_lifecycle/agent.py");
pub const RELAY: &str = include_str!("guest_display_lifecycle/relay.py");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PhaseContract {
    pub phase: u8,
    pub width: u32,
    pub height: u32,
    pub contract_sha256: String,
}

pub fn phase_contract(phase: u8) -> Result<PhaseContract> {
    ensure!(phase <= 2, "only the three reviewed phases are supported");
    let (width, height) = if phase == 1 { (480, 360) } else { (640, 480) };
    let text = format!(
        "GB_VULKAN_LIFECYCLE_V1:{phase}:{width}:{height}:border=8:palette=19,67,139;203,37,91;47,181,113;211,173,53:rotation={phase}"
    );
    Ok(PhaseContract {
        phase,
        width,
        height,
        contract_sha256: gb_core::digest(text.as_bytes()),
    })
}

pub fn bundle(request: &BundleRequest) -> Result<String> {
    // Preserve the established strict boot/profile/driver/program bounds.
    crate::guest_display::bundle(request)?;
    ensure!(
        AGENT.matches("__CONTEXT_HEX__").count() == 1,
        "agent template mismatch"
    );
    let raw = serde_json::to_vec(request)?;
    let encoded: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let result = AGENT.replace("__CONTEXT_HEX__", &encoded);
    ensure!(result.len() <= 65536, "bootstrap payload budget");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_restored_phase_has_a_distinct_palette_contract() {
        let phases: Vec<_> = (0..3).map(|p| phase_contract(p).unwrap()).collect();
        assert_eq!((phases[0].width, phases[0].height), (640, 480));
        assert_eq!((phases[1].width, phases[1].height), (480, 360));
        assert_eq!((phases[2].width, phases[2].height), (640, 480));
        assert_ne!(phases[0].contract_sha256, phases[2].contract_sha256);
        assert!(phase_contract(3).is_err());
    }
    #[test]
    fn lifecycle_bundle_rejects_invalid_context_and_removes_only_template_slot() {
        let mut r = BundleRequest {
            guest_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            uid: 1000,
            compositor_pid: 398,
            driver_sha256: "a".repeat(64),
            profiles_sha256: ["b".repeat(64), "c".repeat(64)],
            program_sha256: "d".repeat(64),
            program_bytes: 397808,
        };
        let value = bundle(&r).unwrap();
        assert!(!value.contains("__CONTEXT_HEX__"));
        assert!(value.len() <= 65536);
        r.uid = 0;
        assert!(bundle(&r).is_err());
    }
}
