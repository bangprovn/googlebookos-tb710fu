//! Separate preparation for the owned displayed-Vulkan handoff. No network/device actions.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const AGENT: &str = include_str!("guest_display/agent.py");
pub const RELAY: &str = include_str!("guest_display/relay.py");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRequest {
    pub guest_boot_id: String,
    pub uid: u32,
    pub compositor_pid: u32,
    pub driver_sha256: String,
    pub profiles_sha256: [String; 2],
    pub program_sha256: String,
    pub program_bytes: u32,
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn bundle(request: &BundleRequest) -> Result<String> {
    ensure!(
        request.guest_boot_id.len() == 36
            && request
                .guest_boot_id
                .split('-')
                .map(str::len)
                .eq([8, 4, 4, 4, 12])
            && hex(&request.guest_boot_id.replace('-', ""), 32),
        "guest boot UUID required"
    );
    ensure!(
        request.uid == 1000
            && (2..=4194304).contains(&request.compositor_pid)
            && hex(&request.driver_sha256, 64)
            && request.profiles_sha256.iter().all(|s| hex(s, 64))
            && hex(&request.program_sha256, 64)
            && (64..=1048576).contains(&request.program_bytes),
        "display context bounds"
    );
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
    fn request() -> BundleRequest {
        BundleRequest {
            guest_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            uid: 1000,
            compositor_pid: 398,
            driver_sha256: "a".repeat(64),
            profiles_sha256: ["b".repeat(64), "c".repeat(64)],
            program_sha256: "d".repeat(64),
            program_bytes: 397808,
        }
    }
    #[test]
    fn binds_context_and_rejects_invalid_bounds() {
        let mut r = request();
        let b = bundle(&r).unwrap();
        assert!(!b.contains("__CONTEXT_HEX__"));
        assert!(b.len() < 65536);
        r.uid = 0;
        assert!(bundle(&r).is_err());
        r = request();
        r.program_bytes = 1048577;
        assert!(bundle(&r).is_err());
        r = request();
        r.guest_boot_id = "$(id)".into();
        assert!(bundle(&r).is_err());
    }
}
