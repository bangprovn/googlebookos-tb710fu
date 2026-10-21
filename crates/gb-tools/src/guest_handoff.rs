//! Integrity-bound transfer of an owned fixture into a caller-bound running guest.
//! No network, device action or payload execution occurs during preparation.
use crate::terminal_workload::{hex, octal, uuid};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const AGENT: &str = include_str!("guest_handoff/agent.py");
pub const RELAY: &str = include_str!("guest_handoff/relay.py");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub host: Ipv4Addr,
    pub port: u16,
    pub route_nonce: String,
    pub observer_nonce: String,
    pub guest_boot_id: String,
    pub payload_sha256: String,
    pub payload_bytes: u32,
}
#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub command: String,
    pub success_marker: String,
    pub guest_boot_id: String,
    pub payload_sha256: String,
    pub payload_bytes: u32,
    pub temporary_file_created: bool,
    pub guest_execution_verified: bool,
}
pub fn prepare(r: &Request) -> Result<Plan> {
    ensure!(
        r.host.is_private() && r.port >= 1024,
        "explicit private IPv4 host/nonprivileged port required"
    );
    ensure!(
        hex(&r.route_nonce, 32)
            && hex(&r.observer_nonce, 32)
            && r.route_nonce != r.observer_nonce
            && uuid(&r.guest_boot_id),
        "invalid handoff nonce or boot identity"
    );
    ensure!(
        hex(&r.payload_sha256, 64) && (1..=65536).contains(&r.payload_bytes),
        "invalid bounded owned payload"
    );
    let base = format!("http://{}:{}/{}", r.host, r.port, r.route_nonce);
    let marker = format!("GB_UI_EXEC_{}", r.observer_nonce);
    let command = format!(
        "(umask 077;[ \"$(cat /proc/sys/kernel/random/boot_id)\" = {} ]||exit;f=$(mktemp '/tmp/gb-gfx-{}.XXXXXX')||exit;trap 'rm -f \"$f\"' 0;trap 'exit 2' 1 2 15;timeout -k 1 9 curl -q --noproxy '*' --proto '=http' --connect-timeout 3 --max-time 7 --max-filesize 65536 --fail --silent --output \"$f\" {base}/runner.py||exit;[ \"$(wc -c < \"$f\")\" = {} ]&&[ \"$(sha256sum \"$f\"|cut -c1-64)\" = {} ]||exit;timeout -k 1 20 python3 \"$f\" {base} {}||exit;rm -f \"$f\"&&[ ! -e \"$f\" ]||exit;printf '{}')",
        r.guest_boot_id,
        r.route_nonce,
        r.payload_bytes,
        r.payload_sha256,
        r.payload_sha256,
        octal(&format!("\n{marker}\n"))
    );
    ensure!(
        command.len() <= 2048 && !command.contains(&marker) && !command.contains("%s"),
        "handoff command exceeds echo/input contract"
    );
    Ok(Plan {
        schema_version: 1,
        command,
        success_marker: marker,
        guest_boot_id: r.guest_boot_id.clone(),
        payload_sha256: r.payload_sha256.clone(),
        payload_bytes: r.payload_bytes,
        temporary_file_created: true,
        guest_execution_verified: false,
    })
}
pub fn graphics_bundle(fixture: &str, guest_boot_id: &str) -> Result<String> {
    ensure!(
        uuid(guest_boot_id) && !fixture.is_empty() && fixture.len() <= 24576,
        "invalid owned fixture or guest context"
    );
    ensure!(
        AGENT.matches("__FIXTURE_HEX__").count() == 1
            && AGENT.matches("__GUEST_BOOT__").count() == 1,
        "agent template mismatch"
    );
    let encoded: String = fixture.bytes().map(|v| format!("{v:02x}")).collect();
    let bundle = AGENT
        .replace("__FIXTURE_HEX__", &encoded)
        .replace("__GUEST_BOOT__", guest_boot_id);
    ensure!(
        bundle.len() <= 65536,
        "owned bundle exceeds transfer budget"
    );
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            host: Ipv4Addr::new(192, 168, 1, 2),
            port: 18000,
            route_nonce: "a".repeat(32),
            observer_nonce: "b".repeat(32),
            guest_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            payload_sha256: "c".repeat(64),
            payload_bytes: 1234,
        }
    }
    #[test]
    fn command_verifies_before_executing_and_removes_only_own_file() {
        let p = prepare(&request()).unwrap();
        assert!(!p.command.contains(&p.success_marker));
        assert!(p.command.find("sha256sum").unwrap() < p.command.find("python3").unwrap());
        assert!(p.command.contains("trap 'rm -f \"$f\"' 0"));
        assert!(!p.guest_execution_verified);
    }
    #[test]
    fn refuses_public_destination_bad_nonce_and_oversized_payload() {
        let mut r = request();
        r.host = Ipv4Addr::new(8, 8, 8, 8);
        assert!(prepare(&r).is_err());
        r = request();
        r.route_nonce = "$(id)".into();
        assert!(prepare(&r).is_err());
        r = request();
        r.payload_bytes = 65537;
        assert!(prepare(&r).is_err());
        assert!(graphics_bundle("x", "$(id)").is_err());
    }
}
