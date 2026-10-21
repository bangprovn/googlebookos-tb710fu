//! Original guest network checks; preparation and validation never contact a device.
use crate::terminal_workload::{hex, octal, uuid};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const URL: &str = "https://deb.debian.org/debian/README";
pub const METADATA_REDUCER: &str = include_str!("terminal_network/reduce-network.sh");

#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub command: String,
    pub success_marker: String,
    pub metadata_prefix: String,
    pub metadata_rows: usize,
    pub maximum_output_row_chars: usize,
    pub guest_boot_id: String,
    pub endpoint: &'static str,
    pub guest_execution_verified: bool,
}

pub fn prepare(nonce: &str, guest_boot_id: &str) -> Result<Plan> {
    ensure!(
        hex(nonce, 32) && uuid(guest_boot_id),
        "invalid network probe nonce or guest UUID"
    );
    let marker = format!("GB_UI_EXEC_{nonce}");
    let prefix = &nonce[..16];
    let mut command = format!(
        "(LC_ALL=C;export LC_ALL;[ \"$(cat /proc/sys/kernel/random/boot_id)\" = {guest_boot_id} ]||exit;p=$(printf '{}');tc=0;tg=0;de=127;ce=127;hc=000;nb=0;tv=-1;pr=0;command -v curl >/dev/null 2>&1&&tc=1;command -v getent >/dev/null 2>&1&&tg=1;if [ $tg = 1 ];then timeout -k 1 4 getent ahosts deb.debian.org >/dev/null 2>&1;de=$?;fi;",
        octal(prefix)
    );
    command.push_str(&format!(
        "if [ $tc = 1 ];then r=$(timeout -k 1 12 curl -q --noproxy '*' --proto '=https' --max-filesize 65536 --connect-timeout 3 --max-time 10 --silent --output /dev/null --write-out '%{{http_code}}|%{{size_download}}|%{{ssl_verify_result}}' {URL} 2>/dev/null);ce=$?;case \"$r\" in ''|*[!0-9\\|-]*) :;;*)hc=${{r%%|*}};r=${{r#*|}};nb=${{r%%|*}};tv=${{r#*|}};if [ ${{#hc}} = 3 ];then case \"$nb:$tv\" in *[!0-9:]*) :;;*)[ -n \"$nb\" ]&&[ -n \"$tv\" ]&&pr=1;;esac;fi;;esac;if [ $pr = 0 ];then hc=000;nb=0;tv=-1;fi;fi;"
    ));
    let rows = ["tc", "tg", "de", "ce", "hc", "nb", "tv", "pr"]
        .map(|tag| format!("$p|{tag}|${tag}|E"))
        .join("\\n");
    command.push_str(&format!(
        "printf '%b' \"\\n{rows}\\n\";[ $tc = 1 ]&&[ $tg = 1 ]&&[ $de = 0 ]&&[ $ce = 0 ]&&[ $pr = 1 ]&&[ \"$hc\" = 200 ]&&[ \"$nb\" -gt 0 ]&&[ \"$nb\" -le 65536 ]&&[ \"$tv\" = 0 ]||exit 1;printf '{}')",
        octal(&format!("\n{marker}\n"))
    ));
    ensure!(
        command.len() <= 2048
            && !command.contains("%s")
            && !command.contains(&marker)
            && !command.contains(prefix),
        "network command exceeds input or echo-safety contract"
    );
    Ok(Plan {
        schema_version: 1,
        command,
        success_marker: marker,
        metadata_prefix: prefix.into(),
        metadata_rows: 8,
        maximum_output_row_chars: 32,
        guest_boot_id: guest_boot_id.into(),
        endpoint: URL,
        guest_execution_verified: false,
    })
}

/// A decoder's scalar result. External caller must bind nonce, device, guest,
/// APK, native/main birth tuples, post-Enter observation and cleanup separately.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32,
    pub status: String,
    pub fields: u32,
    pub nodes: u32,
    pub eligible_text_nodes: u32,
    pub curl_present: u32,
    pub getent_present: u32,
    pub resolver_exit: u32,
    pub curl_exit: u32,
    pub http_status: u32,
    pub downloaded_bytes: u64,
    pub tls_verify_result: i32,
    pub metrics_parsed: u32,
    pub exact_expected_prefix_matching: bool,
    pub unique_complete_full_rows: bool,
    pub input_performed: bool,
    pub raw_other_content_exported: bool,
    pub command_execution_verified: bool,
}
impl Observation {
    pub fn validate(&self) -> Result<bool> {
        ensure!(
            self.schema_version == 1
                && self.status == "owned_guest_network_observed"
                && self.fields == 8,
            "network observation schema mismatch"
        );
        ensure!(
            (8..=4096).contains(&self.nodes)
                && (8..=self.nodes).contains(&self.eligible_text_nodes),
            "network observation exceeds node budget"
        );
        ensure!(
            self.curl_present <= 1
                && self.getent_present <= 1
                && self.metrics_parsed <= 1
                && self.resolver_exit <= 255
                && self.curl_exit <= 255
                && (self.http_status == 0 || (100..=599).contains(&self.http_status))
                && self.downloaded_bytes <= 65536
                && (-1..=65535).contains(&self.tls_verify_result),
            "invalid network metric"
        );
        ensure!(
            self.exact_expected_prefix_matching
                && self.unique_complete_full_rows
                && !self.input_performed
                && !self.raw_other_content_exported
                && !self.command_execution_verified,
            "network capture scope mismatch"
        );
        Ok(self.curl_present == 1
            && self.getent_present == 1
            && self.metrics_parsed == 1
            && self.resolver_exit == 0
            && self.curl_exit == 0
            && self.http_status == 200
            && self.downloaded_bytes > 0
            && self.tls_verify_result == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_network_plan_has_no_literal_echo_proof() {
        let p = prepare(
            "9876543210abcdef0123456789abcdef",
            "abcdef01-2345-6789-abcd-0123456789ab",
        )
        .unwrap();
        assert_eq!(p.metadata_rows, 8);
        assert!(p.command.len() <= 2048);
        assert!(!p.command.contains(&p.success_marker));
        assert!(!p.command.contains(&p.metadata_prefix));
        assert!(!p.guest_execution_verified);
    }
    #[test]
    fn rejects_injected_context() {
        assert!(prepare("$(id)", "abcdef01-2345-6789-abcd-0123456789ab").is_err());
        assert!(prepare("9876543210abcdef0123456789abcdef", "$(id)").is_err());
    }
}
