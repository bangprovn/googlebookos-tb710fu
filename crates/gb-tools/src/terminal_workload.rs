//! Bounded original-Terminal workload protocol. Produces input, never sends it.
//!
//! Numbered fragments are part of the protocol, not a heuristic for joining
//! wrapped terminal lines. Capture must reject duplicate, missing or split rows.
use anyhow::{Result, ensure};
use serde::Serialize;

pub const ZERO_SHA256: &str = "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58";
pub const METADATA_REDUCER: &str = include_str!("terminal_workload/reduce-metadata.sh");

#[derive(Debug, Serialize)]
pub struct Plan {
    pub schema_version: u32,
    pub command: String,
    pub success_marker: String,
    pub metadata_prefix: String,
    pub metadata_rows: usize,
    pub maximum_output_row_chars: usize,
    pub android_boot_id: String,
    pub guest_execution_verified: bool,
}

pub(crate) fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn uuid(s: &str) -> bool {
    let parts: Vec<_> = s.split('-').collect();
    parts.len() == 5 && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| hex(p, n))
}
pub(crate) fn octal(s: &str) -> String {
    s.bytes().map(|b| format!("\\{b:03o}")).collect()
}

/// No files, network, settings or history configuration are explicitly written.
/// Existing interactive-shell history policy can still record the typed input.
pub fn prepare(nonce: &str, android_boot_id: &str) -> Result<Plan> {
    ensure!(hex(nonce, 32), "expected 32 lowercase hex nonce characters");
    ensure!(
        uuid(android_boot_id),
        "expected canonical Android boot UUID"
    );
    let marker = format!("GB_UI_EXEC_{nonce}");
    let prefix = nonce[..16].to_owned();
    let mut command = String::from(
        "(LC_ALL=C;export LC_ALL;b=$(cat /proc/sys/kernel/random/boot_id);s=$(uname -s);k=$(uname -r);a=$(uname -m);m=$(awk '/^MemTotal:/{print $2}' /proc/meminfo);h=$(timeout -k 1 3 sh -c 'head -c 1048576 /dev/zero|sha256sum')||exit;h=${h%% *};",
    );
    command.push_str("case \"$b$s$k$a$m$h\" in *[!a-zA-Z0-9_.+-]*)exit 1;;esac;");
    command.push_str(&format!(
        "printf '%b' \"$b\"|grep -Eq '^[0-9a-f]{{8}}(-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}$'||exit;[ \"$b\" != {android_boot_id} ]&&[ \"$s\" = Linux ]&&[ \"$a\" = aarch64 ]&&[ ${{#k}} -le 80 ]||exit;case \"$k\" in 6.12.[0-9]*) :;;*)exit 1;;esac;[ \"$m\" -ge 1966080 ]&&[ \"$m\" -le 2097152 ]&&[ \"$h\" = {ZERO_SHA256} ]||exit;p=$(printf '{}');",
        octal(&prefix)
    ));
    let mut rows = Vec::new();
    for (variable, tag, chunk, count) in [('b', 'b', 18, 2), ('k', 'k', 16, 5), ('h', 's', 16, 4)] {
        for i in 0..count {
            rows.push(format!(
                "$p|{tag}{i}|$(printf '%b' \"${variable}\"|cut -c{}-{})|E",
                i * chunk + 1,
                (i + 1) * chunk
            ));
        }
    }
    rows.extend(["$p|o|$s|E".into(), "$p|a|$a|E".into(), "$p|m|$m|E".into()]);
    command.push_str(&format!(
        "printf '%b' \"\\n{}\\n\";printf '{}')",
        rows.join("\\n"),
        octal(&format!("\n{marker}\n"))
    ));
    ensure!(command.len() <= 2048, "workload exceeds input budget");
    ensure!(
        !command.contains(&marker) && !command.contains(&prefix) && !command.contains("%s"),
        "literal echo or Android input escape collision"
    );
    Ok(Plan {
        schema_version: 1,
        command,
        success_marker: marker,
        metadata_prefix: prefix,
        metadata_rows: 14,
        maximum_output_row_chars: 40,
        android_boot_id: android_boot_id.into(),
        guest_execution_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_and_echo_distinct() {
        let p = prepare(
            "1234567890abcdef0123456789abcdef",
            "12345678-1234-1234-1234-123456789abc",
        )
        .unwrap();
        assert_eq!(p.metadata_rows, 14);
        assert_eq!(p.maximum_output_row_chars, 40);
        assert!(p.command.len() <= 2048);
        assert!(!p.command.contains(&p.success_marker));
        assert!(!p.command.contains(&p.metadata_prefix));
        assert!(!p.guest_execution_verified);
    }
    #[test]
    fn refuses_shell_injection_and_noncanonical_context() {
        let nonce = "1234567890abcdef0123456789abcdef";
        for invalid in ["$(id)", "ABCDEF12345678901234567890123456", "", "1234"] {
            assert!(prepare(invalid, "12345678-1234-1234-1234-123456789abc").is_err());
        }
        for invalid in ["12345678-1234-1234-1234-123456789abC", "a-b-c-d-e", "$(id)"] {
            assert!(prepare(nonce, invalid).is_err());
        }
    }
}
