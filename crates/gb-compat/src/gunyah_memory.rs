//! Read-only parser for versioned, non-address-bearing Gunyah memory counters.
//! Measurements do not prove log origin, guest startup, or a firmware memory cap.
use anyhow::{Context, Result, ensure};
use gb_core::State;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
const MARKER: &str = "gb-gunyah-mem-v1:";
const START_ERROR: &str = "RM rejected message 56000004. Error:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub pid: u32,
    pub tid: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allocation {
    pub source_line: usize,
    pub actor: Option<Actor>,
    pub label: u32,
    pub bytes: u64,
    pub pages: u64,
    pub base_page_bytes: u64,
    pub spans: u64,
    pub largest_span: u64,
    /// Includes any compound backing, not an assertion of a particular THP size.
    pub compound_pages: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartFailure {
    pub source_line: usize,
    pub actor: Option<Actor>,
    pub rm_error: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub status: String,
    pub compatibility_state: State,
    pub origin_verified: bool,
    pub guest_boot_verified: bool,
    pub allocations: Vec<Allocation>,
    pub start_failures: Vec<StartFailure>,
}
pub(crate) fn actor(prefix: &str) -> Option<Actor> {
    let mut words = prefix.split_whitespace();
    let date = words.next()?;
    let time = words.next()?;
    // Recognize logcat threadtime only. Other kernel capture formats retain
    // their metrics without guessing actor IDs from unrelated numeric fields.
    fn digits_with_separators(text: &str, separators: &[(usize, u8)], len: usize) -> bool {
        text.len() == len
            && text.bytes().enumerate().all(|(index, byte)| {
                separators
                    .iter()
                    .find(|(at, _)| *at == index)
                    .map_or_else(|| byte.is_ascii_digit(), |(_, expected)| byte == *expected)
            })
    }
    if !digits_with_separators(date, &[(2, b'-')], 5)
        || !digits_with_separators(time, &[(2, b':'), (5, b':'), (8, b'.')], 12)
    {
        return None;
    }
    Some(Actor {
        pid: words.next()?.parse().ok()?,
        tid: words.next()?.parse().ok()?,
    })
}
fn allocation(prefix: &str, text: &str, line: usize) -> Result<Allocation> {
    ensure!(
        text.len() <= 1024,
        "oversized Gunyah counter record at line {line}"
    );
    let mut fields = BTreeMap::new();
    for word in text.split_whitespace() {
        let (key, value) = word.split_once('=').context("counter requires key=value")?;
        ensure!(
            fields
                .insert(
                    key,
                    value.parse::<u64>().context("invalid unsigned counter")?
                )
                .is_none(),
            "duplicate counter: {key}"
        );
    }
    ensure!(
        fields.keys().copied().eq([
            "bytes",
            "compound_pages",
            "label",
            "largest_span",
            "pages",
            "spans"
        ]),
        "missing or unknown Gunyah counter field"
    );
    let bytes = fields["bytes"];
    let pages = fields["pages"];
    let spans = fields["spans"];
    let largest_span = fields["largest_span"];
    let compound_pages = fields["compound_pages"];
    ensure!(
        bytes > 0 && pages > 0 && bytes.is_multiple_of(pages),
        "invalid byte/page geometry"
    );
    let base_page_bytes = bytes / pages;
    ensure!(
        [4096, 16384, 65536].contains(&base_page_bytes),
        "unsupported base-page geometry"
    );
    ensure!(
        spans > 0
            && spans <= pages
            && compound_pages <= pages
            && largest_span > 0
            && largest_span <= bytes
            && largest_span <= bytes - (spans - 1) * base_page_bytes
            && largest_span.is_multiple_of(base_page_bytes)
            && u128::from(largest_span) * u128::from(spans) >= u128::from(bytes),
        "inconsistent allocation counters"
    );
    Ok(Allocation {
        source_line: line,
        actor: actor(prefix),
        label: fields["label"]
            .try_into()
            .context("parcel label overflow")?,
        bytes,
        pages,
        base_page_bytes,
        spans,
        largest_span,
        compound_pages,
    })
}
pub fn inspect(text: &str) -> Result<Report> {
    ensure!(
        text.len() <= MAX_LOG_BYTES,
        "kernel log exceeds inspection budget"
    );
    let mut allocations = Vec::new();
    let mut start_failures = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if let Some((prefix, data)) = line.split_once(MARKER) {
            ensure!(
                allocations.len() < 4096,
                "allocation record budget exceeded"
            );
            allocations.push(
                allocation(prefix, data, index + 1)
                    .with_context(|| format!("Gunyah allocation record at line {}", index + 1))?,
            );
        }
        if let Some((prefix, data)) = line.split_once(START_ERROR) {
            ensure!(
                start_failures.len() < 4096,
                "failure record budget exceeded"
            );
            start_failures.push(StartFailure {
                source_line: index + 1,
                actor: actor(prefix),
                rm_error: data.trim().parse().context("invalid VM_START error code")?,
            });
        }
    }
    Ok(Report {
        schema_version: 1,
        status: if allocations.is_empty() {
            "no_matching_allocation_telemetry"
        } else {
            "allocation_telemetry_observed"
        }
        .into(),
        compatibility_state: State::Unknown,
        origin_verified: false,
        guest_boot_verified: false,
        allocations,
        start_failures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const RECORD: &str = "10-18 15:00:00.123 200 201 I gh_vm_mgr: gb-gunyah-mem-v1: label=0 bytes=1073741824 pages=262144 spans=512 largest_span=2097152 compound_pages=262144";
    #[test]
    fn reads_actor_geometry_and_start_failure_without_claiming_boot() -> Result<()> {
        let r = inspect(&format!(
            "{RECORD}\n10-18 15:00:01.123 200 201 W gh_rsc_mgr: RM rejected message 56000004. Error: 2\n"
        ))?;
        assert_eq!(r.allocations.len(), 1);
        let a = &r.allocations[0];
        assert_eq!(a.base_page_bytes, 4096);
        assert_eq!(a.actor.as_ref().unwrap().pid, 200);
        assert_eq!(r.start_failures[0].rm_error, 2);
        assert!(!r.guest_boot_verified && !r.origin_verified);
        assert!(matches!(r.compatibility_state, State::Unknown));
        Ok(())
    }
    #[test]
    fn refuses_malformed_inconsistent_and_overflowing_counters() {
        for (from, to) in [
            ("pages=262144", "pages=0"),
            ("spans=512", "spans=0"),
            ("largest_span=2097152", "largest_span=4096"),
            ("compound_pages=262144", "compound_pages=262145"),
            ("label=0", "label=4294967296"),
            ("label=0", "label=-1"),
            ("spans=512", "spans=512 extra=1"),
            ("spans=512", "spans=512 spans=512"),
            ("largest_span=2097152", "largest_span=1073741824"),
        ] {
            assert!(inspect(&RECORD.replace(from, to)).is_err(), "{to}");
        }
    }
    #[test]
    fn missing_metrics_and_other_log_formats_do_not_invent_evidence() -> Result<()> {
        let r = inspect("unrelated kernel message")?;
        assert_eq!(r.status, "no_matching_allocation_telemetry");
        assert!(r.allocations.is_empty());
        let r = inspect(RECORD.split_once(MARKER).unwrap().1.to_string().as_str())?;
        assert!(r.allocations.is_empty());
        let r = inspect(&format!(
            "gh_vm_mgr: {MARKER}{}",
            RECORD.split_once(MARKER).unwrap().1
        ))?;
        assert!(r.allocations[0].actor.is_none());
        for invalid in ["aa-bb 15:00:00.123", "10-18 15:00", "10-18 15:xx:00.123"] {
            let r = inspect(&format!(
                "{invalid} 200 201 I gh_vm_mgr: {MARKER}{}",
                RECORD.split_once(MARKER).unwrap().1
            ))?;
            assert!(r.allocations[0].actor.is_none());
        }
        Ok(())
    }
}
