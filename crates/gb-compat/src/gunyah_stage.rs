//! Versioned VM construction telemetry. A successful ioctl is not guest boot.
//! Correlate only within one logcat thread; raw kernel records stay unattributed.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::gunyah_memory::{Actor, MAX_LOG_BYTES, actor};

const MARKER: &str = "gb-gunyah-start-v1:";
const MAX_RECORDS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    AddFunction,
    DtbConfig,
    Notifier,
    AllocVmid,
    PciFixup,
    Parcel,
    Configure,
    Initialize,
    Resources,
    Start,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Begin,
    Result,
    Checkpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub source_line: usize,
    pub actor: Option<Actor>,
    pub stage: Stage,
    pub action: Action,
    pub fields: BTreeMap<String, i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadEvidence {
    pub actor: Actor,
    pub event_count: usize,
    pub negative_result_lines: Vec<usize>,
    pub unfinished_begin_lines: Vec<usize>,
    /// Last observed result in this thread, not a VM identity or boot-boundary proof.
    pub start_result: Option<i64>,
    /// Incomplete capture, not proof that a pending operation caused a reset.
    pub last_event_line: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub origin_verified: bool,
    pub guest_boot_verified: bool,
    pub terminal_session_verified: bool,
    pub reset_cause_verified: bool,
    pub events: Vec<Event>,
    pub threads: Vec<ThreadEvidence>,
    /// No lifecycle pairing is inferred across records without actor IDs.
    pub unattributed_event_count: usize,
}

fn event(prefix: &str, data: &str, source_line: usize) -> Result<Event> {
    ensure!(data.len() <= 1024, "oversized stage record");
    let mut words = data.split_whitespace();
    let stage = match words.next() {
        Some("add-function") => Stage::AddFunction,
        Some("dtb-config") => Stage::DtbConfig,
        Some("notifier") => Stage::Notifier,
        Some("alloc-vmid") => Stage::AllocVmid,
        Some("pci-fixup") => Stage::PciFixup,
        Some("parcel") => Stage::Parcel,
        Some("configure") => Stage::Configure,
        Some("initialize") => Stage::Initialize,
        Some("resources") => Stage::Resources,
        Some("start") => Stage::Start,
        _ => bail!("unknown stage"),
    };
    let action_word = words.next();
    let action = match action_word {
        Some("begin") if !matches!(stage, Stage::DtbConfig) => Action::Begin,
        Some("recorded") if stage == Stage::DtbConfig => Action::Checkpoint,
        Some("result") if matches!(stage, Stage::AddFunction | Stage::Parcel) => Action::Result,
        Some(value) if value.starts_with("result=") => Action::Result,
        _ => bail!("unknown stage action"),
    };
    let mut fields = BTreeMap::new();
    // Parcel/function records have a separate action token before their fields.
    let field_start = if action_word.is_some_and(|w| w.starts_with("result=")) {
        1
    } else {
        2
    };
    for word in data.split_whitespace().skip(field_start) {
        let (key, value) = word.split_once('=').context("stage requires key=value")?;
        ensure!(
            fields.insert(key.into(), value.parse::<i64>()?).is_none(),
            "duplicate stage field"
        );
    }
    let keys: Vec<_> = fields.keys().map(String::as_str).collect();
    let expected: &[&str] = match (stage, action) {
        (Stage::AddFunction, Action::Begin) => &["type"],
        (Stage::AddFunction, Action::Result) => &["result", "type"],
        (Stage::Parcel, Action::Begin) => &["acl", "entries", "label", "lend"],
        (Stage::Parcel, Action::Result) => &["label", "result"],
        (Stage::Configure, Action::Begin) => &["auth"],
        (Stage::DtbConfig, Action::Checkpoint) | (Stage::Notifier, Action::Begin) => &[],
        (Stage::DtbConfig | Stage::Notifier, _) => bail!("invalid checkpoint action"),
        (_, Action::Begin) => &[],
        (_, Action::Result) => &["result"],
        _ => bail!("invalid stage action"),
    };
    ensure!(keys == expected, "missing or unknown stage fields");
    for (key, value) in &fields {
        if key == "result" {
            ensure!(
                *value >= -4095
                    && if stage == Stage::AddFunction {
                        *value <= i64::from(i32::MAX)
                    } else {
                        *value <= 0
                    },
                "invalid kernel return code"
            );
        } else {
            ensure!((0..=i64::from(u32::MAX)).contains(value), "field overflow");
        }
    }
    if let Some(lend) = fields.get("lend") {
        ensure!(*lend <= 1, "invalid lend flag");
        ensure!(fields["entries"] > 0 && fields["acl"] > 0, "empty parcel");
    }
    Ok(Event {
        source_line,
        actor: actor(prefix),
        stage,
        action,
        fields,
    })
}

fn same_operation(a: &Event, b: &Event) -> bool {
    a.stage == b.stage
        && ["label", "type"]
            .iter()
            .all(|key| a.fields.get(*key) == b.fields.get(*key))
}

pub fn inspect(text: &str) -> Result<Report> {
    ensure!(
        text.len() <= MAX_LOG_BYTES,
        "stage log exceeds inspection budget"
    );
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if let Some((prefix, data)) = line.split_once(MARKER) {
            ensure!(events.len() < MAX_RECORDS, "stage record budget exceeded");
            events.push(
                event(prefix, data, index + 1)
                    .with_context(|| format!("Gunyah stage at line {}", index + 1))?,
            );
        }
    }
    let mut groups: BTreeMap<(u32, u32), Vec<&Event>> = BTreeMap::new();
    for e in &events {
        if let Some(a) = &e.actor {
            groups.entry((a.pid, a.tid)).or_default().push(e);
        }
    }
    let threads = groups
        .into_iter()
        .map(|((pid, tid), records)| {
            let mut pending: Vec<&Event> = Vec::new();
            let mut negative_result_lines = Vec::new();
            let mut start_result = None;
            for e in &records {
                match e.action {
                    Action::Begin if e.stage != Stage::Notifier => pending.push(e),
                    Action::Result => {
                        if let Some(index) = pending.iter().rposition(|b| same_operation(b, e)) {
                            pending.remove(index);
                        }
                        let result = e.fields["result"];
                        if result < 0 {
                            negative_result_lines.push(e.source_line);
                        }
                        if e.stage == Stage::Start {
                            start_result = Some(result);
                        }
                    }
                    _ => {}
                }
            }
            ThreadEvidence {
                actor: Actor { pid, tid },
                event_count: records.len(),
                negative_result_lines,
                unfinished_begin_lines: pending.iter().map(|e| e.source_line).collect(),
                start_result,
                last_event_line: records.last().map_or(0, |e| e.source_line),
            }
        })
        .collect();
    Ok(Report {
        schema_version: 1,
        origin_verified: false,
        guest_boot_verified: false,
        terminal_session_verified: false,
        reset_cause_verified: false,
        unattributed_event_count: events.iter().filter(|e| e.actor.is_none()).count(),
        events,
        threads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line(pid: u32, data: &str) -> String {
        format!("10-18 22:27:04.886 {pid} {pid} I misc gunyah: {MARKER} {data}\n")
    }
    #[test]
    fn fd_results_are_success_and_start_success_is_not_guest_boot() -> Result<()> {
        let r = inspect(
            &(line(20, "add-function begin type=1")
                + &line(20, "add-function result type=1 result=3")
                + &line(20, "start begin")
                + &line(20, "start result=0")),
        )?;
        assert!(r.threads[0].negative_result_lines.is_empty());
        assert!(r.threads[0].unfinished_begin_lines.is_empty());
        assert_eq!(r.threads[0].start_result, Some(0));
        assert!(!r.guest_boot_verified && !r.terminal_session_verified);
        Ok(())
    }
    #[test]
    fn interleaved_processes_and_parcel_labels_are_not_paired() -> Result<()> {
        let r = inspect(
            &(line(20, "parcel begin label=0 entries=46355 acl=2 lend=0")
                + &line(21, "parcel result label=0 result=0")
                + &line(20, "parcel result label=1 result=0")),
        )?;
        assert_eq!(r.threads[0].unfinished_begin_lines, [1]);
        assert!(!r.reset_cause_verified);
        Ok(())
    }
    #[test]
    fn negative_start_and_unattributed_records_remain_distinct() -> Result<()> {
        let r = inspect(
            &(line(20, "start begin")
                + &line(20, "start result=-19")
                + &format!("[ 10.5] misc gunyah: {MARKER} start result=0\n")),
        )?;
        assert_eq!(r.threads[0].negative_result_lines, [2]);
        assert_eq!(r.threads[0].start_result, Some(-19));
        assert_eq!(r.unattributed_event_count, 1);
        assert!(!r.origin_verified);
        Ok(())
    }
    #[test]
    fn refuses_malformed_versioned_records() {
        for data in [
            "start result=1",
            "start result=-4096",
            "start result=0 result=0",
            "parcel begin label=0 entries=0 acl=2 lend=0",
            "parcel begin label=0 entries=1 acl=2 lend=2",
            "configure begin auth=-1",
            "start begin unknown=1",
            "start begin begin",
            "dtb-config begin",
            "dtb-config result=0",
            "notifier result=0",
            "unknown begin",
            "add-function result type=4294967296 result=3",
        ] {
            assert!(inspect(&line(20, data)).is_err(), "accepted {data}");
        }
        assert!(inspect(&line(20, "start begin").repeat(MAX_RECORDS + 1)).is_err());
    }
}
