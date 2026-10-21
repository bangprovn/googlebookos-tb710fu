//! Scalar-only owned Terminal UI observations. Completeness is not output proof.
//! Older records omit cache policy; no freshness policy may be inferred for them.
//! Java schema/source SHA256: 9700b04fe8a57bea59a5b07a0e6ced28081061915183cee76bb20589f5d34616.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_NODES: u32 = 4096;
const MAX_CHARS: u32 = 262144;
const MAX_MATCHES: u32 = 4096;
const MAX_SAMPLES: usize = 32;
const POLL_MS: u64 = 250;
const JAVA_LONG_MAX: u64 = i64::MAX as u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiObserverProbe {
    OwnedTerminalUiObserverV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiObserverCachePolicy {
    ClearBeforeEachPoll,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiObserverStatus {
    Ready,
    Completed,
    ArgumentsRefused,
    OwnerRefused,
    UserLocked,
    AccessibilityUnavailable,
    AutomationUnavailable,
    QueryFailed,
    NoActiveWindow,
    ForeignActiveWindow,
    TerminalNoWebview,
    TerminalWebviewEmpty,
    TerminalWebviewText,
    NodeLimit,
    DepthLimit,
    TextLimit,
    MatchLimit,
    PollDeadline,
    NodeUnavailable,
    Interrupted,
    DurationExceeded,
    ReportFailed,
    FinishFailed,
}

macro_rules! record {
    ($name:ident { $($field:ident: $ty:ty,)* }) => {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub schema_version: u32,
            pub probe: UiObserverProbe,
            pub status: UiObserverStatus,
            pub android_user: u16,
            pub uid: u32,
            pub observation_only: bool,
            pub command_execution_verified: bool,
            pub output_proof_claimed: bool,
            pub input_performed: bool,
            pub raw_content_exported: bool,
            pub settings_or_permissions_changed: bool,
            pub framework_cleanup_verified: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub accessibility_cache_policy: Option<UiObserverCachePolicy>,
            $(pub $field: $ty,)*
        }
        impl $name {
            fn common(&self) -> Result<()> {
                ensure!(self.schema_version == 1 && self.android_user <= 214
                    && self.uid / 100000 == u32::from(self.android_user)
                    && (10000..20000).contains(&(self.uid % 100000)),
                    "UI observer schema/owned user identity refused");
                ensure!(self.observation_only && !self.command_execution_verified
                    && !self.output_proof_claimed && !self.input_performed
                    && !self.raw_content_exported && !self.settings_or_permissions_changed
                    && !self.framework_cleanup_verified,
                    "UI observer cannot claim input, raw content, settings, cleanup or execution proof");
                Ok(())
            }
        }
    }
}

record!(UiObserverReady {
    accessibility_enabled_before_connection: bool,
    accessibility_enabled_after_connection: bool,
    touch_exploration_before_connection: bool,
    touch_exploration_after_connection: bool,
    ui_automation_acquired: bool,
    first_poll_pending: bool,
});

record!(UiObserverSample {
    sample: UiObserverObservation,
});

record!(UiObserverFinal {
    requested_duration_ms: u32,
    observation_elapsed_ms: u64,
    poll_interval_ms: u32,
    polls: u32,
    complete_polls: u32,
    maximum_poll_start_gap_ms: u64,
    samples: Vec<UiObserverObservation>,
    sample_budget: u32,
    samples_dropped: u32,
    sample_budget_exceeded: bool,
    ready_sent: bool,
    ui_automation_acquired: bool,
    accessibility_manager_available: bool,
    accessibility_enabled_before_connection: bool,
    accessibility_enabled_after_connection: bool,
    accessibility_enabled_before_finish: bool,
    touch_exploration_before_connection: bool,
    touch_exploration_after_connection: bool,
    touch_exploration_before_finish: bool,
    maximum_whole_line_marker_matches: u32,
    maximum_contains_marker_matches: u32,
    node_budget_per_poll: u32,
    depth_budget: u32,
    text_characters_per_node_budget: u32,
    text_characters_per_poll_budget: u32,
    marker_match_budget_per_poll: u32,
    finish_requested: bool,
    finish_failed: bool,
});

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UiObserverObservation {
    pub status: UiObserverStatus,
    pub offset_ms: u64,
    pub query_elapsed_ms: u64,
    pub terminal_window: bool,
    pub poll_complete: bool,
    pub visited_nodes: u32,
    pub webview_roots: u32,
    pub foreign_subtrees_pruned: u32,
    pub null_children: u32,
    pub nonempty_positive_width_text_nodes: u32,
    pub text_characters_examined: u32,
    pub whole_line_marker_matches: u32,
    pub contains_marker_matches: u32,
    pub node_limit: bool,
    pub depth_limit: bool,
    pub text_limit: bool,
    pub match_limit: bool,
    pub poll_deadline_exceeded: bool,
    pub query_failed: bool,
    pub node_recycle_failed: bool,
    pub accessibility_enabled: bool,
    pub touch_exploration_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "record_kind", rename_all = "snake_case")]
pub enum UiObserverRecord {
    Ready(UiObserverReady),
    Sample(UiObserverSample),
    Final(UiObserverFinal),
}

impl UiObserverObservation {
    fn validate(&self) -> Result<()> {
        use UiObserverStatus as S;
        ensure!(self.visited_nodes <= MAX_NODES, "UI observer node budget");
        let visited = u64::from(self.visited_nodes);
        // Null children do not increment visited. Each entered node's child
        // count is bounded by MAX_NODES - visited at that node, not globally.
        let null_bound = visited * u64::from(MAX_NODES) - visited * (visited + 1) / 2;
        ensure!(
            self.visited_nodes <= MAX_NODES
                && u64::from(self.webview_roots) + u64::from(self.foreign_subtrees_pruned)
                    <= visited
                && u64::from(self.null_children) <= null_bound
                && self.nonempty_positive_width_text_nodes <= self.visited_nodes
                && u64::from(self.nonempty_positive_width_text_nodes)
                    + u64::from(self.webview_roots)
                    + u64::from(self.foreign_subtrees_pruned)
                    <= visited
                && (!self.terminal_window || self.visited_nodes > 0)
                && (self.terminal_window || self.visited_nodes <= 1)
                && (self.webview_roots == 0 || self.terminal_window)
                && self.text_characters_examined <= MAX_CHARS
                && u64::from(self.text_characters_examined)
                    <= u64::from(self.nonempty_positive_width_text_nodes) * 4096
                && self.whole_line_marker_matches <= self.contains_marker_matches
                && self.contains_marker_matches <= MAX_MATCHES
                && u64::from(self.contains_marker_matches) * 43
                    <= u64::from(self.text_characters_examined)
                && self.offset_ms <= JAVA_LONG_MAX
                && self.query_elapsed_ms <= JAVA_LONG_MAX,
            "UI observer poll scalar budget/relationship refused"
        );
        let limit_failures = [
            self.node_limit,
            self.depth_limit,
            self.text_limit,
            self.match_limit,
        ]
        .into_iter()
        .filter(|flag| *flag)
        .count();
        ensure!(
            limit_failures <= 1
                && (self.query_elapsed_ms <= POLL_MS || self.poll_deadline_exceeded),
            "UI observer contradictory poll failure flags/time"
        );
        ensure!(
            self.text_characters_examined == 0 || self.nonempty_positive_width_text_nodes > 0,
            "UI observer characters without text nodes"
        );
        ensure!(
            self.nonempty_positive_width_text_nodes == 0 || self.webview_roots > 0,
            "UI observer text outside observed WebView"
        );
        let failure = limit_failures > 0 || self.query_failed || self.poll_deadline_exceeded;
        let complete_status = match self.status {
            S::TerminalNoWebview => {
                ensure!(
                    self.webview_roots == 0,
                    "UI observer no-WebView status mismatch"
                );
                true
            }
            S::TerminalWebviewEmpty => {
                ensure!(
                    self.webview_roots > 0 && self.nonempty_positive_width_text_nodes == 0,
                    "UI observer empty-WebView status mismatch"
                );
                true
            }
            S::TerminalWebviewText => {
                ensure!(
                    self.webview_roots > 0
                        && self.nonempty_positive_width_text_nodes > 0
                        && self.text_characters_examined >= self.nonempty_positive_width_text_nodes,
                    "UI observer text-WebView status mismatch"
                );
                true
            }
            S::NoActiveWindow => {
                ensure!(
                    !self.terminal_window
                        && self.visited_nodes == 0
                        && self.null_children == 0
                        && !self.node_recycle_failed
                        && !failure,
                    "UI observer absent-window mismatch"
                );
                false
            }
            S::ForeignActiveWindow => {
                ensure!(
                    !self.terminal_window
                        && self.visited_nodes == 1
                        && self.foreign_subtrees_pruned == 1
                        && self.null_children == 0
                        && !failure,
                    "UI observer foreign-window mismatch"
                );
                false
            }
            S::NodeUnavailable => {
                ensure!(
                    self.terminal_window
                        && !failure
                        && (self.null_children > 0 || self.node_recycle_failed),
                    "UI observer node-unavailable mismatch"
                );
                false
            }
            S::NodeLimit | S::DepthLimit | S::TextLimit | S::MatchLimit => {
                let expected = match self.status {
                    S::NodeLimit => self.node_limit,
                    S::DepthLimit => self.depth_limit,
                    S::TextLimit => self.text_limit,
                    S::MatchLimit => self.match_limit,
                    _ => unreachable!(),
                };
                ensure!(
                    expected
                        && limit_failures == 1
                        && !self.query_failed
                        && !self.poll_deadline_exceeded
                        && self.terminal_window,
                    "UI observer limit/status mismatch"
                );
                false
            }
            S::QueryFailed => {
                ensure!(
                    self.query_failed && !self.poll_deadline_exceeded,
                    "UI observer query-failure mismatch"
                );
                false
            }
            S::PollDeadline => {
                ensure!(self.poll_deadline_exceeded, "UI observer deadline mismatch");
                false
            }
            _ => anyhow::bail!("UI observer non-poll status in observation"),
        };
        ensure!(
            self.poll_complete == complete_status,
            "UI observer completeness/status mismatch"
        );
        if complete_status {
            ensure!(
                self.terminal_window
                    && !failure
                    && self.null_children == 0
                    && !self.node_recycle_failed,
                "UI observer incomplete poll claims completion"
            );
        }
        ensure!(
            !self.text_limit || self.nonempty_positive_width_text_nodes > 0,
            "UI observer text-limit without text"
        );
        ensure!(
            !self.depth_limit || self.visited_nodes >= 65,
            "UI observer depth-limit before reaching depth budget"
        );
        ensure!(
            !self.match_limit || self.contains_marker_matches == MAX_MATCHES,
            "UI observer match-limit count mismatch"
        );
        Ok(())
    }
}

impl UiObserverFinal {
    fn validate(&self) -> Result<()> {
        use UiObserverStatus as S;
        self.common()?;
        ensure!(
            (1000..=90000).contains(&self.requested_duration_ms)
                && self.poll_interval_ms == POLL_MS as u32
                && self.sample_budget == MAX_SAMPLES as u32
                && self.node_budget_per_poll == MAX_NODES
                && self.depth_budget == 64
                && self.text_characters_per_node_budget == 4096
                && self.text_characters_per_poll_budget == MAX_CHARS
                && self.marker_match_budget_per_poll == MAX_MATCHES
                && self.finish_requested
                && !self.finish_failed,
            "UI observer final budget/finish mismatch"
        );
        ensure!(
            self.observation_elapsed_ms <= JAVA_LONG_MAX
                && self.maximum_poll_start_gap_ms <= self.observation_elapsed_ms
                && self.polls <= self.requested_duration_ms / POLL_MS as u32 + 1
                && self.complete_polls <= self.polls
                && self.samples.len() <= MAX_SAMPLES
                && self.samples.len() as u64 + u64::from(self.samples_dropped)
                    <= u64::from(self.polls)
                && self.sample_budget_exceeded == (self.samples_dropped > 0)
                && (self.samples_dropped == 0 || self.samples.len() == MAX_SAMPLES)
                && (self.polls == 0) == self.samples.is_empty()
                && (self.polls <= 1) == (self.maximum_poll_start_gap_ms == 0),
            "UI observer final counts/time mismatch"
        );
        ensure!(
            (!self.ready_sent || self.ui_automation_acquired)
                && (!self.ui_automation_acquired || self.accessibility_manager_available)
                && (self.polls == 0 || self.ready_sent)
                && (self.accessibility_manager_available
                    || !(self.accessibility_enabled_before_connection
                        || self.accessibility_enabled_after_connection
                        || self.accessibility_enabled_before_finish
                        || self.touch_exploration_before_connection
                        || self.touch_exploration_after_connection
                        || self.touch_exploration_before_finish))
                && (self.ui_automation_acquired
                    || !(self.accessibility_enabled_after_connection
                        || self.touch_exploration_after_connection)),
            "UI observer final acquisition/readiness mismatch"
        );
        match self.status {
            S::Completed => ensure!(
                self.ready_sent
                    && self.observation_elapsed_ms >= u64::from(self.requested_duration_ms),
                "UI observer completed without duration/readiness"
            ),
            S::DurationExceeded => ensure!(
                self.ready_sent
                    && self.observation_elapsed_ms > u64::from(self.requested_duration_ms) + 1000,
                "UI observer exceeded-duration mismatch"
            ),
            S::Interrupted => ensure!(
                self.ready_sent && self.polls > 0,
                "UI observer interrupted before polling"
            ),
            S::ArgumentsRefused | S::OwnerRefused | S::UserLocked | S::AccessibilityUnavailable => {
                ensure!(
                    !self.ready_sent
                        && !self.ui_automation_acquired
                        && !self.accessibility_manager_available
                        && self.polls == 0,
                    "UI observer preflight refusal after acquisition"
                )
            }
            S::AutomationUnavailable => ensure!(
                !self.ready_sent
                    && !self.ui_automation_acquired
                    && self.accessibility_manager_available
                    && self.polls == 0,
                "UI observer automation-unavailable mismatch"
            ),
            S::QueryFailed | S::ReportFailed => {}
            _ => anyhow::bail!("UI observer invalid final status"),
        }
        let mut previous = None;
        let mut complete_rows = 0_u32;
        let mut row_whole = 0;
        let mut row_contains = 0;
        for row in &self.samples {
            row.validate()?;
            ensure!(
                previous.is_none_or(|offset| row.offset_ms > offset)
                    && row
                        .offset_ms
                        .checked_add(row.query_elapsed_ms)
                        .is_some_and(|end| end <= self.observation_elapsed_ms),
                "UI observer sample order/time mismatch"
            );
            previous = Some(row.offset_ms);
            complete_rows += u32::from(row.poll_complete);
            row_whole = row_whole.max(row.whole_line_marker_matches);
            row_contains = row_contains.max(row.contains_marker_matches);
        }
        ensure!(
            complete_rows <= self.complete_polls
                && self.complete_polls <= self.polls - (self.samples.len() as u32 - complete_rows)
                && row_whole <= self.maximum_whole_line_marker_matches
                && self.maximum_whole_line_marker_matches <= self.maximum_contains_marker_matches
                && row_contains <= self.maximum_contains_marker_matches
                && self.maximum_contains_marker_matches <= MAX_MATCHES,
            "UI observer final completeness/maxima mismatch"
        );
        if self.samples_dropped == 0 {
            ensure!(
                row_whole == self.maximum_whole_line_marker_matches
                    && row_contains == self.maximum_contains_marker_matches,
                "UI observer maximum absent from retained samples"
            );
        }
        Ok(())
    }
}

/// Parse one decoded instrumentation JSON payload. Minimal refusal/finish-failure
/// records without the standard identity are errors, never fabricated readiness.
pub fn inspect_ui_observer(text: &str) -> Result<UiObserverRecord> {
    ensure!(text.len() <= 65536, "UI observer JSON exceeds byte budget");
    let record: UiObserverRecord =
        serde_json::from_str(text).context("UI observer scalar schema")?;
    match &record {
        UiObserverRecord::Ready(value) => {
            value.common()?;
            ensure!(
                value.status == UiObserverStatus::Ready
                    && value.ui_automation_acquired
                    && value.first_poll_pending,
                "UI observer readiness mismatch"
            );
        }
        UiObserverRecord::Sample(value) => {
            value.common()?;
            value.sample.validate()?;
            ensure!(
                value.status == value.sample.status,
                "UI observer sample status mismatch"
            );
        }
        UiObserverRecord::Final(value) => value.validate()?,
    }
    Ok(record)
}

#[cfg(test)]
#[path = "ui_observer_tests.rs"]
mod tests;
