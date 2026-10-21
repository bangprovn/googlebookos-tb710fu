//! Strict scalar protocol. Parser success verifies schema, not target identity,
//! cleanup, registration, RF discovery or feature functionality.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneLinkUiStatus {
    Completed,
    ArgumentsRefused,
    OwnerRefused,
    UserLocked,
    AutomationUnavailable,
    QueryIncomplete,
    Interrupted,
    DurationExceeded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneLinkUiQueryStatus {
    NativeObserved,
    NoActiveWindow,
    ForeignActiveWindow,
    WebviewActiveWindow,
    QueryFailed,
    NodeLimit,
    DepthLimit,
    TextLimit,
    PollDeadline,
    NodeUnavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    OwnedPhoneLinkUiV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    ClearBeforeEachPoll,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLinkUiCounts {
    pub searching_label: u32,
    pub setup_intro_title: u32,
    pub setup_intro_body: u32,
    pub setup_required_title: u32,
    pub setup_required_body: u32,
    pub setup_new_phone_option: u32,
    pub wifi_required_body: u32,
    pub phone_app_cast_disabled_body: u32,
    pub open_settings_on_phone: u32,
    pub wifi_disconnected_description: u32,
    pub onboarding_illustration_description: u32,
}
impl PhoneLinkUiCounts {
    fn values(&self) -> [u32; 11] {
        [
            self.searching_label,
            self.setup_intro_title,
            self.setup_intro_body,
            self.setup_required_title,
            self.setup_required_body,
            self.setup_new_phone_option,
            self.wifi_required_body,
            self.phone_app_cast_disabled_body,
            self.open_settings_on_phone,
            self.wifi_disconnected_description,
            self.onboarding_illustration_description,
        ]
    }
    fn total(&self) -> u64 {
        self.values().into_iter().map(u64::from).sum()
    }
    fn minimum_characters(&self) -> u64 {
        let lengths = [28_u64, 22, 72, 34, 58, 16, 25, 102, 22, 18, 23];
        self.values()
            .into_iter()
            .zip(lengths)
            .map(|(n, l)| u64::from(n) * l)
            .sum()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLinkUiSample {
    pub status: PhoneLinkUiQueryStatus,
    pub offset_ms: u64,
    pub query_elapsed_ms: u64,
    pub target_window: bool,
    pub poll_complete: bool,
    pub visited_nodes: u32,
    pub foreign_subtrees_pruned: u32,
    pub webview_subtrees_pruned: u32,
    pub null_children: u32,
    pub nodes_recycled: u32,
    pub text_characters_examined: u32,
    pub node_limit: bool,
    pub depth_limit: bool,
    pub text_limit: bool,
    pub poll_deadline_exceeded: bool,
    pub query_failed: bool,
    pub node_recycle_failed: bool,
    pub text_counts: PhoneLinkUiCounts,
    pub description_counts: PhoneLinkUiCounts,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneLinkUiReport {
    pub schema_version: u32,
    pub probe: Probe,
    pub status: PhoneLinkUiStatus,
    pub android_user: u16,
    pub uid: u32,
    pub expected_target_uid: u32,
    pub target_package: String,
    pub expected_target_apk_sha256: String,
    pub whitelist_sha256: String,
    pub observation_only: bool,
    pub input_performed: bool,
    pub raw_content_exported: bool,
    pub settings_or_permissions_changed: bool,
    pub framework_cleanup_verified: bool,
    pub registration_verified: bool,
    pub active_rf_scan_verified: bool,
    pub peer_eligibility_verified: bool,
    pub functional_phone_link_verified: bool,
    pub external_target_identity_verified: bool,
    pub ui_automation_acquired: bool,
    pub accessibility_cache_policy: CachePolicy,
    pub cache_clear_attempts: u32,
    pub cache_clear_successes: u32,
    pub root_queries: u32,
    pub observation_elapsed_ms: u64,
    pub node_budget_per_poll: u32,
    pub depth_budget: u32,
    pub text_characters_per_field_budget: u32,
    pub text_characters_per_poll_budget: u32,
    pub window_budget_per_poll: u32,
    pub sample_budget: u32,
    pub samples: Vec<PhoneLinkUiSample>,
    pub finish_requested: bool,
    pub finish_failed: bool,
}
impl PhoneLinkUiSample {
    fn validate(&self) -> Result<()> {
        use PhoneLinkUiQueryStatus as S;
        let n = u64::from(self.visited_nodes);
        ensure!(
            n <= 512
                && self.nodes_recycled <= self.visited_nodes
                && u64::from(self.foreign_subtrees_pruned)
                    + u64::from(self.webview_subtrees_pruned)
                    <= n
                && u64::from(self.null_children) <= n * 512
                && self.text_characters_examined <= 65536,
            "Phone Link UI query budget refused"
        );
        ensure!(
            self.text_counts.total()
                <= n - u64::from(self.foreign_subtrees_pruned)
                    - u64::from(self.webview_subtrees_pruned)
                && self.description_counts.total()
                    <= n - u64::from(self.foreign_subtrees_pruned)
                        - u64::from(self.webview_subtrees_pruned)
                && self.text_counts.minimum_characters()
                    + self.description_counts.minimum_characters()
                    <= u64::from(self.text_characters_examined),
            "Phone Link UI count budget refused"
        );
        let failed = self.node_limit
            || self.depth_limit
            || self.text_limit
            || self.poll_deadline_exceeded
            || self.query_failed
            || self.node_recycle_failed
            || self.null_children > 0;
        ensure!(
            !self.poll_complete
                || (self.target_window
                    && n > 0
                    && !failed
                    && self.nodes_recycled == self.visited_nodes
                    && self.query_elapsed_ms <= 250),
            "Phone Link UI completion contradicts query"
        );
        ensure!(
            self.target_window
                || (self.text_counts.total() == 0
                    && self.description_counts.total() == 0
                    && self.text_characters_examined == 0),
            "Phone Link UI foreign counts refused"
        );
        match self.status {
            S::NativeObserved => ensure!(self.poll_complete, "incomplete native query"),
            S::NoActiveWindow => ensure!(
                !self.poll_complete && !self.target_window && n == 0 && !failed,
                "invalid missing window"
            ),
            S::ForeignActiveWindow => ensure!(
                !self.poll_complete
                    && !self.target_window
                    && n == 1
                    && self.foreign_subtrees_pruned == 1
                    && !self.node_limit
                    && !self.depth_limit
                    && !self.text_limit
                    && !self.poll_deadline_exceeded
                    && !self.query_failed,
                "invalid foreign window"
            ),
            S::WebviewActiveWindow => ensure!(
                !self.poll_complete
                    && self.target_window
                    && n == 1
                    && self.webview_subtrees_pruned == 1
                    && self.text_counts.total() == 0
                    && self.description_counts.total() == 0
                    && !self.poll_deadline_exceeded
                    && !self.query_failed,
                "invalid WebView window"
            ),
            S::QueryFailed => ensure!(
                !self.poll_complete && self.query_failed,
                "missing query failure"
            ),
            S::NodeLimit => ensure!(!self.poll_complete && self.node_limit, "missing node limit"),
            S::DepthLimit => ensure!(
                !self.poll_complete && self.depth_limit,
                "missing depth limit"
            ),
            S::TextLimit => ensure!(!self.poll_complete && self.text_limit, "missing text limit"),
            S::PollDeadline => ensure!(
                !self.poll_complete && self.poll_deadline_exceeded,
                "missing query deadline"
            ),
            S::NodeUnavailable => ensure!(
                !self.poll_complete && (self.null_children > 0 || self.node_recycle_failed),
                "missing unavailable node"
            ),
        }
        ensure!(
            !self.poll_complete || self.status == S::NativeObserved,
            "completion status refused"
        );
        Ok(())
    }
}
/// Inspect one bounded raw JSON report. Deserialize directly so duplicates and
/// private/unknown fields cannot be discarded by an intermediate Value parser.
pub fn inspect_phone_link_ui(text: &str) -> Result<PhoneLinkUiReport> {
    ensure!(text.len() <= 65536, "Phone Link UI input budget");
    let r: PhoneLinkUiReport =
        serde_json::from_str(text).context("Phone Link UI protocol refused")?;
    ensure!(
        r.schema_version == 1
            && r.android_user == 11
            && r.uid / 100000 == 11
            && (10000..20000).contains(&(r.uid % 100000))
            && r.expected_target_uid == 1110128
            && r.target_package == "com.google.ambient.streaming"
            && r.expected_target_apk_sha256 == super::TARGET_APK_SHA256
            && r.whitelist_sha256 == super::WHITELIST_SHA256,
        "Phone Link UI source/owner identity refused"
    );
    ensure!(
        r.observation_only
            && !r.input_performed
            && !r.raw_content_exported
            && !r.settings_or_permissions_changed
            && !r.framework_cleanup_verified
            && !r.registration_verified
            && !r.active_rf_scan_verified
            && !r.peer_eligibility_verified
            && !r.functional_phone_link_verified
            && !r.external_target_identity_verified
            && r.finish_requested
            && !r.finish_failed,
        "Phone Link UI proof/privacy scope refused"
    );
    ensure!(
        r.node_budget_per_poll == 512
            && r.depth_budget == 32
            && r.text_characters_per_field_budget == 2048
            && r.text_characters_per_poll_budget == 65536
            && r.window_budget_per_poll == 1
            && r.sample_budget == 2
            && r.samples.len() <= 2
            && r.observation_elapsed_ms <= i64::MAX as u64,
        "Phone Link UI fixed budgets refused"
    );
    ensure!(
        r.cache_clear_attempts as usize == r.samples.len()
            && r.cache_clear_successes <= r.cache_clear_attempts
            && r.root_queries == r.cache_clear_successes,
        "Phone Link UI cache/query accounting refused"
    );
    for (i, s) in r.samples.iter().enumerate() {
        s.validate()?;
        ensure!(
            r.ui_automation_acquired
                && s.offset_ms < 8000
                && s.query_elapsed_ms <= i64::MAX as u64
                && s.offset_ms.saturating_add(s.query_elapsed_ms) <= r.observation_elapsed_ms,
            "Phone Link UI sample timing refused"
        );
        if i == 1 {
            ensure!(
                s.offset_ms >= 5500
                    && s.offset_ms >= r.samples[0].offset_ms + r.samples[0].query_elapsed_ms,
                "Phone Link UI second sample timing refused"
            );
        }
    }
    use PhoneLinkUiStatus as S;
    if r.status == S::Completed {
        ensure!(
            r.ui_automation_acquired
                && r.samples.len() == 2
                && r.samples.iter().all(|s| s.poll_complete)
                && r.cache_clear_successes == 2
                && r.observation_elapsed_ms < 8000,
            "Phone Link UI final completion refused"
        );
    }
    if matches!(
        r.status,
        S::ArgumentsRefused | S::OwnerRefused | S::UserLocked | S::AutomationUnavailable
    ) {
        ensure!(
            !r.ui_automation_acquired && r.samples.is_empty(),
            "Phone Link UI preflight contradicts acquisition"
        );
    }
    if r.status == S::DurationExceeded {
        ensure!(
            r.observation_elapsed_ms >= 8000,
            "Phone Link UI duration status refused"
        );
    }
    Ok(r)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
