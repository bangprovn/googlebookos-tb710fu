//! Anonymous BLE callback counts. API returns do not prove controller/RF activity.
use super::{BluetoothAdapterState, BluetoothFunctionalState};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeScanStatus {
    Observed,
    Unavailable,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeScanReason {
    BoundedScanWindowComplete,
    PermissionDenied,
    ManagerUnavailable,
    AdapterUnavailable,
    InvalidState,
    AdapterNotOn,
    AdapterStateChanged,
    PassiveApiUnavailable,
    ScannerUnavailable,
    ApiException,
    Interrupted,
    CleanupIncomplete,
    CallbackBudgetExceeded,
    WindowMismatch,
    ScanFailed,
    InvalidFailureCode,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeScanFailure {
    AlreadyStarted,
    ApplicationRegistrationFailed,
    InternalError,
    FeatureUnsupported,
    OutOfHardwareResources,
    ScanningTooFrequently,
    InvalidCode,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeScanScope {
    AnonymousPassiveLeScanWindow,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeScanMode {
    LowPower,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeScanType {
    Passive,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BluetoothLeScanObservation {
    pub status: BluetoothLeScanStatus,
    pub state: BluetoothFunctionalState,
    pub scope: BluetoothLeScanScope,
    pub reason: BluetoothLeScanReason,
    pub connect_permission_granted: bool,
    pub scan_permission_granted: bool,
    pub le_feature_declared: Option<bool>,
    pub adapter_present: Option<bool>,
    pub state_before: Option<BluetoothAdapterState>,
    pub state_after: Option<BluetoothAdapterState>,
    pub state_matches_at_checks: Option<bool>,
    pub passive_api_verified: bool,
    pub scan_mode: BluetoothLeScanMode,
    pub scan_type: BluetoothLeScanType,
    pub never_for_location: bool,
    pub window_budget_ms: u32,
    pub window_elapsed_ms: u64,
    pub drain_budget_ms: u32,
    pub drain_elapsed_ms: u64,
    pub elapsed_ms: u64,
    pub scan_start_attempted: bool,
    /// Void startScan returned; neither registration nor RF acknowledgement.
    pub scan_start_returned: bool,
    pub scan_stop_attempted: bool,
    /// Void stopScan returned; not proof no future callbacks can arrive.
    pub scan_stop_returned: bool,
    pub result_callback_count: u32,
    pub batch_callback_count: u32,
    pub failure_callback_count: u32,
    pub late_callback_count: u32,
    pub late_failure_count: u32,
    pub scan_failure: Option<BluetoothLeScanFailure>,
    pub invalid_failure_code: bool,
    pub callback_budget_exceeded: bool,
    pub callback_gate_closed: bool,
    pub identifiers_collected: bool,
    pub payloads_inspected: bool,
    pub rssi_collected: bool,
    pub batch_entries_inspected: bool,
    pub user_content_collected: bool,
    pub radio_change_requested: bool,
    pub paired_devices_accessed: bool,
    pub advertising_started: bool,
    pub connection_opened: bool,
    pub rf_verified: bool,
    pub peer_verified: bool,
    pub phone_link_verified: bool,
}

pub fn inspect_bluetooth_le_scan(value: &serde_json::Value) -> Result<BluetoothLeScanObservation> {
    use BluetoothLeScanReason as Reason;
    let r: BluetoothLeScanObservation = serde_json::from_value(value.clone())?;
    ensure!(
        r.never_for_location
            && !r.identifiers_collected
            && !r.payloads_inspected
            && !r.rssi_collected
            && !r.batch_entries_inspected
            && !r.user_content_collected
            && !r.radio_change_requested
            && !r.paired_devices_accessed
            && !r.advertising_started
            && !r.connection_opened
            && !r.rf_verified
            && !r.peer_verified
            && !r.phone_link_verified,
        "BLE scan scope cannot inspect peer data or qualify RF/peers/Phone Link"
    );
    let total = u64::from(r.result_callback_count)
        + u64::from(r.batch_callback_count)
        + u64::from(r.failure_callback_count)
        + u64::from(r.late_callback_count)
        + u64::from(r.late_failure_count);
    ensure!(
        r.window_budget_ms == 5000
            && r.drain_budget_ms == 200
            && total <= 1024
            && r.window_elapsed_ms.saturating_add(r.drain_elapsed_ms) <= r.elapsed_ms
            && r.elapsed_ms <= 90000
            && r.callback_gate_closed,
        "BLE budgets/closed callback gate"
    );
    ensure!(
        (!r.scan_start_returned || r.scan_start_attempted)
            && (!r.scan_stop_returned || r.scan_stop_attempted)
            && r.scan_stop_attempted == r.scan_start_attempted,
        "BLE attempted/returned lifecycle inconsistent"
    );
    if r.scan_start_attempted {
        ensure!(
            r.connect_permission_granted
                && r.scan_permission_granted
                && r.adapter_present == Some(true)
                && r.state_before == Some(BluetoothAdapterState::On)
                && r.passive_api_verified,
            "BLE start requires actual ON adapter and passive API with both permissions"
        );
    } else {
        ensure!(
            total == 0
                && r.scan_failure.is_none()
                && !r.invalid_failure_code
                && !r.callback_budget_exceeded
                && r.window_elapsed_ms == 0
                && r.drain_elapsed_ms == 0,
            "BLE callbacks/window without a start attempt"
        );
    }
    ensure!(
        r.state_matches_at_checks == r.state_before.zip(r.state_after).map(|(a, b)| a == b),
        "BLE adapter equality must reflect actual checks"
    );
    if r.state_before.is_some() || r.state_after.is_some() {
        ensure!(
            r.connect_permission_granted
                && r.scan_permission_granted
                && r.adapter_present == Some(true),
            "BLE state reads without permission/adapter"
        );
    }
    let failures = r.failure_callback_count + r.late_failure_count;
    ensure!(
        (failures > 0) == r.scan_failure.is_some()
            && (!r.invalid_failure_code || failures > 0)
            && (r.scan_failure != Some(BluetoothLeScanFailure::InvalidCode)
                || r.invalid_failure_code),
        "BLE failure enum/counters inconsistent"
    );
    ensure!(
        !r.callback_budget_exceeded || total == 1024,
        "BLE exceeded flag requires saturated counters"
    );
    match r.status {
        BluetoothLeScanStatus::Observed => ensure!(
            r.reason == Reason::BoundedScanWindowComplete
                && r.state_after == Some(BluetoothAdapterState::On)
                && r.scan_start_returned
                && r.scan_stop_returned
                && !r.callback_budget_exceeded
                && !r.invalid_failure_code
                && failures == 0
                && (5000..=6500).contains(&r.window_elapsed_ms)
                && (200..=1500).contains(&r.drain_elapsed_ms)
                && r.elapsed_ms <= 9000,
            "BLE observed requires bounded passive window, both API returns and no reported failures"
        ),
        BluetoothLeScanStatus::Unavailable => {
            ensure!(
                r.reason != Reason::BoundedScanWindowComplete,
                "unavailable BLE cannot claim completion"
            );
            match r.reason {
                Reason::ScanFailed => {
                    ensure!(failures > 0, "scan failure needs an actual callback")
                }
                Reason::InvalidFailureCode => ensure!(
                    r.invalid_failure_code,
                    "invalid-code reason needs observed invalid code"
                ),
                Reason::CallbackBudgetExceeded => ensure!(
                    r.callback_budget_exceeded,
                    "budget reason needs exceeded flag"
                ),
                Reason::AdapterUnavailable => ensure!(
                    r.adapter_present == Some(false)
                        && r.state_before.is_none()
                        && !r.scan_start_attempted,
                    "missing adapter cannot carry scan/state"
                ),
                Reason::ManagerUnavailable => ensure!(
                    r.adapter_present.is_none()
                        && r.state_before.is_none()
                        && !r.scan_start_attempted,
                    "missing manager cannot carry scan/state"
                ),
                Reason::AdapterNotOn => ensure!(
                    r.state_before
                        .is_some_and(|s| s != BluetoothAdapterState::On)
                        && !r.scan_start_attempted,
                    "adapter-not-on cannot start a scan"
                ),
                Reason::AdapterStateChanged => ensure!(
                    r.state_after
                        .is_some_and(|s| s != BluetoothAdapterState::On),
                    "changed adapter reason needs actual changed state"
                ),
                Reason::PassiveApiUnavailable | Reason::ScannerUnavailable => ensure!(
                    !r.scan_start_attempted,
                    "API/scanner unavailable cannot start a scan"
                ),
                _ => (),
            }
        }
    }
    Ok(r)
}
