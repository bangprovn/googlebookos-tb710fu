//! Anonymous Bluetooth API status; neither RF operation nor transition qualification.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "u8", into = "u8")]
pub enum BluetoothAdapterState {
    Off,
    TurningOn,
    On,
    TurningOff,
}
impl TryFrom<u8> for BluetoothAdapterState {
    type Error = &'static str;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            10 => Ok(Self::Off),
            11 => Ok(Self::TurningOn),
            12 => Ok(Self::On),
            13 => Ok(Self::TurningOff),
            _ => Err("not a public Bluetooth adapter state"),
        }
    }
}
impl From<BluetoothAdapterState> for u8 {
    fn from(value: BluetoothAdapterState) -> Self {
        match value {
            BluetoothAdapterState::Off => 10,
            BluetoothAdapterState::TurningOn => 11,
            BluetoothAdapterState::On => 12,
            BluetoothAdapterState::TurningOff => 13,
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothStatus {
    Observed,
    Unavailable,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothStatusReason {
    BoundedStatusComplete,
    PermissionDenied,
    ManagerUnavailable,
    AdapterUnavailable,
    InvalidState,
    ApiException,
    Interrupted,
    CleanupIncomplete,
    CallbackBudgetExceeded,
    WindowMismatch,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothFunctionalState {
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothStatusScope {
    PublicApiStatusOnly,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BluetoothStatusObservation {
    pub status: BluetoothStatus,
    pub state: BluetoothFunctionalState,
    pub scope: BluetoothStatusScope,
    pub reason: BluetoothStatusReason,
    pub classic_feature_declared: Option<bool>,
    pub le_feature_declared: Option<bool>,
    pub connect_permission_granted: bool,
    pub adapter_present: Option<bool>,
    pub state_before: Option<BluetoothAdapterState>,
    pub state_after: Option<BluetoothAdapterState>,
    /// Equality at two reads does not establish continuous state stability.
    pub state_matches_at_checks: Option<bool>,
    pub window_budget_ms: u32,
    pub window_elapsed_ms: u64,
    pub elapsed_ms: u64,
    pub receiver_registered: bool,
    pub receiver_cleanup_attempted: bool,
    pub receiver_removed: bool,
    pub callback_thread_stopped: bool,
    pub callback_count: u32,
    pub valid_transition_callbacks: u32,
    pub invalid_state_callback: bool,
    pub callback_budget_exceeded: bool,
    pub read_only: bool,
    pub identifiers_collected: bool,
    pub user_content_collected: bool,
    pub radio_change_requested: bool,
    pub discovery_or_scan_started: bool,
    pub paired_devices_accessed: bool,
    pub socket_opened: bool,
    pub functionality_verified: bool,
    pub radio_transition_verified: bool,
}

pub fn inspect_bluetooth_status(value: &serde_json::Value) -> Result<BluetoothStatusObservation> {
    let r: BluetoothStatusObservation = serde_json::from_value(value.clone())?;
    ensure!(
        r.read_only
            && !r.identifiers_collected
            && !r.user_content_collected
            && !r.radio_change_requested
            && !r.discovery_or_scan_started
            && !r.paired_devices_accessed
            && !r.socket_opened
            && !r.functionality_verified
            && !r.radio_transition_verified,
        "Bluetooth status cannot collect identifiers/content or qualify radio operations"
    );
    ensure!(
        r.window_budget_ms == 2000
            && r.callback_count <= 32
            && r.valid_transition_callbacks <= r.callback_count
            && r.window_elapsed_ms <= r.elapsed_ms
            && r.elapsed_ms <= 90000,
        "Bluetooth callback/window budget"
    );
    ensure!(
        (!r.receiver_removed || (r.receiver_registered && r.receiver_cleanup_attempted))
            && (r.receiver_registered
                || (r.callback_count == 0
                    && r.window_elapsed_ms == 0
                    && !r.invalid_state_callback
                    && !r.callback_budget_exceeded)),
        "Bluetooth registration/callback evidence inconsistent"
    );
    ensure!(
        r.state_matches_at_checks == r.state_before.zip(r.state_after).map(|(a, b)| a == b),
        "Bluetooth state equality must reflect both actual checks"
    );
    if r.state_before.is_some() || r.state_after.is_some() || r.receiver_registered {
        ensure!(
            r.connect_permission_granted && r.adapter_present == Some(true),
            "Bluetooth reads require permission and an available adapter"
        );
    }
    match r.status {
        BluetoothStatus::Observed => ensure!(
            r.reason == BluetoothStatusReason::BoundedStatusComplete
                && r.state_before.is_some()
                && r.state_after.is_some()
                && r.receiver_registered
                && r.receiver_cleanup_attempted
                && r.receiver_removed
                && r.callback_thread_stopped
                && !r.invalid_state_callback
                && !r.callback_budget_exceeded
                && (2000..=3500).contains(&r.window_elapsed_ms)
                && r.elapsed_ms <= 6000,
            "Bluetooth observed requires two valid reads, bounded receiver window and teardown"
        ),
        BluetoothStatus::Unavailable => {
            ensure!(
                r.reason != BluetoothStatusReason::BoundedStatusComplete,
                "incomplete Bluetooth status cannot claim completed observation"
            );
            match r.reason {
                BluetoothStatusReason::AdapterUnavailable => ensure!(
                    r.adapter_present == Some(false)
                        && r.connect_permission_granted
                        && r.state_before.is_none()
                        && r.state_after.is_none()
                        && !r.receiver_registered,
                    "missing adapter cannot carry state observations"
                ),
                BluetoothStatusReason::ManagerUnavailable => ensure!(
                    r.adapter_present.is_none()
                        && r.connect_permission_granted
                        && r.state_before.is_none()
                        && r.state_after.is_none()
                        && !r.receiver_registered,
                    "missing manager cannot carry state observations"
                ),
                BluetoothStatusReason::CallbackBudgetExceeded => ensure!(
                    r.callback_budget_exceeded && r.callback_count == 32,
                    "callback budget failure requires saturated counter"
                ),
                _ => (),
            }
        }
    }
    Ok(r)
}
