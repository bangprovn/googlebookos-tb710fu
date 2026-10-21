//! Anonymous public-API USB inventory; never a functional USB qualification.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_DEVICES: u32 = 32;
const MAX_CONFIGURATIONS: u32 = 128;
const MAX_INTERFACES: u32 = 512;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsbInventoryStatus {
    Observed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsbInventoryReason {
    SnapshotComplete,
    UsbManagerUnavailable,
    ApiException,
    BudgetExceeded,
    InvalidDescriptor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsbFunctionalState {
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsbInventoryScope {
    PublicApiInventoryOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsbClassCount {
    pub usb_class: u8,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsbInventory {
    pub status: UsbInventoryStatus,
    pub state: UsbFunctionalState,
    pub scope: UsbInventoryScope,
    pub reason: UsbInventoryReason,
    /// PackageManager declaration, not a hardware exercise or attestation.
    pub host_feature_declared: Option<bool>,
    pub attached_device_count: Option<u32>,
    /// All configurations, including alternate interface descriptors; not
    /// unique active interfaces or endpoints.
    pub configuration_descriptor_count: Option<u32>,
    pub interface_descriptor_count: Option<u32>,
    pub device_class_counts: Vec<UsbClassCount>,
    pub interface_class_counts: Vec<UsbClassCount>,
    pub inventory_complete: bool,
    pub observation_budget_exceeded: bool,
    pub read_only: bool,
    pub permission_requested: bool,
    pub device_opened: bool,
    pub transfer_performed: bool,
    pub role_or_settings_changed: bool,
    pub identifiers_collected: bool,
    pub content_collected: bool,
    pub host_functionality_verified: bool,
    pub typec_or_pd_verified: bool,
}

fn classes(rows: &[UsbClassCount], total: u32, bound: u32) -> Result<()> {
    ensure!(rows.len() <= 256, "USB class histogram budget");
    let mut previous = None;
    let mut sum = 0_u64;
    for row in rows {
        ensure!(
            previous.is_none_or(|value| row.usb_class > value) && (1..=bound).contains(&row.count),
            "USB class counts must be positive, bounded, unique and sorted"
        );
        previous = Some(row.usb_class);
        sum += u64::from(row.count);
    }
    ensure!(sum == u64::from(total), "USB histogram/total mismatch");
    Ok(())
}

pub fn inspect_usb_inventory(value: &serde_json::Value) -> Result<UsbInventory> {
    let inventory: UsbInventory =
        serde_json::from_value(value.clone()).context("anonymous USB inventory schema")?;
    ensure!(
        inventory.read_only
            && !inventory.permission_requested
            && !inventory.device_opened
            && !inventory.transfer_performed
            && !inventory.role_or_settings_changed
            && !inventory.identifiers_collected
            && !inventory.content_collected
            && !inventory.host_functionality_verified
            && !inventory.typec_or_pd_verified,
        "USB inventory cannot claim device operations or functional qualification"
    );
    match inventory.status {
        UsbInventoryStatus::Observed => {
            let devices = inventory
                .attached_device_count
                .context("USB attached count missing")?;
            let configurations = inventory
                .configuration_descriptor_count
                .context("USB configuration count missing")?;
            let interfaces = inventory
                .interface_descriptor_count
                .context("USB interface count missing")?;
            ensure!(
                inventory.reason == UsbInventoryReason::SnapshotComplete
                    && inventory.inventory_complete
                    && !inventory.observation_budget_exceeded
                    && devices <= MAX_DEVICES
                    && configurations <= MAX_CONFIGURATIONS
                    && interfaces <= MAX_INTERFACES
                    && (devices > 0 || (configurations == 0 && interfaces == 0))
                    && (configurations > 0 || interfaces == 0),
                "USB snapshot completeness/count budget"
            );
            classes(&inventory.device_class_counts, devices, MAX_DEVICES)?;
            classes(
                &inventory.interface_class_counts,
                interfaces,
                MAX_INTERFACES,
            )?;
        }
        UsbInventoryStatus::Unavailable => ensure!(
            inventory.reason != UsbInventoryReason::SnapshotComplete
                && !inventory.inventory_complete
                && inventory.observation_budget_exceeded
                    == (inventory.reason == UsbInventoryReason::BudgetExceeded)
                && inventory.attached_device_count.is_none()
                && inventory.configuration_descriptor_count.is_none()
                && inventory.interface_descriptor_count.is_none()
                && inventory.device_class_counts.is_empty()
                && inventory.interface_class_counts.is_empty(),
            "unavailable USB inventory must not publish incomplete totals"
        ),
    }
    Ok(inventory)
}
