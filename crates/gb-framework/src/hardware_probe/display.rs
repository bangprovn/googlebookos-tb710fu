//! Bounded owned-window rendering/readback evidence, never panel or input qualification.
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Display {
    status: String,
    owned_window_only: bool,
    settings_changed: bool,
    physical_panel_verified: bool,
    physical_touch_verified: bool,
    external_display_verified: bool,
    results: Vec<Observation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    operation: String,
    state: String,
    failure: String,
    width: u32,
    height: u32,
    phases_completed: u32,
    draw_calls: u32,
    draw_budget_exceeded: bool,
    frame_callbacks: u32,
    frame_commit_callbacks: u32,
    frame_timestamps_increasing: bool,
    hardware_accelerated_view: bool,
    hardware_accelerated_canvas: bool,
    pixel_copy_successes: u32,
    last_pixel_copy_result: i32,
    sampled_pixels: u32,
    matching_pixels: u32,
    color_tolerance: u32,
    owned_bitmap_peak_bytes: u32,
    bitmap_released: bool,
    pixel_copy_pending: bool,
    ui_cleanup_completed: bool,
    owned_view_removed: bool,
    timed_out: bool,
    work_budget_ms: u32,
    elapsed_ms: u64,
    owned_source_only: bool,
    raw_pixels_saved_or_exported: bool,
    other_windows_captured: bool,
}
pub(super) fn inspect_display(value: &Value) -> Result<()> {
    if value == &serde_json::json!({"state":"unknown"}) {
        return Ok(());
    }
    let report: Display = serde_json::from_value(value.clone())?;
    ensure!(
        report.status == "observed"
            && report.owned_window_only
            && !report.settings_changed
            && !report.physical_panel_verified
            && !report.physical_touch_verified
            && !report.external_display_verified,
        "display operation cannot qualify other windows, settings, panel, touch or external display"
    );
    ensure!(
        report.results.len() == 1,
        "one bounded owned-window operation required"
    );
    let r = &report.results[0];
    ensure!(
        r.operation == "owned_window_render_readback"
            && matches!(r.state.as_str(), "compatible" | "unknown")
            && matches!(
                r.failure.as_str(),
                "none"
                    | "ui_deadline"
                    | "frame_deadline"
                    | "copy_deadline"
                    | "hardware_unavailable"
                    | "pixel_copy_error"
                    | "pattern_mismatch"
                    | "interrupted"
                    | "api_exception"
            ),
        "display verdict/operation/failure enum"
    );
    ensure!(
        r.width == 256
            && r.height == 256
            && r.color_tolerance == 4
            && r.phases_completed <= 3
            && r.frame_callbacks <= 3
            && r.frame_commit_callbacks <= 3
            && r.pixel_copy_successes <= 3
            && r.draw_calls <= 17
            && r.draw_budget_exceeded == (r.draw_calls > 16)
            && r.sampled_pixels <= 768
            && r.sampled_pixels.is_multiple_of(256)
            && r.matching_pixels <= r.sampled_pixels
            && matches!(r.owned_bitmap_peak_bytes, 0 | 262144)
            && (-1..=5).contains(&r.last_pixel_copy_result)
            && r.work_budget_ms == 12000
            && r.elapsed_ms <= 20000,
        "display allocation/frame/readback/time budget"
    );
    ensure!(
        r.owned_source_only && !r.raw_pixels_saved_or_exported && !r.other_windows_captured,
        "display pixels must remain local and diagnostic-window owned"
    );
    if r.state == "compatible" {
        ensure!(
            r.failure == "none"
                && !r.timed_out
                && !r.draw_budget_exceeded
                && r.phases_completed == 3
                && r.frame_callbacks == 3
                && r.frame_commit_callbacks == 3
                && r.frame_timestamps_increasing
                && (3..=16).contains(&r.draw_calls)
                && r.hardware_accelerated_view
                && r.hardware_accelerated_canvas
                && r.pixel_copy_successes == 3
                && r.last_pixel_copy_result == 0
                && r.sampled_pixels == 768
                && r.matching_pixels == 768
                && r.owned_bitmap_peak_bytes == 262144
                && r.bitmap_released
                && !r.pixel_copy_pending
                && r.ui_cleanup_completed
                && r.owned_view_removed,
            "display pass requires actual accelerated draws, callbacks, three local pattern readbacks and cleanup"
        );
    }
    Ok(())
}
