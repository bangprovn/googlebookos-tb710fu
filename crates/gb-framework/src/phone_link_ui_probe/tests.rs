use super::*;
use serde_json::{Value, json};
fn sample(offset: u64) -> Value {
    json!({"status":"native_observed","offset_ms":offset,"query_elapsed_ms":10,
        "target_window":true,"poll_complete":true,"visited_nodes":2,"foreign_subtrees_pruned":0,
        "webview_subtrees_pruned":0,"null_children":0,"nodes_recycled":2,"text_characters_examined":28,
        "node_limit":false,"depth_limit":false,"text_limit":false,"poll_deadline_exceeded":false,
        "query_failed":false,"node_recycle_failed":false,"text_counts":counts(),"description_counts":counts()})
}
fn counts() -> Value {
    serde_json::to_value(PhoneLinkUiCounts::default()).unwrap()
}
fn report() -> Value {
    json!({"schema_version":1,"probe":"owned_phone_link_ui_v1","status":"completed","android_user":11,
        "uid":1110001,"expected_target_uid":1110128,"target_package":"com.google.ambient.streaming",
        "expected_target_apk_sha256":crate::phone_link_ui_probe::TARGET_APK_SHA256,
        "whitelist_sha256":crate::phone_link_ui_probe::WHITELIST_SHA256,
        "observation_only":true,"input_performed":false,"raw_content_exported":false,
        "settings_or_permissions_changed":false,"framework_cleanup_verified":false,
        "registration_verified":false,"active_rf_scan_verified":false,"peer_eligibility_verified":false,
        "functional_phone_link_verified":false,"external_target_identity_verified":false,
        "ui_automation_acquired":true,"accessibility_cache_policy":"clear_before_each_poll",
        "cache_clear_attempts":2,"cache_clear_successes":2,"root_queries":2,
        "observation_elapsed_ms":5520,"node_budget_per_poll":512,"depth_budget":32,
        "text_characters_per_field_budget":2048,"text_characters_per_poll_budget":65536,
        "window_budget_per_poll":1,"sample_budget":2,"samples":[sample(0),sample(5500)],
        "finish_requested":true,"finish_failed":false})
}
fn ok(v: &Value) -> bool {
    inspect_phone_link_ui(&v.to_string()).is_ok()
}
#[test]
fn valid_fixed_counts_and_incomplete_observations_keep_scope_unknown() {
    let mut r = report();
    r["samples"][0]["text_counts"]["searching_label"] = 1.into();
    let parsed = inspect_phone_link_ui(&r.to_string()).unwrap();
    assert_eq!(parsed.samples[0].text_counts.searching_label, 1);
    assert!(!parsed.active_rf_scan_verified && !parsed.registration_verified);
    r["status"] = "query_incomplete".into();
    r["samples"][1]["poll_complete"] = false.into();
    r["samples"][1]["status"] = "node_unavailable".into();
    r["samples"][1]["null_children"] = 1.into();
    assert!(ok(&r)); // Counts on incomplete polls are observations, not proof.
}
#[test]
fn refuses_private_fields_duplicates_and_claims() {
    for field in ["raw_text", "peer_name", "account", "url", "extra"] {
        let mut r = report();
        r[field] = "private".into();
        assert!(!ok(&r));
    }
    let r = report().to_string();
    assert!(inspect_phone_link_ui(&r.replacen("{", "{\"schema_version\":1,", 1)).is_err());
    let r = r.replacen(
        "\"searching_label\":0",
        "\"searching_label\":0,\"searching_label\":0",
        1,
    );
    assert!(inspect_phone_link_ui(&r).is_err());
    for field in [
        "input_performed",
        "raw_content_exported",
        "settings_or_permissions_changed",
        "framework_cleanup_verified",
        "registration_verified",
        "active_rf_scan_verified",
        "peer_eligibility_verified",
        "functional_phone_link_verified",
        "external_target_identity_verified",
        "finish_failed",
    ] {
        let mut r = report();
        r[field] = true.into();
        assert!(!ok(&r), "{field}");
    }
    for field in ["observation_only", "finish_requested"] {
        let mut r = report();
        r[field] = false.into();
        assert!(!ok(&r));
    }
    let mut r = report();
    r["samples"][0]["text_counts"]["peer_name"] = "private".into();
    assert!(!ok(&r));
}
#[test]
fn refuses_identity_budget_and_timing_contradictions() {
    for (field, value) in [
        ("android_user", json!(0)),
        ("uid", json!(1110128_u32 + 100000)),
        ("expected_target_uid", json!(1110129)),
        ("target_package", json!("other")),
        ("expected_target_apk_sha256", json!("0".repeat(64))),
        ("whitelist_sha256", json!("0".repeat(64))),
        ("node_budget_per_poll", json!(513)),
        ("sample_budget", json!(3)),
        ("cache_clear_successes", json!(1)),
        ("root_queries", json!(1)),
        ("observation_elapsed_ms", json!(8000)),
    ] {
        let mut r = report();
        r[field] = value;
        assert!(!ok(&r), "{field}");
    }
    for (field, value) in [
        ("visited_nodes", json!(513)),
        ("nodes_recycled", json!(1)),
        ("text_characters_examined", json!(65537)),
        ("node_limit", json!(true)),
        ("poll_complete", json!(false)),
        ("query_elapsed_ms", json!(251)),
        ("target_window", json!(false)),
        ("offset_ms", json!(u64::MAX)),
    ] {
        let mut r = report();
        r["samples"][0][field] = value;
        assert!(!ok(&r), "{field}");
    }
    let mut r = report();
    r["samples"][1]["offset_ms"] = 5499.into();
    assert!(!ok(&r));
    let mut r = report();
    r["samples"][0]["text_counts"]["searching_label"] = 3.into();
    assert!(!ok(&r));
    let mut r = report();
    r["samples"][0]["text_counts"]["searching_label"] = 1.into();
    r["samples"][0]["text_characters_examined"] = 27.into();
    assert!(!ok(&r));
    let mut pruned = report();
    pruned["samples"][0]["foreign_subtrees_pruned"] = 2.into();
    pruned["samples"][0]["text_counts"]["searching_label"] = 1.into();
    assert!(!ok(&pruned));
    let mut r = report();
    r.as_object_mut().unwrap().remove("uid");
    assert!(!ok(&r));
    assert!(inspect_phone_link_ui(&" ".repeat(65537)).is_err());
}
#[test]
fn rejects_missing_observations_and_contradictory_failures() {
    let mut r = report();
    r["samples"] = json!([]);
    assert!(!ok(&r));
    r["status"] = "automation_unavailable".into();
    r["ui_automation_acquired"] = false.into();
    r["cache_clear_attempts"] = 0.into();
    r["cache_clear_successes"] = 0.into();
    r["root_queries"] = 0.into();
    assert!(ok(&r));
    r["status"] = "duration_exceeded".into();
    assert!(!ok(&r));
    r["observation_elapsed_ms"] = 8000.into();
    assert!(ok(&r));
    let mut r = report();
    r["status"] = "query_incomplete".into();
    r["samples"][0]["status"] = "query_failed".into();
    r["samples"][0]["poll_complete"] = false.into();
    assert!(!ok(&r));
    r["samples"][0]["query_failed"] = true.into();
    assert!(ok(&r));
}
#[test]
fn java_literals_source_and_protocol_are_pinned() {
    let java = include_str!("PhoneLinkUiProbe.java");
    assert!(java.contains(crate::phone_link_ui_probe::TARGET_APK_SHA256));
    assert!(java.contains(crate::phone_link_ui_probe::WHITELIST_SHA256));
    assert!(
        java.contains("FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES")
            && java.contains("a.clearCache()")
    );
    for forbidden in [
        "performAction(",
        "injectInputEvent(",
        "getWindows(",
        "takeScreenshot(",
        "Log.",
        "getViewIdResourceName(",
    ] {
        assert!(!java.contains(forbidden), "{forbidden}");
    }
}
