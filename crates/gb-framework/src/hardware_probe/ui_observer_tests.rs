use super::*;
use serde_json::{Value, json};

fn common(kind: &str, status: &str) -> Value {
    json!({"schema_version":1,"probe":"owned_terminal_ui_observer_v1",
        "record_kind":kind,"status":status,"android_user":11,"uid":1110248,
        "observation_only":true,"command_execution_verified":false,"output_proof_claimed":false,
        "input_performed":false,"raw_content_exported":false,
        "settings_or_permissions_changed":false,"framework_cleanup_verified":false})
}
fn observation() -> Value {
    json!({"status":"terminal_webview_empty","offset_ms":0,"query_elapsed_ms":1,
        "terminal_window":true,"poll_complete":true,"visited_nodes":3,"webview_roots":1,
        "foreign_subtrees_pruned":0,"null_children":0,"nonempty_positive_width_text_nodes":0,
        "text_characters_examined":0,"whole_line_marker_matches":0,"contains_marker_matches":0,
        "node_limit":false,"depth_limit":false,"text_limit":false,"match_limit":false,
        "poll_deadline_exceeded":false,"query_failed":false,"node_recycle_failed":false,
        "accessibility_enabled":true,"touch_exploration_enabled":false})
}
fn ready() -> Value {
    let mut v = common("ready", "ready");
    v.as_object_mut().unwrap().extend(json!({
        "accessibility_enabled_before_connection":false,"accessibility_enabled_after_connection":true,
        "touch_exploration_before_connection":false,"touch_exploration_after_connection":false,
        "ui_automation_acquired":true,"first_poll_pending":true}).as_object().unwrap().clone());
    v
}
fn sample(row: Value) -> Value {
    let mut v = common("sample", row["status"].as_str().unwrap());
    v["sample"] = row;
    v
}
fn final_record() -> Value {
    let mut v = common("final", "completed");
    let mut last = observation();
    last["offset_ms"] = json!(750);
    v.as_object_mut().unwrap().extend(json!({
        "requested_duration_ms":1000,"observation_elapsed_ms":1000,"poll_interval_ms":250,
        "polls":4,"complete_polls":4,"maximum_poll_start_gap_ms":250,
        "samples":[observation(),last],"sample_budget":32,"samples_dropped":0,
        "sample_budget_exceeded":false,"ready_sent":true,"ui_automation_acquired":true,
        "accessibility_manager_available":true,"accessibility_enabled_before_connection":false,
        "accessibility_enabled_after_connection":true,"accessibility_enabled_before_finish":true,
        "touch_exploration_before_connection":false,"touch_exploration_after_connection":false,
        "touch_exploration_before_finish":false,"maximum_whole_line_marker_matches":0,
        "maximum_contains_marker_matches":0,"node_budget_per_poll":4096,"depth_budget":64,
        "text_characters_per_node_budget":4096,"text_characters_per_poll_budget":262144,
        "marker_match_budget_per_poll":4096,"finish_requested":true,"finish_failed":false
    }).as_object().unwrap().clone());
    v
}
fn inspect(value: &Value) -> Result<UiObserverRecord> {
    inspect_ui_observer(&value.to_string())
}

#[test]
fn valid_ready_sample_and_final_remain_observation_only() {
    assert!(matches!(
        inspect(&ready()).unwrap(),
        UiObserverRecord::Ready(_)
    ));
    assert!(matches!(
        inspect(&sample(observation())).unwrap(),
        UiObserverRecord::Sample(_)
    ));
    let value = inspect(&final_record()).unwrap();
    let UiObserverRecord::Final(report) = value else {
        panic!("wrong kind")
    };
    assert!(!report.command_execution_verified && !report.framework_cleanup_verified);
    assert_eq!(report.complete_polls, 4);
    assert!(report.accessibility_cache_policy.is_none());
}

#[test]
fn cache_policy_is_explicit_typed_and_not_execution_proof() {
    for mut value in [ready(), sample(observation()), final_record()] {
        value["accessibility_cache_policy"] = json!("clear_before_each_poll");
        let parsed = inspect(&value).unwrap();
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["accessibility_cache_policy"],
            json!("clear_before_each_poll")
        );
        for invalid in [json!("fresh_dom"), json!(true), json!(1), json!({})] {
            value["accessibility_cache_policy"] = invalid;
            assert!(inspect(&value).is_err());
        }
    }
}

#[test]
fn incomplete_matches_and_maxima_do_not_become_proof() {
    let mut row = observation();
    row["status"] = json!("poll_deadline");
    row["poll_complete"] = json!(false);
    row["poll_deadline_exceeded"] = json!(true);
    row["query_elapsed_ms"] = json!(251);
    row["nonempty_positive_width_text_nodes"] = json!(1);
    row["text_characters_examined"] = json!(43);
    row["whole_line_marker_matches"] = json!(1);
    row["contains_marker_matches"] = json!(1);
    assert!(inspect(&sample(row.clone())).is_ok());
    let mut value = final_record();
    value["samples"] = json!([row]);
    value["complete_polls"] = json!(0);
    value["maximum_whole_line_marker_matches"] = json!(1);
    value["maximum_contains_marker_matches"] = json!(1);
    let UiObserverRecord::Final(parsed) = inspect(&value).unwrap() else {
        panic!("kind")
    };
    assert_eq!(parsed.maximum_whole_line_marker_matches, 1);
    assert!(!parsed.command_execution_verified && !parsed.output_proof_claimed);
}

#[test]
fn private_unknown_fields_rejected_at_every_level() {
    for key in [
        "text",
        "marker",
        "url",
        "cookie",
        "exception",
        "private_payload",
    ] {
        let mut v = ready();
        v[key] = json!({"raw":"private"});
        assert!(inspect(&v).is_err());
        let mut v = sample(observation());
        v["sample"][key] = json!("private");
        assert!(inspect(&v).is_err());
        let mut v = final_record();
        v["samples"][0][key] = json!("private");
        assert!(inspect(&v).is_err());
    }
}

#[test]
fn all_scope_or_execution_claims_rejected() {
    for mut v in [ready(), sample(observation()), final_record()] {
        v["observation_only"] = json!(false);
        assert!(inspect(&v).is_err());
        v["observation_only"] = json!(true);
        for key in [
            "command_execution_verified",
            "output_proof_claimed",
            "input_performed",
            "raw_content_exported",
            "settings_or_permissions_changed",
            "framework_cleanup_verified",
        ] {
            v[key] = json!(true);
            assert!(inspect(&v).is_err(), "{key}");
            v[key] = json!(false);
        }
    }
}

#[test]
fn identity_schema_missing_and_minimal_failures_are_not_readiness() {
    for (key, value) in [
        ("schema_version", json!(2)),
        ("probe", json!("other")),
        ("android_user", json!(215)),
        ("android_user", json!(-1)),
        ("android_user", json!(true)),
        ("uid", json!(1109999)),
        ("uid", json!(1120000)),
        ("uid", json!(10123)),
        ("uid", json!(u32::MAX)),
    ] {
        let mut v = ready();
        v[key] = value;
        assert!(inspect(&v).is_err(), "{key}");
    }
    for key in [
        "schema_version",
        "probe",
        "record_kind",
        "uid",
        "observation_only",
        "first_poll_pending",
    ] {
        let mut v = ready();
        v.as_object_mut().unwrap().remove(key);
        assert!(inspect(&v).is_err());
    }
    for status in ["arguments_refused", "finish_failed"] {
        assert!(
            inspect(
                &json!({"schema_version":1,"status":status,"finish_requested":true,
            "finish_failed":status=="finish_failed","framework_cleanup_verified":false})
            )
            .is_err()
        );
    }
    let mut v = ready();
    v["android_user"] = json!(214);
    v["uid"] = json!(21419999);
    assert!(inspect(&v).is_ok());
}

#[test]
fn poll_budgets_status_and_completeness_are_checked_without_panics() {
    for (key, value) in [
        ("visited_nodes", json!(4097)),
        ("visited_nodes", json!(u32::MAX)),
        ("text_characters_examined", json!(262145)),
        ("contains_marker_matches", json!(4097)),
        ("whole_line_marker_matches", json!(1)),
        ("null_children", json!(u32::MAX)),
        ("query_elapsed_ms", json!(251)),
        ("offset_ms", json!(u64::MAX)),
        ("poll_complete", json!(false)),
        ("status", json!("ready")),
        ("query_failed", json!(true)),
    ] {
        let mut row = observation();
        row[key] = value;
        assert!(inspect(&sample(row)).is_err(), "{key}");
    }
    let mut v = sample(observation());
    v["status"] = json!("query_failed");
    assert!(inspect(&v).is_err());
    let mut row = observation();
    row["status"] = json!("text_limit");
    row["poll_complete"] = json!(false);
    row["text_limit"] = json!(true);
    row["nonempty_positive_width_text_nodes"] = json!(1);
    // Rejected text increments textNodes before checking its per-file budget.
    assert!(inspect(&sample(row)).is_ok());

    let mut row = observation();
    row["status"] = json!("depth_limit");
    row["poll_complete"] = json!(false);
    row["depth_limit"] = json!(true);
    assert!(inspect(&sample(row)).is_err());
    let mut row = observation();
    row["status"] = json!("terminal_webview_text");
    row["nonempty_positive_width_text_nodes"] = json!(1);
    row["text_characters_examined"] = json!(4097);
    assert!(inspect(&sample(row)).is_err());
}

#[test]
fn null_children_are_not_incorrectly_capped_at_visited_nodes() {
    let mut row = observation();
    row["status"] = json!("node_unavailable");
    row["poll_complete"] = json!(false);
    row["null_children"] = json!(5000);
    assert!(inspect(&sample(row)).is_ok());
}

#[test]
fn retained_failure_flags_remain_incomplete_after_query_or_deadline_failure() {
    let mut row = observation();
    row["poll_complete"] = json!(false);
    row["node_limit"] = json!(true);
    row["query_failed"] = json!(true);
    row["status"] = json!("query_failed");
    row["node_recycle_failed"] = json!(true);
    assert!(inspect(&sample(row.clone())).is_ok());
    row["poll_deadline_exceeded"] = json!(true);
    row["status"] = json!("poll_deadline");
    row["query_elapsed_ms"] = json!(300);
    assert!(inspect(&sample(row)).is_ok());
}

#[test]
fn dropped_incomplete_poll_can_supply_a_maximum_absent_from_retained_rows() {
    let mut v = final_record();
    let mut rows = Vec::new();
    for index in 0..32 {
        let mut row = observation();
        row["status"] = json!("poll_deadline");
        row["poll_complete"] = json!(false);
        row["poll_deadline_exceeded"] = json!(true);
        row["offset_ms"] = json!(index * 251);
        row["query_elapsed_ms"] = json!(251);
        row["accessibility_enabled"] = json!(index % 2 == 0);
        rows.push(row);
    }
    v["requested_duration_ms"] = json!(9000);
    v["observation_elapsed_ms"] = json!(9036);
    v["polls"] = json!(36);
    v["complete_polls"] = json!(0);
    v["maximum_poll_start_gap_ms"] = json!(251);
    v["samples"] = json!(rows);
    v["samples_dropped"] = json!(1);
    v["sample_budget_exceeded"] = json!(true);
    v["maximum_whole_line_marker_matches"] = json!(1);
    v["maximum_contains_marker_matches"] = json!(1);
    assert!(inspect(&v).is_ok());
    v["sample_budget_exceeded"] = json!(false);
    assert!(inspect(&v).is_err());
}

#[test]
fn final_contradictions_and_caps_are_rejected() {
    for (key, value) in [
        ("requested_duration_ms", json!(999)),
        ("requested_duration_ms", json!(90001)),
        ("poll_interval_ms", json!(249)),
        ("sample_budget", json!(33)),
        ("node_budget_per_poll", json!(4095)),
        ("finish_requested", json!(false)),
        ("finish_failed", json!(true)),
        ("ready_sent", json!(false)),
        ("polls", json!(6)),
        ("complete_polls", json!(5)),
        ("maximum_poll_start_gap_ms", json!(0)),
        ("observation_elapsed_ms", json!(999)),
        ("observation_elapsed_ms", json!(u64::MAX)),
        ("maximum_whole_line_marker_matches", json!(1)),
        ("sample_budget_exceeded", json!(true)),
        ("samples_dropped", json!(1)),
        ("status", json!("finish_failed")),
    ] {
        let mut v = final_record();
        v[key] = value;
        assert!(inspect(&v).is_err(), "{key}");
    }
    let mut v = final_record();
    v["samples"][1]["offset_ms"] = json!(0);
    assert!(inspect(&v).is_err());
    let mut v = final_record();
    v["samples"][1]["query_elapsed_ms"] = json!(251);
    v["samples"][1]["status"] = json!("poll_deadline");
    v["samples"][1]["poll_complete"] = json!(false);
    v["samples"][1]["poll_deadline_exceeded"] = json!(true);
    assert!(inspect(&v).is_err());
    let mut v = final_record();
    v["samples"] = json!(vec![observation(); 33]);
    assert!(inspect(&v).is_err());
}

#[test]
fn fully_scoped_preflight_failure_remains_failure() {
    let mut v = final_record();
    v["status"] = json!("automation_unavailable");
    v["polls"] = json!(0);
    v["complete_polls"] = json!(0);
    v["samples"] = json!([]);
    v["maximum_poll_start_gap_ms"] = json!(0);
    v["ready_sent"] = json!(false);
    v["ui_automation_acquired"] = json!(false);
    v["accessibility_enabled_after_connection"] = json!(false);
    assert!(inspect(&v).is_ok());
    v["ready_sent"] = json!(true);
    assert!(inspect(&v).is_err());
}

#[test]
fn json_size_duplicates_and_trailing_payloads_rejected() {
    let text = ready().to_string();
    assert!(inspect_ui_observer(&format!("{text}{{}}")).is_err());
    assert!(inspect_ui_observer(&format!("{{\"uid\":1110248,{}", &text[1..])).is_err());
    assert!(inspect_ui_observer(&format!("{}{}", text, " ".repeat(65537))).is_err());
    assert!(inspect_ui_observer("").is_err());
}

#[test]
fn java_schema_source_pin_is_explicit() {
    assert_eq!(
        gb_core::digest(include_bytes!("TerminalUiObserver.java")),
        "a94d087915c0d7d10f8735e03622b26f8822782c54f081a84c4e06935035ea0d"
    );
}
