use super::*;
const FOCUS: &str = "mCurrentFocus=Window{abc123 u11 com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity}";
fn node(class: &str, bounds: &str, clickable: bool, text: &str, kids: &str) -> String {
    format!(
        r#"<node package_scope="own" class="{class}" bounds="{bounds}" enabled="true" clickable="{clickable}" visibility="unknown" text="{text}" content-desc="">{kids}</node>"#
    )
}
fn fixture(extra: &str) -> String {
    let title = node(
        "android.widget.TextView",
        "[100,100][500,140]",
        false,
        TITLE,
        "",
    );
    let body = node(
        "android.widget.TextView",
        "[100,180][500,240]",
        false,
        BODY,
        "",
    );
    let label = node(
        "android.widget.TextView",
        "[220,400][380,440]",
        false,
        BUTTON,
        "",
    );
    let click = node("android.view.View", "[100,380][500,460]", true, "", &label);
    let root = node(
        "android.view.View",
        "[0,0][600,600]",
        false,
        "",
        &format!("{title}{body}{click}{extra}"),
    );
    format!(
        r#"<gb-phone-link-ui><hierarchy>{root}</hierarchy><gb-meta complete="true" node_count="{}" visibility_attributes="0" raw_content_exported="false"/></gb-phone-link-ui>"#,
        5 + extra.matches("<node ").count()
    )
}
fn ok(xml: &str) -> bool {
    plan_get_started(xml, FOCUS, 11).is_ok()
}
#[test]
fn plans_only_fixed_label_with_explicit_visibility_unknown() {
    let r = plan_get_started(&fixture(""), FOCUS, 11).unwrap();
    assert_eq!((r.x, r.y), (300, 420));
    assert_eq!(r.label_path, vec![0, 2, 0]);
    assert_eq!(r.click_path, vec![0, 2]);
    assert!(
        !r.input_authorized
            && !r.mutation_performed
            && !r.registration_verified
            && !r.qr_setup_completed
    );
    assert!(
        !r.visibility_verified
            && !r.global_window_coverage_verified
            && r.external_identity_verification_required
    );
    let xml = fixture("")
        .replace("visibility=\"unknown\"", "visibility=\"true\"")
        .replace("visibility_attributes=\"0\"", "visibility_attributes=\"5\"");
    assert!(
        plan_get_started(&xml, FOCUS, 11)
            .unwrap()
            .visibility_verified
    );
}
#[test]
fn rejects_wrong_owner_focus_and_fake_component_suffix() {
    assert!(plan_get_started(&fixture(""), FOCUS, 0).is_err());
    for f in [
        FOCUS.replace("u11", "u0"),
        FOCUS.replace(
            ".RemoteAppsLauncherActivity",
            ".RemoteAppsLauncherActivityFake",
        ),
        FOCUS.replace("com.google.ambient.streaming/", "foreign/"),
        format!("{FOCUS}\n{FOCUS}"),
        FOCUS.to_owned() + " extra",
    ] {
        assert!(plan_get_started(&fixture(""), &f, 11).is_err());
    }
}
#[test]
fn rejects_duplicate_missing_and_conflicting_labels() {
    let duplicate = node(
        "android.widget.TextView",
        "[10,250][200,280]",
        false,
        BUTTON,
        "",
    );
    assert!(!ok(&fixture(&duplicate)));
    for needle in [TITLE, BODY, BUTTON] {
        assert!(!ok(&fixture("").replace(needle, "")));
    }
    for signal in [
        "Searching for nearby devices",
        "Check your phone to continue setup",
        "You need to turn on Wi-Fi",
        "Scan the QR code using your phone to start setup",
    ] {
        let n = node(
            "android.widget.TextView",
            "[10,250][590,280]",
            false,
            signal,
            "",
        );
        assert!(!ok(&fixture(&n)));
    }
}
#[test]
fn rejects_foreign_webview_and_competing_hit_targets() {
    assert!(!ok(&fixture("").replacen(
        "class=\"android.view.View\"",
        "class=\"redacted.Other\"",
        1
    )));
    assert!(!ok(&fixture("").replacen(
        "package_scope=\"own\"",
        "package_scope=\"foreign\"",
        1
    )));
    assert!(!ok(&fixture("").replace(
        "class=\"android.view.View\" bounds=\"[100,380][500,460]\"",
        "class=\"android.webkit.WebView\" bounds=\"[100,380][500,460]\""
    )));
    for foreign in [false, true] {
        let mut overlay = node("android.view.View", "[200,390][400,450]", true, "", "");
        if foreign {
            overlay = overlay.replace("package_scope=\"own\"", "package_scope=\"foreign\"");
        }
        assert!(!ok(&fixture(&overlay)));
    }
    let foreign = node("android.view.View", "[200,390][400,450]", false, "", "")
        .replace("package_scope=\"own\"", "package_scope=\"foreign\"");
    assert!(!ok(&fixture(&foreign)));
}
#[test]
fn rejects_unavailable_invalid_geometry_and_ambiguous_ancestor() {
    for replacement in [
        "[0,0][0,0]",
        "[500,380][100,460]",
        "[100,380][200,460]",
        "[100,380][99999,460]",
    ] {
        assert!(!ok(&fixture("").replace("[100,380][500,460]", replacement)));
    }
    for (from, to) in [
        ("enabled=\"true\"", "enabled=\"false\""),
        ("visibility=\"unknown\"", "visibility=\"false\""),
        (
            "[0,0][600,600]\" enabled=\"true\" clickable=\"false\"",
            "[0,0][600,600]\" enabled=\"true\" clickable=\"true\"",
        ),
    ] {
        assert!(!ok(&fixture("").replacen(from, to, 1)));
    }
    assert!(!ok(
        &fixture("").replace("[220,400][380,440]", "[220,400][580,440]")
    ));
}
#[test]
fn rejects_unredacted_private_metadata_budgets_and_false_completion() {
    for xml in [
        fixture("").replace("text=\"\"", "text=\"private account\""),
        fixture("").replacen(
            "package_scope=\"own\"",
            "package_scope=\"own\" account=\"private\"",
            1,
        ),
        fixture("").replace("complete=\"true\"", "complete=\"false\""),
        fixture("").replace("node_count=\"5\"", "node_count=\"4\""),
        fixture("").replace("visibility_attributes=\"0\"", "visibility_attributes=\"1\""),
        fixture("").replace(
            "raw_content_exported=\"false\"",
            "raw_content_exported=\"true\"",
        ),
        fixture("").replace("Get started", "Get&#32;started"),
    ] {
        assert!(!ok(&xml));
    }
    assert!(!ok(&"x".repeat(65537)));
}
