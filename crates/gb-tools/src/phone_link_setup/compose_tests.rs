use super::*;
const FOCUS: &str = "mCurrentFocus=Window{123abc u11 com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity}";
fn fixture(class: &str) -> String {
    let n = |class: &str, bounds: &str, clickable: bool, text: &str, children: &str| {
        format!(
            r#"<node package_scope="own" class="{class}" bounds="{bounds}" enabled="true" clickable="{clickable}" visibility="unknown" text="{text}" content-desc="">{children}</node>"#
        )
    };
    let label = n(
        "android.widget.TextView",
        "[120,400][280,440]",
        false,
        BUTTON,
        "",
    );
    let button = n("android.view.View", "[100,380][300,460]", true, "", &label);
    let title = n(
        "android.widget.TextView",
        "[100,100][400,140]",
        false,
        TITLE,
        "",
    );
    let body = n(
        "android.widget.TextView",
        "[100,180][400,240]",
        false,
        BODY,
        "",
    );
    let compose = n(
        class,
        "[0,0][600,600]",
        false,
        "",
        &(title + &body + &button),
    );
    let root = n(
        "android.widget.FrameLayout",
        "[0,0][600,600]",
        false,
        "",
        &compose,
    );
    format!(
        r#"<gb-phone-link-ui><hierarchy>{root}</hierarchy><gb-meta complete="true" node_count="6" visibility_attributes="0" raw_content_exported="false"/></gb-phone-link-ui>"#
    )
}
#[test]
fn exact_source_qualified_compose_is_opt_in_and_plan_only() {
    let xml = fixture("androidx.compose.ui.platform.ComposeView");
    assert!(plan_get_started(&xml, FOCUS, 11).is_err());
    let plan = plan_get_started_qualified(&xml, FOCUS, 11).unwrap();
    assert_eq!(plan.profile, "phone-link-local-onboarding-compose-v2");
    assert_eq!((plan.x, plan.y), (200, 420));
    assert!(!plan.visibility_verified);
    assert!(!plan.input_authorized && !plan.registration_verified && !plan.mutation_performed);
}
#[test]
fn classifier_candidates_and_other_never_gain_native_authority() {
    for class in [
        "redacted.Other",
        "androidx.compose.ui.platform.AndroidComposeView",
        "androidx.compose.ui.platform.AbstractComposeView",
        "android.webkit.WebView",
        "androidx.compose.ui.platform.ComposeViewFake",
    ] {
        assert!(
            plan_get_started_qualified(&fixture(class), FOCUS, 11).is_err(),
            "{class}"
        );
    }
    let xml = fixture("androidx.compose.ui.platform.ComposeView");
    assert!(
        plan_get_started_qualified(
            &xml.replacen("package_scope=\"own\"", "package_scope=\"foreign\"", 1),
            FOCUS,
            11
        )
        .is_err()
    );
    assert!(
        plan_get_started_qualified(
            &xml.replacen("visibility=\"unknown\"", "visibility=\"false\"", 1),
            FOCUS,
            11
        )
        .is_err()
    );
}
