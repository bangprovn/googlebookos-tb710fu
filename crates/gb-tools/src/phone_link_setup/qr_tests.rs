use super::*;
const FOCUS: &str = "mCurrentFocus=Window{abc123 u11 com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity}";
const QR: &str = "Scan the QR code using your phone to start setup";
fn node(class: &str, b: &str, text: &str, desc: &str, kids: &str) -> String {
    format!(
        r#"<node package_scope="own" class="{class}" bounds="{b}" enabled="true" clickable="false" visibility="unknown" text="{text}" content-desc="{desc}">{kids}</node>"#
    )
}
fn fixture(extra: &str) -> String {
    let image = node("android.widget.ImageView", "[200,100][400,300]", "", QR, "");
    let text = node("android.widget.TextView", "[100,350][500,450]", QR, "", "");
    let scroll = node(
        "android.widget.ScrollView",
        "[0,0][600,600]",
        "",
        "",
        &(image + &text + extra),
    );
    let compose = node(
        "androidx.compose.ui.platform.ComposeView",
        "[0,0][600,600]",
        "",
        "",
        &scroll,
    );
    let root = node(
        "android.widget.FrameLayout",
        "[0,0][600,600]",
        "",
        "",
        &compose,
    );
    format!(
        r#"<gb-phone-link-ui><hierarchy>{root}</hierarchy><gb-meta complete="true" node_count="{}" visibility_attributes="0" raw_content_exported="false"/></gb-phone-link-ui>"#,
        5 + extra.matches("<node ").count()
    )
}
fn ok(xml: &str) -> bool {
    inspect_qr_state_qualified(xml, FOCUS, 11).is_ok()
}
#[test]
fn exact_native_pair_is_observation_only_never_qr_content_proof() {
    let r = inspect_qr_state_qualified(&fixture(""), FOCUS, 11).unwrap();
    assert_eq!(r.instruction_nodes, 2);
    assert!(r.native_qr_view_observed);
    assert_eq!(r.shared_scroll_view_path, vec![0, 0, 0]);
    assert!(
        !r.visibility_verified
            && !r.qr_image_pixels_verified
            && !r.qr_content_read
            && !r.qr_decoding_verified
            && !r.registration_verified
            && !r.functional_phone_link_verified
            && !r.input_authorized
            && !r.mutation_performed
    );
}
#[test]
fn wrong_role_one_or_three_matches_or_mixed_intro_refused() {
    for xml in [
        fixture("").replacen("android.widget.ImageView", "android.widget.TextView", 1),
        fixture("").replacen(QR, "", 1),
        fixture("").replace(QR, "prefix instruction"),
        fixture(&node(
            "android.widget.TextView",
            "[10,500][590,550]",
            QR,
            "",
            "",
        )),
        fixture(&node(
            "android.widget.TextView",
            "[10,500][590,550]",
            BUTTON,
            "",
            "",
        )),
    ] {
        assert!(!ok(&xml));
    }
}
#[test]
fn unavailable_foreign_wrong_scroll_and_geometry_refused() {
    for xml in [
        fixture("").replacen("package_scope=\"own\"", "package_scope=\"foreign\"", 1),
        fixture("").replacen("visibility=\"unknown\"", "visibility=\"false\"", 1),
        fixture("").replace("android.widget.ScrollView", "android.view.View"),
        fixture("").replace("[200,100][400,300]", "[200,100][450,300]"),
        fixture("").replace("[100,350][500,450]", "[100,250][500,450]"),
        fixture("").replace(
            "[200,100][400,300]\" enabled=\"true\" clickable=\"false\"",
            "[200,100][400,300]\" enabled=\"true\" clickable=\"true\"",
        ),
    ] {
        assert!(!ok(&xml));
    }
    assert!(inspect_qr_state_qualified(&fixture(""), FOCUS, 0).is_err());
    let image = node("android.widget.ImageView", "[200,100][400,300]", "", QR, "");
    let caption = node("android.widget.TextView", "[100,350][500,450]", QR, "", "");
    let a = node(
        "android.widget.ScrollView",
        "[0,0][600,600]",
        "",
        "",
        &image,
    );
    let b = node(
        "android.widget.ScrollView",
        "[0,0][600,600]",
        "",
        "",
        &caption,
    );
    let root = node(
        "android.widget.FrameLayout",
        "[0,0][600,600]",
        "",
        "",
        &(a + &b),
    );
    let xml = format!(
        r#"<gb-phone-link-ui><hierarchy>{root}</hierarchy><gb-meta complete="true" node_count="5" visibility_attributes="0" raw_content_exported="false"/></gb-phone-link-ui>"#
    );
    assert!(!ok(&xml));
}
