//! Source-bound, plan-only original Phone Link onboarding control guard.
//! Root must independently bind the pinned APK, owner/UID, boot/process births,
//! trusted on-device reducer/producer, fresh focus and the one intended action.
//! Missing visibility remains unknown. No input or device operations occur here.
use crate::terminal_ui::Bounds;
use anyhow::{Context, Result, ensure};
use roxmltree::Node;
use serde::Serialize;

pub const CONTROL_REDUCER_V2: &str = include_str!("phone_link_setup/reduce-setup-v2.sh");
pub const CONTROL_REDUCER: &str = include_str!("phone_link_setup/reduce-setup.sh");
pub const TARGET_APK_SHA256: &str =
    "518884a1bf141dd2f83308b5833a729c36f4db59456d19554e9f0ab43008e82f";
const SHORT: &str = "com.google.ambient.streaming/.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity";
const FULL: &str = "com.google.ambient.streaming/com.google.ambient.streaming.multidevicesync.appcast.receiver.launcher.RemoteAppsLauncherActivity";
const TITLE: &str = "Cast your phone’s apps";
const BODY: &str = "Use your Android phone’s apps on your Googlebook with no installs needed";
const BUTTON: &str = "Get started";
const LABELS: &[&str] = &[
    "Searching for nearby devices",
    TITLE,
    BODY,
    "Check your phone to continue setup",
    "Follow the guided setup on your phone to allow permissions",
    "Set up new phone",
    "You need to turn on Wi-Fi",
    "Turn on App Cast in Cross-device services on your Phone to access apps from your phone on this device.",
    "Open Settings on phone",
    "Wi-Fi disconnected",
    "Onboarding illustration",
    BUTTON,
    "Scan the QR code using your phone to start setup",
];
#[derive(Debug, Serialize)]
pub struct SetupPlan {
    pub profile: &'static str,
    pub expected_target_apk_sha256: &'static str,
    pub x: u32,
    pub y: u32,
    pub label_bounds: Bounds,
    pub click_bounds: Bounds,
    pub label_path: Vec<usize>,
    pub click_path: Vec<usize>,
    pub visibility_verified: bool,
    pub active_hierarchy_coverage_checked: bool,
    pub global_window_coverage_verified: bool,
    pub external_identity_verification_required: bool,
    pub source_callback_local_setup_state_only: bool,
    pub input_authorized: bool,
    pub mutation_performed: bool,
    pub registration_verified: bool,
    pub qr_setup_completed: bool,
}
fn integer(s: &str) -> Result<usize> {
    ensure!(
        !s.is_empty()
            && s.len() <= 6
            && s.bytes().all(|v| v.is_ascii_digit())
            && (s == "0" || !s.starts_with('0')),
        "invalid reducer count"
    );
    Ok(s.parse()?)
}
fn native(n: Node<'_, '_>) -> bool {
    n.has_tag_name("node")
        && n.ancestors().filter(|p| p.has_tag_name("node")).all(|p| {
            p.attribute("package_scope") == Some("own")
                && !matches!(
                    p.attribute("class"),
                    Some("android.webkit.WebView" | "redacted.Other")
                )
        })
}
fn has(n: Node<'_, '_>, label: &str) -> bool {
    n.attribute("text") == Some(label) || n.attribute("content-desc") == Some(label)
}
fn bounds(n: Node<'_, '_>) -> Result<Bounds> {
    Bounds::parse(n.attribute("bounds").context("node bounds absent")?)
}
fn contains(a: Bounds, b: Bounds) -> bool {
    a.left <= b.left && a.top <= b.top && a.right >= b.right && a.bottom >= b.bottom
}
fn hits(b: Bounds, x: u32, y: u32) -> bool {
    b.left <= x && x < b.right && b.top <= y && y < b.bottom
}
fn path(n: Node<'_, '_>) -> Result<Vec<usize>> {
    let mut current = n;
    let mut result = Vec::new();
    while let Some(parent) = current.parent_element() {
        result.push(
            parent
                .children()
                .filter(Node::is_element)
                .position(|p| p == current)
                .context("node path absent")?,
        );
        if parent.has_tag_name("hierarchy") {
            result.reverse();
            return Ok(result);
        }
        ensure!(result.len() <= 32, "node path depth");
        current = parent;
    }
    anyhow::bail!("node outside native hierarchy")
}
fn focus(text: &str, owner: u32) -> Result<()> {
    ensure!(
        owner == 11 && text.len() <= 16384,
        "Phone Link focus owner/budget refused"
    );
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with("mCurrentFocus="))
        .collect();
    ensure!(lines.len() == 1, "sole Phone Link focus absent");
    let body = lines[0]
        .strip_prefix("mCurrentFocus=Window{")
        .and_then(|s| s.strip_suffix('}'))
        .context("focus format refused")?;
    let fields: Vec<_> = body.split_whitespace().collect();
    ensure!(
        fields.len() == 3
            && fields[0].len() <= 16
            && !fields[0].is_empty()
            && fields[0].bytes().all(|b| b.is_ascii_hexdigit())
            && fields[1] == "u11"
            && matches!(fields[2], SHORT | FULL),
        "exact owner Phone Link popup not focused"
    );
    Ok(())
}
/// Plan only the fixed source-backed Get started control. Does not issue input,
/// prove global overlay absence or authenticate the caller-supplied snapshot.
pub fn plan_get_started(xml: &str, current_focus: &str, owner: u32) -> Result<SetupPlan> {
    plan_profile(xml, current_focus, owner, false)
}
/// Opt-in exact ComposeView qualifier from pinned donor evo -> erh -> ViewGroup.
/// No AndroidComposeView/Other promotion; no device action or readiness claim.
pub fn plan_get_started_qualified(xml: &str, current_focus: &str, owner: u32) -> Result<SetupPlan> {
    plan_profile(xml, current_focus, owner, true)
}
fn parse_ui(xml: &str, compose_view: bool) -> Result<roxmltree::Document<'_>> {
    ensure!(
        !xml.is_empty() && xml.len() <= 65536 && !xml.contains('&') && !xml.contains("<!"),
        "redacted UI input budget/entities refused"
    );
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 4096,
            ..Default::default()
        },
    )
    .context("invalid redacted UI")?;
    ensure!(
        doc.descendants().all(|n| matches!(
            n.node_type(),
            roxmltree::NodeType::Root | roxmltree::NodeType::Element | roxmltree::NodeType::Text
        ) && (!n.is_text() || n.text().unwrap_or("").trim().is_empty())),
        "unexpected reducer markup/content"
    );
    let root = doc.root_element();
    ensure!(
        root.has_tag_name("gb-phone-link-ui") && root.attributes().len() == 0,
        "redacted UI envelope refused"
    );
    let children: Vec<_> = root.children().filter(Node::is_element).collect();
    ensure!(
        children.len() == 2
            && children[0].has_tag_name("hierarchy")
            && children[1].has_tag_name("gb-meta"),
        "redacted UI framing absent"
    );
    let hierarchy = children[0];
    let meta = children[1];
    ensure!(
        hierarchy.attributes().len() == 0 && meta.children().filter(Node::is_element).count() == 0,
        "invalid reducer envelope"
    );
    ensure!(
        meta.attributes().len() == 4
            && meta.attribute("complete") == Some("true")
            && meta.attribute("raw_content_exported") == Some("false"),
        "incomplete redaction"
    );
    let nodes: Vec<_> = hierarchy
        .descendants()
        .skip(1)
        .filter(Node::is_element)
        .collect();
    ensure!(
        !nodes.is_empty()
            && nodes.len() <= 512
            && nodes.iter().all(|n| n.has_tag_name("node"))
            && hierarchy.children().filter(Node::is_element).count() == 1
            && integer(meta.attribute("node_count").context("node count absent")?)? == nodes.len(),
        "redacted node count refused"
    );
    let known_visibility = nodes
        .iter()
        .filter(|n| n.attribute("visibility") != Some("unknown"))
        .count();
    let vis = integer(
        meta.attribute("visibility_attributes")
            .context("visibility count absent")?,
    )?;
    ensure!(
        vis >= known_visibility && vis <= 2 * known_visibility,
        "visibility accounting refused"
    );
    for node in &nodes {
        ensure!(
            node.attributes().len() == 8
                && node.attributes().all(|a| matches!(
                    a.name(),
                    "package_scope"
                        | "class"
                        | "bounds"
                        | "enabled"
                        | "clickable"
                        | "visibility"
                        | "text"
                        | "content-desc"
                )),
            "unknown node attributes"
        );
        ensure!(
            matches!(node.attribute("package_scope"), Some("own" | "foreign"))
                && (matches!(
                    node.attribute("class"),
                    Some(
                        "android.view.View"
                            | "android.widget.TextView"
                            | "android.widget.Button"
                            | "android.widget.ImageButton"
                            | "android.widget.ImageView"
                            | "android.webkit.WebView"
                            | "android.widget.FrameLayout"
                            | "android.widget.LinearLayout"
                            | "android.widget.RelativeLayout"
                            | "android.widget.ScrollView"
                            | "redacted.Other"
                    )
                ) || (compose_view
                    && node.attribute("class")
                        == Some("androidx.compose.ui.platform.ComposeView")))
                && matches!(node.attribute("enabled"), Some("true" | "false"))
                && matches!(node.attribute("clickable"), Some("true" | "false"))
                && matches!(
                    node.attribute("visibility"),
                    Some("true" | "false" | "unknown")
                ),
            "redacted role/flags refused"
        );
        ensure!(
            node.ancestors().filter(|p| p.has_tag_name("node")).count() <= 32,
            "redacted UI depth"
        );
        let b = bounds(*node)?;
        if let Some(parent) = node.parent_element().filter(|p| p.has_tag_name("node")) {
            ensure!(contains(bounds(parent)?, b), "node escaped parent bounds");
        }
        for field in ["text", "content-desc"] {
            let label = node.attribute(field).context("label field absent")?;
            ensure!(
                label.is_empty() || (native(*node) && LABELS.contains(&label)),
                "unredacted/non-native label refused"
            );
        }
    }
    ensure!(native(nodes[0]), "own native active root required");
    drop(nodes);
    Ok(doc)
}

fn plan_profile(
    xml: &str,
    current_focus: &str,
    owner: u32,
    compose_view: bool,
) -> Result<SetupPlan> {
    focus(current_focus, owner)?;
    let doc = parse_ui(xml, compose_view)?;
    let nodes: Vec<_> = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("hierarchy"))
        .context("hierarchy absent")?
        .descendants()
        .skip(1)
        .filter(Node::is_element)
        .collect();
    let unique = |label: &str| -> Result<Node<'_, '_>> {
        let matches: Vec<_> = nodes.iter().copied().filter(|n| has(*n, label)).collect();
        ensure!(matches.len() == 1, "unique fixed onboarding label absent");
        let n = matches[0];
        ensure!(
            native(n)
                && n.attribute("enabled") == Some("true")
                && n.attribute("visibility") != Some("false")
                && matches!(
                    n.attribute("class"),
                    Some("android.view.View" | "android.widget.TextView" | "android.widget.Button")
                )
                && n.children().filter(Node::is_element).count() == 0,
            "onboarding label role refused"
        );
        Ok(n)
    };
    let title = unique(TITLE)?;
    let body = unique(BODY)?;
    let label = unique(BUTTON)?;
    ensure!(
        title.attribute("clickable") == Some("false")
            && body.attribute("clickable") == Some("false"),
        "intro text unexpectedly interactive"
    );
    for signal in [
        "Searching for nearby devices",
        "Check your phone to continue setup",
        "You need to turn on Wi-Fi",
        "Turn on App Cast in Cross-device services on your Phone to access apps from your phone on this device.",
        "Scan the QR code using your phone to start setup",
    ] {
        ensure!(
            !nodes.iter().any(|n| has(*n, signal)),
            "conflicting setup state observed"
        );
    }
    let clicks: Vec<_> = label
        .ancestors()
        .filter(|n| n.has_tag_name("node") && n.attribute("clickable") == Some("true"))
        .collect();
    ensure!(
        clicks.len() == 1,
        "unique onboarding button hit target absent"
    );
    let click = clicks[0];
    ensure!(
        native(click)
            && click.attribute("enabled") == Some("true")
            && click.attribute("visibility") != Some("false")
            && matches!(
                click.attribute("class"),
                Some("android.view.View" | "android.widget.Button")
            ),
        "button role refused"
    );
    for n in title
        .ancestors()
        .chain(body.ancestors())
        .chain(label.ancestors())
        .filter(|n| n.has_tag_name("node"))
    {
        ensure!(
            n.attribute("enabled") == Some("true") && n.attribute("visibility") != Some("false"),
            "onboarding ancestor unavailable"
        );
    }
    let label_bounds = bounds(label)?;
    let click_bounds = bounds(click)?;
    ensure!(contains(click_bounds, label_bounds), "label outside button");
    let (x, y) = label_bounds.center();
    ensure!(hits(click_bounds, x, y), "button center not contained");
    for n in &nodes {
        if *n == click {
            continue;
        }
        if hits(bounds(*n)?, x, y)
            && (n.attribute("clickable") == Some("true")
                || n.attribute("package_scope") == Some("foreign")
                || n.attribute("class") == Some("android.webkit.WebView"))
        {
            anyhow::bail!("button point has competing hit target");
        }
    }
    let visibility_verified = title
        .ancestors()
        .chain(body.ancestors())
        .chain(label.ancestors())
        .filter(|n| n.has_tag_name("node"))
        .all(|n| n.attribute("visibility") == Some("true"));
    Ok(SetupPlan {
        profile: if compose_view {
            "phone-link-local-onboarding-compose-v2"
        } else {
            "phone-link-local-onboarding-v1"
        },
        expected_target_apk_sha256: TARGET_APK_SHA256,
        x,
        y,
        label_bounds,
        click_bounds,
        label_path: path(label)?,
        click_path: path(click)?,
        visibility_verified,
        active_hierarchy_coverage_checked: true,
        global_window_coverage_verified: false,
        external_identity_verification_required: true,
        source_callback_local_setup_state_only: true,
        input_authorized: false,
        mutation_performed: false,
        registration_verified: false,
        qr_setup_completed: false,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "phone_link_setup/compose_tests.rs"]
mod compose_tests;

#[derive(Debug, Serialize)]
pub struct QrStateObservation {
    pub profile: &'static str,
    pub expected_target_apk_sha256: &'static str,
    pub native_qr_view_observed: bool,
    pub instruction_nodes: u32,
    pub image_bounds: Bounds,
    pub instruction_bounds: Bounds,
    pub shared_scroll_view_path: Vec<usize>,
    pub visibility_verified: bool,
    pub qr_image_pixels_verified: bool,
    pub qr_content_read: bool,
    pub qr_decoding_verified: bool,
    pub registration_verified: bool,
    pub functional_phone_link_verified: bool,
    pub external_identity_verification_required: bool,
    pub input_authorized: bool,
    pub mutation_performed: bool,
}
/// Recognize only the pinned native QR view's two distinct instruction roles.
/// No pixels, QR contents, registration, phone operation or input are verified.
pub fn inspect_qr_state_qualified(
    xml: &str,
    current_focus: &str,
    owner: u32,
) -> Result<QrStateObservation> {
    focus(current_focus, owner)?;
    let doc = parse_ui(xml, true)?;
    let nodes: Vec<_> = doc
        .descendants()
        .filter(|n| n.has_tag_name("node"))
        .collect();
    const QR: &str = "Scan the QR code using your phone to start setup";
    let matches: Vec<_> = nodes.iter().copied().filter(|n| has(*n, QR)).collect();
    ensure!(matches.len() == 2, "exact QR instruction pair absent");
    let image = matches
        .iter()
        .copied()
        .find(|n| {
            n.attribute("class") == Some("android.widget.ImageView")
                && n.attribute("content-desc") == Some(QR)
                && n.attribute("text") == Some("")
        })
        .context("native QR image description absent")?;
    let caption = matches
        .iter()
        .copied()
        .find(|n| {
            n.attribute("class") == Some("android.widget.TextView")
                && n.attribute("text") == Some(QR)
                && n.attribute("content-desc") == Some("")
        })
        .context("native QR instruction text absent")?;
    ensure!(image != caption, "distinct QR instruction roles required");
    for n in [image, caption] {
        ensure!(
            native(n)
                && n.attribute("clickable") == Some("false")
                && n.children().filter(Node::is_element).count() == 0,
            "QR node role refused"
        );
        for parent in n.ancestors().filter(|p| p.has_tag_name("node")) {
            ensure!(
                parent.attribute("enabled") == Some("true")
                    && parent.attribute("visibility") != Some("false"),
                "QR ancestor unavailable"
            );
        }
    }
    let a = image
        .ancestors()
        .skip(1)
        .find(|p| p.attribute("class") == Some("android.widget.ScrollView"))
        .context("QR image native scroll container absent")?;
    let b = caption
        .ancestors()
        .skip(1)
        .find(|p| p.attribute("class") == Some("android.widget.ScrollView"));
    ensure!(
        Some(a) == b && native(a),
        "QR roles have different scroll containers"
    );
    ensure!(
        !nodes
            .iter()
            .any(|n| has(*n, TITLE) || has(*n, BODY) || has(*n, BUTTON)),
        "stale intro and QR state mixed"
    );
    let image_bounds = bounds(image)?;
    let instruction_bounds = bounds(caption)?;
    ensure!(
        image_bounds.right - image_bounds.left == image_bounds.bottom - image_bounds.top
            && instruction_bounds.top >= image_bounds.bottom,
        "QR image/caption geometry refused"
    );
    let visibility_verified = image
        .ancestors()
        .chain(caption.ancestors())
        .filter(|n| n.has_tag_name("node"))
        .all(|n| n.attribute("visibility") == Some("true"));
    Ok(QrStateObservation {
        profile: "phone-link-native-qr-instruction-pair-v1",
        expected_target_apk_sha256: TARGET_APK_SHA256,
        native_qr_view_observed: true,
        instruction_nodes: 2,
        image_bounds,
        instruction_bounds,
        shared_scroll_view_path: path(a)?,
        visibility_verified,
        qr_image_pixels_verified: false,
        qr_content_read: false,
        qr_decoding_verified: false,
        registration_verified: false,
        functional_phone_link_verified: false,
        external_identity_verification_required: true,
        input_authorized: false,
        mutation_performed: false,
    })
}

#[cfg(test)]
#[path = "phone_link_setup/qr_tests.rs"]
mod qr_tests;
