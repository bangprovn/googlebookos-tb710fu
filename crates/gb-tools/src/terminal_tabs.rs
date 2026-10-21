//! Read-only structural guard for the pinned donor Terminal's native tab bar.
//!
//! Generic Compose Views carry the labels, while an inert Button sibling marks
//! each IconButton. Guest output or a native title named "Add tab" is insufficient.
//! This observed LTR profile counts local visible tabs, never global sessions or
//! semantic tab IDs. Callers must independently bind APK, owner, native lifetime,
//! fresh focus and a single controlled action; this module issues no device input.
use crate::terminal_ui::{Bounds, PACKAGE};
use anyhow::{Context, Result, ensure};
use roxmltree::Node;
use serde::Serialize;

const VIEW: &str = "android.view.View";
const BUTTON: &str = "android.widget.Button";
const TEXT: &str = "android.widget.TextView";
const WEB: &str = "android.webkit.WebView";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeControl {
    pub label_bounds: Bounds,
    pub click_bounds: Bounds,
    pub label_path: Vec<usize>,
    pub click_path: Vec<usize>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeTab {
    pub ordinal: usize,
    pub bounds: Bounds,
    pub path: Vec<usize>,
    pub title_bounds: Bounds,
    pub selected: bool,
    pub close_control: Option<NativeControl>,
}
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub profile: &'static str,
    pub local_tab_count: usize,
    pub selected_index: usize,
    pub tabs: Vec<NativeTab>,
    pub add_tab: NativeControl,
    pub display_control: Bounds,
    pub strip_bounds: Bounds,
    pub local_count_is_global_count: bool,
    pub semantic_tab_identity_verified: bool,
}
#[derive(Debug, Serialize)]
pub struct ModeSnapshot {
    pub profile: &'static str,
    pub display_enabled: bool,
    pub local_tab_count: usize,
    pub selected_index: Option<usize>,
    pub tabs: Vec<NativeTab>,
    pub add_tab: NativeControl,
    pub display_control: Bounds,
    pub strip_bounds: Bounds,
    pub local_count_is_global_count: bool,
    pub semantic_tab_identity_verified: bool,
}
#[derive(Debug, Serialize)]
pub struct ExistingTabSelection {
    pub ordinal: usize,
    pub x: u32,
    pub y: u32,
    pub semantic_tab_identity_verified: bool,
    pub input_authorized: bool,
}
#[derive(Debug, Serialize)]
pub struct AppendObservation {
    pub appended_ordinal: usize,
    pub original_tab_retained_structurally: bool,
    pub semantic_tab_identity_verified: bool,
    pub fresh_guest_prompt_verified: bool,
    pub native_lifetime_must_be_verified_externally: bool,
    pub mutation_performed: bool,
}
#[derive(Debug, Serialize)]
pub struct SelectedAppendObservation {
    pub before_local_tab_count: usize,
    pub after_local_tab_count: usize,
    pub appended_ordinal: usize,
    pub prior_tabs_retained_structurally: bool,
    pub semantic_tab_identity_verified: bool,
    pub fresh_guest_prompt_verified: bool,
    pub native_lifetime_must_be_verified_externally: bool,
    pub mutation_performed: bool,
}

fn own(n: Node<'_, '_>) -> bool {
    n.has_tag_name("node") && n.attribute("package") == Some(PACKAGE)
}
fn native(n: Node<'_, '_>) -> bool {
    own(n)
        && n.ancestors()
            .filter(|p| p.has_tag_name("node"))
            .all(|p| own(p) && p.attribute("class") != Some(WEB))
}
fn children<'a, 'input>(n: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    n.children().filter(Node::is_element).collect()
}
fn b(n: Node<'_, '_>) -> Result<Bounds> {
    Bounds::parse(n.attribute("bounds").context("native bounds absent")?)
}
// This observed, inert accessibility leaf is not a native control or a hit
// target. Keep the exception here rather than relaxing Bounds or b().
fn passive_zero_web_text(n: Node<'_, '_>) -> bool {
    own(n)
        && n.attribute("class") == Some(TEXT)
        && n.attribute("bounds") == Some("[0,0][0,0]")
        && n.attribute("enabled") == Some("true")
        && ["clickable", "focusable", "focused", "password", "selected"]
            .iter()
            .all(|key| n.attribute(*key) == Some("false"))
        && n.attribute("content-desc").is_none()
        && children(n).is_empty()
        && n.ancestors().filter(|p| p.has_tag_name("node")).all(own)
        && n.ancestors()
            .skip(1)
            .any(|p| own(p) && p.attribute("class") == Some(WEB))
}
// xterm accessibility exposes clipped rows as focusable zero-height Views at
// their containing View's bottom edge. They are neither native controls nor
// TTY editors, and never supply a hit target. Keep native geometry strict.
fn clipped_web_row(n: Node<'_, '_>) -> bool {
    if !(own(n)
        && n.attribute("class") == Some(VIEW)
        && n.attribute("enabled") == Some("true")
        && n.attribute("focusable") == Some("true")
        && ["clickable", "focused", "password", "selected"]
            .iter()
            .all(|key| n.attribute(*key) == Some("false"))
        && n.attribute("content-desc").is_none()
        && children(n).is_empty()
        && n.ancestors().filter(|p| p.has_tag_name("node")).all(own)
        && n.ancestors()
            .skip(1)
            .any(|p| own(p) && p.attribute("class") == Some(WEB)))
    {
        return false;
    }
    let Some(parent) = n
        .parent_element()
        .filter(|p| own(*p) && p.attribute("class") == Some(VIEW))
    else {
        return false;
    };
    let Ok(parent_bounds) = b(parent) else {
        return false;
    };
    n.attribute("bounds")
        == Some(
            format!(
                "[{},{}][{},{}]",
                parent_bounds.left, parent_bounds.bottom, parent_bounds.right, parent_bounds.bottom
            )
            .as_str(),
        )
}
// A clipped xterm caret and its one-child View wrapper can share a zero-height
// rectangle at the owning WebView bottom. This metadata is irrelevant to native
// header controls: accept only that pair in the envelope, never as a hit target.
// terminal_ui independently keeps clipped cursors in Refresh/reobserve state.
fn clipped_web_cursor_pair(n: Node<'_, '_>) -> bool {
    let (wrapper, cursor) = match n.attribute("class") {
        Some(VIEW) => {
            let kids = children(n);
            if kids.len() != 1 {
                return false;
            }
            (n, kids[0])
        }
        Some("android.widget.EditText") => {
            let Some(parent) = n.parent_element() else {
                return false;
            };
            (parent, n)
        }
        _ => return false,
    };
    let inert = |node: Node<'_, '_>| {
        own(node)
            && node.attribute("enabled") == Some("true")
            && ["clickable", "focusable", "focused", "password", "selected"]
                .iter()
                .all(|key| node.attribute(*key) == Some("false"))
    };
    if !(wrapper.attribute("class") == Some(VIEW)
        && inert(wrapper)
        && wrapper.attribute("content-desc").is_none()
        && children(wrapper) == [cursor]
        && own(cursor)
        && cursor.attribute("class") == Some("android.widget.EditText")
        && cursor.attribute("content-desc") == Some("Cursor")
        && cursor.attribute("enabled") == Some("true")
        && ["clickable", "focusable", "focused"]
            .iter()
            .all(|key| cursor.attribute(*key) == Some("true"))
        && ["password", "selected"]
            .iter()
            .all(|key| cursor.attribute(*key) == Some("false"))
        && children(cursor).is_empty()
        && cursor
            .ancestors()
            .filter(|p| p.has_tag_name("node"))
            .all(own))
    {
        return false;
    }
    let Some(web) = wrapper
        .ancestors()
        .skip(1)
        .find(|p| own(*p) && p.attribute("class") == Some(WEB))
    else {
        return false;
    };
    let Ok(web_bounds) = b(web) else {
        return false;
    };
    let Some(raw) = cursor.attribute("bounds") else {
        return false;
    };
    if wrapper.attribute("bounds") != Some(raw) {
        return false;
    }
    let Some((left, rest)) = raw.strip_prefix('[').and_then(|v| v.split_once(',')) else {
        return false;
    };
    let Some((_, right)) = rest.split_once("][") else {
        return false;
    };
    let Some((right, _)) = right.split_once(',') else {
        return false;
    };
    let (Ok(left), Ok(right)) = (left.parse::<u32>(), right.parse::<u32>()) else {
        return false;
    };
    left < right
        && web_bounds.left <= left
        && right <= web_bounds.right
        && raw
            == format!(
                "[{},{}][{},{}]",
                left, web_bounds.bottom, right, web_bounds.bottom
            )
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
                .context("native path absent")?,
        );
        if parent.has_tag_name("hierarchy") {
            result.reverse();
            return Ok(result);
        }
        ensure!(result.len() <= 512, "native path exceeds bound");
        current = parent;
    }
    anyhow::bail!("native path outside hierarchy")
}
fn flags(n: Node<'_, '_>, clickable: bool, focusable: bool, selected: bool) -> bool {
    let bit = |v| if v { "true" } else { "false" };
    native(n)
        && n.attribute("enabled") == Some("true")
        && n.attribute("password") == Some("false")
        && n.attribute("clickable") == Some(bit(clickable))
        && n.attribute("focusable") == Some(bit(focusable))
        && n.attribute("selected") == Some(bit(selected))
}
fn contains(outer: Bounds, inner: Bounds) -> bool {
    outer.left <= inner.left
        && outer.top <= inner.top
        && outer.right >= inner.right
        && outer.bottom >= inner.bottom
}
fn center_inside(outer: Bounds, inner: Bounds) -> bool {
    let (x, y) = inner.center();
    outer.left <= x && x < outer.right && outer.top <= y && y < outer.bottom
}
fn icon_control(label: Node<'_, '_>) -> Result<NativeControl> {
    ensure!(
        label.attribute("class") == Some(VIEW)
            && flags(label, false, false, false)
            && children(label).is_empty(),
        "native icon label shape changed"
    );
    let parent = label
        .parent_element()
        .context("native icon parent absent")?;
    ensure!(
        parent.attribute("class") == Some(VIEW)
            && flags(parent, true, true, false)
            && parent.attribute("content-desc").is_none(),
        "native icon click parent changed"
    );
    let kids = children(parent);
    ensure!(
        kids.len() == 2 && kids[0] == label,
        "native icon children changed"
    );
    let marker = kids[1];
    ensure!(
        marker.attribute("class") == Some(BUTTON)
            && flags(marker, false, false, false)
            && marker.attribute("content-desc").is_none()
            && children(marker).is_empty(),
        "native inert Button role marker absent"
    );
    let label_bounds = b(label)?;
    let click_bounds = b(parent)?;
    ensure!(
        contains(click_bounds, label_bounds),
        "native icon outside click target"
    );
    Ok(NativeControl {
        label_bounds,
        click_bounds,
        label_path: path(label)?,
        click_path: path(parent)?,
    })
}
fn validate_envelope(doc: &roxmltree::Document<'_>) -> Result<()> {
    let root = doc.root_element();
    let parts = children(root);
    ensure!(
        root.has_tag_name("gb-ui")
            && root.attributes().len() == 0
            && parts.len() == 2
            && parts[0].has_tag_name("hierarchy")
            && parts[0].attributes().len() == 0
            && parts[1].has_tag_name("gb-meta")
            && parts[1].attributes().len() == 2
            && parts[1].attribute("complete") == Some("true")
            && children(parts[1]).is_empty(),
        "complete reduced inventory required"
    );
    let expected: usize = parts[1]
        .attribute("node_count")
        .context("inventory count absent")?
        .parse()?;
    let mut count = 0;
    for n in parts[0].descendants().filter(Node::is_element).skip(1) {
        count += 1;
        ensure!(
            n.has_tag_name("node") && n.ancestors().count() <= 514,
            "unexpected inventory node or depth"
        );
        for key in [
            "class",
            "package",
            "bounds",
            "enabled",
            "clickable",
            "focusable",
            "focused",
            "password",
            "selected",
        ] {
            ensure!(
                n.attribute(key).is_some(),
                "incomplete reduced native metadata"
            );
        }
        for a in n.attributes() {
            match a.name() {
                "package" => ensure!(
                    matches!(a.value(), PACKAGE | "redacted.foreign"),
                    "unreduced package"
                ),
                "class" => ensure!(
                    matches!(
                        a.value(),
                        VIEW | BUTTON
                            | TEXT
                            | WEB
                            | "android.widget.ImageButton"
                            | "android.widget.ImageView"
                            | "android.widget.EditText"
                            | "android.app.ActionBar$Tab"
                    ),
                    "unreduced class"
                ),
                "enabled" | "clickable" | "focusable" | "focused" | "password" | "selected" => {
                    ensure!(matches!(a.value(), "true" | "false"), "unreduced boolean")
                }
                "bounds" => {
                    if !passive_zero_web_text(n)
                        && !clipped_web_row(n)
                        && !clipped_web_cursor_pair(n)
                    {
                        b(n)?;
                    }
                }
                "content-desc" => ensure!(
                    matches!(
                        a.value(),
                        "Add tab"
                            | "Close tab"
                            | "Display options"
                            | "Close display controls"
                            | "Cursor"
                    ),
                    "unreduced description"
                ),
                _ => anyhow::bail!("unreduced inventory attribute"),
            }
        }
    }
    ensure!(
        count == expected && count <= 50000,
        "inventory count mismatch"
    );
    ensure!(
        doc.descendants()
            .filter(Node::is_text)
            .all(|n| n.text().unwrap_or("").trim().is_empty()),
        "unreduced inventory text"
    );
    Ok(())
}

/// Qualifies the observed native LTR IconButton/tab-strip topology only.
/// Absence or a different accessibility structure is a refusal, never a tap guess.
fn inspect_mode(xml: &str, allow_desktop: bool) -> Result<ModeSnapshot> {
    ensure!(xml.len() <= 2 * 1024 * 1024, "inventory XML exceeds budget");
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 50000,
            ..Default::default()
        },
    )
    .context("invalid inventory XML")?;
    validate_envelope(&doc)?;
    let displays: Vec<_> = doc
        .descendants()
        .filter(|n| {
            native(*n)
                && matches!(
                    n.attribute("content-desc"),
                    Some("Display options" | "Close display controls")
                )
        })
        .collect();
    ensure!(
        displays.len() == 1,
        "unique native display mode control absent"
    );
    let display_enabled = displays[0].attribute("content-desc") == Some("Close display controls");
    ensure!(
        allow_desktop || !display_enabled,
        "legacy tab guard requires TTY mode"
    );
    if display_enabled {
        ensure!(
            !doc.descendants()
                .any(|n| own(n) && n.attribute("class") == Some(WEB)),
            "desktop topology still exposes TTY WebView"
        );
    }

    let adds: Vec<_> = doc
        .descendants()
        .filter(|n| native(*n) && n.attribute("content-desc") == Some("Add tab"))
        .collect();
    ensure!(adds.len() == 1, "unique native Add tab absent");
    let add_label = adds[0];
    let add_tab = icon_control(add_label)?;
    let add_parent = add_label.parent_element().context("Add parent absent")?;
    ensure!(
        !add_parent
            .ancestors()
            .any(|n| n.attribute("selected") == Some("true")),
        "Add tab is inside a selected subtree"
    );
    let bar = add_parent.parent_element().context("tab bar absent")?;
    ensure!(
        bar.attribute("class") == Some(VIEW)
            && flags(bar, false, false, false)
            && bar.attribute("content-desc").is_none(),
        "tab bar shape changed"
    );
    let bar_children = children(bar);
    ensure!(
        bar_children.len() == 2 && bar_children[1] == add_parent,
        "Add tab must be distinct strip sibling"
    );
    let strip = bar_children[0];
    ensure!(
        strip.attribute("class") == Some(VIEW)
            && flags(strip, false, false, false)
            && strip.attribute("content-desc").is_none(),
        "native strip shape changed"
    );
    let strip_bounds = b(strip)?;
    ensure!(
        strip_bounds.right == add_tab.click_bounds.left
            && strip_bounds.top == add_tab.click_bounds.top
            // Adjacent Compose touch targets in the observed donor layout can
            // differ by one physical pixel at their bottom edge. Keep exact
            // horizontal adjacency and top alignment; larger drift is refused.
            && strip_bounds.bottom.abs_diff(add_tab.click_bounds.bottom) <= 1,
        "observed LTR strip geometry changed"
    );
    let mut tabs = Vec::new();
    for n in children(strip) {
        if n.attribute("focusable") != Some("true") {
            ensure!(
                n.attribute("class") == Some(VIEW)
                    && flags(n, false, false, false)
                    && n.attribute("content-desc").is_none()
                    && children(n).is_empty(),
                "unexpected strip decoration"
            );
            continue;
        }
        let selected = n.attribute("selected") == Some("true");
        ensure!(
            matches!(
                n.attribute("class"),
                Some(VIEW | "android.app.ActionBar$Tab")
            ) && flags(n, !selected, true, selected)
                && n.attribute("content-desc").is_none(),
            "native tab shape changed"
        );
        let kids = children(n);
        let titles: Vec<_> = kids
            .iter()
            .filter(|p| p.attribute("class") == Some(TEXT))
            .collect();
        ensure!(
            titles.len() == 1
                && flags(*titles[0], false, false, false)
                && titles[0].attribute("content-desc").is_none()
                && children(*titles[0]).is_empty(),
            "native tab title shape changed"
        );
        let tab_bounds = b(n)?;
        let title_bounds = b(*titles[0])?;
        ensure!(
            contains(tab_bounds, title_bounds),
            "tab title body outside tab"
        );
        ensure!(
            contains(strip_bounds, tab_bounds),
            "native tab outside strip"
        );
        let closes: Vec<_> = n
            .descendants()
            .filter(|p| p.attribute("content-desc") == Some("Close tab"))
            .collect();
        ensure!(
            closes.len() <= 1 && (!selected || closes.len() == 1),
            "selected tab close control absent or duplicated"
        );
        let close_control = closes
            .first()
            .map(|p| -> Result<_> {
                ensure!(
                    p.parent_element().and_then(|p| p.parent_element()) == Some(n),
                    "close control outside direct tab body"
                );
                let control = icon_control(*p)?;
                ensure!(
                    center_inside(tab_bounds, control.label_bounds),
                    "close icon center outside tab"
                );
                Ok(control)
            })
            .transpose()?;
        for kid in &kids {
            if kid.attribute("class") == Some(TEXT)
                || closes
                    .first()
                    .is_some_and(|p| p.parent_element() == Some(*kid))
            {
                continue;
            }
            ensure!(
                kid.attribute("class") == Some(VIEW)
                    && flags(*kid, false, false, false)
                    && kid.attribute("content-desc").is_none()
                    && children(*kid).is_empty(),
                "unexpected native tab child"
            );
        }
        tabs.push(NativeTab {
            ordinal: tabs.len(),
            bounds: tab_bounds,
            path: path(n)?,
            title_bounds,
            selected,
            close_control,
        });
        ensure!(tabs.len() <= 8, "native tab count exceeds qualified budget");
    }
    ensure!(!tabs.is_empty(), "native local tabs absent");
    ensure!(
        tabs.windows(2)
            .all(|w| w[0].bounds.right <= w[1].bounds.left),
        "native tab order overlaps or reverses"
    );
    let selected: Vec<_> = tabs.iter().filter(|t| t.selected).collect();
    let global_selected = doc
        .descendants()
        .filter(|n| native(*n) && n.attribute("selected") == Some("true"))
        .count();
    if display_enabled {
        ensure!(
            selected.is_empty() && global_selected == 0,
            "desktop must deselect all TTY tabs"
        );
    } else {
        ensure!(
            selected.len() == 1 && global_selected == 1,
            "TTY selected tab is ambiguous"
        );
    }
    let selected_index = selected.first().map(|t| t.ordinal);
    let display_control = b(displays[0])?;
    ensure!(
        !displays[0].ancestors().any(|n| n == bar)
            && display_control.left > add_tab.click_bounds.right
            && display_control.top >= strip_bounds.top
            && display_control.bottom <= strip_bounds.bottom,
        "native toolbar relation changed"
    );
    Ok(ModeSnapshot {
        profile: "donor-8bbe-generic-compose-ltr-v2",
        display_enabled,
        local_tab_count: tabs.len(),
        selected_index,
        tabs,
        add_tab,
        display_control,
        strip_bounds,
        local_count_is_global_count: false,
        semantic_tab_identity_verified: false,
    })
}

/// Original TTY-only API: desktop/zero-selected observations remain refused.
pub fn inspect(xml: &str) -> Result<Snapshot> {
    let mode = inspect_mode(xml, false)?;
    Ok(Snapshot {
        profile: "donor-8bbe-generic-compose-ltr-v1",
        local_tab_count: mode.local_tab_count,
        selected_index: mode.selected_index.context("TTY selected tab absent")?,
        tabs: mode.tabs,
        add_tab: mode.add_tab,
        display_control: mode.display_control,
        strip_bounds: mode.strip_bounds,
        local_count_is_global_count: false,
        semantic_tab_identity_verified: false,
    })
}

/// Desktop intentionally supplies a null selected ID to TabBar, while preserving
/// MainViewModel._selectedTabId. Only its exact mode label + no WebView + zero
/// selected topology permits a null index. TTY still requires a unique selection.
pub fn inspect_mode_aware(xml: &str) -> Result<ModeSnapshot> {
    inspect_mode(xml, true)
}

/// Rebind the completed one-to-two append receipt across a display-mode change.
/// This remains structural evidence, requiring prior single-action/native-lifetime
/// observations externally. It does not prove semantic IDs or a clean shell.
pub fn verify_retained_append(
    before: &Snapshot,
    after: &ModeSnapshot,
) -> Result<AppendObservation> {
    ensure!(
        before.local_tab_count == 1
            && before.selected_index == 0
            && before.tabs.len() == 1
            && after.local_tab_count == 2
            && after.tabs.len() == 2,
        "two retained local tabs required"
    );
    ensure!(
        if after.display_enabled {
            after.selected_index.is_none()
        } else {
            after.selected_index == Some(1)
        },
        "owned last tab is not selected in TTY mode"
    );
    ensure!(
        before.display_control == after.display_control
            && before.strip_bounds.left == after.strip_bounds.left
            && before.strip_bounds.top == after.strip_bounds.top
            && before.strip_bounds.bottom == after.strip_bounds.bottom
            && before.tabs.first().context("prior tab absent")?.bounds.left
                == after
                    .tabs
                    .first()
                    .context("retained tab absent")?
                    .bounds
                    .left,
        "retained native window geometry changed"
    );
    Ok(AppendObservation {
        appended_ordinal: 1,
        original_tab_retained_structurally: true,
        semantic_tab_identity_verified: false,
        fresh_guest_prompt_verified: false,
        native_lifetime_must_be_verified_externally: true,
        mutation_performed: false,
    })
}

/// A native title-body center safely excludes both tabs' Close IconButtons.
/// The source-backed Tab onClick calls selectTab(id), setting DisplayState.Hidden.
/// No action is issued here and no Add/keyboard/close target is returned.
pub fn select_retained_last(
    before: &Snapshot,
    after: &ModeSnapshot,
) -> Result<ExistingTabSelection> {
    verify_retained_append(before, after)?;
    ensure!(
        after.display_enabled && after.selected_index.is_none(),
        "desktop return required"
    );
    let last = after.tabs.last().context("owned last tab absent")?;
    let (x, y) = last.title_bounds.center();
    ensure!(
        center_inside(last.bounds, last.title_bounds)
            && after
                .tabs
                .iter()
                .all(|tab| tab.close_control.as_ref().is_none_or(|c| {
                    !(c.click_bounds.left <= x
                        && x < c.click_bounds.right
                        && c.click_bounds.top <= y
                        && y < c.click_bounds.bottom)
                })),
        "tab body target overlaps close control"
    );
    Ok(ExistingTabSelection {
        ordinal: 1,
        x,
        y,
        semantic_tab_identity_verified: false,
        input_authorized: false,
    })
}

/// Confirms only the structural one-to-two append observed around one controlled
/// Add action. It cannot establish semantic tab identity, VM continuity or shell
/// readiness; those are separate mandatory runtime observations.
pub fn verify_append_transition(before: &Snapshot, after: &Snapshot) -> Result<AppendObservation> {
    ensure!(
        before.local_tab_count == 1
            && before.selected_index == 0
            && after.local_tab_count == 2
            && after.selected_index == 1,
        "one-to-two selected append not observed"
    );
    ensure!(
        before.tabs.len() == 1 && after.tabs.len() == 2,
        "inconsistent tab vector"
    );
    let before_first = before.tabs.first().context("prior tab absent")?;
    let after_first = after.tabs.first().context("retained tab absent")?;
    ensure!(
        before.display_control == after.display_control
            && before.strip_bounds.left == after.strip_bounds.left
            && before.strip_bounds.top == after.strip_bounds.top
            && before.strip_bounds.bottom == after.strip_bounds.bottom
            && before_first.bounds.left == after_first.bounds.left,
        "native toolbar/window changed during append"
    );
    Ok(AppendObservation {
        appended_ordinal: 1,
        original_tab_retained_structurally: true,
        semantic_tab_identity_verified: false,
        fresh_guest_prompt_verified: false,
        native_lifetime_must_be_verified_externally: true,
        mutation_performed: false,
    })
}

/// Explicitly selected TTY-only n-to-n+1 append policy. Both snapshots must be
/// independently inspected. Exact prior body bounds and paths are required;
/// changing selection may remove a Close control or change title layout, so
/// those are not semantic identity evidence. No input or shell readiness follows
/// from this structural observation. The older one-to-two policies are unchanged.
pub fn verify_selected_append(
    before: &Snapshot,
    after: &Snapshot,
) -> Result<SelectedAppendObservation> {
    let n = before.local_tab_count;
    ensure!(
        (1..=7).contains(&n)
            && before.tabs.len() == n
            && after.local_tab_count == n + 1
            && after.tabs.len() == n + 1,
        "bounded n-to-n+1 append not observed"
    );
    ensure!(
        before.selected_index == n - 1
            && after.selected_index == n
            && before
                .tabs
                .iter()
                .enumerate()
                .all(|(i, t)| t.ordinal == i && t.selected == (i == n - 1))
            && after
                .tabs
                .iter()
                .enumerate()
                .all(|(i, t)| t.ordinal == i && t.selected == (i == n)),
        "prior and appended last tabs must be uniquely selected"
    );
    ensure!(
        before.display_control == after.display_control
            && before.strip_bounds.left == after.strip_bounds.left
            && before.strip_bounds.top == after.strip_bounds.top
            && before.strip_bounds.bottom == after.strip_bounds.bottom
            && before.tabs.iter().zip(&after.tabs).all(|(old, retained)| {
                old.bounds == retained.bounds && old.path == retained.path
            }),
        "prior native tab geometry or paths changed"
    );
    let prior_last = &after.tabs[n - 1];
    let appended = &after.tabs[n];
    ensure!(
        prior_last.bounds.right <= appended.bounds.left
            && after.tabs[..n].iter().all(|t| t.path != appended.path),
        "appended tab overlaps or reuses a prior path"
    );
    Ok(SelectedAppendObservation {
        before_local_tab_count: n,
        after_local_tab_count: n + 1,
        appended_ordinal: n,
        prior_tabs_retained_structurally: true,
        semantic_tab_identity_verified: false,
        fresh_guest_prompt_verified: false,
        native_lifetime_must_be_verified_externally: true,
        mutation_performed: false,
    })
}

#[derive(PartialEq, Eq)]
struct SelectionDecorationLayout {
    strip_path: Vec<usize>,
    leading: [i64; 4],
    trailing: [i64; 4],
}

fn selected_decoration_layout(xml: &str, snapshot: &Snapshot) -> Result<SelectionDecorationLayout> {
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 50000,
            ..Default::default()
        },
    )?;
    let add = doc
        .descendants()
        .find(|n| native(*n) && n.attribute("content-desc") == Some("Add tab"))
        .context("native Add label absent")?;
    ensure!(
        path(add)? == snapshot.add_tab.label_path,
        "Add path changed during decoration qualification"
    );
    let bar = add
        .parent_element()
        .and_then(|p| p.parent_element())
        .context("tab bar absent")?;
    let strip = children(bar)
        .into_iter()
        .next()
        .context("tab strip absent")?;
    let strip_path = path(strip)?;
    let n = snapshot.local_tab_count;
    ensure!(
        (1..=8).contains(&n) && snapshot.selected_index == n - 1,
        "decorated policy requires selected last tab"
    );
    let kids = children(strip);
    ensure!(
        kids.len() == n + 2,
        "exactly two selection decorations required"
    );
    for (ordinal, tab) in snapshot.tabs.iter().enumerate() {
        let raw_index = if ordinal == n - 1 { n } else { ordinal };
        ensure!(
            path(kids[raw_index])? == tab.path
                && tab
                    .path
                    .split_last()
                    .is_some_and(|(_, parent)| parent == strip_path.as_slice()),
            "decoration topology or strip ancestor changed"
        );
    }
    let decoration = |node: Node<'_, '_>| -> Result<Bounds> {
        ensure!(
            node.attribute("class") == Some(VIEW)
                && flags(node, false, false, false)
                && node.attribute("focused") == Some("false")
                && node.attribute("content-desc").is_none()
                && children(node).is_empty(),
            "selection decoration is not an inert native View"
        );
        b(node)
    };
    let leading = decoration(kids[n - 1])?;
    let trailing = decoration(kids[n + 1])?;
    let selected = snapshot.tabs.last().context("selected tab absent")?.bounds;
    ensure!(
        leading.right == selected.left
            && trailing.left < selected.right
            && trailing.right >= selected.right
            && [leading, trailing]
                .iter()
                .all(|d| d.top >= selected.top && d.bottom <= selected.bottom),
        "selection decorations do not bracket selected body edges"
    );
    let relative = |bounds: Bounds, origin_x: u32| {
        [
            i64::from(bounds.left) - i64::from(origin_x),
            i64::from(bounds.top) - i64::from(selected.top),
            i64::from(bounds.right) - i64::from(origin_x),
            i64::from(bounds.bottom) - i64::from(selected.top),
        ]
    };
    Ok(SelectionDecorationLayout {
        strip_path,
        leading: relative(leading, selected.left),
        trailing: relative(trailing, selected.right),
    })
}

/// Opt-in append policy for the observed pair of inert selection decorations.
/// Independently inspect both immutable XML inputs, require the same strip path
/// and decoration geometry relative to the selected LAST body, then normalize
/// only each local tab path's final child index to its ordinal. All retained
/// body geometry and remaining path components still use the strict policy.
/// This proves structural retention only, never semantic IDs or text readiness.
pub fn verify_selected_decorated_append(
    before_xml: &str,
    after_xml: &str,
) -> Result<SelectedAppendObservation> {
    let mut before = inspect(before_xml)?;
    let mut after = inspect(after_xml)?;
    ensure!(
        selected_decoration_layout(before_xml, &before)?
            == selected_decoration_layout(after_xml, &after)?,
        "selection decoration geometry or strip ancestor changed"
    );
    for snapshot in [&mut before, &mut after] {
        for tab in &mut snapshot.tabs {
            *tab.path.last_mut().context("tab path absent")? = tab.ordinal;
        }
    }
    verify_selected_append(&before, &after)
}

/// Return-only observation: the previous last TTY title is retained and visible
/// in the clipped desktop strip. Never authorizes keyboard input or tab closing.
#[derive(Debug, Serialize)]
pub struct ClippedDesktopRecovery {
    pub ordinal: usize,
    pub x: u32,
    pub y: u32,
    pub prior_tabs_retained_structurally: bool,
    pub semantic_tab_identity_verified: bool,
    pub input_authorized: bool,
    pub mutation_performed: bool,
    pub native_lifetime_must_be_verified_externally: bool,
}

fn inventory_node_at_path<'a, 'input>(
    doc: &'a roxmltree::Document<'input>,
    indices: &[usize],
) -> Result<Node<'a, 'input>> {
    let mut n = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("hierarchy"))
        .context("inventory hierarchy absent")?;
    for index in indices {
        n = *children(n)
            .get(*index)
            .context("retained native path absent")?;
    }
    Ok(n)
}

/// Explicit recovery for the observed missing-Add desktop strip. Previous TTY
/// inspection remains ordinary/strict; this separate current-layout validator
/// permits only clipping the last body's right edge while retaining its full
/// title. External callers still bind APK, native births, freshness and surfaces.
pub fn select_clipped_desktop_last(
    previous_tty_xml: &str,
    current_desktop_xml: &str,
) -> Result<ClippedDesktopRecovery> {
    let previous = inspect(previous_tty_xml)?;
    ensure!(
        previous.selected_index + 1 == previous.local_tab_count,
        "previous last TTY must be selected"
    );
    ensure!(
        current_desktop_xml.len() <= 2 * 1024 * 1024,
        "inventory XML exceeds budget"
    );
    let options = || roxmltree::ParsingOptions {
        nodes_limit: 50000,
        ..Default::default()
    };
    let old_doc = roxmltree::Document::parse_with_options(previous_tty_xml, options())?;
    let doc = roxmltree::Document::parse_with_options(current_desktop_xml, options())?;
    validate_envelope(&doc)?;
    ensure!(
        !doc.descendants()
            .any(|n| n.has_tag_name("node") && n.attribute("content-desc") == Some("Add tab")),
        "recovery requires missing Add label"
    );
    ensure!(
        !doc.descendants()
            .any(|n| own(n) && n.attribute("class") == Some(WEB)),
        "desktop still exposes TTY WebView"
    );
    ensure!(
        !doc.descendants()
            .any(|n| native(n) && n.attribute("selected") == Some("true")),
        "desktop selection is not empty"
    );
    let displays: Vec<_> = doc
        .descendants()
        .filter(|n| {
            n.has_tag_name("node")
                && matches!(
                    n.attribute("content-desc"),
                    Some("Close display controls" | "Display options")
                )
        })
        .collect();
    ensure!(
        displays.len() == 1
            && displays[0].attribute("content-desc") == Some("Close display controls")
            && displays[0].attribute("class") == Some(VIEW)
            && flags(displays[0], false, false, false)
            && displays[0].attribute("focused") == Some("false")
            && children(displays[0]).is_empty()
            && b(displays[0])? == previous.display_control,
        "unique retained desktop control absent"
    );
    let last = previous.tabs.last().context("previous last tab absent")?;
    let (_, strip_path) = last
        .path
        .split_last()
        .context("previous strip path absent")?;
    let strip = inventory_node_at_path(&doc, strip_path)?;
    let old_strip = inventory_node_at_path(&old_doc, strip_path)?;
    let strip_bounds = b(strip)?;
    ensure!(
        native(strip)
            && strip.attribute("class") == old_strip.attribute("class")
            && flags(strip, false, false, false)
            && strip.attribute("focused") == Some("false")
            && strip.attribute("content-desc").is_none()
            && strip_bounds.left == previous.strip_bounds.left
            && strip_bounds.top == previous.strip_bounds.top
            && strip_bounds.bottom == previous.strip_bounds.bottom
            && strip_bounds.right < previous.strip_bounds.right,
        "retained strip path or clipping geometry changed"
    );
    let bar = strip.parent_element().context("current tab bar absent")?;
    ensure!(
        bar.attribute("class") == Some(VIEW)
            && flags(bar, false, false, false)
            && bar.attribute("focused") == Some("false")
            && bar.attribute("content-desc").is_none()
            && children(bar) == [strip]
            && b(bar)? == strip_bounds,
        "missing-Add bar topology changed"
    );
    ensure!(
        !displays[0].ancestors().any(|n| n == bar)
            && previous.display_control.left > strip_bounds.right,
        "desktop control is not outside clipped strip"
    );
    let strip_children = children(strip);
    ensure!(
        strip_children
            .last()
            .is_some_and(|n| path(*n).is_ok_and(|p| p == last.path)),
        "last retained tab is not strip endpoint"
    );
    let mut target = None;
    for tab in &previous.tabs {
        let old = inventory_node_at_path(&old_doc, &tab.path)?;
        let current = inventory_node_at_path(&doc, &tab.path)?;
        ensure!(
            current.parent_element() == Some(strip)
                && current.attribute("class") == old.attribute("class")
                && flags(current, true, true, false)
                && old.attribute("focused") == Some("false")
                && current.attribute("focused") == Some("false")
                && current.attribute("content-desc").is_none(),
            "retained tab identity or flags changed"
        );
        let bounds = b(current)?;
        if tab.ordinal == last.ordinal {
            ensure!(
                bounds.left == tab.bounds.left
                    && bounds.top == tab.bounds.top
                    && bounds.bottom == tab.bounds.bottom
                    && bounds.right == strip_bounds.right
                    && bounds.right < tab.bounds.right,
                "last body is not right-edge-only clipped"
            );
        } else {
            ensure!(bounds == tab.bounds, "prior inactive tab body changed");
        }
        ensure!(
            contains(strip_bounds, bounds),
            "retained tab outside current strip"
        );
        let titles: Vec<_> = children(current)
            .into_iter()
            .filter(|n| n.attribute("class") == Some(TEXT))
            .collect();
        ensure!(
            titles.len() == 1
                && flags(titles[0], false, false, false)
                && titles[0].attribute("focused") == Some("false")
                && titles[0].attribute("content-desc").is_none()
                && children(titles[0]).is_empty()
                && b(titles[0])? == tab.title_bounds
                && contains(bounds, tab.title_bounds),
            "retained title changed or clipped"
        );
        let old_title = children(old)
            .into_iter()
            .find(|n| n.attribute("class") == Some(TEXT))
            .context("prior title absent")?;
        ensure!(
            path(titles[0])? == path(old_title)?,
            "retained title path changed"
        );
        if tab.ordinal == last.ordinal {
            target = Some((current, tab.title_bounds.center()));
        }
    }
    for n in strip_children {
        if previous
            .tabs
            .iter()
            .any(|t| path(n).is_ok_and(|p| p == t.path))
        {
            continue;
        }
        ensure!(
            n.attribute("class") == Some(VIEW)
                && flags(n, false, false, false)
                && n.attribute("focused") == Some("false")
                && n.attribute("content-desc").is_none()
                && children(n).is_empty(),
            "unexpected current strip child"
        );
    }
    let (body, (x, y)) = target.context("retained target absent")?;
    ensure!(
        center_inside(b(body)?, last.title_bounds),
        "title center outside clipped body"
    );
    for node in doc
        .descendants()
        .filter(|n| n.has_tag_name("node") && *n != body)
    {
        if node.attribute("clickable") == Some("true") || !own(node) {
            let bounds = b(node)?;
            ensure!(
                !(bounds.left <= x && x < bounds.right && bounds.top <= y && y < bounds.bottom),
                "target covered by another control or foreign node"
            );
        }
    }
    Ok(ClippedDesktopRecovery {
        ordinal: last.ordinal,
        x,
        y,
        prior_tabs_retained_structurally: true,
        semantic_tab_identity_verified: false,
        input_authorized: false,
        mutation_performed: false,
        native_lifetime_must_be_verified_externally: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(
        class: &str,
        bounds: &str,
        click: bool,
        focus: bool,
        selected: bool,
        desc: Option<&str>,
        body: &str,
    ) -> String {
        let desc = desc
            .map(|s| format!(" content-desc=\"{s}\""))
            .unwrap_or_default();
        format!(
            r#"<node class="{class}" package="{PACKAGE}" bounds="{bounds}" enabled="true" clickable="{click}" focusable="{focus}" selected="{selected}" focused="false" password="false"{desc}>{body}</node>"#
        )
    }
    fn rect(l: u32, r: u32, top: u32, bottom: u32) -> String {
        format!("[{l},{top}][{r},{bottom}]")
    }
    fn plain(l: u32, r: u32) -> String {
        node(VIEW, &rect(l, r, 10, 40), false, false, false, None, "")
    }
    fn icon(desc: &str, l: u32, r: u32) -> String {
        let leaf = node(
            VIEW,
            &rect(l + 10, r - 10, 20, 30),
            false,
            false,
            false,
            Some(desc),
            "",
        );
        let marker = node(
            BUTTON,
            &rect(l + 5, r - 5, 15, 35),
            false,
            false,
            false,
            None,
            "",
        );
        node(
            VIEW,
            &rect(l, r, 10, 40),
            true,
            true,
            false,
            None,
            &(leaf + &marker),
        )
    }
    fn tab(ordinal: usize, selected: bool, close: bool) -> String {
        let left = ordinal as u32 * 100 + 10;
        let title = node(
            TEXT,
            &rect(left + 2, left + 50, 15, 30),
            false,
            false,
            false,
            None,
            "",
        );
        let close = if close {
            icon("Close tab", left + 50, left + 90)
        } else {
            String::new()
        };
        node(
            VIEW,
            &rect(left, left + 80, 10, 40),
            !selected,
            true,
            selected,
            None,
            &(title + &close + &plain(left, left + 80)),
        )
    }
    fn envelope(body: &str) -> String {
        format!(
            r#"<gb-ui><hierarchy>{body}</hierarchy><gb-meta complete="true" node_count="{}"/></gb-ui>"#,
            body.matches("<node ").count()
        )
    }
    fn fixture(count: usize, selected: usize) -> String {
        let mut tabs = plain(0, 5);
        for i in 0..count {
            tabs += &tab(i, i == selected, i == selected);
        }
        tabs += &plain(count as u32 * 100 - 5, count as u32 * 100);
        let strip = node(
            VIEW,
            &rect(0, count as u32 * 100, 10, 40),
            false,
            false,
            false,
            None,
            &tabs,
        );
        let add = icon("Add tab", count as u32 * 100, count as u32 * 100 + 40);
        let bar = node(
            VIEW,
            &rect(0, count as u32 * 100 + 40, 10, 40),
            false,
            false,
            false,
            None,
            &(strip + &add),
        );
        let display = node(
            VIEW,
            &rect(400, 420, 20, 30),
            false,
            false,
            false,
            Some("Display options"),
            "",
        );
        envelope(&(bar + &display))
    }
    fn decorated_fixture(count: usize) -> String {
        let mut body = String::new();
        for i in 0..count {
            let selected = i + 1 == count;
            let left = i as u32 * 100 + 10;
            if selected {
                body += &node(
                    VIEW,
                    &rect(left - 5, left, 15, 40),
                    false,
                    false,
                    false,
                    None,
                    "",
                );
            }
            body += &tab(i, selected, selected);
            if selected {
                body += &node(
                    VIEW,
                    &rect(left + 73, left + 93, 15, 40),
                    false,
                    false,
                    false,
                    None,
                    "",
                );
            }
        }
        let edge = count as u32 * 100 + 3;
        let strip = node(
            VIEW,
            &rect(0, edge, 10, 40),
            false,
            false,
            false,
            None,
            &body,
        );
        let bar = node(
            VIEW,
            &rect(0, edge + 40, 10, 40),
            false,
            false,
            false,
            None,
            &(strip + &icon("Add tab", edge, edge + 40)),
        );
        let display = node(
            VIEW,
            "[1000,20][1020,30]",
            false,
            false,
            false,
            Some("Display options"),
            "",
        );
        envelope(&(bar + &display))
    }
    #[test]
    fn decorated_selected_append_is_opt_in_and_handles_only_selection_child_shift() -> Result<()> {
        for n in 1..=2 {
            let before = decorated_fixture(n);
            let after = decorated_fixture(n + 1);
            assert!(verify_selected_append(&inspect(&before)?, &inspect(&after)?).is_err());
            let observation = verify_selected_decorated_append(&before, &after)?;
            assert_eq!(
                (
                    observation.before_local_tab_count,
                    observation.after_local_tab_count
                ),
                (n, n + 1)
            );
            assert_eq!(observation.appended_ordinal, n);
            assert!(observation.prior_tabs_retained_structurally);
            assert!(!observation.semantic_tab_identity_verified);
            assert!(!observation.fresh_guest_prompt_verified && !observation.mutation_performed);
        }
        Ok(())
    }
    #[test]
    fn decorated_selected_append_still_refuses_retained_body_ancestor_or_count_changes() {
        let before = decorated_fixture(1);
        let after = decorated_fixture(2);
        let moved = after.replace("[10,10][90,40]", "[11,10][91,40]");
        let ancestor = recount(&after.replace("<hierarchy>",
            "<hierarchy><node class=\"android.view.View\" package=\"com.android.virtualization.terminal\" bounds=\"[0,0][2000,1000]\" enabled=\"true\" clickable=\"false\" focusable=\"false\" focused=\"false\" password=\"false\" selected=\"false\">")
            .replace("</hierarchy>", "</node></hierarchy>"));
        for changed in [moved, ancestor, decorated_fixture(3)] {
            assert!(verify_selected_decorated_append(&before, &changed).is_err());
        }
        assert!(verify_selected_decorated_append(&fixture(1, 0), &fixture(2, 1)).is_err());
    }
    #[test]
    fn decorated_selected_append_requires_exact_two_inert_relative_decorations() {
        let before = decorated_fixture(1);
        let after = decorated_fixture(2);
        let leading = node(VIEW, "[105,15][110,40]", false, false, false, None, "");
        assert!(after.contains(&leading));
        for changed in [
            after.replace("[105,15][110,40]", "[104,15][110,40]"),
            after.replace("[183,15][203,40]", "[183,16][203,40]"),
            recount(&after.replace(&leading, &(leading.clone() + &plain(0, 1)))),
            after.replace(
                &leading,
                &leading.replace("clickable=\"false\"", "clickable=\"true\""),
            ),
            after.replace(
                &leading,
                &leading.replace("focused=\"false\"", "focused=\"true\""),
            ),
            after.replace(&leading, &leading.replace(PACKAGE, "redacted.foreign")),
        ] {
            assert!(verify_selected_decorated_append(&before, &changed).is_err());
        }
        let shifted_before = before.replace("[5,15][10,40]", "[6,15][11,40]");
        let shifted_after = after.replace("[105,15][110,40]", "[106,15][111,40]");
        assert!(verify_selected_decorated_append(&shifted_before, &shifted_after).is_err());
    }
    fn clipped_desktop_fixture() -> (String, String) {
        let previous = fixture(2, 1);
        let mut tabs = plain(0, 5) + &tab(0, false, false);
        let title = node(TEXT, "[112,15][160,30]", false, false, false, None, "");
        tabs += &node(
            VIEW,
            "[110,10][170,40]",
            true,
            true,
            false,
            None,
            &(title + &plain(110, 190)),
        );
        let strip = node(VIEW, "[0,10][170,40]", false, false, false, None, &tabs);
        let bar = node(VIEW, "[0,10][170,40]", false, false, false, None, &strip);
        let display = node(
            VIEW,
            "[400,20][420,30]",
            false,
            false,
            false,
            Some("Close display controls"),
            "",
        );
        (previous, envelope(&(bar + &display)))
    }
    #[test]
    fn clipped_desktop_recovery_is_return_only_and_leaves_ordinary_inspection_strict() -> Result<()>
    {
        let (before, current) = clipped_desktop_fixture();
        assert!(inspect_mode_aware(&current).is_err());
        let target = select_clipped_desktop_last(&before, &current)?;
        assert_eq!((target.ordinal, target.x, target.y), (1, 136, 22));
        assert!(target.prior_tabs_retained_structurally);
        assert!(
            !target.input_authorized
                && !target.semantic_tab_identity_verified
                && !target.mutation_performed
        );
        Ok(())
    }
    #[test]
    fn clipped_recovery_refuses_title_body_ancestor_selection_or_mode_drift() {
        let (before, current) = clipped_desktop_fixture();
        let ancestor = recount(&current.replace("<hierarchy>",
            "<hierarchy><node class=\"android.view.View\" package=\"com.android.virtualization.terminal\" bounds=\"[0,0][1000,1000]\" enabled=\"true\" clickable=\"false\" focusable=\"false\" focused=\"false\" password=\"false\" selected=\"false\">")
            .replace("</hierarchy>", "</node></hierarchy>"));
        for changed in [
            current.replace("[112,15][160,30]", "[112,15][171,30]"),
            current.replace("[10,10][90,40]", "[11,10][91,40]"),
            current.replace("[110,10][170,40]", "[111,10][170,40]"),
            current.replace("[110,10][170,40]", "[110,10][171,40]"),
            current.replace("Close display controls", "Display options"),
            current.replacen("selected=\"false\"", "selected=\"true\"", 1),
            ancestor,
        ] {
            assert!(select_clipped_desktop_last(&before, &changed).is_err());
        }
        let wrong_before = before.replace("selected=\"true\"", "selected=\"false\"");
        assert!(select_clipped_desktop_last(&wrong_before, &current).is_err());
    }
    #[test]
    fn clipped_recovery_refuses_other_native_or_foreign_covering_targets_and_extra_controls() {
        let (before, current) = clipped_desktop_fixture();
        let cover = node(VIEW, "[130,20][140,25]", true, true, false, None, "");
        let foreign = cover
            .replace(PACKAGE, "redacted.foreign")
            .replace("clickable=\"true\"", "clickable=\"false\"");
        for added in [cover, foreign, icon("Add tab", 600, 640)] {
            let changed = recount(&current.replace("</hierarchy>", &(added + "</hierarchy>")));
            assert!(select_clipped_desktop_last(&before, &changed).is_err());
        }
        let title = node(TEXT, "[112,15][160,30]", false, false, false, None, "");
        for changed in [
            current.replace(
                &title,
                &title.replace("clickable=\"false\"", "clickable=\"true\""),
            ),
            current.replace(&title, &title.replace(PACKAGE, "redacted.foreign")),
            current.replace(&title, &(title.clone() + &title)),
        ] {
            assert!(select_clipped_desktop_last(&before, &changed).is_err());
        }
    }
    fn recount(xml: &str) -> String {
        let start = xml.find("node_count=\"").unwrap() + 12;
        let end = start + xml[start..].find('"').unwrap();
        format!(
            "{}{}{}",
            &xml[..start],
            xml.matches("<node ").count(),
            &xml[end..]
        )
    }
    #[test]
    fn observed_generic_compose_shape_has_scoped_controls_and_local_count() -> Result<()> {
        let s = inspect(&fixture(1, 0))?;
        assert_eq!((s.local_tab_count, s.selected_index), (1, 0));
        assert_eq!(s.add_tab.label_bounds.center(), (120, 25));
        assert!(s.tabs[0].close_control.is_some());
        assert!(!s.local_count_is_global_count && !s.semantic_tab_identity_verified);
        Ok(())
    }
    #[test]
    fn observed_touch_target_rounding_preserves_native_roles() -> Result<()> {
        let observed = include_str!("../tests/fixtures/terminal-compose-touch-rounding.xml");
        let snapshot = inspect(observed)?;
        assert_eq!((snapshot.local_tab_count, snapshot.selected_index), (1, 0));
        assert_eq!(snapshot.strip_bounds.bottom, 208);
        assert_eq!(snapshot.add_tab.click_bounds.bottom, 209);
        assert_eq!(snapshot.add_tab.click_bounds.center(), (719, 149));
        for changed in [
            observed.replace("[659,90][779,209]", "[659,90][779,210]"),
            observed.replace("[659,90][779,209]", "[659,90][779,206]"),
            observed.replace("[659,90][779,209]", "[660,90][779,209]"),
            observed.replace("[659,90][779,209]", "[658,90][779,209]"),
            observed.replace("[659,90][779,209]", "[659,91][779,209]"),
            observed.replace(
                "class=\"android.widget.Button\"",
                "class=\"android.view.View\"",
            ),
        ] {
            assert!(inspect(&changed).is_err());
        }
        let shorter = observed.replace("[659,90][779,209]", "[659,90][779,207]");
        assert!(inspect(&shorter).is_ok());
        Ok(())
    }
    #[test]
    fn observed_passive_zero_web_text_preserves_native_tabs_and_append_geometry() -> Result<()> {
        let observed = include_str!("../tests/fixtures/terminal-webview-passive-zero-text.xml");
        let provenance: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/terminal-webview-passive-zero-text.provenance.json"
        ))?;
        assert_eq!(
            provenance["fixture_sha256"],
            gb_core::digest(observed.as_bytes())
        );
        assert_eq!(
            provenance["source_receipt_sha256"],
            provenance["fixture_sha256"]
        );
        assert_eq!(provenance["fixture_bytes"], observed.len());
        let snapshot = inspect(observed)?;
        assert_eq!((snapshot.local_tab_count, snapshot.selected_index), (2, 1));
        assert_eq!(snapshot.strip_bounds.bottom, 190);
        assert!(snapshot.add_tab.click_bounds.right > snapshot.add_tab.click_bounds.left);
        assert!(
            snapshot
                .tabs
                .iter()
                .all(|tab| tab.title_bounds.bottom > tab.title_bounds.top)
        );
        let before = inspect(include_str!(
            "../tests/fixtures/terminal-compose-touch-rounding.xml"
        ))?;
        assert_eq!(before.strip_bounds.bottom, 208);
        assert!(verify_retained_append(&before, &inspect_mode_aware(observed)?).is_err());
        Ok(())
    }
    #[test]
    fn zero_bounds_exception_requires_exact_passive_owned_web_text_leaf() -> Result<()> {
        let zero = node(TEXT, "[0,0][0,0]", false, false, false, None, "");
        let wrap = |leaf: &str| {
            let web = node(WEB, &rect(0, 500, 50, 100), false, false, false, None, leaf);
            recount(&fixture(2, 1).replace("</hierarchy>", &(web + "</hierarchy>")))
        };
        assert_eq!(inspect(&wrap(&zero))?.selected_index, 1);
        for (old, new) in [
            ("clickable=\"false\"", "clickable=\"true\""),
            ("focusable=\"false\"", "focusable=\"true\""),
            ("focused=\"false\"", "focused=\"true\""),
            ("password=\"false\"", "password=\"true\""),
            ("selected=\"false\"", "selected=\"true\""),
            ("enabled=\"true\"", "enabled=\"false\""),
            (PACKAGE, "redacted.foreign"),
            ("[0,0][0,0]", "[1,1][1,1]"),
            ("[0,0][0,0]", "[0,0][1,0]"),
            ("[0,0][0,0]", "[0,0][0,1]"),
            (TEXT, VIEW),
            (TEXT, BUTTON),
            (TEXT, WEB),
            (TEXT, "android.widget.ImageButton"),
            (TEXT, "android.widget.ImageView"),
            (TEXT, "android.widget.EditText"),
            (TEXT, "android.app.ActionBar$Tab"),
        ] {
            assert!(
                inspect(&wrap(&zero.replace(old, new))).is_err(),
                "{old} -> {new}"
            );
        }
        assert!(
            inspect(&wrap(
                &zero.replace("<node ", "<node content-desc=\"Cursor\" ")
            ))
            .is_err()
        );
        assert!(inspect(&wrap(&zero.replace("<node ", "<node content-desc=\"\" "))).is_err());
        let nonleaf = node(TEXT, "[0,0][0,0]", false, false, false, None, &plain(0, 5));
        assert!(inspect(&wrap(&nonleaf)).is_err());
        let native =
            recount(&fixture(2, 1).replace("</hierarchy>", &(zero.clone() + "</hierarchy>")));
        assert!(inspect(&native).is_err());
        // An owned WebView cannot launder a foreign ancestor into eligibility.
        let own_web = node(
            WEB,
            &rect(0, 500, 50, 100),
            false,
            false,
            false,
            None,
            &zero,
        );
        let foreign = node(
            VIEW,
            &rect(0, 500, 50, 100),
            false,
            false,
            false,
            None,
            &own_web,
        )
        .replacen(PACKAGE, "redacted.foreign", 1);
        let changed = recount(&fixture(2, 1).replace("</hierarchy>", &(foreign + "</hierarchy>")));
        assert!(inspect(&changed).is_err());
        let foreign = node(
            VIEW,
            &rect(0, 500, 50, 100),
            false,
            false,
            false,
            None,
            &zero,
        )
        .replacen(PACKAGE, "redacted.foreign", 1);
        assert!(inspect(&wrap(&foreign)).is_err());
        // Neither a WebView nor any native hit target gets zero-sized bounds.
        let changed =
            wrap(&zero).replacen("bounds=\"[0,50][500,100]\"", "bounds=\"[0,0][0,0]\"", 1);
        assert!(inspect(&changed).is_err());
        let changed =
            fixture(2, 1).replacen("bounds=\"[200,10][240,40]\"", "bounds=\"[0,0][0,0]\"", 1);
        assert!(inspect(&changed).is_err());
        Ok(())
    }
    #[test]
    fn two_tab_append_is_only_structural_evidence() -> Result<()> {
        let before = inspect(&fixture(1, 0))?;
        let after = inspect(&fixture(2, 1))?;
        let proof = verify_append_transition(&before, &after)?;
        assert_eq!(proof.appended_ordinal, 1);
        assert!(proof.original_tab_retained_structurally);
        assert!(
            !proof.fresh_guest_prompt_verified
                && !proof.semantic_tab_identity_verified
                && !proof.mutation_performed
        );
        assert!(proof.native_lifetime_must_be_verified_externally);
        Ok(())
    }
    #[test]
    fn selected_append_two_to_three_retains_only_structural_evidence() -> Result<()> {
        let before = inspect(&fixture(2, 1))?;
        let after = inspect(&fixture(3, 2))?;
        let proof = verify_selected_append(&before, &after)?;
        assert_eq!(
            (proof.before_local_tab_count, proof.after_local_tab_count),
            (2, 3)
        );
        assert_eq!(proof.appended_ordinal, 2);
        assert!(proof.prior_tabs_retained_structurally);
        assert!(proof.native_lifetime_must_be_verified_externally);
        assert!(!proof.semantic_tab_identity_verified && !proof.fresh_guest_prompt_verified);
        assert!(!proof.mutation_performed);
        // The explicitly selected policy does not widen the legacy API.
        assert!(verify_append_transition(&before, &after).is_err());
        Ok(())
    }
    #[test]
    fn selected_append_refuses_jump_selection_and_inconsistent_vectors() -> Result<()> {
        let before = inspect(&fixture(2, 1))?;
        assert!(verify_selected_append(&before, &inspect(&fixture(3, 0))?).is_err());
        assert!(
            verify_selected_append(&inspect(&fixture(2, 0))?, &inspect(&fixture(3, 2))?).is_err()
        );
        assert!(verify_selected_append(&before, &inspect(&fixture(2, 1))?).is_err());
        let mut after = inspect(&fixture(3, 2))?;
        after.local_tab_count = 4;
        assert!(verify_selected_append(&before, &after).is_err());
        let mut after = inspect(&fixture(3, 2))?;
        after.tabs[0].selected = true;
        assert!(verify_selected_append(&before, &after).is_err());
        Ok(())
    }
    #[test]
    fn selected_append_refuses_any_retained_body_path_or_toolbar_change() -> Result<()> {
        let before = inspect(&fixture(2, 1))?;
        for index in 0..2 {
            let mut after = inspect(&fixture(3, 2))?;
            after.tabs[index].bounds.left += 1;
            assert!(verify_selected_append(&before, &after).is_err());
            let mut after = inspect(&fixture(3, 2))?;
            after.tabs[index].path.push(0);
            assert!(verify_selected_append(&before, &after).is_err());
        }
        let mut after = inspect(&fixture(3, 2))?;
        after.strip_bounds.bottom += 1;
        assert!(verify_selected_append(&before, &after).is_err());
        let mut after = inspect(&fixture(3, 2))?;
        after.display_control.left += 1;
        assert!(verify_selected_append(&before, &after).is_err());
        Ok(())
    }
    #[test]
    fn selected_append_accepts_seven_to_eight_but_refuses_zero_or_eight_base() -> Result<()> {
        let wide = |count, selected| {
            fixture(count, selected).replace("[400,20][420,30]", "[1000,20][1020,30]")
        };
        let before = inspect(&wide(7, 6))?;
        let after = inspect(&wide(8, 7))?;
        assert_eq!(verify_selected_append(&before, &after)?.appended_ordinal, 7);
        assert!(verify_selected_append(&after, &after).is_err());
        let mut invalid = inspect(&fixture(2, 1))?;
        invalid.local_tab_count = 0;
        assert!(verify_selected_append(&invalid, &inspect(&fixture(3, 2))?).is_err());
        Ok(())
    }
    fn cursor_pair(bounds: &str) -> String {
        let cursor = node(
            "android.widget.EditText",
            bounds,
            true,
            true,
            false,
            Some("Cursor"),
            "",
        )
        .replace("focused=\"false\"", "focused=\"true\"");
        node(VIEW, bounds, false, false, false, None, &cursor)
    }
    fn with_cursor_pair(pair: &str, web: bool) -> String {
        let body = if web {
            node(WEB, "[0,50][500,100]", false, false, false, None, pair)
        } else {
            pair.to_owned()
        };
        recount(&fixture(3, 2).replace("</hierarchy>", &(body + "</hierarchy>")))
    }
    #[test]
    fn clipped_cursor_pair_does_not_invalidate_native_header_or_authorize_input() -> Result<()> {
        let xml = with_cursor_pair(&cursor_pair("[100,100][120,100]"), true);
        let snapshot = inspect(&xml)?;
        assert_eq!((snapshot.local_tab_count, snapshot.selected_index), (3, 2));
        assert!(Bounds::parse("[100,100][120,100]").is_err());
        let tty = crate::terminal_ui::inspect(&xml)?;
        assert!(tty.tty_cursor_present);
        assert!(tty.focused_tty_editor.is_none());
        assert_eq!(
            crate::terminal_ui::prepare_input(&tty, false)?,
            crate::terminal_ui::InputPreparation::RefreshTtyViewAndReobserve
        );
        Ok(())
    }
    #[test]
    fn clipped_cursor_exception_requires_exact_owned_bottom_pair() {
        let original = cursor_pair("[100,100][120,100]");
        assert!(inspect(&with_cursor_pair(&original, false)).is_err());
        for changed in [
            original.replace(PACKAGE, "redacted.foreign"),
            original.replace("[100,100][120,100]", "[100,99][120,99]"),
            original.replace("[100,100][120,100]", "[100,101][120,101]"),
            original.replace("[100,100][120,100]", "[100,100][501,100]"),
            original.replace("[100,100][120,100]", "[-1,100][120,100]"),
            original.replace("[100,100][120,100]", "[100,100][100,100]"),
            original.replacen("clickable=\"false\"", "clickable=\"true\"", 1),
            original.replacen("focused=\"false\"", "focused=\"true\"", 1),
            original.replace("content-desc=\"Cursor\"", "content-desc=\"Close tab\""),
            original.replacen("[100,100][120,100]", "[101,100][120,100]", 1),
            original.replace("focused=\"true\"", "focused=\"false\""),
            original.replace("password=\"false\"", "password=\"true\""),
            original.replacen(
                "</node>",
                "</node><node class=\"android.view.View\" package=\"com.android.virtualization.terminal\" bounds=\"[1,60][2,61]\" enabled=\"true\" clickable=\"false\" focusable=\"false\" focused=\"false\" password=\"false\" selected=\"false\"></node>",
                1,
            ),
        ] {
            assert!(inspect(&with_cursor_pair(&changed, true)).is_err(), "{changed}");
        }
    }
    #[test]
    fn positive_cursor_bounds_use_normal_validation_not_clipped_exception() -> Result<()> {
        let xml = with_cursor_pair(&cursor_pair("[100,90][120,100]"), true);
        let doc = roxmltree::Document::parse(&xml)?;
        for n in doc
            .descendants()
            .filter(|n| n.attribute("bounds") == Some("[100,90][120,100]"))
        {
            assert!(!clipped_web_cursor_pair(n));
        }
        assert_eq!(inspect(&xml)?.local_tab_count, 3);
        assert!(
            crate::terminal_ui::inspect(&xml)?
                .focused_tty_editor
                .is_some()
        );
        Ok(())
    }
    fn with_clipped_web_row(leaf: &str, web: bool) -> String {
        let parent = node(VIEW, "[0,50][500,100]", false, false, false, None, leaf);
        let body = if web {
            node(WEB, "[0,50][500,100]", false, false, false, None, &parent)
        } else {
            parent
        };
        recount(&fixture(2, 1).replace("</hierarchy>", &(body + "</hierarchy>")))
    }
    #[test]
    fn clipped_web_output_rows_do_not_invalidate_native_tab_inventory() -> Result<()> {
        let leaf = node(VIEW, "[0,100][500,100]", false, true, false, None, "");
        let snapshot = inspect(&with_clipped_web_row(&leaf, true))?;
        assert_eq!(snapshot.local_tab_count, 2);
        assert_eq!(snapshot.selected_index, 1);
        assert!(Bounds::parse("[0,100][500,100]").is_err());
        Ok(())
    }
    #[test]
    fn clipped_row_exception_never_accepts_native_editor_or_interactive_target() {
        let leaf = node(VIEW, "[0,100][500,100]", false, true, false, None, "");
        assert!(inspect(&with_clipped_web_row(&leaf, false)).is_err());
        for changed in [
            leaf.replace("android.view.View", "android.widget.EditText"),
            leaf.replace("focused=\"false\"", "focused=\"true\""),
            leaf.replace("clickable=\"false\"", "clickable=\"true\""),
            leaf.replace("password=\"false\"", "password=\"true\""),
            leaf.replace("selected=\"false\"", "selected=\"true\""),
            leaf.replace("[0,100][500,100]", "[0,99][500,99]"),
            leaf.replace("[0,100][500,100]", "[1,100][500,100]"),
            leaf.replace("<node ", "<node content-desc=\"Add tab\" "),
        ] {
            assert!(inspect(&with_clipped_web_row(&changed, true)).is_err());
        }
    }
    #[test]
    fn native_title_labels_cannot_impersonate_add_icon() {
        let original = fixture(1, 0);
        let spoof = node(
            TEXT,
            &rect(12, 60, 15, 30),
            false,
            false,
            false,
            Some("Add tab"),
            "",
        );
        let duplicate = recount(&original.replace("</hierarchy>", &(spoof + "</hierarchy>")));
        assert!(inspect(&duplicate).is_err());
        // With the actual label removed, the sole spoof still lacks IconButton topology.
        let one = duplicate.replacen("content-desc=\"Add tab\"", "content-desc=\"Cursor\"", 1);
        assert!(inspect(&one).is_err());
    }
    #[test]
    fn guest_webview_cannot_supply_native_add_control() -> Result<()> {
        let guest = node(
            WEB,
            &rect(0, 500, 50, 100),
            false,
            false,
            false,
            None,
            &icon("Add tab", 100, 140),
        );
        let good = fixture(1, 0);
        let with_guest = recount(&good.replace("</hierarchy>", &(guest + "</hierarchy>")));
        assert_eq!(inspect(&with_guest)?.local_tab_count, 1);
        let guest_only =
            with_guest.replacen("content-desc=\"Add tab\"", "content-desc=\"Cursor\"", 1);
        assert!(inspect(&guest_only).is_err());
        Ok(())
    }
    #[test]
    fn missing_role_marker_or_changed_icon_order_is_refused() {
        let good = fixture(1, 0);
        let changed = good.replace(
            "class=\"android.widget.Button\"",
            "class=\"android.view.View\"",
        );
        assert!(inspect(&changed).is_err());
        let changed=good.replace("class=\"android.view.View\" package=\"com.android.virtualization.terminal\" bounds=\"[110,20][130,30]\"","class=\"android.widget.TextView\" package=\"com.android.virtualization.terminal\" bounds=\"[110,20][130,30]\"");
        assert!(inspect(&changed).is_err());
    }
    #[test]
    fn disabled_parent_bad_ltr_geometry_and_ambiguous_selection_are_refused() {
        let good = fixture(1, 0);
        for changed in [
            good.replace(
                "bounds=\"[100,10][140,40]\" enabled=\"true\"",
                "bounds=\"[100,10][140,40]\" enabled=\"false\"",
            ),
            good.replace("bounds=\"[0,10][100,40]\"", "bounds=\"[0,10][99,40]\""),
            good.replace("bounds=\"[400,20][420,30]\"", "bounds=\"[50,20][60,30]\""),
            good.replace("selected=\"true\"", "selected=\"false\""),
        ] {
            assert!(inspect(&changed).is_err());
        }
        let mut extra = node(VIEW, &rect(0, 5, 50, 60), false, true, true, None, "");
        extra.push_str("</hierarchy>");
        assert!(inspect(&recount(&good.replace("</hierarchy>", &extra))).is_err());
    }
    #[test]
    fn unreduced_private_fields_malformed_or_incomplete_envelope_are_refused() {
        let good = fixture(1, 0);
        for changed in [
            good.replacen("<node ", "<node text=\"private\" ", 1),
            good.replacen("<node ", "<node resource-id=\"private:id/value\" ", 1),
            good.replace("complete=\"true\"", "complete=\"false\""),
            good.replace(
                &format!("node_count=\"{}\"", good.matches("<node ").count()),
                "node_count=\"0\"",
            ),
            good.replacen("enabled=\"true\"", "enabled=\"maybe\"", 1),
            good.replacen("[0,10][140,40]", "[140,10][0,40]", 1),
            good.replace("</hierarchy>", "private</hierarchy>"),
            "<!DOCTYPE gb-ui><gb-ui/>".to_owned(),
        ] {
            assert!(inspect(&changed).is_err(), "unexpected acceptance");
        }
    }
    #[test]
    fn foreign_ancestor_and_nested_strip_controls_are_not_native() {
        let good = fixture(1, 0);
        let foreign=recount(&good.replacen("<hierarchy>","<hierarchy><node class=\"android.view.View\" package=\"redacted.foreign\" bounds=\"[0,0][500,100]\" enabled=\"true\" clickable=\"false\" focusable=\"false\" selected=\"false\" focused=\"false\" password=\"false\">",1).replace("</hierarchy>","</node></hierarchy>"));
        assert!(inspect(&foreign).is_err());
        let nested = recount(&good.replace(
            &plain(0, 5),
            &node(
                VIEW,
                &rect(0, 5, 10, 40),
                false,
                false,
                false,
                None,
                &icon("Close tab", 1, 41),
            ),
        ));
        assert!(inspect(&nested).is_err());
    }
    #[test]
    fn excessive_local_tabs_and_wrong_append_are_refused() -> Result<()> {
        assert!(inspect(&fixture(9, 8)).is_err());
        let before = inspect(&fixture(1, 0))?;
        assert!(verify_append_transition(&before, &inspect(&fixture(1, 0))?).is_err());
        assert!(verify_append_transition(&before, &inspect(&fixture(2, 0))?).is_err());
        let mut after = inspect(&fixture(2, 1))?;
        after.display_control.left += 1;
        assert!(verify_append_transition(&before, &after).is_err());
        Ok(())
    }
    fn desktop_fixture(count: usize) -> String {
        fixture(count, usize::MAX).replace("Display options", "Close display controls")
    }
    #[test]
    fn desktop_zero_selection_is_mode_specific_and_legacy_remains_strict() -> Result<()> {
        let desktop = desktop_fixture(2);
        let mode = inspect_mode_aware(&desktop)?;
        assert!(mode.display_enabled);
        assert_eq!(mode.selected_index, None);
        assert_eq!(mode.local_tab_count, 2);
        assert!(inspect(&desktop).is_err());
        assert!(inspect_mode_aware(&fixture(2, usize::MAX)).is_err());
        assert!(
            inspect_mode_aware(&fixture(2, 1).replace("Display options", "Close display controls"))
                .is_err()
        );
        let web = node(WEB, &rect(0, 100, 50, 100), false, false, false, None, "");
        assert!(
            inspect_mode_aware(&recount(
                &desktop.replace("</hierarchy>", &(web + "</hierarchy>"))
            ))
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn retained_desktop_return_targets_last_title_body_never_close_or_add() -> Result<()> {
        let before = inspect(&fixture(1, 0))?;
        let desktop = inspect_mode_aware(&desktop_fixture(2))?;
        let p = select_retained_last(&before, &desktop)?;
        assert_eq!((p.ordinal, p.x, p.y), (1, 136, 22));
        assert!(!p.input_authorized && !p.semantic_tab_identity_verified);
        assert!(verify_retained_append(&before, &inspect_mode_aware(&fixture(2, 1))?).is_ok());
        assert!(verify_retained_append(&before, &inspect_mode_aware(&fixture(2, 0))?).is_err());
        assert!(select_retained_last(&before, &inspect_mode_aware(&desktop_fixture(1))?).is_err());
        assert!(select_retained_last(&before, &inspect_mode_aware(&fixture(2, 1))?).is_err());
        Ok(())
    }
    #[test]
    fn retained_title_selection_refuses_close_overlap_and_geometry_drift() -> Result<()> {
        let before = inspect(&fixture(1, 0))?;
        let mut desktop = inspect_mode_aware(&desktop_fixture(2))?;
        // Add an explicit Close hit target covering the proposed title point.
        let last = desktop.tabs.last_mut().context("last tab")?;
        last.close_control = Some(NativeControl {
            label_bounds: last.title_bounds,
            click_bounds: last.title_bounds,
            label_path: vec![],
            click_path: vec![],
        });
        assert!(select_retained_last(&before, &desktop).is_err());
        let mut desktop = inspect_mode_aware(&desktop_fixture(2))?;
        desktop.display_control.left += 1;
        assert!(select_retained_last(&before, &desktop).is_err());
        Ok(())
    }
}
