//! Guards for the original Terminal UI. A focused window alone does not prove
//! that text will reach its TTY. Never target arbitrary terminal-output pixels.
use anyhow::{Context, Result, ensure};
use serde::Serialize;

pub const PACKAGE: &str = "com.android.virtualization.terminal";
/// On-device native-control redaction; accepts both XML attribute quote styles.
pub const CONTROL_REDUCER: &str = include_str!("terminal_ui/reduce-controls.sh");
/// Same read-only identity predicates in one bounded ADB transport for UI tests.
pub const BATCH_IDENTITY: &str = include_str!("terminal_ui/batch_identity.py");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bounds {
    pub left: u32,
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
}

impl Bounds {
    pub fn parse(text: &str) -> Result<Self> {
        Self::parse_visible(text)?.context("empty UI bounds")
    }

    fn parse_visible(text: &str) -> Result<Option<Self>> {
        let text = text
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .context("invalid UI bounds")?;
        let (a, b) = text.split_once("][").context("invalid UI bounds")?;
        let pair = |s: &str| -> Result<(u32, u32)> {
            let (x, y) = s.split_once(',').context("invalid UI point")?;
            Ok((x.parse()?, y.parse()?))
        };
        let (left, top) = pair(a)?;
        let (right, bottom) = pair(b)?;
        ensure!(
            left <= right && top <= bottom && right <= 16384 && bottom <= 16384,
            "inverted or excessive UI bounds"
        );
        if left == right || top == bottom {
            return Ok(None);
        }
        Ok(Some(Self {
            left,
            top,
            right,
            bottom,
        }))
    }

    pub fn center(self) -> (u32, u32) {
        ((self.left + self.right) / 2, (self.top + self.bottom) / 2)
    }
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub display_enabled: bool,
    pub display_control: Bounds,
    pub focused_tty_editor: Option<Bounds>,
    pub tty_editor: Option<Bounds>,
    pub tty_cursor_present: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum InputPreparation {
    ActivateImeAtEditor { x: u32, y: u32 },
    RefreshTtyViewAndReobserve,
}

/// Plans activation only for a visible, focused cursor editor with IME hidden.
/// An already-open IME can have a stale connection despite apparent focus.
/// It, missing focus and a clipped cursor require a TTY refresh/reobservation.
/// Recheck IME and native focus before applying a plan; activation of a known
/// focused editor must be followed by IME readiness before text is sent.
pub fn prepare_input(snapshot: &Snapshot, ime_shown: bool) -> Result<InputPreparation> {
    prepare_input_with_refresh(snapshot, ime_shown, false)
}

/// A completed, observed display-to-TTY round trip replaces the stale view.
/// Its new focused cursor may reopen the IME automatically. In that case plan
/// a fresh editor activation instead of refreshing forever. This is not text
/// authorization: callers must recheck native window focus and IME afterward,
/// and verify delivery through an owned canary or receipt. Starting another
/// UiAutomation session after activation can disturb WebView focus again.
/// Set `tty_refreshed` only after the round trip succeeds, never from old state.
pub fn prepare_input_with_refresh(
    snapshot: &Snapshot,
    ime_shown: bool,
    tty_refreshed: bool,
) -> Result<InputPreparation> {
    ensure!(!snapshot.display_enabled, "TTY mode required before input");
    ensure!(snapshot.tty_cursor_present, "TTY cursor editor absent");
    if ime_shown && !tty_refreshed {
        return Ok(InputPreparation::RefreshTtyViewAndReobserve);
    }
    let Some(editor) = snapshot.focused_tty_editor else {
        return Ok(InputPreparation::RefreshTtyViewAndReobserve);
    };
    let (x, y) = editor.center();
    Ok(InputPreparation::ActivateImeAtEditor { x, y })
}

pub fn verify_window_focus(text: &str, owner: u32) -> Result<()> {
    ensure!(text.len() <= 16384, "focus output exceeds budget");
    let lines: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("mCurrentFocus="))
        .collect();
    ensure!(
        lines.len() == 1 && lines[0].contains(&format!(" u{owner} {PACKAGE}/")),
        "original Terminal is not the sole focused window for this owner"
    );
    Ok(())
}

pub fn inspect(xml: &str) -> Result<Snapshot> {
    ensure!(xml.len() <= 2 * 1024 * 1024, "UI XML exceeds budget");
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            nodes_limit: 50000,
            ..Default::default()
        },
    )
    .context("invalid UI XML")?;
    let own = |n: roxmltree::Node<'_, '_>| n.attribute("package") == Some(PACKAGE);
    let web = |n: roxmltree::Node<'_, '_>| n.attribute("class") == Some("android.webkit.WebView");
    let controls: Vec<_> = doc
        .descendants()
        .filter(|n| {
            own(*n)
                && matches!(
                    n.attribute("content-desc"),
                    Some("Display options" | "Close display controls")
                )
                && !n.ancestors().any(web)
        })
        .collect();
    ensure!(
        controls.len() == 1,
        "unambiguous native Terminal display control absent"
    );
    let control = controls[0];
    let display_enabled = control.attribute("content-desc") == Some("Close display controls");
    let editors: Vec<_> = doc
        .descendants()
        .filter(|n| {
            own(*n)
                && n.attribute("class") == Some("android.widget.EditText")
                && n.attribute("password") == Some("false")
                && n.attribute("content-desc") == Some("Cursor")
                && n.ancestors().any(|p| own(p) && web(p))
        })
        .collect();
    ensure!(editors.len() <= 1, "ambiguous TTY cursor editor");
    let tty_editor = if display_enabled {
        None
    } else {
        editors
            .first()
            .map(|n| Bounds::parse_visible(n.attribute("bounds").unwrap_or("")))
            .transpose()?
            .flatten()
    };
    let focused_tty_editor = tty_editor.filter(|_| {
        editors
            .first()
            .is_some_and(|n| n.attribute("focused") == Some("true"))
    });
    Ok(Snapshot {
        display_enabled,
        display_control: Bounds::parse(control.attribute("bounds").unwrap_or(""))?,
        focused_tty_editor,
        tty_editor,
        tty_cursor_present: !display_enabled && !editors.is_empty(),
    })
}

/// Encode owned, non-secret commands for Android's `input text`. The caller
/// must check the editor, activate its IME, and recheck focus before Enter.
pub fn input_text_command(command: &str) -> Result<String> {
    ensure!(
        !command.is_empty()
            && command.len() <= 16000
            && command.bytes().all(|b| (32..=126).contains(&b))
            && !command.contains("%s"),
        "text must be bounded printable ASCII without literal Android %s escapes"
    );
    let encoded = command.replace(' ', "%s");
    Ok(format!("input text '{}'", encoded.replace('\'', "'\\''")))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(control: &str, editor: &str) -> String {
        format!(
            r#"<hierarchy><node package="{PACKAGE}" content-desc="{control}" bounds="[2036,117][2086,167]"/>{editor}</hierarchy>"#
        )
    }
    fn editor(package: &str, password: bool) -> String {
        format!(
            r#"<node package="{package}" class="android.webkit.WebView"><node package="{package}" class="android.widget.EditText" content-desc="Cursor" focused="true" password="{password}" bounds="[957,960][980,1002]"/></node>"#
        )
    }
    #[test]
    fn moved_controls_and_real_tty_editor_are_distinct() -> Result<()> {
        let s = inspect(&fixture("Display options", &editor(PACKAGE, false)))?;
        assert_eq!(s.display_control.center(), (2061, 142));
        assert_eq!(s.focused_tty_editor.context("editor")?.center(), (968, 981));
        assert!(!s.display_enabled);
        Ok(())
    }
    #[test]
    fn an_open_ime_never_plans_a_coordinate_tap() -> Result<()> {
        let s = inspect(&fixture("Display options", &editor(PACKAGE, false)))?;
        assert_eq!(
            prepare_input(&s, true)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        assert_eq!(
            prepare_input(&s, false)?,
            InputPreparation::ActivateImeAtEditor { x: 968, y: 981 }
        );
        let display = inspect(&fixture("Close display controls", &editor(PACKAGE, false)))?;
        assert!(prepare_input(&display, true).is_err());
        let missing = inspect(&fixture("Display options", ""))?;
        assert!(prepare_input(&missing, true).is_err());
        let unfocused = inspect(&fixture(
            "Display options",
            &editor(PACKAGE, false).replace("focused=\"true\"", "focused=\"false\""),
        ))?;
        assert_eq!(
            prepare_input(&unfocused, true)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        assert_eq!(
            prepare_input(&unfocused, false)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        assert!(unfocused.focused_tty_editor.is_none());
        Ok(())
    }
    #[test]
    fn only_one_actual_cursor_can_be_refocused() -> Result<()> {
        let e = editor(PACKAGE, false).replace("focused=\"true\"", "focused=\"false\"");
        assert!(inspect(&fixture("Display options", &(e.clone() + &e))).is_err());
        for changed in [
            e.replace("Cursor", "Search"),
            e.replace("Cursor", ""),
            e.replace("password=\"false\"", "password=\"true\""),
        ] {
            let s = inspect(&fixture("Display options", &changed))?;
            assert!(s.tty_editor.is_none());
            assert!(prepare_input(&s, false).is_err());
        }
        Ok(())
    }
    #[test]
    fn freshly_recreated_tty_can_reactivate_an_automatically_reopened_ime() -> Result<()> {
        let s = inspect(&fixture("Display options", &editor(PACKAGE, false)))?;
        assert_eq!(
            prepare_input_with_refresh(&s, true, false)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        assert_eq!(
            prepare_input_with_refresh(&s, true, true)?,
            InputPreparation::ActivateImeAtEditor { x: 968, y: 981 }
        );
        for changed in [
            editor(PACKAGE, false).replace("focused=\"true\"", "focused=\"false\""),
            editor(PACKAGE, false).replace("[957,960][980,1002]", "[957,960][957,960]"),
        ] {
            let s = inspect(&fixture("Display options", &changed))?;
            assert_eq!(
                prepare_input_with_refresh(&s, true, true)?,
                InputPreparation::RefreshTtyViewAndReobserve
            );
        }
        for (control, cursor) in [
            ("Close display controls", editor(PACKAGE, false)),
            ("Display options", editor(PACKAGE, true)),
            ("Display options", editor("com.android.chrome", false)),
        ] {
            let s = inspect(&fixture(control, &cursor))?;
            assert!(prepare_input_with_refresh(&s, true, true).is_err());
        }
        Ok(())
    }
    #[test]
    fn clipped_cursor_never_produces_tap_coordinates() -> Result<()> {
        let clipped = editor(PACKAGE, false).replace("[957,960][980,1002]", "[957,960][957,960]");
        let s = inspect(&fixture("Display options", &clipped))?;
        assert!(s.tty_cursor_present);
        assert!(s.tty_editor.is_none());
        assert_eq!(
            prepare_input(&s, true)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        assert_eq!(
            prepare_input(&s, false)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        let unfocused = inspect(&fixture(
            "Display options",
            &clipped.replace("focused=\"true\"", "focused=\"false\""),
        ))?;
        assert_eq!(
            prepare_input(&unfocused, true)?,
            InputPreparation::RefreshTtyViewAndReobserve
        );
        let malformed = clipped.replace("[957,960][957,960]", "[958,960][957,960]");
        assert!(inspect(&fixture("Display options", &malformed)).is_err());
        Ok(())
    }
    #[test]
    fn display_mode_and_foreign_or_password_inputs_cannot_qualify_tty() -> Result<()> {
        assert!(
            inspect(&fixture("Close display controls", &editor(PACKAGE, false)))?
                .focused_tty_editor
                .is_none()
        );
        assert!(
            inspect(&fixture(
                "Display options",
                &editor("com.android.chrome", false)
            ))?
            .focused_tty_editor
            .is_none()
        );
        assert!(
            inspect(&fixture("Display options", &editor(PACKAGE, true)))?
                .focused_tty_editor
                .is_none()
        );
        Ok(())
    }
    #[test]
    fn embedded_labels_ambiguity_and_malformed_geometry_are_rejected() {
        let html = format!(
            r#"<hierarchy><node package="{PACKAGE}" class="android.webkit.WebView"><node package="{PACKAGE}" content-desc="Display options" bounds="[1,1][2,2]"/></node></hierarchy>"#
        );
        assert!(inspect(&html).is_err());
        let duplicate = fixture("Display options", &fixture("Display options", ""));
        assert!(inspect(&duplicate).is_err());
        for bad in ["[1,2][1,2]", "[-1,2][3,4]", "[1,2][99999,4]", "nonsense"] {
            assert!(Bounds::parse(bad).is_err());
        }
        assert!(inspect("<!DOCTYPE x [<!ENTITY y 'value'>]><x/>").is_err());
    }
    #[test]
    fn foreign_owner_or_keyguard_focus_is_refused() {
        assert!(
            verify_window_focus(
                &format!(" mCurrentFocus=Window{{abc u11 {PACKAGE}/.MainActivity}}"),
                11
            )
            .is_ok()
        );
        assert!(
            verify_window_focus(
                &format!("mCurrentFocus=Window{{abc u10 {PACKAGE}/.MainActivity}}"),
                11
            )
            .is_err()
        );
        assert!(
            verify_window_focus(
                "mCurrentFocus=Window{abc u11 com.android.systemui/Keyguard}",
                11
            )
            .is_err()
        );
        assert!(verify_window_focus("mCurrentFocus=null", 11).is_err());
    }
    #[test]
    fn text_encoding_preserves_shell_metacharacters_and_refuses_lossy_input() -> Result<()> {
        let command = "echo $(false); 'quoted'";
        let encoded = input_text_command(command)?;
        let quoted = encoded.strip_prefix("input text ").context("prefix")?;
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s' {quoted}"))
            .output()?;
        assert!(out.status.success());
        assert_eq!(String::from_utf8(out.stdout)?.replace("%s", " "), command);
        for bad in ["", "echo %s", "echo\nnext", "echo é", "echo\tfoo"] {
            assert!(input_text_command(bad).is_err());
        }
        Ok(())
    }
}
