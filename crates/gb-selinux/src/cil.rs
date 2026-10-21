//! Bounded statement ranges for evidence and narrowly reviewed transformations.
//! The official compiler owns CIL grammar and policy semantics.
use anyhow::{Result, ensure};
#[derive(Debug, Clone)]
pub struct Form {
    pub start: usize,
    pub end: usize,
    pub head: String,
    pub depth: usize,
}
pub fn forms(text: &str) -> Result<Vec<Form>> {
    ensure!(
        text.len() <= 16 * 1024 * 1024 && !text.contains('\0'),
        "CIL input exceeds bounds or contains NUL"
    );
    let b = text.as_bytes();
    let mut stack: Vec<(usize, Option<String>)> = Vec::new();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b';' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'(' => {
                ensure!(stack.len() < 128, "CIL nesting limit exceeded");
                stack.push((i, None));
                i += 1;
            }
            b')' => {
                let (start, head) = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("unbalanced CIL closing parenthesis"))?;
                ensure!(out.len() < 1_000_000, "CIL statement limit exceeded");
                out.push(Form {
                    start,
                    end: i + 1,
                    head: head.unwrap_or_default(),
                    depth: stack.len(),
                });
                i += 1;
            }
            b'"' => {
                ensure!(
                    stack.last().is_some_and(|(_, head)| head.is_some()),
                    "quoted CIL heads are unsupported"
                );
                i += 1;
                let mut closed = false;
                while i < b.len() {
                    match b[i] {
                        b'\\' => {
                            i += 1;
                            ensure!(i < b.len(), "unterminated CIL escape");
                            i += 1;
                        }
                        b'"' => {
                            i += 1;
                            closed = true;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                ensure!(closed, "unterminated CIL string");
            }
            c if c.is_ascii_whitespace() => i += 1,
            _ => {
                let start = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && !b"();\"".contains(&b[i]) {
                    i += 1;
                }
                if let Some((_, head)) = stack.last_mut() {
                    if head.is_none() {
                        ensure!(i - start <= 512, "CIL head exceeds limit");
                        *head = Some(text[start..i].to_string());
                    }
                } else {
                    anyhow::bail!("CIL atom outside a form");
                }
            }
        }
    }
    ensure!(stack.is_empty(), "unclosed CIL form");
    out.sort_by_key(|f| f.start);
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_ignore_strings_comments_and_keep_nested_forms() {
        let text = "; (typepermissive hidden)\n(block b (type t) (filecon \"(escaped\\\"name)\" file c))\n(neverallow t t (file (read)))";
        let parsed = forms(text).unwrap();
        assert!(!parsed.iter().any(|f| f.head == "typepermissive"));
        assert_eq!(parsed.iter().filter(|f| f.head == "neverallow").count(), 1);
        let top: Vec<_> = parsed.iter().filter(|f| f.depth == 0).collect();
        assert_eq!(top.len(), 2);
        assert_eq!(
            &text[top[1].start..top[1].end],
            "(neverallow t t (file (read)))"
        );
    }
    #[test]
    fn malformed_and_deep_cil_is_rejected_without_panics() {
        for input in [
            "(type t",
            ")",
            "atom",
            "(x \"unterminated)",
            "(x \"escape\\",
            "(x\0)",
            "(\"typepermissive\" t)",
        ] {
            assert!(forms(input).is_err(), "{input:?}");
        }
        assert!(forms(&format!("{}{}", "(x ".repeat(129), ")".repeat(129))).is_err());
    }
}
