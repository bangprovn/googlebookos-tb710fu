//! Device-scoped Venus selection. Preserve unrelated GPU fields verbatim and
//! reject ambiguous syntax before changing a running VM's launch contract.

pub const DRIVER: &str = "/system_ext/lib64/gb-runtime-v1/libvulkan_freedreno.so";

pub fn parameters(input: &str) -> Result<String, &'static str> {
    if input.is_empty() || input.len() > 8192 || input.chars().any(char::is_control) {
        return Err("GPU parameter budget/encoding");
    }
    let mut fields = Vec::new();
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    for (index, byte) in input.bytes().enumerate() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == q {
                quote = None;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' => quote = Some(byte),
            b'[' | b'{' | b'(' => {
                if stack.len() == 8 {
                    return Err("GPU parameter nesting budget");
                }
                stack.push(byte);
            }
            b']' | b'}' | b')' => {
                let expected = match byte {
                    b']' => b'[',
                    b'}' => b'{',
                    _ => b'(',
                };
                if stack.pop() != Some(expected) {
                    return Err("GPU parameter bracket mismatch");
                }
            }
            b',' if stack.is_empty() => {
                fields.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() || !stack.is_empty() {
        return Err("GPU parameter unterminated structure");
    }
    fields.push(&input[start..]);
    if fields.len() > 64 {
        return Err("GPU parameter field budget");
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut retained = Vec::new();
    for field in fields {
        let key = field.split_once('=').map_or(field, |(key, _)| key);
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !seen.insert(key)
        {
            return Err("GPU parameter duplicate or invalid field");
        }
        match key {
            "vulkan" | "udmabuf" | "context-types" => {}
            // Venus does not replace or disable the existing GLES renderer.
            _ => retained.push(field),
        }
    }
    retained.extend([
        "vulkan=true",
        "udmabuf=true",
        "context-types=virgl:virgl2:venus",
    ]);
    Ok(retained.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_gles_and_nested_unrelated_options() {
        let input = "mode=virglrenderer,egl=true,gles=true,display=[{width=3200,height=2000}],renderer-features='owned,a=b',vulkan=false,udmabuf=false,context-types=virgl2";
        assert_eq!(
            parameters(input).unwrap(),
            "mode=virglrenderer,egl=true,gles=true,display=[{width=3200,height=2000}],renderer-features='owned,a=b',vulkan=true,udmabuf=true,context-types=virgl:virgl2:venus"
        );
        assert_eq!(
            parameters(&parameters(input).unwrap()).unwrap(),
            parameters(input).unwrap()
        );
    }
    #[test]
    fn refuses_ambiguous_structure_and_duplicate_keys() {
        for input in [
            "",
            "mode=virglrenderer,",
            "vulkan=true,vulkan=false",
            "gles=true,gles=false",
            "x=[a,b)",
            "x=[a,b",
            "x='a,b",
            "x=1\n",
            " gpu=true",
        ] {
            assert!(parameters(input).is_err(), "{input}");
        }
        assert!(parameters(&"x".repeat(8193)).is_err());
        assert!(parameters("x=[[[[[[[[[1]]]]]]]]]").is_err());
    }
}
