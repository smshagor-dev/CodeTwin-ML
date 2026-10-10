//! Reflection context for harmless markers, not a JavaScript execution oracle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Context {
    Markup,
    Attribute,
    Script,
    Inert,
}

pub(crate) fn classify(body: &str, marker: &str) -> Context {
    let Some(index) = body.find(marker) else {
        return Context::Inert;
    };
    let lower = body.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut cursor = 0;
    while cursor < index {
        if lower[cursor..].starts_with("<!--") {
            let end = lower[cursor + 4..]
                .find("-->")
                .map(|n| cursor + 4 + n + 3)
                .unwrap_or(body.len());
            if index < end {
                return Context::Inert;
            }
            cursor = end;
            continue;
        }
        if bytes[cursor] != b'<' {
            cursor += body[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        }
        let start = cursor;
        cursor += 1;
        let mut quote = None;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if let Some(delimiter) = quote {
                if byte == delimiter {
                    quote = None;
                }
            } else if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else if byte == b'>' {
                break;
            }
            cursor += 1;
        }
        if index <= cursor {
            return Context::Attribute;
        }
        if cursor == bytes.len() {
            return Context::Inert;
        }
        cursor += 1;
        let tag = &body[start..cursor];
        let name = lower[start + 1..cursor - 1]
            .split(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
            .next()
            .unwrap_or("");
        if matches!(
            name,
            "script"
                | "textarea"
                | "title"
                | "xmp"
                | "iframe"
                | "noembed"
                | "noframes"
                | "noscript"
                | "template"
                | "plaintext"
        ) {
            let close = format!("</{name}");
            let end = if name == "plaintext" {
                body.len()
            } else {
                lower[cursor..]
                    .find(&close)
                    .map(|n| cursor + n)
                    .unwrap_or(body.len())
            };
            if index < end {
                if name != "script" {
                    return Context::Inert;
                }
                let kind = crate::discover::attribute_from_tag(tag, "type")
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                return if matches!(
                    kind.as_str(),
                    "" | "module" | "text/javascript" | "application/javascript"
                ) {
                    Context::Script
                } else {
                    Context::Inert
                };
            }
            cursor = end;
        }
    }
    Context::Markup
}

#[cfg(test)]
mod tests {
    use super::{classify, Context};
    #[test]
    fn shared_browser_fixtures_have_expected_contexts() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/xss-contexts.json"))
                .expect("fixtures");
        for case in fixtures.as_array().expect("array") {
            let expected = match case["context"].as_str().unwrap() {
                "markup" => Context::Markup,
                "attribute" => Context::Attribute,
                "script" => Context::Script,
                _ => Context::Inert,
            };
            assert_eq!(
                classify(case["body"].as_str().unwrap(), "<codetwin-xss-lab>"),
                expected,
                "{}",
                case["name"]
            );
        }
    }
}
