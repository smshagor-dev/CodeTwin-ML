//! Conservative, bounded discovery. Never executes JavaScript.
#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Literal(String),
    Symbol(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiCall {
    pub url: String,
    pub method: String,
}

#[cfg(test)]
pub(crate) fn get_literals(source: &str) -> Vec<String> {
    calls(source)
        .into_iter()
        .filter(|call| call.method == "GET")
        .map(|call| call.url)
        .collect()
}

pub(crate) fn calls(source: &str) -> Vec<ApiCall> {
    let bytes = source.as_bytes();
    if bytes.len() > 1_048_576 {
        return Vec::new();
    }
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() && tokens.len() < 32_768 {
        let b = bytes[i];
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            if i + 1 >= bytes.len() {
                return Vec::new();
            }
            i += 2;
        } else if matches!(b, b'\'' | b'"' | b'`') {
            let quote = b;
            i += 1;
            let start = i;
            let mut escaped = false;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    escaped = true;
                    i = (i + 2).min(bytes.len());
                } else {
                    i += 1;
                }
            }
            if i >= bytes.len() {
                return Vec::new();
            }
            let value = source.get(start..i).unwrap_or("");
            // Reject escapes and templates rather than guess runtime values.
            if i < bytes.len() && !escaped && quote != b'`' && value.len() <= 2_048 {
                tokens.push(Token::Literal(value.into()));
            } else {
                tokens.push(Token::Symbol(0));
            }
            i = (i + 1).min(bytes.len());
        } else if b.is_ascii_alphabetic() || matches!(b, b'_' | b'$') {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'$'))
            {
                i += 1;
            }
            tokens.push(Token::Word(source[start..i].into()));
        } else if b == b'/' {
            // Division and regex literals need a full grammar. Decline this
            // source rather than interpreting regex contents as executable calls.
            return Vec::new();
        } else {
            if !b.is_ascii_whitespace() {
                tokens.push(Token::Symbol(b));
            }
            i += 1;
        }
    }
    // A partial token stream must not be treated as a complete program.
    if i < bytes.len() {
        return Vec::new();
    }
    let mut output = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let Token::Word(name) = token else {
            continue;
        };
        let unqualified = i == 0
            || !matches!(tokens[i - 1], Token::Symbol(b'.') | Token::Word(_))
            || matches!(&tokens[i - 1], Token::Word(word) if matches!(word.as_str(), "await" | "return" | "yield"));
        let browser_fetch = i >= 2
            && tokens.get(i - 1) == Some(&Token::Symbol(b'.'))
            && matches!(tokens.get(i - 2), Some(Token::Word(owner)) if owner == "window" || owner == "globalThis")
            && (i == 2 || !matches!(tokens[i - 3], Token::Symbol(b'.')));
        let (start, mut method) = if name == "fetch" && (unqualified || browser_fetch) {
            (i + 1, "GET".to_string())
        } else if name == "axios" && unqualified && tokens.get(i + 1) == Some(&Token::Symbol(b'.'))
        {
            let Some(Token::Word(method)) = tokens.get(i + 2) else {
                continue;
            };
            if !matches!(
                method.as_str(),
                "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
            ) {
                continue;
            }
            (i + 3, method.to_ascii_uppercase())
        } else {
            continue;
        };
        if tokens.get(start) != Some(&Token::Symbol(b'(')) {
            continue;
        }
        let Some(Token::Literal(value)) = tokens.get(start + 1) else {
            continue;
        };
        if tokens.get(start + 2) != Some(&Token::Symbol(b')')) {
            // Only a complete, literal method-only fetch options object is
            // understood. Unknown options must not silently become GET.
            if name != "fetch"
                || tokens.get(start + 2) != Some(&Token::Symbol(b','))
                || tokens.get(start + 3) != Some(&Token::Symbol(b'{'))
                || !matches!(tokens.get(start + 4), Some(Token::Word(key) | Token::Literal(key)) if key == "method")
                || tokens.get(start + 5) != Some(&Token::Symbol(b':'))
                || tokens.get(start + 7) != Some(&Token::Symbol(b'}'))
                || tokens.get(start + 8) != Some(&Token::Symbol(b')'))
            {
                continue;
            }
            let Some(Token::Literal(value)) = tokens.get(start + 6) else {
                continue;
            };
            method = value.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                continue;
            }
        }
        let call = ApiCall {
            url: value.clone(),
            method,
        };
        if !value.is_empty() && !output.contains(&call) {
            output.push(call);
        }
        if output.len() == 256 {
            break;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::get_literals;
    #[test]
    fn only_static_single_argument_get_calls_are_discovered() {
        let source = r#"
            // fetch('/comment')
            /* axios.get('/comment2') */
            const decoy = "fetch('/string')";
            fetch('/api/live?q=1'); axios.get('../relative');
            fetch('/dynamic' + id); fetch(`/template/${id}`);
            fetch('/post', {method: 'POST'}); axios.post('/write');
            client.fetch('/custom'); fetch('/escaped\x2fvalue');
        "#;
        assert_eq!(get_literals(source), vec!["/api/live?q=1", "../relative"]);
    }
    #[test]
    fn oversized_source_is_not_partially_parsed() {
        assert!(get_literals(&" ".repeat(1_048_577)).is_empty());
        assert!(get_literals(&format!("{}fetch('/late')", ";".repeat(32_769))).is_empty());
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::calls;
    #[test]
    fn preserves_static_methods_and_declines_unknown_options() {
        let calls = calls(
            r#"fetch('/read', {method:'GET'}); fetch('/write', {'method':'POST'}); axios.delete('/delete'); fetch('/unknown', options); fetch('/dynamic', {method: method}); fetch('/body', {method:'POST', body:data});"#,
        );
        assert_eq!(
            calls
                .iter()
                .map(|c| (c.url.as_str(), c.method.as_str()))
                .collect::<Vec<_>>(),
            vec![("/read", "GET"), ("/write", "POST"), ("/delete", "DELETE")]
        );
    }
}

#[cfg(test)]
mod accuracy_tests {
    use super::calls;
    #[test]
    fn browser_fetch_is_distinct_from_custom_objects() {
        let result = calls("window.fetch('/window'); globalThis.fetch('/global'); client.fetch('/custom'); obj.window.fetch('/nested'); await fetch('/await'); return fetch('/return');");
        assert_eq!(
            result.iter().map(|c| c.url.as_str()).collect::<Vec<_>>(),
            vec!["/window", "/global", "/await", "/return"]
        );
    }
    #[test]
    fn incomplete_sources_do_not_return_partial_inventory() {
        assert!(calls("fetch('/early'); /* unclosed").is_empty());
        assert!(calls("fetch('/early'); 'unclosed").is_empty());
        assert!(calls("const regex = /fetch('/decoy')/; fetch('/actual');").is_empty());
    }
}
