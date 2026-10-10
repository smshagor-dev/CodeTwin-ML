//! Conservative, bounded discovery. Never executes JavaScript.
#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Literal(String),
    Symbol(u8),
}

pub(crate) fn get_literals(source: &str) -> Vec<String> {
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
            i = (i + 2).min(bytes.len());
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
        let unqualified = i == 0 || !matches!(tokens[i - 1], Token::Symbol(b'.') | Token::Word(_));
        let start = if name == "fetch" && unqualified {
            i + 1
        } else if name == "axios"
            && unqualified
            && tokens.get(i + 1) == Some(&Token::Symbol(b'.'))
            && tokens.get(i + 2) == Some(&Token::Word("get".into()))
        {
            i + 3
        } else {
            continue;
        };
        if tokens.get(start) == Some(&Token::Symbol(b'('))
            && tokens.get(start + 2) == Some(&Token::Symbol(b')'))
        {
            if let Some(Token::Literal(value)) = tokens.get(start + 1) {
                if !value.is_empty() && !output.contains(value) {
                    output.push(value.clone());
                }
            }
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
