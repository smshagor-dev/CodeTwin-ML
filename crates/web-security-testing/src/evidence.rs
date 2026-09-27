use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{EvidenceObservation, ObservedResponse};

const SENSITIVE_KEYS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "session",
    "sessionid",
    "email",
    "phone",
    "telephone",
    "ssn",
    "social_security",
    "date_of_birth",
    "dob",
];

pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            if is_sensitive_name(name) {
                (name.clone(), "<redacted>".to_string())
            } else {
                (name.clone(), truncate(value, 512))
            }
        })
        .collect()
}

pub fn redact_url(url: &Url) -> String {
    redact_url_with_secrets(url, &[])
}

pub fn redact_url_with_secrets(url: &Url, secrets: &[String]) -> String {
    let mut safe = url.clone();
    let pairs: Vec<(String, String)> = safe
        .query_pairs()
        .map(|(name, value)| {
            let value = if is_sensitive_name(&name)
                || secrets.iter().any(|secret| {
                    let secret = secret.trim();
                    !secret.is_empty() && value.as_ref() == secret
                }) {
                "<redacted>".to_string()
            } else {
                truncate(&value, 256)
            };
            (name.into_owned(), value)
        })
        .collect();
    safe.set_query(None);
    if !pairs.is_empty() {
        let mut query = safe.query_pairs_mut();
        for (name, value) in pairs {
            query.append_pair(&name, &value);
        }
    }
    safe.to_string()
}

pub fn response_evidence(
    label: &str,
    method: &str,
    url: &Url,
    response: &ObservedResponse,
) -> EvidenceObservation {
    let safe_url = redact_url_with_secrets(url, &response.redaction_secrets);
    EvidenceObservation {
        summary: format!(
            "{label}: {method} {} -> HTTP {} in {} ms",
            safe_url, response.status, response.elapsed_ms
        ),
        request_metadata: serde_json::json!({
            "method": method,
            "url": safe_url,
        }),
        response_metadata: serde_json::json!({
            "status": response.status,
            "elapsed_ms": response.elapsed_ms,
            "content_type": response.content_type,
            "body_sha256": body_hash(&response.body),
            "body_bytes": response.body.len(),
            "headers": redact_headers(&response.headers),
            "body_excerpt": evidence_body_excerpt(response),
            "truncated": response.truncated,
        }),
    }
}

fn evidence_body_excerpt(response: &ObservedResponse) -> Option<String> {
    let content_type = response
        .content_type
        .as_deref()?
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let textual = content_type.starts_with("text/")
        || content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("javascript")
        || content_type == "application/x-www-form-urlencoded";
    textual.then(|| redact_body_with_secrets(&response.body, &response.redaction_secrets))
}

pub fn redact_body_with_secrets(body: &[u8], secrets: &[String]) -> String {
    let mut redacted = redact_body(body);
    for secret in secrets {
        let secret = secret.trim();
        if !secret.is_empty() {
            redacted = redacted.replace(secret, "<redacted>");
        }
    }
    redacted
}

pub fn redact_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if let Ok(mut json) = serde_json::from_str::<Value>(&text) {
        redact_json(&mut json);
        return truncate(&json.to_string(), 1_024);
    }
    let mut output = truncate(&text, 1_024);
    for key in SENSITIVE_KEYS {
        output = redact_assignment(&output, key);
    }
    output = redact_prefixed_token(&output, "Bearer ", true);
    for prefix in ["ghp_", "github_pat_", "sk-"] {
        output = redact_prefixed_token(&output, prefix, false);
    }
    redact_jwt_like_tokens(&output)
}

pub fn body_hash(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

pub fn fingerprint(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => redact_map(map),
        Value::Array(items) => {
            for item in items {
                redact_json(item);
            }
        }
        _ => {}
    }
}

fn redact_map(map: &mut Map<String, Value>) {
    for (key, value) in map.iter_mut() {
        if is_sensitive_name(key) {
            *value = Value::String("<redacted>".to_string());
        } else {
            redact_json(value);
        }
    }
}

fn is_sensitive_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace(['-', '_'], "");
    SENSITIVE_KEYS.iter().any(|candidate| {
        normalized.contains(&candidate.to_ascii_lowercase().replace(['-', '_'], ""))
    })
}

fn redact_assignment(input: &str, key: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let needle = key.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(relative) = lower[cursor..].find(&needle) {
        let start = cursor + relative;
        output.push_str(&input[cursor..start + needle.len()]);
        let mut index = start + needle.len();
        while index < input.len() && input.as_bytes()[index].is_ascii_whitespace() {
            output.push(input.as_bytes()[index] as char);
            index += 1;
        }
        if index < input.len() && matches!(input.as_bytes()[index], b'=' | b':') {
            output.push(input.as_bytes()[index] as char);
            index += 1;
            while index < input.len() && input.as_bytes()[index].is_ascii_whitespace() {
                output.push(input.as_bytes()[index] as char);
                index += 1;
            }
            output.push_str("<redacted>");
            while index < input.len() {
                let byte = input.as_bytes()[index];
                if matches!(byte, b'&' | b',' | b';' | b'\n' | b'\r') {
                    break;
                }
                index += 1;
            }
        }
        cursor = index;
    }
    output.push_str(&input[cursor..]);
    output
}

fn redact_prefixed_token(input: &str, prefix: &str, keep_prefix: bool) -> String {
    let lower = input.to_ascii_lowercase();
    let needle = prefix.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(relative) = lower[cursor..].find(&needle) {
        let start = cursor + relative;
        let token_start = start + prefix.len();
        output.push_str(&input[cursor..start]);
        if keep_prefix {
            output.push_str(&input[start..token_start]);
        }
        output.push_str("<redacted>");
        let mut end = token_start;
        while end < input.len() {
            let byte = input.as_bytes()[end];
            if byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'"' | b'\'' | b'<' | b'>' | b',' | b';' | b'&' | b')' | b']'
                )
            {
                break;
            }
            end += 1;
        }
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn redact_jwt_like_tokens(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for part in input.split_inclusive(char::is_whitespace) {
        let trimmed = part.trim_end_matches(char::is_whitespace);
        let suffix = &part[trimmed.len()..];
        let core = trimmed.trim_matches(|character: char| {
            matches!(
                character,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
        });
        let jwt_like = core.len() >= 32
            && core.starts_with("eyJ")
            && core.matches('.').count() == 2
            && core.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            });
        if jwt_like {
            let prefix_len = trimmed.find(core).unwrap_or(0);
            output.push_str(&trimmed[..prefix_len]);
            output.push_str("<redacted>");
            output.push_str(&trimmed[prefix_len + core.len()..]);
        } else {
            output.push_str(trimmed);
        }
        output.push_str(suffix);
    }
    output
}

fn truncate(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use super::{
        redact_body, redact_body_with_secrets, redact_headers, redact_url_with_secrets,
        response_evidence,
    };
    use crate::ObservedResponse;
    use url::Url;

    #[test]
    fn redacts_secrets_from_headers_and_json() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer secret".to_string()),
            ("Server".to_string(), "example".to_string()),
        ];
        let redacted = redact_headers(&headers);
        assert_eq!(redacted[0].1, "<redacted>");
        assert_eq!(redacted[1].1, "example");

        let body = br#"{"user":"a","token":"super-secret","nested":{"password":"pw"}}"#;
        let text = redact_body(body);
        assert!(!text.contains("super-secret"));
        assert!(!text.contains("pw"));
        assert!(text.contains("<redacted>"));

        let obvious = redact_body(
            b"Authorization: Bearer abc.def.ghi ghp_abcdefghijklmnopqrstuvwxyz github_pat_longvalue sk-secretvalue eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue",
        );
        assert!(!obvious.contains("abc.def.ghi"));
        assert!(!obvious.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!obvious.contains("github_pat_longvalue"));
        assert!(!obvious.contains("sk-secretvalue"));
        assert!(!obvious.contains("eyJhbGci"));

        let echoed = redact_body_with_secrets(
            b"debug echo raw-primary-secret and custom-secret",
            &[
                "raw-primary-secret".to_string(),
                "custom-secret".to_string(),
            ],
        );
        assert!(!echoed.contains("raw-primary-secret"));
        assert!(!echoed.contains("custom-secret"));
        assert!(echoed.matches("<redacted>").count() >= 2);
    }

    #[test]
    fn runtime_request_seed_values_are_redacted_from_query_evidence() {
        let url =
            Url::parse("https://example.test/search?q=Alice&csrf_token=runtime-token&mode=safe")
                .expect("url");
        let safe =
            redact_url_with_secrets(&url, &["Alice".to_string(), "runtime-token".to_string()]);
        assert!(!safe.contains("Alice"));
        assert!(!safe.contains("runtime-token"));
        assert!(safe.contains("q=%3Credacted%3E"));
        assert!(safe.contains("csrf_token=%3Credacted%3E"));
        assert!(safe.contains("mode=safe"));

        let response = ObservedResponse {
            status: 200,
            headers: vec![],
            content_type: Some("text/plain".into()),
            location: None,
            body: b"ok".to_vec(),
            elapsed_ms: 1,
            truncated: false,
            redaction_secrets: vec!["Alice".into(), "runtime-token".into()],
        };
        let evidence = response_evidence("seeded", "GET", &url, &response);
        let request_url = evidence.request_metadata["url"]
            .as_str()
            .expect("request URL");
        assert!(!request_url.contains("Alice"));
        assert!(!request_url.contains("runtime-token"));
    }

    #[test]
    fn omits_binary_body_excerpts_and_redacts_direct_pii_fields() {
        let url = Url::parse("https://example.test/profile").expect("url");
        let binary = ObservedResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "image/png".into())],
            content_type: Some("image/png".into()),
            location: None,
            body: vec![0, 1, 2, 3, 4],
            elapsed_ms: 5,
            truncated: false,
            redaction_secrets: Vec::new(),
        };
        let binary_evidence = response_evidence("binary", "GET", &url, &binary);
        assert!(binary_evidence.response_metadata["body_excerpt"].is_null());
        assert!(binary_evidence.response_metadata["body_sha256"].is_string());

        let json = ObservedResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            content_type: Some("application/json".into()),
            location: None,
            body: br#"{"email":"user@example.test","phone":"+15551234567","ok":true}"#.to_vec(),
            elapsed_ms: 7,
            truncated: false,
            redaction_secrets: Vec::new(),
        };
        let json_evidence = response_evidence("json", "GET", &url, &json);
        let excerpt = json_evidence.response_metadata["body_excerpt"]
            .as_str()
            .expect("text excerpt");
        assert!(!excerpt.contains("user@example.test"));
        assert!(!excerpt.contains("+15551234567"));
        assert!(excerpt.contains("<redacted>"));
    }
}
