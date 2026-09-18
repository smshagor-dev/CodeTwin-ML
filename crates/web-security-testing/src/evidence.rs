use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{EvidenceObservation, ObservedResponse};

const SENSITIVE_KEYS: &[&str] = &[
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "api-key", "apikey", "password", "passwd", "secret", "token", "access_token",
    "refresh_token", "session", "sessionid",
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
    let mut safe = url.clone();
    let pairs: Vec<(String, String)> = safe
        .query_pairs()
        .map(|(name, value)| {
            let value = if is_sensitive_name(&name) {
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
    EvidenceObservation {
        summary: format!(
            "{label}: {method} {} -> HTTP {} in {} ms",
            redact_url(url),
            response.status,
            response.elapsed_ms
        ),
        request_metadata: serde_json::json!({
            "method": method,
            "url": redact_url(url),
        }),
        response_metadata: serde_json::json!({
            "status": response.status,
            "elapsed_ms": response.elapsed_ms,
            "content_type": response.content_type,
            "body_sha256": body_hash(&response.body),
            "body_bytes": response.body.len(),
            "headers": redact_headers(&response.headers),
            "body_excerpt": redact_body(&response.body),
            "truncated": response.truncated,
        }),
    }
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
    output
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

fn truncate(value: &str, max: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() { format!("{prefix}…") } else { prefix }
}

#[cfg(test)]
mod tests {
    use super::{redact_body, redact_headers};

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
        assert!(!text.contains(""pw""));
        assert!(text.contains("<redacted>"));
    }
}
