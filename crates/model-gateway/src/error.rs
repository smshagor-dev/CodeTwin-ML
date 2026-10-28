//! Provider error taxonomy and bounded error-body parsing.
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum ProviderError {
    #[error("authentication failed: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("model or endpoint not found: {0}")]
    NotFound(String),
    #[error("request rejected: {0}")]
    Invalid(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("provider unavailable (HTTP {0})")]
    Unavailable(u16),
    #[error("timed out")]
    Timeout,
    #[error("network error: {0}")]
    Network(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("incomplete response: {0}")]
    Incomplete(String),
    #[error("circuit open after repeated failures; retry later")]
    CircuitOpen,
    #[error("too many concurrent requests")]
    Saturated,
    #[error("consent required: {0}")]
    ConsentRequired(String),
    #[error("payload of {0} bytes exceeds the approved limit")]
    PayloadTooLarge(usize),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("credential error: {0}")]
    Credential(String),
    #[error("cancelled")]
    Cancelled,
}

impl ProviderError {
    /// Whether a fresh, identical, non-streamed request may be retried.
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited(_) | Self::Unavailable(_) | Self::Timeout | Self::Network(_)
        )
    }

    /// Whether this failure counts toward opening the circuit breaker.
    pub const fn trips_breaker(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_) | Self::Timeout | Self::Network(_)
        )
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::Invalid(_) => "invalid",
            Self::RateLimited(_) => "rate_limited",
            Self::Unavailable(_) => "unavailable",
            Self::Timeout => "timeout",
            Self::Network(_) => "network",
            Self::Protocol(_) => "protocol",
            Self::Incomplete(_) => "incomplete",
            Self::CircuitOpen => "circuit_open",
            Self::Saturated => "saturated",
            Self::ConsentRequired(_) => "consent_required",
            Self::PayloadTooLarge(_) => "payload_too_large",
            Self::Config(_) => "config",
            Self::Credential(_) => "credential",
            Self::Cancelled => "cancelled",
        }
    }
}

const MAX_MESSAGE: usize = 200;

/// Extract a short, safe message from an error body. OpenMindAI returns
/// `{"error":{"message":…}}` from the portal gateway, `{"message":…}` from the
/// backend and may include framework debug fields (`exception`, `file`,
/// `trace`); those are never read, logged or surfaced.
pub fn error_message(body: &[u8]) -> String {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let message = parsed.as_ref().and_then(|v| {
        v.get("error")
            .and_then(|e| e.get("message").or(Some(e)))
            .and_then(serde_json::Value::as_str)
            .or_else(|| v.get("message").and_then(serde_json::Value::as_str))
    });
    let text = message.unwrap_or("provider returned an error without a readable message");
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_MESSAGE)
        .collect();
    cleaned
}

pub fn from_status(status: u16, body: &[u8]) -> ProviderError {
    let message = error_message(body);
    match status {
        401 => ProviderError::Unauthorized(message),
        403 => ProviderError::Forbidden(message),
        404 => ProviderError::NotFound(message),
        400 | 413 | 422 => ProviderError::Invalid(message),
        429 => ProviderError::RateLimited(message),
        408 | 504 => ProviderError::Timeout,
        500..=599 => ProviderError::Unavailable(status),
        _ => ProviderError::Protocol(format!("unexpected HTTP {status}: {message}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_documented_statuses() {
        assert!(matches!(
            from_status(401, b"{}"),
            ProviderError::Unauthorized(_)
        ));
        assert!(matches!(
            from_status(403, b"{}"),
            ProviderError::Forbidden(_)
        ));
        assert!(matches!(
            from_status(404, b"{}"),
            ProviderError::NotFound(_)
        ));
        assert!(matches!(from_status(422, b"{}"), ProviderError::Invalid(_)));
        assert!(matches!(
            from_status(429, b"{}"),
            ProviderError::RateLimited(_)
        ));
        assert_eq!(from_status(502, b""), ProviderError::Unavailable(502));
        assert_eq!(from_status(503, b""), ProviderError::Unavailable(503));
        assert!(from_status(503, b"").retryable());
        assert!(!from_status(401, b"{}").retryable());
        assert!(!from_status(422, b"{}").retryable());
    }

    #[test]
    fn reads_all_observed_error_shapes_and_never_leaks_traces() {
        assert_eq!(
            error_message(br#"{"error":{"message":"A valid Bearer developer API key is required.","type":"gateway_error"}}"#),
            "A valid Bearer developer API key is required."
        );
        assert_eq!(
            error_message(br#"{"message":"Unauthenticated."}"#),
            "Unauthenticated."
        );
        let laravel = br#"{"message":"This chat model is not enabled.","exception":"Symfony\\X","file":"/home/u/app/vendor/x.php","line":1,"trace":[{"file":"/secret/path.php"}]}"#;
        let msg = error_message(laravel);
        assert_eq!(msg, "This chat model is not enabled.");
        assert!(!format!("{:?}", from_status(404, laravel)).contains("/home/"));
        assert!(!error_message(&[b'x'; 10]).is_empty());
        assert!(
            error_message(format!("{{\"message\":\"{}\"}}", "a".repeat(5000)).as_bytes()).len()
                <= 200
        );
    }
}
