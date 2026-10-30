//! Cloud disclosure consent, previews and approved-egress tokens.
//!
//! Nothing reaches a cloud provider unless (1) the project has explicit cloud
//! consent, (2) the exact redacted payload was previewed, and (3) the caller
//! holds an [`ApprovedEgress`] whose digest matches the bytes being sent.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ProviderError;
use crate::redact::redact;
use crate::types::ChatRequest;

pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 24 * 1024;
pub const HARD_MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// Per-project consent recorded by an operator. Persisted by `codetwin-core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudConsent {
    pub project_id: String,
    /// Master switch; false means offline-only for this project.
    pub allow_cloud: bool,
    /// Whether redacted source excerpts may be included at all.
    pub allow_source_excerpts: bool,
    /// Whether a failed cloud call may fall back to the local model.
    pub allow_local_fallback: bool,
    pub max_payload_bytes: usize,
    pub granted_by: String,
    pub granted_ms: i64,
}

/// What the operator is shown before anything is transmitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EgressPreview {
    pub provider: String,
    pub model: String,
    /// The exact redacted request that would be sent.
    pub request: ChatRequest,
    pub bytes: usize,
    pub redactions: usize,
    pub contains_source: bool,
    pub sha256: String,
}

/// Proof that a specific preview was approved. Only constructible through
/// [`approve_preview`], and only valid for the identical payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedEgress {
    sha256: String,
    project_id: String,
}

impl ApprovedEgress {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }
}

pub fn payload_digest(request: &ChatRequest) -> String {
    let bytes = serde_json::to_vec(request).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Redact and bound a request, producing the preview the operator approves.
pub fn prepare_egress(
    consent: Option<&CloudConsent>,
    provider: &str,
    mut request: ChatRequest,
    contains_source: bool,
) -> Result<EgressPreview, ProviderError> {
    let consent = consent.ok_or_else(|| {
        ProviderError::ConsentRequired(
            "no cloud disclosure consent recorded for this project".into(),
        )
    })?;
    if !consent.allow_cloud {
        return Err(ProviderError::ConsentRequired(
            "project is offline-only".into(),
        ));
    }
    if contains_source && !consent.allow_source_excerpts {
        return Err(ProviderError::ConsentRequired(
            "consent does not cover source excerpts".into(),
        ));
    }
    let mut redactions = 0;
    for message in &mut request.messages {
        if let Some(content) = &message.content {
            let (clean, n) = redact(content);
            redactions += n;
            message.content = Some(clean);
        }
        for call in &mut message.tool_calls {
            let (clean, n) = redact(&call.function.arguments);
            redactions += n;
            call.function.arguments = clean;
        }
    }
    let bytes = serde_json::to_vec(&request)
        .map_err(|e| ProviderError::Config(e.to_string()))?
        .len();
    let limit = consent.max_payload_bytes.min(HARD_MAX_PAYLOAD_BYTES);
    if bytes > limit {
        return Err(ProviderError::PayloadTooLarge(bytes));
    }
    Ok(EgressPreview {
        provider: provider.to_owned(),
        model: request.model.clone(),
        sha256: payload_digest(&request),
        request,
        bytes,
        redactions,
        contains_source,
    })
}

/// Operator approval of a preview. `confirmed_sha256` must be the digest the
/// operator saw; this binds approval to exact bytes.
pub fn approve_preview(
    preview: &EgressPreview,
    consent: &CloudConsent,
    confirmed_sha256: &str,
) -> Result<ApprovedEgress, ProviderError> {
    if !consent.allow_cloud {
        return Err(ProviderError::ConsentRequired("consent was revoked".into()));
    }
    if preview.sha256 != confirmed_sha256 || payload_digest(&preview.request) != preview.sha256 {
        return Err(ProviderError::ConsentRequired(
            "approved digest does not match the payload".into(),
        ));
    }
    Ok(ApprovedEgress {
        sha256: preview.sha256.clone(),
        project_id: consent.project_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChatMessage;

    fn consent() -> CloudConsent {
        CloudConsent {
            project_id: "p".into(),
            allow_cloud: true,
            allow_source_excerpts: false,
            allow_local_fallback: false,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            granted_by: "operator".into(),
            granted_ms: 0,
        }
    }

    fn request(text: &str) -> ChatRequest {
        ChatRequest {
            model: "openmindai-lite".into(),
            messages: vec![ChatMessage::user(text)],
            tools: vec![],
            max_tokens: Some(256),
            temperature: None,
        }
    }

    #[test]
    fn offline_and_missing_consent_fail_closed() {
        assert!(prepare_egress(None, "openmindai", request("hi"), false).is_err());
        let off = CloudConsent {
            allow_cloud: false,
            ..consent()
        };
        assert!(prepare_egress(Some(&off), "openmindai", request("hi"), false).is_err());
        assert!(
            prepare_egress(Some(&consent()), "openmindai", request("hi"), true).is_err(),
            "source needs explicit scope"
        );
    }

    #[test]
    fn previews_are_redacted_bounded_and_digest_bound() {
        let p = prepare_egress(
            Some(&consent()),
            "openmindai",
            request("token=abcdef123456 hello"),
            false,
        )
        .unwrap();
        assert_eq!(p.redactions, 1);
        assert!(!serde_json::to_string(&p.request)
            .unwrap()
            .contains("abcdef123456"));
        assert!(approve_preview(&p, &consent(), "deadbeef").is_err());
        let ok = approve_preview(&p, &consent(), &p.sha256).unwrap();
        assert_eq!(ok.sha256(), p.sha256);
        let revoked = CloudConsent {
            allow_cloud: false,
            ..consent()
        };
        assert!(approve_preview(&p, &revoked, &p.sha256).is_err());
        let small = CloudConsent {
            max_payload_bytes: 64,
            ..consent()
        };
        assert!(matches!(
            prepare_egress(Some(&small), "openmindai", request(&"x".repeat(500)), false),
            Err(ProviderError::PayloadTooLarge(_))
        ));
    }
}
