//! Consent-gated model provider gateway.
//!
//! * [`client`] — chat-completions client (OpenMindAI Cloud, local loopback).
//! * [`consent`] — project disclosure consent, redacted previews, approvals.
//! * [`credentials`] — OS credential store; tokens never touch SQLite.
//! * [`sse`] — response/stream parsing and tool-call validation.
//! * [`resilience`] — retries with jitter, circuit breaker, concurrency.
//! * [`router`] — deterministic local/cloud routing and fallback.
pub mod client;
pub mod consent;
pub mod credentials;
pub mod error;
pub mod redact;
pub mod resilience;
pub mod router;
pub mod sse;
pub mod types;

pub use client::{
    CallAudit, ChatClient, ClientConfig, Diagnostics, ProviderKind, ProviderProfile,
    OPENMINDAI_DEFAULT_BASE_URL,
};
pub use consent::{approve_preview, prepare_egress, ApprovedEgress, CloudConsent, EgressPreview};
pub use credentials::{CredentialStore, KeyringStore, Secret};
pub use error::ProviderError;
pub use types::{
    ChatMessage, ChatRequest, ChatResponse, ModelInfo, ProposedToolCall, StreamDelta, ToolSpec,
};
