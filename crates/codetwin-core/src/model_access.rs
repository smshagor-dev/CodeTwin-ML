//! Role-aware model access for workflow planning and workers.
//!
//! * Each specialist role may name its own cloud and local model
//!   ([`RoleModels`]); unnamed roles use the provider defaults.
//! * Cloud calls need project consent, are redacted and bounded through
//!   [`prepare_egress`], and are audited in `provider_requests`.
//! * A failed cloud call falls back to the loopback local model only when the
//!   project consent allows it and the failure is an infrastructure failure
//!   (timeouts, 429/5xx, open circuit). Never local → cloud.
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use model_gateway::router::{choose_route, fallback_after, RoleModels, Route, RoutingInput};
use model_gateway::types::Usage;
use model_gateway::{
    approve_preview, prepare_egress, ChatClient, ChatMessage, ChatRequest, CloudConsent,
    ProposedToolCall, ProviderError, ToolSpec,
};
use serde::{Deserialize, Serialize};

use crate::cloud_settings::CloudSettings;
use crate::Database;

pub const DEFAULT_CLOUD_MODEL: &str = "openmindai-lite";
pub const DEFAULT_LOCAL_MODEL: &str = "local";

#[derive(Clone)]
pub struct CloudRoute {
    pub client: Arc<ChatClient>,
    pub consent: CloudConsent,
}

#[derive(Clone, Default)]
pub struct ModelAccess {
    pub cloud: Option<CloudRoute>,
    pub local: Option<Arc<ChatClient>>,
    pub role_models: RoleModels,
}

/// Who is calling, for model selection and the audit trail.
#[derive(Debug, Clone, Copy)]
pub struct CallScope<'a> {
    pub project_id: &'a str,
    pub run_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
    pub role: &'a str,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelReply {
    pub content: String,
    pub provider: String,
    pub model: String,
    pub route: Route,
    pub request_id: String,
    /// Digest of the exact (redacted) cloud payload; `None` for local calls.
    pub payload_sha256: Option<String>,
    pub redactions: usize,
    pub credits: u32,
    pub usage: Option<Usage>,
    /// Set when the cloud call failed and the local model answered instead.
    pub fallback_reason: Option<String>,
    /// Provider stop reason (`stop`, `length`, `tool_calls`, …).
    pub finish_reason: Option<String>,
    /// Tool calls naming a declared tool with object arguments (unexecuted).
    pub tool_calls: Vec<ProposedToolCall>,
    /// Hidden reasoning characters received and discarded (count only).
    pub reasoning_chars_discarded: usize,
}

/// One model call: messages, optional declared tools, and output budget.
#[derive(Debug, Clone)]
pub struct ChatCall {
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
    pub temperature: f32,
    /// Stream the completion so cancellation is observed during long
    /// reasoning; streams are never retried once bytes arrived.
    pub stream: bool,
}

/// A failed call: the classified error of the last route tried, plus a
/// human-readable account of every route.
#[derive(Debug, Clone)]
pub struct CallFailure {
    pub error: ProviderError,
    pub detail: String,
}

impl std::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl ModelAccess {
    pub fn is_configured(&self) -> bool {
        self.cloud.is_some() || self.local.is_some()
    }

    pub fn model_for(&self, role: &str, route: Route) -> String {
        self.role_models
            .model_for(role, route)
            .map(str::to_owned)
            .unwrap_or_else(|| match route {
                Route::Cloud => DEFAULT_CLOUD_MODEL.into(),
                Route::Local => DEFAULT_LOCAL_MODEL.into(),
            })
    }

    fn routing(&self) -> RoutingInput<'_> {
        RoutingInput {
            preferred: if self.cloud.is_some() {
                Route::Cloud
            } else {
                Route::Local
            },
            consent: self.cloud.as_ref().map(|c| &c.consent),
            local_configured: self.local.is_some(),
            cloud_configured: self.cloud.is_some(),
        }
    }

    /// One completion for `scope.role`, with consented fallback.
    pub fn chat(
        &self,
        db: &Database,
        scope: CallScope<'_>,
        messages: Vec<ChatMessage>,
        max_tokens: u32,
        temperature: f32,
        cancel: &AtomicBool,
    ) -> Result<ModelReply, String> {
        self.complete(
            db,
            scope,
            &ChatCall {
                messages,
                tools: vec![],
                max_tokens,
                temperature,
                stream: false,
            },
            cancel,
        )
        .map_err(|f| f.detail)
    }

    /// One completion with declared tools and an explicit output budget.
    pub fn complete(
        &self,
        db: &Database,
        scope: CallScope<'_>,
        call: &ChatCall,
        cancel: &AtomicBool,
    ) -> Result<ModelReply, CallFailure> {
        let routing = self.routing();
        let route = choose_route(&routing).map_err(|e| CallFailure {
            detail: e.to_string(),
            error: e,
        })?;
        let request = |route| ChatRequest {
            model: self.model_for(scope.role, route),
            messages: call.messages.clone(),
            tools: call.tools.clone(),
            max_tokens: Some(call.max_tokens),
            temperature: Some(call.temperature),
        };
        match self.call(db, scope, route, request(route), call.stream, cancel) {
            Ok(reply) => Ok(reply),
            Err(error) => match fallback_after(route, &error, &routing) {
                Some(Route::Local) => {
                    let mut reply = self
                        .call(
                            db,
                            scope,
                            Route::Local,
                            request(Route::Local),
                            call.stream,
                            cancel,
                        )
                        .map_err(|e| CallFailure {
                            detail: format!("cloud failed ({error}); local fallback failed ({e})"),
                            error: e,
                        })?;
                    reply.fallback_reason = Some(error.to_string());
                    Ok(reply)
                }
                _ => Err(CallFailure {
                    detail: error.to_string(),
                    error,
                }),
            },
        }
    }

    fn call(
        &self,
        db: &Database,
        scope: CallScope<'_>,
        route: Route,
        request: ChatRequest,
        stream: bool,
        cancel: &AtomicBool,
    ) -> Result<ModelReply, ProviderError> {
        let (client, request, egress, redactions) = match route {
            Route::Cloud => {
                let cloud = self
                    .cloud
                    .as_ref()
                    .ok_or_else(|| ProviderError::Config("cloud not configured".into()))?;
                let preview = prepare_egress(Some(&cloud.consent), "openmindai", request, false)?;
                // The operator's plan/task approval covers payloads inside the
                // consented scope; the exact digest is kept in the audit row.
                let egress = approve_preview(&preview, &cloud.consent, &preview.sha256)?;
                (
                    &cloud.client,
                    preview.request,
                    Some(egress),
                    preview.redactions,
                )
            }
            Route::Local => {
                let local = self
                    .local
                    .as_ref()
                    .ok_or_else(|| ProviderError::Config("local model not configured".into()))?;
                (local, request, None, 0)
            }
        };
        let (result, audit) = if stream {
            // Visible deltas are not surfaced here; the caller validates the
            // whole answer. Streaming exists for cancellation and timeouts.
            client.chat_stream(&request, egress.as_ref(), cancel, &mut |_| {})
        } else {
            client.chat(&request, egress.as_ref(), cancel)
        };
        let credits = u32::from(route == Route::Cloud && result.is_ok());
        let _ = CloudSettings::new(db).record_request(
            &audit,
            Some(scope.project_id),
            scope.run_id,
            scope.task_id,
            redactions,
            credits,
            result.as_ref().ok().and_then(|r| r.usage.as_ref()),
        );
        let response = result?;
        Ok(ModelReply {
            content: response.content.unwrap_or_default(),
            provider: audit.provider,
            model: response.model,
            route,
            request_id: response.request_id,
            payload_sha256: if route == Route::Cloud {
                audit.payload_sha256
            } else {
                None
            },
            redactions,
            credits,
            usage: response.usage,
            fallback_reason: None,
            finish_reason: response.finish_reason,
            tool_calls: response.tool_calls,
            reasoning_chars_discarded: response.reasoning_chars_discarded,
        })
    }
}
