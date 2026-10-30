//! Opt-in live smoke test against the real OpenMindAI Cloud API.
//!
//! Runs only when `CODETWIN_TEST_OPENMINDAI_LIVE=1` and `OPENMINDAI_API_KEY`
//! are set (optionally `OPENMINDAI_BASE_URL`, `OPENMINDAI_TEST_MODEL`). It
//! sends a fixed, non-sensitive fixture prompt — never project content — and
//! spends a few application credits. Not part of default CI.
use std::sync::atomic::AtomicBool;

use model_gateway::client::{ChatClient, ClientConfig, ProviderProfile};
use model_gateway::consent::{approve_preview, prepare_egress, CloudConsent};
use model_gateway::credentials::{CredentialStore, EnvCredentialStore};
use model_gateway::types::{ChatMessage, ChatRequest, ToolSpec};
use serde_json::json;

fn live() -> Option<ChatClient> {
    if std::env::var("CODETWIN_TEST_OPENMINDAI_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set CODETWIN_TEST_OPENMINDAI_LIVE=1 and OPENMINDAI_API_KEY to run");
        return None;
    }
    let secret = EnvCredentialStore {
        variable: "OPENMINDAI_API_KEY".into(),
    }
    .get("openmindai")
    .expect("read env")
    .expect("OPENMINDAI_API_KEY must be set for the live test");
    let base = std::env::var("OPENMINDAI_BASE_URL")
        .unwrap_or_else(|_| model_gateway::OPENMINDAI_DEFAULT_BASE_URL.into());
    Some(
        ChatClient::new(
            ProviderProfile::openmindai(&base).unwrap(),
            Some(secret),
            ClientConfig::default(),
        )
        .unwrap(),
    )
}

fn consent() -> CloudConsent {
    CloudConsent {
        project_id: "live-fixture".into(),
        allow_cloud: true,
        allow_source_excerpts: false,
        allow_local_fallback: false,
        max_payload_bytes: 8 * 1024,
        granted_by: "ci-operator".into(),
        granted_ms: 0,
    }
}

fn model() -> String {
    std::env::var("OPENMINDAI_TEST_MODEL").unwrap_or_else(|_| "openmindai-lite".into())
}

#[test]
fn live_model_discovery_chat_tools_and_stream() {
    let Some(client) = live() else { return };
    let diagnostics = client.diagnose();
    assert!(
        diagnostics.authenticated,
        "diagnostics: {:?}",
        diagnostics.error
    );
    assert!(
        diagnostics.models.iter().any(|m| m.id == model()),
        "model {} not listed",
        model()
    );
    let catalog = client.catalog().expect("catalog");
    assert!(!catalog.is_empty());

    // The provider spends tokens on hidden reasoning, so give it room.
    let chat = ChatRequest {
        model: model(),
        messages: vec![ChatMessage::user("Reply with exactly the word: pong")],
        tools: vec![],
        max_tokens: Some(1024),
        temperature: None,
    };
    let preview = prepare_egress(Some(&consent()), "openmindai", chat, false).unwrap();
    let egress = approve_preview(&preview, &consent(), &preview.sha256).unwrap();
    let (result, audit) = client.chat(&preview.request, Some(&egress), &AtomicBool::new(false));
    let response = result.expect("live chat");
    eprintln!("chat audit: {audit:?}");
    assert!(response
        .content
        .unwrap_or_default()
        .to_lowercase()
        .contains("pong"));

    let tools = vec![ToolSpec {
        name: "get_time".into(),
        description: "Get the current time".into(),
        parameters: json!({"type":"object","properties":{"timezone":{"type":"string"}},"required":["timezone"]}),
    }];
    let tool_req = ChatRequest {
        model: model(),
        messages: vec![ChatMessage::user(
            "Call the get_time tool for timezone UTC.",
        )],
        tools,
        max_tokens: Some(1024),
        temperature: None,
    };
    let preview = prepare_egress(Some(&consent()), "openmindai", tool_req, false).unwrap();
    let egress = approve_preview(&preview, &consent(), &preview.sha256).unwrap();
    let (result, _) = client.chat(&preview.request, Some(&egress), &AtomicBool::new(false));
    let response = result.expect("live tool call");
    assert_eq!(
        response.tool_calls.first().map(|c| c.name.as_str()),
        Some("get_time")
    );

    let stream_req = ChatRequest {
        model: model(),
        messages: vec![ChatMessage::user("Reply with exactly: pong")],
        tools: vec![],
        max_tokens: Some(1024),
        temperature: None,
    };
    let preview = prepare_egress(Some(&consent()), "openmindai", stream_req, false).unwrap();
    let egress = approve_preview(&preview, &consent(), &preview.sha256).unwrap();
    let mut deltas = 0;
    let (result, _) = client.chat_stream(
        &preview.request,
        Some(&egress),
        &AtomicBool::new(false),
        &mut |_| deltas += 1,
    );
    let response = result.expect("live stream");
    assert!(response.streamed && deltas > 0);
    assert!(response
        .content
        .unwrap_or_default()
        .to_lowercase()
        .contains("pong"));
}
