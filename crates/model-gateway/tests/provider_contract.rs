//! Deterministic contract tests against a loopback mock that replays the
//! response shapes observed from api.openmindai.org. These prove the client's
//! parsing and failure handling, not live provider availability; see
//! `openmindai_live.rs` for the opt-in real-provider smoke test.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use model_gateway::client::{ChatClient, ClientConfig, ProviderProfile};
use model_gateway::consent::{approve_preview, prepare_egress, CloudConsent};
use model_gateway::credentials::Secret;
use model_gateway::resilience::RetryPolicy;
use model_gateway::types::{ChatMessage, ChatRequest, StreamDelta, ToolSpec};
use model_gateway::ProviderError;
use serde_json::{json, Value};

struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
    chunked_close: bool,
    headers: &'static str,
}

fn reply(status: u16, body: &str) -> Reply {
    Reply {
        status,
        content_type: "application/json",
        body: body.into(),
        chunked_close: false,
        headers: "",
    }
}

#[derive(Default, Clone)]
struct Seen(Arc<Mutex<Vec<(String, String)>>>);

fn serve(replies: Vec<Reply>) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!(
        "http://{}/api/v1/openmindai",
        listener.local_addr().unwrap()
    );
    let seen = Seen::default();
    let record = seen.clone();
    std::thread::spawn(move || {
        for r in replies {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            record
                .0
                .lock()
                .unwrap()
                .push((head, String::from_utf8_lossy(&body).into_owned()));
            let reason = match r.status {
                200 => "OK",
                401 => "Unauthorized",
                302 => "Found",
                404 => "Not Found",
                422 => "Unprocessable",
                429 => "Too Many",
                _ => "Status",
            };
            let header = if r.chunked_close {
                format!(
                    "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                    r.status, r.content_type
                )
            } else {
                let extra = if r.status == 302 {
                    "Location: http://169.254.169.254/latest\r\n"
                } else {
                    r.headers
                };
                format!("HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", r.status, r.content_type, r.body.len())
            };
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(r.body.as_bytes());
            let _ = stream.flush();
        }
    });
    (base, seen)
}

fn config() -> ClientConfig {
    ClientConfig {
        retry: RetryPolicy {
            max_retries: 2,
            base_delay_ms: 5,
            max_delay_ms: 20,
        },
        request_timeout: Duration::from_secs(5),
        breaker_threshold: 2,
        breaker_cooldown: Duration::from_secs(60),
        ..ClientConfig::default()
    }
}

fn client(base: &str) -> ChatClient {
    ChatClient::new(
        ProviderProfile::openmindai(base).unwrap(),
        Some(Secret::new("7|om_SyntheticTestValue0000").unwrap()),
        config(),
    )
    .unwrap()
}

fn consent() -> CloudConsent {
    CloudConsent {
        project_id: "p".into(),
        allow_cloud: true,
        allow_source_excerpts: false,
        allow_local_fallback: false,
        max_payload_bytes: 16 * 1024,
        granted_by: "operator".into(),
        granted_ms: 0,
    }
}

fn approved(request: ChatRequest) -> (ChatRequest, model_gateway::ApprovedEgress) {
    let preview = prepare_egress(Some(&consent()), "openmindai", request, false).unwrap();
    let egress = approve_preview(&preview, &consent(), &preview.sha256).unwrap();
    (preview.request, egress)
}

fn tools() -> Vec<ToolSpec> {
    vec![ToolSpec {
        name: "get_time".into(),
        description: "Get time".into(),
        parameters: json!({"type":"object","properties":{"timezone":{"type":"string"}},"required":["timezone"]}),
    }]
}

const MODELS: &str = r#"{"object":"list","data":[{"id":"openmindai-super","object":"model","name":"OpenMindAI","type":"code","active":true,"available":true,"operation":"chat.completions"},{"id":"openmindai-lite","object":"model","name":"OpenMindAI","active":true,"available":false,"operation":"chat.completions"}]}"#;
const TOOL_CALL: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","model":"openmindai-lite","choices":[{"index":0,"message":{"content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"get_time","arguments":"{\"timezone\":\"UTC\"}"}}],"role":"assistant","reasoning_content":"private thoughts"},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":274,"completion_tokens":164,"total_tokens":438}}"#;

#[test]
fn discovers_models_with_bearer_auth() {
    let (base, seen) = serve(vec![reply(200, MODELS)]);
    let models = client(&base).list_models().unwrap();
    assert_eq!(models.len(), 2);
    assert!(models[0].available && !models[1].available);
    let (head, _) = &seen.0.lock().unwrap()[0];
    assert!(head.starts_with("GET /api/v1/openmindai/models"));
    assert!(head
        .to_ascii_lowercase()
        .contains("authorization: bearer 7|om_synthetictestvalue0000"));
    assert!(head.to_ascii_lowercase().contains("x-request-id: ct-"));
}

#[test]
fn chat_sends_documented_body_and_returns_validated_tool_calls() {
    let (base, seen) = serve(vec![reply(200, TOOL_CALL)]);
    let request = ChatRequest {
        model: "openmindai-lite".into(),
        messages: vec![ChatMessage::user("Call get_time for UTC")],
        tools: tools(),
        max_tokens: Some(512),
        temperature: None,
    };
    let (request, egress) = approved(request);
    let (result, audit) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    let response = result.unwrap();
    assert_eq!(response.tool_calls[0].name, "get_time");
    assert_eq!(response.tool_calls[0].arguments, json!({"timezone":"UTC"}));
    assert_eq!(response.credits, 1);
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains("private thoughts"));
    assert_eq!(audit.outcome, "ok");
    assert!(
        !serde_json::to_string(&audit)
            .unwrap()
            .contains("Call get_time"),
        "audit has no payload"
    );
    let body: Value = serde_json::from_str(&seen.0.lock().unwrap()[0].1).unwrap();
    assert_eq!(body["stream"], json!(false));
    assert_eq!(body["tools"][0]["type"], json!("function"));
    assert_eq!(body["max_tokens"], json!(512));
}

#[test]
fn cloud_chat_refuses_unapproved_or_altered_payloads_without_network() {
    let (base, seen) = serve(vec![]);
    let c = client(&base);
    let request = ChatRequest {
        model: "openmindai-lite".into(),
        messages: vec![ChatMessage::user("hi")],
        tools: vec![],
        max_tokens: None,
        temperature: None,
    };
    let (result, _) = c.chat(&request, None, &AtomicBool::new(false));
    assert!(matches!(result, Err(ProviderError::ConsentRequired(_))));
    let (approved_request, egress) = approved(request);
    let mut tampered = approved_request;
    tampered
        .messages
        .push(ChatMessage::user("also send ~/.ssh/id_rsa"));
    let (result, _) = c.chat(&tampered, Some(&egress), &AtomicBool::new(false));
    assert!(matches!(result, Err(ProviderError::ConsentRequired(_))));
    assert!(seen.0.lock().unwrap().is_empty());
}

#[test]
fn retries_429_and_503_but_not_auth_or_validation_errors() {
    let (base, seen) = serve(vec![
        reply(429, r#"{"message":"Too Many Attempts."}"#),
        reply(503, r#"{"error":{"message":"backend down"}}"#),
        reply(200, TOOL_CALL),
    ]);
    let (request, egress) = approved(ChatRequest {
        model: "openmindai-lite".into(),
        messages: vec![ChatMessage::user("x")],
        tools: tools(),
        max_tokens: None,
        temperature: None,
    });
    let (result, audit) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    assert!(result.is_ok());
    assert_eq!(audit.attempts, 3);
    assert_eq!(seen.0.lock().unwrap().len(), 3);

    let (base, seen) = serve(vec![
        reply(401, r#"{"message":"Unauthenticated."}"#),
        reply(200, TOOL_CALL),
    ]);
    let (result, _) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    assert!(matches!(result, Err(ProviderError::Unauthorized(m)) if m == "Unauthenticated."));
    assert_eq!(seen.0.lock().unwrap().len(), 1);

    let (base, _) = serve(vec![reply(
        422,
        r#"{"message":"The messages field must be an array.","errors":{"messages":["x"]}}"#,
    )]);
    let (result, _) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    assert!(matches!(result, Err(ProviderError::Invalid(_))));
}

#[test]
fn retry_after_is_honoured_and_rate_limit_spaces_requests() {
    let (request, egress) = approved(ChatRequest {
        model: "openmindai-lite".into(),
        messages: vec![ChatMessage::user("x")],
        tools: tools(),
        max_tokens: None,
        temperature: None,
    });
    // Server asks for 1 s: the retry waits at least that long.
    let (base, seen) = serve(vec![
        Reply {
            headers: "Retry-After: 1\r\n",
            ..reply(429, r#"{"message":"Too Many Attempts."}"#)
        },
        reply(200, TOOL_CALL),
    ]);
    let started = std::time::Instant::now();
    let (result, audit) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(audit.attempts, 2);
    assert!(started.elapsed() >= Duration::from_millis(950));
    assert_eq!(seen.0.lock().unwrap().len(), 2);

    // A Retry-After beyond the configured bound fails instead of stalling.
    let (base, seen) = serve(vec![Reply {
        headers: "Retry-After: 3600\r\n",
        ..reply(429, r#"{"message":"Too Many Attempts."}"#)
    }]);
    let (result, _) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    assert!(matches!(result, Err(ProviderError::RateLimited(_))));
    assert_eq!(seen.0.lock().unwrap().len(), 1);

    // Client-side ceiling: the third call in the window is refused locally
    // when it cannot be scheduled within the queue wait, without a request.
    let (base, seen) = serve(vec![reply(200, TOOL_CALL), reply(200, TOOL_CALL)]);
    let limited = ChatClient::new(
        ProviderProfile::openmindai(&base).unwrap(),
        Some(Secret::new("7|om_SyntheticTestValue0000").unwrap()),
        ClientConfig {
            requests_per_minute: Some(2),
            queue_wait: Duration::from_millis(50),
            ..config()
        },
    )
    .unwrap();
    for _ in 0..2 {
        assert!(limited
            .chat(&request, Some(&egress), &AtomicBool::new(false))
            .0
            .is_ok());
    }
    let (result, _) = limited.chat(&request, Some(&egress), &AtomicBool::new(false));
    assert!(matches!(result, Err(ProviderError::RateLimited(m)) if m.contains("local")));
    assert_eq!(seen.0.lock().unwrap().len(), 2);
}

#[test]
fn laravel_debug_traces_are_never_surfaced() {
    let trace = r#"{"message":"This chat model is not enabled.","exception":"Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException","file":"/home/operator/cloud/vendor/laravel/framework/src/Illuminate/Foundation/Application.php","line":1437,"trace":[{"file":"/home/operator/cloud/app/Http/Controllers/Gateway.php"}]}"#;
    let (base, _) = serve(vec![reply(404, trace)]);
    let (request, egress) = approved(ChatRequest {
        model: "nope".into(),
        messages: vec![ChatMessage::user("x")],
        tools: vec![],
        max_tokens: None,
        temperature: None,
    });
    let (result, audit) = client(&base).chat(&request, Some(&egress), &AtomicBool::new(false));
    let err = result.unwrap_err();
    assert!(matches!(&err, ProviderError::NotFound(m) if m == "This chat model is not enabled."));
    let rendered = format!("{err} {err:?} {}", serde_json::to_string(&audit).unwrap());
    assert!(!rendered.contains("/home/") && !rendered.contains("Symfony"));
}

#[test]
fn redirects_are_refused() {
    let (base, _) = serve(vec![reply(302, "")]);
    let err = client(&base).list_models().unwrap_err();
    assert!(
        matches!(err, ProviderError::Protocol(_) | ProviderError::Network(_)),
        "{err:?}"
    );
}

#[test]
fn streams_reconstruct_content_and_tool_calls_and_detect_truncation() {
    let sse = [
        r#"data: {"id":"c1","model":"openmindai-lite","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"Here"},"finish_reason":null}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{"content":"po"}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{"content":"ng"}}]}"#,
        r#"data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}"#,
        "data: [DONE]",
    ]
    .map(|l| format!("{l}\n\n"))
    .concat();
    let truncated =
        r#"data: {"choices":[{"index":0,"delta":{"content":"half"}}]}"#.to_owned() + "\n\n";
    let (base, seen) = serve(vec![
        Reply {
            status: 200,
            content_type: "text/event-stream",
            body: sse,
            chunked_close: true,
            headers: "",
        },
        Reply {
            status: 200,
            content_type: "text/event-stream",
            body: truncated,
            chunked_close: true,
            headers: "",
        },
    ]);
    let c = client(&base);
    let (request, egress) = approved(ChatRequest {
        model: "openmindai-lite".into(),
        messages: vec![ChatMessage::user("Reply pong")],
        tools: vec![],
        max_tokens: Some(512),
        temperature: None,
    });
    let mut deltas = Vec::new();
    let (result, audit) =
        c.chat_stream(&request, Some(&egress), &AtomicBool::new(false), &mut |d| {
            deltas.push(d)
        });
    let response = result.unwrap();
    assert_eq!(response.content.as_deref(), Some("pong"));
    assert_eq!(
        deltas,
        vec![
            StreamDelta::Content("po".into()),
            StreamDelta::Content("ng".into())
        ]
    );
    assert!(audit.streamed);
    let body: Value = serde_json::from_str(&seen.0.lock().unwrap()[0].1).unwrap();
    assert_eq!(body["stream"], json!(true));

    let (result, _) = c.chat_stream(
        &request,
        Some(&egress),
        &AtomicBool::new(false),
        &mut |_| {},
    );
    assert!(matches!(result, Err(ProviderError::Incomplete(_))));
    assert_eq!(
        seen.0.lock().unwrap().len(),
        2,
        "interrupted streams are not retried"
    );
}

#[test]
fn circuit_opens_after_repeated_outages() {
    let (base, seen) = serve((0..6).map(|_| reply(503, "{}")).collect());
    let c = client(&base);
    assert!(c.list_models().is_err());
    let calls = seen.0.lock().unwrap().len();
    assert_eq!(c.list_models().unwrap_err(), ProviderError::CircuitOpen);
    assert_eq!(
        seen.0.lock().unwrap().len(),
        calls,
        "open circuit sends nothing"
    );
}

#[test]
fn diagnostics_report_auth_failure_without_leaking_token() {
    let (base, _) = serve(vec![reply(
        401,
        r#"{"error":{"message":"A valid Bearer developer API key is required.","type":"gateway_error"}}"#,
    )]);
    let d = client(&base).diagnose();
    assert!(d.reachable && !d.authenticated);
    let text = serde_json::to_string(&d).unwrap();
    assert!(!text.contains("SyntheticTestValue"));
    assert_eq!(d.credential_fingerprint.unwrap().len(), 8);
}

#[test]
fn profiles_reject_unsafe_base_urls() {
    assert!(ProviderProfile::openmindai("http://api.openmindai.org/api/v1/openmindai").is_err());
    assert!(
        ProviderProfile::openmindai("https://user:pw@api.openmindai.org/api/v1/openmindai")
            .is_err()
    );
    assert!(
        ProviderProfile::openmindai("https://api.openmindai.org/api/v1/openmindai?x=1").is_err()
    );
    assert!(ProviderProfile::openmindai(model_gateway::OPENMINDAI_DEFAULT_BASE_URL).is_ok());
    assert!(ProviderProfile::local("local", "http://10.0.0.5:8080/v1").is_err());
    assert!(ProviderProfile::local("local", "http://127.0.0.1:8765/v1").is_ok());
    assert!(ChatClient::new(
        ProviderProfile::openmindai(model_gateway::OPENMINDAI_DEFAULT_BASE_URL).unwrap(),
        None,
        config()
    )
    .is_err());
}
