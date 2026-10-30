//! Chat-completions HTTP client for OpenMindAI Cloud and local
//! OpenAI-compatible endpoints.
//!
//! OpenMindAI contract (verified against https://api.openmindai.org/docs and
//! live responses on 2026-10-28): base URL `…/api/v1/openmindai`;
//! `Authorization: Bearer <developer key>`; `GET /models`, `GET /catalog`,
//! `POST /chat/completions` with `model`, `messages`, optional `tools`,
//! `stream`, `max_tokens`, `temperature`; native function tool calls (≤64);
//! SSE streams terminated by `data: [DONE]`; errors 401/403/404/422/429/502/503.
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::consent::{payload_digest, ApprovedEgress};
use crate::credentials::Secret;
use crate::error::{from_status, ProviderError};
use crate::resilience::{CircuitBreaker, ConcurrencyLimiter, RateLimiter, RetryPolicy};
use crate::sse::{parse_completion, SseAccumulator};
use crate::types::{ChatRequest, ChatResponse, ModelInfo, StreamDelta};

pub const OPENMINDAI_DEFAULT_BASE_URL: &str = "https://api.openmindai.org/api/v1/openmindai";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Remote provider: requires project consent and an approved preview.
    Cloud,
    /// Loopback-only endpoint on this machine.
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub name: String,
    pub kind: ProviderKind,
    pub base_url: String,
    pub has_catalog: bool,
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Validate a configured base URL: no credentials, query or fragment; cloud
/// providers must use HTTPS (plain HTTP only to loopback, e.g. contract tests);
/// local providers must be loopback.
pub fn validate_base_url(raw: &str, kind: ProviderKind) -> Result<Url, ProviderError> {
    let url = Url::parse(raw.trim())
        .map_err(|_| ProviderError::Config("base URL is not a valid URL".into()))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProviderError::Config(
            "base URL must not embed credentials".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProviderError::Config(
            "base URL must not have a query or fragment".into(),
        ));
    }
    match (url.scheme(), kind) {
        ("https", ProviderKind::Cloud) => {}
        ("http", ProviderKind::Cloud) if is_loopback(&url) => {}
        ("http" | "https", ProviderKind::Local) if is_loopback(&url) => {}
        (_, ProviderKind::Local) => {
            return Err(ProviderError::Config(
                "local providers must listen on loopback".into(),
            ))
        }
        _ => {
            return Err(ProviderError::Config(
                "cloud providers require HTTPS".into(),
            ))
        }
    }
    Ok(url)
}

impl ProviderProfile {
    pub fn openmindai(base_url: &str) -> Result<Self, ProviderError> {
        validate_base_url(base_url, ProviderKind::Cloud)?;
        Ok(Self {
            name: "openmindai".into(),
            kind: ProviderKind::Cloud,
            base_url: base_url.trim().trim_end_matches('/').to_owned(),
            has_catalog: true,
        })
    }

    pub fn local(name: &str, base_url: &str) -> Result<Self, ProviderError> {
        validate_base_url(base_url, ProviderKind::Local)?;
        Ok(Self {
            name: name.into(),
            kind: ProviderKind::Local,
            base_url: base_url.trim().trim_end_matches('/').to_owned(),
            has_catalog: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub retry: RetryPolicy,
    pub breaker_threshold: u32,
    pub breaker_cooldown: Duration,
    pub max_concurrency: usize,
    pub queue_wait: Duration,
    pub max_response_bytes: usize,
    /// Client-side request-rate ceiling; `None` for unmetered local endpoints.
    pub requests_per_minute: Option<u32>,
    /// Total time for one streamed completion. Streams check cancellation on
    /// every event, so this may exceed `request_timeout` for slow reasoning.
    pub stream_timeout: Duration,
    /// Longest provider `Retry-After` honoured before giving up.
    pub max_retry_after: Duration,
}

/// OpenMindAI Cloud's documented per-key request rate.
pub const OPENMINDAI_REQUESTS_PER_MINUTE: u32 = 40;

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(120),
            retry: RetryPolicy::default(),
            breaker_threshold: 4,
            breaker_cooldown: Duration::from_secs(30),
            max_concurrency: 2,
            queue_wait: Duration::from_secs(30),
            max_response_bytes: 2 * 1024 * 1024,
            requests_per_minute: None,
            stream_timeout: Duration::from_secs(300),
            max_retry_after: Duration::from_secs(60),
        }
    }
}

impl ClientConfig {
    /// Defaults for OpenMindAI Cloud, including its request-rate limit.
    pub fn openmindai() -> Self {
        Self {
            requests_per_minute: Some(OPENMINDAI_REQUESTS_PER_MINUTE),
            // Reasoning models took up to ~95 s for a short structured
            // answer in live measurements; leave headroom.
            request_timeout: Duration::from_secs(180),
            ..Self::default()
        }
    }
}

/// Seconds from a `Retry-After` header (delta-seconds form only).
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Audit metadata for one provider call. Contains no prompt or response text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallAudit {
    pub request_id: String,
    pub provider: String,
    pub model: String,
    pub operation: String,
    pub outcome: String,
    pub http_status: Option<u16>,
    pub attempts: u32,
    pub latency_ms: u64,
    pub bytes_sent: usize,
    pub payload_sha256: Option<String>,
    pub streamed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Diagnostics {
    pub provider: String,
    pub base_url: String,
    pub reachable: bool,
    pub authenticated: bool,
    pub models: Vec<ModelInfo>,
    pub latency_ms: u64,
    pub error: Option<String>,
    pub credential_fingerprint: Option<String>,
}

pub struct ChatClient {
    profile: ProviderProfile,
    secret: Option<Secret>,
    http: reqwest::blocking::Client,
    config: ClientConfig,
    breaker: CircuitBreaker,
    limiter: ConcurrencyLimiter,
    rate: Option<Arc<RateLimiter>>,
}

/// One limiter per endpoint for the whole process: the provider meters the
/// key, not our client objects, and the desktop builds clients per command.
fn shared_rate_limiter(base_url: &str, per_minute: u32) -> Arc<RateLimiter> {
    static LIMITERS: OnceLock<Mutex<BTreeMap<(String, u32), Arc<RateLimiter>>>> = OnceLock::new();
    LIMITERS
        .get_or_init(Mutex::default)
        .lock()
        .expect("rate registry mutex")
        .entry((base_url.to_owned(), per_minute))
        .or_insert_with(|| Arc::new(RateLimiter::per_minute(per_minute)))
        .clone()
}

/// Sleep in short slices so a cancelled caller is not held for a backoff.
fn sleep_cancellable(total: Duration, cancel: &AtomicBool) -> Result<(), ProviderError> {
    let deadline = Instant::now() + total;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(ProviderError::Cancelled);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

fn request_id() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("ct-{nanos:x}-{:x}", N.fetch_add(1, Ordering::Relaxed))
}

fn transport_error(e: &reqwest::Error) -> ProviderError {
    if e.is_timeout() {
        ProviderError::Timeout
    } else if e.is_redirect() {
        ProviderError::Protocol("redirects are refused".into())
    } else {
        // reqwest errors can include URLs; keep only the category.
        ProviderError::Network(if e.is_connect() {
            "connection failed".into()
        } else {
            "request failed".into()
        })
    }
}

impl ChatClient {
    pub fn new(
        profile: ProviderProfile,
        secret: Option<Secret>,
        config: ClientConfig,
    ) -> Result<Self, ProviderError> {
        validate_base_url(&profile.base_url, profile.kind)?;
        if profile.kind == ProviderKind::Cloud && secret.is_none() {
            return Err(ProviderError::Credential(
                "no API token configured for the cloud provider".into(),
            ));
        }
        let http = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .user_agent(concat!("CodeTwin-ML/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ProviderError::Config(format!("HTTP client: {e}")))?;
        Ok(Self {
            breaker: CircuitBreaker::new(config.breaker_threshold, config.breaker_cooldown),
            limiter: ConcurrencyLimiter::new(config.max_concurrency),
            rate: config
                .requests_per_minute
                .map(|n| shared_rate_limiter(&profile.base_url, n)),
            profile,
            secret,
            http,
            config,
        })
    }

    pub fn profile(&self) -> &ProviderProfile {
        &self.profile
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.profile.base_url, path.trim_start_matches('/'))
    }

    fn builder(
        &self,
        method: reqwest::Method,
        path: &str,
        rid: &str,
    ) -> reqwest::blocking::RequestBuilder {
        let mut b = self
            .http
            .request(method, self.url(path))
            .header("X-Request-Id", rid)
            .header("Accept", "application/json");
        if let Some(secret) = &self.secret {
            b = b.bearer_auth(secret.expose());
        }
        b
    }

    fn read_bounded(
        &self,
        response: reqwest::blocking::Response,
    ) -> Result<(u16, Vec<u8>), ProviderError> {
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .take(self.config.max_response_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| ProviderError::Network("response read failed".into()))?;
        if body.len() > self.config.max_response_bytes {
            return Err(ProviderError::Protocol(
                "response exceeds size limit".into(),
            ));
        }
        Ok((status, body))
    }

    /// Send with bounded retries; only for idempotent or non-streamed calls.
    fn send_with_retry(
        &self,
        make: impl Fn(&str) -> reqwest::blocking::RequestBuilder,
        rid: &str,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, u32, u16), ProviderError> {
        let _permit = self.limiter.acquire(self.config.queue_wait)?;
        let mut attempt = 0;
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(ProviderError::Cancelled);
            }
            self.breaker.check()?;
            self.acquire_rate(cancel)?;
            let mut server_delay = None;
            let result = make(rid)
                .send()
                .map_err(|e| transport_error(&e))
                .and_then(|r| {
                    server_delay = retry_after(r.headers());
                    self.read_bounded(r)
                })
                .and_then(|(status, body)| {
                    if (200..300).contains(&status) {
                        Ok((body, status))
                    } else {
                        Err(from_status(status, &body))
                    }
                });
            self.breaker.record(result.as_ref().map(|_| ()));
            attempt += 1;
            match result {
                Ok((body, status)) => return Ok((body, attempt, status)),
                Err(e) if e.retryable() && attempt <= self.config.retry.max_retries => {
                    let backoff = self.config.retry.delay(rid, attempt);
                    let delay = match server_delay {
                        // The provider said how long; never retry sooner, and
                        // give up rather than wait past the configured bound.
                        Some(d) if d > self.config.max_retry_after => return Err(e),
                        Some(d) => {
                            self.defer_rate(d);
                            d.max(backoff)
                        }
                        None => backoff,
                    };
                    sleep_cancellable(delay, cancel)?;
                }
                Err(e) => {
                    if let (ProviderError::RateLimited(_), Some(d)) = (&e, server_delay) {
                        self.defer_rate(d.min(self.config.max_retry_after));
                    }
                    return Err(e);
                }
            }
        }
    }

    fn acquire_rate(&self, cancel: &AtomicBool) -> Result<(), ProviderError> {
        match &self.rate {
            Some(rate) => rate.acquire(self.config.queue_wait, cancel),
            None => Ok(()),
        }
    }

    fn defer_rate(&self, delay: Duration) {
        if let Some(rate) = &self.rate {
            rate.defer(delay);
        }
    }

    fn parse_models(body: &[u8]) -> Result<Vec<ModelInfo>, ProviderError> {
        let v: Value = serde_json::from_slice(body)
            .map_err(|_| ProviderError::Protocol("model list is not JSON".into()))?;
        let data = v
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::Protocol("model list has no data array".into()))?;
        Ok(data
            .iter()
            .take(200)
            .filter_map(|m| {
                let id = m.get("id")?.as_str()?;
                if id.is_empty() || id.len() > 128 {
                    return None;
                }
                let s = |k: &str| {
                    m.get(k)
                        .and_then(Value::as_str)
                        .map(|x| x.chars().take(300).collect())
                };
                Some(ModelInfo {
                    id: id.to_owned(),
                    display_name: s("name"),
                    // Absent flags mean "unknown"; treat as available only if not false.
                    available: m.get("available").and_then(Value::as_bool).unwrap_or(true),
                    active: m.get("active").and_then(Value::as_bool).unwrap_or(true),
                    operation: s("operation"),
                    category: s("category"),
                    description: s("description"),
                })
            })
            .collect())
    }

    /// Discover models (`GET /models`). Availability reflects server
    /// configuration, not a guarantee that inference will succeed.
    pub fn list_models(&self) -> Result<Vec<ModelInfo>, ProviderError> {
        let rid = request_id();
        let (body, ..) = self.send_with_retry(
            |r| self.builder(reqwest::Method::GET, "models", r),
            &rid,
            &AtomicBool::new(false),
        )?;
        Self::parse_models(&body)
    }

    /// Capability catalog (`GET /catalog`, OpenMindAI only).
    pub fn catalog(&self) -> Result<Vec<ModelInfo>, ProviderError> {
        if !self.profile.has_catalog {
            return Err(ProviderError::Config(
                "provider has no catalog endpoint".into(),
            ));
        }
        let rid = request_id();
        let (body, ..) = self.send_with_retry(
            |r| self.builder(reqwest::Method::GET, "catalog", r),
            &rid,
            &AtomicBool::new(false),
        )?;
        Self::parse_models(&body)
    }

    /// Connection diagnostics without sending any project content.
    pub fn diagnose(&self) -> Diagnostics {
        let start = Instant::now();
        let result = self.list_models();
        let latency_ms = start.elapsed().as_millis() as u64;
        let (reachable, authenticated, models, error) = match result {
            Ok(models) => (true, true, models, None),
            Err(e @ (ProviderError::Unauthorized(_) | ProviderError::Forbidden(_))) => {
                (true, false, vec![], Some(e.to_string()))
            }
            Err(
                e @ (ProviderError::Network(_)
                | ProviderError::Timeout
                | ProviderError::CircuitOpen),
            ) => (false, false, vec![], Some(e.to_string())),
            Err(e) => (true, false, vec![], Some(e.to_string())),
        };
        Diagnostics {
            provider: self.profile.name.clone(),
            base_url: self.profile.base_url.clone(),
            reachable,
            authenticated,
            models,
            latency_ms,
            error,
            credential_fingerprint: self.secret.as_ref().map(Secret::fingerprint),
        }
    }

    fn check_egress(
        &self,
        request: &ChatRequest,
        egress: Option<&ApprovedEgress>,
    ) -> Result<(), ProviderError> {
        if request.tools.len() > crate::sse::MAX_TOOL_CALLS {
            return Err(ProviderError::Invalid(
                "at most 64 tools may be declared".into(),
            ));
        }
        if self.profile.kind == ProviderKind::Cloud {
            let egress = egress.ok_or_else(|| {
                ProviderError::ConsentRequired("cloud request without an approved preview".into())
            })?;
            if egress.sha256() != payload_digest(request) {
                return Err(ProviderError::ConsentRequired(
                    "request differs from the approved preview".into(),
                ));
            }
        }
        Ok(())
    }

    fn body(request: &ChatRequest, stream: bool) -> Value {
        let mut body =
            json!({"model": request.model, "messages": request.messages, "stream": stream});
        if !request.tools.is_empty() {
            body["tools"] = Value::Array(
                request
                    .tools
                    .iter()
                    .map(|t| json!({"type":"function","function":{"name":t.name,"description":t.description,"parameters":t.parameters}}))
                    .collect(),
            );
        }
        if let Some(n) = request.max_tokens {
            body["max_tokens"] = json!(n);
        }
        if let Some(t) = request.temperature {
            body["temperature"] = json!(t);
        }
        body
    }

    fn audit(
        &self,
        rid: &str,
        request: &ChatRequest,
        outcome: &Result<ChatResponse, ProviderError>,
        attempts: u32,
        status: Option<u16>,
        started: Instant,
        sent: usize,
        streamed: bool,
    ) -> CallAudit {
        CallAudit {
            request_id: rid.to_owned(),
            provider: self.profile.name.clone(),
            model: request.model.clone(),
            operation: "chat.completions".into(),
            outcome: match outcome {
                Ok(_) => "ok".into(),
                Err(e) => e.kind().into(),
            },
            http_status: status,
            attempts,
            latency_ms: started.elapsed().as_millis() as u64,
            bytes_sent: sent,
            payload_sha256: Some(payload_digest(request)),
            streamed,
        }
    }

    /// Non-streamed completion with bounded retries.
    pub fn chat(
        &self,
        request: &ChatRequest,
        egress: Option<&ApprovedEgress>,
        cancel: &AtomicBool,
    ) -> (Result<ChatResponse, ProviderError>, CallAudit) {
        let rid = request_id();
        let started = Instant::now();
        let body = Self::body(request, false);
        let sent = body.to_string().len();
        let mut attempts = 0;
        let mut status = None;
        let result = self.check_egress(request, egress).and_then(|()| {
            let (bytes, a, s) = self.send_with_retry(
                |r| {
                    self.builder(reqwest::Method::POST, "chat/completions", r)
                        .header("Content-Type", "application/json")
                        .body(body.to_string())
                },
                &rid,
                cancel,
            )?;
            attempts = a;
            status = Some(s);
            parse_completion(&bytes, &rid, &request.model, &request.tools)
        });
        let audit = self.audit(
            &rid, request, &result, attempts, status, started, sent, false,
        );
        (result, audit)
    }

    /// Streamed completion. Visible deltas are passed to `on_delta`. A
    /// stream is never retried once any byte was received, and an interrupted
    /// stream is reported as incomplete.
    pub fn chat_stream(
        &self,
        request: &ChatRequest,
        egress: Option<&ApprovedEgress>,
        cancel: &AtomicBool,
        on_delta: &mut dyn FnMut(StreamDelta),
    ) -> (Result<ChatResponse, ProviderError>, CallAudit) {
        let rid = request_id();
        let started = Instant::now();
        let body = Self::body(request, true);
        let sent = body.to_string().len();
        let mut status = None;
        let result = (|| {
            self.check_egress(request, egress)?;
            let _permit = self.limiter.acquire(self.config.queue_wait)?;
            self.breaker.check()?;
            self.acquire_rate(cancel)?;
            let response = self
                .builder(reqwest::Method::POST, "chat/completions", &rid)
                .timeout(self.config.stream_timeout)
                .header("Accept", "text/event-stream")
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .map_err(|e| transport_error(&e));
            let response = match response {
                Ok(r) => r,
                Err(e) => {
                    self.breaker.record(Err(&e));
                    return Err(e);
                }
            };
            status = Some(response.status().as_u16());
            if !response.status().is_success() {
                if let Some(d) = retry_after(response.headers()) {
                    self.defer_rate(d.min(self.config.max_retry_after));
                }
                let (code, bytes) = self.read_bounded(response)?;
                let e = from_status(code, &bytes);
                self.breaker.record(Err(&e));
                return Err(e);
            }
            let mut acc = SseAccumulator::new();
            let mut total = 0usize;
            let reader = BufReader::new(response.take(self.config.max_response_bytes as u64 + 1));
            for line in reader.lines() {
                if cancel.load(Ordering::SeqCst) {
                    return Err(ProviderError::Cancelled);
                }
                let line =
                    line.map_err(|_| ProviderError::Incomplete("stream interrupted".into()))?;
                total += line.len() + 1;
                if total > self.config.max_response_bytes {
                    return Err(ProviderError::Protocol("stream exceeds size limit".into()));
                }
                for delta in acc.feed(&line)? {
                    on_delta(delta);
                }
                if acc.is_done() {
                    break;
                }
            }
            let r = acc.finish(&rid, &request.model, &request.tools);
            self.breaker.record(r.as_ref().map(|_| ()));
            r
        })();
        let audit = self.audit(&rid, request, &result, 1, status, started, sent, true);
        (result, audit)
    }
}
