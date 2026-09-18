use std::{
    io::Read,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, LOCATION},
    Method,
};
use thiserror::Error;
use url::Url;

use crate::{AuthContext, ObservedResponse};
use crate::scope::{ScopeError, ScopePolicy};

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("{0}")]
    Scope(#[from] ScopeError),
    #[error("scan cancelled")]
    Cancelled,
    #[error("request budget exhausted")]
    BudgetExhausted,
    #[error("invalid request header: {0}")]
    Header(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("response body could not be read: {0}")]
    Body(String),
}

#[derive(Clone)]
pub struct RequestBudget {
    used: Arc<AtomicUsize>,
    max: usize,
}

impl RequestBudget {
    pub fn new(max: usize) -> Self {
        Self { used: Arc::new(AtomicUsize::new(0)), max }
    }

    pub fn claim(&self) -> Result<usize, RequestError> {
        let next = self.used.fetch_add(1, Ordering::SeqCst) + 1;
        if next > self.max {
            self.used.fetch_sub(1, Ordering::SeqCst);
            return Err(RequestError::BudgetExhausted);
        }
        Ok(next)
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct ScopedRequester {
    policy: ScopePolicy,
    auth: AuthContext,
    budget: RequestBudget,
    cancelled: Arc<AtomicBool>,
}

impl ScopedRequester {
    pub fn new(
        policy: ScopePolicy,
        auth: AuthContext,
        budget: RequestBudget,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self { policy, auth, budget, cancelled }
    }

    pub fn budget(&self) -> &RequestBudget {
        &self.budget
    }

    pub fn get(&self, url: &Url) -> Result<ObservedResponse, RequestError> {
        self.send(Method::GET, url, None, &[])
    }

    pub fn send(
        &self,
        method: Method,
        url: &Url,
        body: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<ObservedResponse, RequestError> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(RequestError::Cancelled);
        }
        self.policy.assert_url(url)?;
        let pinned = self.policy.resolve_and_pin(url)?;
        self.budget.claim()?;
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(RequestError::Cancelled);
        }

        let client = client_for(&self.policy, url, pinned)?;
        let mut request = client.request(method, url.clone());
        if let Some(token) = self.auth.bearer_token.as_deref().filter(|value| !value.trim().is_empty()) {
            request = request.bearer_auth(token.trim());
        }
        if let Some(cookie) = self.auth.cookie_header.as_deref().filter(|value| !value.trim().is_empty()) {
            request = request.header("Cookie", cookie.trim());
        }
        for (name, value) in &self.auth.custom_headers {
            if forbidden_user_header(name) {
                return Err(RequestError::Header(format!("header {name} cannot be overridden")));
            }
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| RequestError::Header(error.to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|error| RequestError::Header(error.to_string()))?;
            request = request.header(name, value);
        }
        for (name, value) in extra_headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| RequestError::Header(error.to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|error| RequestError::Header(error.to_string()))?;
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
        }

        let started = Instant::now();
        let mut response = request.send().map_err(|error| RequestError::Http(error.to_string()))?;
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let status = response.status().as_u16();
        let headers = copy_headers(response.headers());
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let max = self.policy.config().response_limit_bytes;
        let mut body_bytes = Vec::with_capacity(max.min(65_536));
        let mut limited = response.take(max as u64 + 1);
        limited
            .read_to_end(&mut body_bytes)
            .map_err(|error| RequestError::Body(error.to_string()))?;
        let truncated = body_bytes.len() > max;
        if truncated {
            body_bytes.truncate(max);
        }
        Ok(ObservedResponse {
            status,
            headers,
            content_type,
            location,
            body: body_bytes,
            elapsed_ms,
            truncated,
        })
    }
}

fn client_for(policy: &ScopePolicy, url: &Url, pinned: SocketAddr) -> Result<Client, RequestError> {
    let host = url.host_str().ok_or_else(|| RequestError::Http("URL host is missing".to_string()))?;
    Client::builder()
        .timeout(Duration::from_millis(policy.config().timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("CodeTwin-Authorized-Security-Test/1.0")
        .resolve(host, pinned)
        .build()
        .map_err(|error| RequestError::Http(error.to_string()))
}

fn copy_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_string(),
            )
        })
        .collect()
}

fn forbidden_user_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "host" | "content-length" | "transfer-encoding" | "connection"
    )
}
