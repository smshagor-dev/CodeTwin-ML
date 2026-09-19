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
    blocking::{Client, RequestBuilder},
    header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, LOCATION},
    Method,
};
use thiserror::Error;
use url::Url;

use crate::scope::{ScopeError, ScopePolicy};
use crate::{redact_url, AuthContext, ObservedResponse};

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
    #[error("response body could not be read")]
    Body,
}

#[derive(Clone)]
pub struct RequestBudget {
    used: Arc<AtomicUsize>,
    max: usize,
}

impl RequestBudget {
    pub fn new(max: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            max,
        }
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
        Self {
            policy,
            auth,
            budget,
            cancelled,
        }
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
        self.policy.assert_url(url)?;
        let attach_credentials = self.policy.credentials_allowed_for(url);
        let redaction_secrets = if attach_credentials {
            self.auth.redaction_values()
        } else {
            Vec::new()
        };
        let custom_headers = if attach_credentials {
            parse_headers(&self.auth.custom_headers)?
        } else {
            Vec::new()
        };
        let extra_headers = parse_borrowed_headers(extra_headers)?;
        let retry_safe = method == Method::GET || method == Method::HEAD || method == Method::OPTIONS;
        let attempts = if retry_safe {
            self.policy.config().retry_limit + 1
        } else {
            1
        };

        for attempt in 0..attempts {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(RequestError::Cancelled);
            }

            // Resolve again for every attempt and pin the checked address into reqwest.
            // This prevents redirects/DNS changes from bypassing the authorized network scope.
            let pinned = self.policy.resolve_and_pin(url)?;
            self.budget.claim()?;
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(RequestError::Cancelled);
            }

            let client = client_for(&self.policy, url, pinned)?;
            let request = build_request(
                &client,
                method.clone(),
                url,
                body,
                attach_credentials.then_some(&self.auth),
                &custom_headers,
                &extra_headers,
            );

            let started = Instant::now();
            let response = match request.send() {
                Ok(response) => response,
                Err(_) if attempt + 1 < attempts => continue,
                Err(_) => {
                    return Err(RequestError::Http(format!(
                        "transport failure for {}",
                        redact_url(url)
                    )));
                }
            };
            let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            return read_response(
                response,
                elapsed_ms,
                self.policy.config().response_limit_bytes,
                redaction_secrets.clone(),
            );
        }

        Err(RequestError::Http(format!(
            "transport failure for {}",
            redact_url(url)
        )))
    }
}

fn build_request(
    client: &Client,
    method: Method,
    url: &Url,
    body: Option<&str>,
    auth: Option<&AuthContext>,
    custom_headers: &[(HeaderName, HeaderValue)],
    extra_headers: &[(HeaderName, HeaderValue)],
) -> RequestBuilder {
    let mut request = client.request(method, url.clone());
    if let Some(token) = auth
        .and_then(|auth| auth.bearer_token.as_deref())
        .filter(|value| !value.trim().is_empty())
    {
        request = request.bearer_auth(token.trim());
    }
    if let Some(cookie) = auth
        .and_then(|auth| auth.cookie_header.as_deref())
        .filter(|value| !value.trim().is_empty())
    {
        request = request.header("Cookie", cookie.trim());
    }
    for (name, value) in custom_headers {
        request = request.header(name.clone(), value.clone());
    }
    for (name, value) in extra_headers {
        request = request.header(name.clone(), value.clone());
    }
    if let Some(body) = body {
        request = request.body(body.to_string());
    }
    request
}

fn read_response(
    response: reqwest::blocking::Response,
    elapsed_ms: u64,
    max: usize,
    redaction_secrets: Vec<String>,
) -> Result<ObservedResponse, RequestError> {
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
    let mut body_bytes = Vec::with_capacity(max.min(65_536));
    let mut limited = response.take(max as u64 + 1);
    limited
        .read_to_end(&mut body_bytes)
        .map_err(|_| RequestError::Body)?;
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
        redaction_secrets,
    })
}

fn client_for(policy: &ScopePolicy, url: &Url, pinned: SocketAddr) -> Result<Client, RequestError> {
    let host = url
        .host_str()
        .ok_or_else(|| RequestError::Http("URL host is missing".to_string()))?;
    Client::builder()
        .timeout(Duration::from_millis(policy.config().timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("CodeTwin-Authorized-Security-Test/1.0")
        .resolve(host, pinned)
        .build()
        .map_err(|_| RequestError::Http("HTTP client initialization failed".to_string()))
}

fn parse_headers(values: &[(String, String)]) -> Result<Vec<(HeaderName, HeaderValue)>, RequestError> {
    values
        .iter()
        .map(|(name, value)| parse_header(name, value))
        .collect()
}

fn parse_borrowed_headers(values: &[(&str, &str)]) -> Result<Vec<(HeaderName, HeaderValue)>, RequestError> {
    values
        .iter()
        .map(|(name, value)| parse_header(name, value))
        .collect()
}

fn parse_header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), RequestError> {
    if forbidden_user_header(name) {
        return Err(RequestError::Header(format!(
            "header {} cannot be overridden",
            name.trim()
        )));
    }
    let name = HeaderName::from_bytes(name.trim().as_bytes())
        .map_err(|_| RequestError::Header("invalid header name".to_string()))?;
    let value = HeaderValue::from_str(value)
        .map_err(|_| RequestError::Header("invalid header value".to_string()))?;
    Ok((name, value))
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

#[cfg(test)]
mod tests {
    use super::{RequestBudget, RequestError};

    #[test]
    fn request_budget_never_exceeds_limit() {
        let budget = RequestBudget::new(2);
        assert_eq!(budget.claim().expect("first"), 1);
        assert_eq!(budget.claim().expect("second"), 2);
        assert!(matches!(budget.claim(), Err(RequestError::BudgetExhausted)));
        assert_eq!(budget.used(), 2);
    }
}
