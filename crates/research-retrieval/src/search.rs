//! External web search providers for consented research.
//!
//! Search runs through the same SSRF-resistant fetcher as page retrieval:
//! HTTPS only, public addresses only, DNS pinned, bounded size and time, and
//! the API key is never sent after a redirect. Queries come from the
//! operator, never from model output. Result pages are not fetched here;
//! the caller retrieves each hit separately under the same policy.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{fetch_raw, FetchPolicy, RetrievalError};

pub const MAX_QUERY_CHARS: usize = 400;
pub const MAX_RESULTS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchProviderKind {
    /// Brave Search API (`X-Subscription-Token`).
    Brave,
    /// A SearXNG instance with the JSON output format enabled.
    Searxng,
}

impl SearchProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Brave => "brave",
            Self::Searxng => "searxng",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "brave" => Some(Self::Brave),
            "searxng" => Some(Self::Searxng),
            _ => None,
        }
    }

    pub fn needs_key(self) -> bool {
        matches!(self, Self::Brave)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchConfig {
    pub kind: SearchProviderKind,
    pub base_url: String,
    pub max_results: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub rank: usize,
    pub title: String,
    pub url: String,
    /// Provider snippet: untrusted text.
    pub snippet: String,
    pub provider: String,
}

fn clean_query(query: &str) -> Result<String, RetrievalError> {
    let q: String = query
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_QUERY_CHARS)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if q.is_empty() {
        return Err(RetrievalError::Rejected("empty search query".into()));
    }
    Ok(q)
}

/// The request URL for `query` (no credentials in the URL).
pub fn request_url(config: &SearchConfig, query: &str) -> Result<Url, RetrievalError> {
    let q = clean_query(query)?;
    let mut url = Url::parse(config.base_url.trim_end_matches('/'))
        .map_err(|_| RetrievalError::Rejected("invalid search base URL".into()))?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
        return Err(RetrievalError::Rejected(
            "search base URL must not carry credentials or a query".into(),
        ));
    }
    let count = config.max_results.clamp(1, MAX_RESULTS).to_string();
    let path = url.path().trim_end_matches('/').to_owned();
    match config.kind {
        SearchProviderKind::Brave => {
            url.set_path(&format!("{path}/res/v1/web/search"));
            url.query_pairs_mut()
                .append_pair("q", &q)
                .append_pair("count", &count)
                .append_pair("safesearch", "strict");
        }
        SearchProviderKind::Searxng => {
            url.set_path(&format!("{path}/search"));
            url.query_pairs_mut()
                .append_pair("q", &q)
                .append_pair("format", "json")
                .append_pair("safesearch", "2");
        }
    }
    Ok(url)
}

fn text(v: &Value, key: &str, max: usize) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

/// Parse a provider response into ranked, HTTPS-only, de-duplicated hits.
pub fn parse_results(
    kind: SearchProviderKind,
    body: &[u8],
    max_results: usize,
) -> Result<Vec<SearchHit>, RetrievalError> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|_| RetrievalError::Rejected("search response is not JSON".into()))?;
    let (items, snippet_key) = match kind {
        SearchProviderKind::Brave => (v.pointer("/web/results"), "description"),
        SearchProviderKind::Searxng => (v.get("results"), "content"),
    };
    let items = items.and_then(Value::as_array).cloned().unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    let mut hits = Vec::new();
    for item in items {
        let Ok(mut url) = Url::parse(&text(&item, "url", 2048)) else {
            continue;
        };
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            continue;
        }
        url.set_fragment(None);
        if !seen.insert(url.to_string()) {
            continue;
        }
        hits.push(SearchHit {
            rank: hits.len() + 1,
            title: text(&item, "title", 300),
            url: url.to_string(),
            // Brave wraps matches in <strong>; strip tags.
            snippet: crate::extract_text(&text(&item, snippet_key, 600), "text/html").1,
            provider: kind.as_str().into(),
        });
        if hits.len() >= max_results.clamp(1, MAX_RESULTS) {
            break;
        }
    }
    Ok(hits)
}

/// Run one search. `api_key` comes from the OS credential store.
pub fn search(
    config: &SearchConfig,
    api_key: Option<&str>,
    query: &str,
    policy: &FetchPolicy,
) -> Result<Vec<SearchHit>, RetrievalError> {
    if config.kind.needs_key() && api_key.is_none_or(str::is_empty) {
        return Err(RetrievalError::Rejected(
            "search provider API key is not configured".into(),
        ));
    }
    let url = request_url(config, query)?;
    // Search APIs do not redirect; refusing redirects keeps the key on one host.
    // A configured search API is an API contract, not a crawl, so robots.txt
    // does not apply to it; result pages fetched later are still checked.
    let policy = FetchPolicy {
        max_redirects: 0,
        respect_robots: false,
        max_bytes: policy.max_bytes.min(1024 * 1024),
        ..policy.clone()
    };
    let mut headers: Vec<(&str, &str)> = vec![("Accept", "application/json")];
    if let (SearchProviderKind::Brave, Some(key)) = (config.kind, api_key) {
        headers.push(("X-Subscription-Token", key));
    }
    let (doc, body) = fetch_raw(url.as_str(), &headers, &policy)?;
    if doc.content_type != "application/json" {
        return Err(RetrievalError::UnsupportedContent(doc.content_type));
    }
    parse_results(config.kind, &body, config.max_results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    #[test]
    fn builds_provider_urls_without_credentials() {
        let brave = SearchConfig {
            kind: SearchProviderKind::Brave,
            base_url: "https://api.search.brave.com".into(),
            max_results: 50,
        };
        let u = request_url(&brave, "  rust\u{0007} sqlite   wal ").unwrap();
        assert_eq!(u.path(), "/res/v1/web/search");
        assert!(u.as_str().contains("q=rust+sqlite+wal"));
        assert!(u.as_str().contains("count=10"), "clamped");
        let searx = SearchConfig {
            kind: SearchProviderKind::Searxng,
            base_url: "https://user:pw@searx.example.org".into(),
            max_results: 5,
        };
        assert!(request_url(&searx, "x").is_err());
        assert!(request_url(&brave, "   ").is_err());
    }

    #[test]
    fn parses_and_filters_results() {
        let brave = br#"{"web":{"results":[
            {"title":"A","url":"https://a.example/x#frag","description":"<strong>hi</strong> there"},
            {"title":"dup","url":"https://a.example/x","description":""},
            {"title":"http","url":"http://insecure.example/","description":""},
            {"title":"js","url":"javascript:alert(1)","description":""},
            {"title":"B","url":"https://b.example/","description":"b"}]}}"#;
        let hits = parse_results(SearchProviderKind::Brave, brave, 10).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].url, "https://a.example/x");
        assert_eq!(hits[0].snippet, "hi there");
        assert_eq!(hits[1].rank, 2);
        let searx = br#"{"results":[{"title":"S","url":"https://s.example/","content":"c"}]}"#;
        let hits = parse_results(SearchProviderKind::Searxng, searx, 10).unwrap();
        assert_eq!(hits[0].provider, "searxng");
        assert!(parse_results(SearchProviderKind::Brave, b"<html>", 10).is_err());
    }

    #[test]
    fn brave_requires_a_key() {
        let cfg = SearchConfig {
            kind: SearchProviderKind::Brave,
            base_url: "https://api.search.brave.com".into(),
            max_results: 3,
        };
        assert!(search(&cfg, None, "q", &FetchPolicy::default()).is_err());
    }

    #[test]
    fn searches_a_loopback_fixture_and_sends_the_key() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let body = r#"{"web":{"results":[{"title":"Doc","url":"https://docs.example/a","description":"d"}]}}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            head
        });
        let cfg = SearchConfig {
            kind: SearchProviderKind::Brave,
            base_url: base,
            max_results: 3,
        };
        let hits = search(
            &cfg,
            Some("k-123"),
            "sqlite wal",
            &FetchPolicy::loopback_fixture_for_tests(),
        )
        .unwrap();
        assert_eq!(hits.len(), 1);
        let head = handle.join().unwrap().to_ascii_lowercase();
        assert!(head.contains("x-subscription-token: k-123"));
        assert!(head.starts_with("get /res/v1/web/search?q=sqlite+wal"));
    }
}
