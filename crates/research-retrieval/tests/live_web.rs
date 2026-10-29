//! Opt-in live checks against the real internet.
//!
//! Runs only when `CODETWIN_TEST_LIVE_WEB=1`. Search runs when
//! `CODETWIN_TEST_SEARXNG_URL` (an instance with JSON output enabled) or
//! `BRAVE_SEARCH_API_KEY` is set. Not part of default CI.
use research_retrieval::search::{search, SearchConfig, SearchProviderKind};
use research_retrieval::{fetch, quote_supported, FetchPolicy};

fn live() -> bool {
    let on = std::env::var("CODETWIN_TEST_LIVE_WEB").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set CODETWIN_TEST_LIVE_WEB=1 to run");
    }
    on
}

#[test]
fn live_fetch_extracts_text_and_checks_claims() {
    if !live() {
        return;
    }
    let doc = fetch("https://www.rfc-editor.org/rfc/rfc9110.html", &FetchPolicy::default())
        .expect("fetch RFC 9110");
    assert_eq!(doc.status, 200);
    assert!(doc.untrusted);
    assert!(doc.text.len() > 10_000, "text was {} bytes", doc.text.len());
    assert!(quote_supported(&doc.text, "HTTP Semantics"));
    assert!(!quote_supported(&doc.text, "HTTP was invented in 2031 by robots"));
    println!(
        "fetched {} -> {} ({} bytes, title {:?})",
        doc.requested_url, doc.final_url, doc.bytes, doc.title
    );
}

#[test]
fn live_fetch_refuses_private_targets() {
    if !live() {
        return;
    }
    for url in ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/"] {
        assert!(fetch(url, &FetchPolicy::default()).is_err(), "{url} must be refused");
    }
}

#[test]
fn live_search_returns_ranked_hits() {
    if !live() {
        return;
    }
    let (config, key) = if let Ok(base_url) = std::env::var("CODETWIN_TEST_SEARXNG_URL") {
        let config = SearchConfig {
            kind: SearchProviderKind::Searxng,
            base_url,
            max_results: 5,
        };
        (config, None)
    } else if let Ok(key) = std::env::var("BRAVE_SEARCH_API_KEY") {
        let config = SearchConfig {
            kind: SearchProviderKind::Brave,
            base_url: "https://api.search.brave.com".into(),
            max_results: 5,
        };
        (config, Some(key))
    } else {
        eprintln!("skipped search: set CODETWIN_TEST_SEARXNG_URL or BRAVE_SEARCH_API_KEY");
        return;
    };
    let hits = search(&config, key.as_deref(), "rust serde json", &FetchPolicy::default())
        .expect("live search");
    assert!(!hits.is_empty());
    for hit in &hits {
        assert!(hit.url.starts_with("http"), "{hit:?}");
        println!("{}. {} {}", hit.rank, hit.title, hit.url);
    }
}
