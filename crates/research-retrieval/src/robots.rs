//! robots.txt compliance (RFC 9309 subset).
//!
//! * Groups are selected by our product token (`codetwin-ml-research`),
//!   falling back to `*`; all matching groups are merged.
//! * The longest matching `Allow`/`Disallow` pattern wins; ties favour Allow.
//!   `*` and a trailing `$` are supported.
//! * A 4xx robots.txt means "no restrictions"; a 5xx or an unreachable host
//!   means "fully disallowed", as the RFC requires.
//! * robots.txt is fetched through the same SSRF-validated, pinned fetcher as
//!   pages, so it can never reach a private address either.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use url::Url;

use crate::{fetch_raw, FetchPolicy, RetrievalError};

pub const PRODUCT_TOKEN: &str = "codetwin-ml-research";
const MAX_ROBOTS_BYTES: usize = 512 * 1024;
const CACHE_TTL: Duration = Duration::from_secs(3600);
const CACHE_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Robots {
    AllowAll,
    DisallowAll,
    Rules(Vec<Rule>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub allow: bool,
    pub pattern: String,
}

/// Parse robots.txt and keep only the rules that apply to `token`.
pub fn parse(body: &str, token: &str) -> Robots {
    let token = token.to_ascii_lowercase();
    let mut specific: Vec<Rule> = Vec::new();
    let mut wildcard: Vec<Rule> = Vec::new();
    let mut matched_specific = false;
    let mut agents: Vec<String> = Vec::new();
    let mut in_rules = false;
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "user-agent" => {
                if in_rules {
                    agents.clear();
                    in_rules = false;
                }
                agents.push(value.to_ascii_lowercase());
            }
            "allow" | "disallow" => {
                in_rules = true;
                // An empty Disallow means "allow everything" and adds no rule.
                if value.is_empty() {
                    continue;
                }
                let rule = Rule {
                    allow: key == "allow",
                    pattern: value.to_owned(),
                };
                if agents.iter().any(|a| token.starts_with(a.as_str()) && a != "*") {
                    matched_specific = true;
                    specific.push(rule.clone());
                }
                if agents.iter().any(|a| a == "*") {
                    wildcard.push(rule);
                }
            }
            _ => {}
        }
    }
    let rules = if matched_specific { specific } else { wildcard };
    if rules.is_empty() {
        Robots::AllowAll
    } else {
        Robots::Rules(rules)
    }
}

fn pattern_match_len(pattern: &str, path: &str) -> Option<usize> {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !path.starts_with(part) {
                return None;
            }
            pos = part.len();
        } else if i == parts.len() - 1 && anchored {
            // The final literal must sit at the very end of the path.
            if path.len() < pos + part.len() || !path.ends_with(part) {
                return None;
            }
            pos = path.len();
        } else {
            let found = path[pos..].find(part)?;
            pos += found + part.len();
        }
    }
    if anchored && pos != path.len() {
        return None;
    }
    Some(pattern.len())
}

impl Robots {
    /// Whether `path_and_query` (starting with `/`) may be fetched.
    pub fn allows(&self, path_and_query: &str) -> bool {
        match self {
            Robots::AllowAll => true,
            Robots::DisallowAll => false,
            Robots::Rules(rules) => {
                if path_and_query == "/robots.txt" {
                    return true;
                }
                let mut best: Option<(usize, bool)> = None;
                for rule in rules {
                    if let Some(len) = pattern_match_len(&rule.pattern, path_and_query) {
                        best = match best {
                            Some((l, a)) if l > len || (l == len && a) => Some((l, a)),
                            _ => Some((len, rule.allow)),
                        };
                    }
                }
                best.is_none_or(|(_, allow)| allow)
            }
        }
    }
}

fn cache() -> &'static Mutex<HashMap<String, (Instant, Robots)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, Robots)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Fetch (or reuse a cached copy of) robots.txt for the URL's origin.
pub fn robots_for(url: &Url, policy: &FetchPolicy) -> Robots {
    let origin = url.origin().ascii_serialization();
    if let Some((at, robots)) = cache().lock().ok().and_then(|c| c.get(&origin).cloned()) {
        if at.elapsed() < CACHE_TTL {
            return robots;
        }
    }
    let robots_policy = FetchPolicy {
        max_bytes: MAX_ROBOTS_BYTES,
        respect_robots: false,
        ..policy.clone()
    };
    let robots = match fetch_raw(&format!("{origin}/robots.txt"), &[], &robots_policy) {
        Ok((_, body)) => parse(&String::from_utf8_lossy(&body), PRODUCT_TOKEN),
        Err(RetrievalError::Status(code)) if (400..500).contains(&code) => Robots::AllowAll,
        // An unparseable media type is treated as an empty file.
        Err(RetrievalError::UnsupportedContent(_)) => Robots::AllowAll,
        // 5xx, unreachable, too large or unsafe: fail closed.
        Err(_) => Robots::DisallowAll,
    };
    if let Ok(mut c) = cache().lock() {
        if c.len() >= CACHE_CAPACITY {
            c.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
            if c.len() >= CACHE_CAPACITY {
                c.clear();
            }
        }
        c.insert(origin, (Instant::now(), robots.clone()));
    }
    robots
}

/// Refuse the URL when its origin's robots.txt disallows it.
pub fn check(url: &Url, policy: &FetchPolicy) -> Result<(), RetrievalError> {
    let mut path = url.path().to_owned();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    if robots_for(url, policy).allows(&path) {
        Ok(())
    } else {
        Err(RetrievalError::RobotsDisallowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "
# comment
User-agent: *
Disallow: /private/
Allow: /private/public-page
Disallow: /*.json$

User-agent: CodeTwin-ML-research
User-agent: other-bot
Disallow: /no-codetwin/
";

    #[test]
    fn specific_group_overrides_wildcard() {
        let r = parse(SAMPLE, PRODUCT_TOKEN);
        assert!(!r.allows("/no-codetwin/x"));
        // The wildcard group no longer applies once a specific group matched.
        assert!(r.allows("/private/secret"));
    }

    #[test]
    fn wildcard_longest_match_and_anchors() {
        let r = parse(SAMPLE, "some-other-crawler");
        assert!(!r.allows("/private/secret"));
        assert!(r.allows("/private/public-page"));
        assert!(!r.allows("/data/feed.json"));
        assert!(r.allows("/data/feed.json?x=1"));
        assert!(r.allows("/"));
        assert!(r.allows("/robots.txt"));
    }

    #[test]
    fn empty_and_tie_rules() {
        assert_eq!(parse("User-agent: *\nDisallow:\n", PRODUCT_TOKEN), Robots::AllowAll);
        let r = parse("User-agent: *\nDisallow: /a\nAllow: /a\n", PRODUCT_TOKEN);
        assert!(r.allows("/a/b"), "ties favour allow");
        let all = parse("User-agent: *\nDisallow: /\n", PRODUCT_TOKEN);
        assert!(!all.allows("/anything"));
        assert!(Robots::AllowAll.allows("/x") && !Robots::DisallowAll.allows("/x"));
    }

    #[test]
    fn middle_wildcards() {
        let r = parse("User-agent: *\nDisallow: /a*/c\n", PRODUCT_TOKEN);
        assert!(!r.allows("/abc/c/d"));
        assert!(r.allows("/abd"));
    }
}
