//! Source hygiene for research: structure-preserving Markdown extraction,
//! near-duplicate detection and freshness classification.
//!
//! Everything here is deterministic and local. Extracted Markdown is still
//! untrusted page content; links are kept as text and never followed.
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

const MAX_MARKDOWN_CHARS: usize = 40_000;

fn md_regexes() -> &'static [Regex; 9] {
    static R: OnceLock<[Regex; 9]> = OnceLock::new();
    R.get_or_init(|| {
        [
            Regex::new(r"(?is)<(script|style|noscript|template|svg|iframe|head)\b.*?</\s*(script|style|noscript|template|svg|iframe|head)\s*>").unwrap(),
            Regex::new(r"(?s)<!--.*?-->").unwrap(),
            Regex::new(r"(?is)<h([1-6])[^>]*>(.*?)</h[1-6]\s*>").unwrap(),
            Regex::new(r"(?is)<pre[^>]*>(.*?)</pre\s*>").unwrap(),
            Regex::new(r#"(?is)<a\b[^>]*?href\s*=\s*["']([^"']*)["'][^>]*>(.*?)</a\s*>"#).unwrap(),
            Regex::new(r"(?is)<li[^>]*>").unwrap(),
            Regex::new(r"(?is)</?(p|div|section|article|br|tr|ul|ol|table|blockquote|li)\b[^>]*>").unwrap(),
            Regex::new(r"(?s)<[^>]+>").unwrap(),
            Regex::new(r"[ \t]+").unwrap(),
        ]
    })
}

fn decode(text: &str) -> String {
    text.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn inline(text: &str) -> String {
    let r = md_regexes();
    let t = r[7].replace_all(text, " ");
    r[8].replace_all(&decode(&t), " ").trim().to_owned()
}

/// HTML → bounded Markdown keeping headings, lists, links and code blocks.
/// Only http(s) and root-relative link targets are kept; `javascript:` and
/// `data:` targets are reduced to their text.
pub fn extract_markdown(html: &str) -> String {
    let r = md_regexes();
    let body = r[0].replace_all(html, " ");
    let body = r[1].replace_all(&body, " ");
    let body = r[3].replace_all(&body, |c: &regex::Captures| {
        let code = decode(&r[7].replace_all(&c[1], ""));
        format!("\n\n```\n{}\n```\n\n", code.trim_matches('\n'))
    });
    let body = r[2].replace_all(&body, |c: &regex::Captures| {
        let level: usize = c[1].parse().unwrap_or(1);
        format!("\n\n{} {}\n\n", "#".repeat(level), inline(&c[2]))
    });
    let body = r[4].replace_all(&body, |c: &regex::Captures| {
        let href = c[1].trim();
        let text = inline(&c[2]);
        let lower = href.to_ascii_lowercase();
        let safe = lower.starts_with("https://")
            || lower.starts_with("http://")
            || (href.starts_with('/') && !href.starts_with("//"));
        if safe && !text.is_empty() {
            format!(
                "[{}]({})",
                text.replace(['[', ']'], ""),
                href.replace([' ', ')'], "")
            )
        } else {
            text
        }
    });
    let body = r[5].replace_all(&body, "\n- ");
    let body = r[6].replace_all(&body, "\n");
    let body = decode(&r[7].replace_all(&body, ""));
    let mut out = String::new();
    let mut in_code = false;
    let mut blank = 0;
    for line in body.lines() {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
        }
        let line = if in_code {
            line.trim_end().to_owned()
        } else {
            r[8].replace_all(line, " ").trim().to_owned()
        };
        if line.is_empty() || line == "-" {
            blank += 1;
            if blank > 1 || out.is_empty() {
                continue;
            }
            out.push('\n');
            continue;
        }
        blank = 0;
        out.push_str(&line);
        out.push('\n');
        if out.len() > MAX_MARKDOWN_CHARS {
            break;
        }
    }
    out.trim().chars().take(MAX_MARKDOWN_CHARS).collect()
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// 64-bit SimHash over word 3-shingles (case and punctuation folded).
pub fn simhash(text: &str) -> u64 {
    let words: Vec<String> = text
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return 0;
    }
    let shingles: Vec<String> = if words.len() < 3 {
        vec![words.join(" ")]
    } else {
        words.windows(3).map(|w| w.join(" ")).collect()
    };
    let mut weights = [0i32; 64];
    for s in &shingles {
        let h = fnv1a(s.as_bytes());
        for (bit, w) in weights.iter_mut().enumerate() {
            *w += if (h >> bit) & 1 == 1 { 1 } else { -1 };
        }
    }
    weights
        .iter()
        .enumerate()
        .fold(0u64, |acc, (bit, w)| if *w > 0 { acc | (1 << bit) } else { acc })
}

/// Default near-duplicate threshold (bits) for [`simhash`] fingerprints.
pub const NEAR_DUPLICATE_BITS: u32 = 3;

pub fn near_duplicate(a: u64, b: u64) -> bool {
    (a ^ b).count_ones() <= NEAR_DUPLICATE_BITS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// Index of the representative (first-seen) source.
    pub canonical: usize,
    pub duplicates: Vec<usize>,
    pub exact: bool,
}

/// Group sources that are exact (same content hash) or near (SimHash)
/// duplicates. Input is `(content_sha256, text)` in retrieval order.
pub fn duplicate_groups(sources: &[(&str, &str)]) -> Vec<DuplicateGroup> {
    let hashes: Vec<u64> = sources.iter().map(|(_, t)| simhash(t)).collect();
    let mut assigned = vec![false; sources.len()];
    let mut groups = Vec::new();
    for i in 0..sources.len() {
        if assigned[i] {
            continue;
        }
        let mut group = DuplicateGroup {
            canonical: i,
            duplicates: Vec::new(),
            exact: true,
        };
        for j in i + 1..sources.len() {
            if assigned[j] {
                continue;
            }
            let exact = sources[i].0 == sources[j].0;
            if exact || (hashes[i] != 0 && near_duplicate(hashes[i], hashes[j])) {
                assigned[j] = true;
                group.exact &= exact;
                group.duplicates.push(j);
            }
        }
        if !group.duplicates.is_empty() {
            groups.push(group);
        }
    }
    groups
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Modified within 90 days of the reference time.
    Current,
    /// 90 days to 2 years old.
    Aging,
    /// Older than 2 years.
    Stale,
    /// The server sent no usable Last-Modified header.
    Unknown,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse an IMF-fixdate (`Tue, 01 Oct 2026 00:00:00 GMT`) into Unix ms.
pub fn parse_http_date(value: &str) -> Option<i64> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let m = MONTHS.iter().position(|x| x == month)? as i64 + 1;
    let d: i64 = day.parse().ok().filter(|d| (1..=31).contains(d))?;
    let y: i64 = year.parse().ok().filter(|y| (1970..=9999).contains(y))?;
    let hms: Vec<i64> = time
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let [h, mi, s] = hms.as_slice() else {
        return None;
    };
    if *h > 23 || *mi > 59 || *s > 60 {
        return None;
    }
    Some((days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + s) * 1000)
}

pub fn freshness(last_modified: Option<&str>, now_ms: i64) -> Freshness {
    let Some(ms) = last_modified.and_then(parse_http_date) else {
        return Freshness::Unknown;
    };
    match (now_ms - ms) / 86_400_000 {
        d if d < 90 => Freshness::Current,
        d if d < 730 => Freshness::Aging,
        _ => Freshness::Stale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_keeps_structure_and_drops_unsafe_links() {
        let html = r#"<html><head><title>x</title></head><body>
            <h1>Guide &amp; Notes</h1><p>Intro <a href="https://docs.rs/x">docs</a>
            and <a href="javascript:alert(1)">bad</a>.</p>
            <ul><li>one</li><li>two</li></ul>
            <pre><code>fn main() {}</code></pre><script>evil()</script></body></html>"#;
        let md = extract_markdown(html);
        assert!(md.starts_with("# Guide & Notes"), "{md}");
        assert!(md.contains("[docs](https://docs.rs/x)"), "{md}");
        assert!(md.contains("bad") && !md.contains("javascript"), "{md}");
        assert!(md.contains("- one") && md.contains("- two"), "{md}");
        assert!(md.contains("```\nfn main() {}\n```"), "{md}");
        assert!(!md.contains("evil"), "{md}");
    }

    #[test]
    fn near_duplicates_are_grouped_but_distinct_pages_are_not() {
        let a = "The quick brown fox jumps over the lazy dog near the river bank today while birds sing loudly in the tall green trees by the old mill";
        let b = "The quick brown fox jumps over the lazy dog near the river bank today, while birds sing loudly in the tall green trees by the old mill!";
        let c = "Rust ownership rules guarantee memory safety without a garbage collector by tracking borrows at compile time";
        assert!(near_duplicate(simhash(a), simhash(b)));
        assert!(!near_duplicate(simhash(a), simhash(c)));
        let groups = duplicate_groups(&[("h1", a), ("h2", c), ("h3", b), ("h2", c)]);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0],
            DuplicateGroup { canonical: 0, duplicates: vec![2], exact: false }
        );
        assert_eq!(
            groups[1],
            DuplicateGroup { canonical: 1, duplicates: vec![3], exact: true }
        );
    }

    #[test]
    fn http_dates_and_freshness() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        let oct = parse_http_date("Thu, 01 Oct 2026 00:00:00 GMT").unwrap();
        assert_eq!(oct, 1_790_812_800_000);
        assert!(parse_http_date("yesterday").is_none());
        assert!(parse_http_date("Thu, 32 Oct 2026 00:00:00 GMT").is_none());
        let day = 86_400_000;
        let lm = Some("Thu, 01 Oct 2026 00:00:00 GMT");
        assert_eq!(freshness(lm, oct + 10 * day), Freshness::Current);
        assert_eq!(freshness(lm, oct + 400 * day), Freshness::Aging);
        assert_eq!(freshness(lm, oct + 900 * day), Freshness::Stale);
        assert_eq!(freshness(None, oct), Freshness::Unknown);
    }
}
