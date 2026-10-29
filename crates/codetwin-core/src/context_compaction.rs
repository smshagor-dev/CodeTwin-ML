//! Deterministic context compaction for model prompts.
//!
//! Material is split into prioritized sections. Sections that fit are kept
//! verbatim; larger ones are summarized extractively (JSON is flattened to
//! `path: value` lines, then the most informative lines are kept in original
//! order); sections whose share is too small are omitted. Every summary and
//! omission is reported, so a prompt never silently loses context.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Below this share a section is omitted rather than reduced to noise.
const MIN_SECTION_CHARS: usize = 160;
const MAX_ARRAY_ITEMS: usize = 8;
const MAX_DEPTH: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub id: String,
    pub label: String,
    pub text: String,
    /// Higher is more important; ties keep input order.
    pub priority: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compacted {
    pub text: String,
    pub verbatim: Vec<String>,
    pub summarized: Vec<String>,
    pub omitted: Vec<String>,
    pub original_chars: usize,
    pub final_chars: usize,
    pub estimated_tokens: usize,
}

/// Rough token estimate (≈4 characters per token for English and code).
pub fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Flatten JSON into `path: value` lines with bounded depth and arrays.
pub fn flatten_json(value: &Value) -> Vec<String> {
    fn walk(v: &Value, path: &str, depth: usize, out: &mut Vec<String>) {
        if depth > MAX_DEPTH {
            out.push(format!("{path}: …"));
            return;
        }
        match v {
            Value::Object(map) => {
                for (k, child) in map {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    walk(child, &p, depth + 1, out);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().take(MAX_ARRAY_ITEMS).enumerate() {
                    walk(child, &format!("{path}[{i}]"), depth + 1, out);
                }
                if items.len() > MAX_ARRAY_ITEMS {
                    out.push(format!(
                        "{path}: (+{} more items)",
                        items.len() - MAX_ARRAY_ITEMS
                    ));
                }
            }
            Value::Null => {}
            Value::String(s) => out.push(format!("{path}: {}", clip(s, 240))),
            other => out.push(format!("{path}: {other}")),
        }
    }
    let mut out = Vec::new();
    walk(value, "", 0, &mut out);
    out
}

fn units(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            return flatten_json(&v);
        }
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.is_empty() {
            continue;
        }
        // Long prose lines are split into sentences.
        if line.len() > 300 {
            out.extend(
                line.split_inclusive(". ")
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty()),
            );
        } else {
            out.push(line);
        }
    }
    out
}

fn informativeness(unit: &str) -> f64 {
    let lower = unit.to_lowercase();
    let mut score = 1.0;
    for (needle, weight) in [
        ("critical", 4.0),
        ("high", 2.5),
        ("severity", 2.0),
        ("vulnerab", 3.0),
        ("finding", 2.0),
        ("drift", 3.0),
        ("missing", 2.0),
        ("error", 2.0),
        ("fail", 2.0),
        ("verified", 1.5),
        ("summary", 1.5),
        ("advisor", 2.0),
        ("secret", 2.5),
        ("cve-", 3.0),
    ] {
        if lower.contains(needle) {
            score += weight;
        }
    }
    if unit.chars().any(|c| c.is_ascii_digit()) {
        score += 0.5;
    }
    // Hashes and ids carry little meaning for a reader.
    if unit.len() > 40 && unit.chars().filter(char::is_ascii_hexdigit).count() * 10 > unit.len() * 7
    {
        score -= 1.5;
    }
    score / (1.0 + (unit.len() as f64 / 200.0))
}

/// Extractive summary of `text` within `max_chars`, keeping original order.
pub fn summarize_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let mut seen = BTreeSet::new();
    let units: Vec<String> = units(text)
        .into_iter()
        .filter(|u| seen.insert(u.to_lowercase()))
        .collect();
    let mut ranked: Vec<(usize, f64)> = units
        .iter()
        .enumerate()
        .map(|(i, u)| (i, informativeness(u) + if i < 3 { 1.0 } else { 0.0 }))
        .collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut keep = BTreeSet::new();
    let mut used = 0usize;
    for (i, _) in ranked {
        let len = units[i].chars().count().min(240) + 1;
        if used + len > max_chars.saturating_sub(24) {
            continue;
        }
        used += len;
        keep.insert(i);
    }
    let dropped = units.len() - keep.len();
    let mut out: Vec<String> = keep.iter().map(|&i| clip(&units[i], 240)).collect();
    if dropped > 0 {
        out.push(format!("(… {dropped} line(s) condensed)"));
    }
    clip(&out.join("\n"), max_chars)
}

/// Fit prioritized sections into `budget_chars`.
pub fn compact(sections: &[Section], budget_chars: usize) -> Compacted {
    let original_chars: usize = sections.iter().map(|s| s.text.chars().count()).sum();
    let mut order: Vec<usize> = (0..sections.len()).collect();
    order.sort_by(|&a, &b| sections[b].priority.cmp(&sections[a].priority).then(a.cmp(&b)));

    let header = |s: &Section| format!("## {}\n", s.label);
    let mut remaining = budget_chars;
    let mut parts: Vec<(usize, String)> = Vec::new();
    let (mut verbatim, mut summarized, mut omitted) = (Vec::new(), Vec::new(), Vec::new());
    for (n, &i) in order.iter().enumerate() {
        let s = &sections[i];
        let left = order.len() - n;
        let fair = remaining / left;
        let need = header(s).len() + s.text.chars().count();
        if need <= fair || (need <= remaining && left == 1) {
            parts.push((i, format!("{}{}", header(s), s.text)));
            remaining -= need;
            verbatim.push(s.id.clone());
            continue;
        }
        // The most important section may borrow up to twice its fair share.
        let share = if n == 0 {
            fair.saturating_mul(2).min(remaining)
        } else {
            fair.min(remaining)
        };
        let body_budget = share.saturating_sub(header(s).len());
        if body_budget < MIN_SECTION_CHARS {
            omitted.push(s.id.clone());
            continue;
        }
        let body = summarize_text(&s.text, body_budget);
        remaining = remaining.saturating_sub(header(s).len() + body.chars().count());
        parts.push((i, format!("{}{}", header(s), body)));
        summarized.push(s.id.clone());
    }
    parts.sort_by_key(|(i, _)| *i);
    let mut text = parts
        .into_iter()
        .map(|(_, p)| p)
        .collect::<Vec<_>>()
        .join("\n\n");
    if !omitted.is_empty() {
        text.push_str(&format!(
            "\n\n[context budget: omitted {}]",
            omitted.join(", ")
        ));
    }
    let final_chars = text.chars().count();
    Compacted {
        estimated_tokens: estimate_tokens(&text),
        text,
        verbatim,
        summarized,
        omitted,
        original_chars,
        final_chars,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(id: &str, priority: u8, text: String) -> Section {
        Section {
            id: id.into(),
            label: id.into(),
            text,
            priority,
        }
    }

    #[test]
    fn small_material_is_kept_verbatim() {
        let c = compact(&[section("a", 1, "hello".into())], 1_000);
        assert_eq!(c.verbatim, vec!["a"]);
        assert!(c.text.contains("hello"));
        assert!(c.summarized.is_empty() && c.omitted.is_empty());
    }

    #[test]
    fn large_material_is_summarized_within_budget_and_keeps_salient_lines() {
        let mut lines: Vec<String> = (0..400).map(|i| format!("ordinary line number {i}")).collect();
        lines.insert(250, "CRITICAL finding: SQL injection in login handler".into());
        let big = section("security", 9, lines.join("\n"));
        let other = section("deps", 5, "x".repeat(5_000));
        let c = compact(&[other, big], 3_000);
        assert!(c.final_chars <= 3_100, "{}", c.final_chars);
        assert!(c.text.contains("CRITICAL finding"));
        assert!(c.summarized.contains(&"security".to_owned()));
        assert!(c.original_chars > c.final_chars);
    }

    #[test]
    fn tiny_budgets_report_omissions() {
        let sections: Vec<Section> = (0..10)
            .map(|i| section(&format!("s{i}"), i, "word ".repeat(400)))
            .collect();
        let c = compact(&sections, 800);
        assert!(!c.omitted.is_empty());
        assert!(c.text.contains("[context budget: omitted"));
    }

    #[test]
    fn json_is_flattened_with_bounded_arrays() {
        let v = json!({"a": {"b": [1,2,3,4,5,6,7,8,9,10]}, "s": "text"});
        let lines = flatten_json(&v);
        assert!(lines.contains(&"a.b[0]: 1".to_owned()));
        assert!(lines.iter().any(|l| l.contains("+2 more items")));
        assert!(lines.contains(&"s: text".to_owned()));
        assert_eq!(estimate_tokens("abcdefgh"), 2);
    }
}
