//! Scores the Java rules against the OWASP Benchmark (https://github.com/OWASP-Benchmark/BenchmarkJava).
//!
//! cargo run --release -p security-analyzer --example owasp_benchmark -- <BenchmarkJava checkout>
//!
//! Each test case is one servlet with a known answer in `expectedresults-1.2.csv`. A test case
//! counts as flagged for a category when any rule mapped to that category fires in its file.
//! The Benchmark score is true-positive rate minus false-positive rate (0 = guessing).

use std::{collections::BTreeMap, path::PathBuf};

use security_analyzer::analyze_source;

fn category_rules(category: &str, include_review: bool) -> &'static [&'static str] {
    match (category, include_review) {
        ("sqli", false) => &["web.sql.request_to_query"],
        ("sqli", true) => &["web.sql.request_to_query", "java.sql.concatenated_query"],
        ("cmdi", false) => &["web.command.request_to_process"],
        ("cmdi", true) => &[
            "web.command.request_to_process",
            "java.command.dynamic_exec",
        ],
        ("hash", _) => &["security.weak_cryptographic_hash"],
        ("crypto", _) => &["java.crypto.weak_cipher"],
        ("pathtraver", _) => &["web.path.request_to_file"],
        ("xss", _) => &["web.xss.request_to_response"],
        ("ldapi", _) => &["web.ldap.request_to_filter"],
        ("xpathi", _) => &["web.xpath.request_to_expression"],
        ("securecookie", _) => &["java.cookie.not_secure"],
        _ => &[],
    }
}

#[derive(Default)]
struct Counts {
    review_tp: u32,
    review_fp: u32,
    tp: u32,
    fp: u32,
    tn: u32,
    fn_: u32,
}

fn main() {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: owasp_benchmark <BenchmarkJava>"),
    );
    let expected = std::fs::read_to_string(root.join("expectedresults-1.2.csv"))
        .expect("expectedresults-1.2.csv");
    let code = root.join("src/main/java/org/owasp/benchmark/testcode");
    let mut per_category: BTreeMap<String, Counts> = BTreeMap::new();
    let mut parse_errors = 0;

    for line in expected.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split(',').collect();
        let [name, category, real, _cwe] = fields.as_slice() else {
            continue;
        };
        let rules = category_rules(category, false);
        let review_rules = category_rules(category, true);
        let counts = per_category.entry((*category).to_string()).or_default();
        if rules.is_empty() {
            continue;
        }
        let source = std::fs::read_to_string(code.join(format!("{name}.java"))).expect("test case");
        let result = analyze_source("Java", &source).expect("analyze");
        parse_errors += u32::from(result.parsed_with_errors);
        let flagged = result
            .observations
            .iter()
            .any(|item| rules.contains(&item.rule_id.as_str()));
        let review_flagged = result
            .observations
            .iter()
            .any(|item| review_rules.contains(&item.rule_id.as_str()));
        if review_flagged && *real == "true" {
            counts.review_tp += 1;
        } else if review_flagged {
            counts.review_fp += 1;
        }
        match (*real == "true", flagged) {
            (true, true) => counts.tp += 1,
            (false, true) => counts.fp += 1,
            (false, false) => counts.tn += 1,
            (true, false) => counts.fn_ += 1,
        }
    }

    println!(
        "{:<12} {:>5} {:>5} {:>5} {:>5} {:>7} {:>7} {:>7}",
        "category", "TP", "FP", "TN", "FN", "TPR", "FPR", "score"
    );
    let (mut sum_score, mut scored) = (0.0, 0);
    for (category, c) in &per_category {
        if category_rules(category, false).is_empty() {
            println!("{category:<12} (no rule for this category)");
            continue;
        }
        let tpr = f64::from(c.tp) / f64::from((c.tp + c.fn_).max(1));
        let fpr = f64::from(c.fp) / f64::from((c.fp + c.tn).max(1));
        sum_score += tpr - fpr;
        scored += 1;
        println!(
            "{category:<12} {:>5} {:>5} {:>5} {:>5} {:>6.1}% {:>6.1}% {:>+7.1}",
            c.tp,
            c.fp,
            c.tn,
            c.fn_,
            tpr * 100.0,
            fpr * 100.0,
            (tpr - fpr) * 100.0
        );
        if category_rules(category, true) != category_rules(category, false) {
            let positives = f64::from((c.tp + c.fn_).max(1));
            let negatives = f64::from((c.fp + c.tn).max(1));
            let (rtpr, rfpr) = (
                f64::from(c.review_tp) / positives,
                f64::from(c.review_fp) / negatives,
            );
            println!(
                "{:<12} {:>5} {:>5} {:>5} {:>5} {:>6.1}% {:>6.1}% {:>+7.1}   (with review-level rules)",
                format!("  +review"),
                c.review_tp,
                c.review_fp,
                (c.fp + c.tn) - c.review_fp,
                (c.tp + c.fn_) - c.review_tp,
                rtpr * 100.0,
                rfpr * 100.0,
                (rtpr - rfpr) * 100.0
            );
        }
    }
    println!(
        "average score over {scored} covered categories: {:+.1}",
        sum_score / f64::from(scored.max(1)) * 100.0
    );
    println!("files parsed with errors: {parse_errors}");
}
