use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    metrics::{RepairPairMetrics, Scores, SecretProbeMetrics, VulnerabilityMetrics},
    BenchmarkError, BenchmarkReport, DatasetResult, DatasetStatus,
};

#[derive(Debug, Clone, Serialize)]
pub struct ReportFiles {
    pub directory: PathBuf,
    pub json: PathBuf,
    pub markdown: PathBuf,
    pub html: PathBuf,
}

/// Writes `report.json`, `report.md` and `report.html` into `directory` (created if needed).
pub fn write_report(
    report: &BenchmarkReport,
    directory: &Path,
) -> Result<ReportFiles, BenchmarkError> {
    fs::create_dir_all(directory).map_err(|error| BenchmarkError::Io(directory.into(), error))?;
    let files = ReportFiles {
        directory: directory.to_path_buf(),
        json: directory.join("report.json"),
        markdown: directory.join("report.md"),
        html: directory.join("report.html"),
    };
    let json = serde_json::to_string_pretty(report)
        .map_err(|error| BenchmarkError::Report(error.to_string()))?;
    for (path, contents) in [
        (&files.json, json),
        (&files.markdown, render_markdown(report)),
        (&files.html, render_html(report)),
    ] {
        fs::write(path, contents).map_err(|error| BenchmarkError::Io(path.clone(), error))?;
    }
    Ok(files)
}

fn percent(value: Option<f64>) -> String {
    value.map_or_else(
        || "n/a".to_string(),
        |value| format!("{:.1}%", value * 100.0),
    )
}

fn status_label(status: DatasetStatus) -> &'static str {
    match status {
        DatasetStatus::Evaluated => "evaluated",
        DatasetStatus::NotInstalled => "not installed",
        DatasetStatus::IntegrityFailed => "integrity check failed",
        DatasetStatus::SchemaUnrecognized => "columns not recognized",
        DatasetStatus::NoProfile => "no benchmark profile",
        DatasetStatus::Failed => "failed",
    }
}

/// Plain-language reading of the headline scores, so the report is not just numbers.
fn verdict(scores: &Scores) -> String {
    match (
        scores.f1,
        scores.always_flag_f1,
        scores.recall,
        scores.precision,
    ) {
        (Some(f1), Some(baseline), Some(recall), Some(precision)) => {
            let comparison = if f1 > baseline {
                "beats"
            } else {
                "does not beat"
            };
            format!(
                "The analyzer {comparison} the flag-everything baseline (F1 {:.3} vs {:.3}). It caught {} of labeled vulnerable samples, and {} of what it flagged was labeled vulnerable.",
                f1,
                baseline,
                percent(Some(recall)),
                percent(Some(precision))
            )
        }
        (_, _, Some(recall), None) => format!(
            "The analyzer flagged nothing, so precision is undefined and recall is {}.",
            percent(Some(recall))
        ),
        _ => "Not enough labeled samples to score.".to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Markdown

pub fn render_markdown(report: &BenchmarkReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# CodeTwin dataset benchmark\n");
    let _ = writeln!(
        out,
        "Generated {} · split `{}` · up to {} samples per dataset · {} of {} dataset(s) evaluated in {:.1}s\n",
        report.generated_at,
        report.options.split,
        report.options.max_samples,
        report.evaluated(),
        report.datasets.len(),
        report.duration_ms as f64 / 1000.0
    );
    let _ = writeln!(
        out,
        "Analyzers: security `{}` (ruleset `{}`), secret scanner `{}`.\n",
        report.analyzers.security_analyzer,
        report.analyzers.security_ruleset,
        report.analyzers.secret_scanner
    );
    let _ = writeln!(
        out,
        "These numbers measure CodeTwin's deterministic rules against public labeled data. Labels in public vulnerability datasets are noisy and many samples are fragments without their callers, so treat scores as a regression signal between versions, not as an absolute detection rate.\n"
    );

    let _ = writeln!(out, "## Summary\n");
    let _ = writeln!(
        out,
        "| Dataset | Task | Status | Samples | Precision | Recall | F1 | Baseline F1 |"
    );
    let _ = writeln!(
        out,
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"
    );
    for dataset in &report.datasets {
        let task = dataset
            .task
            .map(|task| {
                serde_json::to_value(task)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default()
            })
            .unwrap_or_else(|| "-".to_string());
        let (samples, scores) = match (
            &dataset.vulnerability,
            &dataset.repair_pairs,
            &dataset.secret_probe,
        ) {
            (Some(metrics), _, _) => (metrics.evaluated.to_string(), Some(metrics.scores)),
            (_, Some(pairs), _) => (pairs.pairs_evaluated.to_string(), None),
            (_, _, Some(probe)) => (probe.texts_scanned.to_string(), None),
            _ => ("-".to_string(), None),
        };
        let score = |pick: fn(&Scores) -> Option<f64>| {
            scores
                .as_ref()
                .map_or("-".to_string(), |s| percent(pick(s)))
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            md_escape(&dataset.name),
            task,
            status_label(dataset.status),
            samples,
            score(|s| s.precision),
            score(|s| s.recall),
            scores
                .as_ref()
                .and_then(|s| s.f1)
                .map_or("-".to_string(), |v| format!("{v:.3}")),
            scores
                .as_ref()
                .and_then(|s| s.always_flag_f1)
                .map_or("-".to_string(), |v| format!("{v:.3}")),
        );
    }
    out.push('\n');

    for dataset in &report.datasets {
        markdown_dataset(&mut out, dataset);
    }
    out
}

fn md_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace('\n', " ")
}

fn describe_columns(columns: &crate::ColumnMapping) -> String {
    let mut parts: Vec<String> = [
        ("code", &columns.code),
        ("label", &columns.label),
        ("cwe", &columns.cwe),
        ("language", &columns.language),
        ("before", &columns.before),
        ("after", &columns.after),
    ]
    .into_iter()
    .filter_map(|(role, column)| {
        column
            .as_ref()
            .map(|column| format!("{role} = `{}`", md_escape(column)))
    })
    .collect();
    if !columns.text.is_empty() {
        parts.push(format!(
            "text = {}",
            columns
                .text
                .iter()
                .map(|c| format!("`{}`", md_escape(c)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    parts.join(", ")
}

fn markdown_dataset(out: &mut String, dataset: &DatasetResult) {
    let _ = writeln!(out, "## {}\n", md_escape(&dataset.name));
    let _ = writeln!(
        out,
        "Source `{}` at revision `{}` · license `{}` ({}) · status **{}**\n",
        dataset.repository,
        dataset.revision,
        dataset.license,
        dataset.license_url,
        status_label(dataset.status)
    );
    if let Some(message) = &dataset.message {
        let _ = writeln!(out, "> {}\n", md_escape(message));
    }
    if !dataset.files.is_empty() {
        let _ = writeln!(out, "| File | Rows | Verified |\n| --- | ---: | --- |");
        for file in &dataset.files {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} |",
                file.path,
                file.rows.map_or("-".to_string(), |rows| rows.to_string()),
                if file.verified {
                    "SHA-256 match"
                } else if file.present {
                    "mismatch"
                } else {
                    "missing"
                }
            );
        }
        out.push('\n');
    }
    if let Some(columns) = &dataset.columns {
        let _ = writeln!(
            out,
            "Columns used: {} · sampled every {} row(s) of {}.\n",
            describe_columns(columns),
            dataset.stride,
            dataset.total_rows
        );
    }
    if let Some(metrics) = &dataset.vulnerability {
        markdown_vulnerability(out, metrics);
    }
    if let Some(pairs) = &dataset.repair_pairs {
        markdown_pairs(out, pairs);
    }
    if let Some(probe) = &dataset.secret_probe {
        markdown_secrets(out, probe);
    }
}

fn markdown_vulnerability(out: &mut String, metrics: &VulnerabilityMetrics) {
    let c = &metrics.confusion;
    let _ = writeln!(out, "### Vulnerability detection\n");
    let _ = writeln!(out, "{}\n", verdict(&metrics.scores));
    let _ = writeln!(
        out,
        "| | Flagged | Not flagged |\n| --- | ---: | ---: |\n| Labeled vulnerable | {} | {} |\n| Labeled safe | {} | {} |\n",
        c.true_positive, c.false_negative, c.false_positive, c.true_negative
    );
    let _ = writeln!(
        out,
        "Read {} rows, scored {}. Skipped: {} unlabeled, {} empty, {} oversize, {} in unsupported languages{}. {} sample(s) parsed with syntax errors; {} analyzer error(s).\n",
        metrics.rows_read,
        metrics.evaluated,
        metrics.skipped_unlabeled,
        metrics.skipped_empty,
        metrics.skipped_oversize,
        metrics.skipped_unsupported_language.values().sum::<u64>(),
        if metrics.skipped_unsupported_language.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                metrics
                    .skipped_unsupported_language
                    .iter()
                    .map(|(language, count)| format!("{language}: {count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        metrics.parsed_with_errors,
        metrics.analyzer_errors
    );
    if metrics.by_language.len() > 1 {
        let _ = writeln!(
            out,
            "| Language | Samples | Precision | Recall | F1 |\n| --- | ---: | ---: | ---: | ---: |"
        );
        for (language, stats) in &metrics.by_language {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                md_escape(language),
                stats.confusion.total(),
                percent(stats.scores.precision),
                percent(stats.scores.recall),
                stats
                    .scores
                    .f1
                    .map_or("n/a".to_string(), |v| format!("{v:.3}"))
            );
        }
        out.push('\n');
    }
    if !metrics.by_rule.is_empty() {
        let _ = writeln!(out, "| Rule | Fired on vulnerable | Fired on safe | Precision |\n| --- | ---: | ---: | ---: |");
        for (rule, stats) in &metrics.by_rule {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                rule,
                stats.fired_on_vulnerable,
                stats.fired_on_safe,
                percent(stats.precision)
            );
        }
        out.push('\n');
    }
    if !metrics.by_cwe.is_empty() {
        let mut rows: Vec<_> = metrics.by_cwe.iter().collect();
        rows.sort_by(|a, b| {
            b.1.vulnerable_samples
                .cmp(&a.1.vulnerable_samples)
                .then(a.0.cmp(b.0))
        });
        let _ = writeln!(out, "| CWE | Vulnerable samples | Flagged | Same CWE reported |\n| --- | ---: | ---: | ---: |");
        for (cwe, stats) in rows.into_iter().take(25) {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                cwe,
                stats.vulnerable_samples,
                percent(stats.recall_any),
                percent(stats.recall_same_cwe)
            );
        }
        out.push('\n');
    }
}

fn markdown_pairs(out: &mut String, pairs: &RepairPairMetrics) {
    let _ = writeln!(out, "### Fix pairs\n");
    let _ = writeln!(
        out,
        "Read {} pairs, scored {}. Buggy side flagged in {}; the fix cleared every finding in {}; the fix introduced a new rule in {}. Skipped: {} empty, {} oversize, {} unsupported language.\n",
        pairs.rows_read,
        pairs.pairs_evaluated,
        pairs.pairs_flagged_before,
        pairs.pairs_cleared_by_fix,
        pairs.pairs_with_new_findings,
        pairs.skipped_empty,
        pairs.skipped_oversize,
        pairs.skipped_unsupported_language.values().sum::<u64>()
    );
}

fn markdown_secrets(out: &mut String, probe: &SecretProbeMetrics) {
    let _ = writeln!(out, "### Secret scanner noise probe\n");
    let _ = writeln!(
        out,
        "{} text(s) scanned, {} with at least one hit ({} per 1,000). Public benchmark code rarely holds live credentials, so most hits here point at placeholder or test values the scanner should learn to skip.\n",
        probe.texts_scanned,
        probe.texts_with_hits,
        probe.hit_texts_per_thousand.map_or("n/a".to_string(), |v| format!("{v:.2}"))
    );
    if !probe.hits_by_rule.is_empty() {
        let _ = writeln!(out, "| Rule | Hits |\n| --- | ---: |");
        for (rule, hits) in &probe.hits_by_rule {
            let _ = writeln!(out, "| `{rule}` | {hits} |");
        }
        out.push('\n');
    }
}

// ---------------------------------------------------------------------------------------------
// HTML (self-contained, no scripts)

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

const STYLE: &str = r#"
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--good:#1f7a4d;--bad:#b3261e;--warn:#9a6700;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--ink:#ecebe6;--muted:#a2a19b;--line:#34332f;--good:#5cc28f;--bad:#f2867d;--warn:#e0b44c;--accent:#8aa6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:0 0 6px}h3{font-size:15px;margin:20px 0 8px}
.meta,.muted{color:var(--muted)}.note{border-left:3px solid var(--warn);padding:8px 12px;background:var(--panel);margin:16px 0}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin:18px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:12px 0}
.card{border:1px solid var(--line);border-radius:8px;padding:10px 12px}.card b{display:block;font-size:22px}.card small{color:var(--muted)}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;border:1px solid currentColor}.ok{color:var(--good)}.fail{color:var(--bad)}.skip{color:var(--warn)}
.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;min-width:60px}.bar i{display:block;height:100%;background:var(--accent)}
"#;

fn badge(status: DatasetStatus) -> String {
    let class = match status {
        DatasetStatus::Evaluated => "ok",
        DatasetStatus::IntegrityFailed | DatasetStatus::Failed => "fail",
        _ => "skip",
    };
    format!(
        "<span class=\"badge {class}\">{}</span>",
        status_label(status)
    )
}

fn bar(value: Option<f64>) -> String {
    match value {
        Some(value) => format!(
            "{} <div class=\"bar\"><i style=\"width:{:.1}%\"></i></div>",
            percent(Some(value)),
            (value * 100.0).clamp(0.0, 100.0)
        ),
        None => "n/a".to_string(),
    }
}

pub fn render_html(report: &BenchmarkReport) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CodeTwin dataset benchmark</title><style>{STYLE}</style></head><body><main>"
    );
    let _ = write!(
        out,
        "<h1>CodeTwin dataset benchmark</h1><p class=\"meta\">Generated {} · split <code>{}</code> · up to {} samples per dataset · {} of {} dataset(s) evaluated in {:.1}s<br>Security analyzer <code>{}</code> (ruleset <code>{}</code>) · secret scanner <code>{}</code></p>",
        escape(&report.generated_at),
        escape(&report.options.split),
        report.options.max_samples,
        report.evaluated(),
        report.datasets.len(),
        report.duration_ms as f64 / 1000.0,
        escape(&report.analyzers.security_analyzer),
        escape(&report.analyzers.security_ruleset),
        escape(&report.analyzers.secret_scanner)
    );
    let _ = write!(
        out,
        "<p class=\"note\">These scores measure CodeTwin's deterministic rules against public labeled data. Labels are noisy and many samples are fragments without their callers, so use them to compare versions, not as an absolute detection rate.</p>"
    );
    out.push_str("<section><h2>Summary</h2><div class=\"table-wrap\"><table><tr><th>Dataset</th><th>Status</th><th class=\"n\">Scored</th><th class=\"n\">Precision</th><th class=\"n\">Recall</th><th class=\"n\">F1</th><th class=\"n\">Baseline F1</th></tr>");
    for dataset in &report.datasets {
        let (scored, scores) = match (
            &dataset.vulnerability,
            &dataset.repair_pairs,
            &dataset.secret_probe,
        ) {
            (Some(metrics), _, _) => (metrics.evaluated.to_string(), Some(metrics.scores)),
            (_, Some(pairs), _) => (format!("{} pairs", pairs.pairs_evaluated), None),
            (_, _, Some(probe)) => (format!("{} texts", probe.texts_scanned), None),
            _ => ("-".to_string(), None),
        };
        let cell = |value: Option<String>| value.unwrap_or_else(|| "-".to_string());
        let _ = write!(
            out,
            "<tr><td>{}</td><td>{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td><td class=\"n\">{}</td></tr>",
            escape(&dataset.name),
            badge(dataset.status),
            scored,
            cell(scores.map(|s| percent(s.precision))),
            cell(scores.map(|s| percent(s.recall))),
            cell(scores.and_then(|s| s.f1).map(|v| format!("{v:.3}"))),
            cell(scores.and_then(|s| s.always_flag_f1).map(|v| format!("{v:.3}"))),
        );
    }
    out.push_str("</table></div></section>");
    for dataset in &report.datasets {
        html_dataset(&mut out, dataset);
    }
    out.push_str("</main></body></html>\n");
    out
}

fn html_dataset(out: &mut String, dataset: &DatasetResult) {
    let _ = write!(
        out,
        "<section><h2>{}</h2><p class=\"muted\"><code>{}</code> @ <code>{}</code> · license <a href=\"{}\">{}</a> · {}</p>",
        escape(&dataset.name),
        escape(&dataset.repository),
        escape(&dataset.revision),
        escape(&dataset.license_url),
        escape(&dataset.license),
        badge(dataset.status)
    );
    if let Some(message) = &dataset.message {
        let _ = write!(out, "<p class=\"note\">{}</p>", escape(message));
    }
    if let Some(metrics) = &dataset.vulnerability {
        let s = &metrics.scores;
        let _ = write!(
            out,
            "<p>{}</p><div class=\"cards\"><div class=\"card\"><b>{}</b><small>samples scored</small></div><div class=\"card\"><b>{}</b><small>precision</small></div><div class=\"card\"><b>{}</b><small>recall</small></div><div class=\"card\"><b>{}</b><small>F1 (baseline {})</small></div><div class=\"card\"><b>{}</b><small>flag rate (base rate {})</small></div></div>",
            escape(&verdict(s)),
            metrics.evaluated,
            percent(s.precision),
            percent(s.recall),
            s.f1.map_or("n/a".to_string(), |v| format!("{v:.3}")),
            s.always_flag_f1.map_or("n/a".to_string(), |v| format!("{v:.3}")),
            percent(s.flag_rate),
            percent(s.base_rate)
        );
        let c = &metrics.confusion;
        let _ = write!(
            out,
            "<div class=\"table-wrap\"><table><tr><th></th><th class=\"n\">Flagged</th><th class=\"n\">Not flagged</th></tr><tr><td>Labeled vulnerable</td><td class=\"n\">{}</td><td class=\"n\">{}</td></tr><tr><td>Labeled safe</td><td class=\"n\">{}</td><td class=\"n\">{}</td></tr></table></div>",
            c.true_positive, c.false_negative, c.false_positive, c.true_negative
        );
        let unsupported: u64 = metrics.skipped_unsupported_language.values().sum();
        let _ = write!(
            out,
            "<p class=\"muted\">Read {} rows. Skipped {} unlabeled, {} empty, {} oversize, {} unsupported language. {} parsed with syntax errors.</p>",
            metrics.rows_read, metrics.skipped_unlabeled, metrics.skipped_empty, metrics.skipped_oversize, unsupported, metrics.parsed_with_errors
        );
        if metrics.by_language.len() > 1 {
            out.push_str("<h3>By language</h3><div class=\"table-wrap\"><table><tr><th>Language</th><th class=\"n\">Samples</th><th>Precision</th><th>Recall</th></tr>");
            for (language, stats) in &metrics.by_language {
                let _ = write!(
                    out,
                    "<tr><td>{}</td><td class=\"n\">{}</td><td>{}</td><td>{}</td></tr>",
                    escape(language),
                    stats.confusion.total(),
                    bar(stats.scores.precision),
                    bar(stats.scores.recall)
                );
            }
            out.push_str("</table></div>");
        }
        if !metrics.by_rule.is_empty() {
            out.push_str("<h3>By rule</h3><div class=\"table-wrap\"><table><tr><th>Rule</th><th class=\"n\">On vulnerable</th><th class=\"n\">On safe</th><th>Precision</th></tr>");
            for (rule, stats) in &metrics.by_rule {
                let _ = write!(
                    out,
                    "<tr><td><code>{}</code></td><td class=\"n\">{}</td><td class=\"n\">{}</td><td>{}</td></tr>",
                    escape(rule),
                    stats.fired_on_vulnerable,
                    stats.fired_on_safe,
                    bar(stats.precision)
                );
            }
            out.push_str("</table></div>");
        }
        if !metrics.by_cwe.is_empty() {
            let mut rows: Vec<_> = metrics.by_cwe.iter().collect();
            rows.sort_by(|a, b| {
                b.1.vulnerable_samples
                    .cmp(&a.1.vulnerable_samples)
                    .then(a.0.cmp(b.0))
            });
            out.push_str("<h3>By CWE (top 25)</h3><div class=\"table-wrap\"><table><tr><th>CWE</th><th class=\"n\">Vulnerable samples</th><th>Flagged</th><th>Same CWE</th></tr>");
            for (cwe, stats) in rows.into_iter().take(25) {
                let _ = write!(
                    out,
                    "<tr><td>{}</td><td class=\"n\">{}</td><td>{}</td><td>{}</td></tr>",
                    escape(cwe),
                    stats.vulnerable_samples,
                    bar(stats.recall_any),
                    bar(stats.recall_same_cwe)
                );
            }
            out.push_str("</table></div>");
        }
    }
    if let Some(pairs) = &dataset.repair_pairs {
        let _ = write!(
            out,
            "<h3>Fix pairs</h3><div class=\"cards\"><div class=\"card\"><b>{}</b><small>pairs scored</small></div><div class=\"card\"><b>{}</b><small>buggy side flagged</small></div><div class=\"card\"><b>{}</b><small>cleared by fix</small></div><div class=\"card\"><b>{}</b><small>new finding after fix</small></div></div>",
            pairs.pairs_evaluated, pairs.pairs_flagged_before, pairs.pairs_cleared_by_fix, pairs.pairs_with_new_findings
        );
    }
    if let Some(probe) = &dataset.secret_probe {
        let _ = write!(
            out,
            "<h3>Secret scanner noise probe</h3><p class=\"muted\">{} text(s) scanned, {} with a hit ({} per 1,000). Hits on public benchmark code are almost always placeholders or published test keys.</p>",
            probe.texts_scanned,
            probe.texts_with_hits,
            probe.hit_texts_per_thousand.map_or("n/a".to_string(), |v| format!("{v:.2}"))
        );
        if !probe.hits_by_rule.is_empty() {
            out.push_str(
                "<div class=\"table-wrap\"><table><tr><th>Rule</th><th class=\"n\">Hits</th></tr>",
            );
            for (rule, hits) in &probe.hits_by_rule {
                let _ = write!(
                    out,
                    "<tr><td><code>{}</code></td><td class=\"n\">{hits}</td></tr>",
                    escape(rule)
                );
            }
            out.push_str("</table></div>");
        }
    }
    if !dataset.files.is_empty() {
        out.push_str("<h3>Files</h3><div class=\"table-wrap\"><table><tr><th>File</th><th class=\"n\">Rows</th><th>Integrity</th></tr>");
        for file in &dataset.files {
            let state = if file.verified {
                "<span class=\"ok\">SHA-256 match</span>"
            } else if file.present {
                "<span class=\"fail\">mismatch</span>"
            } else {
                "<span class=\"skip\">missing</span>"
            };
            let _ = write!(
                out,
                "<tr><td><code>{}</code></td><td class=\"n\">{}</td><td>{state}</td></tr>",
                escape(&file.path),
                file.rows.map_or("-".to_string(), |rows| rows.to_string())
            );
        }
        out.push_str("</table></div>");
    }
    out.push_str("</section>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escapes_untrusted_text() {
        assert_eq!(
            escape("<script>\"x\"&'"),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;"
        );
    }
}
