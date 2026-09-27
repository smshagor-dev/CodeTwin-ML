//! Scores CodeTwin's deterministic analyzers against the pinned Hugging Face datasets that the
//! installer downloads, and writes JSON, Markdown and HTML reports.
//!
//! Nothing here downloads data: a dataset is evaluated only if its files are already on disk
//! and match the catalog's size and SHA-256 pins.

pub mod catalog;
pub mod metrics;
pub mod report;
pub mod table;

use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use catalog::{BenchmarkTask, Catalog, DatasetSpec, EMBEDDED_CATALOG};
pub use metrics::{
    Confusion, CweStats, RepairPairMetrics, RuleStats, Scores, SecretProbeMetrics,
    VulnerabilityMetrics,
};
pub use report::{render_html, render_markdown, write_report, ReportFiles};
pub use table::ColumnMapping;

use table::{normalize_language, parse_cwes, parse_label, resolve_columns, Table, Value};

pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_SPLIT: &str = "test";
pub const DEFAULT_MAX_SAMPLES: usize = 2_000;
pub const MAX_SAMPLES_LIMIT: usize = 200_000;
pub const DEFAULT_MAX_CODE_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("dataset catalog: {0}")]
    Catalog(String),
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("parquet: {0}")]
    Parquet(String),
    #[error("report: {0}")]
    Report(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkOptions {
    pub datasets_root: PathBuf,
    /// Empty = every catalog dataset with a benchmark profile.
    pub dataset_ids: Vec<String>,
    pub split: String,
    /// Upper bound on samples per dataset; rows are taken at an even stride across the split.
    pub max_samples: usize,
    pub max_code_bytes: usize,
}

impl BenchmarkOptions {
    pub fn new(datasets_root: impl Into<PathBuf>) -> Self {
        Self {
            datasets_root: datasets_root.into(),
            dataset_ids: Vec::new(),
            split: DEFAULT_SPLIT.to_string(),
            max_samples: DEFAULT_MAX_SAMPLES,
            max_code_bytes: DEFAULT_MAX_CODE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetStatus {
    Evaluated,
    /// Files are not installed under the datasets root.
    NotInstalled,
    /// A file exists but its size or SHA-256 does not match the catalog pin.
    IntegrityFailed,
    /// The parquet columns could not be mapped to the benchmark task.
    SchemaUnrecognized,
    /// The catalog has no benchmark profile for this dataset.
    NoProfile,
    /// The split has no files or the files could not be read.
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCheck {
    pub path: String,
    pub present: bool,
    pub verified: bool,
    pub sha256: Option<String>,
    pub rows: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetResult {
    pub id: String,
    pub name: String,
    pub repository: String,
    pub revision: String,
    pub license: String,
    pub license_url: String,
    pub task: Option<BenchmarkTask>,
    pub split: String,
    pub status: DatasetStatus,
    pub message: Option<String>,
    pub files: Vec<FileCheck>,
    pub columns: Option<ColumnMapping>,
    pub total_rows: u64,
    pub stride: u64,
    pub vulnerability: Option<VulnerabilityMetrics>,
    pub repair_pairs: Option<RepairPairMetrics>,
    pub secret_probe: Option<SecretProbeMetrics>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerVersions {
    pub codetwin: String,
    pub security_analyzer: String,
    pub security_ruleset: String,
    pub secret_scanner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub generated_at: String,
    pub analyzers: AnalyzerVersions,
    pub options: BenchmarkOptions,
    pub datasets: Vec<DatasetResult>,
    pub duration_ms: u64,
}

impl BenchmarkReport {
    pub fn evaluated(&self) -> usize {
        self.datasets
            .iter()
            .filter(|dataset| dataset.status == DatasetStatus::Evaluated)
            .count()
    }
}

pub fn analyzer_versions() -> AnalyzerVersions {
    AnalyzerVersions {
        codetwin: env!("CARGO_PKG_VERSION").to_string(),
        security_analyzer: security_analyzer::ANALYZER_VERSION.to_string(),
        security_ruleset: security_analyzer::RULESET_VERSION.to_string(),
        secret_scanner: secret_scanner::ANALYZER_VERSION.to_string(),
    }
}

pub fn run_benchmark(catalog: &Catalog, options: &BenchmarkOptions) -> BenchmarkReport {
    let started = Instant::now();
    let selected: Vec<&DatasetSpec> = if options.dataset_ids.is_empty() {
        catalog
            .datasets
            .iter()
            .filter(|dataset| dataset.benchmark.is_some())
            .collect()
    } else {
        catalog
            .datasets
            .iter()
            .filter(|dataset| options.dataset_ids.contains(&dataset.id))
            .collect()
    };
    let datasets = selected
        .into_iter()
        .map(|dataset| evaluate_dataset(dataset, options))
        .collect();
    BenchmarkReport {
        schema_version: REPORT_SCHEMA_VERSION,
        generated_at: rfc3339_now(),
        analyzers: analyzer_versions(),
        options: options.clone(),
        datasets,
        duration_ms: elapsed_ms(started),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn evaluate_dataset(spec: &DatasetSpec, options: &BenchmarkOptions) -> DatasetResult {
    let started = Instant::now();
    let mut result = DatasetResult {
        id: spec.id.clone(),
        name: spec.name.clone(),
        repository: spec.repository.clone(),
        revision: spec.revision.clone(),
        license: spec.license.clone(),
        license_url: spec.license_url.clone(),
        task: spec.benchmark.as_ref().map(|profile| profile.task),
        split: options.split.clone(),
        status: DatasetStatus::Failed,
        message: None,
        files: Vec::new(),
        columns: None,
        total_rows: 0,
        stride: 1,
        vulnerability: None,
        repair_pairs: None,
        secret_probe: None,
        duration_ms: 0,
    };
    let outcome = evaluate_inner(spec, options, &mut result);
    if let Err((status, message)) = outcome {
        result.status = status;
        result.message = Some(message);
    } else {
        result.status = DatasetStatus::Evaluated;
    }
    result.duration_ms = elapsed_ms(started);
    result
}

type Outcome = Result<(), (DatasetStatus, String)>;

fn evaluate_inner(
    spec: &DatasetSpec,
    options: &BenchmarkOptions,
    result: &mut DatasetResult,
) -> Outcome {
    let profile = spec.benchmark.as_ref().ok_or_else(|| {
        (
            DatasetStatus::NoProfile,
            "no benchmark profile in the dataset catalog".to_string(),
        )
    })?;
    let files = spec.split_files(&options.split);
    if files.is_empty() {
        return Err((
            DatasetStatus::Failed,
            format!(
                "split '{}' not in this dataset; available: {}",
                options.split,
                spec.splits().join(", ")
            ),
        ));
    }

    // Verify every file of the split before reading any of them.
    let root = spec.revision_root(&options.datasets_root);
    let mut paths = Vec::new();
    let mut missing = 0;
    let mut mismatched = Vec::new();
    for file in &files {
        let relative = catalog::safe_relative_path(&file.path)
            .map_err(|error| (DatasetStatus::Failed, error.to_string()))?;
        let path = root.join(relative);
        let mut check = FileCheck {
            path: file.path.clone(),
            present: path.is_file(),
            verified: false,
            sha256: None,
            rows: None,
        };
        if !check.present {
            missing += 1;
        } else {
            let size_ok = match (file.size_bytes, std::fs::metadata(&path)) {
                (Some(expected), Ok(metadata)) => metadata.len() == expected,
                (None, Ok(_)) => true,
                (_, Err(_)) => false,
            };
            let hash = sha256_file(&path).ok();
            check.verified = size_ok
                && hash.is_some()
                && file
                    .sha256
                    .as_deref()
                    .is_some_and(|expected| Some(expected) == hash.as_deref());
            check.sha256 = hash;
            if !check.verified {
                mismatched.push(file.path.clone());
            }
        }
        result.files.push(check);
        paths.push(path);
    }
    if missing > 0 {
        return Err((
            DatasetStatus::NotInstalled,
            format!(
                "{missing} of {} file(s) for split '{}' are not installed under {}",
                files.len(),
                options.split,
                root.display()
            ),
        ));
    }
    if !mismatched.is_empty() {
        return Err((
            DatasetStatus::IntegrityFailed,
            format!(
                "size or SHA-256 does not match the catalog pin: {}; reinstall the dataset",
                mismatched.join(", ")
            ),
        ));
    }

    let tables = paths
        .iter()
        .map(|path| Table::open(path))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| (DatasetStatus::Failed, error.to_string()))?;
    for (check, table) in result.files.iter_mut().zip(&tables) {
        check.rows = Some(table.num_rows());
    }
    result.total_rows = tables.iter().map(Table::num_rows).sum();
    let columns = tables[0].columns();
    let mapping = resolve_columns(profile, &columns)
        .map_err(|message| (DatasetStatus::SchemaUnrecognized, message))?;
    result.columns = Some(mapping.clone());
    let limit = options.max_samples.clamp(1, MAX_SAMPLES_LIMIT);
    let stride = result.total_rows.div_ceil(limit as u64).max(1);
    result.stride = stride;

    let wanted = mapping.wanted();
    let index_of = |name: &Option<String>| {
        name.as_ref()
            .and_then(|name| wanted.iter().position(|column| column == name))
    };
    let default_language = profile.default_language.clone().unwrap_or_default();
    let mut remaining = limit;
    let read_error = |error: BenchmarkError| (DatasetStatus::Failed, error.to_string());

    match profile.task {
        BenchmarkTask::VulnerabilityDetection => {
            let (code_at, label_at) = (index_of(&mapping.code), index_of(&mapping.label));
            let (cwe_at, language_at) = (index_of(&mapping.cwe), index_of(&mapping.language));
            let mut metrics = VulnerabilityMetrics::default();
            let mut secrets = SecretProbeMetrics::default();
            for table in &tables {
                if remaining == 0 {
                    break;
                }
                let mut visited = 0;
                table
                    .for_each_row(&wanted, stride, remaining, |_, row| {
                        visited += 1;
                        metrics.rows_read += 1;
                        let get = |at: Option<usize>| at.map(|at| &row[at]).unwrap_or(&Value::Null);
                        let language = get(language_at)
                            .as_text()
                            .map(normalize_language)
                            .unwrap_or_else(|| default_language.clone());
                        let code = get(code_at).as_text().unwrap_or_default();
                        let Some(vulnerable) = parse_label(get(label_at)) else {
                            metrics.skipped_unlabeled += 1;
                            return;
                        };
                        if code.trim().is_empty() {
                            metrics.skipped_empty += 1;
                            return;
                        }
                        if code.len() > options.max_code_bytes {
                            metrics.skipped_oversize += 1;
                            return;
                        }
                        record_secrets(&mut secrets, code);
                        match security_analyzer::analyze_source(&language, code) {
                            Ok(analysis) => {
                                metrics.parsed_with_errors +=
                                    u64::from(analysis.parsed_with_errors);
                                let rules: BTreeSet<String> = analysis
                                    .observations
                                    .iter()
                                    .map(|item| item.rule_id.clone())
                                    .collect();
                                let cwes: BTreeSet<String> = analysis
                                    .observations
                                    .iter()
                                    .map(|item| item.cwe.clone())
                                    .collect();
                                let labeled = parse_cwes(get(cwe_at));
                                metrics.record(&language, vulnerable, &labeled, &rules, &cwes);
                            }
                            Err(security_analyzer::SecurityAnalyzerError::UnsupportedLanguage(
                                _,
                            )) => {
                                *metrics
                                    .skipped_unsupported_language
                                    .entry(language.clone())
                                    .or_default() += 1;
                            }
                            Err(_) => metrics.analyzer_errors += 1,
                        }
                    })
                    .map_err(read_error)?;
                remaining = remaining.saturating_sub(visited);
            }
            metrics.finish();
            secrets.finish();
            let evaluated = metrics.evaluated;
            let unsupported: u64 = metrics.skipped_unsupported_language.values().sum();
            result.vulnerability = Some(metrics);
            result.secret_probe = Some(secrets);
            if evaluated == 0 {
                result.message = Some(if unsupported > 0 {
                    "no sample was in a language the security analyzer supports".to_string()
                } else {
                    "no labeled sample could be evaluated".to_string()
                });
            }
        }
        BenchmarkTask::RepairPairs => {
            let (before_at, after_at) = (index_of(&mapping.before), index_of(&mapping.after));
            let language_at = index_of(&mapping.language);
            let mut metrics = RepairPairMetrics::default();
            for table in &tables {
                if remaining == 0 {
                    break;
                }
                let mut visited = 0;
                table
                    .for_each_row(&wanted, stride, remaining, |_, row| {
                        visited += 1;
                        metrics.rows_read += 1;
                        let get = |at: Option<usize>| at.map(|at| &row[at]).unwrap_or(&Value::Null);
                        let language = get(language_at)
                            .as_text()
                            .map(normalize_language)
                            .unwrap_or_else(|| default_language.clone());
                        let before = get(before_at).as_text().unwrap_or_default();
                        let after = get(after_at).as_text().unwrap_or_default();
                        if before.trim().is_empty() || after.trim().is_empty() {
                            metrics.skipped_empty += 1;
                            return;
                        }
                        if before.len().max(after.len()) > options.max_code_bytes {
                            metrics.skipped_oversize += 1;
                            return;
                        }
                        let analyze = |code: &str| {
                            security_analyzer::analyze_source(&language, code).map(|analysis| {
                                analysis
                                    .observations
                                    .into_iter()
                                    .map(|item| item.rule_id)
                                    .collect::<BTreeSet<String>>()
                            })
                        };
                        match (analyze(before), analyze(after)) {
                            (Ok(before_rules), Ok(after_rules)) => {
                                metrics.pairs_evaluated += 1;
                                metrics.findings_before += before_rules.len() as u64;
                                metrics.findings_after += after_rules.len() as u64;
                                if !before_rules.is_empty() {
                                    metrics.pairs_flagged_before += 1;
                                    if after_rules.is_empty() {
                                        metrics.pairs_cleared_by_fix += 1;
                                    }
                                }
                                let introduced: Vec<&String> =
                                    after_rules.difference(&before_rules).collect();
                                if !introduced.is_empty() {
                                    metrics.pairs_with_new_findings += 1;
                                }
                                for rule in introduced {
                                    *metrics
                                        .rules_introduced_by_fix
                                        .entry(rule.clone())
                                        .or_default() += 1;
                                }
                                for rule in before_rules.difference(&after_rules) {
                                    *metrics
                                        .rules_removed_by_fix
                                        .entry(rule.clone())
                                        .or_default() += 1;
                                }
                            }
                            (
                                Err(security_analyzer::SecurityAnalyzerError::UnsupportedLanguage(
                                    _,
                                )),
                                _,
                            )
                            | (
                                _,
                                Err(security_analyzer::SecurityAnalyzerError::UnsupportedLanguage(
                                    _,
                                )),
                            ) => {
                                *metrics
                                    .skipped_unsupported_language
                                    .entry(language.clone())
                                    .or_default() += 1;
                            }
                            _ => metrics.analyzer_errors += 1,
                        }
                    })
                    .map_err(read_error)?;
                remaining = remaining.saturating_sub(visited);
            }
            if metrics.pairs_evaluated == 0 && !metrics.skipped_unsupported_language.is_empty() {
                result.message = Some(format!(
                    "the security analyzer does not support {}; pairs were read but not scored",
                    metrics
                        .skipped_unsupported_language
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            result.repair_pairs = Some(metrics);
        }
        BenchmarkTask::SecretProbe => {
            let text_at: Vec<usize> = mapping
                .text
                .iter()
                .filter_map(|name| wanted.iter().position(|column| column == name))
                .collect();
            let mut secrets = SecretProbeMetrics::default();
            for table in &tables {
                if remaining == 0 {
                    break;
                }
                let mut visited = 0;
                table
                    .for_each_row(&wanted, stride, remaining, |_, row| {
                        visited += 1;
                        for at in &text_at {
                            if let Some(text) = row[*at].as_text() {
                                if !text.trim().is_empty() && text.len() <= options.max_code_bytes {
                                    record_secrets(&mut secrets, text);
                                }
                            }
                        }
                    })
                    .map_err(read_error)?;
                remaining = remaining.saturating_sub(visited);
            }
            secrets.finish();
            result.secret_probe = Some(secrets);
        }
    }
    Ok(())
}

fn record_secrets(metrics: &mut SecretProbeMetrics, text: &str) {
    // A neutral source path: test-path heuristics should not change the probe.
    let observations = secret_scanner::scan_text("dataset/sample.txt", text);
    let rules: Vec<&str> = observations.iter().map(|item| item.rule_id).collect();
    metrics.record(&rules);
}

fn rfc3339_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    rfc3339(seconds)
}

/// UTC timestamp without a date-time dependency (civil-from-days, Howard Hinnant).
pub fn rfc3339(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let seconds_of_day = unix_seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day / 60) % 60,
        seconds_of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_790_532_245), "2026-09-27T18:04:05Z");
    }
}
