//! Repository secret scanning with a persisted finding lifecycle.
//!
//! Raw secret values are never persisted or returned: findings store a redacted preview
//! and a fingerprint derived from a project-salted digest of the value.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

use crate::{deterministic_id, normalize_relative_path, AnalysisStatus, Database};

const ANALYZER_KEY: &str = "secret_scanning";
const ANALYZER_VERSION: &str = "secret-scanning-v1";
const MAX_FILES: usize = 50_000;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 24;
const MAX_QUERY: usize = 1_000;

#[derive(Debug, Error)]
pub enum SecretScanError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretScanSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub coverage_complete: bool,
    pub files_considered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub observations: usize,
    pub observations_in_test_paths: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretFindingRecord {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub relative_path: String,
    pub line: Option<usize>,
    pub redacted: String,
    pub in_test_path: bool,
    pub remediation: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretScanRunRecord {
    pub run_id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub coverage_complete: bool,
    pub files_scanned: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_resolved: usize,
}

struct Observed {
    fingerprint: String,
    relative_path: String,
    observation: secret_scanner::SecretObservation,
}

struct Collection {
    observed: Vec<Observed>,
    coverage_complete: bool,
    files_considered: usize,
    files_scanned: usize,
    files_skipped: usize,
}

pub struct SecretScanningService<'a> {
    database: &'a Database,
}

impl<'a> SecretScanningService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn scan_project(&self, project_id: &str) -> Result<SecretScanSummary, SecretScanError> {
        let connection = self.database.connection();
        let root = project_root(connection, project_id)?;
        let root = fs::canonicalize(&root)?;
        if !root.is_dir() {
            return Err(SecretScanError::InvalidProjectRoot(
                root.display().to_string(),
            ));
        }
        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = json!({
            "ruleset_version": secret_scanner::RULESET_VERSION,
            "max_files": MAX_FILES,
            "max_file_bytes": MAX_FILE_BYTES,
            "raw_secrets_persisted": false,
            "git_history_scanned": false,
            "repository_commands_executed": false,
        })
        .to_string();
        connection.execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, started_at, configuration_json, run_kind) \
             VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'secret_scanning')",
            params![run_id, project_id, ANALYZER_VERSION, configuration_json],
        )?;

        let collection = match collect(project_id, &root) {
            Ok(collection) => collection,
            Err(error) => {
                let _ = finish_run(
                    connection,
                    &run_id,
                    AnalysisStatus::Failed,
                    elapsed_ms(started),
                );
                return Err(error);
            }
        };
        let duration_ms = elapsed_ms(started);
        persist(connection, project_id, &run_id, collection, duration_ms).inspect_err(|_| {
            let _ = finish_run(connection, &run_id, AnalysisStatus::Failed, duration_ms);
        })
    }

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SecretFindingRecord>, SecretScanError> {
        let mut statement = self.database.connection().prepare(
            "SELECT f.id, f.sub_category, f.severity, COALESCE(f.confidence, 0), f.title, f.description, \
                    COALESCE(e.uri, ''), e.line_start, COALESCE(e.metadata_json, '{}'), f.status, \
                    f.first_seen, f.last_seen, f.resolved_at \
             FROM findings f \
             LEFT JOIN finding_evidence e ON e.finding_id = f.id \
             WHERE f.project_id = ?1 AND f.analyzer_key = ?2 AND (?3 IS NULL OR f.status = ?3) \
             ORDER BY f.status = 'open' DESC, \
                      CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, \
                      f.last_seen DESC \
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![project_id, ANALYZER_KEY, status, bounded(limit)],
            |row| {
                let metadata: serde_json::Value =
                    serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default();
                Ok(SecretFindingRecord {
                    id: row.get(0)?,
                    rule_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    severity: row.get(2)?,
                    confidence: row.get(3)?,
                    title: row.get(4)?,
                    description: row.get(5)?,
                    relative_path: row.get(6)?,
                    line: row.get::<_, Option<i64>>(7)?.map(to_usize),
                    redacted: metadata["redacted"]
                        .as_str()
                        .unwrap_or("********")
                        .to_string(),
                    in_test_path: metadata["in_test_path"].as_bool().unwrap_or(false),
                    remediation: metadata["remediation"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    status: row.get(9)?,
                    first_seen: row.get(10)?,
                    last_seen: row.get(11)?,
                    resolved_at: row.get(12)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<SecretScanRunRecord>, SecretScanError> {
        let mut statement = self.database.connection().prepare(
            "SELECT r.id, r.status, r.started_at, r.finished_at, r.duration_ms, \
                    COALESCE(m.coverage_complete, 0), COALESCE(m.files_scanned, 0), \
                    COALESCE(m.observations, 0), COALESCE(m.findings_opened, 0), \
                    COALESCE(m.findings_resolved, 0) \
             FROM analysis_runs r LEFT JOIN secret_scan_run_metrics m ON m.run_id = r.id \
             WHERE r.project_id = ?1 AND r.run_kind = 'secret_scanning' \
             ORDER BY r.started_at DESC, r.rowid DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id, bounded(limit.min(100))], |row| {
            Ok(SecretScanRunRecord {
                run_id: row.get(0)?,
                status: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                duration_ms: row
                    .get::<_, Option<i64>>(4)?
                    .map(|value| value.max(0) as u64),
                coverage_complete: row.get::<_, i64>(5)? == 1,
                files_scanned: to_usize(row.get(6)?),
                observations: to_usize(row.get(7)?),
                findings_opened: to_usize(row.get(8)?),
                findings_resolved: to_usize(row.get(9)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn collect(project_id: &str, root: &Path) -> Result<Collection, SecretScanError> {
    let mut collection = Collection {
        observed: Vec::new(),
        coverage_complete: true,
        files_considered: 0,
        files_scanned: 0,
        files_skipped: 0,
    };
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_DEPTH)
        .into_iter()
        .filter_entry(|entry| !should_skip(entry));
    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                // An unreadable directory means we cannot prove its secrets are gone.
                collection.coverage_complete = false;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        collection.files_considered += 1;
        if collection.files_considered > MAX_FILES {
            collection.coverage_complete = false;
            break;
        }
        let Some(relative_path) = entry
            .path()
            .strip_prefix(root)
            .ok()
            .and_then(|path| path.to_str())
            .and_then(|path| normalize_relative_path(path, false))
        else {
            collection.files_skipped += 1;
            continue;
        };
        if entry
            .metadata()
            .map_or(true, |metadata| metadata.len() > MAX_FILE_BYTES)
        {
            collection.files_skipped += 1;
            continue;
        }
        let bytes = match fs::read(entry.path()) {
            Ok(bytes) => bytes,
            Err(_) => {
                collection.files_skipped += 1;
                collection.coverage_complete = false;
                continue;
            }
        };
        if secret_scanner::looks_binary(&bytes) {
            collection.files_skipped += 1;
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            collection.files_skipped += 1;
            continue;
        };
        collection.files_scanned += 1;
        for observation in secret_scanner::scan_text(&relative_path, &text) {
            let (start, end) = observation.secret_range;
            let value_digest = salted_digest(project_id, &text[start..end]);
            let fingerprint = deterministic_id(
                "secret-finding",
                &[
                    project_id,
                    observation.rule_id,
                    &relative_path,
                    &value_digest,
                ],
            );
            collection.observed.push(Observed {
                fingerprint,
                relative_path: relative_path.clone(),
                observation,
            });
        }
    }
    // The same value repeated on several lines of one file is one finding.
    let mut seen = BTreeSet::new();
    collection
        .observed
        .retain(|item| seen.insert(item.fingerprint.clone()));
    Ok(collection)
}

fn persist(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    collection: Collection,
    duration_ms: u64,
) -> Result<SecretScanSummary, SecretScanError> {
    let existing = existing_findings(connection, project_id)?;
    let observed: BTreeSet<&str> = collection
        .observed
        .iter()
        .map(|item| item.fingerprint.as_str())
        .collect();
    let findings_opened = collection
        .observed
        .iter()
        .filter(|item| !existing.contains_key(item.fingerprint.as_str()))
        .count();
    let findings_refreshed = collection.observed.len() - findings_opened;
    let findings_resolved = if collection.coverage_complete {
        existing
            .iter()
            .filter(|(fingerprint, (_, status))| {
                status == "open" && !observed.contains(fingerprint.as_str())
            })
            .count()
    } else {
        0
    };
    let in_test_paths = collection
        .observed
        .iter()
        .filter(|item| item.observation.in_test_path)
        .count();

    let transaction = connection.unchecked_transaction()?;
    if collection.coverage_complete {
        transaction.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, last_run_id = ?2 \
             WHERE project_id = ?1 AND analyzer_key = ?3 AND status = 'open'",
            params![project_id, run_id, ANALYZER_KEY],
        )?;
    }
    for item in &collection.observed {
        let observation = &item.observation;
        let finding_id = existing.get(item.fingerprint.as_str()).map_or_else(
            || deterministic_id("finding", &[project_id, ANALYZER_KEY, &item.fingerprint]),
            |(id, _)| id.clone(),
        );
        let file_id: Option<String> = transaction
            .query_row(
                "SELECT id FROM files WHERE project_id = ?1 AND relative_path = ?2",
                params![project_id, item.relative_path],
                |row| row.get(0),
            )
            .optional()?;
        let description = format!(
            "{} in {} (line {}). Preview: {}.{}",
            observation.title,
            item.relative_path,
            observation.line,
            observation.redacted,
            if observation.in_test_path {
                " Found in a test/fixture/example path; confidence is reduced."
            } else {
                ""
            }
        );
        transaction.execute(
            "INSERT INTO findings( \
               id, project_id, run_id, category, sub_category, severity, confidence, title, description, \
               file_id, symbol_id, source_start_line, source_end_line, cwe, owasp, status, fingerprint, \
               rule_version, first_seen, last_seen, analyzer_key, last_run_id, resolved_at \
             ) VALUES (?1, ?2, ?3, 'secrets', ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?10, 'CWE-798', \
                       'A07:2021 Identification and Authentication Failures', 'open', ?11, ?12, \
                       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?13, ?3, NULL) \
             ON CONFLICT(project_id, fingerprint) DO UPDATE SET \
               run_id = excluded.run_id, severity = excluded.severity, confidence = excluded.confidence, \
               title = excluded.title, description = excluded.description, file_id = excluded.file_id, \
               source_start_line = excluded.source_start_line, source_end_line = excluded.source_end_line, \
               status = 'open', rule_version = excluded.rule_version, last_seen = CURRENT_TIMESTAMP, \
               last_run_id = excluded.last_run_id, resolved_at = NULL",
            params![
                finding_id,
                project_id,
                run_id,
                observation.rule_id,
                observation.severity.as_str(),
                observation.confidence,
                observation.title,
                description,
                file_id,
                to_i64(observation.line),
                item.fingerprint,
                secret_scanner::RULESET_VERSION,
                ANALYZER_KEY,
            ],
        )?;
        transaction.execute(
            "DELETE FROM finding_evidence WHERE finding_id = ?1",
            [&finding_id],
        )?;
        transaction.execute(
            "INSERT INTO finding_evidence(id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json) \
             VALUES (?1, ?2, 'secret_match', ?3, ?4, ?4, ?5, ?6)",
            params![
                deterministic_id("secret-evidence", &[&finding_id]),
                finding_id,
                item.relative_path,
                to_i64(observation.line),
                format!("Redacted value: {}", observation.redacted),
                json!({
                    "rule_id": observation.rule_id,
                    "redacted": observation.redacted,
                    "in_test_path": observation.in_test_path,
                    "remediation": observation.remediation,
                    "raw_value_persisted": false,
                })
                .to_string(),
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO secret_scan_run_metrics( \
           run_id, coverage_complete, files_considered, files_scanned, files_skipped, observations, \
           observations_in_test_paths, findings_opened, findings_refreshed, findings_resolved \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            run_id,
            i64::from(collection.coverage_complete),
            to_i64(collection.files_considered),
            to_i64(collection.files_scanned),
            to_i64(collection.files_skipped),
            to_i64(collection.observed.len()),
            to_i64(in_test_paths),
            to_i64(findings_opened),
            to_i64(findings_refreshed),
            to_i64(findings_resolved),
        ],
    )?;
    finish_run(&transaction, run_id, AnalysisStatus::Completed, duration_ms)?;
    transaction.commit()?;

    Ok(SecretScanSummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        coverage_complete: collection.coverage_complete,
        files_considered: collection.files_considered,
        files_scanned: collection.files_scanned,
        files_skipped: collection.files_skipped,
        observations: collection.observed.len(),
        observations_in_test_paths: in_test_paths,
        findings_opened,
        findings_refreshed,
        findings_resolved,
        duration_ms,
    })
}

fn existing_findings(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, (String, String)>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, id, status FROM findings WHERE project_id = ?1 AND analyzer_key = ?2",
    )?;
    let rows = statement.query_map(params![project_id, ANALYZER_KEY], |row| {
        Ok((row.get(0)?, (row.get(1)?, row.get(2)?)))
    })?;
    rows.collect()
}

/// Project-salted digest so the same secret yields different fingerprints per project
/// and a fingerprint cannot be matched against a global list of leaked values.
pub(crate) fn salted_digest(project_id: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codetwin-secret\0");
    digest.update(project_id.as_bytes());
    digest.update(b"\0");
    digest.update(value.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn should_skip(entry: &DirEntry) -> bool {
    entry.depth() > 0
        && entry.file_type().is_dir()
        && entry.file_name().to_str().is_some_and(is_skipped_dir)
}

/// Directories neither secret scan descends into: VCS metadata, dependencies, build output.
pub(crate) fn is_skipped_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | ".venv"
            | "venv"
            | "dist"
            | "build"
            | "coverage"
            | ".next"
            | ".turbo"
            | ".cache"
            | "vendor"
            | "__pycache__"
    )
}

pub(crate) fn project_root(
    connection: &Connection,
    project_id: &str,
) -> Result<PathBuf, SecretScanError> {
    connection
        .query_row(
            "SELECT root_path FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(PathBuf::from)
        .ok_or_else(|| SecretScanError::ProjectNotFound(project_id.to_string()))
}

pub(crate) fn finish_run(
    connection: &Connection,
    run_id: &str,
    status: AnalysisStatus,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET status = ?2, finished_at = CURRENT_TIMESTAMP, duration_ms = ?3 WHERE id = ?1",
        params![run_id, status.as_db(), i64::try_from(duration_ms).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    deterministic_id("secret-scan-run", &[project_id, &nanos.to_string()])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn bounded(limit: usize) -> i64 {
    i64::try_from(limit.clamp(1, MAX_QUERY)).unwrap_or(1)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
