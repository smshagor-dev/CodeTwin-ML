use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use database_analyzer::{analyze_artifact, DatabaseArtifactKind, DatabaseObservation};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

use crate::{
    deterministic_id, is_windows_path_identity, normalize_relative_path, AnalysisStatus, Database,
    FindingEvidenceRecord,
};

const ANALYZER_KEY: &str = "database_analysis";
const ANALYZER_VERSION: &str = "database-analysis-v1";
const QUERY_VERSION: &str = "passive-database-artifacts-v1";
const RULE_VERSION: &str = "1";
const MAX_ARTIFACTS: usize = 10_000;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FINDINGS_QUERY: usize = 500;
const MAX_EVIDENCE_QUERY: usize = 500;
const MAX_HISTORY_QUERY: usize = 100;
const MAX_ARTIFACT_QUERY: usize = 500;

#[derive(Debug, Error)]
pub enum DatabaseAnalysisError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
    #[error("database artifact scan exceeds the bounded limit of {limit} artifacts")]
    TooManyArtifacts { limit: usize },
    #[error("unsafe database artifact path: {0}")]
    UnsafeArtifactPath(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseRunSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub coverage_complete: bool,
    pub artifacts_considered: usize,
    pub artifacts_analyzed: usize,
    pub artifacts_skipped: usize,
    pub sql_files: usize,
    pub prisma_schemas: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub destructive_statements: usize,
    pub unscoped_writes: usize,
    pub foreign_keys_disabled: usize,
    pub literal_datasource_urls: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseRunRecord {
    pub run_id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub coverage_complete: bool,
    pub artifacts_considered: usize,
    pub artifacts_analyzed: usize,
    pub artifacts_skipped: usize,
    pub sql_files: usize,
    pub prisma_schemas: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub destructive_statements: usize,
    pub unscoped_writes: usize,
    pub foreign_keys_disabled: usize,
    pub literal_datasource_urls: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseArtifactRecord {
    pub id: String,
    pub project_id: String,
    pub relative_path: String,
    pub artifact_kind: String,
    pub framework: Option<String>,
    pub content_hash: String,
    pub byte_size: u64,
    pub last_run_id: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseFindingRecord {
    pub id: String,
    pub project_id: String,
    pub run_id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: Option<f64>,
    pub title: String,
    pub description: String,
    pub source_start_line: Option<usize>,
    pub source_end_line: Option<usize>,
    pub status: String,
    pub fingerprint: String,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseRuleRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
struct ScannedArtifact {
    id: String,
    relative_path: String,
    path_identity: String,
    kind: DatabaseArtifactKind,
    framework: Option<String>,
    content_hash: String,
    byte_size: u64,
    observations: Vec<DatabaseObservation>,
}

#[derive(Debug, Default)]
struct ScanCollection {
    coverage_complete: bool,
    artifacts_considered: usize,
    artifacts_analyzed: usize,
    artifacts_skipped: usize,
    sql_files: usize,
    prisma_schemas: usize,
    artifacts: Vec<ScannedArtifact>,
}

#[derive(Debug, Clone)]
struct ExistingFinding {
    id: String,
    status: String,
}

pub struct DatabaseAnalysisService<'a> {
    database: &'a Database,
}

impl<'a> DatabaseAnalysisService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn analyze_project(
        &self,
        project_id: &str,
    ) -> Result<DatabaseRunSummary, DatabaseAnalysisError> {
        let (root, path_identity) = project_root(self.database.connection(), project_id)?;
        let canonical_root = fs::canonicalize(&root)?;
        if !canonical_root.is_dir() {
            return Err(DatabaseAnalysisError::InvalidProjectRoot(
                canonical_root.display().to_string(),
            ));
        }

        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = json!({
            "max_artifacts": MAX_ARTIFACTS,
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
            "max_depth": 8,
            "ruleset_version": database_analyzer::RULESET_VERSION,
            "database_connections_opened": false,
            "repository_commands_executed": false,
            "literal_datasource_values_persisted": false
        })
        .to_string();
        let config_fingerprint = deterministic_id(
            "database-analysis-config",
            &[
                ANALYZER_VERSION,
                QUERY_VERSION,
                database_analyzer::ANALYZER_VERSION,
                database_analyzer::RULESET_VERSION,
                &configuration_json,
            ],
        );

        self.database.connection().execute(
            "INSERT INTO analysis_runs(\
               id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint\
             ) VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'database_analysis', ?5, ?6)",
            params![
                run_id,
                project_id,
                ANALYZER_VERSION,
                configuration_json,
                QUERY_VERSION,
                config_fingerprint,
            ],
        )?;

        let collection = match scan_database_artifacts(
            project_id,
            &canonical_root,
            is_windows_path_identity(&path_identity),
        ) {
            Ok(collection) => collection,
            Err(error) => {
                let _ = finish_run(
                    self.database.connection(),
                    &run_id,
                    AnalysisStatus::Failed,
                    elapsed_ms(started),
                );
                return Err(error);
            }
        };

        let duration_ms = elapsed_ms(started);
        match persist_scan(
            self.database.connection(),
            project_id,
            &run_id,
            collection,
            duration_ms,
        ) {
            Ok(summary) => Ok(summary),
            Err(error) => {
                let _ = finish_run(
                    self.database.connection(),
                    &run_id,
                    AnalysisStatus::Failed,
                    duration_ms,
                );
                Err(error)
            }
        }
    }

    pub fn list_artifacts(
        &self,
        project_id: &str,
        active_only: bool,
        limit: usize,
    ) -> Result<Vec<DatabaseArtifactRecord>, DatabaseAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, relative_path, artifact_kind, framework, content_hash, byte_size,\
                    last_run_id, first_seen_at, last_seen_at, is_active\
             FROM database_artifacts\
             WHERE project_id = ?1 AND (?2 = 0 OR is_active = 1)\
             ORDER BY is_active DESC, artifact_kind, relative_path, id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![project_id, i64::from(active_only), bounded(limit, MAX_ARTIFACT_QUERY)],
            |row| {
                Ok(DatabaseArtifactRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    relative_path: row.get(2)?,
                    artifact_kind: row.get(3)?,
                    framework: row.get(4)?,
                    content_hash: row.get(5)?,
                    byte_size: to_u64(row.get(6)?),
                    last_run_id: row.get(7)?,
                    first_seen_at: row.get(8)?,
                    last_seen_at: row.get(9)?,
                    is_active: row.get::<_, i64>(10)? != 0,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DatabaseFindingRecord>, DatabaseAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, run_id, COALESCE(sub_category, ''), severity, confidence, title, description,\
                    source_start_line, source_end_line, status, fingerprint, first_seen, last_seen, resolved_at\
             FROM findings\
             WHERE project_id = ?1 AND analyzer_key = ?2 AND (?3 IS NULL OR status = ?3)\
             ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,\
                      status, last_seen DESC, id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![project_id, ANALYZER_KEY, status, bounded(limit, MAX_FINDINGS_QUERY)],
            |row| {
                Ok(DatabaseFindingRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    run_id: row.get(2)?,
                    rule_id: row.get(3)?,
                    severity: row.get(4)?,
                    confidence: row.get(5)?,
                    title: row.get(6)?,
                    description: row.get(7)?,
                    source_start_line: optional_usize(row.get(8)?),
                    source_end_line: optional_usize(row.get(9)?),
                    status: row.get(10)?,
                    fingerprint: row.get(11)?,
                    first_seen: row.get(12)?,
                    last_seen: row.get(13)?,
                    resolved_at: row.get(14)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn finding_evidence(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<FindingEvidenceRecord>, DatabaseAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json\
             FROM finding_evidence WHERE finding_id = ?1\
             ORDER BY COALESCE(uri, ''), COALESCE(line_start, 0), id LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![finding_id, bounded(limit, MAX_EVIDENCE_QUERY)],
            |row| {
                Ok(FindingEvidenceRecord {
                    id: row.get(0)?,
                    finding_id: row.get(1)?,
                    evidence_type: row.get(2)?,
                    uri: row.get(3)?,
                    line_start: optional_usize(row.get(4)?),
                    line_end: optional_usize(row.get(5)?),
                    summary: row.get(6)?,
                    metadata_json: row.get(7)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn rules(&self) -> Vec<DatabaseRuleRecord> {
        vec![
            DatabaseRuleRecord {
                id: "database.destructive_migration".into(),
                title: "Destructive database change".into(),
                description: "Flags DROP TABLE/DATABASE, TRUNCATE TABLE, and ALTER TABLE DROP COLUMN for rollout and rollback review. Presence does not mean the migration is incorrect.".into(),
                confidence: 0.98,
            },
            DatabaseRuleRecord {
                id: "database.unscoped_data_write".into(),
                title: "Unscoped UPDATE/DELETE".into(),
                description: "Flags UPDATE/DELETE statements without a WHERE token outside SQL string literals/comments. Full-table writes can be intentional and require review rather than automatic rejection.".into(),
                confidence: 0.96,
            },
            DatabaseRuleRecord {
                id: "database.sqlite_foreign_keys_disabled".into(),
                title: "SQLite foreign keys disabled".into(),
                description: "Flags SQL artifacts that explicitly set PRAGMA foreign_keys to OFF/0. The analyzer does not claim the statement has executed.".into(),
                confidence: 0.99,
            },
            DatabaseRuleRecord {
                id: "database.literal_datasource_url".into(),
                title: "Literal Prisma datasource URL".into(),
                description: "Flags non-placeholder literal datasource URLs in Prisma schemas. Literal values are redacted before persistence.".into(),
                confidence: 0.95,
            },
        ]
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<DatabaseRunRecord>, DatabaseAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT a.id, a.project_id, a.status, a.started_at, a.finished_at, a.duration_ms,\
                    COALESCE(m.coverage_complete, 0), COALESCE(m.artifacts_considered, 0),\
                    COALESCE(m.artifacts_analyzed, 0), COALESCE(m.artifacts_skipped, 0),\
                    COALESCE(m.sql_files, 0), COALESCE(m.prisma_schemas, 0), COALESCE(m.observations, 0),\
                    COALESCE(m.findings_opened, 0), COALESCE(m.findings_refreshed, 0), COALESCE(m.findings_resolved, 0),\
                    COALESCE(m.destructive_statements, 0), COALESCE(m.unscoped_writes, 0),\
                    COALESCE(m.foreign_keys_disabled, 0), COALESCE(m.literal_datasource_urls, 0)\
             FROM analysis_runs a LEFT JOIN database_run_metrics m ON m.run_id = a.id\
             WHERE a.project_id = ?1 AND a.run_kind = 'database_analysis'\
             ORDER BY a.started_at DESC, a.id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded(limit, MAX_HISTORY_QUERY)],
            |row| {
                let status_text: String = row.get(2)?;
                let status = AnalysisStatus::from_db(&status_text).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        format!("invalid analysis status {status_text}").into(),
                    )
                })?;
                Ok(DatabaseRunRecord {
                    run_id: row.get(0)?,
                    project_id: row.get(1)?,
                    status,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get::<_, Option<i64>>(5)?.map(to_u64),
                    coverage_complete: row.get::<_, i64>(6)? != 0,
                    artifacts_considered: to_usize(row.get(7)?),
                    artifacts_analyzed: to_usize(row.get(8)?),
                    artifacts_skipped: to_usize(row.get(9)?),
                    sql_files: to_usize(row.get(10)?),
                    prisma_schemas: to_usize(row.get(11)?),
                    observations: to_usize(row.get(12)?),
                    findings_opened: to_usize(row.get(13)?),
                    findings_refreshed: to_usize(row.get(14)?),
                    findings_resolved: to_usize(row.get(15)?),
                    destructive_statements: to_usize(row.get(16)?),
                    unscoped_writes: to_usize(row.get(17)?),
                    foreign_keys_disabled: to_usize(row.get(18)?),
                    literal_datasource_urls: to_usize(row.get(19)?),
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn project_root(
    connection: &Connection,
    project_id: &str,
) -> Result<(PathBuf, String), DatabaseAnalysisError> {
    connection
        .query_row(
            "SELECT root_path, path_identity FROM projects WHERE id = ?1",
            [project_id],
            |row| Ok((PathBuf::from(row.get::<_, String>(0)?), row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| DatabaseAnalysisError::ProjectNotFound(project_id.to_string()))
}

fn scan_database_artifacts(
    project_id: &str,
    canonical_root: &Path,
    case_insensitive: bool,
) -> Result<ScanCollection, DatabaseAnalysisError> {
    let mut collection = ScanCollection {
        coverage_complete: true,
        ..ScanCollection::default()
    };
    let iterator = WalkDir::new(canonical_root)
        .max_depth(8)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !should_skip_entry(entry));

    for entry in iterator {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                collection.coverage_complete = false;
                collection.artifacts_skipped += 1;
                continue;
            }
        };
        if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
            continue;
        }
        let Some(kind) = artifact_kind(entry.path()) else {
            continue;
        };
        collection.artifacts_considered += 1;
        if collection.artifacts_considered > MAX_ARTIFACTS {
            return Err(DatabaseAnalysisError::TooManyArtifacts { limit: MAX_ARTIFACTS });
        }
        if entry.file_type().is_symlink() {
            collection.coverage_complete = false;
            collection.artifacts_skipped += 1;
            continue;
        }

        let canonical = match fs::canonicalize(entry.path()) {
            Ok(path) => path,
            Err(_) => {
                collection.coverage_complete = false;
                collection.artifacts_skipped += 1;
                continue;
            }
        };
        if !canonical.starts_with(canonical_root) {
            collection.coverage_complete = false;
            collection.artifacts_skipped += 1;
            continue;
        }
        let relative = canonical
            .strip_prefix(canonical_root)
            .map_err(|_| DatabaseAnalysisError::UnsafeArtifactPath(canonical.display().to_string()))?;
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        let path_identity = normalize_relative_path(&relative_text, case_insensitive)
            .ok_or_else(|| DatabaseAnalysisError::UnsafeArtifactPath(relative_text.clone()))?;
        let metadata = match fs::metadata(&canonical) {
            Ok(metadata) => metadata,
            Err(_) => {
                collection.coverage_complete = false;
                collection.artifacts_skipped += 1;
                continue;
            }
        };
        if metadata.len() > MAX_ARTIFACT_BYTES {
            collection.coverage_complete = false;
            collection.artifacts_skipped += 1;
            continue;
        }
        let bytes = match fs::read(&canonical) {
            Ok(bytes) => bytes,
            Err(_) => {
                collection.coverage_complete = false;
                collection.artifacts_skipped += 1;
                continue;
            }
        };
        let source = match std::str::from_utf8(&bytes) {
            Ok(source) => source,
            Err(_) => {
                collection.coverage_complete = false;
                collection.artifacts_skipped += 1;
                continue;
            }
        };
        let content_hash = hex_sha256(&bytes);
        let observations = analyze_artifact(kind, source);
        let framework = match kind {
            DatabaseArtifactKind::PrismaSchema => Some("Prisma".to_string()),
            DatabaseArtifactKind::SqlMigration | DatabaseArtifactKind::SqlSchema => None,
        };
        match kind {
            DatabaseArtifactKind::PrismaSchema => collection.prisma_schemas += 1,
            DatabaseArtifactKind::SqlMigration | DatabaseArtifactKind::SqlSchema => collection.sql_files += 1,
        }
        collection.artifacts_analyzed += 1;
        collection.artifacts.push(ScannedArtifact {
            id: deterministic_id("database-artifact", &[project_id, &path_identity]),
            relative_path: relative_text,
            path_identity,
            kind,
            framework,
            content_hash,
            byte_size: metadata.len(),
            observations,
        });
    }

    collection.artifacts.sort_by(|left, right| left.path_identity.cmp(&right.path_identity));
    Ok(collection)
}

fn should_skip_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return false;
    }
    if !entry.file_type().is_dir() {
        return false;
    }
    matches!(
        entry.file_name().to_str(),
        Some(
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
        )
    )
}

fn artifact_kind(path: &Path) -> Option<DatabaseArtifactKind> {
    let file_name = path.file_name()?.to_str()?;
    if file_name.eq_ignore_ascii_case("schema.prisma") {
        return Some(DatabaseArtifactKind::PrismaSchema);
    }
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sql"))
    {
        return None;
    }
    let is_migration = path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "migration" | "migrations" | "migrate"))
    }) || file_name.to_ascii_lowercase().contains("migration");
    Some(if is_migration {
        DatabaseArtifactKind::SqlMigration
    } else {
        DatabaseArtifactKind::SqlSchema
    })
}

fn persist_scan(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    collection: ScanCollection,
    duration_ms: u64,
) -> Result<DatabaseRunSummary, DatabaseAnalysisError> {
    let existing_findings = load_existing_findings(connection, project_id)?;
    let observed = flatten_observations(project_id, &collection.artifacts);
    let observed_fingerprints: BTreeSet<&str> = observed.iter().map(|item| item.fingerprint.as_str()).collect();
    let findings_opened = observed
        .iter()
        .filter(|item| !existing_findings.contains_key(item.fingerprint.as_str()))
        .count();
    let findings_refreshed = observed.len().saturating_sub(findings_opened);
    let findings_resolved = if collection.coverage_complete {
        existing_findings
            .iter()
            .filter(|(fingerprint, finding)| {
                finding.status == "open" && !observed_fingerprints.contains(fingerprint.as_str())
            })
            .count()
    } else {
        0
    };

    let destructive_statements = count_rule(&observed, "database.destructive_migration");
    let unscoped_writes = count_rule(&observed, "database.unscoped_data_write");
    let foreign_keys_disabled = count_rule(&observed, "database.sqlite_foreign_keys_disabled");
    let literal_datasource_urls = count_rule(&observed, "database.literal_datasource_url");

    let transaction = connection.unchecked_transaction()?;
    let active_artifact_ids: BTreeSet<&str> = collection.artifacts.iter().map(|artifact| artifact.id.as_str()).collect();
    for artifact in &collection.artifacts {
        transaction.execute(
            "INSERT INTO database_artifacts(\
               id, project_id, relative_path, path_identity, artifact_kind, framework, content_hash, byte_size, last_run_id, first_seen_at, last_seen_at, is_active\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)\
             ON CONFLICT(project_id, path_identity) DO UPDATE SET\
               relative_path = excluded.relative_path, artifact_kind = excluded.artifact_kind, framework = excluded.framework,\
               content_hash = excluded.content_hash, byte_size = excluded.byte_size, last_run_id = excluded.last_run_id,\
               last_seen_at = CURRENT_TIMESTAMP, is_active = 1",
            params![
                artifact.id,
                project_id,
                artifact.relative_path,
                artifact.path_identity,
                artifact_kind_text(artifact.kind),
                artifact.framework,
                artifact.content_hash,
                to_i64(artifact.byte_size),
                run_id,
            ],
        )?;
    }
    if collection.coverage_complete {
        let mut statement = transaction.prepare(
            "SELECT id FROM database_artifacts WHERE project_id = ?1 AND is_active = 1",
        )?;
        let ids = statement
            .query_map([project_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for id in ids {
            if !active_artifact_ids.contains(id.as_str()) {
                transaction.execute(
                    "UPDATE database_artifacts SET is_active = 0, last_run_id = ?2, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?1",
                    params![id, run_id],
                )?;
            }
        }
    }

    if collection.coverage_complete {
        transaction.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, last_run_id = ?2\
             WHERE project_id = ?1 AND analyzer_key = ?3 AND status = 'open'",
            params![project_id, run_id, ANALYZER_KEY],
        )?;
    }

    for item in &observed {
        let finding_id = existing_findings.get(item.fingerprint.as_str()).map_or_else(
            || deterministic_id("finding", &[project_id, ANALYZER_KEY, &item.fingerprint]),
            |finding| finding.id.clone(),
        );
        transaction.execute(
            "INSERT INTO findings(\
               id, project_id, run_id, category, sub_category, severity, confidence, title, description,\
               file_id, symbol_id, source_start_line, source_end_line, status, fingerprint, rule_version,\
               model_version, first_seen, last_seen, analyzer_key, last_run_id, resolved_at\
             ) VALUES (?1, ?2, ?3, 'database', ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9, ?10, 'open', ?11, ?12,\
                       NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?13, ?3, NULL)\
             ON CONFLICT(project_id, fingerprint) DO UPDATE SET\
               run_id = excluded.run_id, category = excluded.category, sub_category = excluded.sub_category,\
               severity = excluded.severity, confidence = excluded.confidence, title = excluded.title,\
               description = excluded.description, source_start_line = excluded.source_start_line,\
               source_end_line = excluded.source_end_line, status = 'open', rule_version = excluded.rule_version,\
               last_seen = CURRENT_TIMESTAMP, analyzer_key = excluded.analyzer_key, last_run_id = excluded.last_run_id,\
               resolved_at = NULL",
            params![
                finding_id,
                project_id,
                run_id,
                item.observation.rule_id,
                item.observation.severity,
                item.observation.confidence,
                item.observation.title,
                item.observation.description,
                to_i64_usize(item.observation.start_line),
                to_i64_usize(item.observation.end_line),
                item.fingerprint,
                RULE_VERSION,
                ANALYZER_KEY,
            ],
        )?;
        transaction.execute("DELETE FROM finding_evidence WHERE finding_id = ?1", [&finding_id])?;
        let evidence_id = deterministic_id(
            "database-evidence",
            &[&finding_id, &item.artifact.id, &item.observation.rule_id, &item.observation.anchor],
        );
        let metadata = merge_evidence_metadata(
            &item.observation.metadata_json,
            &item.artifact.id,
            &item.artifact.content_hash,
            artifact_kind_text(item.artifact.kind),
        );
        transaction.execute(
            "INSERT INTO finding_evidence(\
               id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json\
             ) VALUES (?1, ?2, 'database_artifact', ?3, ?4, ?5, ?6, ?7)",
            params![
                evidence_id,
                finding_id,
                item.artifact.relative_path,
                to_i64_usize(item.observation.start_line),
                to_i64_usize(item.observation.end_line),
                item.observation.evidence_summary,
                metadata,
            ],
        )?;
    }

    transaction.execute(
        "INSERT INTO database_run_metrics(\
           run_id, coverage_complete, artifacts_considered, artifacts_analyzed, artifacts_skipped, sql_files, prisma_schemas,\
           observations, findings_opened, findings_refreshed, findings_resolved, destructive_statements, unscoped_writes,\
           foreign_keys_disabled, literal_datasource_urls\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            run_id,
            i64::from(collection.coverage_complete),
            to_i64_usize(collection.artifacts_considered),
            to_i64_usize(collection.artifacts_analyzed),
            to_i64_usize(collection.artifacts_skipped),
            to_i64_usize(collection.sql_files),
            to_i64_usize(collection.prisma_schemas),
            to_i64_usize(observed.len()),
            to_i64_usize(findings_opened),
            to_i64_usize(findings_refreshed),
            to_i64_usize(findings_resolved),
            to_i64_usize(destructive_statements),
            to_i64_usize(unscoped_writes),
            to_i64_usize(foreign_keys_disabled),
            to_i64_usize(literal_datasource_urls),
        ],
    )?;
    finish_run(&transaction, run_id, AnalysisStatus::Completed, duration_ms)?;
    transaction.commit()?;

    Ok(DatabaseRunSummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        coverage_complete: collection.coverage_complete,
        artifacts_considered: collection.artifacts_considered,
        artifacts_analyzed: collection.artifacts_analyzed,
        artifacts_skipped: collection.artifacts_skipped,
        sql_files: collection.sql_files,
        prisma_schemas: collection.prisma_schemas,
        observations: observed.len(),
        findings_opened,
        findings_refreshed,
        findings_resolved,
        destructive_statements,
        unscoped_writes,
        foreign_keys_disabled,
        literal_datasource_urls,
        duration_ms,
    })
}

#[derive(Debug)]
struct PersistedDatabaseObservation<'a> {
    artifact: &'a ScannedArtifact,
    observation: &'a DatabaseObservation,
    fingerprint: String,
}

fn flatten_observations<'a>(
    project_id: &str,
    artifacts: &'a [ScannedArtifact],
) -> Vec<PersistedDatabaseObservation<'a>> {
    let mut output = Vec::new();
    for artifact in artifacts {
        for observation in &artifact.observations {
            output.push(PersistedDatabaseObservation {
                artifact,
                observation,
                fingerprint: deterministic_id(
                    "database-finding",
                    &[
                        project_id,
                        &observation.rule_id,
                        &artifact.path_identity,
                        &observation.anchor,
                    ],
                ),
            });
        }
    }
    output.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    output
}

fn load_existing_findings(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, ExistingFinding>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, id, status FROM findings WHERE project_id = ?1 AND analyzer_key = ?2",
    )?;
    let rows = statement.query_map(params![project_id, ANALYZER_KEY], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExistingFinding {
                id: row.get(1)?,
                status: row.get(2)?,
            },
        ))
    })?;
    rows.collect()
}

fn count_rule(observations: &[PersistedDatabaseObservation<'_>], rule_id: &str) -> usize {
    observations
        .iter()
        .filter(|item| item.observation.rule_id == rule_id)
        .count()
}

fn merge_evidence_metadata(
    metadata_json: &str,
    artifact_id: &str,
    content_hash: &str,
    artifact_kind: &str,
) -> String {
    let mut value = serde_json::from_str::<serde_json::Value>(metadata_json)
        .unwrap_or_else(|_| json!({"metadata_parse_error": true}));
    if let Some(object) = value.as_object_mut() {
        object.insert("artifact_id".into(), json!(artifact_id));
        object.insert("content_hash".into(), json!(content_hash));
        object.insert("artifact_kind".into(), json!(artifact_kind));
        object.insert("source_executed".into(), json!(false));
    }
    value.to_string()
}

fn artifact_kind_text(kind: DatabaseArtifactKind) -> &'static str {
    match kind {
        DatabaseArtifactKind::SqlMigration => "sql_migration",
        DatabaseArtifactKind::SqlSchema => "sql_schema",
        DatabaseArtifactKind::PrismaSchema => "prisma_schema",
    }
}

fn finish_run(
    connection: &Connection,
    run_id: &str,
    status: AnalysisStatus,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET status = ?2, finished_at = CURRENT_TIMESTAMP, duration_ms = ?3 WHERE id = ?1",
        params![run_id, status.as_db(), to_i64(duration_ms)],
    )?;
    Ok(())
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    deterministic_id("database-analysis-run", &[project_id, &nanos.to_string()])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn bounded(requested: usize, maximum: usize) -> i64 {
    let value = requested.max(1).min(maximum);
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn optional_usize(value: Option<i64>) -> Option<usize> {
    value.and_then(|value| usize::try_from(value).ok())
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value.max(0)).unwrap_or(usize::MAX)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value.max(0)).unwrap_or(u64::MAX)
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_i64_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
