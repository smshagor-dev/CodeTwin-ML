use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use qa_analyzer::{detect_artifacts, is_candidate_path, QaArtifactKind};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

use crate::{
    deterministic_id, is_windows_path_identity, normalize_relative_path, AnalysisStatus, Database,
};

const ANALYZER_VERSION: &str = "qa-discovery-v1";
const QUERY_VERSION: &str = "passive-test-inventory-v1";
const MAX_CANDIDATE_FILES: usize = 50_000;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_QUERY: usize = 1_000;
const MAX_HISTORY_QUERY: usize = 100;
const MAX_DEPTH: usize = 16;

#[derive(Debug, Error)]
pub enum QaDiscoveryError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
    #[error("QA discovery exceeds the bounded limit of {limit} candidate files")]
    TooManyCandidates { limit: usize },
    #[error("unsafe QA artifact path: {0}")]
    UnsafeArtifactPath(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaDiscoveryRunSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub coverage_complete: bool,
    pub candidate_files: usize,
    pub artifacts_discovered: usize,
    pub artifacts_skipped: usize,
    pub test_files: usize,
    pub config_files: usize,
    pub framework_count: usize,
    pub frameworks: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaDiscoveryRunRecord {
    pub run_id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub coverage_complete: bool,
    pub candidate_files: usize,
    pub artifacts_discovered: usize,
    pub artifacts_skipped: usize,
    pub test_files: usize,
    pub config_files: usize,
    pub framework_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaArtifactRecord {
    pub id: String,
    pub project_id: String,
    pub relative_path: String,
    pub artifact_kind: String,
    pub framework: String,
    pub evidence_kind: String,
    pub content_hash: String,
    pub byte_size: u64,
    pub last_run_id: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaFrameworkSummary {
    pub framework: String,
    pub artifacts: usize,
    pub test_files: usize,
    pub config_files: usize,
}

#[derive(Debug, Clone)]
struct ScannedArtifact {
    id: String,
    relative_path: String,
    path_identity: String,
    artifact_kind: QaArtifactKind,
    framework: String,
    evidence_kind: String,
    content_hash: String,
    byte_size: u64,
}

#[derive(Debug, Default)]
struct ScanCollection {
    coverage_complete: bool,
    candidate_files: usize,
    artifacts_skipped: usize,
    test_files: usize,
    config_files: usize,
    frameworks: BTreeSet<String>,
    artifacts: Vec<ScannedArtifact>,
}

pub struct QaDiscoveryService<'a> {
    database: &'a Database,
}

impl<'a> QaDiscoveryService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn discover_project(
        &self,
        project_id: &str,
    ) -> Result<QaDiscoveryRunSummary, QaDiscoveryError> {
        let (root, path_identity) = project_root(self.database.connection(), project_id)?;
        let canonical_root = fs::canonicalize(&root)?;
        if !canonical_root.is_dir() {
            return Err(QaDiscoveryError::InvalidProjectRoot(
                canonical_root.display().to_string(),
            ));
        }

        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = json!({
            "max_candidate_files": MAX_CANDIDATE_FILES,
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
            "max_depth": MAX_DEPTH,
            "detector_version": qa_analyzer::DETECTOR_VERSION,
            "repository_commands_executed": false,
            "package_scripts_executed": false,
            "tests_executed": false
        })
        .to_string();
        let config_fingerprint = deterministic_id(
            "qa-discovery-config",
            &[
                ANALYZER_VERSION,
                QUERY_VERSION,
                qa_analyzer::ANALYZER_VERSION,
                qa_analyzer::DETECTOR_VERSION,
                &configuration_json,
            ],
        );

        self.database.connection().execute(
            "INSERT INTO analysis_runs(\
               id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint\
             ) VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'qa_discovery', ?5, ?6)",
            params![
                run_id,
                project_id,
                ANALYZER_VERSION,
                configuration_json,
                QUERY_VERSION,
                config_fingerprint,
            ],
        )?;

        let collection = match scan_project(
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
        framework: Option<&str>,
        limit: usize,
    ) -> Result<Vec<QaArtifactRecord>, QaDiscoveryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, relative_path, artifact_kind, framework, evidence_kind,\
                    content_hash, byte_size, last_run_id, first_seen_at, last_seen_at, is_active\
             FROM qa_test_artifacts\
             WHERE project_id = ?1 AND (?2 = 0 OR is_active = 1) AND (?3 IS NULL OR framework = ?3)\
             ORDER BY is_active DESC, framework, artifact_kind, relative_path, evidence_kind, id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                project_id,
                i64::from(active_only),
                framework,
                bounded(limit, MAX_ARTIFACT_QUERY)
            ],
            |row| {
                Ok(QaArtifactRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    relative_path: row.get(2)?,
                    artifact_kind: row.get(3)?,
                    framework: row.get(4)?,
                    evidence_kind: row.get(5)?,
                    content_hash: row.get(6)?,
                    byte_size: to_u64(row.get(7)?),
                    last_run_id: row.get(8)?,
                    first_seen_at: row.get(9)?,
                    last_seen_at: row.get(10)?,
                    is_active: row.get::<_, i64>(11)? != 0,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_frameworks(
        &self,
        project_id: &str,
    ) -> Result<Vec<QaFrameworkSummary>, QaDiscoveryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT framework, COUNT(*),\
                    SUM(CASE WHEN artifact_kind = 'test_file' THEN 1 ELSE 0 END),\
                    SUM(CASE WHEN artifact_kind = 'config_file' THEN 1 ELSE 0 END)\
             FROM qa_test_artifacts\
             WHERE project_id = ?1 AND is_active = 1\
             GROUP BY framework\
             ORDER BY framework",
        )?;
        let rows = statement.query_map([project_id], |row| {
            Ok(QaFrameworkSummary {
                framework: row.get(0)?,
                artifacts: to_usize(row.get(1)?),
                test_files: to_usize(row.get(2)?),
                config_files: to_usize(row.get(3)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<QaDiscoveryRunRecord>, QaDiscoveryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT a.id, a.project_id, a.status, a.started_at, a.finished_at, a.duration_ms,\
                    COALESCE(m.coverage_complete, 0), COALESCE(m.candidate_files, 0),\
                    COALESCE(m.artifacts_discovered, 0), COALESCE(m.artifacts_skipped, 0),\
                    COALESCE(m.test_files, 0), COALESCE(m.config_files, 0), COALESCE(m.framework_count, 0)\
             FROM analysis_runs a LEFT JOIN qa_discovery_run_metrics m ON m.run_id = a.id\
             WHERE a.project_id = ?1 AND a.run_kind = 'qa_discovery'\
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
                Ok(QaDiscoveryRunRecord {
                    run_id: row.get(0)?,
                    project_id: row.get(1)?,
                    status,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get::<_, Option<i64>>(5)?.map(to_u64),
                    coverage_complete: row.get::<_, i64>(6)? != 0,
                    candidate_files: to_usize(row.get(7)?),
                    artifacts_discovered: to_usize(row.get(8)?),
                    artifacts_skipped: to_usize(row.get(9)?),
                    test_files: to_usize(row.get(10)?),
                    config_files: to_usize(row.get(11)?),
                    framework_count: to_usize(row.get(12)?),
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn project_root(
    connection: &Connection,
    project_id: &str,
) -> Result<(PathBuf, String), QaDiscoveryError> {
    connection
        .query_row(
            "SELECT root_path, path_identity FROM projects WHERE id = ?1",
            [project_id],
            |row| Ok((PathBuf::from(row.get::<_, String>(0)?), row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| QaDiscoveryError::ProjectNotFound(project_id.to_string()))
}

fn scan_project(
    project_id: &str,
    canonical_root: &Path,
    case_insensitive: bool,
) -> Result<ScanCollection, QaDiscoveryError> {
    let mut collection = ScanCollection {
        coverage_complete: true,
        ..ScanCollection::default()
    };
    let iterator = WalkDir::new(canonical_root)
        .max_depth(MAX_DEPTH)
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

        let relative = match entry.path().strip_prefix(canonical_root) {
            Ok(relative) => relative,
            Err(_) => {
                collection.coverage_complete = false;
                collection.artifacts_skipped += 1;
                continue;
            }
        };
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        if !is_candidate_path(&relative_text) {
            continue;
        }

        collection.candidate_files += 1;
        if collection.candidate_files > MAX_CANDIDATE_FILES {
            return Err(QaDiscoveryError::TooManyCandidates {
                limit: MAX_CANDIDATE_FILES,
            });
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
        let path_identity = normalize_relative_path(&relative_text, case_insensitive)
            .ok_or_else(|| QaDiscoveryError::UnsafeArtifactPath(relative_text.clone()))?;
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
        for detection in detect_artifacts(&relative_text, source) {
            collection.frameworks.insert(detection.framework.clone());
            match detection.artifact_kind {
                QaArtifactKind::TestFile => collection.test_files += 1,
                QaArtifactKind::ConfigFile => collection.config_files += 1,
            }
            let id = deterministic_id(
                "qa-test-artifact",
                &[
                    project_id,
                    &path_identity,
                    &detection.framework,
                    &detection.evidence_kind,
                ],
            );
            collection.artifacts.push(ScannedArtifact {
                id,
                relative_path: relative_text.clone(),
                path_identity: path_identity.clone(),
                artifact_kind: detection.artifact_kind,
                framework: detection.framework,
                evidence_kind: detection.evidence_kind,
                content_hash: content_hash.clone(),
                byte_size: metadata.len(),
            });
        }
    }

    collection.artifacts.sort_by(|left, right| {
        (
            &left.path_identity,
            &left.framework,
            &left.evidence_kind,
            left.artifact_kind,
        )
            .cmp(&(
                &right.path_identity,
                &right.framework,
                &right.evidence_kind,
                right.artifact_kind,
            ))
    });
    collection.artifacts.dedup_by(|left, right| left.id == right.id);
    Ok(collection)
}

fn should_skip_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
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
                | "__pycache__"
        )
    )
}

fn persist_scan(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    collection: ScanCollection,
    duration_ms: u64,
) -> Result<QaDiscoveryRunSummary, QaDiscoveryError> {
    let active_ids: BTreeSet<&str> = collection.artifacts.iter().map(|item| item.id.as_str()).collect();
    let transaction = connection.unchecked_transaction()?;

    for artifact in &collection.artifacts {
        transaction.execute(
            "INSERT INTO qa_test_artifacts(\
               id, project_id, relative_path, path_identity, artifact_kind, framework, evidence_kind,\
               content_hash, byte_size, last_run_id, first_seen_at, last_seen_at, is_active\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)\
             ON CONFLICT(project_id, path_identity, framework, evidence_kind) DO UPDATE SET\
               id = excluded.id, relative_path = excluded.relative_path, artifact_kind = excluded.artifact_kind,\
               content_hash = excluded.content_hash, byte_size = excluded.byte_size, last_run_id = excluded.last_run_id,\
               last_seen_at = CURRENT_TIMESTAMP, is_active = 1",
            params![
                artifact.id,
                project_id,
                artifact.relative_path,
                artifact.path_identity,
                artifact.artifact_kind.as_str(),
                artifact.framework,
                artifact.evidence_kind,
                artifact.content_hash,
                to_i64(artifact.byte_size),
                run_id,
            ],
        )?;
    }

    if collection.coverage_complete {
        let mut statement = transaction.prepare(
            "SELECT id FROM qa_test_artifacts WHERE project_id = ?1 AND is_active = 1",
        )?;
        let ids = statement
            .query_map([project_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for id in ids {
            if !active_ids.contains(id.as_str()) {
                transaction.execute(
                    "UPDATE qa_test_artifacts SET is_active = 0, last_run_id = ?2, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?1",
                    params![id, run_id],
                )?;
            }
        }
    }

    transaction.execute(
        "INSERT INTO qa_discovery_run_metrics(\
           run_id, coverage_complete, candidate_files, artifacts_discovered, artifacts_skipped,\
           test_files, config_files, framework_count\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            run_id,
            i64::from(collection.coverage_complete),
            to_i64_usize(collection.candidate_files),
            to_i64_usize(collection.artifacts.len()),
            to_i64_usize(collection.artifacts_skipped),
            to_i64_usize(collection.test_files),
            to_i64_usize(collection.config_files),
            to_i64_usize(collection.frameworks.len()),
        ],
    )?;
    transaction.execute(
        "UPDATE analysis_runs SET status = 'completed', finished_at = CURRENT_TIMESTAMP, duration_ms = ?2 WHERE id = ?1",
        params![run_id, to_i64(duration_ms)],
    )?;
    transaction.commit()?;

    Ok(QaDiscoveryRunSummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        coverage_complete: collection.coverage_complete,
        candidate_files: collection.candidate_files,
        artifacts_discovered: collection.artifacts.len(),
        artifacts_skipped: collection.artifacts_skipped,
        test_files: collection.test_files,
        config_files: collection.config_files,
        framework_count: collection.frameworks.len(),
        frameworks: collection.frameworks.into_iter().collect(),
        duration_ms,
    })
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
        .map_or(0, |duration| duration.as_nanos());
    deterministic_id("qa-discovery-run", &[project_id, &nanos.to_string()])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn bounded(value: usize, maximum: usize) -> i64 {
    to_i64_usize(value.min(maximum).max(1))
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_i64_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::QaDiscoveryService;
    use crate::Database;

    fn project(database: &Database, root: &std::path::Path) -> String {
        let id = "qa-project".to_string();
        database
            .connection()
            .execute(
                "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES (?1, ?2, 'QA Project', ?3)",
                rusqlite::params![id, root.to_string_lossy(), root.to_string_lossy()],
            )
            .expect("insert project");
        id
    }

    #[test]
    fn discovers_framework_evidence_without_running_tests() {
        let root = tempdir().expect("temp root");
        fs::create_dir_all(root.path().join("src")).expect("src");
        fs::write(
            root.path().join("package.json"),
            r#"{"devDependencies":{"vitest":"^2.0.0"},"scripts":{"test":"vitest run"}}"#,
        )
        .expect("manifest");
        fs::write(
            root.path().join("src/math.test.ts"),
            "import { it } from 'vitest'; it('adds', () => {});",
        )
        .expect("test file");

        let database = Database::open_in_memory().expect("db");
        let project_id = project(&database, root.path());
        let service = QaDiscoveryService::new(&database);
        let summary = service.discover_project(&project_id).expect("discover");

        assert!(summary.coverage_complete);
        assert!(summary.frameworks.iter().any(|item| item == "vitest"));
        assert!(summary.test_files >= 1);
        let frameworks = service.list_frameworks(&project_id).expect("frameworks");
        assert!(frameworks.iter().any(|item| item.framework == "vitest"));
        let artifacts = service
            .list_artifacts(&project_id, true, Some("vitest"), 100)
            .expect("artifacts");
        assert!(artifacts.iter().any(|item| item.relative_path == "src/math.test.ts"));
    }

    #[test]
    fn complete_rescan_deactivates_removed_test_artifacts() {
        let root = tempdir().expect("temp root");
        let test_path = root.path().join("thing_test.go");
        fs::write(&test_path, "package sample").expect("test file");
        let database = Database::open_in_memory().expect("db");
        let project_id = project(&database, root.path());
        let service = QaDiscoveryService::new(&database);
        service.discover_project(&project_id).expect("first discovery");
        fs::remove_file(test_path).expect("remove");
        service.discover_project(&project_id).expect("second discovery");
        let records = service
            .list_artifacts(&project_id, false, None, 100)
            .expect("artifacts");
        assert!(records.iter().any(|item| !item.is_active));
    }
}
