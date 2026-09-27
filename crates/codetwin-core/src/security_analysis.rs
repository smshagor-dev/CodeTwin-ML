use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Component, Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OptionalExtension};
use security_analyzer::{analyze_source, SecurityObservation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{deterministic_id, AnalysisStatus, Database, FindingEvidenceRecord};

const ANALYZER_KEY: &str = "appsec";
const ANALYZER_VERSION: &str = "appsec-v1";
const QUERY_VERSION: &str = "indexed-source-appsec-v1";
const RULE_VERSION: &str = "1";
const MAX_FILES: usize = 20_000;
const MAX_SOURCE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_FINDINGS_QUERY: usize = 500;
const MAX_EVIDENCE_QUERY: usize = 500;
const MAX_HISTORY_QUERY: usize = 100;

#[derive(Debug, Error)]
pub enum SecurityAnalysisError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("security parser error: {0}")]
    Analyzer(#[from] security_analyzer::SecurityAnalyzerError),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
    #[error("security analysis exceeds the bounded limit of {limit} active files")]
    TooManyFiles { limit: usize },
    #[error("unsafe indexed relative path: {0}")]
    UnsafeRelativePath(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRunSummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub coverage_complete: bool,
    pub files_considered: usize,
    pub files_analyzed: usize,
    pub files_stale: usize,
    pub files_skipped: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub hardcoded_credentials: usize,
    pub dynamic_execution: usize,
    pub weak_crypto: usize,
    pub unsafe_c_apis: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRunRecord {
    pub run_id: String,
    pub project_id: String,
    pub status: AnalysisStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub coverage_complete: bool,
    pub files_considered: usize,
    pub files_analyzed: usize,
    pub files_stale: usize,
    pub files_skipped: usize,
    pub observations: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub hardcoded_credentials: usize,
    pub dynamic_execution: usize,
    pub weak_crypto: usize,
    pub unsafe_c_apis: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityFindingRecord {
    pub id: String,
    pub project_id: String,
    pub run_id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: Option<f64>,
    pub title: String,
    pub description: String,
    pub file_id: Option<String>,
    pub symbol_id: Option<String>,
    pub source_start_line: Option<usize>,
    pub source_end_line: Option<usize>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub status: String,
    pub fingerprint: String,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityRuleRecord {
    pub id: String,
    pub title: String,
    pub description: String,
    pub cwe: String,
    pub owasp: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
struct IndexedSecurityFile {
    id: String,
    relative_path: String,
    language: Option<String>,
    content_hash: String,
    byte_size: u64,
    parse_state: Option<String>,
}

#[derive(Debug, Clone)]
struct PersistedObservation {
    file: IndexedSecurityFile,
    observation: SecurityObservation,
}

#[derive(Debug, Default)]
struct Collection {
    files_considered: usize,
    files_analyzed: usize,
    files_stale: usize,
    files_skipped: usize,
    observations: Vec<PersistedObservation>,
}

impl Collection {
    fn coverage_complete(&self) -> bool {
        self.files_stale == 0
            && self.files_skipped == 0
            && self.files_analyzed == self.files_considered
    }
}

pub struct CodeSecurityService<'a> {
    database: &'a Database,
}

impl<'a> CodeSecurityService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn analyze_project(
        &self,
        project_id: &str,
    ) -> Result<SecurityRunSummary, SecurityAnalysisError> {
        let root = project_root(self.database.connection(), project_id)?;
        let canonical_root = fs::canonicalize(&root)?;
        if !canonical_root.is_dir() {
            return Err(SecurityAnalysisError::InvalidProjectRoot(
                canonical_root.display().to_string(),
            ));
        }

        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = json!({
            "max_files": MAX_FILES,
            "max_source_bytes": MAX_SOURCE_BYTES,
            "ruleset_version": security_analyzer::RULESET_VERSION,
            "secret_values_persisted": false
        })
        .to_string();
        let config_fingerprint = deterministic_id(
            "security-config",
            &[
                ANALYZER_VERSION,
                QUERY_VERSION,
                security_analyzer::ANALYZER_VERSION,
                security_analyzer::RULESET_VERSION,
                &configuration_json,
            ],
        );
        self.database.connection().execute(
            "INSERT INTO analysis_runs( \
               id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint \
             ) VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'security_analysis', ?5, ?6)",
            params![run_id, project_id, ANALYZER_VERSION, configuration_json, QUERY_VERSION, config_fingerprint],
        )?;

        let collected =
            match collect_observations(self.database.connection(), project_id, &canonical_root) {
                Ok(value) => value,
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
        match persist_collection(
            self.database.connection(),
            project_id,
            &run_id,
            collected,
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

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SecurityFindingRecord>, SecurityAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, run_id, COALESCE(sub_category, ''), severity, confidence, title, description, \
                    file_id, symbol_id, source_start_line, source_end_line, cwe, owasp, status, fingerprint, \
                    first_seen, last_seen, resolved_at \
             FROM findings \
             WHERE project_id = ?1 AND analyzer_key = ?2 AND (?3 IS NULL OR status = ?3) \
             ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 \
                        WHEN 'low' THEN 2 ELSE 1 END DESC, status, last_seen DESC, id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                project_id,
                ANALYZER_KEY,
                status,
                bounded(limit, MAX_FINDINGS_QUERY)
            ],
            |row| {
                Ok(SecurityFindingRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    run_id: row.get(2)?,
                    rule_id: row.get(3)?,
                    severity: row.get(4)?,
                    confidence: row.get(5)?,
                    title: row.get(6)?,
                    description: row.get(7)?,
                    file_id: row.get(8)?,
                    symbol_id: row.get(9)?,
                    source_start_line: optional_usize(row.get(10)?),
                    source_end_line: optional_usize(row.get(11)?),
                    cwe: row.get(12)?,
                    owasp: row.get(13)?,
                    status: row.get(14)?,
                    fingerprint: row.get(15)?,
                    first_seen: row.get(16)?,
                    last_seen: row.get(17)?,
                    resolved_at: row.get(18)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn finding_evidence(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<FindingEvidenceRecord>, SecurityAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json \
             FROM finding_evidence WHERE finding_id = ?1 \
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

    pub fn rules(&self) -> Vec<SecurityRuleRecord> {
        vec![
            SecurityRuleRecord {
                id: "security.hardcoded_credential_literal".into(),
                title: "Potential hard-coded credential literal".into(),
                description: "Credential-like assignment to a non-placeholder string literal. Values are redacted and never persisted.".into(),
                cwe: "CWE-798".into(),
                owasp: Some("OWASP A07:2021 Identification and Authentication Failures".into()),
                confidence: 0.90,
            },
            SecurityRuleRecord {
                id: "security.dynamic_code_execution".into(),
                title: "Dynamic code execution primitive".into(),
                description: "Flags eval/exec-style primitives for input-provenance review; it does not claim attacker-controlled input.".into(),
                cwe: "CWE-95".into(),
                owasp: Some("OWASP A03:2021 Injection".into()),
                confidence: 0.68,
            },
            SecurityRuleRecord {
                id: "security.weak_cryptographic_hash".into(),
                title: "Weak cryptographic hash primitive".into(),
                description: "Flags MD5/SHA-1 use for security-context review because checksum-only uses can be intentional.".into(),
                cwe: "CWE-327".into(),
                owasp: Some("OWASP A02:2021 Cryptographic Failures".into()),
                confidence: 0.82,
            },
            SecurityRuleRecord {
                id: "security.unsafe_c_string_api".into(),
                title: "Unsafe C/C++ string API".into(),
                description: "Flags unbounded legacy C/C++ string APIs for concrete destination-bounds review.".into(),
                cwe: "CWE-120".into(),
                owasp: None,
                confidence: 0.78,
            },
        ]
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<SecurityRunRecord>, SecurityAnalysisError> {
        let mut statement = self.database.connection().prepare(
            "SELECT a.id, a.project_id, a.status, a.started_at, a.finished_at, a.duration_ms, \
                    COALESCE(m.files_considered, 0), COALESCE(m.files_analyzed, 0), \
                    COALESCE(m.files_stale, 0), COALESCE(m.files_skipped, 0), COALESCE(m.observations, 0), \
                    COALESCE(m.findings_opened, 0), COALESCE(m.findings_refreshed, 0), COALESCE(m.findings_resolved, 0), \
                    COALESCE(m.hardcoded_credentials, 0), COALESCE(m.dynamic_execution, 0), \
                    COALESCE(m.weak_crypto, 0), COALESCE(m.unsafe_c_apis, 0) \
             FROM analysis_runs a LEFT JOIN security_run_metrics m ON m.run_id = a.id \
             WHERE a.project_id = ?1 AND a.run_kind = 'security_analysis' \
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
                let files_considered = to_usize(row.get(6)?);
                let files_analyzed = to_usize(row.get(7)?);
                let files_stale = to_usize(row.get(8)?);
                let files_skipped = to_usize(row.get(9)?);
                Ok(SecurityRunRecord {
                    run_id: row.get(0)?,
                    project_id: row.get(1)?,
                    status,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get::<_, Option<i64>>(5)?.map(to_u64),
                    coverage_complete: files_stale == 0
                        && files_skipped == 0
                        && files_analyzed == files_considered,
                    files_considered,
                    files_analyzed,
                    files_stale,
                    files_skipped,
                    observations: to_usize(row.get(10)?),
                    findings_opened: to_usize(row.get(11)?),
                    findings_refreshed: to_usize(row.get(12)?),
                    findings_resolved: to_usize(row.get(13)?),
                    hardcoded_credentials: to_usize(row.get(14)?),
                    dynamic_execution: to_usize(row.get(15)?),
                    weak_crypto: to_usize(row.get(16)?),
                    unsafe_c_apis: to_usize(row.get(17)?),
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn project_root(
    connection: &Connection,
    project_id: &str,
) -> Result<PathBuf, SecurityAnalysisError> {
    connection
        .query_row(
            "SELECT root_path FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(PathBuf::from)
        .ok_or_else(|| SecurityAnalysisError::ProjectNotFound(project_id.to_string()))
}

fn collect_observations(
    connection: &Connection,
    project_id: &str,
    canonical_root: &Path,
) -> Result<Collection, SecurityAnalysisError> {
    let files = load_active_files(connection, project_id)?;
    if files.len() > MAX_FILES {
        return Err(SecurityAnalysisError::TooManyFiles { limit: MAX_FILES });
    }
    let mut collection = Collection {
        files_considered: files.len(),
        ..Collection::default()
    };

    for file in files {
        let Some(language) = file.language.as_deref() else {
            collection.files_skipped += 1;
            continue;
        };
        if !supported_language(language)
            || file.parse_state.as_deref() != Some("parsed")
            || file.byte_size > MAX_SOURCE_BYTES
        {
            collection.files_skipped += 1;
            continue;
        }
        let Some(bytes) = read_verified_source(canonical_root, &file)? else {
            collection.files_stale += 1;
            continue;
        };
        let Ok(source) = String::from_utf8(bytes) else {
            collection.files_skipped += 1;
            continue;
        };
        let result = analyze_source(language, &source)?;
        if result.parsed_with_errors {
            collection.files_skipped += 1;
            continue;
        }
        collection.files_analyzed += 1;
        collection
            .observations
            .extend(
                result
                    .observations
                    .into_iter()
                    .map(|observation| PersistedObservation {
                        file: file.clone(),
                        observation,
                    }),
            );
    }
    Ok(collection)
}

fn load_active_files(
    connection: &Connection,
    project_id: &str,
) -> Result<Vec<IndexedSecurityFile>, SecurityAnalysisError> {
    let mut statement = connection.prepare(
        "SELECT id, relative_path, language, content_hash, byte_size, parse_state \
         FROM files WHERE project_id = ?1 AND is_active = 1 \
         ORDER BY relative_path, id LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![project_id, i64::try_from(MAX_FILES + 1).unwrap_or(i64::MAX)],
        |row| {
            Ok(IndexedSecurityFile {
                id: row.get(0)?,
                relative_path: row.get(1)?,
                language: row.get(2)?,
                content_hash: row.get(3)?,
                byte_size: to_u64(row.get(4)?),
                parse_state: row.get(5)?,
            })
        },
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn read_verified_source(
    canonical_root: &Path,
    file: &IndexedSecurityFile,
) -> Result<Option<Vec<u8>>, SecurityAnalysisError> {
    let relative = Path::new(&file.relative_path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(SecurityAnalysisError::UnsafeRelativePath(
            file.relative_path.clone(),
        ));
    }
    let candidate = canonical_root.join(relative);
    let metadata = match fs::symlink_metadata(&candidate) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_SOURCE_BYTES
    {
        return Ok(None);
    }
    let canonical = fs::canonicalize(&candidate)?;
    if !canonical.starts_with(canonical_root) {
        return Err(SecurityAnalysisError::UnsafeRelativePath(
            file.relative_path.clone(),
        ));
    }
    let bytes = fs::read(canonical)?;
    if sha256_hex(&bytes) != file.content_hash {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn persist_collection(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    collection: Collection,
    duration_ms: u64,
) -> Result<SecurityRunSummary, SecurityAnalysisError> {
    let transaction = connection.unchecked_transaction()?;
    let previous = load_open_fingerprints(&transaction, project_id)?;
    let mut current = BTreeSet::new();
    let mut opened = 0usize;
    let mut refreshed = 0usize;
    let mut hardcoded_credentials = 0usize;
    let mut dynamic_execution = 0usize;
    let mut weak_crypto = 0usize;
    let mut unsafe_c_apis = 0usize;

    for item in &collection.observations {
        match item.observation.rule_id.as_str() {
            "security.hardcoded_credential_literal" => hardcoded_credentials += 1,
            "security.dynamic_code_execution" => dynamic_execution += 1,
            "security.weak_cryptographic_hash" => weak_crypto += 1,
            "security.unsafe_c_string_api" => unsafe_c_apis += 1,
            _ => {}
        }
        let fingerprint = finding_fingerprint(project_id, item);
        current.insert(fingerprint.clone());
        if previous.contains_key(&fingerprint) {
            refreshed += 1;
        } else {
            opened += 1;
        }
        persist_finding(&transaction, project_id, run_id, &fingerprint, item)?;
    }

    let coverage_complete = collection.coverage_complete();
    let mut resolved = 0usize;
    if coverage_complete {
        for (fingerprint, finding_id) in previous {
            if current.contains(&fingerprint) {
                continue;
            }
            resolved += transaction.execute(
                "UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, last_run_id = ?1 \
                 WHERE id = ?2 AND analyzer_key = ?3 AND status = 'open'",
                params![run_id, finding_id, ANALYZER_KEY],
            )?;
        }
    }

    transaction.execute(
        "INSERT INTO security_run_metrics( \
           run_id, files_considered, files_analyzed, files_stale, files_skipped, observations, \
           findings_opened, findings_refreshed, findings_resolved, hardcoded_credentials, \
           dynamic_execution, weak_crypto, unsafe_c_apis \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            run_id,
            to_i64(collection.files_considered),
            to_i64(collection.files_analyzed),
            to_i64(collection.files_stale),
            to_i64(collection.files_skipped),
            to_i64(collection.observations.len()),
            to_i64(opened),
            to_i64(refreshed),
            to_i64(resolved),
            to_i64(hardcoded_credentials),
            to_i64(dynamic_execution),
            to_i64(weak_crypto),
            to_i64(unsafe_c_apis),
        ],
    )?;
    finish_run(&transaction, run_id, AnalysisStatus::Completed, duration_ms)?;
    transaction.commit()?;

    Ok(SecurityRunSummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        coverage_complete,
        files_considered: collection.files_considered,
        files_analyzed: collection.files_analyzed,
        files_stale: collection.files_stale,
        files_skipped: collection.files_skipped,
        observations: collection.observations.len(),
        findings_opened: opened,
        findings_refreshed: refreshed,
        findings_resolved: resolved,
        hardcoded_credentials,
        dynamic_execution,
        weak_crypto,
        unsafe_c_apis,
        duration_ms,
    })
}

fn load_open_fingerprints(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, String>, SecurityAnalysisError> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, id FROM findings \
         WHERE project_id = ?1 AND analyzer_key = ?2 AND status = 'open'",
    )?;
    let rows = statement.query_map(params![project_id, ANALYZER_KEY], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(Into::into)
}

fn persist_finding(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    fingerprint: &str,
    item: &PersistedObservation,
) -> Result<(), SecurityAnalysisError> {
    let finding_id = deterministic_id("security-finding-id", &[project_id, fingerprint]);
    let symbol_id = containing_symbol(
        connection,
        &item.file.id,
        item.observation.start_line,
        item.observation.end_line,
    )?;
    connection.execute(
        "INSERT INTO findings( \
           id, project_id, run_id, category, sub_category, severity, confidence, title, description, \
           file_id, symbol_id, source_start_line, source_end_line, cwe, owasp, status, fingerprint, \
           rule_version, first_seen, last_seen, analyzer_key, last_run_id, resolved_at \
         ) VALUES (?1, ?2, ?3, 'security', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                   'open', ?15, ?16, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?17, ?3, NULL) \
         ON CONFLICT(project_id, fingerprint) DO UPDATE SET \
           run_id = excluded.run_id, category = excluded.category, sub_category = excluded.sub_category, \
           severity = excluded.severity, confidence = excluded.confidence, title = excluded.title, \
           description = excluded.description, file_id = excluded.file_id, symbol_id = excluded.symbol_id, \
           source_start_line = excluded.source_start_line, source_end_line = excluded.source_end_line, \
           cwe = excluded.cwe, owasp = excluded.owasp, status = 'open', rule_version = excluded.rule_version, \
           last_seen = CURRENT_TIMESTAMP, analyzer_key = excluded.analyzer_key, last_run_id = excluded.last_run_id, \
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
            item.file.id,
            symbol_id,
            to_i64(item.observation.start_line),
            to_i64(item.observation.end_line),
            item.observation.cwe,
            item.observation.owasp,
            fingerprint,
            RULE_VERSION,
            ANALYZER_KEY,
        ],
    )?;

    connection.execute(
        "DELETE FROM finding_evidence WHERE finding_id = ?1",
        [&finding_id],
    )?;
    let evidence_id = deterministic_id("security-evidence", &[&finding_id, &item.file.id]);
    let analyzer_metadata: Value = serde_json::from_str(&item.observation.metadata_json)
        .unwrap_or_else(|_| json!({"metadata_parse_error": true}));
    let metadata_json = json!({
        "content_hash": item.file.content_hash,
        "start_column": item.observation.start_column,
        "end_column": item.observation.end_column,
        "anchor": item.observation.anchor,
        "secret_values_persisted": false,
        "analyzer": analyzer_metadata
    })
    .to_string();
    connection.execute(
        "INSERT INTO finding_evidence( \
           id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json \
         ) VALUES (?1, ?2, 'source', ?3, ?4, ?5, ?6, ?7)",
        params![
            evidence_id,
            finding_id,
            item.file.relative_path,
            to_i64(item.observation.start_line),
            to_i64(item.observation.end_line),
            item.observation.evidence_summary,
            metadata_json,
        ],
    )?;
    Ok(())
}

fn containing_symbol(
    connection: &Connection,
    file_id: &str,
    start_line: usize,
    end_line: usize,
) -> Result<Option<String>, SecurityAnalysisError> {
    connection
        .query_row(
            "SELECT id FROM symbols WHERE file_id = ?1 AND is_active = 1 \
               AND start_line <= ?2 AND end_line >= ?3 \
             ORDER BY (end_line - start_line) ASC, start_line DESC, id LIMIT 1",
            params![file_id, to_i64(start_line), to_i64(end_line)],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn finding_fingerprint(project_id: &str, item: &PersistedObservation) -> String {
    deterministic_id(
        "security-finding",
        &[
            project_id,
            &item.file.id,
            &item.observation.rule_id,
            &item.observation.anchor,
            &item.observation.start_line.to_string(),
        ],
    )
}

fn supported_language(language: &str) -> bool {
    matches!(
        language,
        "TypeScript"
            | "TypeScript TSX"
            | "JavaScript"
            | "Python"
            | "Rust"
            | "Go"
            | "C"
            | "C++"
            | "PHP"
    )
}

fn finish_run(
    connection: &Connection,
    run_id: &str,
    status: AnalysisStatus,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET status = ?2, finished_at = CURRENT_TIMESTAMP, duration_ms = ?3 WHERE id = ?1",
        params![run_id, status.as_str(), to_i64_u64(duration_ms)],
    )?;
    Ok(())
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    deterministic_id("security-run", &[project_id, &nanos.to_string()])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn bounded(value: usize, maximum: usize) -> i64 {
    i64::try_from(value.clamp(1, maximum)).unwrap_or(i64::MAX)
}

fn optional_usize(value: Option<i64>) -> Option<usize> {
    value.and_then(|item| usize::try_from(item).ok())
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_i64_u64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
