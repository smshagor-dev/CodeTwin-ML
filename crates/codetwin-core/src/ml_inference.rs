use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::{deterministic_id, Database};

const ANALYZER_VERSION: &str = "ml-inference-provenance-v1";
const QUERY_VERSION: &str = "ml-inference-record-v1";
const MAX_INPUT_BYTES: u64 = 65_536;
const MAX_SCORES: usize = 256;
const MAX_LABEL_BYTES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_JSON_BYTES: usize = 131_072;
const MAX_HISTORY_QUERY: usize = 200;
const SCORE_SUM_TOLERANCE: f64 = 0.001;
const CONFIDENCE_TOLERANCE: f64 = 0.000_001;

#[derive(Debug, Error)]
pub enum MlInferenceError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("source file not found or inactive: {0}")]
    SourceFileNotFound(String),
    #[error("source file does not belong to project")]
    SourceProjectMismatch,
    #[error("source file content hash is stale")]
    SourceHashMismatch,
    #[error("invalid ML inference observation: {0}")]
    InvalidObservation(String),
    #[error("ML inference record not found: {0}")]
    InferenceNotFound(String),
    #[error("finding not found: {0}")]
    FindingNotFound(String),
    #[error("ML inference and finding must belong to the same project")]
    LinkProjectMismatch,
    #[error("unsupported ML/finding relationship: {0}")]
    UnsupportedRelationship(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MlScore {
    pub label: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MlInferenceObservation {
    pub action: String,
    pub source_file_id: Option<String>,
    pub source_content_hash: Option<String>,
    pub input_sha256: String,
    pub input_utf8_bytes: u64,
    pub preprocessing: String,
    pub model_id: String,
    pub model_version: String,
    pub backend: String,
    pub package_digest: String,
    pub prediction_label: String,
    pub prediction_confidence: f64,
    pub scores: Vec<MlScore>,
    pub runtime: Value,
    pub evaluation_provenance: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MlInferenceRecord {
    pub id: String,
    pub project_id: String,
    pub run_id: String,
    pub action: String,
    pub source_file_id: Option<String>,
    pub source_content_hash: Option<String>,
    pub input_sha256: String,
    pub input_utf8_bytes: u64,
    pub preprocessing: String,
    pub model_id: String,
    pub model_version: String,
    pub backend: String,
    pub package_digest: String,
    pub prediction_label: String,
    pub prediction_confidence: f64,
    pub scores: Vec<MlScore>,
    pub runtime: Value,
    pub evaluation_provenance: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlFindingLinkRecord {
    pub id: String,
    pub project_id: String,
    pub inference_record_id: String,
    pub finding_id: String,
    pub relationship: String,
    pub created_at: String,
}

pub struct MlInferenceStore<'a> {
    database: &'a Database,
}

impl<'a> MlInferenceStore<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn record(
        &self,
        project_id: &str,
        observation: &MlInferenceObservation,
    ) -> Result<MlInferenceRecord, MlInferenceError> {
        ensure_project(self.database.connection(), project_id)?;
        validate_observation(observation)?;
        validate_source(self.database.connection(), project_id, observation)?;

        let now_nonce = time_nonce();
        let run_id = deterministic_id(
            "ml-inference-run",
            &[
                project_id,
                &observation.action,
                &observation.model_id,
                &observation.model_version,
                &observation.input_sha256,
                &now_nonce,
            ],
        );
        let record_id = deterministic_id(
            "ml-inference-record",
            &[project_id, &run_id, &observation.package_digest],
        );
        let scores_json = serde_json::to_string(&observation.scores)?;
        let runtime_json = serde_json::to_string(&observation.runtime)?;
        let evaluation_json = serde_json::to_string(&observation.evaluation_provenance)?;
        let configuration_json = serde_json::to_string(&json!({
            "action": observation.action,
            "model_id": observation.model_id,
            "model_version": observation.model_version,
            "backend": observation.backend,
            "preprocessing": observation.preprocessing,
        }))?;

        let tx = self.database.connection().unchecked_transaction()?;
        tx.execute(
            "INSERT INTO analysis_runs( \
               id, project_id, status, analyzer_version, started_at, finished_at, configuration_json, \
               run_kind, query_version, config_fingerprint \
             ) VALUES (?1, ?2, 'completed', ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?4, \
                       'ml_inference', ?5, ?6)",
            params![
                run_id,
                project_id,
                ANALYZER_VERSION,
                configuration_json,
                QUERY_VERSION,
                observation.package_digest,
            ],
        )?;
        tx.execute(
            "INSERT INTO ml_inference_records( \
               id, project_id, run_id, action, source_file_id, source_content_hash, input_sha256, \
               input_utf8_bytes, preprocessing, model_id, model_version, backend, package_digest, \
               prediction_label, prediction_confidence, scores_json, runtime_json, evaluation_provenance_json \
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                record_id,
                project_id,
                run_id,
                observation.action,
                observation.source_file_id,
                observation.source_content_hash,
                observation.input_sha256,
                observation.input_utf8_bytes,
                observation.preprocessing,
                observation.model_id,
                observation.model_version,
                observation.backend,
                observation.package_digest,
                observation.prediction_label,
                observation.prediction_confidence,
                scores_json,
                runtime_json,
                evaluation_json,
            ],
        )?;
        tx.commit()?;

        self.get(&record_id)?
            .ok_or_else(|| MlInferenceError::InferenceNotFound(record_id))
    }

    pub fn get(&self, record_id: &str) -> Result<Option<MlInferenceRecord>, MlInferenceError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, project_id, run_id, action, source_file_id, source_content_hash, \
                        input_sha256, input_utf8_bytes, preprocessing, model_id, model_version, backend, \
                        package_digest, prediction_label, prediction_confidence, scores_json, runtime_json, \
                        evaluation_provenance_json, created_at \
                 FROM ml_inference_records WHERE id = ?1",
                [record_id],
                map_inference_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn history(
        &self,
        project_id: &str,
        action: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MlInferenceRecord>, MlInferenceError> {
        ensure_project(self.database.connection(), project_id)?;
        let limit = bounded(limit, MAX_HISTORY_QUERY);
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, run_id, action, source_file_id, source_content_hash, \
                    input_sha256, input_utf8_bytes, preprocessing, model_id, model_version, backend, \
                    package_digest, prediction_label, prediction_confidence, scores_json, runtime_json, \
                    evaluation_provenance_json, created_at \
             FROM ml_inference_records \
             WHERE project_id = ?1 AND (?2 IS NULL OR action = ?2) \
             ORDER BY created_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![project_id, action, limit], map_inference_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn link_to_finding(
        &self,
        project_id: &str,
        inference_record_id: &str,
        finding_id: &str,
        relationship: &str,
    ) -> Result<MlFindingLinkRecord, MlInferenceError> {
        if !matches!(
            relationship,
            "supports_review" | "contradicts_review" | "related"
        ) {
            return Err(MlInferenceError::UnsupportedRelationship(
                relationship.to_owned(),
            ));
        }
        let inference_project =
            project_for_inference(self.database.connection(), inference_record_id)?.ok_or_else(
                || MlInferenceError::InferenceNotFound(inference_record_id.to_owned()),
            )?;
        let finding_project = project_for_finding(self.database.connection(), finding_id)?
            .ok_or_else(|| MlInferenceError::FindingNotFound(finding_id.to_owned()))?;
        if inference_project != project_id || finding_project != project_id {
            return Err(MlInferenceError::LinkProjectMismatch);
        }

        let id = deterministic_id(
            "ml-finding-link",
            &[project_id, inference_record_id, finding_id, relationship],
        );
        self.database.connection().execute(
            "INSERT INTO ml_finding_links(id, project_id, inference_record_id, finding_id, relationship) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(project_id, inference_record_id, finding_id, relationship) DO NOTHING",
            params![id, project_id, inference_record_id, finding_id, relationship],
        )?;
        self.database
            .connection()
            .query_row(
                "SELECT id, project_id, inference_record_id, finding_id, relationship, created_at \
                 FROM ml_finding_links \
                 WHERE project_id = ?1 AND inference_record_id = ?2 AND finding_id = ?3 AND relationship = ?4",
                params![project_id, inference_record_id, finding_id, relationship],
                |row| {
                    Ok(MlFindingLinkRecord {
                        id: row.get(0)?,
                        project_id: row.get(1)?,
                        inference_record_id: row.get(2)?,
                        finding_id: row.get(3)?,
                        relationship: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn links_for_finding(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<MlFindingLinkRecord>, MlInferenceError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, inference_record_id, finding_id, relationship, created_at \
             FROM ml_finding_links WHERE finding_id = ?1 \
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![finding_id, bounded(limit, MAX_HISTORY_QUERY)],
            |row| {
                Ok(MlFindingLinkRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    inference_record_id: row.get(2)?,
                    finding_id: row.get(3)?,
                    relationship: row.get(4)?,
                    created_at: row.get(5)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn validate_observation(observation: &MlInferenceObservation) -> Result<(), MlInferenceError> {
    for (name, value) in [
        ("action", observation.action.as_str()),
        ("preprocessing", observation.preprocessing.as_str()),
        ("model_id", observation.model_id.as_str()),
        ("model_version", observation.model_version.as_str()),
        ("backend", observation.backend.as_str()),
        ("prediction_label", observation.prediction_label.as_str()),
    ] {
        if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
            return Err(MlInferenceError::InvalidObservation(format!(
                "{name} must contain 1-{MAX_IDENTIFIER_BYTES} bytes"
            )));
        }
    }
    if observation.input_utf8_bytes > MAX_INPUT_BYTES {
        return Err(MlInferenceError::InvalidObservation(format!(
            "input exceeds {MAX_INPUT_BYTES} UTF-8 bytes"
        )));
    }
    validate_sha256("input_sha256", &observation.input_sha256)?;
    validate_sha256("package_digest", &observation.package_digest)?;
    if let Some(hash) = observation.source_content_hash.as_deref() {
        validate_sha256("source_content_hash", hash)?;
    }
    if !observation.prediction_confidence.is_finite()
        || !(0.0..=1.0).contains(&observation.prediction_confidence)
    {
        return Err(MlInferenceError::InvalidObservation(
            "prediction confidence must be finite and between 0 and 1".to_owned(),
        ));
    }
    if observation.scores.is_empty() || observation.scores.len() > MAX_SCORES {
        return Err(MlInferenceError::InvalidObservation(format!(
            "scores must contain 1-{MAX_SCORES} labels"
        )));
    }
    let mut labels = std::collections::BTreeSet::new();
    let mut sum = 0.0;
    let mut selected_score = None;
    for score in &observation.scores {
        if score.label.is_empty()
            || score.label.len() > MAX_LABEL_BYTES
            || !labels.insert(&score.label)
        {
            return Err(MlInferenceError::InvalidObservation(
                "score labels must be unique bounded non-empty strings".to_owned(),
            ));
        }
        if !score.score.is_finite() || !(0.0..=1.0).contains(&score.score) {
            return Err(MlInferenceError::InvalidObservation(
                "scores must be finite probabilities between 0 and 1".to_owned(),
            ));
        }
        if score.label == observation.prediction_label {
            selected_score = Some(score.score);
        }
        sum += score.score;
    }
    if (sum - 1.0).abs() > SCORE_SUM_TOLERANCE {
        return Err(MlInferenceError::InvalidObservation(
            "scores must sum to approximately 1".to_owned(),
        ));
    }
    let selected_score = selected_score.ok_or_else(|| {
        MlInferenceError::InvalidObservation("prediction label must appear in scores".to_owned())
    })?;
    if (selected_score - observation.prediction_confidence).abs() > CONFIDENCE_TOLERANCE {
        return Err(MlInferenceError::InvalidObservation(
            "prediction confidence must match the selected label score".to_owned(),
        ));
    }
    for (name, value) in [
        ("runtime", &observation.runtime),
        ("evaluation_provenance", &observation.evaluation_provenance),
    ] {
        let serialized = serde_json::to_vec(value)?;
        if serialized.len() > MAX_JSON_BYTES {
            return Err(MlInferenceError::InvalidObservation(format!(
                "{name} JSON exceeds {MAX_JSON_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_source(
    connection: &Connection,
    project_id: &str,
    observation: &MlInferenceObservation,
) -> Result<(), MlInferenceError> {
    let Some(file_id) = observation.source_file_id.as_deref() else {
        if observation.source_content_hash.is_some() {
            return Err(MlInferenceError::InvalidObservation(
                "source_content_hash requires source_file_id".to_owned(),
            ));
        }
        return Ok(());
    };
    let expected_hash = observation.source_content_hash.as_deref().ok_or_else(|| {
        MlInferenceError::InvalidObservation(
            "source_file_id requires source_content_hash to prevent stale attribution".to_owned(),
        )
    })?;
    let source = connection
        .query_row(
            "SELECT project_id, content_hash FROM files WHERE id = ?1 AND is_active = 1",
            [file_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((source_project, current_hash)) = source else {
        return Err(MlInferenceError::SourceFileNotFound(file_id.to_owned()));
    };
    if source_project != project_id {
        return Err(MlInferenceError::SourceProjectMismatch);
    }
    if current_hash != expected_hash {
        return Err(MlInferenceError::SourceHashMismatch);
    }
    Ok(())
}

fn validate_sha256(name: &str, value: &str) -> Result<(), MlInferenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(MlInferenceError::InvalidObservation(format!(
            "{name} must be a lowercase SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn ensure_project(connection: &Connection, project_id: &str) -> Result<(), MlInferenceError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
        [project_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(MlInferenceError::ProjectNotFound(project_id.to_owned()))
    }
}

fn project_for_inference(
    connection: &Connection,
    inference_record_id: &str,
) -> Result<Option<String>, MlInferenceError> {
    connection
        .query_row(
            "SELECT project_id FROM ml_inference_records WHERE id = ?1",
            [inference_record_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn project_for_finding(
    connection: &Connection,
    finding_id: &str,
) -> Result<Option<String>, MlInferenceError> {
    connection
        .query_row(
            "SELECT project_id FROM findings WHERE id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn map_inference_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MlInferenceRecord> {
    let scores_json: String = row.get(15)?;
    let runtime_json: String = row.get(16)?;
    let evaluation_json: String = row.get(17)?;
    let input_bytes: i64 = row.get(7)?;
    Ok(MlInferenceRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        run_id: row.get(2)?,
        action: row.get(3)?,
        source_file_id: row.get(4)?,
        source_content_hash: row.get(5)?,
        input_sha256: row.get(6)?,
        input_utf8_bytes: u64::try_from(input_bytes).unwrap_or_default(),
        preprocessing: row.get(8)?,
        model_id: row.get(9)?,
        model_version: row.get(10)?,
        backend: row.get(11)?,
        package_digest: row.get(12)?,
        prediction_label: row.get(13)?,
        prediction_confidence: row.get(14)?,
        scores: serde_json::from_str(&scores_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                scores_json.len(),
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        runtime: serde_json::from_str(&runtime_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                runtime_json.len(),
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        evaluation_provenance: serde_json::from_str(&evaluation_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                evaluation_json.len(),
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        created_at: row.get(18)?,
    })
}

fn bounded(requested: usize, maximum: usize) -> i64 {
    requested.max(1).min(maximum) as i64
}

fn time_nonce() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MlInferenceError, MlInferenceObservation, MlInferenceStore, MlScore};
    use crate::Database;

    fn insert_project(db: &Database, project_id: &str) {
        db.connection()
            .execute(
                "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES (?1, ?2, ?3, ?4)",
                [project_id, "/tmp/project", "project", "/tmp/project"],
            )
            .expect("insert project");
    }

    fn observation() -> MlInferenceObservation {
        MlInferenceObservation {
            action: "security_analysis".to_owned(),
            source_file_id: None,
            source_content_hash: None,
            input_sha256: "a".repeat(64),
            input_utf8_bytes: 7,
            preprocessing: "utf8-bytes-v1".to_owned(),
            model_id: "openmindai-security".to_owned(),
            model_version: "1.0.0".to_owned(),
            backend: "onnx-classification-v1".to_owned(),
            package_digest: "b".repeat(64),
            prediction_label: "review".to_owned(),
            prediction_confidence: 0.8,
            scores: vec![
                MlScore {
                    label: "safe".to_owned(),
                    score: 0.2,
                },
                MlScore {
                    label: "review".to_owned(),
                    score: 0.8,
                },
            ],
            runtime: json!({"engine":"onnxruntime","provider":"CPUExecutionProvider"}),
            evaluation_provenance: json!({"status":"passed","datasets":[]}),
        }
    }

    #[test]
    fn records_bounded_inference_provenance_without_raw_source() {
        let db = Database::open_in_memory().expect("open db");
        insert_project(&db, "project-1");
        let store = MlInferenceStore::new(&db);
        let record = store
            .record("project-1", &observation())
            .expect("record inference");
        assert_eq!(record.prediction_label, "review");
        assert_eq!(record.input_sha256, "a".repeat(64));
        assert_eq!(
            store
                .history("project-1", Some("security_analysis"), 50)
                .expect("history")
                .len(),
            1
        );

        let columns: Vec<String> = db
            .connection()
            .prepare("PRAGMA table_info(ml_inference_records)")
            .expect("table info")
            .query_map([], |row| row.get(1))
            .expect("columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect");
        assert!(!columns
            .iter()
            .any(|column| column == "source_text" || column == "input_text"));
    }

    #[test]
    fn rejects_stale_source_attribution() {
        let db = Database::open_in_memory().expect("open db");
        insert_project(&db, "project-1");
        db.connection()
            .execute(
                "INSERT INTO files(id, project_id, relative_path, language, content_hash, byte_size, relative_path_identity, is_active) \
                 VALUES ('file-1','project-1','src/a.ts','typescript',?1,10,'src/a.ts',1)",
                ["c".repeat(64)],
            )
            .expect("insert file");
        let mut value = observation();
        value.source_file_id = Some("file-1".to_owned());
        value.source_content_hash = Some("d".repeat(64));
        let error = MlInferenceStore::new(&db)
            .record("project-1", &value)
            .expect_err("stale hash must fail");
        assert!(matches!(error, MlInferenceError::SourceHashMismatch));
    }

    #[test]
    fn review_links_do_not_mutate_deterministic_findings() {
        let db = Database::open_in_memory().expect("open db");
        insert_project(&db, "project-1");
        let store = MlInferenceStore::new(&db);
        let inference = store
            .record("project-1", &observation())
            .expect("record inference");
        db.connection()
            .execute(
                "INSERT INTO findings(id, project_id, run_id, category, severity, confidence, title, description, status, fingerprint) \
                 VALUES ('finding-1','project-1',?1,'security','medium',0.95,'deterministic','evidence','open','fp-1')",
                [&inference.run_id],
            )
            .expect("insert finding");
        store
            .link_to_finding("project-1", &inference.id, "finding-1", "supports_review")
            .expect("link");
        let (status, confidence): (String, f64) = db
            .connection()
            .query_row(
                "SELECT status, confidence FROM findings WHERE id='finding-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("finding");
        assert_eq!(status, "open");
        assert_eq!(confidence, 0.95);
        assert_eq!(
            store
                .links_for_finding("finding-1", 20)
                .expect("links")
                .len(),
            1
        );
    }
}
