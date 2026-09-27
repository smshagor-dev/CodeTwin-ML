use lsp_enrichment::LanguageServerKind;
use rusqlite::{params, OptionalExtension};
use thiserror::Error;

use crate::{
    AnalysisStatus, Database, SemanticImportResolutionRecord, SemanticRelationDirection,
    SemanticRelationRecord, SemanticRunRecord, SemanticSymbolState, SemanticSymbolStateRecord,
};

const MAX_RELATION_LIMIT: usize = 300;
const MAX_HISTORY_LIMIT: usize = 100;

#[derive(Debug, Error)]
pub enum SemanticQueryError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid persisted semantic value: {0}")]
    InvalidEnum(String),
}

pub struct SemanticQueryService<'a> {
    database: &'a Database,
}

impl<'a> SemanticQueryService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn relations_for_symbol(
        &self,
        symbol_id: &str,
        direction: SemanticRelationDirection,
        limit: usize,
    ) -> Result<Vec<SemanticRelationRecord>, SemanticQueryError> {
        let clause = match direction {
            SemanticRelationDirection::Incoming => "r.target_symbol_id = ?1",
            SemanticRelationDirection::Outgoing => "r.container_symbol_id = ?1",
            SemanticRelationDirection::Subject => "r.subject_symbol_id = ?1",
            SemanticRelationDirection::All => {
                "(r.subject_symbol_id = ?1 OR r.container_symbol_id = ?1 OR r.target_symbol_id = ?1)"
            }
        };
        let sql = format!(
            "SELECT r.id, r.project_id, r.run_id, r.subject_symbol_id, r.occurrence_file_id, \
                    r.container_symbol_id, r.target_file_id, r.target_symbol_id, r.relationship, \
                    r.occurrence_start_line, r.occurrence_start_column, r.occurrence_end_line, r.occurrence_end_column, \
                    r.target_start_line, r.target_start_column, r.target_end_line, r.target_end_column, \
                    r.provider_kind, r.server_name, r.server_version \
             FROM semantic_relations r \
             JOIN files occurrence_file ON occurrence_file.id = r.occurrence_file_id \
             JOIN files target_file ON target_file.id = r.target_file_id \
             JOIN symbols subject_symbol ON subject_symbol.id = r.subject_symbol_id \
             WHERE {clause} \
               AND r.is_active = 1 \
               AND occurrence_file.is_active = 1 \
               AND target_file.is_active = 1 \
               AND subject_symbol.is_active = 1 \
               AND occurrence_file.content_hash = r.occurrence_content_hash \
               AND target_file.content_hash = r.target_content_hash \
             ORDER BY r.occurrence_file_id, r.occurrence_start_line, r.occurrence_start_column \
             LIMIT ?2"
        );
        let mut statement = self.database.connection().prepare(&sql)?;
        let rows = statement.query_map(
            params![symbol_id, bounded(limit, MAX_RELATION_LIMIT)],
            |row| {
                let provider_text: String = row.get(17)?;
                let provider_kind =
                    LanguageServerKind::from_str(&provider_text).ok_or_else(|| {
                        conversion_error(17, format!("invalid provider kind {provider_text}"))
                    })?;
                Ok(SemanticRelationRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    run_id: row.get(2)?,
                    subject_symbol_id: row.get(3)?,
                    occurrence_file_id: row.get(4)?,
                    container_symbol_id: row.get(5)?,
                    target_file_id: row.get(6)?,
                    target_symbol_id: row.get(7)?,
                    relationship: row.get(8)?,
                    occurrence_start_line: to_usize(row.get(9)?),
                    occurrence_start_column: to_usize(row.get(10)?),
                    occurrence_end_line: to_usize(row.get(11)?),
                    occurrence_end_column: to_usize(row.get(12)?),
                    target_start_line: to_usize(row.get(13)?),
                    target_start_column: to_usize(row.get(14)?),
                    target_end_line: to_usize(row.get(15)?),
                    target_end_column: to_usize(row.get(16)?),
                    provider_kind,
                    server_name: row.get(18)?,
                    server_version: row.get(19)?,
                })
            },
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn symbol_state(
        &self,
        symbol_id: &str,
    ) -> Result<Option<SemanticSymbolStateRecord>, SemanticQueryError> {
        self.database
            .connection()
            .query_row(
                "SELECT symbol_id, project_id, run_id, provider_kind, state, reference_locations, definitions_resolved, last_error \
                 FROM semantic_symbol_states WHERE symbol_id = ?1",
                [symbol_id],
                |row| {
                    let provider_text: String = row.get(3)?;
                    let state_text: String = row.get(4)?;
                    let provider_kind = LanguageServerKind::from_str(&provider_text).ok_or_else(|| {
                        conversion_error(3, format!("invalid provider kind {provider_text}"))
                    })?;
                    let state = SemanticSymbolState::from_db(&state_text).ok_or_else(|| {
                        conversion_error(4, format!("invalid semantic state {state_text}"))
                    })?;
                    Ok(SemanticSymbolStateRecord {
                        symbol_id: row.get(0)?,
                        project_id: row.get(1)?,
                        run_id: row.get(2)?,
                        provider_kind,
                        state,
                        reference_locations: to_usize(row.get(5)?),
                        definitions_resolved: to_usize(row.get(6)?),
                        last_error: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn semantic_imports(
        &self,
        file_id: &str,
        limit: usize,
    ) -> Result<Vec<SemanticImportResolutionRecord>, SemanticQueryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT r.id, r.project_id, r.run_id, r.import_reference_id, r.source_file_id, r.target_file_id, \
                    r.provider_kind, r.target_start_line, r.target_start_column, r.target_end_line, r.target_end_column \
             FROM semantic_import_resolutions r \
             JOIN files source_file ON source_file.id = r.source_file_id \
             JOIN files target_file ON target_file.id = r.target_file_id \
             WHERE (r.source_file_id = ?1 OR r.target_file_id = ?1) \
               AND r.is_active = 1 \
               AND source_file.is_active = 1 AND target_file.is_active = 1 \
               AND source_file.content_hash = r.source_content_hash \
               AND target_file.content_hash = r.target_content_hash \
             ORDER BY r.source_file_id, r.import_reference_id, r.target_file_id \
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![file_id, bounded(limit, MAX_RELATION_LIMIT)],
            |row| {
                let provider_text: String = row.get(6)?;
                let provider_kind =
                    LanguageServerKind::from_str(&provider_text).ok_or_else(|| {
                        conversion_error(6, format!("invalid provider kind {provider_text}"))
                    })?;
                Ok(SemanticImportResolutionRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    run_id: row.get(2)?,
                    import_reference_id: row.get(3)?,
                    source_file_id: row.get(4)?,
                    target_file_id: row.get(5)?,
                    provider_kind,
                    target_start_line: to_usize(row.get(7)?),
                    target_start_column: to_usize(row.get(8)?),
                    target_end_line: to_usize(row.get(9)?),
                    target_end_column: to_usize(row.get(10)?),
                })
            },
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<SemanticRunRecord>, SemanticQueryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT a.id, a.project_id, a.status, a.started_at, a.finished_at, a.duration_ms, \
                    COALESCE(m.files_processed, 0), COALESCE(m.symbols_processed, 0), \
                    COALESCE(m.symbols_matched, 0), COALESCE(m.reference_locations, 0), \
                    COALESCE(m.definitions_resolved, 0), COALESCE(m.relations_persisted, 0), \
                    COALESCE(m.graph_edges_materialized, 0), COALESCE(m.imports_upgraded, 0), \
                    COALESCE(m.errors, 0) \
             FROM analysis_runs a \
             LEFT JOIN semantic_run_metrics m ON m.run_id = a.id \
             WHERE a.project_id = ?1 AND a.run_kind = 'lsp_semantic' \
             ORDER BY a.started_at DESC, a.id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded(limit, MAX_HISTORY_LIMIT)],
            |row| {
                let status_text: String = row.get(2)?;
                let status = AnalysisStatus::from_db(&status_text).ok_or_else(|| {
                    conversion_error(2, format!("invalid analysis status {status_text}"))
                })?;
                Ok(SemanticRunRecord {
                    run_id: row.get(0)?,
                    project_id: row.get(1)?,
                    status,
                    started_at: row.get(3)?,
                    finished_at: row.get(4)?,
                    duration_ms: row.get::<_, Option<i64>>(5)?.map(to_u64),
                    files_processed: to_usize(row.get(6)?),
                    symbols_processed: to_usize(row.get(7)?),
                    symbols_matched: to_usize(row.get(8)?),
                    reference_locations: to_usize(row.get(9)?),
                    definitions_resolved: to_usize(row.get(10)?),
                    relations_persisted: to_usize(row.get(11)?),
                    graph_edges_materialized: to_usize(row.get(12)?),
                    imports_upgraded: to_usize(row.get(13)?),
                    errors: to_usize(row.get(14)?),
                })
            },
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }
}

fn bounded(value: usize, maximum: usize) -> i64 {
    i64::try_from(value.clamp(1, maximum)).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn conversion_error(column: usize, message: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, message.into())
}
