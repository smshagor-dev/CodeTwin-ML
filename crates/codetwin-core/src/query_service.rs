use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

use crate::{
    AnalysisStatus, Database, GraphEdgeRecord, GraphNeighborhood, GraphNodeRecord, GraphSummary,
    ImportReferenceRecord, ImportResolutionState, IndexDelta, IndexRunRecord, SourceFileRecord,
    SymbolRecord, SymbolSearchQuery,
};

const MAX_QUERY_LIMIT: usize = 500;
const MAX_GRAPH_LIMIT: usize = 200;

#[derive(Debug, Error)]
pub enum QueryServiceError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid persisted enum value: {0}")]
    InvalidEnum(String),
}

pub struct ProjectQueryService<'a> {
    database: &'a Database,
}

impl<'a> ProjectQueryService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn list_files(
        &self,
        project_id: &str,
        search: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SourceFileRecord>, QueryServiceError> {
        let connection = self.database.connection();
        let limit = bounded_limit(limit, MAX_QUERY_LIMIT);
        let search = search.map(str::trim).filter(|value| !value.is_empty());
        let mut records = Vec::new();
        if let Some(search) = search {
            let pattern = format!("%{}%", escape_like(search));
            let mut statement = connection.prepare(
                "SELECT id, project_id, relative_path, COALESCE(relative_path_identity, relative_path), language, content_hash, byte_size, ast_root_kind, parse_state, is_active \
                 FROM files WHERE project_id = ?1 AND is_active = 1 AND relative_path LIKE ?2 ESCAPE '\\' \
                 ORDER BY relative_path LIMIT ?3",
            )?;
            let rows = statement.query_map(params![project_id, pattern, limit], map_file)?;
            for row in rows {
                records.push(row?);
            }
        } else {
            let mut statement = connection.prepare(
                "SELECT id, project_id, relative_path, COALESCE(relative_path_identity, relative_path), language, content_hash, byte_size, ast_root_kind, parse_state, is_active \
                 FROM files WHERE project_id = ?1 AND is_active = 1 \
                 ORDER BY relative_path LIMIT ?2",
            )?;
            let rows = statement.query_map(params![project_id, limit], map_file)?;
            for row in rows {
                records.push(row?);
            }
        }
        Ok(records)
    }

    pub fn get_file(&self, file_id: &str) -> Result<Option<SourceFileRecord>, QueryServiceError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, project_id, relative_path, COALESCE(relative_path_identity, relative_path), language, content_hash, byte_size, ast_root_kind, parse_state, is_active \
                 FROM files WHERE id = ?1 AND is_active = 1",
                [file_id],
                map_file,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_file_symbols(
        &self,
        file_id: &str,
        limit: usize,
    ) -> Result<Vec<SymbolRecord>, QueryServiceError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, file_id, kind, name, qualified_name, parent_symbol_id, fingerprint, start_line, start_column, end_line, end_column \
             FROM symbols WHERE file_id = ?1 AND is_active = 1 \
             ORDER BY start_line, start_column, name LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![file_id, bounded_limit(limit, MAX_QUERY_LIMIT)],
            map_symbol,
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn search_symbols(
        &self,
        project_id: &str,
        search: &SymbolSearchQuery,
    ) -> Result<Vec<SymbolRecord>, QueryServiceError> {
        let exact = search.query.trim().to_string();
        let escaped = escape_like(&exact);
        let prefix = format!("{escaped}%");
        let substring = format!("%{escaped}%");
        let mut statement = self.database.connection().prepare(
            "SELECT s.id, s.project_id, s.file_id, s.kind, s.name, s.qualified_name, s.parent_symbol_id, s.fingerprint, \
                    s.start_line, s.start_column, s.end_line, s.end_column \
             FROM symbols s JOIN files f ON f.id = s.file_id \
             WHERE s.project_id = ?1 AND s.is_active = 1 AND f.is_active = 1 \
               AND ( \
                 (?2 = 'exact' AND (s.name = ?3 OR COALESCE(s.qualified_name, '') = ?3)) OR \
                 (?2 = 'prefix' AND (s.name LIKE ?4 ESCAPE '\\' OR COALESCE(s.qualified_name, '') LIKE ?4 ESCAPE '\\')) OR \
                 (?2 = 'substring' AND (s.name LIKE ?5 ESCAPE '\\' OR COALESCE(s.qualified_name, '') LIKE ?5 ESCAPE '\\')) \
               ) \
               AND (?6 IS NULL OR s.kind = ?6) \
               AND (?7 IS NULL OR f.language = ?7) \
               AND (?8 IS NULL OR f.relative_path = ?8) \
               AND (?9 = 0 OR s.qualified_name IS NOT NULL) \
             ORDER BY s.name, f.relative_path, s.start_line, s.start_column \
             LIMIT ?10",
        )?;
        let rows = statement.query_map(
            params![
                project_id,
                search.mode.as_str(),
                exact,
                prefix,
                substring,
                search.kind,
                search.language,
                search.file,
                i64::from(search.qualified_only),
                bounded_limit(search.limit, MAX_QUERY_LIMIT),
            ],
            map_symbol,
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn get_symbol(&self, symbol_id: &str) -> Result<Option<SymbolRecord>, QueryServiceError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, project_id, file_id, kind, name, qualified_name, parent_symbol_id, fingerprint, start_line, start_column, end_line, end_column \
                 FROM symbols WHERE id = ?1 AND is_active = 1",
                [symbol_id],
                map_symbol,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn graph_summary(&self, project_id: &str) -> Result<GraphSummary, QueryServiceError> {
        let connection = self.database.connection();
        let node_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM graph_nodes WHERE project_id = ?1 AND is_active = 1",
            [project_id],
            |row| row.get(0),
        )?;
        let edge_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM graph_edges WHERE project_id = ?1 AND is_active = 1",
            [project_id],
            |row| row.get(0),
        )?;
        Ok(GraphSummary {
            node_count: to_usize(node_count),
            edge_count: to_usize(edge_count),
        })
    }

    pub fn graph_neighborhood(
        &self,
        node_id: &str,
        limit: usize,
    ) -> Result<Option<GraphNeighborhood>, QueryServiceError> {
        let connection = self.database.connection();
        let Some(center) = get_graph_node(connection, node_id)? else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            "SELECT id, project_id, source_node_id, target_node_id, relationship, metadata_json \
             FROM graph_edges \
             WHERE project_id = ?1 AND is_active = 1 AND (source_node_id = ?2 OR target_node_id = ?2) \
             ORDER BY relationship, id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                center.project_id,
                node_id,
                bounded_limit(limit, MAX_GRAPH_LIMIT)
            ],
            map_graph_edge,
        )?;
        let mut edges = Vec::new();
        let mut nodes = BTreeMap::new();
        nodes.insert(center.id.clone(), center.clone());
        for row in rows {
            let edge = row?;
            for endpoint in [&edge.source_node_id, &edge.target_node_id] {
                if !nodes.contains_key(endpoint) {
                    if let Some(node) = get_graph_node(connection, endpoint)? {
                        nodes.insert(node.id.clone(), node);
                    }
                }
            }
            edges.push(edge);
        }
        Ok(Some(GraphNeighborhood {
            center,
            nodes: nodes.into_values().collect(),
            edges,
        }))
    }

    pub fn dependencies(
        &self,
        file_id: &str,
        limit: usize,
    ) -> Result<Vec<ImportReferenceRecord>, QueryServiceError> {
        self.imports_with_clause(
            "source_file_id = ?1",
            file_id,
            bounded_limit(limit, MAX_QUERY_LIMIT),
        )
    }

    pub fn dependents(
        &self,
        file_id: &str,
        limit: usize,
    ) -> Result<Vec<ImportReferenceRecord>, QueryServiceError> {
        self.imports_with_clause(
            "resolved_target_file_id = ?1",
            file_id,
            bounded_limit(limit, MAX_QUERY_LIMIT),
        )
    }

    pub fn index_history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<IndexRunRecord>, QueryServiceError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, status, analyzer_version, query_version, config_fingerprint, started_at, finished_at, duration_ms, \
                    files_scanned, files_added, files_modified, files_unchanged, files_deleted, symbols_added, symbols_updated, symbols_removed, parse_errors, skipped_files \
             FROM analysis_runs WHERE project_id = ?1 AND run_kind = 'source_index' \
             ORDER BY started_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id, bounded_limit(limit, 100)], |row| {
            let status_text: String = row.get(2)?;
            let status = AnalysisStatus::from_db(&status_text).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    format!("invalid analysis status {status_text}").into(),
                )
            })?;
            Ok(IndexRunRecord {
                id: row.get(0)?,
                project_id: row.get(1)?,
                status,
                analyzer_version: row.get(3)?,
                query_version: row.get(4)?,
                config_fingerprint: row.get(5)?,
                started_at: row.get(6)?,
                finished_at: row.get(7)?,
                duration_ms: row.get::<_, Option<i64>>(8)?.map(to_u64),
                delta: IndexDelta {
                    files_scanned: to_usize(row.get(9)?),
                    files_added: to_usize(row.get(10)?),
                    files_modified: to_usize(row.get(11)?),
                    files_unchanged: to_usize(row.get(12)?),
                    files_deleted: to_usize(row.get(13)?),
                    symbols_added: to_usize(row.get(14)?),
                    symbols_updated: to_usize(row.get(15)?),
                    symbols_removed: to_usize(row.get(16)?),
                    parse_errors: to_usize(row.get(17)?),
                    skipped_files: to_usize(row.get(18)?),
                },
            })
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    fn imports_with_clause(
        &self,
        clause: &str,
        file_id: &str,
        limit: i64,
    ) -> Result<Vec<ImportReferenceRecord>, QueryServiceError> {
        let sql = format!(
            "SELECT id, project_id, source_file_id, raw_specifier, kind, start_line, start_column, end_line, end_column, resolution_state, resolved_target_file_id \
             FROM import_references WHERE {clause} ORDER BY source_file_id, start_line, start_column LIMIT ?2"
        );
        let mut statement = self.database.connection().prepare(&sql)?;
        let rows = statement.query_map(params![file_id, limit], |row| {
            let state_text: String = row.get(9)?;
            let state = ImportResolutionState::from_db(&state_text).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    format!("invalid import state {state_text}").into(),
                )
            })?;
            Ok(ImportReferenceRecord {
                id: row.get(0)?,
                project_id: row.get(1)?,
                source_file_id: row.get(2)?,
                raw_specifier: row.get(3)?,
                kind: row.get(4)?,
                start_line: to_usize(row.get(5)?),
                start_column: to_usize(row.get(6)?),
                end_line: to_usize(row.get(7)?),
                end_column: to_usize(row.get(8)?),
                resolution_state: state,
                resolved_target_file_id: row.get(10)?,
            })
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }
}

fn map_file(row: &rusqlite::Row<'_>) -> Result<SourceFileRecord, rusqlite::Error> {
    Ok(SourceFileRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        relative_path: row.get(2)?,
        relative_path_identity: row.get(3)?,
        language: row.get(4)?,
        content_hash: row.get(5)?,
        byte_size: to_u64(row.get(6)?),
        ast_root_kind: row.get(7)?,
        parse_state: row.get(8)?,
        is_active: row.get::<_, i64>(9)? != 0,
    })
}

fn map_symbol(row: &rusqlite::Row<'_>) -> Result<SymbolRecord, rusqlite::Error> {
    Ok(SymbolRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        file_id: row.get(2)?,
        kind: row.get(3)?,
        name: row.get(4)?,
        qualified_name: row.get(5)?,
        parent_symbol_id: row.get(6)?,
        fingerprint: row.get(7)?,
        start_line: to_usize(row.get(8)?),
        start_column: to_usize(row.get(9)?),
        end_line: to_usize(row.get(10)?),
        end_column: to_usize(row.get(11)?),
    })
}

fn map_graph_edge(row: &rusqlite::Row<'_>) -> Result<GraphEdgeRecord, rusqlite::Error> {
    Ok(GraphEdgeRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        source_node_id: row.get(2)?,
        target_node_id: row.get(3)?,
        relationship: row.get(4)?,
        metadata_json: row.get(5)?,
    })
}

fn get_graph_node(
    connection: &Connection,
    node_id: &str,
) -> Result<Option<GraphNodeRecord>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT id, project_id, node_type, external_key, label, metadata_json \
             FROM graph_nodes WHERE id = ?1 AND is_active = 1",
            [node_id],
            |row| {
                Ok(GraphNodeRecord {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    node_type: row.get(2)?,
                    external_key: row.get(3)?,
                    label: row.get(4)?,
                    metadata_json: row.get(5)?,
                })
            },
        )
        .optional()
}

fn bounded_limit(requested: usize, maximum: usize) -> i64 {
    i64::try_from(requested.clamp(1, maximum)).unwrap_or(maximum as i64)
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{Database, ProjectIndexService, SymbolSearchMode, SymbolSearchQuery};

    use super::ProjectQueryService;

    #[test]
    fn bounded_queries_return_real_persisted_index_data() {
        let repository = tempdir().expect("repository");
        fs::write(
            repository.path().join("alpha.ts"),
            "export function alpha() { return 1; }\nexport const beta = () => 2;",
        )
        .expect("fixture");
        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(repository.path())
            .expect("index");
        let queries = ProjectQueryService::new(&database);

        let files = queries
            .list_files(&summary.project_id, Some("alpha"), 20)
            .expect("files");
        assert_eq!(files.len(), 1);
        let symbols = queries
            .list_file_symbols(&files[0].id, 20)
            .expect("symbols");
        assert!(symbols.iter().any(|symbol| symbol.name == "alpha"));

        let search = queries
            .search_symbols(
                &summary.project_id,
                &SymbolSearchQuery {
                    query: "alp".to_string(),
                    mode: SymbolSearchMode::Prefix,
                    kind: None,
                    language: Some("TypeScript".to_string()),
                    file: None,
                    qualified_only: false,
                    limit: 10_000,
                },
            )
            .expect("search");
        assert!(search.iter().any(|symbol| symbol.name == "alpha"));
        assert!(search.len() <= 500);

        let graph = queries.graph_summary(&summary.project_id).expect("graph");
        assert_eq!(graph.node_count, summary.graph_node_count);
        assert_eq!(graph.edge_count, summary.graph_edge_count);
        let history = queries
            .index_history(&summary.project_id, 10)
            .expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, summary.run_id);
    }
}
