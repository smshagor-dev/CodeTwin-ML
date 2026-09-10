use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use source_indexer::{IndexResult, IndexedFile, IndexedSymbol, ParseState};
use thiserror::Error;

use crate::{
    deterministic_id, file_id, graph_edge_id, graph_node_id, is_windows_path_identity,
    normalize_path_identity, normalize_relative_path, project_id, symbol_fingerprint, AnalysisStatus,
    Database, GraphSummary, IndexDelta, IndexSummary, ProjectRecord,
};

const INDEXER_VERSION: &str = "source-indexer/0.1.0";
const QUERY_VERSION: &str = "definitions-v1";
const DEFAULT_CONFIG_JSON: &str = "{}";

#[derive(Debug, Error)]
pub enum IndexServiceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("source index error: {0}")]
    Index(#[from] source_indexer::IndexError),
    #[error("unsafe relative path: {0}")]
    UnsafeRelativePath(String),
}

pub struct ProjectIndexService<'a> {
    database: &'a Database,
}

impl<'a> ProjectIndexService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn open_project(&self, root: impl AsRef<Path>) -> Result<ProjectRecord, IndexServiceError> {
        open_project(self.database.connection(), root.as_ref())
    }

    pub fn index_project(&self, root: impl AsRef<Path>) -> Result<IndexSummary, IndexServiceError> {
        let started = Instant::now();
        let project = self.open_project(root.as_ref())?;
        let root = PathBuf::from(&project.root_path);
        let config_fingerprint = deterministic_id("config", &[DEFAULT_CONFIG_JSON]);
        let analysis_fingerprint = deterministic_id(
            "index-analysis",
            &[INDEXER_VERSION, QUERY_VERSION, &config_fingerprint],
        );
        let known_hashes = load_known_hashes(
            self.database.connection(),
            &project.id,
            &analysis_fingerprint,
        )?;
        let run_id = new_run_id(&project.id);

        self.database.connection().execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint)\
             VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'source_index', ?5, ?6)",
            params![
                run_id,
                project.id,
                INDEXER_VERSION,
                DEFAULT_CONFIG_JSON,
                QUERY_VERSION,
                config_fingerprint
            ],
        )?;

        let result = match source_indexer::index_project(&root, &known_hashes) {
            Ok(result) => result,
            Err(error) => {
                mark_run_failed(self.database.connection(), &run_id, started.elapsed().as_millis())?;
                return Err(error.into());
            }
        };

        let persistence = persist_index_result(
            self.database.connection(),
            &project,
            &run_id,
            &analysis_fingerprint,
            &result,
            started,
        );
        if let Err(error) = persistence {
            let _ = mark_run_failed(
                self.database.connection(),
                &run_id,
                started.elapsed().as_millis(),
            );
            return Err(error);
        }
        persistence
    }
}

fn open_project(connection: &Connection, root: &Path) -> Result<ProjectRecord, IndexServiceError> {
    let canonical = fs::canonicalize(root)?;
    let root_path = canonical.to_string_lossy().into_owned();
    let path_identity = normalize_path_identity(&canonical);
    let display_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("Project")
        .to_string();
    let git_remote = read_origin_remote(&canonical);

    let existing_id: Option<String> = connection
        .query_row(
            "SELECT id FROM projects\
             WHERE path_identity = ?1 OR root_path = ?2\
             ORDER BY CASE WHEN path_identity = ?1 THEN 0 ELSE 1 END\
             LIMIT 1",
            params![path_identity, root_path],
            |row| row.get(0),
        )
        .optional()?;
    let id = existing_id.unwrap_or_else(|| project_id(&path_identity));

    connection.execute(
        "INSERT INTO projects(id, root_path, display_name, path_identity, git_remote, last_opened_at)\
         VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)\
         ON CONFLICT(id) DO UPDATE SET\
           root_path = excluded.root_path,\
           display_name = excluded.display_name,\
           path_identity = excluded.path_identity,\
           git_remote = excluded.git_remote,\
           last_opened_at = CURRENT_TIMESTAMP,\
           updated_at = CURRENT_TIMESTAMP",
        params![id, root_path, display_name, path_identity, git_remote],
    )?;

    connection.query_row(
        "SELECT id, display_name, root_path, path_identity, git_remote, last_opened_at, last_indexed_at\
         FROM projects WHERE id = ?1",
        [&id],
        |row| {
            Ok(ProjectRecord {
                id: row.get(0)?,
                display_name: row.get(1)?,
                root_path: row.get(2)?,
                path_identity: row.get(3)?,
                git_remote: row.get(4)?,
                last_opened_at: row.get(5)?,
                last_indexed_at: row.get(6)?,
            })
        },
    ).map_err(Into::into)
}

fn load_known_hashes(
    connection: &Connection,
    project_id: &str,
    analysis_fingerprint: &str,
) -> Result<BTreeMap<String, String>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT relative_path, content_hash FROM files\
         WHERE project_id = ?1 AND is_active = 1 AND analysis_fingerprint = ?2",
    )?;
    let rows = statement.query_map(params![project_id, analysis_fingerprint], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut hashes = BTreeMap::new();
    for row in rows {
        let (path, hash) = row?;
        hashes.insert(path, hash);
    }
    Ok(hashes)
}

fn persist_index_result(
    connection: &Connection,
    project: &ProjectRecord,
    run_id: &str,
    analysis_fingerprint: &str,
    result: &IndexResult,
    started: Instant,
) -> Result<IndexSummary, IndexServiceError> {
    let transaction = connection.unchecked_transaction()?;
    let case_insensitive = is_windows_path_identity(&project.path_identity);
    let mut delta = IndexDelta {
        files_scanned: result.indexed_files.len()
            + result.unchanged_files.len()
            + result.skipped_files.len(),
        files_unchanged: result.unchanged_files.len(),
        parse_errors: result.parse_error_count(),
        skipped_files: result.skipped_files.len(),
        ..IndexDelta::default()
    };

    let existing_files = load_active_files(&transaction, &project.id)?;
    let mut touched_identities = BTreeSet::new();

    for indexed in &result.indexed_files {
        let relative_identity = normalize_relative_path(&indexed.relative_path, case_insensitive)
            .ok_or_else(|| IndexServiceError::UnsafeRelativePath(indexed.relative_path.clone()))?;
        touched_identities.insert(relative_identity.clone());
        let existing = existing_files.get(&relative_identity);
        let stable_file_id = existing
            .map(|record| record.id.clone())
            .unwrap_or_else(|| file_id(&project.id, &relative_identity));
        if existing.is_some() {
            delta.files_modified += 1;
        } else {
            delta.files_added += 1;
        }
        persist_file_and_symbols(
            &transaction,
            project,
            run_id,
            analysis_fingerprint,
            &stable_file_id,
            &relative_identity,
            indexed,
            &mut delta,
        )?;
    }

    for unchanged in &result.unchanged_files {
        let identity = normalize_relative_path(unchanged, case_insensitive)
            .ok_or_else(|| IndexServiceError::UnsafeRelativePath(unchanged.clone()))?;
        touched_identities.insert(identity);
    }
    for skipped in &result.skipped_files {
        if let Some(identity) = normalize_relative_path(&skipped.relative_path, case_insensitive) {
            touched_identities.insert(identity);
        }
    }

    for (identity, record) in &existing_files {
        if touched_identities.contains(identity) {
            continue;
        }
        match regular_file_state(Path::new(&project.root_path), &record.relative_path)? {
            Some(false) => deactivate_file(&transaction, &record.id, run_id, &mut delta)?,
            Some(true) | None => {}
        }
    }

    materialize_foundation_graph(&transaction, &project.id, run_id)?;
    let graph = graph_summary(&transaction, &project.id)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    transaction.execute(
        "UPDATE projects SET last_indexed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
        [&project.id],
    )?;
    transaction.execute(
        "UPDATE analysis_runs SET\
           status = 'completed', finished_at = CURRENT_TIMESTAMP,\
           files_scanned = ?2, files_added = ?3, files_modified = ?4, files_unchanged = ?5, files_deleted = ?6,\
           symbols_added = ?7, symbols_updated = ?8, symbols_removed = ?9, parse_errors = ?10, skipped_files = ?11, duration_ms = ?12\
         WHERE id = ?1",
        params![
            run_id,
            to_i64(delta.files_scanned),
            to_i64(delta.files_added),
            to_i64(delta.files_modified),
            to_i64(delta.files_unchanged),
            to_i64(delta.files_deleted),
            to_i64(delta.symbols_added),
            to_i64(delta.symbols_updated),
            to_i64(delta.symbols_removed),
            to_i64(delta.parse_errors),
            to_i64(delta.skipped_files),
            i64::try_from(duration_ms).unwrap_or(i64::MAX),
        ],
    )?;
    transaction.commit()?;

    Ok(IndexSummary {
        project_id: project.id.clone(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        delta,
        graph_node_count: graph.node_count,
        graph_edge_count: graph.edge_count,
        duration_ms,
    })
}

#[derive(Debug, Clone)]
struct ExistingFile {
    id: String,
    relative_path: String,
}

fn load_active_files(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, ExistingFile>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT id, relative_path, COALESCE(relative_path_identity, relative_path)\
         FROM files WHERE project_id = ?1 AND is_active = 1",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(2)?,
            ExistingFile {
                id: row.get(0)?,
                relative_path: row.get(1)?,
            },
        ))
    })?;
    let mut files = BTreeMap::new();
    for row in rows {
        let (identity, record) = row?;
        files.insert(identity, record);
    }
    Ok(files)
}

fn persist_file_and_symbols(
    connection: &Connection,
    project: &ProjectRecord,
    run_id: &str,
    analysis_fingerprint: &str,
    stable_file_id: &str,
    relative_identity: &str,
    indexed: &IndexedFile,
    delta: &mut IndexDelta,
) -> Result<(), IndexServiceError> {
    connection.execute(
        "INSERT INTO files(\
           id, project_id, relative_path, relative_path_identity, language, content_hash, byte_size, indexed_at,\
           ast_root_kind, parse_state, analysis_fingerprint, last_index_run_id, is_active\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, ?8, ?9, ?10, ?11, 1)\
         ON CONFLICT(project_id, relative_path) DO UPDATE SET\
           relative_path_identity = excluded.relative_path_identity, language = excluded.language,\
           content_hash = excluded.content_hash, byte_size = excluded.byte_size, indexed_at = CURRENT_TIMESTAMP,\
           ast_root_kind = excluded.ast_root_kind, parse_state = excluded.parse_state,\
           analysis_fingerprint = excluded.analysis_fingerprint, last_index_run_id = excluded.last_index_run_id,\
           updated_at = CURRENT_TIMESTAMP, is_active = 1",
        params![
            stable_file_id,
            project.id,
            indexed.relative_path,
            relative_identity,
            indexed.language,
            indexed.content_hash,
            i64::try_from(indexed.byte_size).unwrap_or(i64::MAX),
            indexed.ast_root_kind,
            parse_state_text(indexed.parse_state),
            analysis_fingerprint,
            run_id,
        ],
    )?;

    let previous = load_active_symbols(connection, stable_file_id)?;
    connection.execute(
        "UPDATE symbols SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE file_id = ?1 AND is_active = 1",
        [stable_file_id],
    )?;

    let mut current_fingerprints = BTreeSet::new();
    let mut occurrence = BTreeMap::<(String, String), usize>::new();
    for symbol in &indexed.symbols {
        let key = (symbol.kind.clone(), symbol.name.clone());
        let ordinal = occurrence.entry(key).or_default();
        let base = symbol_fingerprint(
            &project.id,
            stable_file_id,
            &symbol.kind,
            &symbol.name,
            None,
        );
        let fingerprint = if *ordinal == 0 {
            base
        } else {
            deterministic_id("symbol-overload", &[&base, &ordinal.to_string()])
        };
        *ordinal += 1;
        current_fingerprints.insert(fingerprint.clone());

        match previous.get(&fingerprint) {
            Some(previous_symbol) => {
                if previous_symbol.range != symbol_range(symbol) {
                    delta.symbols_updated += 1;
                }
            }
            None => delta.symbols_added += 1,
        }

        connection.execute(
            "INSERT INTO symbols(\
               id, file_id, project_id, kind, name, qualified_name, start_line, start_column, end_line, end_column,\
               fingerprint, last_index_run_id, is_active\
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9, ?1, ?10, 1)\
             ON CONFLICT(id) DO UPDATE SET\
               file_id = excluded.file_id, project_id = excluded.project_id, kind = excluded.kind, name = excluded.name,\
               start_line = excluded.start_line, start_column = excluded.start_column, end_line = excluded.end_line,\
               end_column = excluded.end_column, last_index_run_id = excluded.last_index_run_id,\
               updated_at = CURRENT_TIMESTAMP, is_active = 1",
            params![
                fingerprint,
                stable_file_id,
                project.id,
                symbol.kind,
                symbol.name,
                to_i64(symbol.start_line),
                to_i64(symbol.start_column),
                to_i64(symbol.end_line),
                to_i64(symbol.end_column),
                run_id,
            ],
        )?;
    }

    delta.symbols_removed += previous
        .keys()
        .filter(|fingerprint| !current_fingerprints.contains(*fingerprint))
        .count();
    Ok(())
}

#[derive(Debug)]
struct ExistingSymbol {
    range: (usize, usize, usize, usize),
}

fn load_active_symbols(
    connection: &Connection,
    file_id: &str,
) -> Result<BTreeMap<String, ExistingSymbol>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, start_line, start_column, end_line, end_column\
         FROM symbols WHERE file_id = ?1 AND is_active = 1 AND fingerprint IS NOT NULL",
    )?;
    let rows = statement.query_map([file_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExistingSymbol {
                range: (
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)? as usize,
                    row.get::<_, i64>(3)? as usize,
                    row.get::<_, i64>(4)? as usize,
                ),
            },
        ))
    })?;
    let mut symbols = BTreeMap::new();
    for row in rows {
        let (fingerprint, symbol) = row?;
        symbols.insert(fingerprint, symbol);
    }
    Ok(symbols)
}

fn deactivate_file(
    connection: &Connection,
    file_id: &str,
    run_id: &str,
    delta: &mut IndexDelta,
) -> Result<(), rusqlite::Error> {
    let removed_symbols: i64 = connection.query_row(
        "SELECT COUNT(*) FROM symbols WHERE file_id = ?1 AND is_active = 1",
        [file_id],
        |row| row.get(0),
    )?;
    connection.execute(
        "UPDATE symbols SET is_active = 0, last_index_run_id = ?2, updated_at = CURRENT_TIMESTAMP\
         WHERE file_id = ?1 AND is_active = 1",
        params![file_id, run_id],
    )?;
    connection.execute(
        "UPDATE files SET is_active = 0, last_index_run_id = ?2, updated_at = CURRENT_TIMESTAMP\
         WHERE id = ?1 AND is_active = 1",
        params![file_id, run_id],
    )?;
    delta.files_deleted += 1;
    delta.symbols_removed += usize::try_from(removed_symbols).unwrap_or(usize::MAX);
    Ok(())
}

fn materialize_foundation_graph(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE graph_edges SET is_active = 0, updated_at = CURRENT_TIMESTAMP\
         WHERE project_id = ?1 AND relationship IN ('PROJECT_CONTAINS_FILE','FILE_DEFINES_SYMBOL','SYMBOL_PARENT_OF_SYMBOL','FILE_IMPORTS_FILE')",
        [project_id],
    )?;
    connection.execute(
        "UPDATE graph_nodes SET is_active = 0, updated_at = CURRENT_TIMESTAMP\
         WHERE project_id = ?1 AND node_type IN ('FILE','SYMBOL')",
        [project_id],
    )?;

    let project_node_id = graph_node_id(project_id, "PROJECT", project_id);
    upsert_graph_node(
        connection,
        &project_node_id,
        project_id,
        "PROJECT",
        project_id,
        project_id,
        &json!({"project_id": project_id}).to_string(),
        run_id,
    )?;

    let mut files = connection.prepare(
        "SELECT id, relative_path, language FROM files WHERE project_id = ?1 AND is_active = 1 ORDER BY relative_path",
    )?;
    let file_rows = files.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in file_rows {
        let (stable_file_id, relative_path, language) = row?;
        let file_node_id = graph_node_id(project_id, "FILE", &stable_file_id);
        upsert_graph_node(
            connection,
            &file_node_id,
            project_id,
            "FILE",
            &stable_file_id,
            &relative_path,
            &json!({"file_id": stable_file_id, "relative_path": relative_path, "language": language}).to_string(),
            run_id,
        )?;
        upsert_graph_edge(
            connection,
            project_id,
            &project_node_id,
            &file_node_id,
            "PROJECT_CONTAINS_FILE",
            run_id,
        )?;

        let mut symbols = connection.prepare(
            "SELECT id, name, kind FROM symbols WHERE file_id = ?1 AND is_active = 1 ORDER BY start_line, start_column, name",
        )?;
        let symbol_rows = symbols.query_map([&stable_file_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for symbol_row in symbol_rows {
            let (symbol_id, name, kind) = symbol_row?;
            let symbol_node_id = graph_node_id(project_id, "SYMBOL", &symbol_id);
            upsert_graph_node(
                connection,
                &symbol_node_id,
                project_id,
                "SYMBOL",
                &symbol_id,
                &name,
                &json!({"symbol_id": symbol_id, "file_id": stable_file_id, "kind": kind}).to_string(),
                run_id,
            )?;
            upsert_graph_edge(
                connection,
                project_id,
                &file_node_id,
                &symbol_node_id,
                "FILE_DEFINES_SYMBOL",
                run_id,
            )?;
        }
    }
    Ok(())
}

fn upsert_graph_node(
    connection: &Connection,
    id: &str,
    project_id: &str,
    node_type: &str,
    external_key: &str,
    label: &str,
    metadata_json: &str,
    run_id: &str,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO graph_nodes(id, project_id, node_type, external_key, label, metadata_json, last_index_run_id, is_active)\
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)\
         ON CONFLICT(project_id, node_type, external_key) DO UPDATE SET\
           label = excluded.label, metadata_json = excluded.metadata_json, last_index_run_id = excluded.last_index_run_id,\
           updated_at = CURRENT_TIMESTAMP, is_active = 1",
        params![id, project_id, node_type, external_key, label, metadata_json, run_id],
    )?;
    Ok(())
}

fn upsert_graph_edge(
    connection: &Connection,
    project_id: &str,
    source_node_id: &str,
    target_node_id: &str,
    relationship: &str,
    run_id: &str,
) -> Result<(), rusqlite::Error> {
    let id = graph_edge_id(project_id, source_node_id, target_node_id, relationship);
    connection.execute(
        "INSERT INTO graph_edges(id, project_id, source_node_id, target_node_id, relationship, metadata_json, last_index_run_id, is_active)\
         VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, 1)\
         ON CONFLICT(project_id, source_node_id, target_node_id, relationship) DO UPDATE SET\
           last_index_run_id = excluded.last_index_run_id, updated_at = CURRENT_TIMESTAMP, is_active = 1",
        params![id, project_id, source_node_id, target_node_id, relationship, run_id],
    )?;
    Ok(())
}

fn graph_summary(connection: &Connection, project_id: &str) -> Result<GraphSummary, rusqlite::Error> {
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
        node_count: usize::try_from(node_count).unwrap_or(usize::MAX),
        edge_count: usize::try_from(edge_count).unwrap_or(usize::MAX),
    })
}

fn regular_file_state(root: &Path, relative_path: &str) -> Result<Option<bool>, IndexServiceError> {
    let normalized = normalize_relative_path(relative_path, false)
        .ok_or_else(|| IndexServiceError::UnsafeRelativePath(relative_path.to_string()))?;
    let mut candidate = root.to_path_buf();
    for segment in normalized.split('/') {
        candidate.push(segment);
    }
    match fs::symlink_metadata(candidate) {
        Ok(metadata) => Ok(Some(metadata.file_type().is_file())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(false)),
        Err(_) => Ok(None),
    }
}

fn read_origin_remote(root: &Path) -> Option<String> {
    let git_dir = root.join(".git");
    let git_metadata = fs::symlink_metadata(&git_dir).ok()?;
    if !git_metadata.file_type().is_dir() {
        return None;
    }
    let config_path = git_dir.join("config");
    let config_metadata = fs::symlink_metadata(&config_path).ok()?;
    if !config_metadata.file_type().is_file() {
        return None;
    }
    let config = fs::read_to_string(config_path).ok()?;
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_origin = line.eq_ignore_ascii_case("[remote \"origin\"]");
            continue;
        }
        if in_origin {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim().eq_ignore_ascii_case("url") {
                    let value = value.trim();
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }
    None
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();
    deterministic_id("run", &[project_id, &nanos])
}

fn mark_run_failed(
    connection: &Connection,
    run_id: &str,
    elapsed_ms: u128,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET status = 'failed', finished_at = CURRENT_TIMESTAMP, duration_ms = ?2 WHERE id = ?1",
        params![run_id, i64::try_from(elapsed_ms).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn parse_state_text(state: ParseState) -> &'static str {
    match state {
        ParseState::Parsed => "parsed",
        ParseState::ParsedWithErrors => "parsed_with_errors",
    }
}

fn symbol_range(symbol: &IndexedSymbol) -> (usize, usize, usize, usize) {
    (
        symbol.start_line,
        symbol.start_column,
        symbol.end_line,
        symbol.end_column,
    )
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::Database;

    use super::ProjectIndexService;

    #[test]
    fn reopening_project_reuses_stable_identity() {
        let repository = tempdir().expect("repository");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);

        let first = service.open_project(repository.path()).expect("first open");
        let second = service.open_project(repository.path()).expect("second open");
        assert_eq!(first.id, second.id);
        assert_eq!(first.path_identity, second.path_identity);

        let count: i64 = database
            .connection()
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
            .expect("project count");
        assert_eq!(count, 1);
    }

    #[test]
    fn indexes_incrementally_and_cleans_deleted_files() {
        let repository = tempdir().expect("repository");
        fs::write(
            repository.path().join("main.ts"),
            "export function value() { return 1; }",
        )
        .expect("source");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);

        let first = service.index_project(repository.path()).expect("first index");
        assert_eq!(first.delta.files_added, 1);
        assert!(first.delta.symbols_added >= 1);
        assert!(first.graph_node_count >= 3);
        assert!(first.graph_edge_count >= 2);

        let second = service.index_project(repository.path()).expect("second index");
        assert_eq!(second.delta.files_unchanged, 1);
        assert_eq!(second.delta.files_added, 0);
        assert_eq!(second.delta.files_deleted, 0);

        fs::write(
            repository.path().join("main.ts"),
            "export function renamed() { return 2; }",
        )
        .expect("modify source");
        let third = service.index_project(repository.path()).expect("changed index");
        assert_eq!(third.delta.files_modified, 1);
        assert!(third.delta.symbols_added >= 1);
        assert!(third.delta.symbols_removed >= 1);

        fs::remove_file(repository.path().join("main.ts")).expect("delete source");
        let fourth = service.index_project(repository.path()).expect("deleted index");
        assert_eq!(fourth.delta.files_deleted, 1);
        assert!(fourth.delta.symbols_removed >= 1);

        let active_files: i64 = database
            .connection()
            .query_row("SELECT COUNT(*) FROM files WHERE is_active = 1", [], |row| row.get(0))
            .expect("active files");
        let active_symbols: i64 = database
            .connection()
            .query_row("SELECT COUNT(*) FROM symbols WHERE is_active = 1", [], |row| row.get(0))
            .expect("active symbols");
        assert_eq!(active_files, 0);
        assert_eq!(active_symbols, 0);
    }

    #[test]
    fn records_git_origin_without_running_git() {
        let repository = tempdir().expect("repository");
        fs::create_dir(repository.path().join(".git")).expect("git dir");
        fs::write(
            repository.path().join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.test/repository.git\n",
        )
        .expect("git config");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);
        let project = service.open_project(repository.path()).expect("open project");
        assert_eq!(
            project.git_remote.as_deref(),
            Some("https://example.test/repository.git")
        );
    }
}
