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
    normalize_path_identity, normalize_relative_path, project_id, resolve_import,
    symbol_fingerprint, AnalysisStatus, Database, GraphSummary, ImportResolutionState, IndexDelta,
    IndexSummary, ProjectRecord,
};

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
            &[
                source_indexer::INDEXER_VERSION,
                source_indexer::QUERY_VERSION,
                &config_fingerprint,
            ],
        );
        let known_hashes = load_known_hashes(
            self.database.connection(),
            &project.id,
            &analysis_fingerprint,
        )?;
        let run_id = new_run_id(&project.id);

        self.database.connection().execute(
            "INSERT INTO analysis_runs(\
               id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint\
             ) VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'source_index', ?5, ?6)",
            params![
                run_id,
                project.id,
                source_indexer::INDEXER_VERSION,
                DEFAULT_CONFIG_JSON,
                source_indexer::QUERY_VERSION,
                config_fingerprint,
            ],
        )?;

        let result = match source_indexer::index_project(&root, &known_hashes) {
            Ok(result) => result,
            Err(error) => {
                let _ = mark_run_failed(
                    self.database.connection(),
                    &run_id,
                    started.elapsed().as_millis(),
                );
                return Err(error.into());
            }
        };

        match persist_index_result(
            self.database.connection(),
            &project,
            &run_id,
            &analysis_fingerprint,
            &result,
            started,
        ) {
            Ok(summary) => Ok(summary),
            Err(error) => {
                let _ = mark_run_failed(
                    self.database.connection(),
                    &run_id,
                    started.elapsed().as_millis(),
                );
                Err(error)
            }
        }
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
             ORDER BY CASE WHEN path_identity = ?1 THEN 0 ELSE 1 END LIMIT 1",
            params![path_identity, root_path],
            |row| row.get(0),
        )
        .optional()?;
    let id = existing_id.unwrap_or_else(|| project_id(&path_identity));

    connection.execute(
        "INSERT INTO projects(id, root_path, display_name, path_identity, git_remote, last_opened_at)\
         VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)\
         ON CONFLICT(id) DO UPDATE SET\
           root_path = excluded.root_path, display_name = excluded.display_name,\
           path_identity = excluded.path_identity, git_remote = excluded.git_remote,\
           last_opened_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
        params![id, root_path, display_name, path_identity, git_remote],
    )?;

    connection
        .query_row(
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
        )
        .map_err(Into::into)
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
    let existing_files = load_active_files(&transaction, &project.id, case_insensitive)?;
    let mut touched = BTreeSet::new();

    for indexed in &result.indexed_files {
        let identity = normalize_relative_path(&indexed.relative_path, case_insensitive)
            .ok_or_else(|| IndexServiceError::UnsafeRelativePath(indexed.relative_path.clone()))?;
        touched.insert(identity.clone());
        let existing = existing_files.get(&identity);
        let stable_file_id = existing
            .map(|file| file.id.clone())
            .unwrap_or_else(|| file_id(&project.id, &identity));
        match existing {
            None => delta.files_added += 1,
            Some(file) if file.content_hash == indexed.content_hash => delta.files_unchanged += 1,
            Some(_) => delta.files_modified += 1,
        }
        persist_file(
            &transaction,
            project,
            run_id,
            analysis_fingerprint,
            &stable_file_id,
            &identity,
            indexed,
        )?;
        persist_symbols(
            &transaction,
            &project.id,
            &stable_file_id,
            run_id,
            &indexed.symbols,
            &mut delta,
        )?;
        persist_routes(
            &transaction,
            &project.id,
            &stable_file_id,
            run_id,
            indexed,
        )?;
        persist_route_mounts(
            &transaction,
            &project.id,
            &stable_file_id,
            run_id,
            indexed,
        )?;
        persist_imports(
            &transaction,
            &project.id,
            &stable_file_id,
            run_id,
            indexed,
        )?;
    }

    for unchanged in &result.unchanged_files {
        let identity = normalize_relative_path(unchanged, case_insensitive)
            .ok_or_else(|| IndexServiceError::UnsafeRelativePath(unchanged.clone()))?;
        touched.insert(identity);
    }
    for skipped in &result.skipped_files {
        if let Some(identity) = normalize_relative_path(&skipped.relative_path, case_insensitive) {
            touched.insert(identity);
        }
    }

    for (identity, file) in &existing_files {
        if touched.contains(identity) {
            continue;
        }
        match regular_file_state(Path::new(&project.root_path), &file.relative_path)? {
            Some(false) => deactivate_file(&transaction, &file.id, run_id, &mut delta)?,
            Some(true) | None => {}
        }
    }

    resolve_all_imports(&transaction, project, case_insensitive)?;
    materialize_graph(&transaction, &project.id, run_id)?;
    let graph = graph_summary(&transaction, &project.id)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    transaction.execute(
        "UPDATE projects SET last_indexed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
        [&project.id],
    )?;
    finish_run(&transaction, run_id, &delta, duration_ms)?;
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
    content_hash: String,
}

fn load_active_files(
    connection: &Connection,
    project_id: &str,
    case_insensitive: bool,
) -> Result<BTreeMap<String, ExistingFile>, IndexServiceError> {
    let mut statement = connection.prepare(
        "SELECT id, relative_path, relative_path_identity, content_hash\
         FROM files WHERE project_id = ?1 AND is_active = 1",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut files = BTreeMap::new();
    for row in rows {
        let (id, relative_path, stored_identity, content_hash) = row?;
        let identity = match stored_identity {
            Some(identity) => identity,
            None => normalize_relative_path(&relative_path, case_insensitive)
                .ok_or_else(|| IndexServiceError::UnsafeRelativePath(relative_path.clone()))?,
        };
        files.insert(
            identity,
            ExistingFile {
                id,
                relative_path,
                content_hash,
            },
        );
    }
    Ok(files)
}

fn persist_file(
    connection: &Connection,
    project: &ProjectRecord,
    run_id: &str,
    analysis_fingerprint: &str,
    stable_file_id: &str,
    relative_identity: &str,
    indexed: &IndexedFile,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO files(\
           id, project_id, relative_path, relative_path_identity, language, content_hash, byte_size, indexed_at,\
           ast_root_kind, parse_state, analysis_fingerprint, last_index_run_id, created_at, updated_at, is_active\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, ?8, ?9, ?10, ?11, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)\
         ON CONFLICT(id) DO UPDATE SET\
           relative_path = excluded.relative_path, relative_path_identity = excluded.relative_path_identity,\
           language = excluded.language, content_hash = excluded.content_hash, byte_size = excluded.byte_size,\
           indexed_at = CURRENT_TIMESTAMP, ast_root_kind = excluded.ast_root_kind, parse_state = excluded.parse_state,\
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
    Ok(())
}

#[derive(Debug, Clone)]
struct PreparedSymbol<'a> {
    source: &'a IndexedSymbol,
    fingerprint: String,
    parent_id: Option<String>,
}

#[derive(Debug)]
struct ExistingSymbol {
    range: (usize, usize, usize, usize),
    signature: Option<String>,
    parent_id: Option<String>,
}

fn persist_symbols(
    connection: &Connection,
    project_id: &str,
    stable_file_id: &str,
    run_id: &str,
    symbols: &[IndexedSymbol],
    delta: &mut IndexDelta,
) -> Result<(), rusqlite::Error> {
    let previous = load_active_symbols(connection, stable_file_id)?;
    let prepared = prepare_symbols(project_id, stable_file_id, symbols);
    let current: BTreeSet<&str> = prepared
        .iter()
        .map(|symbol| symbol.fingerprint.as_str())
        .collect();

    connection.execute(
        "UPDATE symbols SET is_active = 0, updated_at = CURRENT_TIMESTAMP\
         WHERE file_id = ?1 AND is_active = 1",
        [stable_file_id],
    )?;

    for symbol in &prepared {
        let source = symbol.source;
        match previous.get(&symbol.fingerprint) {
            None => delta.symbols_added += 1,
            Some(old)
                if old.range != symbol_range(source)
                    || old.signature != source.signature
                    || old.parent_id != symbol.parent_id =>
            {
                delta.symbols_updated += 1;
            }
            Some(_) => {}
        }
        connection.execute(
            "INSERT INTO symbols(\
               id, file_id, project_id, kind, name, qualified_name, start_line, start_column, end_line, end_column, signature,\
               parent_symbol_id, fingerprint, last_index_run_id, created_at, updated_at, is_active\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?1, ?13, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)\
             ON CONFLICT(id) DO UPDATE SET\
               file_id = excluded.file_id, project_id = excluded.project_id, kind = excluded.kind, name = excluded.name,\
               qualified_name = excluded.qualified_name, start_line = excluded.start_line, start_column = excluded.start_column,\
               end_line = excluded.end_line, end_column = excluded.end_column, signature = excluded.signature,\
               parent_symbol_id = excluded.parent_symbol_id, last_index_run_id = excluded.last_index_run_id,\
               updated_at = CURRENT_TIMESTAMP, is_active = 1",
            params![
                symbol.fingerprint,
                stable_file_id,
                project_id,
                source.kind,
                source.name,
                source.qualified_name,
                to_i64(source.start_line),
                to_i64(source.start_column),
                to_i64(source.end_line),
                to_i64(source.end_column),
                source.signature,
                symbol.parent_id,
                run_id,
            ],
        )?;
    }

    delta.symbols_removed += previous
        .keys()
        .filter(|fingerprint| !current.contains(fingerprint.as_str()))
        .count();
    Ok(())
}

fn prepare_symbols<'a>(
    project_id: &str,
    stable_file_id: &str,
    symbols: &'a [IndexedSymbol],
) -> Vec<PreparedSymbol<'a>> {
    let mut base_counts = BTreeMap::<String, usize>::new();
    let mut bases = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        let semantic_name = symbol.qualified_name.as_deref().unwrap_or(&symbol.name);
        let base = symbol_fingerprint(
            project_id,
            stable_file_id,
            &symbol.kind,
            semantic_name,
            symbol.parent_scope.as_deref(),
        );
        *base_counts.entry(base.clone()).or_default() += 1;
        bases.push(base);
    }

    let mut duplicate_occurrence = BTreeMap::<String, usize>::new();
    let mut fingerprints = Vec::with_capacity(symbols.len());
    for (symbol, base) in symbols.iter().zip(&bases) {
        let fingerprint = if base_counts.get(base).copied().unwrap_or(0) <= 1 {
            base.clone()
        } else {
            let signature = symbol.signature.as_deref().unwrap_or("");
            let overload = deterministic_id("symbol-overload", &[base, signature]);
            let occurrence = duplicate_occurrence.entry(overload.clone()).or_default();
            let fingerprint = if *occurrence == 0 {
                overload
            } else {
                deterministic_id("symbol-overload-occurrence", &[&overload, &occurrence.to_string()])
            };
            *occurrence += 1;
            fingerprint
        };
        fingerprints.push(fingerprint);
    }

    let mut qualified = BTreeMap::<String, Vec<String>>::new();
    for (symbol, fingerprint) in symbols.iter().zip(&fingerprints) {
        if let Some(name) = symbol.qualified_name.as_ref() {
            qualified
                .entry(name.clone())
                .or_default()
                .push(fingerprint.clone());
        }
    }

    symbols
        .iter()
        .zip(fingerprints)
        .map(|(source, fingerprint)| {
            let parent_id = source.parent_scope.as_ref().and_then(|scope| {
                qualified
                    .get(scope)
                    .filter(|matches| matches.len() == 1)
                    .and_then(|matches| matches.first())
                    .filter(|candidate| candidate.as_str() != fingerprint)
                    .cloned()
            });
            PreparedSymbol {
                source,
                fingerprint,
                parent_id,
            }
        })
        .collect()
}

fn load_active_symbols(
    connection: &Connection,
    file_id: &str,
) -> Result<BTreeMap<String, ExistingSymbol>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, start_line, start_column, end_line, end_column, signature, parent_symbol_id\
         FROM symbols WHERE file_id = ?1 AND is_active = 1 AND fingerprint IS NOT NULL",
    )?;
    let rows = statement.query_map([file_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ExistingSymbol {
                range: (
                    to_usize(row.get(1)?),
                    to_usize(row.get(2)?),
                    to_usize(row.get(3)?),
                    to_usize(row.get(4)?),
                ),
                signature: row.get(5)?,
                parent_id: row.get(6)?,
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

fn persist_routes(
    connection: &Connection,
    project_id: &str,
    source_file_id: &str,
    run_id: &str,
    indexed: &IndexedFile,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE source_routes
         SET is_active = 0, last_index_run_id = ?2, updated_at = CURRENT_TIMESTAMP
         WHERE file_id = ?1 AND is_active = 1",
        params![source_file_id, run_id],
    )?;

    for route in &indexed.routes {
        let id = deterministic_id(
            "source-route",
            &[
                project_id,
                source_file_id,
                &route.http_method,
                &route.path_template,
                &route.start_line.to_string(),
            ],
        );
        let parameter_names: Vec<String> = route
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect();
        let parameter_locations: BTreeMap<String, String> = route
            .parameters
            .iter()
            .map(|parameter| (parameter.name.clone(), parameter.location.clone()))
            .collect();
        let parameter_names_json = serde_json::to_string(&parameter_names)
            .unwrap_or_else(|_| "[]".to_string());
        let parameter_locations_json = serde_json::to_string(&parameter_locations)
            .unwrap_or_else(|_| "{}".to_string());
        let symbol_id: Option<String> = route.handler_name.as_deref().and_then(|handler| {
            connection
                .query_row(
                    "SELECT CASE WHEN COUNT(*) = 1 THEN MIN(id) ELSE NULL END
                     FROM symbols
                     WHERE file_id = ?1 AND is_active = 1 AND name = ?2",
                    params![source_file_id, handler],
                    |row| row.get(0),
                )
                .ok()
                .flatten()
        });

        connection.execute(
            "INSERT INTO source_routes(
               id, project_id, file_id, symbol_id, framework, router_name,
               http_method, path_template, handler_name, parameter_names_json,
               parameter_locations_json, request_content_type, source_content_hash,
               start_line, end_line, last_index_run_id, is_active
             ) VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 1
             )
             ON CONFLICT(id) DO UPDATE SET
               symbol_id = excluded.symbol_id,
               framework = excluded.framework,
               router_name = excluded.router_name,
               handler_name = excluded.handler_name,
               parameter_names_json = excluded.parameter_names_json,
               parameter_locations_json = excluded.parameter_locations_json,
               request_content_type = excluded.request_content_type,
               source_content_hash = excluded.source_content_hash,
               end_line = excluded.end_line,
               last_index_run_id = excluded.last_index_run_id,
               is_active = 1,
               updated_at = CURRENT_TIMESTAMP",
            params![
                id,
                project_id,
                source_file_id,
                symbol_id,
                route.framework,
                route.router_name,
                route.http_method,
                route.path_template,
                route.handler_name,
                parameter_names_json,
                parameter_locations_json,
                route.request_content_type,
                indexed.content_hash,
                to_i64(route.start_line),
                to_i64(route.end_line),
                run_id,
            ],
        )?;
    }

    Ok(())
}

fn persist_route_mounts(
    connection: &Connection,
    project_id: &str,
    source_file_id: &str,
    run_id: &str,
    indexed: &IndexedFile,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE source_route_mounts
         SET is_active = 0, last_index_run_id = ?2, updated_at = CURRENT_TIMESTAMP
         WHERE source_file_id = ?1 AND is_active = 1",
        params![source_file_id, run_id],
    )?;

    for mount in &indexed.route_mounts {
        let id = deterministic_id(
            "source-route-mount",
            &[
                project_id,
                source_file_id,
                &mount.framework,
                &mount.parent_router,
                &mount.mounted_binding,
                &mount.prefix,
                &mount.start_line.to_string(),
            ],
        );
        connection.execute(
            "INSERT INTO source_route_mounts(
               id, project_id, source_file_id, framework, parent_router, mounted_binding,
               prefix, start_line, end_line, last_index_run_id, is_active
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)
             ON CONFLICT(id) DO UPDATE SET
               framework = excluded.framework,
               parent_router = excluded.parent_router,
               mounted_binding = excluded.mounted_binding,
               prefix = excluded.prefix,
               end_line = excluded.end_line,
               last_index_run_id = excluded.last_index_run_id,
               is_active = 1,
               updated_at = CURRENT_TIMESTAMP",
            params![
                id,
                project_id,
                source_file_id,
                mount.framework,
                mount.parent_router,
                mount.mounted_binding,
                mount.prefix,
                to_i64(mount.start_line),
                to_i64(mount.end_line),
                run_id,
            ],
        )?;
    }
    Ok(())
}

fn persist_imports(
    connection: &Connection,
    project_id: &str,
    source_file_id: &str,
    run_id: &str,
    indexed: &IndexedFile,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM import_references WHERE source_file_id = ?1",
        [source_file_id],
    )?;
    for reference in &indexed.imports {
        let id = deterministic_id(
            "import",
            &[
                project_id,
                source_file_id,
                &reference.kind,
                &reference.raw_specifier,
                &reference.start_line.to_string(),
                &reference.start_column.to_string(),
                &reference.end_line.to_string(),
                &reference.end_column.to_string(),
            ],
        );
        let bindings_json = serde_json::to_string(&reference.bindings)
            .unwrap_or_else(|_| "[]".to_string());
        connection.execute(
            "INSERT INTO import_references(\
               id, project_id, source_file_id, raw_specifier, kind, start_line, start_column, end_line, end_column,\
               resolution_state, resolved_target_file_id, last_index_run_id, bindings_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'observed', NULL, ?10, ?11)",
            params![
                id,
                project_id,
                source_file_id,
                reference.raw_specifier,
                reference.kind,
                to_i64(reference.start_line),
                to_i64(reference.start_column),
                to_i64(reference.end_line),
                to_i64(reference.end_column),
                run_id,
                bindings_json,
            ],
        )?;
    }
    Ok(())
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
        "DELETE FROM import_references WHERE source_file_id = ?1",
        [file_id],
    )?;
    connection.execute(
        "UPDATE source_routes
         SET is_active = 0, last_index_run_id = ?2, updated_at = CURRENT_TIMESTAMP
         WHERE file_id = ?1 AND is_active = 1",
        params![file_id, run_id],
    )?;
    connection.execute(
        "UPDATE source_route_mounts
         SET is_active = 0, last_index_run_id = ?2, updated_at = CURRENT_TIMESTAMP
         WHERE source_file_id = ?1 AND is_active = 1",
        params![file_id, run_id],
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
    delta.symbols_removed += to_usize(removed_symbols);
    Ok(())
}

fn resolve_all_imports(
    connection: &Connection,
    project: &ProjectRecord,
    case_insensitive: bool,
) -> Result<(), IndexServiceError> {
    let file_map = load_file_identity_map(connection, &project.id, case_insensitive)?;
    let mut statement = connection.prepare(
        "SELECT i.id, f.relative_path, COALESCE(f.language, ''), i.raw_specifier\
         FROM import_references i JOIN files f ON f.id = i.source_file_id\
         WHERE i.project_id = ?1 AND f.is_active = 1",
    )?;
    let rows = statement.query_map([&project.id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut updates = Vec::new();
    for row in rows {
        updates.push(row?);
    }
    drop(statement);

    for (id, source_path, language, raw_specifier) in updates {
        let resolved = resolve_import(
            &source_path,
            &language,
            &raw_specifier,
            &file_map,
            case_insensitive,
        );
        connection.execute(
            "UPDATE import_references SET resolution_state = ?2, resolved_target_file_id = ?3, updated_at = CURRENT_TIMESTAMP\
             WHERE id = ?1",
            params![id, resolved.state.as_str(), resolved.target_file_id],
        )?;
    }
    Ok(())
}

fn load_file_identity_map(
    connection: &Connection,
    project_id: &str,
    case_insensitive: bool,
) -> Result<BTreeMap<String, String>, IndexServiceError> {
    let mut statement = connection.prepare(
        "SELECT id, relative_path, relative_path_identity FROM files\
         WHERE project_id = ?1 AND is_active = 1",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut files = BTreeMap::new();
    for row in rows {
        let (id, path, identity) = row?;
        let identity = match identity {
            Some(identity) => identity,
            None => normalize_relative_path(&path, case_insensitive)
                .ok_or_else(|| IndexServiceError::UnsafeRelativePath(path.clone()))?,
        };
        files.insert(identity, id);
    }
    Ok(files)
}

fn materialize_graph(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE graph_edges SET is_active = 0, updated_at = CURRENT_TIMESTAMP\
         WHERE project_id = ?1 AND relationship IN (\
           'PROJECT_CONTAINS_FILE','FILE_DEFINES_SYMBOL','SYMBOL_PARENT_OF_SYMBOL','FILE_IMPORTS_FILE'\
         )",
        [project_id],
    )?;
    connection.execute(
        "UPDATE graph_nodes SET is_active = 0, updated_at = CURRENT_TIMESTAMP\
         WHERE project_id = ?1 AND node_type IN ('FILE','SYMBOL')",
        [project_id],
    )?;

    let project_node = graph_node_id(project_id, "PROJECT", project_id);
    upsert_graph_node(
        connection,
        &project_node,
        project_id,
        "PROJECT",
        project_id,
        project_id,
        &json!({"project_id": project_id}).to_string(),
        run_id,
    )?;

    let mut file_statement = connection.prepare(
        "SELECT id, relative_path, language FROM files\
         WHERE project_id = ?1 AND is_active = 1 ORDER BY relative_path",
    )?;
    let rows = file_statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut files = Vec::new();
    for row in rows {
        files.push(row?);
    }
    drop(file_statement);

    for (stable_file_id, relative_path, language) in files {
        let file_node = graph_node_id(project_id, "FILE", &stable_file_id);
        upsert_graph_node(
            connection,
            &file_node,
            project_id,
            "FILE",
            &stable_file_id,
            &relative_path,
            &json!({
                "file_id": stable_file_id,
                "relative_path": relative_path,
                "language": language,
            })
            .to_string(),
            run_id,
        )?;
        upsert_graph_edge(
            connection,
            project_id,
            &project_node,
            &file_node,
            "PROJECT_CONTAINS_FILE",
            run_id,
        )?;
    }

    let mut symbol_statement = connection.prepare(
        "SELECT id, file_id, name, kind, parent_symbol_id FROM symbols\
         WHERE project_id = ?1 AND is_active = 1 ORDER BY file_id, start_line, start_column, name",
    )?;
    let rows = symbol_statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut symbols = Vec::new();
    for row in rows {
        symbols.push(row?);
    }
    drop(symbol_statement);

    let active_symbol_ids: BTreeSet<String> = symbols.iter().map(|row| row.0.clone()).collect();
    for (symbol_id, stable_file_id, name, kind, parent_id) in symbols {
        let symbol_node = graph_node_id(project_id, "SYMBOL", &symbol_id);
        let file_node = graph_node_id(project_id, "FILE", &stable_file_id);
        upsert_graph_node(
            connection,
            &symbol_node,
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
            &file_node,
            &symbol_node,
            "FILE_DEFINES_SYMBOL",
            run_id,
        )?;
        if let Some(parent_id) = parent_id.filter(|id| active_symbol_ids.contains(id)) {
            let parent_node = graph_node_id(project_id, "SYMBOL", &parent_id);
            upsert_graph_edge(
                connection,
                project_id,
                &parent_node,
                &symbol_node,
                "SYMBOL_PARENT_OF_SYMBOL",
                run_id,
            )?;
        }
    }

    let mut import_statement = connection.prepare(
        "SELECT source_file_id, resolved_target_file_id FROM import_references\
         WHERE project_id = ?1 AND resolution_state = 'resolved_local' AND resolved_target_file_id IS NOT NULL",
    )?;
    let rows = import_statement.query_map([project_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut imports = Vec::new();
    for row in rows {
        imports.push(row?);
    }
    drop(import_statement);
    for (source_file, target_file) in imports {
        let source_node = graph_node_id(project_id, "FILE", &source_file);
        let target_node = graph_node_id(project_id, "FILE", &target_file);
        upsert_graph_edge(
            connection,
            project_id,
            &source_node,
            &target_node,
            "FILE_IMPORTS_FILE",
            run_id,
        )?;
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
        "INSERT INTO graph_nodes(\
           id, project_id, node_type, external_key, label, metadata_json, last_index_run_id, created_at, updated_at, is_active\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)\
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
        "INSERT INTO graph_edges(\
           id, project_id, source_node_id, target_node_id, relationship, metadata_json, last_index_run_id, created_at, updated_at, is_active\
         ) VALUES (?1, ?2, ?3, ?4, ?5, '{}', ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)\
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
        node_count: to_usize(node_count),
        edge_count: to_usize(edge_count),
    })
}

fn finish_run(
    connection: &Connection,
    run_id: &str,
    delta: &IndexDelta,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET\
           status = 'completed', finished_at = CURRENT_TIMESTAMP,\
           files_scanned = ?2, files_added = ?3, files_modified = ?4, files_unchanged = ?5, files_deleted = ?6,\
           symbols_added = ?7, symbols_updated = ?8, symbols_removed = ?9, parse_errors = ?10, skipped_files = ?11,\
           duration_ms = ?12 WHERE id = ?1",
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
    Ok(())
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
    if !fs::symlink_metadata(&git_dir).ok()?.file_type().is_dir() {
        return None;
    }
    let config_path = git_dir.join("config");
    if !fs::symlink_metadata(&config_path).ok()?.file_type().is_file() {
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

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{Database, ImportResolutionState, ProjectQueryService};

    use super::ProjectIndexService;

    #[test]
    fn reopening_project_reuses_stable_identity_without_running_git() {
        let repository = tempdir().expect("repository");
        fs::create_dir(repository.path().join(".git")).expect("git dir");
        fs::write(
            repository.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = https://example.test/repository.git\n",
        )
        .expect("git config");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);
        let first = service.open_project(repository.path()).expect("first open");
        let second = service.open_project(repository.path()).expect("second open");
        assert_eq!(first.id, second.id);
        assert_eq!(first.path_identity, second.path_identity);
        assert_eq!(first.git_remote.as_deref(), Some("https://example.test/repository.git"));
        let count: i64 = database
            .connection()
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
            .expect("project count");
        assert_eq!(count, 1);
    }

    #[test]
    fn incremental_lifecycle_materializes_and_cleans_graph() {
        let repository = tempdir().expect("repository");
        fs::write(
            repository.path().join("util.ts"),
            "export function util() { return 1; }",
        )
        .expect("util");
        fs::write(
            repository.path().join("main.ts"),
            "import { util } from './util';\nexport class Service { run() { return util(); } }",
        )
        .expect("main");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);

        let first = service.index_project(repository.path()).expect("first index");
        assert_eq!(first.delta.files_added, 2);
        assert!(first.delta.symbols_added >= 3);
        let import_edges: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE is_active = 1 AND relationship = 'FILE_IMPORTS_FILE'",
                [],
                |row| row.get(0),
            )
            .expect("import edges");
        let parent_edges: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE is_active = 1 AND relationship = 'SYMBOL_PARENT_OF_SYMBOL'",
                [],
                |row| row.get(0),
            )
            .expect("parent edges");
        assert_eq!(import_edges, 1);
        assert!(parent_edges >= 1);

        let second = service.index_project(repository.path()).expect("second index");
        assert_eq!(second.delta.files_unchanged, 2);
        assert_eq!(second.graph_node_count, first.graph_node_count);
        assert_eq!(second.graph_edge_count, first.graph_edge_count);

        fs::write(
            repository.path().join("main.ts"),
            "export class Service { execute() { return 2; } }",
        )
        .expect("modify");
        let third = service.index_project(repository.path()).expect("modified index");
        assert_eq!(third.delta.files_modified, 1);
        assert!(third.delta.symbols_added >= 1);
        assert!(third.delta.symbols_removed >= 1);
        let import_edges: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE is_active = 1 AND relationship = 'FILE_IMPORTS_FILE'",
                [],
                |row| row.get(0),
            )
            .expect("cleaned import edges");
        assert_eq!(import_edges, 0);

        fs::remove_file(repository.path().join("util.ts")).expect("delete util");
        let fourth = service.index_project(repository.path()).expect("delete index");
        assert_eq!(fourth.delta.files_deleted, 1);
        let active_util: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM files WHERE relative_path = 'util.ts' AND is_active = 1",
                [],
                |row| row.get(0),
            )
            .expect("active util");
        assert_eq!(active_util, 0);
    }

    #[test]
    fn symbol_identity_survives_line_movement() {
        let repository = tempdir().expect("repository");
        let path = repository.path().join("main.ts");
        fs::write(&path, "export function stable() { return 1; }\n").expect("source");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);
        service.index_project(repository.path()).expect("first");
        let first_id: String = database
            .connection()
            .query_row(
                "SELECT id FROM symbols WHERE name = 'stable' AND is_active = 1",
                [],
                |row| row.get(0),
            )
            .expect("first id");

        fs::write(&path, "\n\nexport function stable() { return 1; }\n").expect("move");
        service.index_project(repository.path()).expect("second");
        let second_id: String = database
            .connection()
            .query_row(
                "SELECT id FROM symbols WHERE name = 'stable' AND is_active = 1",
                [],
                |row| row.get(0),
            )
            .expect("second id");
        assert_eq!(first_id, second_id);
    }

    #[test]
    fn import_states_distinguish_local_external_unresolved_and_unsupported() {
        let repository = tempdir().expect("repository");
        fs::write(repository.path().join("local.ts"), "export const x = 1;").expect("local");
        fs::write(
            repository.path().join("main.ts"),
            "import './local'; import 'react'; import './missing';",
        )
        .expect("main");
        fs::write(repository.path().join("main.py"), "import os\n").expect("python");
        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(repository.path())
            .expect("index");
        let files = ProjectQueryService::new(&database)
            .list_files(&summary.project_id, Some("main.ts"), 10)
            .expect("files");
        let references = ProjectQueryService::new(&database)
            .dependencies(&files[0].id, 20)
            .expect("dependencies");
        assert!(references.iter().any(|reference| {
            reference.raw_specifier == "./local"
                && reference.resolution_state == ImportResolutionState::ResolvedLocal
        }));
        assert!(references.iter().any(|reference| {
            reference.raw_specifier == "react"
                && reference.resolution_state == ImportResolutionState::External
        }));
        assert!(references.iter().any(|reference| {
            reference.raw_specifier == "./missing"
                && reference.resolution_state == ImportResolutionState::Unresolved
        }));
        let unsupported: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM import_references WHERE resolution_state = 'unsupported'",
                [],
                |row| row.get(0),
            )
            .expect("unsupported");
        assert!(unsupported >= 1);
    }

    #[test]
    fn parse_errors_are_persisted_in_run_metrics() {
        let repository = tempdir().expect("repository");
        fs::write(repository.path().join("broken.ts"), "export function broken(").expect("broken");
        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(repository.path())
            .expect("index");
        assert!(summary.delta.parse_errors >= 1);
    }

    #[test]
    fn persistence_failure_rolls_back_repository_state_and_marks_run_failed() {
        let repository = tempdir().expect("repository");
        let path = repository.path().join("main.ts");
        fs::write(&path, "export function before() { return 1; }").expect("source");
        let database = Database::open_in_memory().expect("database");
        let service = ProjectIndexService::new(&database);
        service.index_project(repository.path()).expect("first");
        let old_hash: String = database
            .connection()
            .query_row("SELECT content_hash FROM files WHERE is_active = 1", [], |row| row.get(0))
            .expect("old hash");
        database
            .connection()
            .execute_batch(
                "CREATE TRIGGER fail_symbol_insert BEFORE INSERT ON symbols BEGIN SELECT RAISE(ABORT, 'forced persistence failure'); END;",
            )
            .expect("trigger");
        fs::write(&path, "export function after() { return 2; }").expect("modify");
        assert!(service.index_project(repository.path()).is_err());
        let current_hash: String = database
            .connection()
            .query_row("SELECT content_hash FROM files WHERE is_active = 1", [], |row| row.get(0))
            .expect("current hash");
        assert_eq!(current_hash, old_hash);
        let latest_status: String = database
            .connection()
            .query_row(
                "SELECT status FROM analysis_runs ORDER BY started_at DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("status");
        assert_eq!(latest_status, "failed");
    }
}
