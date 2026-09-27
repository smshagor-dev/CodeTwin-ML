use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use lsp_enrichment::{
    file_uri_to_path, DocumentSymbolView, LanguageServerConfig, LanguageServerKind, LspError,
    LspLocation, LspPosition, LspRange, StdioLanguageServer,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    deterministic_id, graph_edge_id, is_windows_path_identity, normalize_relative_path,
    AnalysisStatus, Database, LanguageServerConfigService, SemanticConfigError,
    SemanticEnrichmentRequest, SemanticRunSummary, SemanticServerRun, SemanticServerStatus,
    SemanticSymbolState,
};

const SEMANTIC_ANALYZER_VERSION: &str = "lsp-semantic-v1";
const SEMANTIC_QUERY_VERSION: &str = "lsp-3.17-reference-definition-v1";
const MAX_FILES: usize = 250;
const MAX_SYMBOLS: usize = 2_000;
const MAX_REFERENCES_PER_SYMBOL: usize = 100;
const MAX_DEFINITION_LOOKUPS: usize = 5_000;
const MAX_SYMBOLS_PER_MAPPING_FILE: usize = 2_000;
const MAX_SNAPSHOT_CACHE_FILES: usize = 300;
const MAX_SEMANTIC_SOURCE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Error)]
pub enum SemanticServiceError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration error: {0}")]
    Config(#[from] SemanticConfigError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("external language server execution requires explicit project trust")]
    TrustRequired,
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
}

pub struct SemanticEnrichmentService<'a> {
    database: &'a Database,
}

impl<'a> SemanticEnrichmentService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn enrich_project(
        &self,
        project_id: &str,
        request: &SemanticEnrichmentRequest,
    ) -> Result<SemanticRunSummary, SemanticServiceError> {
        let cancelled = AtomicBool::new(false);
        self.enrich_project_with_cancel(project_id, request, &cancelled)
    }

    pub fn enrich_project_with_cancel(
        &self,
        project_id: &str,
        request: &SemanticEnrichmentRequest,
        cancelled: &AtomicBool,
    ) -> Result<SemanticRunSummary, SemanticServiceError> {
        if !request.trusted_project {
            return Err(SemanticServiceError::TrustRequired);
        }
        let started = Instant::now();
        let project = load_project(self.database.connection(), project_id)?;
        if !project.root.is_dir() {
            return Err(SemanticServiceError::InvalidProjectRoot(
                project.root.display().to_string(),
            ));
        }
        let configs = LanguageServerConfigService::new(self.database).list()?;
        let kinds = selected_kinds(&request.server_kinds);
        let limits = Limits::from_request(request);
        let run_id = new_run_id(project_id);
        let configuration_json = serde_json::to_string(request)?;
        let config_fingerprint = semantic_config_fingerprint(&configuration_json, &configs)?;

        self.database.connection().execute(
            "INSERT INTO analysis_runs( \
               id, project_id, status, analyzer_version, started_at, configuration_json, run_kind, query_version, config_fingerprint \
             ) VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'lsp_semantic', ?5, ?6)",
            params![
                run_id,
                project_id,
                SEMANTIC_ANALYZER_VERSION,
                configuration_json,
                SEMANTIC_QUERY_VERSION,
                config_fingerprint,
            ],
        )?;

        let execution = self.execute_run(
            &project, &run_id, &kinds, &configs, limits, cancelled, started,
        );
        match execution {
            Ok(summary) => Ok(summary),
            Err(error) => {
                let duration_ms = elapsed_ms(started);
                let _ = finish_analysis_run(
                    self.database.connection(),
                    &run_id,
                    AnalysisStatus::Failed,
                    duration_ms,
                );
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_run(
        &self,
        project: &ProjectContext,
        run_id: &str,
        kinds: &[LanguageServerKind],
        configs: &[LanguageServerConfig],
        limits: Limits,
        cancelled: &AtomicBool,
        started: Instant,
    ) -> Result<SemanticRunSummary, SemanticServiceError> {
        let mut outputs = Vec::new();
        let mut server_runs = Vec::new();
        let mut remaining_files = limits.max_files;
        let mut remaining_symbols = limits.max_symbols;
        let mut remaining_definition_lookups = limits.max_definition_lookups;

        for kind in kinds {
            if cancelled.load(Ordering::Relaxed) {
                return finish_cancelled_run(
                    self.database.connection(),
                    project,
                    run_id,
                    server_runs,
                    started,
                );
            }
            let Some(config) = configs.iter().find(|config| config.kind == *kind) else {
                server_runs.push(empty_server_run(*kind, SemanticServerStatus::NotConfigured));
                continue;
            };
            if !config.enabled {
                server_runs.push(empty_server_run(*kind, SemanticServerStatus::Disabled));
                continue;
            }
            if remaining_files == 0 || remaining_symbols == 0 {
                server_runs.push(empty_server_run(*kind, SemanticServerStatus::NoFiles));
                continue;
            }
            let files = load_provider_files(
                self.database.connection(),
                &project.id,
                *kind,
                remaining_files,
            )?;
            if files.is_empty() {
                server_runs.push(empty_server_run(*kind, SemanticServerStatus::NoFiles));
                continue;
            }

            let timeout = Duration::from_millis(limits.request_timeout_ms);
            let server = StdioLanguageServer::start(config, &project.root, true, timeout);
            let mut server = match server {
                Ok(server) => server,
                Err(error) => {
                    let mut run = empty_server_run(*kind, SemanticServerStatus::Failed);
                    run.errors = 1;
                    run.error = Some(error.to_string());
                    server_runs.push(run);
                    continue;
                }
            };
            let server_name = server.server_info().name.clone();
            let server_version = server.server_info().version.clone();

            match process_provider(
                self.database.connection(),
                project,
                run_id,
                *kind,
                &files,
                &mut server,
                limits,
                &mut remaining_files,
                &mut remaining_symbols,
                &mut remaining_definition_lookups,
                cancelled,
            )? {
                ProviderResult::Cancelled => {
                    let _ = server.shutdown();
                    return finish_cancelled_run(
                        self.database.connection(),
                        project,
                        run_id,
                        server_runs,
                        started,
                    );
                }
                ProviderResult::Failed(mut run) => {
                    run.server_name = server_name;
                    run.server_version = server_version;
                    let _ = server.shutdown();
                    server_runs.push(run);
                }
                ProviderResult::Completed(mut output) => {
                    output.run.server_name = server_name;
                    output.run.server_version = server_version;
                    let _ = server.shutdown();
                    server_runs.push(output.run.clone());
                    outputs.push(output);
                }
            }
        }

        let overall_status = if server_runs
            .iter()
            .any(|run| run.status == SemanticServerStatus::Completed)
            || server_runs
                .iter()
                .all(|run| run.status != SemanticServerStatus::Failed)
        {
            AnalysisStatus::Completed
        } else {
            AnalysisStatus::Failed
        };

        let graph_counts =
            persist_provider_outputs(self.database.connection(), project, run_id, &outputs)?;
        for run in &mut server_runs {
            run.graph_edges_materialized = graph_counts
                .per_provider
                .get(run.kind.as_str())
                .copied()
                .unwrap_or(0);
        }

        let duration_ms = elapsed_ms(started);
        let summary = summarize_run(
            project,
            run_id,
            overall_status,
            server_runs,
            graph_counts.total_edges,
            duration_ms,
        );
        persist_run_metrics(self.database.connection(), &summary)?;
        finish_analysis_run(
            self.database.connection(),
            run_id,
            overall_status,
            duration_ms,
        )?;
        Ok(summary)
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    max_files: usize,
    max_symbols: usize,
    max_references_per_symbol: usize,
    max_definition_lookups: usize,
    request_timeout_ms: u64,
}

impl Limits {
    fn from_request(request: &SemanticEnrichmentRequest) -> Self {
        Self {
            max_files: request.max_files.clamp(1, MAX_FILES),
            max_symbols: request.max_symbols.clamp(1, MAX_SYMBOLS),
            max_references_per_symbol: request
                .max_references_per_symbol
                .clamp(1, MAX_REFERENCES_PER_SYMBOL),
            max_definition_lookups: request
                .max_definition_lookups
                .clamp(1, MAX_DEFINITION_LOOKUPS),
            request_timeout_ms: request.request_timeout_ms.clamp(100, MAX_TIMEOUT_MS),
        }
    }
}

#[derive(Debug, Clone)]
struct ProjectContext {
    id: String,
    root: PathBuf,
    case_insensitive: bool,
}

#[derive(Debug, Clone)]
struct ActiveFile {
    id: String,
    relative_path: String,
    language: String,
    content_hash: String,
}

#[derive(Debug, Clone)]
struct FileSnapshot {
    file: ActiveFile,
    absolute_path: PathBuf,
    text: String,
}

#[derive(Debug, Clone)]
struct ActiveSymbol {
    id: String,
    #[allow(dead_code)] // kept for Debug output of active symbols
    file_id: String,
    name: String,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Debug, Clone)]
struct ImportReference {
    id: String,
    start_line: usize,
    start_column: usize,
}

#[derive(Debug, Clone)]
struct StateObservation {
    symbol_id: String,
    state: SemanticSymbolState,
    reference_locations: usize,
    definitions_resolved: usize,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct RelationObservation {
    id: String,
    subject_symbol_id: String,
    occurrence_file_id: String,
    container_symbol_id: Option<String>,
    target_file_id: String,
    target_symbol_id: Option<String>,
    occurrence_range: SourceRange,
    target_range: SourceRange,
    provider_kind: LanguageServerKind,
    server_name: Option<String>,
    server_version: Option<String>,
    occurrence_content_hash: String,
    target_content_hash: String,
}

#[derive(Debug, Clone)]
struct ImportObservation {
    id: String,
    import_reference_id: String,
    source_file_id: String,
    target_file_id: String,
    provider_kind: LanguageServerKind,
    target_range: SourceRange,
    source_content_hash: String,
    target_content_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceRange {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Debug)]
struct ProviderOutput {
    run: SemanticServerRun,
    states: BTreeMap<String, StateObservation>,
    relations: BTreeMap<String, RelationObservation>,
    imports: BTreeMap<String, ImportObservation>,
    processed_import_ids: BTreeSet<String>,
}

enum ProviderResult {
    Completed(ProviderOutput),
    Failed(SemanticServerRun),
    Cancelled,
}

#[allow(clippy::too_many_arguments)]
fn process_provider(
    connection: &Connection,
    project: &ProjectContext,
    run_id: &str,
    kind: LanguageServerKind,
    files: &[ActiveFile],
    server: &mut StdioLanguageServer,
    limits: Limits,
    remaining_files: &mut usize,
    remaining_symbols: &mut usize,
    remaining_definition_lookups: &mut usize,
    cancelled: &AtomicBool,
) -> Result<ProviderResult, SemanticServiceError> {
    let mut output = ProviderOutput {
        run: empty_server_run(kind, SemanticServerStatus::Completed),
        states: BTreeMap::new(),
        relations: BTreeMap::new(),
        imports: BTreeMap::new(),
        processed_import_ids: BTreeSet::new(),
    };
    let mut snapshots = BTreeMap::<String, FileSnapshot>::new();
    let mut symbol_cache = BTreeMap::<String, Vec<ActiveSymbol>>::new();
    let mut open_documents = BTreeSet::<String>::new();

    for file in files {
        if cancelled.load(Ordering::Relaxed) {
            close_documents(server, &open_documents);
            return Ok(ProviderResult::Cancelled);
        }
        if *remaining_files == 0 || *remaining_symbols == 0 {
            break;
        }
        let Some(snapshot) = load_snapshot(connection, project, file)? else {
            output.run.errors += 1;
            remember_error(
                &mut output.run.error,
                format!(
                    "{} changed or became unreadable after indexing",
                    file.relative_path
                ),
            );
            continue;
        };
        snapshots.insert(file.id.clone(), snapshot.clone());
        let uri =
            match server.open_document(&snapshot.absolute_path, &file.language, &snapshot.text) {
                Ok(uri) => uri,
                Err(error) => {
                    close_documents(server, &open_documents);
                    return Ok(ProviderResult::Failed(failed_server_run(
                        kind,
                        &output.run,
                        error,
                    )));
                }
            };
        open_documents.insert(uri.clone());
        *remaining_files = remaining_files.saturating_sub(1);
        output.run.files_processed += 1;

        let symbols = load_symbols_for_file(connection, &file.id, *remaining_symbols)?;
        let selected_symbol_count = symbols.len();
        *remaining_symbols = remaining_symbols.saturating_sub(selected_symbol_count);
        output.run.symbols_processed += selected_symbol_count;
        symbol_cache.insert(file.id.clone(), symbols.clone());

        let document_symbols = if symbols.is_empty() {
            Vec::new()
        } else {
            match server.document_symbols(&uri) {
                Ok(symbols) => symbols,
                Err(error) if fatal_lsp_error(&error) => {
                    close_documents(server, &open_documents);
                    return Ok(ProviderResult::Failed(failed_server_run(
                        kind,
                        &output.run,
                        error,
                    )));
                }
                Err(error) => {
                    output.run.errors += symbols.len();
                    remember_error(&mut output.run.error, error.to_string());
                    for symbol in &symbols {
                        output.states.insert(
                            symbol.id.clone(),
                            StateObservation {
                                symbol_id: symbol.id.clone(),
                                state: SemanticSymbolState::Error,
                                reference_locations: 0,
                                definitions_resolved: 0,
                                last_error: Some(error.to_string()),
                            },
                        );
                    }
                    Vec::new()
                }
            }
        };

        if kind == LanguageServerKind::TypeScript && *remaining_definition_lookups > 0 {
            process_import_references(
                connection,
                project,
                run_id,
                kind,
                server,
                &snapshot,
                &uri,
                &mut output,
                &mut snapshots,
                &mut open_documents,
                remaining_definition_lookups,
                cancelled,
            )?;
        }

        for symbol in &symbols {
            if cancelled.load(Ordering::Relaxed) {
                close_documents(server, &open_documents);
                return Ok(ProviderResult::Cancelled);
            }
            if output.states.contains_key(&symbol.id) {
                continue;
            }
            let Some(document_symbol) =
                match_document_symbol(symbol, &document_symbols, &snapshot.text)
            else {
                output.states.insert(
                    symbol.id.clone(),
                    StateObservation {
                        symbol_id: symbol.id.clone(),
                        state: SemanticSymbolState::Unmatched,
                        reference_locations: 0,
                        definitions_resolved: 0,
                        last_error: None,
                    },
                );
                continue;
            };
            output.run.symbols_matched += 1;
            let references =
                match server.references(&uri, &document_symbol.selection_range.start, false) {
                    Ok(references) => references,
                    Err(error) if fatal_lsp_error(&error) => {
                        close_documents(server, &open_documents);
                        return Ok(ProviderResult::Failed(failed_server_run(
                            kind,
                            &output.run,
                            error,
                        )));
                    }
                    Err(error) => {
                        output.run.errors += 1;
                        remember_error(&mut output.run.error, error.to_string());
                        output.states.insert(
                            symbol.id.clone(),
                            StateObservation {
                                symbol_id: symbol.id.clone(),
                                state: SemanticSymbolState::Error,
                                reference_locations: 0,
                                definitions_resolved: 0,
                                last_error: Some(error.to_string()),
                            },
                        );
                        continue;
                    }
                };
            let references: Vec<LspLocation> = references
                .into_iter()
                .take(limits.max_references_per_symbol)
                .collect();
            output.run.reference_locations += references.len();
            let mut local_definitions = 0;

            for reference in &references {
                if cancelled.load(Ordering::Relaxed) {
                    close_documents(server, &open_documents);
                    return Ok(ProviderResult::Cancelled);
                }
                if *remaining_definition_lookups == 0 {
                    break;
                }
                let Some(occurrence) = location_snapshot(
                    connection,
                    project,
                    kind,
                    server,
                    reference,
                    &mut snapshots,
                    &mut open_documents,
                )?
                else {
                    continue;
                };
                let occurrence_range = match range_to_source(&occurrence.text, &reference.range) {
                    Some(range) => range,
                    None => continue,
                };
                *remaining_definition_lookups = remaining_definition_lookups.saturating_sub(1);
                let definitions = match server.definitions(&reference.uri, &reference.range.start) {
                    Ok(definitions) => definitions,
                    Err(error) if fatal_lsp_error(&error) => {
                        close_documents(server, &open_documents);
                        return Ok(ProviderResult::Failed(failed_server_run(
                            kind,
                            &output.run,
                            error,
                        )));
                    }
                    Err(error) => {
                        output.run.errors += 1;
                        remember_error(&mut output.run.error, error.to_string());
                        continue;
                    }
                };

                for definition in definitions.into_iter().take(8) {
                    let Some(target) = location_snapshot(
                        connection,
                        project,
                        kind,
                        server,
                        &definition,
                        &mut snapshots,
                        &mut open_documents,
                    )?
                    else {
                        continue;
                    };
                    let Some(target_range) = range_to_source(&target.text, &definition.range)
                    else {
                        continue;
                    };
                    local_definitions += 1;
                    output.run.definitions_resolved += 1;

                    let container_symbol_id = map_position_to_symbol(
                        connection,
                        &occurrence,
                        &reference.range.start,
                        &mut symbol_cache,
                    )?
                    .map(|symbol| symbol.id);
                    let target_symbol_id = map_position_to_symbol(
                        connection,
                        &target,
                        &definition.range.start,
                        &mut symbol_cache,
                    )?
                    .map(|symbol| symbol.id);
                    let relation_id = deterministic_id(
                        "semantic-relation",
                        &[
                            &project.id,
                            &symbol.id,
                            &occurrence.file.id,
                            &source_range_key(occurrence_range),
                            &target.file.id,
                            &source_range_key(target_range),
                            kind.as_str(),
                        ],
                    );
                    output.relations.insert(
                        relation_id.clone(),
                        RelationObservation {
                            id: relation_id,
                            subject_symbol_id: symbol.id.clone(),
                            occurrence_file_id: occurrence.file.id.clone(),
                            container_symbol_id,
                            target_file_id: target.file.id.clone(),
                            target_symbol_id,
                            occurrence_range,
                            target_range,
                            provider_kind: kind,
                            server_name: server.server_info().name.clone(),
                            server_version: server.server_info().version.clone(),
                            occurrence_content_hash: occurrence.file.content_hash.clone(),
                            target_content_hash: target.file.content_hash.clone(),
                        },
                    );
                }
            }

            let state = if references.is_empty() {
                SemanticSymbolState::NoReferences
            } else if local_definitions > 0 {
                SemanticSymbolState::Resolved
            } else {
                SemanticSymbolState::Unresolved
            };
            output.states.insert(
                symbol.id.clone(),
                StateObservation {
                    symbol_id: symbol.id.clone(),
                    state,
                    reference_locations: references.len(),
                    definitions_resolved: local_definitions,
                    last_error: None,
                },
            );
        }
    }

    close_documents(server, &open_documents);
    output.run.relations_persisted = output.relations.len();
    output.run.imports_upgraded = output.imports.len();
    Ok(ProviderResult::Completed(output))
}

#[allow(clippy::too_many_arguments)]
fn process_import_references(
    connection: &Connection,
    project: &ProjectContext,
    run_id: &str,
    kind: LanguageServerKind,
    server: &mut StdioLanguageServer,
    snapshot: &FileSnapshot,
    uri: &str,
    output: &mut ProviderOutput,
    snapshots: &mut BTreeMap<String, FileSnapshot>,
    open_documents: &mut BTreeSet<String>,
    remaining_definition_lookups: &mut usize,
    cancelled: &AtomicBool,
) -> Result<(), SemanticServiceError> {
    let imports = load_unresolved_imports(connection, &snapshot.file.id, 200)?;
    for reference in imports {
        if cancelled.load(Ordering::Relaxed) || *remaining_definition_lookups == 0 {
            break;
        }
        output.processed_import_ids.insert(reference.id.clone());
        let Some(position) = byte_position_to_lsp(
            &snapshot.text,
            reference.start_line,
            reference.start_column.saturating_add(1),
        ) else {
            continue;
        };
        *remaining_definition_lookups = remaining_definition_lookups.saturating_sub(1);
        let definitions = match server.definitions(uri, &position) {
            Ok(definitions) => definitions,
            Err(error) if fatal_lsp_error(&error) => return Err(lsp_as_io(error)),
            Err(error) => {
                output.run.errors += 1;
                remember_error(&mut output.run.error, error.to_string());
                continue;
            }
        };
        for definition in definitions.into_iter().take(8) {
            let Some(target) = location_snapshot(
                connection,
                project,
                kind,
                server,
                &definition,
                snapshots,
                open_documents,
            )?
            else {
                continue;
            };
            if target.file.id == snapshot.file.id {
                continue;
            }
            let Some(target_range) = range_to_source(&target.text, &definition.range) else {
                continue;
            };
            let id = deterministic_id(
                "semantic-import",
                &[&project.id, &reference.id, &target.file.id, kind.as_str()],
            );
            output.imports.insert(
                id.clone(),
                ImportObservation {
                    id,
                    import_reference_id: reference.id.clone(),
                    source_file_id: snapshot.file.id.clone(),
                    target_file_id: target.file.id.clone(),
                    provider_kind: kind,
                    target_range,
                    source_content_hash: snapshot.file.content_hash.clone(),
                    target_content_hash: target.file.content_hash.clone(),
                },
            );
        }
    }
    let _ = run_id;
    Ok(())
}

fn lsp_as_io(error: LspError) -> SemanticServiceError {
    SemanticServiceError::Io(std::io::Error::other(error.to_string()))
}

fn fatal_lsp_error(error: &LspError) -> bool {
    matches!(
        error,
        LspError::Io(_)
            | LspError::Json(_)
            | LspError::InvalidFrame(_)
            | LspError::MessageTooLarge
            | LspError::ChannelClosed
    )
}

fn close_documents(server: &mut StdioLanguageServer, uris: &BTreeSet<String>) {
    for uri in uris {
        let _ = server.close_document(uri);
    }
}

fn failed_server_run(
    kind: LanguageServerKind,
    progress: &SemanticServerRun,
    error: LspError,
) -> SemanticServerRun {
    let mut run = progress.clone();
    run.kind = kind;
    run.status = SemanticServerStatus::Failed;
    run.errors += 1;
    remember_error(&mut run.error, error.to_string());
    run
}

fn remember_error(slot: &mut Option<String>, error: String) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn empty_server_run(kind: LanguageServerKind, status: SemanticServerStatus) -> SemanticServerRun {
    SemanticServerRun {
        kind,
        status,
        files_processed: 0,
        symbols_processed: 0,
        symbols_matched: 0,
        reference_locations: 0,
        definitions_resolved: 0,
        relations_persisted: 0,
        graph_edges_materialized: 0,
        imports_upgraded: 0,
        errors: 0,
        error: None,
        server_name: None,
        server_version: None,
    }
}

fn selected_kinds(requested: &[LanguageServerKind]) -> Vec<LanguageServerKind> {
    let source = if requested.is_empty() {
        vec![
            LanguageServerKind::TypeScript,
            LanguageServerKind::Pyright,
            LanguageServerKind::RustAnalyzer,
        ]
    } else {
        requested.to_vec()
    };
    let mut selected = Vec::new();
    for kind in source {
        if !selected.contains(&kind) {
            selected.push(kind);
        }
    }
    selected
}

fn semantic_config_fingerprint(
    request_json: &str,
    configs: &[LanguageServerConfig],
) -> Result<String, serde_json::Error> {
    let mut ordered = configs.to_vec();
    ordered.sort_by_key(|config| config.kind.as_str());
    let configs_json = serde_json::to_string(&ordered)?;
    Ok(deterministic_id(
        "semantic-config",
        &[request_json, &configs_json, SEMANTIC_QUERY_VERSION],
    ))
}

fn load_project(
    connection: &Connection,
    project_id: &str,
) -> Result<ProjectContext, SemanticServiceError> {
    let project = connection
        .query_row(
            "SELECT root_path, COALESCE(path_identity, root_path) FROM projects WHERE id = ?1",
            [project_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| SemanticServiceError::ProjectNotFound(project_id.to_string()))?;
    let root = fs::canonicalize(&project.0)?;
    Ok(ProjectContext {
        id: project_id.to_string(),
        root,
        case_insensitive: is_windows_path_identity(&project.1),
    })
}

fn load_provider_files(
    connection: &Connection,
    project_id: &str,
    kind: LanguageServerKind,
    limit: usize,
) -> Result<Vec<ActiveFile>, rusqlite::Error> {
    let language_clause = match kind {
        LanguageServerKind::TypeScript => {
            "language IN ('TypeScript','TypeScript TSX','JavaScript')"
        }
        LanguageServerKind::Pyright => "language = 'Python'",
        LanguageServerKind::RustAnalyzer => "language = 'Rust'",
    };
    let sql = format!(
        "SELECT id, relative_path, COALESCE(language, ''), content_hash \
         FROM files WHERE project_id = ?1 AND is_active = 1 AND {language_clause} \
         ORDER BY relative_path LIMIT ?2"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params![project_id, to_i64(limit)], |row| {
        Ok(ActiveFile {
            id: row.get(0)?,
            relative_path: row.get(1)?,
            language: row.get(2)?,
            content_hash: row.get(3)?,
        })
    })?;
    let mut files = Vec::new();
    for row in rows {
        files.push(row?);
    }
    Ok(files)
}

fn load_symbols_for_file(
    connection: &Connection,
    file_id: &str,
    limit: usize,
) -> Result<Vec<ActiveSymbol>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT id, file_id, name, start_line, start_column, end_line, end_column \
         FROM symbols WHERE file_id = ?1 AND is_active = 1 \
         ORDER BY start_line, start_column, end_line, end_column, name LIMIT ?2",
    )?;
    let rows = statement.query_map(params![file_id, to_i64(limit)], |row| {
        Ok(ActiveSymbol {
            id: row.get(0)?,
            file_id: row.get(1)?,
            name: row.get(2)?,
            start_line: to_usize(row.get(3)?),
            start_column: to_usize(row.get(4)?),
            end_line: to_usize(row.get(5)?),
            end_column: to_usize(row.get(6)?),
        })
    })?;
    let mut symbols = Vec::new();
    for row in rows {
        symbols.push(row?);
    }
    Ok(symbols)
}

fn load_unresolved_imports(
    connection: &Connection,
    file_id: &str,
    limit: usize,
) -> Result<Vec<ImportReference>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT id, start_line, start_column FROM import_references \
         WHERE source_file_id = ?1 AND resolution_state <> 'resolved_local' \
         ORDER BY start_line, start_column, id LIMIT ?2",
    )?;
    let rows = statement.query_map(params![file_id, to_i64(limit)], |row| {
        Ok(ImportReference {
            id: row.get(0)?,
            start_line: to_usize(row.get(1)?),
            start_column: to_usize(row.get(2)?),
        })
    })?;
    let mut imports = Vec::new();
    for row in rows {
        imports.push(row?);
    }
    Ok(imports)
}

fn load_snapshot(
    connection: &Connection,
    project: &ProjectContext,
    file: &ActiveFile,
) -> Result<Option<FileSnapshot>, SemanticServiceError> {
    let Some(relative) = normalize_relative_path(&file.relative_path, false) else {
        invalidate_semantics_for_file(connection, &file.id)?;
        return Ok(None);
    };
    let mut candidate = project.root.clone();
    for segment in relative.split('/') {
        candidate.push(segment);
    }
    let canonical = match fs::canonicalize(candidate) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            invalidate_semantics_for_file(connection, &file.id)?;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    if !canonical.starts_with(&project.root) {
        invalidate_semantics_for_file(connection, &file.id)?;
        return Ok(None);
    }
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() || metadata.len() > MAX_SEMANTIC_SOURCE_BYTES {
        invalidate_semantics_for_file(connection, &file.id)?;
        return Ok(None);
    }
    let bytes = fs::read(&canonical)?;
    if sha256_hex(&bytes) != file.content_hash {
        invalidate_semantics_for_file(connection, &file.id)?;
        return Ok(None);
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            invalidate_semantics_for_file(connection, &file.id)?;
            return Ok(None);
        }
    };
    Ok(Some(FileSnapshot {
        file: file.clone(),
        absolute_path: canonical,
        text,
    }))
}

fn location_snapshot(
    connection: &Connection,
    project: &ProjectContext,
    kind: LanguageServerKind,
    server: &mut StdioLanguageServer,
    location: &LspLocation,
    snapshots: &mut BTreeMap<String, FileSnapshot>,
    open_documents: &mut BTreeSet<String>,
) -> Result<Option<FileSnapshot>, SemanticServiceError> {
    let Some(path) = file_uri_to_path(&location.uri) else {
        return Ok(None);
    };
    let canonical = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    if !canonical.starts_with(&project.root) {
        return Ok(None);
    }
    let Ok(relative) = canonical.strip_prefix(&project.root) else {
        return Ok(None);
    };
    let raw_relative = relative.to_string_lossy().replace('\\', "/");
    let Some(identity) = normalize_relative_path(&raw_relative, project.case_insensitive) else {
        return Ok(None);
    };
    let file = connection
        .query_row(
            "SELECT id, relative_path, COALESCE(language, ''), content_hash FROM files \
             WHERE project_id = ?1 AND is_active = 1 AND relative_path_identity = ?2 LIMIT 1",
            params![project.id, identity],
            |row| {
                Ok(ActiveFile {
                    id: row.get(0)?,
                    relative_path: row.get(1)?,
                    language: row.get(2)?,
                    content_hash: row.get(3)?,
                })
            },
        )
        .optional()?;
    let Some(file) = file else {
        return Ok(None);
    };
    if !kind.supports_indexed_language(&file.language) {
        return Ok(None);
    }

    let snapshot = if let Some(snapshot) = snapshots.get(&file.id) {
        snapshot.clone()
    } else {
        if snapshots.len() >= MAX_SNAPSHOT_CACHE_FILES {
            return Ok(None);
        }
        let Some(snapshot) = load_snapshot(connection, project, &file)? else {
            return Ok(None);
        };
        snapshots.insert(file.id.clone(), snapshot.clone());
        snapshot
    };
    if !open_documents.contains(&location.uri) {
        let opened_uri = server
            .open_document(
                &snapshot.absolute_path,
                &snapshot.file.language,
                &snapshot.text,
            )
            .map_err(lsp_as_io)?;
        open_documents.insert(opened_uri);
    }
    Ok(Some(snapshot))
}

fn match_document_symbol<'a>(
    symbol: &ActiveSymbol,
    document_symbols: &'a [DocumentSymbolView],
    text: &str,
) -> Option<&'a DocumentSymbolView> {
    let mut matches = document_symbols.iter().filter(|candidate| {
        if candidate.name != symbol.name {
            return false;
        }
        let Some((line, column)) = lsp_position_to_source(text, &candidate.selection_range.start)
        else {
            return false;
        };
        contains_position(symbol, line, column)
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn map_position_to_symbol(
    connection: &Connection,
    snapshot: &FileSnapshot,
    position: &LspPosition,
    cache: &mut BTreeMap<String, Vec<ActiveSymbol>>,
) -> Result<Option<ActiveSymbol>, rusqlite::Error> {
    if !cache.contains_key(&snapshot.file.id) {
        if cache.len() >= MAX_SNAPSHOT_CACHE_FILES {
            return Ok(None);
        }
        let symbols =
            load_symbols_for_file(connection, &snapshot.file.id, MAX_SYMBOLS_PER_MAPPING_FILE)?;
        cache.insert(snapshot.file.id.clone(), symbols);
    }
    let Some((line, column)) = lsp_position_to_source(&snapshot.text, position) else {
        return Ok(None);
    };
    let Some(symbols) = cache.get(&snapshot.file.id) else {
        return Ok(None);
    };
    let mut candidates: Vec<&ActiveSymbol> = symbols
        .iter()
        .filter(|symbol| contains_position(symbol, line, column))
        .collect();
    candidates.sort_by_key(|symbol| symbol_extent(symbol));
    let Some(first) = candidates.first() else {
        return Ok(None);
    };
    if candidates
        .get(1)
        .is_some_and(|second| symbol_extent(second) == symbol_extent(first))
    {
        return Ok(None);
    }
    Ok(Some((*first).clone()))
}

fn contains_position(symbol: &ActiveSymbol, line: usize, column: usize) -> bool {
    if line < symbol.start_line || line > symbol.end_line {
        return false;
    }
    if line == symbol.start_line && column < symbol.start_column {
        return false;
    }
    if line == symbol.end_line && column > symbol.end_column {
        return false;
    }
    true
}

fn symbol_extent(symbol: &ActiveSymbol) -> (usize, usize) {
    let line_span = symbol.end_line.saturating_sub(symbol.start_line);
    let column_span = if line_span == 0 {
        symbol.end_column.saturating_sub(symbol.start_column)
    } else {
        usize::MAX
    };
    (line_span, column_span)
}

fn lsp_position_to_source(text: &str, position: &LspPosition) -> Option<(usize, usize)> {
    let line_index = usize::try_from(position.line).ok()?;
    let line = text.split('\n').nth(line_index)?;
    let byte_column = utf16_column_to_byte(line, position.character)?;
    Some((line_index + 1, byte_column))
}

fn byte_position_to_lsp(text: &str, line: usize, byte_column: usize) -> Option<LspPosition> {
    let line_index = line.checked_sub(1)?;
    let source_line = text.split('\n').nth(line_index)?;
    if byte_column > source_line.len() || !source_line.is_char_boundary(byte_column) {
        return None;
    }
    let character = source_line[..byte_column].encode_utf16().count();
    Some(LspPosition {
        line: u32::try_from(line_index).ok()?,
        character: u32::try_from(character).ok()?,
    })
}

fn range_to_source(text: &str, range: &LspRange) -> Option<SourceRange> {
    let (start_line, start_column) = lsp_position_to_source(text, &range.start)?;
    let (end_line, end_column) = lsp_position_to_source(text, &range.end)?;
    Some(SourceRange {
        start_line,
        start_column,
        end_line,
        end_column,
    })
}

fn utf16_column_to_byte(line: &str, target: u32) -> Option<usize> {
    let target = usize::try_from(target).ok()?;
    let mut units = 0_usize;
    let mut bytes = 0_usize;
    for character in line.chars() {
        if units == target {
            return Some(bytes);
        }
        let next = units.saturating_add(character.len_utf16());
        if target < next {
            return None;
        }
        units = next;
        bytes = bytes.saturating_add(character.len_utf8());
    }
    (units == target).then_some(bytes)
}

fn source_range_key(range: SourceRange) -> String {
    format!(
        "{}:{}-{}:{}",
        range.start_line, range.start_column, range.end_line, range.end_column
    )
}

fn invalidate_semantics_for_file(
    connection: &Connection,
    file_id: &str,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE graph_edges SET is_active = 0, updated_at = CURRENT_TIMESTAMP \
         WHERE id IN ( \
           SELECT graph_edge_id FROM semantic_relations \
           WHERE graph_edge_id IS NOT NULL AND (occurrence_file_id = ?1 OR target_file_id = ?1) \
           UNION \
           SELECT graph_edge_id FROM semantic_import_resolutions \
           WHERE graph_edge_id IS NOT NULL AND (source_file_id = ?1 OR target_file_id = ?1) \
         )",
        [file_id],
    )?;
    connection.execute(
        "UPDATE semantic_relations SET is_active = 0, updated_at = CURRENT_TIMESTAMP \
         WHERE occurrence_file_id = ?1 OR target_file_id = ?1",
        [file_id],
    )?;
    connection.execute(
        "UPDATE semantic_import_resolutions SET is_active = 0, updated_at = CURRENT_TIMESTAMP \
         WHERE source_file_id = ?1 OR target_file_id = ?1",
        [file_id],
    )?;
    connection.execute(
        "UPDATE semantic_symbol_states SET state = 'stale', updated_at = CURRENT_TIMESTAMP \
         WHERE symbol_id IN (SELECT id FROM symbols WHERE file_id = ?1)",
        [file_id],
    )?;
    Ok(())
}

#[derive(Debug, Default)]
struct GraphCounts {
    total_edges: usize,
    per_provider: BTreeMap<String, usize>,
}

fn persist_provider_outputs(
    connection: &Connection,
    project: &ProjectContext,
    run_id: &str,
    outputs: &[ProviderOutput],
) -> Result<GraphCounts, SemanticServiceError> {
    let transaction = connection.unchecked_transaction()?;
    for output in outputs {
        let provider = output.run.kind.as_str();
        for state in output.states.values() {
            transaction.execute(
                "UPDATE semantic_relations SET is_active = 0, updated_at = CURRENT_TIMESTAMP \
                 WHERE provider_kind = ?1 AND subject_symbol_id = ?2",
                params![provider, state.symbol_id],
            )?;
            transaction.execute(
                "INSERT INTO semantic_symbol_states( \
                   symbol_id, project_id, run_id, provider_kind, state, reference_locations, definitions_resolved, last_error, updated_at \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP) \
                 ON CONFLICT(symbol_id) DO UPDATE SET \
                   project_id = excluded.project_id, run_id = excluded.run_id, provider_kind = excluded.provider_kind, \
                   state = excluded.state, reference_locations = excluded.reference_locations, \
                   definitions_resolved = excluded.definitions_resolved, last_error = excluded.last_error, \
                   updated_at = CURRENT_TIMESTAMP",
                params![
                    state.symbol_id,
                    project.id,
                    run_id,
                    provider,
                    state.state.as_str(),
                    to_i64(state.reference_locations),
                    to_i64(state.definitions_resolved),
                    state.last_error,
                ],
            )?;
        }
        for import_id in &output.processed_import_ids {
            transaction.execute(
                "UPDATE semantic_import_resolutions SET is_active = 0, updated_at = CURRENT_TIMESTAMP \
                 WHERE provider_kind = ?1 AND import_reference_id = ?2",
                params![provider, import_id],
            )?;
        }
        for relation in output.relations.values() {
            transaction.execute(
                "INSERT INTO semantic_relations( \
                   id, project_id, run_id, subject_symbol_id, occurrence_file_id, container_symbol_id, target_file_id, target_symbol_id, \
                   relationship, occurrence_start_line, occurrence_start_column, occurrence_end_line, occurrence_end_column, \
                   target_start_line, target_start_column, target_end_line, target_end_column, provider_kind, server_name, server_version, \
                   occurrence_content_hash, target_content_hash, graph_edge_id, created_at, updated_at, is_active \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reference_definition', ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1) \
                 ON CONFLICT( \
                   project_id, relationship, occurrence_file_id, occurrence_start_line, occurrence_start_column, occurrence_end_line, occurrence_end_column, \
                   target_file_id, target_start_line, target_start_column, target_end_line, target_end_column \
                 ) DO UPDATE SET \
                   id = excluded.id, run_id = excluded.run_id, subject_symbol_id = excluded.subject_symbol_id, \
                   container_symbol_id = excluded.container_symbol_id, target_symbol_id = excluded.target_symbol_id, \
                   provider_kind = excluded.provider_kind, server_name = excluded.server_name, server_version = excluded.server_version, \
                   occurrence_content_hash = excluded.occurrence_content_hash, target_content_hash = excluded.target_content_hash, \
                   graph_edge_id = NULL, updated_at = CURRENT_TIMESTAMP, is_active = 1",
                params![
                    relation.id,
                    project.id,
                    run_id,
                    relation.subject_symbol_id,
                    relation.occurrence_file_id,
                    relation.container_symbol_id,
                    relation.target_file_id,
                    relation.target_symbol_id,
                    to_i64(relation.occurrence_range.start_line),
                    to_i64(relation.occurrence_range.start_column),
                    to_i64(relation.occurrence_range.end_line),
                    to_i64(relation.occurrence_range.end_column),
                    to_i64(relation.target_range.start_line),
                    to_i64(relation.target_range.start_column),
                    to_i64(relation.target_range.end_line),
                    to_i64(relation.target_range.end_column),
                    relation.provider_kind.as_str(),
                    relation.server_name,
                    relation.server_version,
                    relation.occurrence_content_hash,
                    relation.target_content_hash,
                ],
            )?;
        }
        for import in output.imports.values() {
            transaction.execute(
                "INSERT INTO semantic_import_resolutions( \
                   id, project_id, run_id, import_reference_id, source_file_id, target_file_id, provider_kind, \
                   target_start_line, target_start_column, target_end_line, target_end_column, source_content_hash, target_content_hash, \
                   graph_edge_id, created_at, updated_at, is_active \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1) \
                 ON CONFLICT(import_reference_id, target_file_id) DO UPDATE SET \
                   id = excluded.id, run_id = excluded.run_id, provider_kind = excluded.provider_kind, \
                   target_start_line = excluded.target_start_line, target_start_column = excluded.target_start_column, \
                   target_end_line = excluded.target_end_line, target_end_column = excluded.target_end_column, \
                   source_content_hash = excluded.source_content_hash, target_content_hash = excluded.target_content_hash, \
                   graph_edge_id = NULL, updated_at = CURRENT_TIMESTAMP, is_active = 1",
                params![
                    import.id,
                    project.id,
                    run_id,
                    import.import_reference_id,
                    import.source_file_id,
                    import.target_file_id,
                    import.provider_kind.as_str(),
                    to_i64(import.target_range.start_line),
                    to_i64(import.target_range.start_column),
                    to_i64(import.target_range.end_line),
                    to_i64(import.target_range.end_column),
                    import.source_content_hash,
                    import.target_content_hash,
                ],
            )?;
        }
    }

    let counts = materialize_semantic_graph(&transaction, &project.id, run_id)?;
    transaction.commit()?;
    Ok(counts)
}

#[derive(Debug, Default)]
struct EdgeGroup {
    evidence_ids: Vec<String>,
    providers: BTreeSet<String>,
}

fn materialize_semantic_graph(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
) -> Result<GraphCounts, rusqlite::Error> {
    connection.execute(
        "UPDATE graph_edges SET is_active = 0, updated_at = CURRENT_TIMESTAMP \
         WHERE project_id = ?1 AND relationship IN ('SYMBOL_REFERENCES_SYMBOL','FILE_IMPORTS_FILE_LSP')",
        [project_id],
    )?;
    connection.execute(
        "UPDATE semantic_relations SET graph_edge_id = NULL WHERE project_id = ?1",
        [project_id],
    )?;
    connection.execute(
        "UPDATE semantic_import_resolutions SET graph_edge_id = NULL WHERE project_id = ?1",
        [project_id],
    )?;

    let mut relation_groups = BTreeMap::<(String, String), EdgeGroup>::new();
    let mut statement = connection.prepare(
        "SELECT r.id, source_node.id, target_node.id, r.provider_kind \
         FROM semantic_relations r \
         JOIN files occurrence_file ON occurrence_file.id = r.occurrence_file_id \
         JOIN files target_file ON target_file.id = r.target_file_id \
         JOIN symbols source_symbol ON source_symbol.id = r.container_symbol_id \
         JOIN symbols target_symbol ON target_symbol.id = r.target_symbol_id \
         JOIN graph_nodes source_node ON source_node.project_id = r.project_id AND source_node.node_type = 'SYMBOL' AND source_node.external_key = source_symbol.id \
         JOIN graph_nodes target_node ON target_node.project_id = r.project_id AND target_node.node_type = 'SYMBOL' AND target_node.external_key = target_symbol.id \
         WHERE r.project_id = ?1 AND r.is_active = 1 \
           AND occurrence_file.is_active = 1 AND target_file.is_active = 1 \
           AND source_symbol.is_active = 1 AND target_symbol.is_active = 1 \
           AND source_node.is_active = 1 AND target_node.is_active = 1 \
           AND occurrence_file.content_hash = r.occurrence_content_hash \
           AND target_file.content_hash = r.target_content_hash",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (evidence_id, source_node, target_node, provider) = row?;
        let group = relation_groups
            .entry((source_node, target_node))
            .or_default();
        group.evidence_ids.push(evidence_id);
        group.providers.insert(provider);
    }
    drop(statement);

    let mut counts = GraphCounts::default();
    for ((source_node, target_node), group) in relation_groups {
        let relationship = "SYMBOL_REFERENCES_SYMBOL";
        let edge_id = graph_edge_id(project_id, &source_node, &target_node, relationship);
        let metadata = json!({
            "evidence": "semantic_relations",
            "evidence_count": group.evidence_ids.len(),
            "providers": group.providers,
        })
        .to_string();
        upsert_semantic_edge(
            connection,
            &edge_id,
            project_id,
            &source_node,
            &target_node,
            relationship,
            &metadata,
            run_id,
        )?;
        for evidence_id in &group.evidence_ids {
            connection.execute(
                "UPDATE semantic_relations SET graph_edge_id = ?2 WHERE id = ?1",
                params![evidence_id, edge_id],
            )?;
        }
        counts.total_edges += 1;
        for provider in group.providers {
            *counts.per_provider.entry(provider).or_default() += 1;
        }
    }

    let mut import_groups = BTreeMap::<(String, String), EdgeGroup>::new();
    let mut statement = connection.prepare(
        "SELECT r.id, source_node.id, target_node.id, r.provider_kind \
         FROM semantic_import_resolutions r \
         JOIN files source_file ON source_file.id = r.source_file_id \
         JOIN files target_file ON target_file.id = r.target_file_id \
         JOIN graph_nodes source_node ON source_node.project_id = r.project_id AND source_node.node_type = 'FILE' AND source_node.external_key = source_file.id \
         JOIN graph_nodes target_node ON target_node.project_id = r.project_id AND target_node.node_type = 'FILE' AND target_node.external_key = target_file.id \
         WHERE r.project_id = ?1 AND r.is_active = 1 \
           AND source_file.is_active = 1 AND target_file.is_active = 1 \
           AND source_node.is_active = 1 AND target_node.is_active = 1 \
           AND source_file.content_hash = r.source_content_hash \
           AND target_file.content_hash = r.target_content_hash",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (evidence_id, source_node, target_node, provider) = row?;
        let group = import_groups.entry((source_node, target_node)).or_default();
        group.evidence_ids.push(evidence_id);
        group.providers.insert(provider);
    }
    drop(statement);

    for ((source_node, target_node), group) in import_groups {
        let relationship = "FILE_IMPORTS_FILE_LSP";
        let edge_id = graph_edge_id(project_id, &source_node, &target_node, relationship);
        let metadata = json!({
            "evidence": "semantic_import_resolutions",
            "evidence_count": group.evidence_ids.len(),
            "providers": group.providers,
        })
        .to_string();
        upsert_semantic_edge(
            connection,
            &edge_id,
            project_id,
            &source_node,
            &target_node,
            relationship,
            &metadata,
            run_id,
        )?;
        for evidence_id in &group.evidence_ids {
            connection.execute(
                "UPDATE semantic_import_resolutions SET graph_edge_id = ?2 WHERE id = ?1",
                params![evidence_id, edge_id],
            )?;
        }
        counts.total_edges += 1;
        for provider in group.providers {
            *counts.per_provider.entry(provider).or_default() += 1;
        }
    }
    Ok(counts)
}

#[allow(clippy::too_many_arguments)]
fn upsert_semantic_edge(
    connection: &Connection,
    edge_id: &str,
    project_id: &str,
    source_node_id: &str,
    target_node_id: &str,
    relationship: &str,
    metadata_json: &str,
    run_id: &str,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO graph_edges( \
           id, project_id, source_node_id, target_node_id, relationship, metadata_json, last_index_run_id, created_at, updated_at, is_active \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1) \
         ON CONFLICT(project_id, source_node_id, target_node_id, relationship) DO UPDATE SET \
           metadata_json = excluded.metadata_json, last_index_run_id = excluded.last_index_run_id, \
           updated_at = CURRENT_TIMESTAMP, is_active = 1",
        params![
            edge_id,
            project_id,
            source_node_id,
            target_node_id,
            relationship,
            metadata_json,
            run_id,
        ],
    )?;
    Ok(())
}

fn summarize_run(
    project: &ProjectContext,
    run_id: &str,
    status: AnalysisStatus,
    servers: Vec<SemanticServerRun>,
    graph_edges_materialized: usize,
    duration_ms: u64,
) -> SemanticRunSummary {
    SemanticRunSummary {
        project_id: project.id.clone(),
        run_id: run_id.to_string(),
        status,
        files_processed: servers.iter().map(|run| run.files_processed).sum(),
        symbols_processed: servers.iter().map(|run| run.symbols_processed).sum(),
        symbols_matched: servers.iter().map(|run| run.symbols_matched).sum(),
        reference_locations: servers.iter().map(|run| run.reference_locations).sum(),
        definitions_resolved: servers.iter().map(|run| run.definitions_resolved).sum(),
        relations_persisted: servers.iter().map(|run| run.relations_persisted).sum(),
        graph_edges_materialized,
        imports_upgraded: servers.iter().map(|run| run.imports_upgraded).sum(),
        errors: servers.iter().map(|run| run.errors).sum(),
        duration_ms,
        servers,
    }
}

fn persist_run_metrics(
    connection: &Connection,
    summary: &SemanticRunSummary,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO semantic_run_metrics( \
           run_id, files_processed, symbols_processed, symbols_matched, reference_locations, definitions_resolved, \
           relations_persisted, graph_edges_materialized, imports_upgraded, errors \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(run_id) DO UPDATE SET \
           files_processed = excluded.files_processed, symbols_processed = excluded.symbols_processed, \
           symbols_matched = excluded.symbols_matched, reference_locations = excluded.reference_locations, \
           definitions_resolved = excluded.definitions_resolved, relations_persisted = excluded.relations_persisted, \
           graph_edges_materialized = excluded.graph_edges_materialized, imports_upgraded = excluded.imports_upgraded, \
           errors = excluded.errors",
        params![
            summary.run_id,
            to_i64(summary.files_processed),
            to_i64(summary.symbols_processed),
            to_i64(summary.symbols_matched),
            to_i64(summary.reference_locations),
            to_i64(summary.definitions_resolved),
            to_i64(summary.relations_persisted),
            to_i64(summary.graph_edges_materialized),
            to_i64(summary.imports_upgraded),
            to_i64(summary.errors),
        ],
    )?;
    Ok(())
}

fn finish_cancelled_run(
    connection: &Connection,
    project: &ProjectContext,
    run_id: &str,
    servers: Vec<SemanticServerRun>,
    started: Instant,
) -> Result<SemanticRunSummary, SemanticServiceError> {
    let duration_ms = elapsed_ms(started);
    let mut summary = summarize_run(
        project,
        run_id,
        AnalysisStatus::Cancelled,
        servers,
        0,
        duration_ms,
    );
    summary.relations_persisted = 0;
    summary.graph_edges_materialized = 0;
    summary.imports_upgraded = 0;
    persist_run_metrics(connection, &summary)?;
    finish_analysis_run(connection, run_id, AnalysisStatus::Cancelled, duration_ms)?;
    Ok(summary)
}

fn finish_analysis_run(
    connection: &Connection,
    run_id: &str,
    status: AnalysisStatus,
    duration_ms: u64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE analysis_runs SET status = ?2, finished_at = CURRENT_TIMESTAMP, duration_ms = ?3 WHERE id = ?1",
        params![run_id, status.as_str(), i64::try_from(duration_ms).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();
    deterministic_id("semantic-run", &[project_id, &nanos])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use lsp_enrichment::{LanguageServerKind, LspPosition, LspRange};

    use super::{
        byte_position_to_lsp, range_to_source, selected_kinds, utf16_column_to_byte, ActiveSymbol,
    };

    #[test]
    fn converts_utf16_lsp_columns_to_tree_sitter_byte_columns() {
        let text = "const 😀value = 1;\n";
        let position = LspPosition {
            line: 0,
            character: 8,
        };
        let source = super::lsp_position_to_source(text, &position).expect("source position");
        assert_eq!(source, (1, 10));
        assert_eq!(utf16_column_to_byte("😀value", 2), Some(4));
        assert_eq!(byte_position_to_lsp(text, 1, 10), Some(position));
    }

    #[test]
    fn converts_lsp_ranges_to_one_based_source_ranges() {
        let text = "alpha\nbeta\n";
        let range = LspRange {
            start: LspPosition {
                line: 1,
                character: 1,
            },
            end: LspPosition {
                line: 1,
                character: 3,
            },
        };
        let source = range_to_source(text, &range).expect("source range");
        assert_eq!(source.start_line, 2);
        assert_eq!(source.start_column, 1);
        assert_eq!(source.end_column, 3);
    }

    #[test]
    fn deduplicates_requested_server_kinds_without_reordering() {
        let selected = selected_kinds(&[
            LanguageServerKind::Pyright,
            LanguageServerKind::TypeScript,
            LanguageServerKind::Pyright,
        ]);
        assert_eq!(
            selected,
            vec![LanguageServerKind::Pyright, LanguageServerKind::TypeScript]
        );
    }

    #[test]
    fn smallest_unique_containing_symbol_can_be_selected() {
        let outer = ActiveSymbol {
            id: "outer".into(),
            file_id: "file".into(),
            name: "outer".into(),
            start_line: 1,
            start_column: 0,
            end_line: 10,
            end_column: 1,
        };
        let inner = ActiveSymbol {
            id: "inner".into(),
            file_id: "file".into(),
            name: "inner".into(),
            start_line: 3,
            start_column: 2,
            end_line: 5,
            end_column: 3,
        };
        assert!(super::contains_position(&outer, 4, 4));
        assert!(super::contains_position(&inner, 4, 4));
        assert!(super::symbol_extent(&inner) < super::symbol_extent(&outer));
    }
}
