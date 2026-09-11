use std::sync::Mutex;

use codetwin_core::{
    Database, GraphNeighborhood, GraphSummary, ImpactAnalysisService, ImpactReport,
    ImportReferenceRecord, IndexRunRecord, IndexSummary, ProjectIndexService, ProjectQueryService,
    ReferenceRefreshSummary, SemanticReferenceRecord, SemanticResolutionSummary,
    SemanticSymbolResolver, SourceFileRecord, SymbolRecord, SymbolReferenceObservationRecord,
    SymbolReferenceService, SymbolSearchQuery,
};
use project_discovery::ProjectProfile;
use tauri::Manager;

struct AppState {
    database: Mutex<Database>,
}

fn with_database<T>(
    state: &tauri::State<'_, AppState>,
    operation: impl FnOnce(&Database) -> Result<T, String>,
) -> Result<T, String> {
    let database = state
        .database
        .lock()
        .map_err(|_| "database state lock is poisoned".to_string())?;
    operation(&database)
}

#[tauri::command]
fn discover_project(path: String) -> Result<ProjectProfile, String> {
    project_discovery::discover_project(path).map_err(|error| error.to_string())
}

#[tauri::command]
fn index_project(path: String, state: tauri::State<'_, AppState>) -> Result<IndexSummary, String> {
    with_database(&state, |database| {
        ProjectIndexService::new(database)
            .index_project(path)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_project_files(
    project_id: String,
    search: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SourceFileRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .list_files(&project_id, search.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn get_file(
    file_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<SourceFileRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .get_file(&file_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_file_symbols(
    file_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SymbolRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .list_file_symbols(&file_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn search_symbols(
    project_id: String,
    search: SymbolSearchQuery,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SymbolRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .search_symbols(&project_id, &search)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn get_symbol(
    symbol_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<SymbolRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .get_symbol(&symbol_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn get_graph_summary(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<GraphSummary, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .graph_summary(&project_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn get_graph_neighborhood(
    node_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Option<GraphNeighborhood>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .graph_neighborhood(&node_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_dependencies(
    file_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ImportReferenceRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .dependencies(&file_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_dependents(
    file_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ImportReferenceRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .dependents(&file_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn analyze_file_impact(
    file_id: String,
    max_depth: usize,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Option<ImpactReport>, String> {
    with_database(&state, |database| {
        ImpactAnalysisService::new(database)
            .analyze_file(&file_id, max_depth, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn refresh_symbol_references(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<ReferenceRefreshSummary>, String> {
    with_database(&state, |database| {
        SymbolReferenceService::new(database)
            .refresh_project(&project_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_file_reference_observations(
    file_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SymbolReferenceObservationRecord>, String> {
    with_database(&state, |database| {
        SymbolReferenceService::new(database)
            .list_file_observations(&file_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn resolve_symbol_references(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<SemanticResolutionSummary>, String> {
    with_database(&state, |database| {
        SemanticSymbolResolver::new(database)
            .resolve_project(&project_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_file_semantic_resolutions(
    file_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SemanticReferenceRecord>, String> {
    with_database(&state, |database| {
        SemanticSymbolResolver::new(database)
            .list_file_resolutions(&file_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn index_history(
    project_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<IndexRunRecord>, String> {
    with_database(&state, |database| {
        ProjectQueryService::new(database)
            .index_history(&project_id, limit)
            .map_err(|error| error.to_string())
    })
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data_dir)?;
            let database = Database::open(app_data_dir.join("codetwin.sqlite3"))?;
            app.manage(AppState {
                database: Mutex::new(database),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            discover_project,
            index_project,
            list_project_files,
            get_file,
            list_file_symbols,
            search_symbols,
            get_symbol,
            get_graph_summary,
            get_graph_neighborhood,
            list_dependencies,
            list_dependents,
            analyze_file_impact,
            refresh_symbol_references,
            list_file_reference_observations,
            resolve_symbol_references,
            list_file_semantic_resolutions,
            index_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CodeTwin ML");
}
