mod database_commands;
mod ml_commands;
mod qa_commands;
mod repair_commands;
mod runtime_commands;

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use codetwin_core::{
    CodeQualityService, CodeSecurityService, Database, FindingEvidenceRecord, GraphNeighborhood,
    GraphSummary, ImpactAnalysisService, ImpactReport, ImportReferenceRecord, IndexRunRecord,
    IndexSummary, LanguageServerConfig, LanguageServerConfigService, LanguageServerKind,
    ProjectIndexService, ProjectQueryService, QualityFindingRecord, QualityRuleRecord,
    QualityRunRecord, QualityRunSummary, ReferenceRefreshSummary, SecurityFindingRecord,
    SecurityRuleRecord, SecurityRunRecord, SecurityRunSummary, SemanticEnrichmentRequest,
    SemanticEnrichmentService, SemanticImportResolutionRecord, SemanticQueryService,
    SemanticReferenceRecord, SemanticRelationDirection, SemanticRelationRecord,
    SemanticResolutionSummary, SemanticRunRecord, SemanticRunSummary, SemanticSymbolResolver,
    SemanticSymbolStateRecord, SourceFileRecord, SymbolRecord, SymbolReferenceObservationRecord,
    SymbolReferenceService, SymbolSearchQuery,
};
use database_commands::{
    database_history, list_database_artifacts, list_database_evidence, list_database_findings,
    list_database_rules, run_database_analysis,
};
use ml_commands::{
    link_ml_finding, list_ml_finding_links, ml_inference_history, ml_inference_plan, ml_models,
    ml_sidecar_capabilities, ml_sidecar_health, run_ml_file_inference,
};
use project_discovery::ProjectProfile;
use qa_commands::{
    list_qa_artifacts, list_qa_frameworks, qa_discovery_history, run_qa_discovery,
};
use repair_commands::{
    add_repair_file_replacement, apply_repair_plan, approve_repair_plan, create_repair_plan,
    list_repair_application_items, list_repair_candidate_findings, list_repair_changes,
    list_repair_plans, list_repair_verification_items, read_repair_source, reject_repair_plan,
    repair_application_history, repair_verification_history, rollback_repair_application,
    verify_repair_plan,
};
use runtime_commands::{
    list_runtime_artifacts, list_runtime_evidence, list_runtime_findings, list_runtime_rules,
    run_runtime_analysis, runtime_history,
};
use tauri::Manager;

struct AppState {
    database: Mutex<Database>,
    database_path: PathBuf,
    semantic_cancelled: Arc<AtomicBool>,
    semantic_running: Arc<AtomicBool>,
    quality_running: Arc<AtomicBool>,
    security_running: Arc<AtomicBool>,
    ml_running: Arc<AtomicBool>,
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

#[tauri::command]
fn list_language_server_configs(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<LanguageServerConfig>, String> {
    with_database(&state, |database| {
        LanguageServerConfigService::new(database)
            .list()
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn set_language_server_config(
    config: LanguageServerConfig,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    with_database(&state, |database| {
        LanguageServerConfigService::new(database)
            .set(&config)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn remove_language_server_config(
    kind: LanguageServerKind,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    with_database(&state, |database| {
        LanguageServerConfigService::new(database)
            .remove(kind)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
async fn enrich_project_semantics(
    project_id: String,
    request: SemanticEnrichmentRequest,
    state: tauri::State<'_, AppState>,
) -> Result<SemanticRunSummary, String> {
    if state.semantic_running.swap(true, Ordering::SeqCst) {
        return Err("semantic enrichment is already running".to_string());
    }
    state.semantic_cancelled.store(false, Ordering::SeqCst);

    let database_path = state.database_path.clone();
    let cancelled = Arc::clone(&state.semantic_cancelled);
    let running = Arc::clone(&state.semantic_running);
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(database_path).map_err(|error| error.to_string())?;
        SemanticEnrichmentService::new(&database)
            .enrich_project_with_cancel(&project_id, &request, cancelled.as_ref())
            .map_err(|error| error.to_string())
    })
    .await;
    running.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
fn cancel_semantic_enrichment(state: tauri::State<'_, AppState>) -> bool {
    let running = state.semantic_running.load(Ordering::SeqCst);
    if running {
        state.semantic_cancelled.store(true, Ordering::SeqCst);
    }
    running
}

#[tauri::command]
fn list_symbol_semantic_relations(
    symbol_id: String,
    direction: SemanticRelationDirection,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SemanticRelationRecord>, String> {
    with_database(&state, |database| {
        SemanticQueryService::new(database)
            .relations_for_symbol(&symbol_id, direction, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn get_symbol_semantic_state(
    symbol_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<SemanticSymbolStateRecord>, String> {
    with_database(&state, |database| {
        SemanticQueryService::new(database)
            .symbol_state(&symbol_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_file_semantic_imports(
    file_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SemanticImportResolutionRecord>, String> {
    with_database(&state, |database| {
        SemanticQueryService::new(database)
            .semantic_imports(&file_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn semantic_history(
    project_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SemanticRunRecord>, String> {
    with_database(&state, |database| {
        SemanticQueryService::new(database)
            .history(&project_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
async fn run_code_quality(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<QualityRunSummary, String> {
    if state.quality_running.swap(true, Ordering::SeqCst) {
        return Err("code quality analysis is already running".to_string());
    }
    let database_path = state.database_path.clone();
    let running = Arc::clone(&state.quality_running);
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(database_path).map_err(|error| error.to_string())?;
        CodeQualityService::new(&database)
            .analyze_project(&project_id)
            .map_err(|error| error.to_string())
    })
    .await;
    running.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
fn list_quality_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<QualityFindingRecord>, String> {
    with_database(&state, |database| {
        CodeQualityService::new(database)
            .list_findings(&project_id, status.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_finding_evidence(
    finding_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FindingEvidenceRecord>, String> {
    with_database(&state, |database| {
        CodeQualityService::new(database)
            .finding_evidence(&finding_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn quality_history(
    project_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<QualityRunRecord>, String> {
    with_database(&state, |database| {
        CodeQualityService::new(database)
            .history(&project_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_quality_rules(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<QualityRuleRecord>, String> {
    with_database(&state, |database| Ok(CodeQualityService::new(database).rules()))
}

#[tauri::command]
async fn run_security_analysis(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityRunSummary, String> {
    if state.security_running.swap(true, Ordering::SeqCst) {
        return Err("security analysis is already running".to_string());
    }
    let database_path = state.database_path.clone();
    let running = Arc::clone(&state.security_running);
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(database_path).map_err(|error| error.to_string())?;
        CodeSecurityService::new(&database)
            .analyze_project(&project_id)
            .map_err(|error| error.to_string())
    })
    .await;
    running.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
fn list_security_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityFindingRecord>, String> {
    with_database(&state, |database| {
        CodeSecurityService::new(database)
            .list_findings(&project_id, status.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_security_evidence(
    finding_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<FindingEvidenceRecord>, String> {
    with_database(&state, |database| {
        CodeSecurityService::new(database)
            .finding_evidence(&finding_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn security_history(
    project_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRunRecord>, String> {
    with_database(&state, |database| {
        CodeSecurityService::new(database)
            .history(&project_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_security_rules(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityRuleRecord>, String> {
    with_database(&state, |database| Ok(CodeSecurityService::new(database).rules()))
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data_dir)?;
            let database_path = app_data_dir.join("codetwin.sqlite3");
            let database = Database::open(&database_path)?;
            app.manage(AppState {
                database: Mutex::new(database),
                database_path,
                semantic_cancelled: Arc::new(AtomicBool::new(false)),
                semantic_running: Arc::new(AtomicBool::new(false)),
                quality_running: Arc::new(AtomicBool::new(false)),
                security_running: Arc::new(AtomicBool::new(false)),
                ml_running: Arc::new(AtomicBool::new(false)),
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
            list_language_server_configs,
            set_language_server_config,
            remove_language_server_config,
            enrich_project_semantics,
            cancel_semantic_enrichment,
            list_symbol_semantic_relations,
            get_symbol_semantic_state,
            list_file_semantic_imports,
            semantic_history,
            run_code_quality,
            list_quality_findings,
            list_finding_evidence,
            quality_history,
            list_quality_rules,
            run_security_analysis,
            list_security_findings,
            list_security_evidence,
            security_history,
            list_security_rules,
            run_database_analysis,
            list_database_artifacts,
            list_database_findings,
            list_database_evidence,
            database_history,
            list_database_rules,
            run_runtime_analysis,
            list_runtime_artifacts,
            list_runtime_findings,
            list_runtime_evidence,
            runtime_history,
            list_runtime_rules,
            run_qa_discovery,
            list_qa_artifacts,
            list_qa_frameworks,
            qa_discovery_history,
            ml_sidecar_health,
            ml_sidecar_capabilities,
            ml_models,
            ml_inference_plan,
            run_ml_file_inference,
            ml_inference_history,
            link_ml_finding,
            list_ml_finding_links,
            create_repair_plan,
            add_repair_file_replacement,
            approve_repair_plan,
            reject_repair_plan,
            verify_repair_plan,
            list_repair_plans,
            list_repair_changes,
            repair_verification_history,
            list_repair_verification_items,
            read_repair_source,
            list_repair_candidate_findings,
            apply_repair_plan,
            rollback_repair_application,
            repair_application_history,
            list_repair_application_items,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CodeTwin ML");
}
