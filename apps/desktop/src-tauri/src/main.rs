mod benchmark_commands;
mod database_commands;
mod go_security_commands;
mod guided_security_commands;
mod ml_commands;
mod native_agent_commands;
mod native_agent_reasoning_commands;
mod native_orchestration_commands;
mod network_assessment_commands;
mod qa_commands;
mod repair_commands;
mod runtime_commands;
mod security_campaign_commands;
mod security_fix_commands;
mod supply_chain_commands;
mod web_policy_commands;
mod web_security_commands;
mod workspace_commands;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use benchmark_commands::{
    dataset_benchmark_status, export_dataset_benchmark, list_dataset_benchmarks,
    run_dataset_benchmark,
};
use codetwin_core::{
    AuthorizedWebSecurityStore, CodeQualityService, CodeSecurityService, Database,
    FindingEvidenceRecord, GraphNeighborhood, GraphSummary, GuidedSecurityStore,
    ImpactAnalysisService, ImpactReport, ImportReferenceRecord, IndexRunRecord, IndexSummary,
    LanguageServerConfig, LanguageServerConfigService, LanguageServerKind, ProjectIndexService,
    ProjectQueryService, QualityFindingRecord, QualityRuleRecord, QualityRunRecord,
    QualityRunSummary, ReferenceRefreshSummary, RepairApplicationService, SecurityFindingRecord,
    SecurityRuleRecord, SecurityRunRecord, SecurityRunSummary, SemanticEnrichmentRequest,
    SemanticEnrichmentService, SemanticImportResolutionRecord, SemanticQueryService,
    SemanticReferenceRecord, SemanticRelationDirection, SemanticRelationRecord,
    SemanticResolutionSummary, SemanticRunRecord, SemanticRunSummary, SemanticSymbolResolver,
    SemanticSymbolStateRecord, SourceFileRecord, SymbolRecord, SymbolReferenceObservationRecord,
    SymbolReferenceService, SymbolSearchQuery, WorkspaceService,
};
use database_commands::{
    database_history, list_database_artifacts, list_database_evidence, list_database_findings,
    list_database_rules, run_database_analysis,
};
use go_security_commands::{
    approve_automated_security_flow, enqueue_approved_security_flow, get_automated_flow_followup,
    get_automated_security_flow, go_security_dispatch_preview, go_security_engine_readiness,
    list_approved_flow_queue, list_go_dispatch_audit, prepare_automated_security_flow,
    refine_go_security_task_plan, remove_queued_security_flow, run_approved_security_flow_queue,
    run_automated_security_flow, run_native_go_review, suggest_automated_flow_followup,
    suggest_go_security_task_plan,
};
use guided_security_commands::{
    approve_guided_security_plan, compare_guided_security_scans, correlate_guided_security_sources,
    get_guided_security_session, guided_security_risk_graph, guided_security_scorecard,
    list_guided_security_activity, list_guided_security_plan_items,
    list_guided_security_retest_candidates, list_guided_security_retests,
    list_guided_security_sessions, prepare_guided_security_fix, prepare_guided_security_test,
    retest_guided_security_finding,
};
use ml_commands::{
    link_ml_finding, list_ml_finding_links, ml_inference_history, ml_inference_plan, ml_models,
    ml_sidecar_capabilities, ml_sidecar_health, ml_sidecar_identity, run_ml_file_generation,
    run_ml_file_inference,
};
use native_agent_commands::{
    approve_native_agent_review, assemble_native_review_attestation, audit_native_evidence_history,
    cancel_native_agent_review, clear_native_agent_memory, create_native_agent_review,
    create_native_task_review, list_native_action_receipts, list_native_agent_handoffs,
    list_native_agent_memory, list_native_agent_reviews, native_agent_report, native_agent_review,
    prepare_native_review_attestation, run_native_agent_review, verify_native_agent_run,
    verify_native_review_attestation, verify_native_review_with_signer_policy,
};
use native_agent_reasoning_commands::{
    interpret_native_agent_review, native_agent_insight, native_model_readiness,
    suggest_native_agent_roles, suggest_native_task_plan,
};
use native_orchestration_commands::{
    clear_native_knowledge, index_native_neural_memory, inspect_authorized_dns,
    inspect_authorized_network_services, list_authorized_network_inspections,
    native_delegation_graph, native_isolated_scan_readiness, native_knowledge_graph,
    native_neural_readiness, native_task_schedule, native_worker_audit,
    probe_native_neural_provider, reason_native_knowledge_graph, run_native_isolated_scan,
    search_native_knowledge, search_native_neural_memory, verify_worker_cleanup,
    worker_cleanup_hold_count,
};
use network_assessment_commands::{
    approve_network_assessment, cancel_network_assessment, get_network_assessment,
    list_network_assessments, prepare_network_assessment, run_network_assessment,
};
use project_discovery::ProjectProfile;
use qa_commands::{
    approve_qa_execution_plan, cancel_qa_execution, create_qa_execution_plan, list_qa_artifacts,
    list_qa_execution_plans, list_qa_execution_runs, list_qa_frameworks, qa_discovery_history,
    qa_execution_availability, qa_toolchain_sha256, run_qa_discovery, run_qa_execution_plan,
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
use security_campaign_commands::{
    analyze_security_remediation_campaign, approve_security_remediation_campaign_plan,
    assess_security_remediation_campaign_rollback,
    begin_security_remediation_campaign_completion_verification,
    cancel_security_remediation_campaign, complete_security_remediation_campaign,
    create_security_remediation_campaign,
    finalize_security_remediation_campaign_completion_verification,
    get_security_remediation_campaign, list_security_remediation_campaign_events,
    list_security_remediation_campaign_findings, list_security_remediation_campaign_relationships,
    list_security_remediation_campaigns, pause_security_remediation_campaign,
    resume_security_remediation_campaign, rollback_security_remediation_campaign_fix,
    security_remediation_campaign_before_after, security_remediation_campaign_debt,
    security_remediation_campaign_regression_tracking, security_remediation_campaign_summary,
    skip_security_remediation_campaign_finding, start_security_remediation_campaign,
    sync_security_remediation_campaign,
};
use security_fix_commands::{
    analyze_security_fix_overlap, apply_security_fix, approve_security_fix,
    evaluate_security_fix_eligibility, generate_security_fix_patch, get_security_fix_attempt,
    list_security_fix_attempts, list_security_fix_events, list_security_fix_validation,
    prepare_security_fix, propose_security_fix_replacement, review_security_fix,
    rollback_security_fix, run_security_fix_validation,
};
use supply_chain_commands::{
    dependency_audit_history, export_dependency_sbom, list_dependency_findings,
    list_dependency_inventory, list_secret_findings, list_secret_history_findings,
    run_dependency_audit, run_secret_history_scan, run_secret_scan, secret_history_runs,
    secret_scan_history,
};
use tauri::Manager;
use web_security_commands::{
    cancel_web_security_scan, export_web_security_report, generate_web_security_report,
    get_web_security_scan, list_source_routes, list_web_security_endpoints,
    list_web_security_evidence, list_web_security_findings, list_web_security_scans,
    list_web_source_endpoint_links, start_web_security_scan, update_web_security_finding_status,
};
use workspace_commands::{
    add_website, check_website, get_app_preferences, list_projects, list_websites, recent_activity,
    remove_project, remove_website, save_app_preferences, search_workspace, system_status,
    workspace_summary,
};

struct AppState {
    database: Mutex<Database>,
    database_path: PathBuf,
    assessment_running: Arc<AtomicBool>,
    index_cancelled: Arc<AtomicBool>,
    index_running: Arc<AtomicBool>,
    semantic_cancelled: Arc<AtomicBool>,
    semantic_running: Arc<AtomicBool>,
    quality_running: Arc<AtomicBool>,
    security_running: Arc<AtomicBool>,
    ml_running: Arc<AtomicBool>,
    web_security_cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

// Reserve existing analyzer flags for the complete assessment; Drop also releases on panic.
struct AssessmentReservations(Vec<Arc<AtomicBool>>);
impl Drop for AssessmentReservations {
    fn drop(&mut self) {
        for flag in &self.0 {
            flag.store(false, Ordering::SeqCst);
        }
    }
}
impl AssessmentReservations {
    fn acquire(flags: &[&Arc<AtomicBool>]) -> Result<Self, String> {
        let mut reservations = Self(Vec::new());
        for flag in flags {
            if flag
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err("Indexing, semantic enrichment or analysis is already running; retry after it finishes".into());
            }
            reservations.0.push(Arc::clone(flag));
        }
        Ok(reservations)
    }
}
fn reserve_assessment(state: &AppState) -> Result<AssessmentReservations, String> {
    AssessmentReservations::acquire(&[
        &state.assessment_running,
        &state.index_running,
        &state.semantic_running,
        &state.quality_running,
        &state.security_running,
    ])
}
#[tauri::command]
async fn create_assessment_plan(
    request: codetwin_core::assessment_jobs::AssessmentPlanRequest,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::assessment_jobs::AssessmentJob, String> {
    let reservations = reserve_assessment(&state)?;
    let path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _reservations = reservations;
        let database = Database::open(path).map_err(|e| e.to_string())?;
        codetwin_core::assessment_jobs::AssessmentJobs::new(&database).create_plan(request)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn list_assessment_jobs(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<codetwin_core::assessment_jobs::AssessmentJob>, String> {
    with_database(&state, |database| {
        codetwin_core::assessment_jobs::AssessmentJobs::new(database).list(&project_id)
    })
}
#[tauri::command]
fn cancel_assessment_job(id: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    with_database(&state, |database| {
        codetwin_core::assessment_jobs::AssessmentJobs::new(database).cancel(&id)
    })
}
#[tauri::command]
async fn run_assessment_job(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::assessment_jobs::AssessmentJob, String> {
    let reservations = reserve_assessment(&state)?;
    let path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _reservations = reservations;
        let database = Database::open(path).map_err(|e| e.to_string())?;
        codetwin_core::assessment_jobs::AssessmentJobs::new(&database).execute(&id)
    })
    .await
    .map_err(|e| e.to_string())?
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

fn git_project_root(
    state: &tauri::State<'_, AppState>,
    project_id: &str,
) -> Result<String, String> {
    with_database(state, |database| {
        codetwin_core::WorkspaceService::new(database)
            .get_project(project_id)
            .map_err(|error| error.to_string())?
            .map(|project| project.root_path)
            .ok_or_else(|| "Project not found".to_string())
    })
}

#[tauri::command]
async fn git_review_status(
    project_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::GitReviewStatus, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::review_git_status(root).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn git_create_reviewed_branch(
    project_id: String,
    branch: String,
    expected_head: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::GitBranchReceipt, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::create_reviewed_git_branch(root, &branch, &expected_head)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn git_prepare_selected_commit(
    project_id: String,
    request: codetwin_core::GitCommitRequest,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::GitCommitPreview, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::prepare_selected_commit(root, &request).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn git_apply_selected_commit(
    project_id: String,
    request: codetwin_core::GitCommitRequest,
    expected_digest: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::GitCommitReceipt, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::apply_selected_commit(root, &request, &expected_digest)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn git_publish_commit(
    project_id: String,
    target: codetwin_core::git_publication::GitPublishTarget,
    token: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::git_publication::GitPublishReceipt, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::git_publication::publish_commit(root, &target, &token)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn git_open_draft_pr(
    project_id: String,
    target: codetwin_core::git_publication::GitPublishTarget,
    base: String,
    title: String,
    body: String,
    token: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::git_publication::open_draft_pr(root, &target, &base, &title, &body, &token)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn git_review_file(
    project_id: String,
    path: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::GitFileReview, String> {
    let root = git_project_root(&state, &project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        codetwin_core::review_git_file(root, &path).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
fn recent_security_tool_runs(
    project_id: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<codetwin_core::CatalogRunSummary>, String> {
    with_database(&state, |database| {
        codetwin_core::ToolCatalogService::new(database).recent_runs(project_id.as_deref(), limit)
    })
}

#[tauri::command]
fn list_security_tools(
    project_id: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<codetwin_core::CatalogTool>, String> {
    with_database(&state, |database| {
        codetwin_core::ToolCatalogService::new(database).list(project_id.as_deref())
    })
}

#[tauri::command]
fn discover_project(path: String) -> Result<ProjectProfile, String> {
    project_discovery::discover_project(path).map_err(|error| error.to_string())
}

#[tauri::command]
async fn index_project(
    path: String,
    full_rebuild: Option<bool>,
    state: tauri::State<'_, AppState>,
) -> Result<IndexSummary, String> {
    if state.index_running.swap(true, Ordering::SeqCst) {
        return Err("project indexing is already running".to_string());
    }
    state.index_cancelled.store(false, Ordering::SeqCst);
    let cancelled = Arc::clone(&state.index_cancelled);
    let running = Arc::clone(&state.index_running);
    let database_path = state.database_path.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(database_path).map_err(|error| error.to_string())?;
        let service = ProjectIndexService::new(&database);
        let result = if full_rebuild.unwrap_or(false) {
            service.rebuild_project_with_cancel(path, cancelled.as_ref())
        } else {
            service.index_project_with_cancel(path, cancelled.as_ref())
        };
        result.map_err(|error| error.to_string())
    })
    .await;
    running.store(false, Ordering::SeqCst);
    result.map_err(|error| error.to_string())?
}

#[tauri::command]
fn cancel_project_index(state: tauri::State<'_, AppState>) -> bool {
    let running = state.index_running.load(Ordering::SeqCst)
        && !state.assessment_running.load(Ordering::SeqCst);
    if running {
        state.index_cancelled.store(true, Ordering::SeqCst);
    }
    running
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
    let running = state.semantic_running.load(Ordering::SeqCst)
        && !state.assessment_running.load(Ordering::SeqCst);
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
fn list_quality_rules(state: tauri::State<'_, AppState>) -> Result<Vec<QualityRuleRecord>, String> {
    with_database(&state, |database| {
        Ok(CodeQualityService::new(database).rules())
    })
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
#[allow(clippy::too_many_arguments)]
fn review_security_finding(
    project_id: String,
    finding_id: String,
    expected_run_id: String,
    expected_content_hash: Option<String>,
    verdict: String,
    note: String,
    state: tauri::State<'_, AppState>,
) -> Result<codetwin_core::SecurityFindingReview, String> {
    with_database(&state, |database| {
        codetwin_core::SecurityReviewService::new(database)
            .review(
                &project_id,
                &finding_id,
                &expected_run_id,
                expected_content_hash.as_deref(),
                &verdict,
                &note,
            )
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
fn list_security_finding_reviews(
    project_id: String,
    finding_id: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<codetwin_core::SecurityFindingReview>, String> {
    with_database(&state, |database| {
        codetwin_core::SecurityReviewService::new(database)
            .list(&project_id, finding_id.as_deref(), limit)
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
    with_database(&state, |database| {
        Ok(CodeSecurityService::new(database).rules())
    })
}

fn release_smoke_request() -> Result<Option<(PathBuf, PathBuf)>, String> {
    let mut args = std::env::args_os().skip(1);
    let Some(mode) = args.next() else {
        return Ok(None);
    };
    if mode != "--release-smoke" {
        return Ok(None);
    }
    let fixture = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "--release-smoke requires a fixture repository path".to_string())?;
    let database = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "--release-smoke requires a SQLite database path".to_string())?;
    if args.next().is_some() {
        return Err("--release-smoke accepts exactly two positional arguments".to_string());
    }
    Ok(Some((fixture, database)))
}

fn run_release_smoke(
    fixture: &std::path::Path,
    database_path: &std::path::Path,
) -> Result<(), String> {
    let fixture = std::fs::canonicalize(fixture)
        .map_err(|error| format!("release smoke fixture could not be opened: {error}"))?;
    let fixture_metadata = std::fs::symlink_metadata(&fixture)
        .map_err(|error| format!("release smoke fixture metadata failed: {error}"))?;
    if fixture_metadata.file_type().is_symlink() || !fixture_metadata.is_dir() {
        return Err("release smoke fixture must be a real directory".to_string());
    }

    let parent = database_path
        .parent()
        .ok_or_else(|| "release smoke database path has no parent directory".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("release smoke database directory failed: {error}"))?;
    if database_path.exists() {
        std::fs::remove_file(database_path)
            .map_err(|error| format!("release smoke database cleanup failed: {error}"))?;
    }

    let database =
        Database::open(database_path).map_err(|error| format!("SQLite startup failed: {error}"))?;
    let index = ProjectIndexService::new(&database)
        .index_project(&fixture)
        .map_err(|error| format!("fixture indexing failed: {error}"))?;
    let files = ProjectQueryService::new(&database)
        .list_files(&index.project_id, None, 500)
        .map_err(|error| format!("indexed file query failed: {error}"))?;
    if files.is_empty() {
        return Err("release smoke indexed zero fixture files".to_string());
    }
    let graph = ProjectQueryService::new(&database)
        .graph_summary(&index.project_id)
        .map_err(|error| format!("dashboard graph query failed: {error}"))?;
    let workspace = WorkspaceService::new(&database)
        .summary()
        .map_err(|error| format!("dashboard workspace summary failed: {error}"))?;
    if workspace.project_count == 0 {
        return Err("dashboard workspace summary did not expose the indexed project".to_string());
    }

    println!(
        "{}",
        serde_json::json!({
            "status": "ok",
            "project_id": index.project_id,
            "files": files.len(),
            "graph_nodes": graph.node_count,
            "graph_edges": graph.edge_count,
            "workspace_projects": workspace.project_count,
            "database": database_path.display().to_string(),
        })
    );
    Ok(())
}

fn main() {
    match release_smoke_request() {
        Ok(Some((fixture, database_path))) => {
            if let Err(error) = run_release_smoke(&fixture, &database_path) {
                eprintln!("CodeTwin ML release smoke failed: {error}");
                std::process::exit(1);
            }
            return;
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("CodeTwin ML release smoke arguments are invalid: {error}");
            std::process::exit(2);
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data_dir)?;
            let database_path = app_data_dir.join("codetwin.sqlite3");
            let database = Database::open(&database_path)?;
            codetwin_core::assessment_jobs::AssessmentJobs::new(&database)
                .recover_interrupted()
                .map_err(std::io::Error::other)?;
            codetwin_core::native_agents::NativeAgents::new(&database)
                .recover_interrupted()
                .map_err(std::io::Error::other)?;
            codetwin_core::native_flow_queue::NativeFlowQueue::new(&database)
                .recover_interrupted()
                .map_err(std::io::Error::other)?;
            codetwin_core::network_assessment::NetworkAssessment::new(&database)
                .recover_interrupted()
                .map_err(std::io::Error::other)?;
            codetwin_core::native_worker_audit::WorkerAudit::new(&database)
                .recover_interrupted()
                .map_err(std::io::Error::other)?;
            let repair_backup_root = app_data_dir.join("repair-backups");
            RepairApplicationService::new(&database)
                .recover_interrupted_applications(&repair_backup_root)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            AuthorizedWebSecurityStore::new(&database)
                .recover_interrupted_scans()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            GuidedSecurityStore::new(&database)
                .recover_interrupted_sessions()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            app.manage(AppState {
                database: Mutex::new(database),
                database_path,
                assessment_running: Arc::new(AtomicBool::new(false)),
                index_cancelled: Arc::new(AtomicBool::new(false)),
                index_running: Arc::new(AtomicBool::new(false)),
                semantic_cancelled: Arc::new(AtomicBool::new(false)),
                semantic_running: Arc::new(AtomicBool::new(false)),
                quality_running: Arc::new(AtomicBool::new(false)),
                security_running: Arc::new(AtomicBool::new(false)),
                ml_running: Arc::new(AtomicBool::new(false)),
                web_security_cancellations: Arc::new(Mutex::new(HashMap::new())),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            prepare_network_assessment,
            approve_network_assessment,
            run_network_assessment,
            cancel_network_assessment,
            list_network_assessments,
            get_network_assessment,
            create_assessment_plan,
            list_assessment_jobs,
            cancel_assessment_job,
            run_assessment_job,
            create_native_agent_review,
            create_native_task_review,
            go_security_engine_readiness,
            go_security_dispatch_preview,
            prepare_automated_security_flow,
            get_automated_security_flow,
            get_automated_flow_followup,
            suggest_automated_flow_followup,
            approve_automated_security_flow,
            run_automated_security_flow,
            list_approved_flow_queue,
            enqueue_approved_security_flow,
            remove_queued_security_flow,
            run_approved_security_flow_queue,
            list_go_dispatch_audit,
            refine_go_security_task_plan,
            run_native_go_review,
            suggest_go_security_task_plan,
            native_task_schedule,
            native_worker_audit,
            native_neural_readiness,
            inspect_authorized_network_services,
            list_authorized_network_inspections,
            inspect_authorized_dns,
            probe_native_neural_provider,
            index_native_neural_memory,
            search_native_neural_memory,
            reason_native_knowledge_graph,
            list_native_agent_reviews,
            native_agent_review,
            approve_native_agent_review,
            run_native_agent_review,
            cancel_native_agent_review,
            native_delegation_graph,
            search_native_knowledge,
            native_knowledge_graph,
            clear_native_knowledge,
            native_isolated_scan_readiness,
            run_native_isolated_scan,
            worker_cleanup_hold_count,
            verify_worker_cleanup,
            native_agent_report,
            list_native_agent_memory,
            clear_native_agent_memory,
            list_native_action_receipts,
            list_native_agent_handoffs,
            verify_native_agent_run,
            audit_native_evidence_history,
            prepare_native_review_attestation,
            assemble_native_review_attestation,
            verify_native_review_attestation,
            verify_native_review_with_signer_policy,
            native_model_readiness,
            native_agent_insight,
            interpret_native_agent_review,
            suggest_native_agent_roles,
            suggest_native_task_plan,
            list_security_tools,
            recent_security_tool_runs,
            git_review_status,
            git_review_file,
            git_create_reviewed_branch,
            git_prepare_selected_commit,
            git_apply_selected_commit,
            git_publish_commit,
            git_open_draft_pr,
            discover_project,
            index_project,
            cancel_project_index,
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
            review_security_finding,
            list_security_finding_reviews,
            list_security_evidence,
            security_history,
            list_security_rules,
            run_secret_scan,
            run_secret_history_scan,
            list_secret_history_findings,
            secret_history_runs,
            export_dependency_sbom,
            dataset_benchmark_status,
            run_dataset_benchmark,
            list_dataset_benchmarks,
            export_dataset_benchmark,
            list_secret_findings,
            secret_scan_history,
            run_dependency_audit,
            list_dependency_findings,
            list_dependency_inventory,
            dependency_audit_history,
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
            qa_execution_availability,
            qa_toolchain_sha256,
            create_qa_execution_plan,
            approve_qa_execution_plan,
            list_qa_execution_plans,
            list_qa_execution_runs,
            run_qa_execution_plan,
            cancel_qa_execution,
            ml_sidecar_identity,
            ml_sidecar_health,
            ml_sidecar_capabilities,
            ml_models,
            ml_inference_plan,
            run_ml_file_inference,
            run_ml_file_generation,
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
            list_projects,
            remove_project,
            list_websites,
            add_website,
            check_website,
            remove_website,
            workspace_summary,
            recent_activity,
            search_workspace,
            get_app_preferences,
            save_app_preferences,
            system_status,
            prepare_guided_security_test,
            approve_guided_security_plan,
            get_guided_security_session,
            list_guided_security_sessions,
            list_guided_security_plan_items,
            list_guided_security_activity,
            correlate_guided_security_sources,
            guided_security_scorecard,
            guided_security_risk_graph,
            compare_guided_security_scans,
            prepare_guided_security_fix,
            retest_guided_security_finding,
            list_guided_security_retest_candidates,
            list_guided_security_retests,
            create_security_remediation_campaign,
            analyze_security_remediation_campaign,
            approve_security_remediation_campaign_plan,
            assess_security_remediation_campaign_rollback,
            rollback_security_remediation_campaign_fix,
            start_security_remediation_campaign,
            pause_security_remediation_campaign,
            resume_security_remediation_campaign,
            cancel_security_remediation_campaign,
            sync_security_remediation_campaign,
            begin_security_remediation_campaign_completion_verification,
            finalize_security_remediation_campaign_completion_verification,
            complete_security_remediation_campaign,
            skip_security_remediation_campaign_finding,
            get_security_remediation_campaign,
            list_security_remediation_campaigns,
            list_security_remediation_campaign_findings,
            list_security_remediation_campaign_relationships,
            list_security_remediation_campaign_events,
            security_remediation_campaign_summary,
            security_remediation_campaign_before_after,
            security_remediation_campaign_regression_tracking,
            security_remediation_campaign_debt,
            evaluate_security_fix_eligibility,
            prepare_security_fix,
            generate_security_fix_patch,
            propose_security_fix_replacement,
            review_security_fix,
            approve_security_fix,
            get_security_fix_attempt,
            list_security_fix_attempts,
            list_security_fix_validation,
            list_security_fix_events,
            analyze_security_fix_overlap,
            apply_security_fix,
            rollback_security_fix,
            run_security_fix_validation,
            start_web_security_scan,
            cancel_web_security_scan,
            get_web_security_scan,
            list_web_security_scans,
            list_web_security_endpoints,
            list_source_routes,
            list_web_source_endpoint_links,
            list_web_security_findings,
            list_web_security_evidence,
            update_web_security_finding_status,
            generate_web_security_report,
            export_web_security_report,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CodeTwin ML");
}

#[cfg(test)]
mod assessment_reservation_tests {
    use super::*;
    #[test]
    fn failed_reservation_releases_only_flags_it_owns() {
        let free = Arc::new(AtomicBool::new(false));
        let occupied = Arc::new(AtomicBool::new(true));
        assert!(AssessmentReservations::acquire(&[&free, &occupied]).is_err());
        assert!(!free.load(Ordering::SeqCst));
        assert!(occupied.load(Ordering::SeqCst));
    }
    #[test]
    fn worker_unwind_releases_reservations() {
        let flag = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind(|| {
            let _guard = AssessmentReservations::acquire(&[&flag]).unwrap();
            assert!(flag.load(Ordering::SeqCst));
            panic!("fixture worker failure");
        });
        assert!(result.is_err());
        assert!(!flag.load(Ordering::SeqCst));
    }
}
