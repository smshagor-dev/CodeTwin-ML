//! Desktop commands for security intelligence (cross-analyzer correlation,
//! audited suppressions, policy gate snapshots) and temporal knowledge
//! (memory history, held-back conflicts, "as of" graph reads, neural
//! embedding of project memory through a loopback model).
//!
//! The acting principal is always the local operator; suppressions and
//! conflict resolution are additionally authorized as approvals, which
//! automation principals can never hold.
use codetwin_core::collaboration::{Collaboration, PrincipalKind};
use codetwin_core::knowledge_memory::{
    EmbeddingDestination, EmbeddingProvider, EvidenceGraph, HttpEmbedder, KnowledgeConflict,
    KnowledgeMemory, MemoryVersion,
};
use codetwin_core::security_intelligence::{
    CorrelationReport, SecurityIntelligence, SecurityPolicy, Suppression, SuppressionEvent,
    SuppressionScope,
};
use serde::Serialize;

use crate::workflow_commands::{db, operator};

fn acting_operator(db: &codetwin_core::Database) -> Result<String, String> {
    let me = operator();
    Collaboration::new(db).ensure_principal(&me, &me, PrincipalKind::Human)?;
    Ok(me)
}

#[tauri::command]
pub fn security_correlation_report(
    project_id: String,
    policy: Option<SecurityPolicy>,
    app: tauri::AppHandle,
) -> Result<CorrelationReport, String> {
    SecurityIntelligence::new(&db(&app)?).report(&project_id, &policy.unwrap_or_default())
}

#[derive(Serialize)]
pub struct SnapshotReceipt {
    id: String,
    sha256: String,
    report: CorrelationReport,
}

#[tauri::command]
pub fn security_correlation_snapshot(
    project_id: String,
    policy: Option<SecurityPolicy>,
    app: tauri::AppHandle,
) -> Result<SnapshotReceipt, String> {
    let (id, sha256, report) = SecurityIntelligence::new(&db(&app)?)
        .snapshot(&project_id, &policy.unwrap_or_default())?;
    Ok(SnapshotReceipt { id, sha256, report })
}

#[tauri::command]
pub fn verify_security_snapshot(snapshot_id: String, app: tauri::AppHandle) -> Result<bool, String> {
    SecurityIntelligence::new(&db(&app)?).verify_snapshot(&snapshot_id)
}

#[derive(Serialize)]
pub struct SuppressionOverview {
    suppressions: Vec<Suppression>,
    events: Vec<SuppressionEvent>,
}

#[tauri::command]
pub fn list_security_suppressions(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<SuppressionOverview, String> {
    let db = db(&app)?;
    let intel = SecurityIntelligence::new(&db);
    Ok(SuppressionOverview {
        suppressions: intel.suppressions(&project_id)?,
        events: intel.suppression_events(&project_id)?,
    })
}

#[tauri::command]
pub fn create_security_suppression(
    project_id: String,
    scope: SuppressionScope,
    matcher: String,
    reason: String,
    ttl_days: u32,
    app: tauri::AppHandle,
) -> Result<Suppression, String> {
    let db = db(&app)?;
    let me = acting_operator(&db)?;
    SecurityIntelligence::new(&db).suppress(&project_id, &me, scope, &matcher, &reason, ttl_days)
}

#[tauri::command]
pub fn revoke_security_suppression(
    project_id: String,
    suppression_id: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let db = db(&app)?;
    let me = acting_operator(&db)?;
    SecurityIntelligence::new(&db).revoke(&project_id, &suppression_id, &me)?;
    Ok(true)
}

#[tauri::command]
pub fn memory_item_history(
    project_id: String,
    item_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<MemoryVersion>, String> {
    KnowledgeMemory::new(&db(&app)?).history(&project_id, &item_id)
}

#[tauri::command]
pub fn knowledge_conflicts(
    project_id: String,
    open_only: bool,
    app: tauri::AppHandle,
) -> Result<Vec<KnowledgeConflict>, String> {
    KnowledgeMemory::new(&db(&app)?).conflicts(&project_id, open_only)
}

#[tauri::command]
pub fn resolve_knowledge_conflict(
    project_id: String,
    conflict_id: String,
    accept: bool,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let db = db(&app)?;
    let me = acting_operator(&db)?;
    KnowledgeMemory::new(&db).resolve_conflict(&project_id, &conflict_id, &me, accept)?;
    Ok(true)
}

/// Graph around `node_id` as believed at `at_ms` (omit for "now").
#[tauri::command]
pub fn knowledge_graph_as_of(
    project_id: String,
    node_id: String,
    at_ms: Option<i64>,
    app: tauri::AppHandle,
) -> Result<EvidenceGraph, String> {
    KnowledgeMemory::new(&db(&app)?).neighborhood_at(&project_id, &node_id, 2, at_ms)
}

#[derive(Serialize)]
pub struct EmbedReceipt {
    model: String,
    embedded: usize,
}

/// Embed project memory with a model served on this machine. Remote
/// embedding providers are not offered here: they need a per-project
/// consent flow that the desktop does not expose yet.
#[tauri::command]
pub fn embed_project_memory(
    project_id: String,
    endpoint: String,
    model: String,
    limit: Option<usize>,
    app: tauri::AppHandle,
) -> Result<EmbedReceipt, String> {
    let embedder = HttpEmbedder::new(&endpoint, &model, None, EmbeddingDestination::Loopback)?;
    let embedded = KnowledgeMemory::new(&db(&app)?).embed_project(
        &project_id,
        &embedder,
        limit.unwrap_or(500).clamp(1, 2000),
    )?;
    Ok(EmbedReceipt {
        model: embedder.model_id(),
        embedded,
    })
}

#[tauri::command]
pub fn compare_workflow_runs(
    left_run_id: String,
    right_run_id: String,
    app: tauri::AppHandle,
) -> Result<task_orchestrator::compare::RunComparison, String> {
    let db = db(&app)?;
    let store = task_orchestrator::Store::new(db.connection());
    let (left, right) = (
        store.get_run(&left_run_id).map_err(|e| e.to_string())?,
        store.get_run(&right_run_id).map_err(|e| e.to_string())?,
    );
    if left.project_id != right.project_id {
        return Err("runs from different projects cannot be compared".into());
    }
    Ok(task_orchestrator::compare::compare_runs(
        &left,
        &store.list_tasks(&left_run_id).map_err(|e| e.to_string())?,
        &right,
        &store.list_tasks(&right_run_id).map_err(|e| e.to_string())?,
    ))
}

/// `None` when the run can still make progress (or is waiting on a person).
#[tauri::command]
pub fn diagnose_workflow_stall(
    run_id: String,
    app: tauri::AppHandle,
) -> Result<Option<task_orchestrator::compare::StallReport>, String> {
    let db = db(&app)?;
    let store = task_orchestrator::Store::new(db.connection());
    let run = store.get_run(&run_id).map_err(|e| e.to_string())?;
    let tasks = store.list_tasks(&run_id).map_err(|e| e.to_string())?;
    Ok(task_orchestrator::compare::diagnose_stall(&run, &tasks))
}
