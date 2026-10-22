use std::sync::atomic::{AtomicBool, Ordering};

use codetwin_core::{
    native_agent_delegation::{DelegationGraph, NativeDelegation},
    native_agent_knowledge::{AgentKnowledge, KnowledgeGraph, KnowledgeNode},
    native_agent_workers::{IsolatedScanReadiness, IsolatedScanReceipt, IsolatedWorker},
    native_graph_reasoning::{GraphInference, GraphReasoner},
    native_neural_embeddings::{NeuralMatch, NeuralMemory, NeuralReadiness},
    native_worker_audit::{WorkerAudit, WorkerAuditRecord},
    Database,
};
use tauri::Manager;

static WORKER_BUSY: AtomicBool = AtomicBool::new(false);

struct WorkerLease;
impl Drop for WorkerLease {
    fn drop(&mut self) {
        WORKER_BUSY.store(false, Ordering::SeqCst);
    }
}

fn db(app: &tauri::AppHandle) -> Result<Database, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Database::open(dir.join("codetwin.sqlite3")).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn native_delegation_graph(
    id: String,
    app: tauri::AppHandle,
) -> Result<DelegationGraph, String> {
    NativeDelegation::new(&db(&app)?).graph(&id)
}

#[tauri::command]
pub fn search_native_knowledge(
    project_id: String,
    query: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<KnowledgeNode>, String> {
    AgentKnowledge::new(&db(&app)?).search(&project_id, &query, limit)
}

#[tauri::command]
pub fn native_knowledge_graph(
    project_id: String,
    id: String,
    app: tauri::AppHandle,
) -> Result<KnowledgeGraph, String> {
    AgentKnowledge::new(&db(&app)?).graph(&project_id, &id)
}

#[tauri::command]
pub fn clear_native_knowledge(project_id: String, app: tauri::AppHandle) -> Result<usize, String> {
    AgentKnowledge::new(&db(&app)?).clear(&project_id)
}

#[tauri::command]
pub fn native_isolated_scan_readiness() -> IsolatedScanReadiness {
    IsolatedWorker::readiness()
}

#[tauri::command]
pub async fn run_native_isolated_scan(
    id: String,
    authorized: bool,
    app: tauri::AppHandle,
) -> Result<IsolatedScanReceipt, String> {
    if !authorized {
        return Err("Explicit approval is required".into());
    }
    if WORKER_BUSY
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("An isolated security scan is already running".into());
    }
    let lease = WorkerLease;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        let database = db(&app)?;
        let audit = WorkerAudit::new(&database);
        let audit_id = audit.begin(&id)?;
        let result = IsolatedWorker::new(&database).scan(&id, authorized);
        audit.finish(audit_id, &result)?;
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn native_task_schedule(
    id: String,
    app: tauri::AppHandle,
) -> Result<codetwin_core::native_task_plans::TaskSchedule, String> {
    let graph = NativeDelegation::new(&db(&app)?).graph(&id)?;
    let tasks = graph
        .tasks
        .iter()
        .map(|task| {
            let depends_on = task
                .requires
                .iter()
                .map(|required| {
                    graph
                        .tasks
                        .iter()
                        .find(|candidate| candidate.position == *required)
                        .map(|candidate| candidate.tool.clone())
                        .ok_or_else(|| "Missing required specialist".to_string())
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(codetwin_core::native_task_plans::PlannedSpecialist {
                role: task.tool.clone(),
                objective: task
                    .objective
                    .clone()
                    .unwrap_or_else(|| format!("Review {}", task.tool)),
                depends_on,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    codetwin_core::native_task_plans::validate_proposal(
        &codetwin_core::native_task_plans::TaskProposal {
            tasks,
            rationale: "Persisted bounded review graph".into(),
        },
    )
}

#[tauri::command]
pub fn native_worker_audit(
    id: String,
    app: tauri::AppHandle,
) -> Result<Vec<WorkerAuditRecord>, String> {
    let database = db(&app)?;
    WorkerAudit::new(&database).list(&id)
}

#[tauri::command]
pub fn native_neural_readiness() -> NeuralReadiness {
    NeuralMemory::readiness()
}

#[tauri::command]
pub async fn index_native_neural_memory(
    id: String,
    consent: bool,
    app: tauri::AppHandle,
) -> Result<usize, String> {
    if !consent {
        return Err("Explicit neural indexing consent is required".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let database = db(&app)?;
        NeuralMemory::new(&database).index_run(&id, consent)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn search_native_neural_memory(
    project_id: String,
    query: String,
    limit: usize,
    consent: bool,
    app: tauri::AppHandle,
) -> Result<Vec<NeuralMatch>, String> {
    if !consent {
        return Err("Explicit query embedding consent is required".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let database = db(&app)?;
        NeuralMemory::new(&database).search(&project_id, &query, limit, consent)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn reason_native_knowledge_graph(
    project_id: String,
    id: String,
    position: usize,
    app: tauri::AppHandle,
) -> Result<GraphInference, String> {
    let database = db(&app)?;
    GraphReasoner::new(&database).analyze(&project_id, &id, position)
}
