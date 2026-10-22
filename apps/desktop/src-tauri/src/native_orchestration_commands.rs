use std::sync::atomic::{AtomicBool, Ordering};

use codetwin_core::{
    native_agent_delegation::{DelegationGraph, NativeDelegation},
    native_agent_knowledge::{AgentKnowledge, KnowledgeGraph, KnowledgeNode},
    native_agent_workers::{IsolatedScanReadiness, IsolatedScanReceipt, IsolatedWorker},
    Database,
};
use tauri::Manager;

static WORKER_BUSY: AtomicBool = AtomicBool::new(false);

struct WorkerLease;
impl Drop for WorkerLease {
    fn drop(&mut self) { WORKER_BUSY.store(false, Ordering::SeqCst); }
}

fn db(app: &tauri::AppHandle) -> Result<Database, String> {
    let dir=app.path().app_data_dir().map_err(|e|e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e|e.to_string())?;
    Database::open(dir.join("codetwin.sqlite3")).map_err(|e|e.to_string())
}

#[tauri::command]
pub fn native_delegation_graph(id: String, app: tauri::AppHandle)
    -> Result<DelegationGraph, String>
{
    NativeDelegation::new(&db(&app)?).graph(&id)
}

#[tauri::command]
pub fn search_native_knowledge(project_id: String, query: String, limit: usize, app: tauri::AppHandle)
    -> Result<Vec<KnowledgeNode>, String>
{
    AgentKnowledge::new(&db(&app)?).search(&project_id, &query, limit)
}

#[tauri::command]
pub fn native_knowledge_graph(project_id: String, id: String, app: tauri::AppHandle)
    -> Result<KnowledgeGraph, String>
{
    AgentKnowledge::new(&db(&app)?).graph(&project_id, &id)
}

#[tauri::command]
pub fn clear_native_knowledge(project_id: String, app: tauri::AppHandle)
    -> Result<usize, String>
{
    AgentKnowledge::new(&db(&app)?).clear(&project_id)
}

#[tauri::command]
pub fn native_isolated_scan_readiness() -> IsolatedScanReadiness {
    IsolatedWorker::readiness()
}

#[tauri::command]
pub async fn run_native_isolated_scan(
    id: String, authorized: bool, app: tauri::AppHandle,
) -> Result<IsolatedScanReceipt, String> {
    if !authorized { return Err("Explicit approval is required".into()); }
    if WORKER_BUSY.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err() {
        return Err("An isolated security scan is already running".into());
    }
    let lease=WorkerLease;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease=lease;
        IsolatedWorker::new(&db(&app)?).scan(&id,authorized)
    }).await.map_err(|e|e.to_string())?
}
