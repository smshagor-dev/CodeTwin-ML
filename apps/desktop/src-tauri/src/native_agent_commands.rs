use codetwin_core::{native_agent_memory::{AgentMemory, MemoryEntry}, 
    native_agents::{AgentRun, NativeAgents},
    Database,
};
use tauri::Manager;

use crate::{reserve_assessment, AppState};

fn open_db(app: &tauri::AppHandle) -> Result<Database, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Database::open(dir.join("codetwin.sqlite3")).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn create_native_agent_review(
    project_id: String,
    objective: String,
    max_files: usize,
    budget_seconds: u64,
    app: tauri::AppHandle,
) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).create(&project_id, &objective, max_files, budget_seconds)
}

#[tauri::command]
pub fn native_agent_review(id: String, app: tauri::AppHandle) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).get(&id)
}

#[tauri::command]
pub fn list_native_agent_reviews(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<AgentRun>, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).list(&project_id)
}

#[tauri::command]
pub fn approve_native_agent_review(id: String, app: tauri::AppHandle) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).approve(&id)
}

#[tauri::command]
pub fn cancel_native_agent_review(id: String, app: tauri::AppHandle) -> Result<AgentRun, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).cancel(&id)
}

#[tauri::command]
pub async fn run_native_agent_review(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<AgentRun, String> {
    // Use the same reservations as indexed assessments: no competing index,
    // semantic enrichment, quality or static-security analysis during execution.
    let reservations = reserve_assessment(&state)?;
    let path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _reservations = reservations;
        let db = Database::open(path).map_err(|error| error.to_string())?;
        NativeAgents::new(&db).execute(&id)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn native_agent_report(id: String, app: tauri::AppHandle) -> Result<String, String> {
    let db = open_db(&app)?;
    NativeAgents::new(&db).report(&id)
}

#[tauri::command]
pub fn list_native_agent_memory(
    project_id: String,
    query: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<MemoryEntry>, String> {
    let db = open_db(&app)?;
    AgentMemory::new(&db).search(&project_id, &query, limit)
}

#[tauri::command]
pub fn clear_native_agent_memory(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<usize, String> {
    let db = open_db(&app)?;
    AgentMemory::new(&db).clear(&project_id)
}
