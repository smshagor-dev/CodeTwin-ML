use std::sync::atomic::{AtomicBool, Ordering};

use codetwin_core::{
    Database, QaArtifactRecord, QaDiscoveryRunRecord, QaDiscoveryRunSummary, QaDiscoveryService,
    QaFrameworkSummary,
};
use tauri::Manager;

static QA_DISCOVERY_RUNNING: AtomicBool = AtomicBool::new(false);

fn open_database(app: &tauri::AppHandle) -> Result<Database, String> {
    let app_data_dir = app.path().app_data_dir().map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&app_data_dir).map_err(|error| error.to_string())?;
    Database::open(app_data_dir.join("codetwin.sqlite3")).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn run_qa_discovery(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<QaDiscoveryRunSummary, String> {
    if QA_DISCOVERY_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("QA test discovery is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        QaDiscoveryService::new(&database)
            .discover_project(&project_id)
            .map_err(|error| error.to_string())
    })
    .await;
    QA_DISCOVERY_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_qa_artifacts(
    project_id: String,
    active_only: bool,
    framework: Option<String>,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<QaArtifactRecord>, String> {
    let database = open_database(&app)?;
    QaDiscoveryService::new(&database)
        .list_artifacts(&project_id, active_only, framework.as_deref(), limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_qa_frameworks(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<QaFrameworkSummary>, String> {
    let database = open_database(&app)?;
    QaDiscoveryService::new(&database)
        .list_frameworks(&project_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn qa_discovery_history(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<QaDiscoveryRunRecord>, String> {
    let database = open_database(&app)?;
    QaDiscoveryService::new(&database)
        .history(&project_id, limit)
        .map_err(|error| error.to_string())
}
