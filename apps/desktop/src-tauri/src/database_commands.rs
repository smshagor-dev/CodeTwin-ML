use std::sync::atomic::{AtomicBool, Ordering};

use codetwin_core::{
    Database, DatabaseAnalysisService, DatabaseArtifactRecord, DatabaseFindingRecord,
    DatabaseRuleRecord, DatabaseRunRecord, DatabaseRunSummary, FindingEvidenceRecord,
};
use tauri::Manager;

static DATABASE_ANALYSIS_RUNNING: AtomicBool = AtomicBool::new(false);

fn open_database(app: &tauri::AppHandle) -> Result<Database, String> {
    let app_data_dir = app.path().app_data_dir().map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&app_data_dir).map_err(|error| error.to_string())?;
    Database::open(app_data_dir.join("codetwin.sqlite3")).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn run_database_analysis(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<DatabaseRunSummary, String> {
    if DATABASE_ANALYSIS_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("database analysis is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        DatabaseAnalysisService::new(&database)
            .analyze_project(&project_id)
            .map_err(|error| error.to_string())
    })
    .await;
    DATABASE_ANALYSIS_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_database_artifacts(
    project_id: String,
    active_only: bool,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<DatabaseArtifactRecord>, String> {
    let database = open_database(&app)?;
    DatabaseAnalysisService::new(&database)
        .list_artifacts(&project_id, active_only, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_database_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<DatabaseFindingRecord>, String> {
    let database = open_database(&app)?;
    DatabaseAnalysisService::new(&database)
        .list_findings(&project_id, status.as_deref(), limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_database_evidence(
    finding_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<FindingEvidenceRecord>, String> {
    let database = open_database(&app)?;
    DatabaseAnalysisService::new(&database)
        .finding_evidence(&finding_id, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn database_history(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<DatabaseRunRecord>, String> {
    let database = open_database(&app)?;
    DatabaseAnalysisService::new(&database)
        .history(&project_id, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_database_rules(app: tauri::AppHandle) -> Result<Vec<DatabaseRuleRecord>, String> {
    let database = open_database(&app)?;
    Ok(DatabaseAnalysisService::new(&database).rules())
}
