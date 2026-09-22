use std::{
    fs,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use sha2::{Digest, Sha256};

use codetwin_core::{
    Database, QaArtifactRecord, QaDiscoveryRunRecord, QaDiscoveryRunSummary, QaDiscoveryService,
    QaExecutionAvailability, QaExecutionPlanRecord, QaExecutionRunRecord, QaExecutionService,
    QaFrameworkSummary,
};
use qa_execution::{SandboxPolicy, TestExecutionRequest, TrustedToolchain};
use tauri::Manager;

static QA_DISCOVERY_RUNNING: AtomicBool = AtomicBool::new(false);
static QA_EXECUTION_RUNNING: AtomicBool = AtomicBool::new(false);
static QA_EXECUTION_CANCELLED: AtomicBool = AtomicBool::new(false);
static QA_EXECUTION_RUNNING: AtomicBool = AtomicBool::new(false);
static QA_EXECUTION_CANCELLED: AtomicBool = AtomicBool::new(false);

fn hash_trusted_toolchain(value: &str) -> Result<String, String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("QA toolchain executable must be an absolute path".to_string());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect QA toolchain executable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("QA toolchain executable must be a regular non-symlink file".to_string());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize QA toolchain executable: {error}"))?;
    let mut file = fs::File::open(&canonical)
        .map_err(|error| format!("cannot open QA toolchain executable: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash QA toolchain executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

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


#[tauri::command]
pub fn qa_execution_availability(
    app: tauri::AppHandle,
) -> Result<QaExecutionAvailability, String> {
    let database = open_database(&app)?;
    Ok(QaExecutionService::new(&database).availability())
}

#[tauri::command]
pub fn create_qa_execution_plan(
    project_id: String,
    request: TestExecutionRequest,
    mut toolchain: TrustedToolchain,
    policy: SandboxPolicy,
    app: tauri::AppHandle,
) -> Result<QaExecutionPlanRecord, String> {
    if toolchain.sha256.as_deref().is_none_or(str::is_empty) {
        toolchain.sha256 = Some(hash_trusted_toolchain(&toolchain.executable_path)?);
    }
    let database = open_database(&app)?;
    QaExecutionService::new(&database)
        .create_plan(&project_id, request, toolchain, policy)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn approve_qa_execution_plan(
    plan_id: String,
    app: tauri::AppHandle,
) -> Result<QaExecutionPlanRecord, String> {
    let database = open_database(&app)?;
    QaExecutionService::new(&database)
        .approve_plan(&plan_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_qa_execution_plans(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<QaExecutionPlanRecord>, String> {
    let database = open_database(&app)?;
    QaExecutionService::new(&database)
        .list_plans(&project_id, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_qa_execution_runs(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<QaExecutionRunRecord>, String> {
    let database = open_database(&app)?;
    QaExecutionService::new(&database)
        .list_runs(&project_id, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn run_qa_execution_plan(
    plan_id: String,
    app: tauri::AppHandle,
) -> Result<QaExecutionRunRecord, String> {
    if QA_EXECUTION_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("QA execution is already running".to_string());
    }
    QA_EXECUTION_CANCELLED.store(false, Ordering::SeqCst);

    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        QaExecutionService::new(&database)
            .execute_plan(&plan_id, &QA_EXECUTION_CANCELLED)
            .map_err(|error| error.to_string())
    })
    .await;

    QA_EXECUTION_RUNNING.store(false, Ordering::SeqCst);
    QA_EXECUTION_CANCELLED.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn cancel_qa_execution() -> bool {
    if !QA_EXECUTION_RUNNING.load(Ordering::SeqCst) {
        return false;
    }
    QA_EXECUTION_CANCELLED.store(true, Ordering::SeqCst);
    true
}
