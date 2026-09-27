use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

use codetwin_core::{
    AdvisorySource, Database, DependencyAuditRunRecord, DependencyAuditService,
    DependencyAuditSummary, DependencyFindingRecord, DependencyRecord, SbomService,
    SecretFindingRecord, SecretHistoryFindingRecord, SecretHistoryRunRecord, SecretHistoryService,
    SecretHistorySummary, SecretScanRunRecord, SecretScanSummary, SecretScanningService,
};
use serde::Serialize;
use tauri::Manager;

static SECRET_SCAN_RUNNING: AtomicBool = AtomicBool::new(false);
static SECRET_HISTORY_RUNNING: AtomicBool = AtomicBool::new(false);
static DEPENDENCY_AUDIT_RUNNING: AtomicBool = AtomicBool::new(false);
const OSV_API: &str = "https://api.osv.dev";

fn open_database(app: &tauri::AppHandle) -> Result<Database, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&app_data_dir).map_err(|error| error.to_string())?;
    Database::open(app_data_dir.join("codetwin.sqlite3")).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn run_secret_scan(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<SecretScanSummary, String> {
    if SECRET_SCAN_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a secret scan is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        SecretScanningService::new(&database)
            .scan_project(&project_id)
            .map_err(|error| error.to_string())
    })
    .await;
    SECRET_SCAN_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_secret_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<SecretFindingRecord>, String> {
    let database = open_database(&app)?;
    SecretScanningService::new(&database)
        .list_findings(&project_id, status.as_deref(), limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn secret_scan_history(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<SecretScanRunRecord>, String> {
    let database = open_database(&app)?;
    SecretScanningService::new(&database)
        .history(&project_id, limit)
        .map_err(|error| error.to_string())
}

/// Scans the lines added by up to `max_commits` commits across all refs. Runs `git log`
/// read-only with external diff, textconv, pager and signature programs disabled.
#[tauri::command]
pub async fn run_secret_history_scan(
    project_id: String,
    max_commits: usize,
    app: tauri::AppHandle,
) -> Result<SecretHistorySummary, String> {
    if SECRET_HISTORY_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a git history secret scan is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        SecretHistoryService::new(&database)
            .scan_project(&project_id, max_commits)
            .map_err(|error| error.to_string())
    })
    .await;
    SECRET_HISTORY_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_secret_history_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<SecretHistoryFindingRecord>, String> {
    let database = open_database(&app)?;
    SecretHistoryService::new(&database)
        .list_findings(&project_id, status.as_deref(), limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn secret_history_runs(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<SecretHistoryRunRecord>, String> {
    let database = open_database(&app)?;
    SecretHistoryService::new(&database)
        .history(&project_id, limit)
        .map_err(|error| error.to_string())
}

/// `mode` is `online` (OSV.dev; requires `network_consent`) or `offline` (a local
/// directory of OSV JSON records; no network).
#[tauri::command]
pub async fn run_dependency_audit(
    project_id: String,
    mode: String,
    offline_directory: Option<String>,
    network_consent: bool,
    app: tauri::AppHandle,
) -> Result<DependencyAuditSummary, String> {
    let source = match mode.as_str() {
        "online" if network_consent => AdvisorySource::OsvApi {
            base_url: OSV_API.to_string(),
        },
        "online" => {
            return Err(
                "online advisory lookup sends package names and versions to api.osv.dev; confirm consent first"
                    .to_string(),
            )
        }
        "offline" => {
            let path = offline_directory
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .ok_or_else(|| "choose an absolute path to a local OSV advisory directory".to_string())?;
            let path = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
            AdvisorySource::OfflineDirectory { path }
        }
        _ => return Err("unknown advisory mode".to_string()),
    };
    if DEPENDENCY_AUDIT_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a dependency audit is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        DependencyAuditService::new(&database)
            .audit_project(&project_id, &source)
            .map_err(|error| error.to_string())
    })
    .await;
    DEPENDENCY_AUDIT_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_dependency_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<DependencyFindingRecord>, String> {
    let database = open_database(&app)?;
    DependencyAuditService::new(&database)
        .list_findings(&project_id, status.as_deref(), limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_dependency_inventory(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<DependencyRecord>, String> {
    let database = open_database(&app)?;
    DependencyAuditService::new(&database)
        .list_inventory(&project_id, limit)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn dependency_audit_history(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<DependencyAuditRunRecord>, String> {
    let database = open_database(&app)?;
    DependencyAuditService::new(&database)
        .history(&project_id, limit)
        .map_err(|error| error.to_string())
}

#[derive(Debug, Serialize)]
pub struct SbomExportResult {
    pub path: String,
    pub components: usize,
    pub vulnerabilities: usize,
}

/// Writes a CycloneDX 1.5 JSON SBOM of the project's last dependency inventory to `path`.
#[tauri::command]
pub fn export_dependency_sbom(
    project_id: String,
    path: String,
    app: tauri::AppHandle,
) -> Result<SbomExportResult, String> {
    let destination = PathBuf::from(path);
    if !destination
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("json"))
    {
        return Err("SBOM path must end in .json".to_string());
    }
    if !destination.parent().is_some_and(|parent| parent.is_dir()) {
        return Err("SBOM destination directory does not exist".to_string());
    }
    let database = open_database(&app)?;
    let export = SbomService::new(&database)
        .export_cyclonedx(&project_id)
        .map_err(|error| error.to_string())?;
    std::fs::write(&destination, &export.json).map_err(|error| error.to_string())?;
    Ok(SbomExportResult {
        path: destination.to_string_lossy().to_string(),
        components: export.components,
        vulnerabilities: export.vulnerabilities,
    })
}
