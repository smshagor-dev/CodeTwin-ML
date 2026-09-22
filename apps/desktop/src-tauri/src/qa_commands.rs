use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use codetwin_core::{
    Database, QaArtifactRecord, QaDiscoveryRunRecord, QaDiscoveryRunSummary, QaDiscoveryService,
    QaExecutionAvailability, QaExecutionPlanRecord, QaExecutionRunRecord, QaExecutionService,
    QaFrameworkSummary,
};
use qa_execution::{
    DeclaredExternalReadRoot, ExternalReadRootKind, SandboxPolicy, TestExecutionRequest,
    TestRunnerKind, TrustedToolchain,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tauri::Manager;

static QA_DISCOVERY_RUNNING: AtomicBool = AtomicBool::new(false);
static QA_EXECUTION_CANCELLATIONS: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

fn qa_execution_cancellations() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    QA_EXECUTION_CANCELLATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, Deserialize)]
pub struct QaDockerPlanRequest {
    pub project_id: String,
    pub discovery_run_id: Option<String>,
    pub runner: TestRunnerKind,
    pub targets: Vec<String>,
    pub docker_executable: String,
    pub image: String,
    #[serde(default)]
    pub policy: SandboxPolicy,
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
pub fn qa_docker_availability(
    docker_executable: String,
    image: String,
    app: tauri::AppHandle,
) -> Result<QaExecutionAvailability, String> {
    let database = open_database(&app)?;
    Ok(QaExecutionService::new(&database).docker_availability(&docker_executable, &image))
}

#[tauri::command]
pub fn create_qa_docker_plan(
    request: QaDockerPlanRequest,
    app: tauri::AppHandle,
) -> Result<QaExecutionPlanRecord, String> {
    let docker = validate_docker_executable(&request.docker_executable)?;
    let docker_sha256 = sha256_file(&docker)?;
    let version_output = Command::new(&docker)
        .arg("--version")
        .env_clear()
        .output()
        .map_err(|error| format!("cannot query Docker version: {error}"))?;
    if !version_output.status.success() {
        return Err("Docker executable did not return a successful version response".to_string());
    }
    let version = String::from_utf8_lossy(&version_output.stdout).trim().to_string();
    if version.is_empty() {
        return Err("Docker version response was empty".to_string());
    }
    let runtime_root = docker
        .parent()
        .ok_or_else(|| "Docker executable has no parent runtime directory".to_string())?
        .to_string_lossy()
        .into_owned();

    let toolchain = TrustedToolchain {
        runner: request.runner,
        executable_path: docker.to_string_lossy().into_owned(),
        version,
        sha256: Some(docker_sha256),
        trusted_by_user: true,
        declared_external_read_roots: vec![DeclaredExternalReadRoot {
            kind: ExternalReadRootKind::ToolchainSupport,
            path: runtime_root,
        }],
    };
    let execution_request = TestExecutionRequest {
        runner: request.runner,
        targets: request.targets,
        discovery_run_id: request.discovery_run_id,
    };

    let database = open_database(&app)?;
    QaExecutionService::new(&database)
        .create_docker_plan(
            &request.project_id,
            execution_request,
            toolchain,
            request.policy,
            &request.image,
        )
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
pub async fn run_qa_docker_plan(
    plan_id: String,
    app: tauri::AppHandle,
) -> Result<QaExecutionRunRecord, String> {
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut registry = qa_execution_cancellations()
            .lock()
            .map_err(|_| "QA execution cancellation registry lock is poisoned".to_string())?;
        if registry.contains_key(&plan_id) {
            return Err("this QA execution plan is already running".to_string());
        }
        registry.insert(plan_id.clone(), Arc::clone(&cancelled));
    }

    let task_plan_id = plan_id.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = open_database(&app)?;
        QaExecutionService::new(&database)
            .execute_docker_plan(&task_plan_id, &cancelled)
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string());

    if let Ok(mut registry) = qa_execution_cancellations().lock() {
        registry.remove(&plan_id);
    }
    task?
}

#[tauri::command]
pub fn cancel_qa_execution(plan_id: String) -> Result<bool, String> {
    let registry = qa_execution_cancellations()
        .lock()
        .map_err(|_| "QA execution cancellation registry lock is poisoned".to_string())?;
    if let Some(cancelled) = registry.get(&plan_id) {
        cancelled.store(true, Ordering::SeqCst);
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub fn qa_execution_history(
    project_id: String,
    limit: usize,
    app: tauri::AppHandle,
) -> Result<Vec<QaExecutionRunRecord>, String> {
    let database = open_database(&app)?;
    QaExecutionService::new(&database)
        .list_runs(&project_id, limit)
        .map_err(|error| error.to_string())
}

fn validate_docker_executable(value: &str) -> Result<PathBuf, String> {
    let input = Path::new(value);
    if !input.is_absolute() {
        return Err("Docker executable must be an absolute path".to_string());
    }
    let metadata = fs::symlink_metadata(input)
        .map_err(|error| format!("cannot inspect Docker executable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("Docker executable must be a regular file, not a symlink".to_string());
    }
    input
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize Docker executable: {error}"))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut stream = fs::File::open(path)
        .map_err(|error| format!("cannot open Docker executable: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash Docker executable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
