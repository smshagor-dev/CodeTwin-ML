//! Desktop commands for durable workflows, memory, research and the
//! OpenMindAI Cloud provider. The WebView never receives API tokens; it only
//! learns whether one is stored. All decisions are recorded as the local
//! operator; workers and models have no access to these commands.
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

use codetwin_core::cloud_settings::{
    CloudSettings, ConsentRecord, ProviderRequestRecord, ProviderSettings,
};
use codetwin_core::knowledge_memory::{
    EvidenceGraph, KnowledgeMemory, MemoryItem, MemoryLayer, RetrievalBudget, RetrievalResult,
};
use codetwin_core::specialist_workers::InvestigationOptions;
use codetwin_core::workflow_platform::{CloudProvider, RunDetail, WorkerRole, WorkflowPlatform};
use codetwin_core::Database;
use model_gateway::client::{ChatClient, ClientConfig, Diagnostics, ProviderProfile};
use model_gateway::credentials::{CredentialStore, KeyringStore, Secret};
use model_gateway::{
    approve_preview, prepare_egress, ChatMessage, ChatRequest, EgressPreview, StreamDelta,
};
use serde::Serialize;
use task_orchestrator::store::{
    ApprovalRequest, EventRecord, OverrideResolution, RunBudgets, RunRecord, TaskRecord,
};
use task_orchestrator::{CancelToken, GlobalLimits};
use tauri::{Emitter, Manager};

const PROVIDER: &str = "openmindai";
const TOKEN_ACCOUNT: &str = "openmindai-developer-key";

fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| task_orchestrator::store::new_id("desktop"))
}

fn limits() -> Arc<GlobalLimits> {
    static LIMITS: OnceLock<Arc<GlobalLimits>> = OnceLock::new();
    LIMITS
        .get_or_init(|| Arc::new(GlobalLimits::new(4)))
        .clone()
}

fn running() -> &'static Mutex<HashMap<String, CancelToken>> {
    static RUNNING: OnceLock<Mutex<HashMap<String, CancelToken>>> = OnceLock::new();
    RUNNING.get_or_init(Default::default)
}

fn operator() -> String {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    let user: String = user
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(60)
        .collect();
    if user.is_empty() {
        "operator:local".into()
    } else {
        format!("operator:{user}")
    }
}

fn db_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("codetwin.sqlite3"))
}

fn db(app: &tauri::AppHandle) -> Result<Database, String> {
    Database::open(db_path(app)?).map_err(|e| e.to_string())
}

fn settings(app: &tauri::AppHandle) -> Result<ProviderSettings, String> {
    Ok(CloudSettings::new(&db(app)?)
        .provider(PROVIDER)?
        .unwrap_or(ProviderSettings {
            provider: PROVIDER.into(),
            kind: "cloud".into(),
            base_url: model_gateway::OPENMINDAI_DEFAULT_BASE_URL.into(),
            enabled: false,
            role_models: Default::default(),
            updated_ms: 0,
        }))
}

/// Build the cloud client only when enabled and a token is stored.
fn cloud_client(app: &tauri::AppHandle) -> Result<Option<(Arc<ChatClient>, String)>, String> {
    let s = settings(app)?;
    if !s.enabled {
        return Ok(None);
    }
    let Some(secret) = KeyringStore.get(TOKEN_ACCOUNT).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let profile = ProviderProfile::openmindai(&s.base_url).map_err(|e| e.to_string())?;
    let client = ChatClient::new(profile, Some(secret), ClientConfig::default())
        .map_err(|e| e.to_string())?;
    let model = s
        .role_models
        .default_cloud
        .clone()
        .unwrap_or_else(|| "openmindai-lite".into());
    Ok(Some((Arc::new(client), model)))
}

fn platform(app: &tauri::AppHandle) -> Result<WorkflowPlatform, String> {
    let cloud = cloud_client(app)?.map(|(client, model)| CloudProvider { client, model });
    Ok(WorkflowPlatform::new(
        db_path(app)?,
        instance_id().into(),
        limits(),
        cloud,
    ))
}

/// Startup reconciliation of interrupted workflow runs.
pub fn recover_workflows(database_path: &std::path::Path) -> Result<(), String> {
    WorkflowPlatform::new(
        database_path.to_path_buf(),
        instance_id().into(),
        limits(),
        None,
    )
    .recover()
    .map(|_| ())
}

#[derive(Serialize)]
pub struct PlannedRun {
    run: RunRecord,
    approvals: Vec<ApprovalRequest>,
}

#[tauri::command]
pub fn workflow_roles() -> Vec<WorkerRole> {
    WorkflowPlatform::roles()
}

#[tauri::command]
pub fn workflow_capability_matrix(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<codetwin_core::agent_tools::CapabilityStatus>, String> {
    platform(&app)?.capability_matrix(&project_id)
}

#[tauri::command]
pub fn create_workflow_investigation(
    project_id: String,
    goal: String,
    research_urls: Vec<String>,
    cloud_review: bool,
    max_parallel: Option<u32>,
    app: tauri::AppHandle,
) -> Result<PlannedRun, String> {
    let budgets = RunBudgets {
        max_parallel: max_parallel.unwrap_or(3).clamp(1, 4),
        ..RunBudgets::default()
    };
    let options = InvestigationOptions {
        research_urls,
        cloud_review,
    };
    let (run, approvals) = platform(&app)?.create_investigation(
        &project_id,
        &goal,
        &operator(),
        &options,
        Some(budgets),
    )?;
    Ok(PlannedRun { run, approvals })
}

#[tauri::command]
pub fn list_workflow_runs(
    project_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Vec<RunRecord>, String> {
    platform(&app)?.list_runs(project_id.as_deref(), 50)
}

#[tauri::command]
pub fn workflow_run_detail(run_id: String, app: tauri::AppHandle) -> Result<RunDetail, String> {
    platform(&app)?.detail(&run_id)
}

/// Durable event replay: everything after `cursor` (the last seen `seq`).
#[tauri::command]
pub fn workflow_events(
    run_id: String,
    cursor: i64,
    app: tauri::AppHandle,
) -> Result<Vec<EventRecord>, String> {
    platform(&app)?.events_since(&run_id, cursor.max(0), 500)
}

#[tauri::command]
pub fn pending_workflow_approvals(app: tauri::AppHandle) -> Result<Vec<ApprovalRequest>, String> {
    platform(&app)?.pending_approvals()
}

#[tauri::command]
pub fn decide_workflow_approval(
    approval_id: String,
    approve: bool,
    scope_digest: String,
    note: Option<String>,
    app: tauri::AppHandle,
) -> Result<ApprovalRequest, String> {
    platform(&app)?.decide(
        &approval_id,
        approve,
        &operator(),
        &scope_digest,
        note.as_deref(),
    )
}

/// Start (or continue) an approved run on a background thread.
#[tauri::command]
pub fn start_workflow_run(run_id: String, app: tauri::AppHandle) -> Result<(), String> {
    let token = CancelToken::new();
    {
        let mut map = running().lock().map_err(|_| "run registry poisoned")?;
        if map.contains_key(&run_id) {
            return Err("this run is already executing".into());
        }
        map.insert(run_id.clone(), token.clone());
    }
    let platform = match platform(&app) {
        Ok(p) => p,
        Err(e) => {
            running().lock().map(|mut m| m.remove(&run_id)).ok();
            return Err(e);
        }
    };
    std::thread::spawn(move || {
        let result = platform.execute(&run_id, Some(&token));
        running().lock().map(|mut m| m.remove(&run_id)).ok();
        let _ = app.emit(
            "workflow://settled",
            serde_json::json!({
                "run_id": run_id,
                "error": result.as_ref().err(),
                "state": result.as_ref().ok().map(|r| r.state),
            }),
        );
    });
    Ok(())
}

#[tauri::command]
pub fn cancel_workflow_run(run_id: String, app: tauri::AppHandle) -> Result<RunRecord, String> {
    if let Some(token) = running()
        .lock()
        .map_err(|_| "run registry poisoned")?
        .get(&run_id)
    {
        token.cancel();
    }
    platform(&app)?.cancel(&run_id)
}

#[tauri::command]
pub fn pause_workflow_run(run_id: String, app: tauri::AppHandle) -> Result<RunRecord, String> {
    platform(&app)?.pause(&run_id)
}

#[tauri::command]
pub fn resume_workflow_run(run_id: String, app: tauri::AppHandle) -> Result<RunRecord, String> {
    platform(&app)?.resume(&run_id, &operator())
}

#[tauri::command]
pub fn override_workflow_task(
    task_id: String,
    resolution: OverrideResolution,
    app: tauri::AppHandle,
) -> Result<TaskRecord, String> {
    platform(&app)?.override_task(&task_id, resolution, &operator())
}

#[tauri::command]
pub fn workflow_report(
    run_id: String,
    format: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    platform(&app)?.report(&run_id, &format)
}

// ------------------------------------------------------------------ memory

fn parse_layer(layer: Option<String>) -> Result<Option<MemoryLayer>, String> {
    layer
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_value(serde_json::Value::String(l))
                .map_err(|_| "unknown memory layer".to_string())
        })
        .transpose()
}

#[tauri::command]
pub fn memory_search(
    project_id: String,
    query: String,
    max_items: Option<usize>,
    app: tauri::AppHandle,
) -> Result<RetrievalResult, String> {
    let budget = RetrievalBudget {
        max_items: max_items.unwrap_or(12).clamp(1, 50),
        ..RetrievalBudget::default()
    };
    KnowledgeMemory::new(&db(&app)?).retrieve(&project_id, &query, budget)
}

#[tauri::command]
pub fn memory_list(
    project_id: String,
    layer: Option<String>,
    app: tauri::AppHandle,
) -> Result<Vec<MemoryItem>, String> {
    KnowledgeMemory::new(&db(&app)?).list(&project_id, parse_layer(layer)?, 200)
}

#[tauri::command]
pub fn memory_approve(item_id: String, app: tauri::AppHandle) -> Result<MemoryItem, String> {
    KnowledgeMemory::new(&db(&app)?).approve(&item_id, &operator())
}

#[tauri::command]
pub fn memory_delete(
    project_id: String,
    item_id: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    KnowledgeMemory::new(&db(&app)?).delete(&project_id, &item_id)
}

#[tauri::command]
pub fn memory_clear(
    project_id: String,
    layer: Option<String>,
    app: tauri::AppHandle,
) -> Result<usize, String> {
    KnowledgeMemory::new(&db(&app)?).clear(&project_id, parse_layer(layer)?)
}

#[tauri::command]
pub fn memory_run_graph(
    project_id: String,
    run_id: String,
    app: tauri::AppHandle,
) -> Result<EvidenceGraph, String> {
    let database = db(&app)?;
    let memory = KnowledgeMemory::new(&database);
    let node = memory
        .find_node(&project_id, "run", &run_id)?
        .ok_or("run has not been indexed into memory yet")?;
    memory.neighborhood(&project_id, &node, 2)
}

// ------------------------------------------------------------- cloud provider

#[derive(Serialize)]
pub struct CloudProviderStatus {
    settings: ProviderSettings,
    token_stored: bool,
    credential_backend: &'static str,
}

#[tauri::command]
pub fn cloud_provider_status(app: tauri::AppHandle) -> Result<CloudProviderStatus, String> {
    Ok(CloudProviderStatus {
        settings: settings(&app)?,
        token_stored: KeyringStore
            .get(TOKEN_ACCOUNT)
            .map_err(|e| e.to_string())?
            .is_some(),
        credential_backend: KeyringStore.backend(),
    })
}

#[tauri::command]
pub fn save_cloud_provider_settings(
    base_url: String,
    enabled: bool,
    default_model: Option<String>,
    app: tauri::AppHandle,
) -> Result<ProviderSettings, String> {
    let mut s = settings(&app)?;
    s.base_url = base_url;
    s.enabled = enabled;
    s.role_models.default_cloud = default_model
        .filter(|m| !m.trim().is_empty())
        .map(|m| m.trim().chars().take(128).collect());
    CloudSettings::new(&db(&app)?).save_provider(&s)
}

/// Store the developer key in the OS credential store. Never persisted elsewhere.
#[tauri::command]
pub fn set_cloud_provider_token(token: String) -> Result<bool, String> {
    let secret = Secret::new(token).map_err(|e| e.to_string())?;
    KeyringStore
        .set(TOKEN_ACCOUNT, &secret)
        .map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
pub fn clear_cloud_provider_token() -> Result<bool, String> {
    KeyringStore
        .delete(TOKEN_ACCOUNT)
        .map_err(|e| e.to_string())
}

/// Connection diagnostics: lists models only; sends no project content.
#[tauri::command]
pub async fn cloud_provider_diagnostics(app: tauri::AppHandle) -> Result<Diagnostics, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let s = settings(&app)?;
        let secret = KeyringStore
            .get(TOKEN_ACCOUNT)
            .map_err(|e| e.to_string())?
            .ok_or("no developer key stored")?;
        let profile = ProviderProfile::openmindai(&s.base_url).map_err(|e| e.to_string())?;
        Ok(
            ChatClient::new(profile, Some(secret), ClientConfig::default())
                .map_err(|e| e.to_string())?
                .diagnose(),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn project_cloud_consent(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Option<ConsentRecord>, String> {
    CloudSettings::new(&db(&app)?).consent(&project_id)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn grant_project_cloud_consent(
    project_id: String,
    allow_cloud: bool,
    allow_source_excerpts: bool,
    allow_local_fallback: bool,
    allow_web_research: bool,
    max_payload_bytes: usize,
    app: tauri::AppHandle,
) -> Result<ConsentRecord, String> {
    CloudSettings::new(&db(&app)?).grant_consent(
        &project_id,
        allow_cloud,
        allow_source_excerpts,
        allow_local_fallback,
        allow_web_research,
        max_payload_bytes,
        &operator(),
    )
}

#[tauri::command]
pub fn revoke_project_cloud_consent(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    CloudSettings::new(&db(&app)?).revoke_consent(&project_id)
}

#[tauri::command]
pub fn cloud_request_log(
    project_id: Option<String>,
    app: tauri::AppHandle,
) -> Result<Vec<ProviderRequestRecord>, String> {
    CloudSettings::new(&db(&app)?).recent_requests(project_id.as_deref(), 100)
}

fn ask_request(model: String, prompt: &str) -> ChatRequest {
    ChatRequest {
        model,
        messages: vec![
            ChatMessage::system("You are an engineering assistant inside CodeTwin ML. Answers are unverified suggestions, not evidence."),
            ChatMessage::user(prompt.chars().take(8_000).collect::<String>()),
        ],
        tools: vec![],
        max_tokens: Some(2_048),
        temperature: Some(0.2),
    }
}

/// Show exactly what would leave the machine (after redaction) before sending.
#[tauri::command]
pub fn preview_cloud_question(
    project_id: String,
    prompt: String,
    app: tauri::AppHandle,
) -> Result<EgressPreview, String> {
    let consent = CloudSettings::new(&db(&app)?)
        .consent(&project_id)?
        .map(|c| c.consent);
    let (_, model) = cloud_client(&app)?
        .ok_or("OpenMindAI Cloud is not enabled or no developer key is stored")?;
    prepare_egress(
        consent.as_ref(),
        PROVIDER,
        ask_request(model, &prompt),
        false,
    )
    .map_err(|e| e.to_string())
}

/// Send a previewed question, streaming visible deltas as `cloud://delta`.
#[tauri::command]
pub async fn send_cloud_question(
    project_id: String,
    prompt: String,
    confirmed_sha256: String,
    app: tauri::AppHandle,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let database = db(&app)?;
        let settings_store = CloudSettings::new(&database);
        let consent = settings_store
            .consent(&project_id)?
            .map(|c| c.consent)
            .ok_or("no cloud consent for this project")?;
        let (client, model) = cloud_client(&app)?
            .ok_or("OpenMindAI Cloud is not enabled or no developer key is stored")?;
        // Re-derive the preview so the approved digest must match fresh bytes.
        let preview = prepare_egress(Some(&consent), PROVIDER, ask_request(model, &prompt), false)
            .map_err(|e| e.to_string())?;
        let egress =
            approve_preview(&preview, &consent, &confirmed_sha256).map_err(|e| e.to_string())?;
        let cancel = AtomicBool::new(false);
        let (result, audit) =
            client.chat_stream(&preview.request, Some(&egress), &cancel, &mut |delta| {
                if let StreamDelta::Content(text) = delta {
                    let _ = app.emit(
                        "cloud://delta",
                        serde_json::json!({"payload_sha256": preview.sha256, "text": text}),
                    );
                }
            });
        settings_store.record_request(
            &audit,
            Some(&project_id),
            None,
            None,
            preview.redactions,
            u32::from(result.is_ok()),
            None,
        )?;
        result
            .map(|r| r.content.unwrap_or_default())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
