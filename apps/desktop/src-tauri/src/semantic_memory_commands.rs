//! Desktop commands for neural semantic memory: the pinned local model
//! (status, explicit download), background indexing with progress events
//! and cancellation, ranked semantic search with explanations, settings,
//! retention, secure deletion, episodes and semantic contradictions.
//!
//! Inference is in-process on this machine. Without a verified model the
//! search still works lexically and the result says why it is not neural.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use codetwin_core::knowledge_memory::{
    download_model, model_status, Episode, IndexJob, IndexStatus, KnowledgeMemory,
    LocalModelStatus, LocalNeuralEmbedder, MemorySettings, RankingConfig, RetrievalBudget,
    RetrievalContext, RetrievalResult, SemanticConflict, MINILM_L6_V2,
};
use serde::Serialize;
use tauri::{Emitter, Manager};

use crate::workflow_commands::{db, operator};

/// Loaded once per process; loading verifies every pinned file again.
static EMBEDDER: OnceLock<Mutex<Option<Arc<LocalNeuralEmbedder>>>> = OnceLock::new();
/// Cancellation flags of running index jobs and the model download.
static CANCEL: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

const DOWNLOAD_KEY: &str = "__model_download__";

fn cancel_flags() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    CANCEL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn model_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("CODETWIN_LOCAL_EMBEDDING_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join("models").join(MINILM_L6_V2.name))
}

fn local_embedder(app: &tauri::AppHandle) -> Result<Arc<LocalNeuralEmbedder>, String> {
    let slot = EMBEDDER.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().map_err(|_| "embedder lock poisoned")?;
    if let Some(e) = guard.as_ref() {
        return Ok(e.clone());
    }
    let loaded = Arc::new(LocalNeuralEmbedder::load(&model_dir(app)?, &MINILM_L6_V2)?);
    *guard = Some(loaded.clone());
    Ok(loaded)
}

#[derive(Serialize)]
pub struct LocalModelInfo {
    repository: &'static str,
    revision: &'static str,
    model: String,
    dims: usize,
    download_bytes: u64,
    directory: String,
    status: LocalModelStatus,
}

#[tauri::command]
pub async fn local_embedding_model_status(app: tauri::AppHandle) -> Result<LocalModelInfo, String> {
    let dir = model_dir(&app)?;
    // Hashing ~90 MB takes a moment; keep it off the UI thread.
    let status = tauri::async_runtime::spawn_blocking({
        let dir = dir.clone();
        move || model_status(&dir, &MINILM_L6_V2)
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(LocalModelInfo {
        repository: MINILM_L6_V2.repository,
        revision: MINILM_L6_V2.revision,
        model: MINILM_L6_V2.model_id(),
        dims: MINILM_L6_V2.dims,
        download_bytes: MINILM_L6_V2.files.iter().map(|f| f.bytes).sum(),
        directory: dir.display().to_string(),
        status,
    })
}

#[derive(Clone, Serialize)]
struct DownloadProgress {
    done: u64,
    total: u64,
}

/// Operator-initiated download of the pinned model from Hugging Face.
/// Progress arrives as `memory-model-download` events.
#[tauri::command]
pub async fn download_local_embedding_model(
    app: tauri::AppHandle,
) -> Result<LocalModelStatus, String> {
    let dir = model_dir(&app)?;
    let flag = Arc::new(AtomicBool::new(false));
    {
        let mut flags = cancel_flags().lock().map_err(|_| "lock poisoned")?;
        if flags.contains_key(DOWNLOAD_KEY) {
            return Err("the model is already downloading".into());
        }
        flags.insert(DOWNLOAD_KEY.into(), flag.clone());
    }
    let handle = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let last = std::cell::Cell::new(0u64);
        download_model(&dir, &MINILM_L6_V2, &flag, &|done, total| {
            // ~1 MB granularity keeps the event stream small.
            if done.saturating_sub(last.get()) >= 1 << 20 || done == total {
                last.set(done);
                let _ = handle.emit("memory-model-download", DownloadProgress { done, total });
            }
        })
        .map(|()| model_status(&dir, &MINILM_L6_V2))
    })
    .await
    .map_err(|e| e.to_string());
    if let Ok(mut flags) = cancel_flags().lock() {
        flags.remove(DOWNLOAD_KEY);
    }
    result?
}

#[derive(Clone, Serialize)]
struct IndexEvent {
    project_id: String,
    job: IndexJob,
}

/// Start background embedding of the project's memory with the local
/// model. Returns at once; `memory-index-progress` events report each
/// batch and the final state (completed, cancelled or failed).
#[tauri::command]
pub fn start_memory_indexing(project_id: String, app: tauri::AppHandle) -> Result<(), String> {
    let embedder = local_embedder(&app)?;
    let database = db(&app)?;
    let flag = Arc::new(AtomicBool::new(false));
    {
        let mut flags = cancel_flags().lock().map_err(|_| "lock poisoned")?;
        if flags.contains_key(&project_id) {
            return Err("this project is already being indexed".into());
        }
        flags.insert(project_id.clone(), flag.clone());
    }
    std::thread::spawn(move || {
        let memory = KnowledgeMemory::new(&database);
        let outcome = memory.index_project(&project_id, embedder.as_ref(), &flag, &mut |job| {
            let _ = app.emit(
                "memory-index-progress",
                IndexEvent {
                    project_id: project_id.clone(),
                    job: job.clone(),
                },
            );
        });
        if let Err(error) = outcome {
            let _ = app.emit(
                "memory-index-error",
                serde_json::json!({ "project_id": project_id, "error": error }),
            );
        }
        if let Ok(mut flags) = cancel_flags().lock() {
            flags.remove(&project_id);
        }
    });
    Ok(())
}

/// Cancel a project's index job, or the model download when `project_id`
/// is empty. Returns whether anything was running.
#[tauri::command]
pub fn cancel_memory_indexing(project_id: String) -> Result<bool, String> {
    let flags = cancel_flags().lock().map_err(|_| "lock poisoned")?;
    let key = if project_id.is_empty() {
        DOWNLOAD_KEY
    } else {
        project_id.as_str()
    };
    Ok(flags
        .get(key)
        .map(|f| f.store(true, Ordering::Relaxed))
        .is_some())
}

#[tauri::command]
pub fn memory_index_status(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<IndexStatus, String> {
    KnowledgeMemory::new(&db(&app)?).index_status(&project_id, &MINILM_L6_V2.model_id())
}

#[tauri::command]
pub fn memory_index_jobs(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<IndexJob>, String> {
    KnowledgeMemory::new(&db(&app)?).index_jobs(&project_id, 20)
}

/// Ranked hybrid search. Uses the project's saved ranking unless one is
/// given; the neural half runs only when the model is verified and the
/// project is indexed, and otherwise `fallback_reason` explains why not.
#[tauri::command]
pub async fn semantic_memory_search(
    project_id: String,
    query: String,
    ranking: Option<RankingConfig>,
    context: Option<RetrievalContext>,
    max_items: Option<usize>,
    app: tauri::AppHandle,
) -> Result<RetrievalResult, String> {
    if query.trim().is_empty() || query.len() > 2_000 {
        return Err("enter a search of up to 2000 characters".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let database = db(&app)?;
        let memory = KnowledgeMemory::new(&database);
        let ranking = match ranking {
            Some(r) => r,
            None => memory.settings(&project_id)?.ranking,
        };
        let budget = RetrievalBudget {
            max_items: max_items.unwrap_or(20).clamp(1, 100),
            max_chars: 40_000,
        };
        let embedder = local_embedder(&app);
        let mut result = memory.retrieve_ranked(
            &project_id,
            &query,
            budget,
            embedder
                .as_ref()
                .ok()
                .map(|e| e.as_ref() as &dyn codetwin_core::knowledge_memory::EmbeddingProvider),
            &ranking,
            &context.unwrap_or_default(),
        )?;
        if let Err(reason) = embedder {
            result.fallback_reason = Some(format!("local neural model unavailable: {reason}"));
        }
        Ok(result)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn memory_settings(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<MemorySettings, String> {
    KnowledgeMemory::new(&db(&app)?).settings(&project_id)
}

#[tauri::command]
pub fn save_memory_settings(
    project_id: String,
    settings: MemorySettings,
    app: tauri::AppHandle,
) -> Result<MemorySettings, String> {
    let database = db(&app)?;
    let memory = KnowledgeMemory::new(&database);
    memory.save_settings(&project_id, &settings)?;
    memory.settings(&project_id)
}

#[tauri::command]
pub fn apply_memory_retention(project_id: String, app: tauri::AppHandle) -> Result<usize, String> {
    KnowledgeMemory::new(&db(&app)?).apply_retention(&project_id, &operator())
}

#[tauri::command]
pub fn secure_delete_memory(
    project_id: String,
    item_id: String,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    KnowledgeMemory::new(&db(&app)?).secure_delete(&project_id, &item_id, &operator())
}

#[tauri::command]
pub fn memory_deletions(
    project_id: String,
    app: tauri::AppHandle,
) -> Result<Vec<serde_json::Value>, String> {
    KnowledgeMemory::new(&db(&app)?).deletions(&project_id, 100)
}

#[tauri::command]
pub fn memory_episodes(project_id: String, app: tauri::AppHandle) -> Result<Vec<Episode>, String> {
    KnowledgeMemory::new(&db(&app)?).episodes(&project_id, 20)
}

#[tauri::command]
pub fn semantic_memory_conflicts(
    project_id: String,
    min_similarity: Option<f64>,
    app: tauri::AppHandle,
) -> Result<Vec<SemanticConflict>, String> {
    KnowledgeMemory::new(&db(&app)?).semantic_conflicts(
        &project_id,
        &MINILM_L6_V2.model_id(),
        min_similarity.unwrap_or(0.8),
    )
}
