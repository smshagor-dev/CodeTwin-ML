use std::sync::atomic::{AtomicBool, Ordering};

use codetwin_core::{
    native_agent_reasoning::{ModelInsight, ModelReadiness, NativeReviewReasoner},
    Database,
};
use tauri::Manager;

static INTERPRETATION_RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;
impl Drop for RunGuard {
    fn drop(&mut self) {
        INTERPRETATION_RUNNING.store(false, Ordering::SeqCst);
    }
}

fn open_db(app: &tauri::AppHandle) -> Result<Database, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Database::open(dir.join("codetwin.sqlite3")).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn native_model_readiness() -> ModelReadiness {
    NativeReviewReasoner::status()
}

#[tauri::command]
pub fn native_agent_insight(
    id: String,
    app: tauri::AppHandle,
) -> Result<Option<ModelInsight>, String> {
    let db = open_db(&app)?;
    NativeReviewReasoner::new(&db).existing(&id)
}

#[tauri::command]
pub async fn interpret_native_agent_review(
    id: String,
    consent: bool,
    app: tauri::AppHandle,
) -> Result<ModelInsight, String> {
    if !consent {
        return Err("Explicit model processing consent is required".into());
    }
    if INTERPRETATION_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Another model interpretation is in progress".into());
    }
    let guard = RunGuard;
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let db = open_db(&app)?;
        NativeReviewReasoner::new(&db).interpret(&id, consent)
    })
    .await
    .map_err(|error| error.to_string())?
}
