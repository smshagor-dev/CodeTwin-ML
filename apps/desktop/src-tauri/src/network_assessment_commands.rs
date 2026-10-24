use codetwin_core::{
    network_assessment::{NetworkAssessment, NetworkAssessmentRequest, NetworkAssessmentRun},
    Database,
};

use super::{with_database, AppState};

#[tauri::command]
pub fn prepare_network_assessment(
    request: NetworkAssessmentRequest,
    state: tauri::State<'_, AppState>,
) -> Result<NetworkAssessmentRun, String> {
    with_database(&state, |db| NetworkAssessment::new(db).prepare(request))
}

#[tauri::command]
pub fn approve_network_assessment(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<NetworkAssessmentRun, String> {
    with_database(&state, |db| NetworkAssessment::new(db).approve(&id))
}

#[tauri::command]
pub fn cancel_network_assessment(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<NetworkAssessmentRun, String> {
    with_database(&state, |db| NetworkAssessment::new(db).cancel(&id))
}

#[tauri::command]
pub fn list_network_assessments(
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<NetworkAssessmentRun>, String> {
    with_database(&state, |db| NetworkAssessment::new(db).list(limit))
}

#[tauri::command]
pub fn get_network_assessment(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<NetworkAssessmentRun, String> {
    with_database(&state, |db| NetworkAssessment::new(db).get(&id))
}

#[tauri::command]
pub async fn run_network_assessment(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<NetworkAssessmentRun, String> {
    let path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let db = Database::open(path).map_err(|error| error.to_string())?;
        NetworkAssessment::new(&db).execute(&id)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn network_assessment_evidence_report(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    with_database(&state, |db| NetworkAssessment::new(db).evidence_report(&id))
}
