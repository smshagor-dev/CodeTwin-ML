use codetwin_core::{
    RepairChangeRecord, RepairFindingRecord, RepairPlanRecord, RepairSourceSnapshot,
    RepairVerificationItemRecord, RepairVerificationRunRecord, RepairWorkspaceQueryService,
    VerifiedRepairService,
};

use super::{with_database, AppState};

#[tauri::command]
pub(crate) fn create_repair_plan(
    project_id: String,
    finding_id: Option<String>,
    title: String,
    rationale: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairPlanRecord, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .create_plan(&project_id, finding_id.as_deref(), &title, &rationale)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn add_repair_file_replacement(
    repair_id: String,
    file_id: String,
    proposed_content: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairChangeRecord, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .add_file_replacement(&repair_id, &file_id, &proposed_content)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn approve_repair_plan(
    repair_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairPlanRecord, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .approve_plan(&repair_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn reject_repair_plan(
    repair_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairPlanRecord, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .reject_plan(&repair_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn verify_repair_plan(
    repair_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairVerificationRunRecord, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .verify_plan(&repair_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_repair_plans(
    project_id: String,
    status: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairPlanRecord>, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .list_plans(&project_id, status.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_repair_changes(
    repair_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairChangeRecord>, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .list_changes(&repair_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn repair_verification_history(
    repair_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairVerificationRunRecord>, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .verification_history(&repair_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_repair_verification_items(
    run_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairVerificationItemRecord>, String> {
    with_database(&state, |database| {
        VerifiedRepairService::new(database)
            .verification_items(&run_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn read_repair_source(
    file_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairSourceSnapshot, String> {
    with_database(&state, |database| {
        RepairWorkspaceQueryService::new(database)
            .read_source_snapshot(&file_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_repair_candidate_findings(
    project_id: String,
    status: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairFindingRecord>, String> {
    with_database(&state, |database| {
        RepairWorkspaceQueryService::new(database)
            .list_findings(&project_id, status.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}
