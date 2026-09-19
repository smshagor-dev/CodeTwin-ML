use std::sync::atomic::{AtomicBool, Ordering};

use codetwin_core::{
    Database, GuidedSecurityStore, RepairApplicationItemRecord, RepairApplicationRunRecord,
    RepairApplicationService,
    RepairChangeRecord, RepairFindingRecord, RepairPlanRecord, RepairSourceSnapshot,
    RepairVerificationItemRecord, RepairVerificationRunRecord, RepairWorkspaceQueryService,
    VerifiedRepairService,
};

use super::{with_database, AppState};

static REPAIR_APPLICATION_RUNNING: AtomicBool = AtomicBool::new(false);

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

#[tauri::command]
pub(crate) async fn apply_repair_plan(
    repair_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairApplicationRunRecord, String> {
    let database_path = state.database_path.clone();
    let backup_root = database_path
        .parent()
        .ok_or_else(|| "database path has no parent directory".to_string())?
        .join("repair-backups");
    if REPAIR_APPLICATION_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a repair application or rollback is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(&database_path).map_err(|error| error.to_string())?;
        let run = RepairApplicationService::new(&database)
            .apply_plan(&repair_id, backup_root)
            .map_err(|error| error.to_string())?;
        if run.status == "applied" {
            GuidedSecurityStore::new(&database)
                .sync_repair_application_state(&repair_id, "applied")
                .map_err(|error| error.to_string())?;
        }
        Ok(run)
    })
    .await;
    REPAIR_APPLICATION_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) async fn rollback_repair_application(
    run_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<RepairApplicationRunRecord, String> {
    let database_path = state.database_path.clone();
    let backup_root = database_path
        .parent()
        .ok_or_else(|| "database path has no parent directory".to_string())?
        .join("repair-backups");
    if REPAIR_APPLICATION_RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a repair application or rollback is already running".to_string());
    }
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(&database_path).map_err(|error| error.to_string())?;
        let run = RepairApplicationService::new(&database)
            .rollback_application(&run_id, backup_root)
            .map_err(|error| error.to_string())?;
        if run.status == "rolled_back" {
            GuidedSecurityStore::new(&database)
                .sync_repair_application_state(&run.repair_id, "rolled_back")
                .map_err(|error| error.to_string())?;
        }
        Ok(run)
    })
    .await;
    REPAIR_APPLICATION_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) fn repair_application_history(
    repair_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairApplicationRunRecord>, String> {
    with_database(&state, |database| {
        RepairApplicationService::new(database)
            .history(&repair_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_repair_application_items(
    run_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<RepairApplicationItemRecord>, String> {
    with_database(&state, |database| {
        RepairApplicationService::new(database)
            .application_items(&run_id, limit)
            .map_err(|error| error.to_string())
    })
}
