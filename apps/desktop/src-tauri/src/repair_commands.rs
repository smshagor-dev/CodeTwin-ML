use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use codetwin_core::{
    Database, GuidedSecurityStore, RepairApplicationItemRecord, RepairApplicationRunRecord,
    RepairApplicationService,
    RepairChangeRecord, RepairFindingRecord, RepairPlanRecord, RepairSourceSnapshot,
    RepairVerificationItemRecord, RepairVerificationRunRecord, RepairWorkspaceQueryService,
    SecurityFixAttemptRecord, SecurityFixService, VerifiedRepairService,
};

use super::{with_database, AppState};

pub(crate) static REPAIR_APPLICATION_RUNNING: AtomicBool = AtomicBool::new(false);

fn reject_generic_security_fix_plan_mutation(
    database: &Database,
    repair_id: &str,
    action: &str,
) -> Result<(), String> {
    if SecurityFixService::new(database)
        .attempt_for_repair(repair_id)
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err(format!(
            "security-fix repair plans cannot be {action} through generic Repair commands; use Guided Security Fix & Verify so approval, verification and rollback lifecycle remain authoritative"
        ));
    }
    Ok(())
}

pub(crate) fn finalize_security_fix_application(
    database: &Database,
    attempt_id: &str,
    repair_id: &str,
    application: &RepairApplicationRunRecord,
    backup_root: &Path,
) -> Result<SecurityFixAttemptRecord, String> {
    let service = SecurityFixService::new(database);
    let bookkeeping = (|| -> Result<SecurityFixAttemptRecord, String> {
        let attempt = service
            .record_application(attempt_id, &application.id)
            .map_err(|error| error.to_string())?;
        GuidedSecurityStore::new(database)
            .sync_repair_application_state(repair_id)
            .map_err(|error| error.to_string())?;
        Ok(attempt)
    })();

    match bookkeeping {
        Ok(attempt) => Ok(attempt),
        Err(bookkeeping_error) => {
            let rollback = RepairApplicationService::new(database)
                .rollback_application(&application.id, backup_root);
            match rollback {
                Ok(rollback) if rollback.status == "rolled_back" => {
                    let current = service
                        .get_attempt(attempt_id)
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "security fix attempt disappeared after rollback".to_string())?;
                    match current.application_run_id.as_deref() {
                        Some(run_id) if run_id == application.id => {
                            service
                                .record_rollback(attempt_id, &application.id)
                                .map_err(|error| {
                                    format!(
                                        "{bookkeeping_error}; patch was rolled back but security-fix rollback bookkeeping failed: {error}"
                                    )
                                })?;
                        }
                        None if current.status == "approved" => {
                            service
                                .record_application_recovery_rollback(
                                    attempt_id,
                                    &application.id,
                                )
                                .map_err(|error| {
                                    format!(
                                        "{bookkeeping_error}; patch was rolled back but recovery bookkeeping failed: {error}"
                                    )
                                })?;
                        }
                        _ => {
                            return Err(format!(
                                "{bookkeeping_error}; patch was rolled back but the security-fix attempt is in an unexpected recovery state"
                            ));
                        }
                    }
                    GuidedSecurityStore::new(database)
                        .sync_repair_application_state(repair_id)
                        .map_err(|error| {
                            format!(
                                "{bookkeeping_error}; patch was rolled back but guided lifecycle recovery failed: {error}"
                            )
                        })?;
                    Err(format!(
                        "{bookkeeping_error}; the applied patch was automatically rolled back"
                    ))
                }
                Ok(rollback) => Err(format!(
                    "{bookkeeping_error}; automatic rollback did not complete successfully (status: {})",
                    rollback.status
                )),
                Err(rollback_error) => Err(format!(
                    "{bookkeeping_error}; automatic rollback failed: {rollback_error}"
                )),
            }
        }
    }
}

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
        reject_generic_security_fix_plan_mutation(database, &repair_id, "approved")?;
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
        reject_generic_security_fix_plan_mutation(database, &repair_id, "rejected")?;
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
        reject_generic_security_fix_plan_mutation(database, &repair_id, "verified")?;
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
        let security_fix = SecurityFixService::new(&database)
            .attempt_for_repair(&repair_id)
            .map_err(|error| error.to_string())?;
        if let Some(attempt) = security_fix.as_ref() {
            SecurityFixService::new(&database)
                .assert_application_allowed(&attempt.id)
                .map_err(|error| error.to_string())?;
        }
        let run = RepairApplicationService::new(&database)
            .apply_plan(&repair_id, &backup_root)
            .map_err(|error| error.to_string())?;
        if run.status == "applied" {
            if let Some(attempt) = security_fix.as_ref() {
                finalize_security_fix_application(
                    &database,
                    &attempt.id,
                    &repair_id,
                    &run,
                    &backup_root,
                )?;
            } else {
                GuidedSecurityStore::new(&database)
                    .sync_repair_application_state(&repair_id)
                    .map_err(|error| error.to_string())?;
            }
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
        let security_fix = SecurityFixService::new(&database)
            .attempt_for_application_run(&run_id)
            .map_err(|error| error.to_string())?;
        let run = RepairApplicationService::new(&database)
            .rollback_application(&run_id, backup_root)
            .map_err(|error| error.to_string())?;
        if run.status == "rolled_back" {
            if let Some(attempt) = security_fix.as_ref() {
                SecurityFixService::new(&database)
                    .record_rollback(&attempt.id, &run.id)
                    .map_err(|error| error.to_string())?;
            }
            GuidedSecurityStore::new(&database)
                .sync_repair_application_state(&run.repair_id)
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


#[cfg(test)]
mod security_fix_boundary_tests {
    use super::*;

    fn boundary_database() -> Database {
        let database = Database::open_in_memory().expect("database");
        database
            .connection()
            .execute_batch(
                "INSERT INTO projects(id,root_path,display_name)
                 VALUES ('project-boundary','/tmp/codetwin-boundary','boundary');
                 INSERT INTO web_security_scans(
                    id,project_id,target_url,status,phase,authorization_confirmed,
                    scope_json,config_json,auth_metadata_json
                 ) VALUES (
                    'scan-boundary','project-boundary','http://127.0.0.1:3000',
                    'completed','completed',1,'{}','{}','{}'
                 );
                 INSERT INTO web_security_findings(
                    id,scan_id,fingerprint,category,severity,confidence,target,
                    endpoint_url,method,title,description,reproduction_summary,
                    impact,remediation,references_json
                 ) VALUES (
                    'finding-boundary','scan-boundary','fp-boundary','sql_injection',
                    'high','Likely','http://127.0.0.1:3000',
                    'http://127.0.0.1:3000/search?q=hello','GET',
                    'SQL injection','runtime evidence','local reproduction',
                    'test impact','parameterize query','[]'
                 );
                 INSERT INTO repair_plans(
                    id,project_id,title,rationale,status
                 ) VALUES (
                    'repair-security','project-boundary','security repair',
                    'guided security fix','draft'
                 );
                 INSERT INTO repair_plans(
                    id,project_id,title,rationale,status
                 ) VALUES (
                    'repair-ordinary','project-boundary','ordinary repair',
                    'ordinary repair','draft'
                 );
                 INSERT INTO security_fix_attempts(
                    id,finding_id,project_id,repair_id,attempt_number,eligibility,
                    category,status,root_cause_json,strategy_json,test_plan_json
                 ) VALUES (
                    'attempt-boundary','finding-boundary','project-boundary',
                    'repair-security',1,'AUTO_FIX_CANDIDATE','sql_injection',
                    'prepared','[]','{}','{}'
                 );",
            )
            .expect("boundary fixture");
        database
    }

    #[test]
    fn generic_repair_plan_mutation_is_blocked_for_security_fix_links() {
        let database = boundary_database();
        for action in ["approved", "rejected", "verified"] {
            let error = reject_generic_security_fix_plan_mutation(
                &database,
                "repair-security",
                action,
            )
            .expect_err("security-linked generic mutation must be blocked");
            assert!(error.contains("Guided Security Fix & Verify"));
        }
    }

    #[test]
    fn ordinary_repair_plan_mutation_boundary_remains_open() {
        let database = boundary_database();
        reject_generic_security_fix_plan_mutation(
            &database,
            "repair-ordinary",
            "approved",
        )
        .expect("ordinary repair plan remains supported");
    }
}
