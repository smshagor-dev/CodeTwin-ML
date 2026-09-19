use std::{
    sync::atomic::Ordering,
    time::Instant,
};

use codetwin_core::{
    CodeSecurityService, Database, FixEligibilityAssessment, GuidedSecurityStore,
    MultiFindingOverlap, PatchReview, RepairApplicationRunRecord, RepairApplicationService,
    SecurityFixAttemptRecord, SecurityFixEventRecord, SecurityFixPreparation, SecurityFixService,
    SecurityFixValidationRecord, ValidationResultInput, ProjectIndexService,
};
use serde::Serialize;

use super::{
    repair_commands::{finalize_security_fix_application, REPAIR_APPLICATION_RUNNING},
    with_database, AppState,
};

#[derive(Debug, Serialize)]
pub struct SecurityFixApplicationResult {
    pub attempt: SecurityFixAttemptRecord,
    pub application: RepairApplicationRunRecord,
}

#[derive(Debug, Serialize)]
pub struct SecurityFixValidationRun {
    pub attempt: SecurityFixAttemptRecord,
    pub results: Vec<SecurityFixValidationRecord>,
}

#[tauri::command]
pub(crate) fn evaluate_security_fix_eligibility(
    finding_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<FixEligibilityAssessment, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .evaluate_eligibility(&finding_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn prepare_security_fix(
    finding_id: String,
    allow_additional_attempt: bool,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityFixPreparation, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .prepare_fix(&finding_id, allow_additional_attempt)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn generate_security_fix_patch(
    attempt_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<PatchReview, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .generate_patch(&attempt_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn propose_security_fix_replacement(
    attempt_id: String,
    file_id: String,
    proposed_content: String,
    state: tauri::State<'_, AppState>,
) -> Result<PatchReview, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .propose_replacement(&attempt_id, &file_id, &proposed_content)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn review_security_fix(
    attempt_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<PatchReview, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .review_attempt(&attempt_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn approve_security_fix(
    attempt_id: String,
    expected_patch_hash: String,
    accept_caution: bool,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityFixAttemptRecord, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .approve_attempt(&attempt_id, &expected_patch_hash, accept_caution)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn get_security_fix_attempt(
    attempt_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<SecurityFixAttemptRecord>, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .get_attempt(&attempt_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_fix_attempts(
    finding_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityFixAttemptRecord>, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .list_attempts(&finding_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_fix_validation(
    attempt_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityFixValidationRecord>, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .validation_results(&attempt_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn list_security_fix_events(
    attempt_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<SecurityFixEventRecord>, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .events(&attempt_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) fn analyze_security_fix_overlap(
    finding_ids: Vec<String>,
    state: tauri::State<'_, AppState>,
) -> Result<MultiFindingOverlap, String> {
    with_database(&state, |database| {
        SecurityFixService::new(database)
            .analyze_multi_finding_overlap(&finding_ids)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub(crate) async fn apply_security_fix(
    attempt_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityFixApplicationResult, String> {
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
        let service = SecurityFixService::new(&database);
        let repair_id = service
            .assert_application_allowed(&attempt_id)
            .map_err(|error| error.to_string())?;
        let application = RepairApplicationService::new(&database)
            .apply_plan(&repair_id, &backup_root)
            .map_err(|error| error.to_string())?;
        let attempt = if application.status == "applied" {
            finalize_security_fix_application(
                &database,
                &attempt_id,
                &repair_id,
                &application,
                &backup_root,
            )?
        } else {
            service
                .get_attempt(&attempt_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "security fix attempt disappeared".to_string())?
        };
        Ok(SecurityFixApplicationResult {
            attempt,
            application,
        })
    })
    .await;

    REPAIR_APPLICATION_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) async fn rollback_security_fix(
    attempt_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityFixApplicationResult, String> {
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
        let service = SecurityFixService::new(&database);
        let current = service
            .get_attempt(&attempt_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "security fix attempt not found".to_string())?;
        let run_id = current
            .application_run_id
            .as_deref()
            .ok_or_else(|| "security fix has no applied patch to roll back".to_string())?;
        let application = RepairApplicationService::new(&database)
            .rollback_application(run_id, backup_root)
            .map_err(|error| error.to_string())?;
        let attempt = if application.status == "rolled_back" {
            let attempt = service
                .record_rollback(&attempt_id, &application.id)
                .map_err(|error| error.to_string())?;
            if let Some(repair_id) = current.repair_id.as_deref() {
                GuidedSecurityStore::new(&database)
                    .sync_repair_application_state(repair_id)
                    .map_err(|error| error.to_string())?;
            }
            attempt
        } else {
            current
        };
        Ok(SecurityFixApplicationResult {
            attempt,
            application,
        })
    })
    .await;

    REPAIR_APPLICATION_RUNNING.store(false, Ordering::SeqCst);
    task.map_err(|error| error.to_string())?
}

#[tauri::command]
pub(crate) async fn run_security_fix_validation(
    attempt_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SecurityFixValidationRun, String> {
    let database_path = state.database_path.clone();
    let security_running = state.security_running.clone();

    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(&database_path).map_err(|error| error.to_string())?;
        let service = SecurityFixService::new(&database);
        let attempt = service
            .get_attempt(&attempt_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "security fix attempt not found".to_string())?;
        if !matches!(
            attempt.status.as_str(),
            "applied" | "verification_pending" | "validation_failed"
        ) {
            return Err(format!(
                "security fix validation requires an applied patch; current status is {}",
                attempt.status
            ));
        }

        let root_path: String = database
            .connection()
            .query_row(
                "SELECT root_path FROM projects WHERE id=?1",
                [&attempt.project_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;

        let started = Instant::now();
        match ProjectIndexService::new(&database).index_project(&root_path) {
            Ok(summary) => {
                let text = serde_json::to_string(&summary).map_err(|error| error.to_string())?;
                service
                    .add_validation_result(
                        &attempt_id,
                        ValidationResultInput {
                            command_label: "CodeTwin source re-index",
                            runner_kind: "codetwin_index",
                            targets: &attempt
                                .root_causes
                                .iter()
                                .map(|item| item.relative_path.clone())
                                .collect::<Vec<_>>(),
                            status: "PASS",
                            exit_code: Some(0),
                            duration_ms: Some(started.elapsed().as_millis() as u64),
                            classification: "NONE",
                            stdout_summary: &text,
                            stderr_summary: "",
                        },
                    )
                    .map_err(|error| error.to_string())?;
            }
            Err(error) => {
                let message = error.to_string();
                service
                    .add_validation_result(
                        &attempt_id,
                        ValidationResultInput {
                            command_label: "CodeTwin source re-index",
                            runner_kind: "codetwin_index",
                            targets: &[],
                            status: "FAIL",
                            exit_code: None,
                            duration_ms: Some(started.elapsed().as_millis() as u64),
                            classification: "UNKNOWN",
                            stdout_summary: "",
                            stderr_summary: &message,
                        },
                    )
                    .map_err(|error| error.to_string())?;
            }
        }

        if security_running.swap(true, Ordering::SeqCst) {
            service
                .add_validation_result(
                    &attempt_id,
                    ValidationResultInput {
                        command_label: "CodeTwin static security analysis",
                        runner_kind: "codetwin_security",
                        targets: &[],
                        status: "NOT_EXECUTED",
                        exit_code: None,
                        duration_ms: None,
                        classification: "INFRASTRUCTURE_FAILURE",
                        stdout_summary: "",
                        stderr_summary: "Static security analysis is already running for this workspace.",
                    },
                )
                .map_err(|error| error.to_string())?;
        } else {
            let started = Instant::now();
            let result = CodeSecurityService::new(&database).analyze_project(&attempt.project_id);
            security_running.store(false, Ordering::SeqCst);
            match result {
                Ok(summary) => {
                    let text =
                        serde_json::to_string(&summary).map_err(|error| error.to_string())?;
                    service
                        .add_validation_result(
                            &attempt_id,
                            ValidationResultInput {
                                command_label: "CodeTwin static security analysis",
                                runner_kind: "codetwin_security",
                                targets: &[],
                                status: "PASS",
                                exit_code: Some(0),
                                duration_ms: Some(started.elapsed().as_millis() as u64),
                                classification: "NONE",
                                stdout_summary: &text,
                                stderr_summary: "",
                            },
                        )
                        .map_err(|error| error.to_string())?;
                    service
                        .record_static_after_snapshot(&attempt_id)
                        .map_err(|error| error.to_string())?;
                }
                Err(error) => {
                    let message = error.to_string();
                    service
                        .add_validation_result(
                            &attempt_id,
                            ValidationResultInput {
                                command_label: "CodeTwin static security analysis",
                                runner_kind: "codetwin_security",
                                targets: &[],
                                status: "FAIL",
                                exit_code: None,
                                duration_ms: Some(started.elapsed().as_millis() as u64),
                                classification: "UNKNOWN",
                                stdout_summary: "",
                                stderr_summary: &message,
                            },
                        )
                        .map_err(|error| error.to_string())?;
                }
            }
        }

        for validation in &attempt.test_plan.targeted {
            if !validation.repository_command_execution_required {
                continue;
            }
            service
                .add_validation_result(
                    &attempt_id,
                    ValidationResultInput {
                        command_label: &validation.label,
                        runner_kind: &validation.runner_kind,
                        targets: &validation.targets,
                        status: "NOT_EXECUTED",
                        exit_code: None,
                        duration_ms: None,
                        classification: "INFRASTRUCTURE_FAILURE",
                        stdout_summary: "",
                        stderr_summary: &attempt.test_plan.qa_execution_reason,
                    },
                )
                .map_err(|error| error.to_string())?;
        }

        let attempt = service
            .complete_validation(&attempt_id)
            .map_err(|error| error.to_string())?;
        let results = service
            .validation_results(&attempt_id, 200)
            .map_err(|error| error.to_string())?;
        Ok(SecurityFixValidationRun { attempt, results })
    })
    .await;

    task.map_err(|error| error.to_string())?
}
