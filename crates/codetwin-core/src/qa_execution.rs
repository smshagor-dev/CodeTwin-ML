use std::time::{SystemTime, UNIX_EPOCH};

use ::qa_execution::{
    build_execution_plan, current_backend_info, ExecutionCommand, ExecutionPlanStatus,
    SandboxCapabilities, SandboxPolicy, TestExecutionRequest, TestRunnerKind, TrustedToolchain,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::{deterministic_id, Database};

const MAX_PLAN_QUERY: usize = 100;

#[derive(Debug, Error)]
pub enum QaExecutionError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("execution plan error: {0}")]
    Plan(#[from] ::qa_execution::PlanError),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("QA discovery run is not a completed run for this project: {0}")]
    InvalidDiscoveryRun(String),
    #[error("QA execution plan not found: {0}")]
    PlanNotFound(String),
    #[error("blocked QA execution plan cannot be approved: {0}")]
    PlanBlocked(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaExecutionAvailability {
    pub execution_enabled: bool,
    pub backend_kind: String,
    pub enforced_capabilities: SandboxCapabilities,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QaExecutionPlanRecord {
    pub id: String,
    pub project_id: String,
    pub discovery_run_id: Option<String>,
    pub runner: TestRunnerKind,
    pub status: ExecutionPlanStatus,
    pub request: TestExecutionRequest,
    pub toolchain: TrustedToolchain,
    pub policy: SandboxPolicy,
    pub capabilities: SandboxCapabilities,
    pub command: ExecutionCommand,
    pub provenance: Value,
    pub blocking_reasons: Vec<String>,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub superseded_at: Option<String>,
}

pub struct QaExecutionService<'a> {
    database: &'a Database,
}

impl<'a> QaExecutionService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn availability(&self) -> QaExecutionAvailability {
        let backend = current_backend_info();
        let reason = if cfg!(windows) {
            "The Windows Job Object backend now enforces pre-resume process-tree containment, CPU/memory limits, cancellation, timeout, and bounded logs. Public repository test execution remains disabled because filesystem/write and network isolation are not yet enforced."
        } else {
            "No OS-specific QA execution backend is enabled on this platform. Plans may be persisted and reviewed, but CodeTwin will not execute repository tests."
        };
        QaExecutionAvailability {
            execution_enabled: false,
            backend_kind: backend.kind.as_str().to_string(),
            enforced_capabilities: backend.capabilities,
            reason: reason.to_string(),
        }
    }

    pub fn create_plan(
        &self,
        project_id: &str,
        request: TestExecutionRequest,
        toolchain: TrustedToolchain,
        policy: SandboxPolicy,
    ) -> Result<QaExecutionPlanRecord, QaExecutionError> {
        self.create_plan_with_capabilities(
            project_id,
            request,
            toolchain,
            policy,
            self.availability().enforced_capabilities,
        )
    }

    pub(crate) fn create_plan_with_capabilities(
        &self,
        project_id: &str,
        request: TestExecutionRequest,
        toolchain: TrustedToolchain,
        policy: SandboxPolicy,
        capabilities: SandboxCapabilities,
    ) -> Result<QaExecutionPlanRecord, QaExecutionError> {
        let project_last_indexed_at = self.project_last_indexed_at(project_id)?;
        if let Some(discovery_run_id) = request.discovery_run_id.as_deref() {
            self.verify_discovery_run(project_id, discovery_run_id)?;
        }
        let discovery_run_id = request.discovery_run_id.clone();
        let plan = build_execution_plan(request, toolchain, policy, capabilities)?;
        let plan_id = new_plan_id(project_id, &plan.request);
        let provenance = json!({
            "project_last_indexed_at": project_last_indexed_at,
            "discovery_run_id": discovery_run_id,
            "repository_commands_executed": false,
            "package_scripts_executed": false,
            "tests_executed": false,
            "shell_used": false,
            "execution_backend_enabled": false
        });

        self.database.connection().execute(
            "INSERT INTO qa_execution_plans(\
               id, project_id, discovery_run_id, runner_kind, status, request_json, toolchain_json,\
               policy_json, capabilities_json, command_json, provenance_json, blocking_reasons_json\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                plan_id,
                project_id,
                plan.request.discovery_run_id.as_deref(),
                plan.request.runner.as_str(),
                plan.status.as_str(),
                serde_json::to_string(&plan.request)?,
                serde_json::to_string(&plan.toolchain)?,
                serde_json::to_string(&plan.policy)?,
                serde_json::to_string(&plan.capabilities)?,
                serde_json::to_string(&plan.command)?,
                provenance.to_string(),
                serde_json::to_string(&plan.blocking_reasons)?,
            ],
        )?;
        self.get_plan(&plan_id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(plan_id))
    }

    pub fn approve_plan(&self, plan_id: &str) -> Result<QaExecutionPlanRecord, QaExecutionError> {
        let Some(plan) = self.get_plan(plan_id)? else {
            return Err(QaExecutionError::PlanNotFound(plan_id.to_string()));
        };
        match plan.status {
            ExecutionPlanStatus::Blocked => {
                return Err(QaExecutionError::PlanBlocked(plan_id.to_string()));
            }
            ExecutionPlanStatus::Approved => return Ok(plan),
            ExecutionPlanStatus::Planned => {}
        }
        self.database.connection().execute(
            "UPDATE qa_execution_plans SET status = 'approved', approved_at = CURRENT_TIMESTAMP\
             WHERE id = ?1 AND status = 'planned'",
            [plan_id],
        )?;
        self.get_plan(plan_id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(plan_id.to_string()))
    }

    pub fn get_plan(
        &self,
        plan_id: &str,
    ) -> Result<Option<QaExecutionPlanRecord>, QaExecutionError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, project_id, discovery_run_id, runner_kind, status, request_json,\
                        toolchain_json, policy_json, capabilities_json, command_json, provenance_json,\
                        blocking_reasons_json, created_at, approved_at, superseded_at\
                 FROM qa_execution_plans WHERE id = ?1",
                [plan_id],
                plan_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_plans(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<QaExecutionPlanRecord>, QaExecutionError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, discovery_run_id, runner_kind, status, request_json,\
                    toolchain_json, policy_json, capabilities_json, command_json, provenance_json,\
                    blocking_reasons_json, created_at, approved_at, superseded_at\
             FROM qa_execution_plans WHERE project_id = ?1\
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded(limit, MAX_PLAN_QUERY)],
            plan_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn project_last_indexed_at(
        &self,
        project_id: &str,
    ) -> Result<Option<String>, QaExecutionError> {
        self.database
            .connection()
            .query_row(
                "SELECT last_indexed_at FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .ok_or_else(|| QaExecutionError::ProjectNotFound(project_id.to_string()))
    }

    fn verify_discovery_run(
        &self,
        project_id: &str,
        discovery_run_id: &str,
    ) -> Result<(), QaExecutionError> {
        let valid: bool = self.database.connection().query_row(
            "SELECT EXISTS(\
               SELECT 1 FROM analysis_runs\
               WHERE id = ?1 AND project_id = ?2 AND run_kind = 'qa_discovery' AND status = 'completed'\
             )",
            params![discovery_run_id, project_id],
            |row| row.get(0),
        )?;
        if !valid {
            return Err(QaExecutionError::InvalidDiscoveryRun(
                discovery_run_id.to_string(),
            ));
        }
        Ok(())
    }
}

fn plan_from_row(row: &rusqlite::Row<'_>) -> Result<QaExecutionPlanRecord, rusqlite::Error> {
    let runner_text: String = row.get(3)?;
    let status_text: String = row.get(4)?;
    let request_text: String = row.get(5)?;
    let toolchain_text: String = row.get(6)?;
    let policy_text: String = row.get(7)?;
    let capabilities_text: String = row.get(8)?;
    let command_text: String = row.get(9)?;
    let provenance_text: String = row.get(10)?;
    let blocking_text: String = row.get(11)?;
    Ok(QaExecutionPlanRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        discovery_run_id: row.get(2)?,
        runner: parse_runner(&runner_text, 3)?,
        status: parse_plan_status(&status_text, 4)?,
        request: parse_json(&request_text, 5)?,
        toolchain: parse_json(&toolchain_text, 6)?,
        policy: parse_json(&policy_text, 7)?,
        capabilities: parse_json(&capabilities_text, 8)?,
        command: parse_json(&command_text, 9)?,
        provenance: parse_json(&provenance_text, 10)?,
        blocking_reasons: parse_json(&blocking_text, 11)?,
        created_at: row.get(12)?,
        approved_at: row.get(13)?,
        superseded_at: row.get(14)?,
    })
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    text: &str,
    index: usize,
) -> Result<T, rusqlite::Error> {
    serde_json::from_str(text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_runner(text: &str, index: usize) -> Result<TestRunnerKind, rusqlite::Error> {
    match text {
        "pytest" => Ok(TestRunnerKind::Pytest),
        "rust_cargo_test" => Ok(TestRunnerKind::RustCargoTest),
        "go_test" => Ok(TestRunnerKind::GoTest),
        "vitest" => Ok(TestRunnerKind::Vitest),
        "jest" => Ok(TestRunnerKind::Jest),
        "php_unit" => Ok(TestRunnerKind::PhpUnit),
        _ => invalid_enum(text, index),
    }
}

fn parse_plan_status(text: &str, index: usize) -> Result<ExecutionPlanStatus, rusqlite::Error> {
    match text {
        "blocked" => Ok(ExecutionPlanStatus::Blocked),
        "planned" => Ok(ExecutionPlanStatus::Planned),
        "approved" => Ok(ExecutionPlanStatus::Approved),
        _ => invalid_enum(text, index),
    }
}

fn invalid_enum<T>(text: &str, index: usize) -> Result<T, rusqlite::Error> {
    Err(rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        format!("invalid QA execution enum value {text}").into(),
    ))
}

fn new_plan_id(project_id: &str, request: &TestExecutionRequest) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    deterministic_id(
        "qa-execution-plan",
        &[project_id, request.runner.as_str(), &nanos.to_string()],
    )
}

fn bounded(value: usize, maximum: usize) -> i64 {
    i64::try_from(value.clamp(1, maximum)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use ::qa_execution::{
        current_backend_info, ExecutionPlanStatus, SandboxCapabilities, SandboxPolicy,
        TestExecutionRequest, TestRunnerKind, TrustedToolchain,
    };

    use crate::Database;

    use super::{QaExecutionError, QaExecutionService};

    fn project(database: &Database) {
        database
            .connection()
            .execute(
                "INSERT INTO projects(id, root_path, display_name, last_indexed_at)\
                 VALUES ('project-1', '/tmp/project-1', 'project', CURRENT_TIMESTAMP)",
                [],
            )
            .expect("project");
    }

    fn toolchain() -> TrustedToolchain {
        TrustedToolchain {
            runner: TestRunnerKind::Pytest,
            executable_path: if cfg!(windows) {
                "C:/trusted/python.exe".into()
            } else {
                "/trusted/python".into()
            },
            version: "3.12".into(),
            sha256: Some("b".repeat(64)),
            trusted_by_user: true,
        }
    }

    fn request() -> TestExecutionRequest {
        TestExecutionRequest {
            runner: TestRunnerKind::Pytest,
            targets: vec!["tests/test_api.py".into()],
            discovery_run_id: None,
        }
    }

    #[test]
    fn public_planner_uses_only_enforced_backend_capabilities_and_remains_blocked() {
        let database = Database::open_in_memory().expect("database");
        project(&database);
        let service = QaExecutionService::new(&database);
        let availability = service.availability();
        assert_eq!(
            availability.enforced_capabilities,
            current_backend_info().capabilities
        );
        assert!(!availability.execution_enabled);
        let plan = service
            .create_plan(
                "project-1",
                request(),
                toolchain(),
                SandboxPolicy::default(),
            )
            .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Blocked);
        assert!(!plan.blocking_reasons.is_empty());
        assert!(matches!(
            service.approve_plan(&plan.id),
            Err(QaExecutionError::PlanBlocked(_))
        ));
    }

    #[test]
    fn future_capable_backend_plan_can_be_approved_without_executing() {
        let database = Database::open_in_memory().expect("database");
        project(&database);
        let service = QaExecutionService::new(&database);
        let plan = service
            .create_plan_with_capabilities(
                "project-1",
                request(),
                toolchain(),
                SandboxPolicy::default(),
                SandboxCapabilities::fully_enforced(),
            )
            .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Planned);
        let approved = service.approve_plan(&plan.id).expect("approve");
        assert_eq!(approved.status, ExecutionPlanStatus::Approved);
        assert_eq!(approved.provenance["tests_executed"], false);
        assert!(!service.availability().execution_enabled);
    }
}
