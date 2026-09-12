use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use ::qa_execution::{
    build_execution_plan, cleanup_detached_workspace, current_backend_info,
    prepare_dependency_complete_workspace, snapshot_execution_inputs, ExecutionCommand,
    ExecutionPlanStatus, SandboxCapabilities, SandboxPolicy, TestExecutionPlan,
    TestExecutionRequest, TestRunnerKind, TrustedToolchain,
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
    #[error("execution input snapshot error: {0}")]
    InputSnapshot(#[from] ::qa_execution::BackendExecutionError),
    #[error("project mirror error: {0}")]
    ProjectMirror(#[from] ::qa_execution::WorkspaceError),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("QA discovery run is not a completed run for this project: {0}")]
    InvalidDiscoveryRun(String),
    #[error("QA execution plan not found: {0}")]
    PlanNotFound(String),
    #[error("blocked QA execution plan cannot be approved: {0}")]
    PlanBlocked(String),
    #[error("QA execution approval manifest error: {0}")]
    ApprovalManifest(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaExecutionAvailability {
    pub execution_enabled: bool,
    pub backend_kind: String,
    pub enforced_capabilities: SandboxCapabilities,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QaExecutionProjectManifest {
    pub sha256: String,
    pub file_count: u64,
    pub directory_count: u64,
    pub total_bytes: u64,
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
    pub approved_project_manifest: Option<QaExecutionProjectManifest>,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub superseded_at: Option<String>,
}

impl QaExecutionPlanRecord {
    pub fn execution_plan(&self) -> Result<TestExecutionPlan, QaExecutionError> {
        let approved_project_manifest_sha256 = match (
            self.status,
            self.approved_project_manifest.as_ref(),
        ) {
            (ExecutionPlanStatus::Approved, Some(manifest)) => Some(manifest.sha256.clone()),
            (ExecutionPlanStatus::Approved, None) => {
                return Err(QaExecutionError::ApprovalManifest(format!(
                    "approved plan {} has no bound project manifest; recreate and approve the plan",
                    self.id
                )))
            }
            (_, Some(_)) => {
                return Err(QaExecutionError::ApprovalManifest(format!(
                    "non-approved plan {} unexpectedly carries approval manifest evidence",
                    self.id
                )))
            }
            (_, None) => None,
        };

        Ok(TestExecutionPlan {
            status: self.status,
            blocking_reasons: self.blocking_reasons.clone(),
            request: self.request.clone(),
            toolchain: self.toolchain.clone(),
            policy: self.policy.clone(),
            capabilities: self.capabilities.clone(),
            command: self.command.clone(),
            approved_project_manifest_sha256,
        })
    }
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
            "The Windows QA backend has suspended Job Object containment, a restricted low-integrity launcher, and bounded detached project mirroring. Public repository test execution remains disabled because filesystem capability validation, desktop isolation, and network isolation are not complete."
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
            ExecutionPlanStatus::Approved => {
                if plan.approved_project_manifest.is_none() {
                    return Err(QaExecutionError::ApprovalManifest(format!(
                        "approved plan {plan_id} predates manifest binding; recreate and approve it"
                    )));
                }
                return Ok(plan);
            }
            ExecutionPlanStatus::Planned => {
                if plan.approved_project_manifest.is_some() {
                    return Err(QaExecutionError::ApprovalManifest(format!(
                        "planned plan {plan_id} already contains immutable approval evidence"
                    )));
                }
            }
        }

        let manifest = self.capture_approval_manifest(&plan)?;
        let mut provenance = plan.provenance.clone();
        let Some(provenance_object) = provenance.as_object_mut() else {
            return Err(QaExecutionError::ApprovalManifest(format!(
                "plan {plan_id} provenance is not a JSON object"
            )));
        };
        provenance_object.insert(
            "approved_project_manifest".to_string(),
            serde_json::to_value(&manifest)?,
        );

        let manifest_json = serde_json::to_string(&manifest)?;
        let changed = self.database.connection().execute(
            "UPDATE qa_execution_plans\
             SET status = 'approved', approved_at = CURRENT_TIMESTAMP,\
                 approved_project_manifest_sha256 = ?2, approved_project_manifest_json = ?3,\
                 provenance_json = ?4\
             WHERE id = ?1 AND status = 'planned'\
               AND approved_project_manifest_sha256 IS NULL\
               AND approved_project_manifest_json IS NULL",
            params![plan_id, manifest.sha256, manifest_json, provenance.to_string()],
        )?;

        let current = self
            .get_plan(plan_id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(plan_id.to_string()))?;
        if changed == 1 {
            return Ok(current);
        }
        if current.status == ExecutionPlanStatus::Approved
            && current.approved_project_manifest.is_some()
        {
            return Ok(current);
        }
        Err(QaExecutionError::ApprovalManifest(format!(
            "plan {plan_id} changed while approval evidence was being captured"
        )))
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
                        blocking_reasons_json, approved_project_manifest_sha256,\
                        approved_project_manifest_json, created_at, approved_at, superseded_at\
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
                    blocking_reasons_json, approved_project_manifest_sha256,\
                    approved_project_manifest_json, created_at, approved_at, superseded_at\
             FROM qa_execution_plans WHERE project_id = ?1\
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded(limit, MAX_PLAN_QUERY)],
            plan_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn capture_approval_manifest(
        &self,
        plan: &QaExecutionPlanRecord,
    ) -> Result<QaExecutionProjectManifest, QaExecutionError> {
        let project_root = self.project_root_path(&plan.project_id)?;
        let snapshots = snapshot_execution_inputs(&project_root, &plan.request.targets)?;
        let workspace = prepare_dependency_complete_workspace(
            &project_root,
            std::env::temp_dir(),
            &snapshots,
        )?;

        let evidence = match workspace.project_manifest_sha256.as_deref() {
            Some(sha256)
                if sha256.len() == 64
                    && sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                Ok(QaExecutionProjectManifest {
                    sha256: sha256.to_string(),
                    file_count: u64::try_from(workspace.files.len()).unwrap_or(u64::MAX),
                    directory_count: u64::try_from(workspace.project_directories.len())
                        .unwrap_or(u64::MAX),
                    total_bytes: workspace.total_input_bytes,
                })
            }
            _ => Err(QaExecutionError::ApprovalManifest(
                "prepared project mirror did not expose a valid SHA-256 manifest".to_string(),
            )),
        };

        cleanup_detached_workspace(&workspace)?;
        evidence
    }

    fn project_root_path(&self, project_id: &str) -> Result<PathBuf, QaExecutionError> {
        self.database
            .connection()
            .query_row(
                "SELECT root_path FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(PathBuf::from)
            .ok_or_else(|| QaExecutionError::ProjectNotFound(project_id.to_string()))
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
    let manifest_sha256: Option<String> = row.get(12)?;
    let manifest_json: Option<String> = row.get(13)?;
    let approved_project_manifest =
        parse_optional_manifest(manifest_sha256, manifest_json, 13)?;
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
        approved_project_manifest,
        created_at: row.get(14)?,
        approved_at: row.get(15)?,
        superseded_at: row.get(16)?,
    })
}

fn parse_optional_manifest(
    sha256: Option<String>,
    manifest_json: Option<String>,
    index: usize,
) -> Result<Option<QaExecutionProjectManifest>, rusqlite::Error> {
    match (sha256, manifest_json) {
        (None, None) => Ok(None),
        (Some(sha256), Some(text)) => {
            let manifest: QaExecutionProjectManifest = parse_json(&text, index)?;
            if manifest.sha256 != sha256
                || sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return invalid_manifest(index);
            }
            Ok(Some(manifest))
        }
        _ => invalid_manifest(index),
    }
}

fn invalid_manifest<T>(index: usize) -> Result<T, rusqlite::Error> {
    Err(rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        "inconsistent QA approval project manifest columns".into(),
    ))
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
    use std::fs;

    use ::qa_execution::{
        cleanup_detached_workspace, current_backend_info, prepare_dependency_complete_workspace,
        snapshot_execution_inputs, ExecutionPlanStatus, SandboxCapabilities, SandboxPolicy,
        TestExecutionRequest, TestRunnerKind, TrustedToolchain,
    };
    use rusqlite::params;
    use tempfile::TempDir;

    use crate::Database;

    use super::{QaExecutionError, QaExecutionService};

    fn project(database: &Database) -> TempDir {
        let root = tempfile::tempdir().expect("project root");
        fs::create_dir_all(root.path().join("tests")).expect("tests directory");
        fs::write(
            root.path().join("tests/test_api.py"),
            "def test_ok():\n    assert True\n",
        )
        .expect("test source");
        fs::write(root.path().join("module.py"), "VALUE = 1\n").expect("module source");
        let root_path = root.path().to_string_lossy().into_owned();
        database
            .connection()
            .execute(
                "INSERT INTO projects(id, root_path, display_name, last_indexed_at)\
                 VALUES ('project-1', ?1, 'project', CURRENT_TIMESTAMP)",
                [root_path],
            )
            .expect("project");
        root
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
        let _project = project(&database);
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
        assert!(plan.approved_project_manifest.is_none());
        assert!(!plan.blocking_reasons.is_empty());
        assert!(matches!(
            service.approve_plan(&plan.id),
            Err(QaExecutionError::PlanBlocked(_))
        ));
    }

    #[test]
    fn future_capable_backend_plan_approval_binds_project_manifest_without_executing() {
        let database = Database::open_in_memory().expect("database");
        let project = project(&database);
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
        assert!(plan.approved_project_manifest.is_none());

        let approved = service.approve_plan(&plan.id).expect("approve");
        assert_eq!(approved.status, ExecutionPlanStatus::Approved);
        let manifest = approved
            .approved_project_manifest
            .as_ref()
            .expect("approval manifest");
        assert_eq!(manifest.sha256.len(), 64);
        assert_eq!(manifest.file_count, 2);
        assert!(manifest.directory_count >= 1);
        assert_eq!(approved.provenance["tests_executed"], false);
        assert_eq!(
            approved.provenance["approved_project_manifest"]["sha256"],
            manifest.sha256
        );
        let execution_plan = approved.execution_plan().expect("typed execution plan");
        assert_eq!(
            execution_plan.approved_project_manifest_sha256.as_deref(),
            Some(manifest.sha256.as_str())
        );
        assert!(!service.availability().execution_enabled);

        fs::write(project.path().join("module.py"), "VALUE = 2\n").expect("mutate dependency");
        let approved_again = service.approve_plan(&plan.id).expect("already approved");
        assert_eq!(
            approved_again.approved_project_manifest,
            approved.approved_project_manifest
        );

        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(project.path(), &targets).expect("snapshots");
        let current_workspace = prepare_dependency_complete_workspace(
            project.path(),
            std::env::temp_dir(),
            &snapshots,
        )
        .expect("current project mirror");
        assert_ne!(
            current_workspace.project_manifest_sha256.as_deref(),
            Some(manifest.sha256.as_str())
        );
        cleanup_detached_workspace(&current_workspace).expect("cleanup current mirror");
    }

    #[test]
    fn database_trigger_rejects_approval_without_manifest_binding() {
        let database = Database::open_in_memory().expect("database");
        let _project = project(&database);
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
        let error = database
            .connection()
            .execute(
                "UPDATE qa_execution_plans SET status = 'approved' WHERE id = ?1",
                params![plan.id],
            )
            .expect_err("manifest trigger");
        assert!(error
            .to_string()
            .contains("requires a bound project manifest"));
    }
}
