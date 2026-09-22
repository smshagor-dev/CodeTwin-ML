use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ::qa_execution::{
    build_execution_plan, capture_external_read_surface, cleanup_detached_workspace,
    current_backend_info, docker_backend_info, execute_approved_plan_in_docker,
    prepare_dependency_complete_workspace, snapshot_execution_inputs,
    validate_approved_external_read_surface_shape, validate_pinned_container_image,
    ApprovedExternalReadSurface, ExecutionCommand, ExecutionPlanStatus, ExecutionRunStatus,
    SandboxCapabilities, SandboxPolicy, TestExecutionPlan, TestExecutionRequest, TestRunnerKind,
    TrustedToolchain, MAX_PROJECT_MIRROR_BYTES,
    MAX_PROJECT_MIRROR_DIRECTORIES, MAX_PROJECT_MIRROR_FILES,
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
    #[error("external read provenance error: {0}")]
    ExternalProvenance(#[from] ::qa_execution::ExternalProvenanceError),
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
    pub approved_external_read_surface: Option<ApprovedExternalReadSurface>,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub superseded_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QaExecutionRunRecord {
    pub id: String,
    pub plan_id: String,
    pub project_id: String,
    pub status: ExecutionRunStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub parser_completed: bool,
    pub tests_passed: Option<bool>,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
    pub stdout_original_bytes: usize,
    pub stderr_original_bytes: usize,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub result: Value,
    pub project_manifest_sha256: String,
    pub external_read_surface_sha256: String,
    pub created_at: String,
}

impl QaExecutionPlanRecord {
    pub fn execution_plan(&self) -> Result<TestExecutionPlan, QaExecutionError> {
        let (approved_project_manifest_sha256, approved_external_read_surface) = match (
            self.status,
            self.approved_project_manifest.as_ref(),
            self.approved_external_read_surface.as_ref(),
        ) {
            (ExecutionPlanStatus::Approved, Some(manifest), Some(surface)) => {
                (Some(manifest.sha256.clone()), Some(surface.clone()))
            }
            (ExecutionPlanStatus::Approved, _, _) => {
                return Err(QaExecutionError::ApprovalManifest(format!(
                    "approved plan {} is missing project or external read-surface evidence; recreate and approve the plan",
                    self.id
                )))
            }
            (_, None, None) => (None, None),
            _ => {
                return Err(QaExecutionError::ApprovalManifest(format!(
                    "non-approved plan {} unexpectedly carries approval evidence",
                    self.id
                )))
            }
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
            approved_external_read_surface,
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
            "The Windows QA backend has suspended Job Object containment, a restricted low-integrity launcher, bounded detached project mirroring, and approval-bound external runtime provenance. Public repository test execution remains disabled because undeclared host reads are not denied, desktop isolation is incomplete, and network isolation is not enforced."
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

    pub fn docker_availability(
        &self,
        docker_executable: &str,
        image: &str,
    ) -> QaExecutionAvailability {
        match docker_backend_info(docker_executable, image) {
            Ok(info) => QaExecutionAvailability {
                execution_enabled: true,
                backend_kind: info.kind.as_str().to_string(),
                enforced_capabilities: info.capabilities,
                reason: "Digest-pinned Docker sandbox is available with network disabled, read-only source mounting, dropped Linux capabilities, no-new-privileges, bounded memory/CPU/PIDs/output/time, and cancellation.".to_string(),
            },
            Err(error) => QaExecutionAvailability {
                execution_enabled: false,
                backend_kind: "docker_hardened".to_string(),
                enforced_capabilities: SandboxCapabilities::planning_only(),
                reason: error.to_string(),
            },
        }
    }

    pub fn create_docker_plan(
        &self,
        project_id: &str,
        request: TestExecutionRequest,
        toolchain: TrustedToolchain,
        policy: SandboxPolicy,
        image: &str,
    ) -> Result<QaExecutionPlanRecord, QaExecutionError> {
        validate_pinned_container_image(image)?;
        let backend = docker_backend_info(&toolchain.executable_path, image)?;
        if !backend.execution_available
            || backend.capabilities != SandboxCapabilities::fully_enforced()
        {
            return Err(QaExecutionError::PlanBlocked(
                "hardened Docker backend is not fully available".to_string(),
            ));
        }
        let plan = self.create_plan_with_capabilities(
            project_id,
            request,
            toolchain,
            policy,
            backend.capabilities.clone(),
        )?;
        if plan.status != ExecutionPlanStatus::Planned {
            return Ok(plan);
        }
        let mut provenance = plan.provenance.clone();
        let object = provenance.as_object_mut().ok_or_else(|| {
            QaExecutionError::ApprovalManifest(
                "QA execution provenance must be a JSON object".to_string(),
            )
        })?;
        object.insert(
            "execution_backend".to_string(),
            Value::String("docker_hardened_v1".to_string()),
        );
        object.insert("docker_image".to_string(), Value::String(image.to_string()));
        object.insert("docker_backend".to_string(), serde_json::to_value(&backend)?);
        object.insert("execution_backend_enabled".to_string(), Value::Bool(true));
        let changed = self.database.connection().execute(
            "UPDATE qa_execution_plans SET provenance_json=?2 WHERE id=?1 AND status='planned'",
            params![plan.id, provenance.to_string()],
        )?;
        if changed != 1 {
            return Err(QaExecutionError::ApprovalManifest(
                "QA Docker plan changed before backend provenance could be bound".to_string(),
            ));
        }
        self.get_plan(&plan.id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(plan.id))
    }

    pub fn execute_docker_plan(
        &self,
        plan_id: &str,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<QaExecutionRunRecord, QaExecutionError> {
        let plan = self
            .get_plan(plan_id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(plan_id.to_string()))?;
        if plan.status != ExecutionPlanStatus::Approved {
            return Err(QaExecutionError::PlanBlocked(plan_id.to_string()));
        }
        let backend = plan
            .provenance
            .pointer("/execution_backend")
            .and_then(Value::as_str);
        let image = plan
            .provenance
            .pointer("/docker_image")
            .and_then(Value::as_str)
            .ok_or_else(|| QaExecutionError::ApprovalManifest(
                "approved Docker plan is missing its pinned image identity".to_string(),
            ))?;
        if backend != Some("docker_hardened_v1") {
            return Err(QaExecutionError::PlanBlocked(
                "plan was not created for the hardened Docker backend".to_string(),
            ));
        }
        validate_pinned_container_image(image)?;

        let manifest = plan.approved_project_manifest.as_ref().ok_or_else(|| {
            QaExecutionError::ApprovalManifest(
                "approved Docker plan is missing project manifest evidence".to_string(),
            )
        })?;
        let external_surface = plan.approved_external_read_surface.as_ref().ok_or_else(|| {
            QaExecutionError::ApprovalManifest(
                "approved Docker plan is missing runtime provenance evidence".to_string(),
            )
        })?;
        let project_root = self.project_root_path(&plan.project_id)?;
        let snapshots = snapshot_execution_inputs(&project_root, &plan.request.targets)?;
        let execution_plan = plan.execution_plan()?;
        let run_id = new_run_id(&plan.project_id, plan_id);

        self.database.connection().execute(
            "INSERT INTO qa_execution_runs(
               id, plan_id, project_id, status, project_manifest_sha256,
               external_read_surface_sha256, result_json
             ) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6)",
            params![
                run_id,
                plan_id,
                plan.project_id,
                manifest.sha256,
                external_surface.sha256,
                json!({
                    "backend": "docker_hardened_v1",
                    "docker_image": image,
                }).to_string(),
            ],
        )?;
        self.database.connection().execute(
            "UPDATE qa_execution_runs SET status='running', started_at=CURRENT_TIMESTAMP WHERE id=?1",
            [&run_id],
        )?;

        let outcome = match execute_approved_plan_in_docker(
            &execution_plan,
            &project_root,
            &snapshots,
            image,
            cancelled,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.database.connection().execute(
                    "UPDATE qa_execution_runs
                     SET status='infrastructure_error', finished_at=CURRENT_TIMESTAMP,
                         result_json=?2
                     WHERE id=?1",
                    params![run_id, json!({
                        "backend": "docker_hardened_v1",
                        "docker_image": image,
                        "error": error.to_string(),
                    }).to_string()],
                )?;
                return self
                    .get_run(&run_id)?
                    .ok_or_else(|| QaExecutionError::PlanNotFound(run_id));
            }
        };

        let result_json = json!({
            "backend": outcome.backend,
            "docker_image": image,
            "parser_completed": outcome.parser_completed,
            "tests_passed": outcome.tests_passed,
        });
        self.database.connection().execute(
            "UPDATE qa_execution_runs
             SET status=?2, finished_at=CURRENT_TIMESTAMP, duration_ms=?3, exit_code=?4,
                 parser_completed=?5, tests_passed=?6,
                 stdout_excerpt=?7, stderr_excerpt=?8,
                 stdout_original_bytes=?9, stderr_original_bytes=?10,
                 stdout_truncated=?11, stderr_truncated=?12, result_json=?13
             WHERE id=?1",
            params![
                run_id,
                outcome.status.as_str(),
                i64::try_from(outcome.duration_ms).unwrap_or(i64::MAX),
                outcome.exit_code,
                if outcome.parser_completed { 1i64 } else { 0i64 },
                outcome.tests_passed.map(|value| if value { 1i64 } else { 0i64 }),
                outcome.stdout.text,
                outcome.stderr.text,
                i64::try_from(outcome.stdout.original_bytes).unwrap_or(i64::MAX),
                i64::try_from(outcome.stderr.original_bytes).unwrap_or(i64::MAX),
                if outcome.stdout.truncated { 1i64 } else { 0i64 },
                if outcome.stderr.truncated { 1i64 } else { 0i64 },
                result_json.to_string(),
            ],
        )?;
        self.get_run(&run_id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(run_id))
    }

    pub fn get_run(
        &self,
        run_id: &str,
    ) -> Result<Option<QaExecutionRunRecord>, QaExecutionError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, plan_id, project_id, status, started_at, finished_at,
                        duration_ms, exit_code, parser_completed, tests_passed,
                        stdout_excerpt, stderr_excerpt, stdout_original_bytes,
                        stderr_original_bytes, stdout_truncated, stderr_truncated,
                        result_json, project_manifest_sha256,
                        external_read_surface_sha256, created_at
                 FROM qa_execution_runs WHERE id=?1",
                [run_id],
                run_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_runs(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<QaExecutionRunRecord>, QaExecutionError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, plan_id, project_id, status, started_at, finished_at,
                    duration_ms, exit_code, parser_completed, tests_passed,
                    stdout_excerpt, stderr_excerpt, stdout_original_bytes,
                    stderr_original_bytes, stdout_truncated, stderr_truncated,
                    result_json, project_manifest_sha256,
                    external_read_surface_sha256, created_at
             FROM qa_execution_runs WHERE project_id=?1
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded(limit, MAX_PLAN_QUERY)],
            run_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
                if plan.approved_project_manifest.is_none()
                    || plan.approved_external_read_surface.is_none()
                {
                    return Err(QaExecutionError::ApprovalManifest(format!(
                        "approved plan {plan_id} predates complete provenance binding; recreate and approve it"
                    )));
                }
                return Ok(plan);
            }
            ExecutionPlanStatus::Planned => {
                if plan.approved_project_manifest.is_some()
                    || plan.approved_external_read_surface.is_some()
                {
                    return Err(QaExecutionError::ApprovalManifest(format!(
                        "planned plan {plan_id} already contains immutable approval evidence"
                    )));
                }
            }
        }

        let project_root = self.project_root_path(&plan.project_id)?;
        let manifest = self.capture_approval_manifest(&plan, &project_root)?;
        let external_surface = capture_external_read_surface(
            &plan.toolchain.declared_external_read_roots,
            &project_root,
        )?;
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
        provenance_object.insert(
            "approved_external_read_surface".to_string(),
            serde_json::to_value(&external_surface)?,
        );

        let manifest_json = serde_json::to_string(&manifest)?;
        let external_surface_json = serde_json::to_string(&external_surface)?;
        let request_json = serde_json::to_string(&plan.request)?;
        let toolchain_json = serde_json::to_string(&plan.toolchain)?;
        let policy_json = serde_json::to_string(&plan.policy)?;
        let capabilities_json = serde_json::to_string(&plan.capabilities)?;
        let command_json = serde_json::to_string(&plan.command)?;
        let blocking_reasons_json = serde_json::to_string(&plan.blocking_reasons)?;
        let original_provenance_json = plan.provenance.to_string();
        let changed = self.database.connection().execute(
            "UPDATE qa_execution_plans\
             SET status = 'approved', approved_at = CURRENT_TIMESTAMP,\
                 approved_project_manifest_sha256 = ?2, approved_project_manifest_json = ?3,\
                 approved_external_read_surface_sha256 = ?4,\
                 approved_external_read_surface_json = ?5, provenance_json = ?6\
             WHERE id = ?1 AND status = 'planned'\
               AND approved_project_manifest_sha256 IS NULL\
               AND approved_project_manifest_json IS NULL\
               AND approved_external_read_surface_sha256 IS NULL\
               AND approved_external_read_surface_json IS NULL\
               AND request_json = ?7 AND toolchain_json = ?8 AND policy_json = ?9\
               AND capabilities_json = ?10 AND command_json = ?11\
               AND blocking_reasons_json = ?12 AND provenance_json = ?13",
            params![
                plan_id,
                manifest.sha256,
                manifest_json,
                external_surface.sha256,
                external_surface_json,
                provenance.to_string(),
                request_json,
                toolchain_json,
                policy_json,
                capabilities_json,
                command_json,
                blocking_reasons_json,
                original_provenance_json,
            ],
        )?;

        let current = self
            .get_plan(plan_id)?
            .ok_or_else(|| QaExecutionError::PlanNotFound(plan_id.to_string()))?;
        if changed == 1 {
            return Ok(current);
        }
        if current.status == ExecutionPlanStatus::Approved
            && current.approved_project_manifest.as_ref() == Some(&manifest)
            && current.approved_external_read_surface.as_ref() == Some(&external_surface)
        {
            return Ok(current);
        }
        Err(QaExecutionError::ApprovalManifest(format!(
            "plan {plan_id} changed or different provenance won a concurrent approval"
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
                        approved_project_manifest_json, approved_external_read_surface_sha256,\
                        approved_external_read_surface_json, created_at, approved_at, superseded_at\
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
                    approved_project_manifest_json, approved_external_read_surface_sha256,\
                    approved_external_read_surface_json, created_at, approved_at, superseded_at\
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
        project_root: &Path,
    ) -> Result<QaExecutionProjectManifest, QaExecutionError> {
        let snapshots = snapshot_execution_inputs(project_root, &plan.request.targets)?;
        let workspace = prepare_dependency_complete_workspace(
            project_root,
            std::env::temp_dir(),
            &snapshots,
        )?;

        let evidence = if let Some(sha256) = workspace.project_manifest_sha256.as_deref() {
            if valid_sha256(sha256) {
                Ok(QaExecutionProjectManifest {
                    sha256: sha256.to_string(),
                    file_count: u64::try_from(workspace.files.len()).unwrap_or(u64::MAX),
                    directory_count: u64::try_from(workspace.project_directories.len())
                        .unwrap_or(u64::MAX),
                    total_bytes: workspace.total_input_bytes,
                })
            } else {
                Err(QaExecutionError::ApprovalManifest(
                    "prepared project mirror exposed a malformed SHA-256 manifest".to_string(),
                ))
            }
        } else {
            Err(QaExecutionError::ApprovalManifest(
                "prepared project mirror did not expose a SHA-256 manifest".to_string(),
            ))
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

fn run_from_row(row: &rusqlite::Row<'_>) -> Result<QaExecutionRunRecord, rusqlite::Error> {
    let status_text: String = row.get(3)?;
    let result_text: String = row.get(16)?;
    let project_manifest_sha256: Option<String> = row.get(17)?;
    let external_read_surface_sha256: Option<String> = row.get(18)?;
    let project_manifest_sha256 = project_manifest_sha256
        .filter(|value| valid_sha256(value))
        .ok_or_else(|| rusqlite::Error::FromSqlConversionFailure(
            17,
            rusqlite::types::Type::Text,
            "QA execution run is missing a valid project manifest SHA-256".into(),
        ))?;
    let external_read_surface_sha256 = external_read_surface_sha256
        .filter(|value| valid_sha256(value))
        .ok_or_else(|| rusqlite::Error::FromSqlConversionFailure(
            18,
            rusqlite::types::Type::Text,
            "QA execution run is missing a valid external read-surface SHA-256".into(),
        ))?;
    Ok(QaExecutionRunRecord {
        id: row.get(0)?,
        plan_id: row.get(1)?,
        project_id: row.get(2)?,
        status: parse_run_status(&status_text, 3)?,
        started_at: row.get(4)?,
        finished_at: row.get(5)?,
        duration_ms: row
            .get::<_, Option<i64>>(6)?
            .and_then(|value| u64::try_from(value).ok()),
        exit_code: row.get(7)?,
        parser_completed: row.get::<_, i64>(8)? != 0,
        tests_passed: row.get::<_, Option<i64>>(9)?.map(|value| value != 0),
        stdout_excerpt: row.get(10)?,
        stderr_excerpt: row.get(11)?,
        stdout_original_bytes: usize::try_from(row.get::<_, i64>(12)?).unwrap_or(usize::MAX),
        stderr_original_bytes: usize::try_from(row.get::<_, i64>(13)?).unwrap_or(usize::MAX),
        stdout_truncated: row.get::<_, i64>(14)? != 0,
        stderr_truncated: row.get::<_, i64>(15)? != 0,
        result: parse_json(&result_text, 16)?,
        project_manifest_sha256,
        external_read_surface_sha256,
        created_at: row.get(19)?,
    })
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
    let external_surface_sha256: Option<String> = row.get(14)?;
    let external_surface_json: Option<String> = row.get(15)?;
    let approved_project_manifest = parse_optional_manifest(manifest_sha256, manifest_json, 13)?;
    let approved_external_read_surface = parse_optional_external_surface(
        external_surface_sha256,
        external_surface_json,
        15,
    )?;
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
        approved_external_read_surface,
        created_at: row.get(16)?,
        approved_at: row.get(17)?,
        superseded_at: row.get(18)?,
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
            let file_limit = u64::try_from(MAX_PROJECT_MIRROR_FILES).unwrap_or(u64::MAX);
            let directory_limit =
                u64::try_from(MAX_PROJECT_MIRROR_DIRECTORIES).unwrap_or(u64::MAX);
            if manifest.sha256 != sha256
                || !valid_sha256(&sha256)
                || manifest.file_count == 0
                || manifest.file_count > file_limit
                || manifest.directory_count > directory_limit
                || manifest.total_bytes > MAX_PROJECT_MIRROR_BYTES
            {
                return invalid_manifest(index);
            }
            Ok(Some(manifest))
        }
        _ => invalid_manifest(index),
    }
}

fn parse_optional_external_surface(
    sha256: Option<String>,
    surface_json: Option<String>,
    index: usize,
) -> Result<Option<ApprovedExternalReadSurface>, rusqlite::Error> {
    match (sha256, surface_json) {
        (None, None) => Ok(None),
        (Some(sha256), Some(text)) => {
            let surface: ApprovedExternalReadSurface = parse_json(&text, index)?;
            if surface.sha256 != sha256
                || validate_approved_external_read_surface_shape(&surface).is_err()
            {
                return invalid_external_surface(index);
            }
            Ok(Some(surface))
        }
        _ => invalid_external_surface(index),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid_manifest<T>(index: usize) -> Result<T, rusqlite::Error> {
    Err(rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        "inconsistent QA approval project manifest columns".into(),
    ))
}

fn invalid_external_surface<T>(index: usize) -> Result<T, rusqlite::Error> {
    Err(rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        "inconsistent QA approval external read-surface columns".into(),
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

fn parse_run_status(text: &str, index: usize) -> Result<ExecutionRunStatus, rusqlite::Error> {
    match text {
        "queued" => Ok(ExecutionRunStatus::Queued),
        "running" => Ok(ExecutionRunStatus::Running),
        "completed" => Ok(ExecutionRunStatus::Completed),
        "failed" => Ok(ExecutionRunStatus::Failed),
        "timed_out" => Ok(ExecutionRunStatus::TimedOut),
        "cancelled" => Ok(ExecutionRunStatus::Cancelled),
        "infrastructure_error" => Ok(ExecutionRunStatus::InfrastructureError),
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

fn new_run_id(project_id: &str, plan_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    deterministic_id(
        "qa-execution-run",
        &[project_id, plan_id, &nanos.to_string()],
    )
}

fn bounded(value: usize, maximum: usize) -> i64 {
    i64::try_from(value.clamp(1, maximum)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use ::qa_execution::{
        cleanup_detached_workspace, current_backend_info, prepare_dependency_complete_workspace,
        snapshot_execution_inputs, verify_external_read_surface, DeclaredExternalReadRoot,
        ExecutionPlanStatus, ExternalProvenanceError, ExternalReadRootKind, SandboxCapabilities,
        SandboxPolicy, TestExecutionRequest, TestRunnerKind, TrustedToolchain,
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

    fn runtime_root() -> TempDir {
        let root = tempfile::tempdir().expect("runtime root");
        fs::create_dir_all(root.path().join("Lib")).expect("runtime lib");
        fs::write(root.path().join("Lib/runtime.py"), "VALUE = 1\n").expect("runtime file");
        root
    }

    fn toolchain(runtime_root: &Path) -> TrustedToolchain {
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
            declared_external_read_roots: vec![DeclaredExternalReadRoot {
                kind: ExternalReadRootKind::RuntimeRoot,
                path: runtime_root.to_string_lossy().into_owned(),
            }],
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
        let runtime = runtime_root();
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
                toolchain(runtime.path()),
                SandboxPolicy::default(),
            )
            .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Blocked);
        assert!(plan.approved_project_manifest.is_none());
        assert!(plan.approved_external_read_surface.is_none());
        assert!(!plan.blocking_reasons.is_empty());
        assert!(matches!(
            service.approve_plan(&plan.id),
            Err(QaExecutionError::PlanBlocked(_))
        ));
    }

    #[test]
    fn future_capable_backend_plan_approval_binds_project_and_external_provenance() {
        let database = Database::open_in_memory().expect("database");
        let project = project(&database);
        let runtime = runtime_root();
        let service = QaExecutionService::new(&database);
        let plan = service
            .create_plan_with_capabilities(
                "project-1",
                request(),
                toolchain(runtime.path()),
                SandboxPolicy::default(),
                SandboxCapabilities::fully_enforced(),
            )
            .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Planned);
        assert!(plan.approved_project_manifest.is_none());
        assert!(plan.approved_external_read_surface.is_none());

        let approved = service.approve_plan(&plan.id).expect("approve");
        assert_eq!(approved.status, ExecutionPlanStatus::Approved);
        let manifest = approved
            .approved_project_manifest
            .as_ref()
            .expect("approval manifest");
        let external_surface = approved
            .approved_external_read_surface
            .as_ref()
            .expect("external surface");
        assert_eq!(manifest.sha256.len(), 64);
        assert_eq!(manifest.file_count, 2);
        assert!(manifest.directory_count >= 1);
        assert_eq!(external_surface.sha256.len(), 64);
        assert_eq!(external_surface.roots.len(), 1);
        assert_eq!(approved.provenance["tests_executed"], false);
        assert_eq!(
            approved.provenance["approved_project_manifest"]["sha256"].as_str(),
            Some(manifest.sha256.as_str())
        );
        assert_eq!(
            approved.provenance["approved_external_read_surface"]["sha256"].as_str(),
            Some(external_surface.sha256.as_str())
        );
        let execution_plan = approved.execution_plan().expect("typed execution plan");
        assert_eq!(
            execution_plan.approved_project_manifest_sha256.as_deref(),
            Some(manifest.sha256.as_str())
        );
        assert_eq!(
            execution_plan.approved_external_read_surface.as_ref(),
            Some(external_surface)
        );
        assert!(!service.availability().execution_enabled);

        fs::write(project.path().join("module.py"), "VALUE = 2\n").expect("mutate dependency");
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

        fs::write(runtime.path().join("Lib/runtime.py"), "VALUE = 2\n")
            .expect("mutate runtime");
        assert!(matches!(
            verify_external_read_surface(
                &approved.toolchain.declared_external_read_roots,
                external_surface,
                project.path(),
            ),
            Err(ExternalProvenanceError::SurfaceChanged)
        ));
    }

    #[test]
    fn future_capable_approval_rejects_missing_external_roots() {
        let database = Database::open_in_memory().expect("database");
        let _project = project(&database);
        let runtime = runtime_root();
        let service = QaExecutionService::new(&database);
        let mut trusted = toolchain(runtime.path());
        trusted.declared_external_read_roots.clear();
        let plan = service
            .create_plan_with_capabilities(
                "project-1",
                request(),
                trusted,
                SandboxPolicy::default(),
                SandboxCapabilities::fully_enforced(),
            )
            .expect("plan");
        assert!(matches!(
            service.approve_plan(&plan.id),
            Err(QaExecutionError::ExternalProvenance(
                ExternalProvenanceError::NoDeclaredRoots
            ))
        ));
    }

    #[test]
    fn database_trigger_rejects_approval_without_complete_provenance() {
        let database = Database::open_in_memory().expect("database");
        let _project = project(&database);
        let runtime = runtime_root();
        let service = QaExecutionService::new(&database);
        let plan = service
            .create_plan_with_capabilities(
                "project-1",
                request(),
                toolchain(runtime.path()),
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
            .expect_err("provenance trigger");
        assert!(error.to_string().contains("requires a valid bound"));
    }

    #[test]
    fn database_trigger_rejects_project_only_approval_without_external_surface() {
        let database = Database::open_in_memory().expect("database");
        let _project = project(&database);
        let runtime = runtime_root();
        let service = QaExecutionService::new(&database);
        let plan = service
            .create_plan_with_capabilities(
                "project-1",
                request(),
                toolchain(runtime.path()),
                SandboxPolicy::default(),
                SandboxCapabilities::fully_enforced(),
            )
            .expect("plan");
        let digest = "a".repeat(64);
        let error = database
            .connection()
            .execute(
                "UPDATE qa_execution_plans\
                 SET status = 'approved', approved_project_manifest_sha256 = ?2,\
                     approved_project_manifest_json = '{}'\
                 WHERE id = ?1",
                params![plan.id, digest],
            )
            .expect_err("external provenance trigger");
        assert!(error.to_string().contains("external read surface"));
    }

    #[test]
    fn approved_plan_specification_is_database_immutable() {
        let database = Database::open_in_memory().expect("database");
        let _project = project(&database);
        let runtime = runtime_root();
        let service = QaExecutionService::new(&database);
        let plan = service
            .create_plan_with_capabilities(
                "project-1",
                request(),
                toolchain(runtime.path()),
                SandboxPolicy::default(),
                SandboxCapabilities::fully_enforced(),
            )
            .expect("plan");
        let approved = service.approve_plan(&plan.id).expect("approve");
        let error = database
            .connection()
            .execute(
                "UPDATE qa_execution_plans SET toolchain_json = '{}' WHERE id = ?1",
                params![approved.id],
            )
            .expect_err("approved spec immutable");
        assert!(error.to_string().contains("specification is immutable"));
    }
}
