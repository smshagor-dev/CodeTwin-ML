//! Glue between the desktop and the durable orchestrator: builds the policy
//! context from persisted consent, the tool runtime and the specialist
//! registry; plans, approves, executes and recovers workflow runs.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use model_gateway::ChatClient;
use rusqlite::Connection;
use serde::Serialize;
use task_orchestrator::policy::{PolicyContext, SandboxSupport};
use task_orchestrator::report::{build_report, RunReport};
use task_orchestrator::store::{
    ApprovalRequest, AttemptRecord, EventRecord, OverrideResolution, RecoveryReport, RunBudgets,
    RunRecord, RunSpec, TaskRecord, ToolInvocationRecord,
};
use task_orchestrator::{CancelToken, GlobalLimits, Orchestrator, OrchestratorConfig, Store};

use crate::agent_tools::{CapabilityStatus, CloudAccess, CoreToolRuntime};
use crate::cloud_settings::CloudSettings;
use crate::knowledge_memory::KnowledgeMemory;
use crate::specialist_workers::{plan_investigation, registry, InvestigationOptions};
use crate::Database;

pub const APPROVAL_TTL_MS: i64 = 24 * 3_600_000;

#[derive(Debug, Clone, Serialize)]
pub struct RunDetail {
    pub run: RunRecord,
    pub tasks: Vec<TaskRecord>,
    pub approvals: Vec<ApprovalRequest>,
    pub attempts: Vec<AttemptRecord>,
    pub tool_invocations: Vec<ToolInvocationRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkerRole {
    pub role: String,
    pub display_name: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub output_class: String,
}

/// Cloud configuration resolved by the desktop (token from the OS store).
#[derive(Clone)]
pub struct CloudProvider {
    pub client: Arc<ChatClient>,
    pub model: String,
}

pub struct WorkflowPlatform {
    db_path: PathBuf,
    instance_id: String,
    limits: Arc<GlobalLimits>,
    cloud: Option<CloudProvider>,
}

fn open_connection(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_secs(30))
        .map_err(|e| e.to_string())?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| e.to_string())?;
    Ok(conn)
}

impl WorkflowPlatform {
    /// `db_path` must be an already migrated CodeTwin database.
    pub fn new(
        db_path: PathBuf,
        instance_id: String,
        limits: Arc<GlobalLimits>,
        cloud: Option<CloudProvider>,
    ) -> Self {
        Self {
            db_path,
            instance_id,
            limits,
            cloud,
        }
    }

    fn database(&self) -> Result<Database, String> {
        Database::open_native_worker(&self.db_path).map_err(|e| e.to_string())
    }

    fn with_store<T>(
        &self,
        f: impl FnOnce(&Store<'_>) -> Result<T, task_orchestrator::StoreError>,
    ) -> Result<T, String> {
        let conn = open_connection(&self.db_path)?;
        f(&Store::new(&conn)).map_err(|e| e.to_string())
    }

    /// Policy context and tools for one project, from persisted consent.
    fn runtime_for(&self, project_id: &str) -> Result<(PolicyContext, CoreToolRuntime), String> {
        let db = self.database()?;
        let consent = CloudSettings::new(&db).consent(project_id)?;
        let cloud_ok =
            consent.as_ref().is_some_and(|c| c.consent.allow_cloud) && self.cloud.is_some();
        let research_ok = consent.as_ref().is_some_and(|c| c.allow_web_research);
        let policy = PolicyContext {
            // Workflow tools never spawn processes; no sandbox claim is made.
            sandbox: SandboxSupport::Unavailable,
            cloud_consent: cloud_ok,
            research_enabled: research_ok,
        };
        let cloud = if cloud_ok {
            let provider = self.cloud.as_ref().expect("checked");
            Some(CloudAccess {
                client: provider.client.clone(),
                consent: consent.expect("checked").consent,
                model: provider.model.clone(),
            })
        } else {
            None
        };
        let research = research_ok.then(research_retrieval::FetchPolicy::default);
        Ok((
            policy,
            CoreToolRuntime::new(self.db_path.clone(), research, cloud),
        ))
    }

    fn orchestrator(&self, project_id: &str) -> Result<Orchestrator, String> {
        let (policy, tools) = self.runtime_for(project_id)?;
        Ok(Orchestrator::new(
            open_connection(&self.db_path)?,
            registry(),
            Arc::new(tools),
            policy,
            OrchestratorConfig {
                instance_id: self.instance_id.clone(),
                approval_ttl_ms: APPROVAL_TTL_MS,
                ..OrchestratorConfig::default()
            },
            self.limits.clone(),
        ))
    }

    pub fn roles() -> Vec<WorkerRole> {
        registry()
            .contracts()
            .into_iter()
            .map(|c| WorkerRole {
                role: c.role,
                display_name: c.display_name,
                description: c.description,
                capabilities: c
                    .capabilities
                    .iter()
                    .map(|c| c.as_str().to_owned())
                    .collect(),
                output_class: c.output_class.as_str().into(),
            })
            .collect()
    }

    pub fn capability_matrix(&self, project_id: &str) -> Result<Vec<CapabilityStatus>, String> {
        Ok(self.runtime_for(project_id)?.1.capability_matrix())
    }

    /// Plan a read-only investigation. Nothing executes until approved.
    pub fn create_investigation(
        &self,
        project_id: &str,
        goal: &str,
        owner: &str,
        options: &InvestigationOptions,
        budgets: Option<RunBudgets>,
    ) -> Result<(RunRecord, Vec<ApprovalRequest>), String> {
        let (policy, _) = self.runtime_for(project_id)?;
        let orchestrator = self.orchestrator(project_id)?;
        let contracts = orchestrator.contracts();
        let mut budgets = budgets.unwrap_or_default();
        if options.cloud_review && budgets.max_credits == 0 {
            budgets.max_credits = 3;
        }
        let tasks = plan_investigation(goal, options);
        orchestrator
            .with_store(|s| {
                let run = s.create_run(&RunSpec {
                    project_id: project_id.into(),
                    goal: goal.into(),
                    owner: owner.into(),
                    budgets,
                    cloud_consented: policy.cloud_consent,
                })?;
                let approvals =
                    s.submit_plan(&run.id, &tasks, &contracts, &policy, APPROVAL_TTL_MS);
                match approvals {
                    Ok(approvals) => Ok((s.get_run(&run.id)?, approvals)),
                    Err(e) => {
                        let _ = s.request_cancel(&run.id);
                        Err(e)
                    }
                }
            })
            .map_err(|e| e.to_string())
    }

    pub fn decide(
        &self,
        approval_id: &str,
        approve: bool,
        operator: &str,
        scope_digest: &str,
        note: Option<&str>,
    ) -> Result<ApprovalRequest, String> {
        self.with_store(|s| s.decide_approval(approval_id, approve, operator, scope_digest, note))
    }

    /// Execute an approved run to settlement, then index it into memory.
    pub fn execute(&self, run_id: &str, cancel: Option<&CancelToken>) -> Result<RunRecord, String> {
        let run = self.with_store(|s| s.get_run(run_id))?;
        let orchestrator = self.orchestrator(&run.project_id)?;
        let run = orchestrator
            .run_until_settled(run_id, cancel)
            .map_err(|e| e.to_string())?;
        if run.state.is_terminal() || run.state == task_orchestrator::RunState::Blocked {
            let db = self.database()?;
            let _ = KnowledgeMemory::new(&db).ingest_workflow_run(run_id);
        }
        Ok(run)
    }

    pub fn recover(&self) -> Result<RecoveryReport, String> {
        self.with_store(|s| s.recover(&self.instance_id))
    }

    pub fn list_runs(
        &self,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RunRecord>, String> {
        self.with_store(|s| s.list_runs(project_id, limit))
    }

    pub fn detail(&self, run_id: &str) -> Result<RunDetail, String> {
        self.with_store(|s| {
            Ok(RunDetail {
                run: s.get_run(run_id)?,
                tasks: s.list_tasks(run_id)?,
                approvals: s.list_approvals(Some(run_id), false)?,
                attempts: s.list_attempts(run_id)?,
                tool_invocations: s.tool_invocations(run_id)?,
            })
        })
    }

    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRequest>, String> {
        self.with_store(|s| {
            s.expire_approvals()?;
            s.list_approvals(None, true)
        })
    }

    pub fn events_since(
        &self,
        run_id: &str,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<EventRecord>, String> {
        self.with_store(|s| s.events_since(run_id, cursor, limit))
    }

    pub fn cancel(&self, run_id: &str) -> Result<RunRecord, String> {
        self.with_store(|s| s.request_cancel(run_id))
    }

    pub fn pause(&self, run_id: &str) -> Result<RunRecord, String> {
        self.with_store(|s| s.request_pause(run_id))
    }

    pub fn resume(&self, run_id: &str, operator: &str) -> Result<RunRecord, String> {
        self.with_store(|s| s.resume(run_id, operator))
    }

    pub fn override_task(
        &self,
        task_id: &str,
        resolution: OverrideResolution,
        operator: &str,
    ) -> Result<TaskRecord, String> {
        self.with_store(|s| s.override_blocked_task(task_id, resolution, operator, APPROVAL_TTL_MS))
    }

    pub fn report(&self, run_id: &str, format: &str) -> Result<String, String> {
        let format = match format {
            "markdown" | "json" => format,
            _ => return Err("format must be markdown or json".into()),
        };
        if let Some((_, body)) = self.with_store(|s| s.latest_report(run_id, format))? {
            return Ok(body);
        }
        self.with_store(|s| {
            let report: RunReport = build_report(s, run_id)?;
            Ok(if format == "json" {
                serde_json::to_string_pretty(&report)?
            } else {
                task_orchestrator::report::render_markdown(&report)
            })
        })
    }
}
