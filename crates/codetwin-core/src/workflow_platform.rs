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

use crate::agent_tools::{CapabilityStatus, CoreToolRuntime, SearchAccess};
use crate::cloud_settings::CloudSettings;
use crate::collaboration::{Action, Collaboration};
use crate::knowledge_memory::KnowledgeMemory;
use crate::model_access::{CloudRoute, ModelAccess};
use crate::model_planner::{propose_plan, PlanSource};
use crate::specialist_workers::{registry, InvestigationOptions};
use crate::Database;
use model_gateway::router::RoleModels;

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

/// Loopback local model endpoint (no egress, no consent needed for planning;
/// used as a worker fallback only when project consent allows it).
#[derive(Clone)]
pub struct LocalProvider {
    pub client: Arc<ChatClient>,
    pub model: String,
}

/// What `create_investigation` decided about the plan.
#[derive(Debug, Clone, Serialize)]
pub struct PlanInfo {
    pub source: PlanSource,
    pub rationale: Option<String>,
    pub rejected: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetentionReport {
    pub runs_deleted: usize,
    pub provider_requests_deleted: usize,
    pub audit_records_deleted: usize,
}

pub struct WorkflowPlatform {
    db_path: PathBuf,
    instance_id: String,
    limits: Arc<GlobalLimits>,
    cloud: Option<CloudProvider>,
    local: Option<LocalProvider>,
    role_models: RoleModels,
    search: Option<SearchAccess>,
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
            local: None,
            role_models: RoleModels::default(),
            search: None,
        }
    }

    /// Per-role model selection and an optional local model.
    pub fn with_models(mut self, local: Option<LocalProvider>, role_models: RoleModels) -> Self {
        self.local = local;
        self.role_models = role_models;
        self
    }

    /// Configured external search provider for consented research.
    pub fn with_search(mut self, search: Option<SearchAccess>) -> Self {
        self.search = search;
        self
    }

    fn role_models(&self) -> RoleModels {
        let mut models = self.role_models.clone();
        if models.default_cloud.is_none() {
            models.default_cloud = self.cloud.as_ref().map(|c| c.model.clone());
        }
        if models.default_local.is_none() {
            models.default_local = self.local.as_ref().map(|l| l.model.clone());
        }
        models
    }

    /// Model access for planning: consented cloud (with local fallback), or
    /// the local model alone when the project is offline-only.
    fn planning_models(&self, project_id: &str) -> Result<Option<ModelAccess>, String> {
        let db = self.database()?;
        let consent = CloudSettings::new(&db).consent(project_id)?;
        let cloud = match (&self.cloud, consent) {
            (Some(provider), Some(c)) if c.consent.allow_cloud => Some(CloudRoute {
                client: provider.client.clone(),
                consent: c.consent,
            }),
            _ => None,
        };
        let access = ModelAccess {
            cloud,
            local: self.local.as_ref().map(|l| l.client.clone()),
            role_models: self.role_models(),
        };
        Ok(access.is_configured().then_some(access))
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
        let models = if cloud_ok {
            let provider = self.cloud.as_ref().expect("checked");
            Some(ModelAccess {
                cloud: Some(CloudRoute {
                    client: provider.client.clone(),
                    consent: consent.expect("checked").consent,
                }),
                // Used only after an infrastructure failure and only when the
                // consent allows local fallback (enforced by the router).
                local: self.local.as_ref().map(|l| l.client.clone()),
                role_models: self.role_models(),
            })
        } else {
            None
        };
        let research = research_ok.then(research_retrieval::FetchPolicy::default);
        Ok((
            policy,
            CoreToolRuntime::new(self.db_path.clone(), research, models)
                .with_search(self.search.clone()),
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
        self.create_planned_investigation(project_id, goal, owner, options, budgets)
            .map(|(run, approvals, _)| (run, approvals))
    }

    /// Like [`Self::create_investigation`], also reporting where the plan
    /// came from (model decomposition or the deterministic template).
    pub fn create_planned_investigation(
        &self,
        project_id: &str,
        goal: &str,
        owner: &str,
        options: &InvestigationOptions,
        budgets: Option<RunBudgets>,
    ) -> Result<(RunRecord, Vec<ApprovalRequest>, PlanInfo), String> {
        {
            let db = self.database()?;
            Collaboration::new(&db).authorize(project_id, owner, Action::CreateRun)?;
        }
        let (policy, _) = self.runtime_for(project_id)?;
        let orchestrator = self.orchestrator(project_id)?;
        let contracts = orchestrator.contracts();
        let proposal = {
            let db = self.database()?;
            let models = if options.ai_planning {
                self.planning_models(project_id)?
            } else {
                None
            };
            propose_plan(
                models.as_ref(),
                &db,
                project_id,
                goal,
                options,
                &std::sync::atomic::AtomicBool::new(false),
            )
        };
        let mut budgets = budgets.unwrap_or_default();
        let review_credits = if options.cloud_review { 3 } else { 0 };
        budgets.max_credits = budgets.max_credits.max(proposal.credits + review_credits);
        let tasks = proposal.tasks.clone();
        let info = PlanInfo {
            source: proposal.source.clone(),
            rationale: proposal.rationale.clone(),
            rejected: proposal.rejected.clone(),
        };
        let (run, approvals) = orchestrator
            .with_store(|s| {
                let run = s.create_run(&RunSpec {
                    project_id: project_id.into(),
                    goal: goal.into(),
                    owner: owner.into(),
                    budgets,
                    cloud_consented: policy.cloud_consent,
                })?;
                if proposal.credits > 0 {
                    s.add_credits(&run.id, proposal.credits)?;
                }
                if let PlanSource::Model { request_id, .. } = &proposal.source {
                    s.connection().execute(
                        "UPDATE provider_requests SET run_id=?1 WHERE request_id=?2",
                        rusqlite::params![run.id, request_id],
                    )?;
                }
                s.event(
                    &run.id,
                    None,
                    "plan_source",
                    serde_json::json!({"source": info.source, "rationale": info.rationale,
                        "rejected": info.rejected.iter().take(8).collect::<Vec<_>>(), "tasks": tasks.len()}),
                )?;
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
            .map_err(|e| e.to_string())?;
        Ok((run, approvals, info))
    }

    pub fn decide(
        &self,
        approval_id: &str,
        approve: bool,
        operator: &str,
        scope_digest: &str,
        note: Option<&str>,
    ) -> Result<ApprovalRequest, String> {
        // Role check and separation of duties, before the store's own checks
        // (scope digest, revision, expiry, automated principals).
        let (project_id, owner) = self.with_store(|s| {
            let approval = s.get_approval(approval_id)?;
            let run = s.get_run(&approval.run_id)?;
            Ok((run.project_id, run.owner))
        })?;
        let db = self.database()?;
        let collab = Collaboration::new(&db);
        if approve {
            collab.authorize_approval(&project_id, operator, &owner)?;
        } else {
            collab.authorize(&project_id, operator, Action::Approve)?;
        }
        let decided = self.with_store(|s| {
            s.decide_approval(approval_id, approve, operator, scope_digest, note)
        })?;
        collab.audit(
            operator,
            if approve { "approve" } else { "reject" },
            Some(&project_id),
            Some(approval_id),
            "allowed",
            serde_json::json!({"scope_digest": scope_digest}),
        );
        Ok(decided)
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

    /// PDF rendering of the run's Markdown report (the PDF embeds the
    /// Markdown's SHA-256 so it can be matched to the stored report).
    pub fn report_pdf(&self, run_id: &str) -> Result<Vec<u8>, String> {
        let markdown = self.report(run_id, "markdown")?;
        let run = self.with_store(|s| s.get_run(run_id))?;
        let title: String = format!("CodeTwin workflow report - {}", run.goal)
            .chars()
            .take(120)
            .collect();
        Ok(crate::pdf_report::render_pdf(&title, &markdown))
    }

    /// Delete settled runs (and their tasks, events, tool records and
    /// reports via cascade) older than `older_than_days`, always keeping the
    /// newest `keep_latest` runs per project. Active runs are never touched.
    /// Provider and audit records older than the same horizon are pruned.
    pub fn prune(&self, older_than_days: u32, keep_latest: u32) -> Result<RetentionReport, String> {
        let days = i64::from(older_than_days.max(1));
        let cutoff = task_orchestrator::store::now_ms() - days * 24 * 3_600_000;
        let conn = open_connection(&self.db_path)?;
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let runs_deleted = tx
            .execute(
                "DELETE FROM workflow_runs WHERE state IN ('completed','failed','cancelled')
                   AND COALESCE(finished_ms, updated_ms) < ?1
                   AND id NOT IN (
                     SELECT id FROM (
                       SELECT id, ROW_NUMBER() OVER (PARTITION BY project_id ORDER BY created_ms DESC) AS rn
                       FROM workflow_runs) WHERE rn <= ?2)",
                rusqlite::params![cutoff, i64::from(keep_latest)],
            )
            .map_err(|e| e.to_string())?;
        let provider_requests_deleted = tx
            .execute(
                "DELETE FROM provider_requests WHERE created_ms < ?1",
                [cutoff],
            )
            .map_err(|e| e.to_string())?;
        let audit_records_deleted = tx
            .execute("DELETE FROM audit_records WHERE created_ms < ?1", [cutoff])
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(RetentionReport {
            runs_deleted,
            provider_requests_deleted,
            audit_records_deleted,
        })
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
