//! SQLite persistence for workflow runs. Every state change is a
//! compare-and-set inside a transaction, validated against `state.rs`.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::dag::{topological_order, DagError};
use crate::policy::{validate_schema, ApprovalNeed, Capability, PolicyContext, PolicyEngine};
use crate::state::{
    reason, ErrorCategory, EvidenceClass, Outcome, RunState, SideEffect, TaskState,
};
use crate::worker::{SuccessCriterion, WorkerContract};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid {entity} transition {from} -> {to}")]
    InvalidTransition {
        entity: &'static str,
        from: String,
        to: String,
    },
    #[error("stale state: {0}")]
    Stale(String),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("invalid plan: {0}")]
    Dag(#[from] DagError),
}

pub type StoreResult<T> = Result<T, StoreError>;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Collision-resistant local identifier (no external RNG dependency).
pub fn new_id(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = format!("{prefix}:{nanos}:{n}:{}", std::process::id());
    format!("{prefix}_{}", &sha256_hex(seed.as_bytes())[..24])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunBudgets {
    pub max_replans: u32,
    pub max_parallel: u32,
    pub max_runtime_ms: u64,
    pub max_attempts_per_task: u32,
    pub max_tasks: u32,
    /// Provider credits (one OpenMindAI call = one credit). 0 forbids paid calls.
    pub max_credits: u32,
}

impl Default for RunBudgets {
    fn default() -> Self {
        Self {
            max_replans: 2,
            max_parallel: 3,
            max_runtime_ms: 30 * 60 * 1000,
            max_attempts_per_task: 2,
            max_tasks: 32,
            max_credits: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSpec {
    pub project_id: String,
    pub goal: String,
    pub owner: String,
    pub budgets: RunBudgets,
    pub cloud_consented: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    /// Idempotency key; also the name used by `depends_on`.
    pub key: String,
    pub role: String,
    pub title: String,
    pub input: Value,
    pub success_criteria: Vec<SuccessCriterion>,
    pub capabilities: BTreeSet<Capability>,
    pub resource_key: Option<String>,
    pub priority: i32,
    pub timeout_ms: Option<u64>,
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    pub project_id: String,
    pub goal: String,
    pub owner: String,
    pub state: RunState,
    pub outcome: Option<Outcome>,
    pub reason_code: Option<String>,
    pub plan_revision: u32,
    pub approved_revision: Option<u32>,
    pub approved_capabilities: BTreeSet<Capability>,
    pub replan_count: u32,
    pub budgets: RunBudgets,
    pub credits_used: u32,
    pub cancel_requested: bool,
    pub pause_requested: bool,
    pub cloud_consented: bool,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: String,
    pub run_id: String,
    pub plan_revision: u32,
    pub key: String,
    pub parent_task_id: Option<String>,
    pub delegation_depth: u32,
    pub role: String,
    pub title: String,
    pub input: Value,
    pub success_criteria: Vec<SuccessCriterion>,
    pub side_effect: SideEffect,
    pub capabilities: BTreeSet<Capability>,
    pub scope_digest: String,
    pub resource_key: Option<String>,
    pub priority: i32,
    pub state: TaskState,
    pub reason_code: Option<String>,
    pub attempt_count: u32,
    pub max_attempts: u32,
    pub timeout_ms: u64,
    pub not_before_ms: Option<i64>,
    pub output: Option<Value>,
    pub output_sha256: Option<String>,
    pub summary: Option<String>,
    pub evidence_class: Option<EvidenceClass>,
    pub depends_on: Vec<String>,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub started_ms: Option<i64>,
    pub finished_ms: Option<i64>,
}

impl TaskRecord {
    /// Superseded tasks belong to an abandoned plan revision.
    pub fn is_superseded(&self) -> bool {
        self.reason_code.as_deref() == Some(reason::SUPERSEDED)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub run_id: String,
    pub task_id: Option<String>,
    pub kind: String,
    pub capabilities: BTreeSet<Capability>,
    pub scope_digest: String,
    pub plan_revision: u32,
    pub summary: String,
    pub status: String,
    pub requested_ms: i64,
    pub expires_ms: i64,
    pub decided_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub seq: i64,
    pub run_id: String,
    pub task_id: Option<String>,
    pub kind: String,
    pub detail: Value,
    pub correlation_id: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationRecord {
    pub id: String,
    pub task_id: String,
    pub attempt_no: u32,
    pub tool_id: String,
    pub capability: String,
    pub side_effect: SideEffect,
    pub args_sha256: String,
    pub status: String,
    pub decision_reason: String,
    pub output_sha256: Option<String>,
    pub started_ms: i64,
    pub finished_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub task_id: String,
    pub attempt_no: u32,
    pub worker_id: String,
    pub status: String,
    pub error_category: Option<String>,
    pub error_detail: Option<String>,
    pub started_ms: i64,
    pub finished_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryReport {
    pub tasks_requeued: usize,
    pub tasks_blocked: usize,
    pub tasks_failed: usize,
    pub invocations_uncertain: usize,
    pub runs_paused: usize,
}

/// Operator resolution for a blocked task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideResolution {
    /// Try again (side-effecting tasks go back through approval).
    Requeue,
    Cancel,
    /// Operator confirmed an uncertain side effect did happen: never repeat it.
    SideEffectApplied,
    /// Operator confirmed an uncertain side effect did not happen.
    SideEffectNotApplied,
}

pub enum ToolBegin {
    Proceed(String),
    AlreadyApplied(String),
}

const RUN_COLUMNS: &str = "id,project_id,goal,owner,state,outcome,reason_code,plan_revision,
    approved_revision,approved_capabilities_json,replan_count,max_replans,max_parallel,
    max_runtime_ms,max_attempts_per_task,max_tasks,max_credits,credits_used,cancel_requested,
    pause_requested,cloud_mode,created_ms,updated_ms,started_ms,finished_ms";

const TASK_COLUMNS: &str = "id,run_id,plan_revision,idempotency_key,parent_task_id,
    delegation_depth,role,title,input_json,success_criteria_json,side_effect,capabilities_json,
    scope_digest,resource_key,priority,state,reason_code,attempt_count,max_attempts,timeout_ms,
    not_before_ms,output_json,output_sha256,summary,evidence_class,created_ms,updated_ms,
    started_ms,finished_ms";

fn bad_enum(column: usize, value: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        format!("unexpected value `{value}`").into(),
    )
}

fn json_col<T: for<'de> Deserialize<'de>>(row: &Row<'_>, idx: usize) -> rusqlite::Result<T> {
    let text: String = row.get(idx)?;
    serde_json::from_str(&text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn run_from_row(row: &Row<'_>) -> rusqlite::Result<RunRecord> {
    let state: String = row.get(4)?;
    let outcome: Option<String> = row.get(5)?;
    Ok(RunRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        goal: row.get(2)?,
        owner: row.get(3)?,
        state: RunState::parse(&state).ok_or_else(|| bad_enum(4, &state))?,
        outcome: match outcome {
            Some(o) => Some(Outcome::parse(&o).ok_or_else(|| bad_enum(5, &o))?),
            None => None,
        },
        reason_code: row.get(6)?,
        plan_revision: row.get(7)?,
        approved_revision: row.get(8)?,
        approved_capabilities: json_col(row, 9)?,
        replan_count: row.get(10)?,
        budgets: RunBudgets {
            max_replans: row.get(11)?,
            max_parallel: row.get(12)?,
            max_runtime_ms: row.get::<_, i64>(13)? as u64,
            max_attempts_per_task: row.get(14)?,
            max_tasks: row.get(15)?,
            max_credits: row.get(16)?,
        },
        credits_used: row.get(17)?,
        cancel_requested: row.get::<_, i64>(18)? != 0,
        pause_requested: row.get::<_, i64>(19)? != 0,
        cloud_consented: row.get::<_, String>(20)? == "cloud_consented",
        created_ms: row.get(21)?,
        updated_ms: row.get(22)?,
        started_ms: row.get(23)?,
        finished_ms: row.get(24)?,
    })
}

fn task_from_row(row: &Row<'_>) -> rusqlite::Result<TaskRecord> {
    let side_effect: String = row.get(10)?;
    let state: String = row.get(15)?;
    let evidence: Option<String> = row.get(24)?;
    let output: Option<String> = row.get(21)?;
    Ok(TaskRecord {
        id: row.get(0)?,
        run_id: row.get(1)?,
        plan_revision: row.get(2)?,
        key: row.get(3)?,
        parent_task_id: row.get(4)?,
        delegation_depth: row.get(5)?,
        role: row.get(6)?,
        title: row.get(7)?,
        input: json_col(row, 8)?,
        success_criteria: json_col(row, 9)?,
        side_effect: SideEffect::parse(&side_effect).ok_or_else(|| bad_enum(10, &side_effect))?,
        capabilities: json_col(row, 11)?,
        scope_digest: row.get(12)?,
        resource_key: row.get(13)?,
        priority: row.get(14)?,
        state: TaskState::parse(&state).ok_or_else(|| bad_enum(15, &state))?,
        reason_code: row.get(16)?,
        attempt_count: row.get(17)?,
        max_attempts: row.get(18)?,
        timeout_ms: row.get::<_, i64>(19)? as u64,
        not_before_ms: row.get(20)?,
        output: match output {
            Some(text) => Some(serde_json::from_str(&text).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    21,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?),
            None => None,
        },
        output_sha256: row.get(22)?,
        summary: row.get(23)?,
        evidence_class: match evidence {
            Some(e) => Some(EvidenceClass::parse(&e).ok_or_else(|| bad_enum(24, &e))?),
            None => None,
        },
        depends_on: Vec::new(),
        created_ms: row.get(25)?,
        updated_ms: row.get(26)?,
        started_ms: row.get(27)?,
        finished_ms: row.get(28)?,
    })
}

fn approval_from_row(row: &Row<'_>) -> rusqlite::Result<ApprovalRequest> {
    Ok(ApprovalRequest {
        id: row.get(0)?,
        run_id: row.get(1)?,
        task_id: row.get(2)?,
        kind: row.get(3)?,
        capabilities: json_col(row, 4)?,
        scope_digest: row.get(5)?,
        plan_revision: row.get(6)?,
        summary: row.get(7)?,
        status: row.get(8)?,
        requested_ms: row.get(9)?,
        expires_ms: row.get(10)?,
        decided_by: row.get(11)?,
    })
}

const APPROVAL_SELECT: &str = "SELECT r.id,r.run_id,r.task_id,r.kind,r.capabilities_json,
    r.scope_digest,r.plan_revision,r.summary,r.status,r.requested_ms,r.expires_ms,d.decided_by
    FROM workflow_approval_requests r
    LEFT JOIN workflow_approval_decisions d ON d.request_id = r.id";

/// Digest binding a task's exact scope; any change to role, input,
/// capabilities or side effect produces a different digest.
pub fn task_scope_digest(
    run_id: &str,
    key: &str,
    role: &str,
    input: &Value,
    capabilities: &BTreeSet<Capability>,
    side_effect: SideEffect,
) -> String {
    let canonical = json!({
        "run": run_id, "key": key, "role": role, "input": input,
        "capabilities": capabilities, "side_effect": side_effect,
    });
    sha256_hex(canonical.to_string().as_bytes())
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_owned()
}

/// Thin, connection-borrowing persistence API.
pub struct Store<'c> {
    conn: &'c Connection,
}

impl<'c> Store<'c> {
    pub const fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    pub fn connection(&self) -> &Connection {
        self.conn
    }

    // ---------------------------------------------------------------- runs

    pub fn create_run(&self, spec: &RunSpec) -> StoreResult<RunRecord> {
        let goal = spec.goal.trim();
        if goal.is_empty() || goal.chars().count() > 4000 {
            return Err(StoreError::Rejected(
                "goal must be 1..4000 characters".into(),
            ));
        }
        let owner = spec.owner.trim();
        if owner.is_empty() || owner.len() > 120 {
            return Err(StoreError::Rejected("owner must be 1..120 bytes".into()));
        }
        let b = &spec.budgets;
        let now = now_ms();
        let id = new_id("run");
        self.conn.execute(
            "INSERT INTO workflow_runs(id,project_id,goal,owner,state,max_replans,max_parallel,
                max_runtime_ms,max_attempts_per_task,max_tasks,max_credits,cloud_mode,created_ms,updated_ms)
             VALUES (?1,?2,?3,?4,'draft',?5,?6,?7,?8,?9,?10,?11,?12,?12)",
            params![
                id,
                spec.project_id,
                goal,
                owner,
                b.max_replans,
                b.max_parallel,
                b.max_runtime_ms as i64,
                b.max_attempts_per_task,
                b.max_tasks,
                b.max_credits,
                if spec.cloud_consented { "cloud_consented" } else { "offline" },
                now
            ],
        )?;
        self.event(
            &id,
            None,
            "run_created",
            json!({"goal_chars": goal.chars().count()}),
        )?;
        self.get_run(&id)
    }

    pub fn get_run(&self, run_id: &str) -> StoreResult<RunRecord> {
        self.conn
            .query_row(
                &format!("SELECT {RUN_COLUMNS} FROM workflow_runs WHERE id=?1"),
                [run_id],
                run_from_row,
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("run {run_id}")))
    }

    pub fn list_runs(&self, project_id: Option<&str>, limit: usize) -> StoreResult<Vec<RunRecord>> {
        let limit = limit.clamp(1, 200) as i64;
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {RUN_COLUMNS} FROM workflow_runs
             WHERE (?1 IS NULL OR project_id = ?1) ORDER BY created_ms DESC, id LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![project_id, limit], run_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn transition_run_tx(
        tx: &Connection,
        run_id: &str,
        from: RunState,
        to: RunState,
        reason_code: &str,
        outcome: Option<Outcome>,
    ) -> StoreResult<()> {
        if !from.can_transition_to(to) {
            return Err(StoreError::InvalidTransition {
                entity: "run",
                from: from.to_string(),
                to: to.to_string(),
            });
        }
        let now = now_ms();
        let changed = tx.execute(
            "UPDATE workflow_runs SET state=?3, reason_code=?4, updated_ms=?5,
                outcome=COALESCE(?6, outcome),
                started_ms=CASE WHEN ?3='running' AND started_ms IS NULL THEN ?5 ELSE started_ms END,
                finished_ms=CASE WHEN ?3 IN ('completed','failed','cancelled') THEN ?5 ELSE finished_ms END
             WHERE id=?1 AND state=?2",
            params![run_id, from.as_str(), to.as_str(), reason_code, now, outcome.map(Outcome::as_str)],
        )?;
        if changed != 1 {
            return Err(StoreError::Stale(format!(
                "run {run_id} is no longer {from}"
            )));
        }
        Self::event_tx(
            tx,
            run_id,
            None,
            "run_state",
            json!({"from": from, "to": to, "reason": reason_code, "outcome": outcome}),
        )
    }

    pub fn transition_run(
        &self,
        run_id: &str,
        from: RunState,
        to: RunState,
        reason_code: &str,
        outcome: Option<Outcome>,
    ) -> StoreResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        Self::transition_run_tx(&tx, run_id, from, to, reason_code, outcome)?;
        tx.commit()?;
        Ok(())
    }

    fn transition_task_tx(
        tx: &Connection,
        task_id: &str,
        from: TaskState,
        to: TaskState,
        reason_code: &str,
    ) -> StoreResult<()> {
        if !from.can_transition_to(to) {
            return Err(StoreError::InvalidTransition {
                entity: "task",
                from: from.to_string(),
                to: to.to_string(),
            });
        }
        let now = now_ms();
        let changed = tx.execute(
            "UPDATE workflow_tasks SET state=?3, reason_code=?4, updated_ms=?5,
                started_ms=CASE WHEN ?3='running' AND started_ms IS NULL THEN ?5 ELSE started_ms END,
                finished_ms=CASE WHEN ?3 IN ('completed','failed','cancelled') THEN ?5 ELSE finished_ms END
             WHERE id=?1 AND state=?2",
            params![task_id, from.as_str(), to.as_str(), reason_code, now],
        )?;
        if changed != 1 {
            return Err(StoreError::Stale(format!(
                "task {task_id} is no longer {from}"
            )));
        }
        let run_id: String = tx.query_row(
            "SELECT run_id FROM workflow_tasks WHERE id=?1",
            [task_id],
            |r| r.get(0),
        )?;
        Self::event_tx(
            tx,
            &run_id,
            Some(task_id),
            "task_state",
            json!({"from": from, "to": to, "reason": reason_code}),
        )
    }

    pub fn transition_task(
        &self,
        task_id: &str,
        from: TaskState,
        to: TaskState,
        reason_code: &str,
    ) -> StoreResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        Self::transition_task_tx(&tx, task_id, from, to, reason_code)?;
        tx.commit()?;
        Ok(())
    }

    // --------------------------------------------------------------- tasks

    pub fn list_tasks(&self, run_id: &str) -> StoreResult<Vec<TaskRecord>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {TASK_COLUMNS} FROM workflow_tasks WHERE run_id=?1
             ORDER BY plan_revision, priority DESC, created_ms, id"
        ))?;
        let mut tasks: Vec<TaskRecord> = stmt
            .query_map([run_id], task_from_row)?
            .collect::<Result<_, _>>()?;
        let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT task_id, depends_on FROM workflow_task_dependencies WHERE run_id=?1",
        )?;
        for row in stmt.query_map([run_id], |r| Ok((r.get::<_, String>(0)?, r.get(1)?)))? {
            let (task, dep) = row?;
            deps.entry(task).or_default().push(dep);
        }
        for task in &mut tasks {
            task.depends_on = deps.remove(&task.id).unwrap_or_default();
            task.depends_on.sort();
        }
        Ok(tasks)
    }

    pub fn get_task(&self, task_id: &str) -> StoreResult<TaskRecord> {
        let mut task = self
            .conn
            .query_row(
                &format!("SELECT {TASK_COLUMNS} FROM workflow_tasks WHERE id=?1"),
                [task_id],
                task_from_row,
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("task {task_id}")))?;
        let mut stmt = self
            .conn
            .prepare("SELECT depends_on FROM workflow_task_dependencies WHERE task_id=?1 ORDER BY depends_on")?;
        task.depends_on = stmt
            .query_map([task_id], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(task)
    }

    /// Validate and persist a (re)plan. Returns the approval requests the
    /// operator must decide before anything runs. Planning never executes.
    pub fn submit_plan(
        &self,
        run_id: &str,
        tasks: &[TaskSpec],
        contracts: &BTreeMap<String, WorkerContract>,
        policy: &PolicyContext,
        approval_ttl_ms: i64,
    ) -> StoreResult<Vec<ApprovalRequest>> {
        let tx = self.conn.unchecked_transaction()?;
        let run = self.get_run(run_id)?;
        if run.state.is_terminal() {
            return Err(StoreError::Rejected(format!("run is {}", run.state)));
        }
        if tasks.is_empty() {
            return Err(StoreError::Rejected(
                "a plan needs at least one task".into(),
            ));
        }
        let existing = self.list_tasks(run_id)?;
        if existing
            .iter()
            .any(|t| matches!(t.state, TaskState::Running | TaskState::Validating))
        {
            return Err(StoreError::Rejected(
                "cannot replan while tasks are running; pause the run first".into(),
            ));
        }
        let revision = run.plan_revision + 1;
        if run.plan_revision > 0 && run.replan_count + 1 > run.budgets.max_replans {
            return Err(StoreError::Rejected("replan budget exhausted".into()));
        }
        // Completed work is carried forward and never re-executed.
        let completed: BTreeMap<String, String> = existing
            .iter()
            .filter(|t| t.state == TaskState::Completed)
            .map(|t| (t.key.clone(), t.id.clone()))
            .collect();
        let new_specs: Vec<&TaskSpec> = tasks
            .iter()
            .filter(|t| !completed.contains_key(&t.key))
            .collect();
        if new_specs.is_empty() {
            return Err(StoreError::Rejected(
                "plan contains only completed work".into(),
            ));
        }
        if (new_specs.len() + completed.len()) as u32 > run.budgets.max_tasks {
            return Err(StoreError::Rejected(format!(
                "plan exceeds the {}-task budget",
                run.budgets.max_tasks
            )));
        }
        let mut prepared = Vec::new();
        for spec in &new_specs {
            if spec.key.is_empty() || spec.key.len() > 128 {
                return Err(StoreError::Rejected("task key must be 1..128 bytes".into()));
            }
            if spec.title.trim().is_empty() || spec.title.chars().count() > 200 {
                return Err(StoreError::Rejected(format!(
                    "task `{}` title invalid",
                    spec.key
                )));
            }
            let contract = contracts.get(&spec.role).ok_or_else(|| {
                StoreError::Rejected(format!("unknown worker role `{}`", spec.role))
            })?;
            validate_schema(&contract.input_schema, &spec.input)
                .map_err(|e| StoreError::Rejected(format!("task `{}` input: {e}", spec.key)))?;
            let need =
                PolicyEngine::plan_requirement(&spec.capabilities, &contract.capabilities, policy)
                    .map_err(|reason| {
                        StoreError::Rejected(format!("task `{}` denied: {reason}", spec.key))
                    })?;
            let side_effect = spec
                .capabilities
                .iter()
                .fold(SideEffect::ReadOnly, |acc, c| acc.max(c.side_effect()));
            let input_json = serde_json::to_string(&spec.input)?;
            if input_json.len() > 16_384 {
                return Err(StoreError::Rejected(format!(
                    "task `{}` input too large",
                    spec.key
                )));
            }
            let digest = task_scope_digest(
                run_id,
                &spec.key,
                &spec.role,
                &spec.input,
                &spec.capabilities,
                side_effect,
            );
            prepared.push((*spec, contract, need, side_effect, input_json, digest));
        }
        let keys: Vec<String> = new_specs.iter().map(|s| s.key.clone()).collect();
        let edges: Vec<(String, String)> = new_specs
            .iter()
            .flat_map(|s| s.depends_on.iter().map(|d| (s.key.clone(), d.clone())))
            .collect();
        let external: BTreeSet<String> = completed.keys().cloned().collect();
        topological_order(&keys, &edges, &external)?;

        let mut digest_input: Vec<Value> = prepared
            .iter()
            .map(|(spec, _, _, _, _, digest)| {
                let mut deps = spec.depends_on.clone();
                deps.sort();
                json!([spec.key, digest, deps])
            })
            .collect();
        digest_input.sort_by_key(|v| v.to_string());
        let plan_digest = sha256_hex(Value::Array(digest_input).to_string().as_bytes());
        let previous: Option<String> = tx.query_row(
            "SELECT plan_digest FROM workflow_runs WHERE id=?1",
            [run_id],
            |r| r.get(0),
        )?;
        if previous.as_deref() == Some(plan_digest.as_str()) {
            return Err(StoreError::Rejected(
                "plan is identical to the current plan (runaway replanning)".into(),
            ));
        }

        let now = now_ms();
        // Supersede unfinished work and pending approvals of older revisions.
        for task in existing.iter().filter(|t| !t.state.is_terminal()) {
            Self::transition_task_tx(
                &tx,
                &task.id,
                task.state,
                TaskState::Cancelled,
                reason::SUPERSEDED,
            )?;
        }
        tx.execute(
            "UPDATE workflow_approval_requests SET status='superseded'
             WHERE run_id=?1 AND status='pending'",
            [run_id],
        )?;

        let mut key_to_id: BTreeMap<String, String> = completed.clone();
        for (spec, contract, _, side_effect, input_json, digest) in &prepared {
            let id = new_id("task");
            let max_attempts = run.budgets.max_attempts_per_task.clamp(1, 5);
            let timeout = spec
                .timeout_ms
                .unwrap_or(contract.default_timeout_ms)
                .clamp(100, 3_600_000);
            tx.execute(
                "INSERT INTO workflow_tasks(id,run_id,plan_revision,idempotency_key,role,title,
                    input_json,success_criteria_json,side_effect,capabilities_json,scope_digest,
                    resource_key,priority,state,max_attempts,timeout_ms,created_ms,updated_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'planned',?14,?15,?16,?16)",
                params![
                    id,
                    run_id,
                    revision,
                    spec.key,
                    spec.role,
                    spec.title.trim(),
                    input_json,
                    serde_json::to_string(&spec.success_criteria)?,
                    side_effect.as_str(),
                    serde_json::to_string(&spec.capabilities)?,
                    digest,
                    spec.resource_key,
                    spec.priority.clamp(-100, 100),
                    max_attempts,
                    timeout as i64,
                    now
                ],
            )?;
            key_to_id.insert(spec.key.clone(), id);
        }
        for spec in &new_specs {
            for dep in &spec.depends_on {
                tx.execute(
                    "INSERT INTO workflow_task_dependencies(run_id,task_id,depends_on) VALUES (?1,?2,?3)",
                    params![run_id, key_to_id[&spec.key], key_to_id[dep]],
                )?;
            }
        }
        tx.execute(
            "UPDATE workflow_runs SET plan_revision=?2, plan_digest=?3, approved_revision=NULL,
                approved_capabilities_json='[]', replan_count=replan_count+?4, updated_ms=?5
             WHERE id=?1",
            params![
                run_id,
                revision,
                plan_digest,
                i64::from(run.plan_revision > 0),
                now
            ],
        )?;
        if run.state != RunState::Planned {
            Self::transition_run_tx(
                &tx,
                run_id,
                run.state,
                RunState::Planned,
                reason::PLAN_SUBMITTED,
                None,
            )?;
        }
        Self::transition_run_tx(
            &tx,
            run_id,
            RunState::Planned,
            RunState::AwaitingApproval,
            reason::PLAN_SUBMITTED,
            None,
        )?;

        let read_only_caps: BTreeSet<Capability> = prepared
            .iter()
            .flat_map(|(spec, ..)| spec.capabilities.iter().copied())
            .filter(|c| c.side_effect().is_read_only())
            .collect();
        let plan_summary = format!(
            "Plan revision {revision}: {} new task(s), {} carried forward. Read-only capabilities: {}.",
            prepared.len(),
            completed.len(),
            read_only_caps.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ")
        );
        let mut ids = vec![Self::insert_approval_tx(
            &tx,
            run_id,
            None,
            "plan",
            &read_only_caps,
            &plan_digest,
            revision,
            &plan_summary,
            now,
            approval_ttl_ms,
        )?];
        for (spec, _, need, side_effect, _, digest) in &prepared {
            let task_id = &key_to_id[&spec.key];
            Self::transition_task_tx(
                &tx,
                task_id,
                TaskState::Planned,
                TaskState::AwaitingApproval,
                reason::PLAN_SUBMITTED,
            )?;
            if *need == ApprovalNeed::TaskApproval {
                let summary = format!(
                    "Task `{}` ({}) requests {} capability: {}",
                    spec.title,
                    spec.role,
                    side_effect,
                    spec.capabilities
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                ids.push(Self::insert_approval_tx(
                    &tx,
                    run_id,
                    Some(task_id),
                    "task_capability",
                    &spec.capabilities,
                    digest,
                    revision,
                    &summary,
                    now,
                    approval_ttl_ms,
                )?);
            }
        }
        tx.commit()?;
        ids.into_iter().map(|id| self.get_approval(&id)).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_approval_tx(
        tx: &Connection,
        run_id: &str,
        task_id: Option<&str>,
        kind: &str,
        capabilities: &BTreeSet<Capability>,
        scope_digest: &str,
        revision: u32,
        summary: &str,
        now: i64,
        ttl_ms: i64,
    ) -> StoreResult<String> {
        let id = new_id("apr");
        tx.execute(
            "INSERT INTO workflow_approval_requests(id,run_id,task_id,kind,capabilities_json,
                scope_digest,plan_revision,summary,status,requested_ms,expires_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9,?10)",
            params![
                id,
                run_id,
                task_id,
                kind,
                serde_json::to_string(capabilities)?,
                scope_digest,
                revision,
                truncate(summary, 2000),
                now,
                now + ttl_ms.clamp(60_000, 7 * 24 * 3_600_000)
            ],
        )?;
        Self::event_tx(
            tx,
            run_id,
            task_id,
            "approval_requested",
            json!({"approval_id": id, "kind": kind, "scope_digest": scope_digest}),
        )?;
        Ok(id)
    }

    // ----------------------------------------------------------- approvals

    pub fn get_approval(&self, id: &str) -> StoreResult<ApprovalRequest> {
        self.conn
            .query_row(
                &format!("{APPROVAL_SELECT} WHERE r.id=?1"),
                [id],
                approval_from_row,
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(format!("approval {id}")))
    }

    pub fn list_approvals(
        &self,
        run_id: Option<&str>,
        pending_only: bool,
    ) -> StoreResult<Vec<ApprovalRequest>> {
        let mut stmt = self.conn.prepare(&format!(
            "{APPROVAL_SELECT} WHERE (?1 IS NULL OR r.run_id=?1)
             AND (?2=0 OR r.status='pending') ORDER BY r.requested_ms DESC, r.id LIMIT 500"
        ))?;
        let rows = stmt.query_map(params![run_id, i64::from(pending_only)], approval_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Operator decision. `expected_scope_digest` must be the digest the
    /// operator actually reviewed; any drift makes the decision stale.
    pub fn decide_approval(
        &self,
        approval_id: &str,
        approve: bool,
        decided_by: &str,
        expected_scope_digest: &str,
        note: Option<&str>,
    ) -> StoreResult<ApprovalRequest> {
        let actor = decided_by.trim();
        if actor.is_empty() || actor.len() > 120 {
            return Err(StoreError::Rejected("approver identity required".into()));
        }
        let lowered = actor.to_ascii_lowercase();
        if ["worker:", "model:", "tool:", "agent:", "plugin:"]
            .iter()
            .any(|p| lowered.starts_with(p))
        {
            return Err(StoreError::Rejected(
                "automated principals cannot decide approvals".into(),
            ));
        }
        let tx = self.conn.unchecked_transaction()?;
        let request = self.get_approval(approval_id)?;
        let now = now_ms();
        if request.status != "pending" {
            return Err(StoreError::Stale(format!("approval is {}", request.status)));
        }
        if request.expires_ms <= now {
            tx.execute(
                "UPDATE workflow_approval_requests SET status='expired' WHERE id=?1",
                [approval_id],
            )?;
            tx.commit()?;
            return Err(StoreError::Stale("approval request expired".into()));
        }
        if request.scope_digest != expected_scope_digest {
            return Err(StoreError::Stale(
                "approval scope does not match the reviewed scope".into(),
            ));
        }
        let run = self.get_run(&request.run_id)?;
        if run.plan_revision != request.plan_revision {
            tx.execute(
                "UPDATE workflow_approval_requests SET status='superseded' WHERE id=?1",
                [approval_id],
            )?;
            tx.commit()?;
            return Err(StoreError::Stale(
                "plan changed after this approval was requested".into(),
            ));
        }
        if let Some(task_id) = &request.task_id {
            let digest: String = tx.query_row(
                "SELECT scope_digest FROM workflow_tasks WHERE id=?1",
                [task_id],
                |r| r.get(0),
            )?;
            if digest != request.scope_digest {
                return Err(StoreError::Stale("task scope changed".into()));
            }
        }
        tx.execute(
            "INSERT INTO workflow_approval_decisions(request_id,decision,decided_by,scope_digest,note,decided_ms)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                approval_id,
                if approve { "approve" } else { "reject" },
                actor,
                request.scope_digest,
                note.map(|n| truncate(n, 500)),
                now
            ],
        )?;
        tx.execute(
            "UPDATE workflow_approval_requests SET status=?2 WHERE id=?1",
            params![approval_id, if approve { "approved" } else { "rejected" }],
        )?;
        Self::event_tx(
            &tx,
            &run.id,
            request.task_id.as_deref(),
            "approval_decided",
            json!({"approval_id": approval_id, "approve": approve, "by": actor}),
        )?;
        let tasks = self.list_tasks(&run.id)?;
        match (request.kind.as_str(), approve) {
            ("plan", true) => {
                tx.execute(
                    "UPDATE workflow_runs SET approved_revision=?2, approved_capabilities_json=?3 WHERE id=?1",
                    params![run.id, request.plan_revision, serde_json::to_string(&request.capabilities)?],
                )?;
                for task in tasks.iter().filter(|t| {
                    t.state == TaskState::AwaitingApproval
                        && t.plan_revision == request.plan_revision
                }) {
                    if !self.task_approval_outstanding(&tx, &task.id)? {
                        Self::transition_task_tx(
                            &tx,
                            &task.id,
                            TaskState::AwaitingApproval,
                            TaskState::Queued,
                            reason::PLAN_APPROVED,
                        )?;
                    }
                }
                Self::transition_run_tx(
                    &tx,
                    &run.id,
                    run.state,
                    RunState::Queued,
                    reason::PLAN_APPROVED,
                    None,
                )?;
            }
            ("plan", false) => {
                for task in tasks.iter().filter(|t| !t.state.is_terminal()) {
                    Self::transition_task_tx(
                        &tx,
                        &task.id,
                        task.state,
                        TaskState::Cancelled,
                        reason::PLAN_REJECTED,
                    )?;
                }
                tx.execute(
                    "UPDATE workflow_approval_requests SET status='superseded' WHERE run_id=?1 AND status='pending'",
                    [&run.id],
                )?;
                Self::transition_run_tx(
                    &tx,
                    &run.id,
                    run.state,
                    RunState::Cancelled,
                    reason::PLAN_REJECTED,
                    Some(Outcome::Cancelled),
                )?;
            }
            (_, true) => {
                let task_id = request.task_id.as_deref().expect("task approval has task");
                let task = tasks.iter().find(|t| t.id == task_id).expect("task exists");
                if run.approved_revision == Some(request.plan_revision)
                    && task.state == TaskState::AwaitingApproval
                {
                    Self::transition_task_tx(
                        &tx,
                        task_id,
                        TaskState::AwaitingApproval,
                        TaskState::Queued,
                        reason::TASK_APPROVED,
                    )?;
                }
            }
            (_, false) => {
                let task_id = request.task_id.as_deref().expect("task approval has task");
                let task = tasks.iter().find(|t| t.id == task_id).expect("task exists");
                if !task.state.is_terminal() {
                    Self::transition_task_tx(
                        &tx,
                        task_id,
                        task.state,
                        TaskState::Cancelled,
                        reason::APPROVAL_REJECTED,
                    )?;
                }
            }
        }
        tx.commit()?;
        self.get_approval(approval_id)
    }

    fn task_approval_outstanding(&self, tx: &Connection, task_id: &str) -> StoreResult<bool> {
        Ok(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM workflow_approval_requests
               WHERE task_id=?1 AND kind='task_capability' AND status <> 'approved'
               AND status <> 'superseded')",
            [task_id],
            |r| r.get(0),
        )?)
    }

    /// True only for an approved, unexpired, same-revision, same-scope grant.
    pub fn has_live_task_approval(&self, task_id: &str) -> StoreResult<bool> {
        let task = self.get_task(task_id)?;
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM workflow_approval_requests r
               JOIN workflow_runs w ON w.id = r.run_id
               WHERE r.task_id=?1 AND r.kind='task_capability' AND r.status='approved'
               AND r.scope_digest=?2 AND r.plan_revision=w.plan_revision
               AND w.approved_revision=w.plan_revision AND r.expires_ms > ?3)",
            params![task_id, task.scope_digest, now_ms()],
            |r| r.get(0),
        )?)
    }

    pub fn expire_approvals(&self) -> StoreResult<usize> {
        let tx = self.conn.unchecked_transaction()?;
        let now = now_ms();
        let expired: Vec<(String, String, Option<String>)> = {
            let mut stmt = tx.prepare(
                "SELECT id, run_id, task_id FROM workflow_approval_requests
                 WHERE status='pending' AND expires_ms <= ?1",
            )?;
            let rows = stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (id, run_id, task_id) in &expired {
            tx.execute(
                "UPDATE workflow_approval_requests SET status='expired' WHERE id=?1",
                [id],
            )?;
            Self::event_tx(
                &tx,
                run_id,
                task_id.as_deref(),
                "approval_expired",
                json!({"approval_id": id}),
            )?;
            if let Some(task_id) = task_id {
                tx.execute(
                    "UPDATE workflow_tasks SET state='blocked', reason_code='approval_expired', updated_ms=?2
                     WHERE id=?1 AND state='awaiting_approval'",
                    params![task_id, now],
                )?;
            }
        }
        tx.commit()?;
        Ok(expired.len())
    }

    // ------------------------------------------------------ operator controls

    pub fn request_cancel(&self, run_id: &str) -> StoreResult<RunRecord> {
        let tx = self.conn.unchecked_transaction()?;
        let run = self.get_run(run_id)?;
        if run.state.is_terminal() {
            return Ok(run);
        }
        tx.execute(
            "UPDATE workflow_runs SET cancel_requested=1, updated_ms=?2 WHERE id=?1",
            params![run_id, now_ms()],
        )?;
        Self::event_tx(&tx, run_id, None, "cancel_requested", json!({}))?;
        if !matches!(run.state, RunState::Running | RunState::Validating) {
            Self::cancel_all_tx(&tx, &self.list_tasks(run_id)?)?;
            tx.execute(
                "UPDATE workflow_approval_requests SET status='superseded' WHERE run_id=?1 AND status='pending'",
                [run_id],
            )?;
            Self::transition_run_tx(
                &tx,
                run_id,
                run.state,
                RunState::Cancelled,
                reason::CANCEL_REQUESTED,
                Some(Outcome::Cancelled),
            )?;
        }
        tx.commit()?;
        self.get_run(run_id)
    }

    fn cancel_all_tx(tx: &Connection, tasks: &[TaskRecord]) -> StoreResult<()> {
        for task in tasks.iter().filter(|t| !t.state.is_terminal()) {
            if task.state.can_transition_to(TaskState::Cancelled) {
                Self::transition_task_tx(
                    tx,
                    &task.id,
                    task.state,
                    TaskState::Cancelled,
                    reason::CANCEL_REQUESTED,
                )?;
            } else {
                // Validating cannot be cancelled mid-check; mark failed honestly.
                Self::transition_task_tx(
                    tx,
                    &task.id,
                    task.state,
                    TaskState::Failed,
                    reason::CANCEL_REQUESTED,
                )?;
            }
        }
        Ok(())
    }

    pub fn request_pause(&self, run_id: &str) -> StoreResult<RunRecord> {
        let tx = self.conn.unchecked_transaction()?;
        let run = self.get_run(run_id)?;
        if run.state.is_terminal() {
            return Err(StoreError::Rejected(format!("run is {}", run.state)));
        }
        tx.execute(
            "UPDATE workflow_runs SET pause_requested=1, updated_ms=?2 WHERE id=?1",
            params![run_id, now_ms()],
        )?;
        if run.state == RunState::Queued {
            Self::transition_run_tx(
                &tx,
                run_id,
                RunState::Queued,
                RunState::Paused,
                reason::PAUSE_REQUESTED,
                None,
            )?;
        } else {
            Self::event_tx(&tx, run_id, None, "pause_requested", json!({}))?;
        }
        tx.commit()?;
        self.get_run(run_id)
    }

    pub fn resume(&self, run_id: &str, operator: &str) -> StoreResult<RunRecord> {
        let tx = self.conn.unchecked_transaction()?;
        let run = self.get_run(run_id)?;
        if !matches!(run.state, RunState::Paused | RunState::Blocked) {
            return Err(StoreError::Rejected(format!(
                "run is {}, not paused or blocked",
                run.state
            )));
        }
        if run.approved_revision != Some(run.plan_revision) {
            return Err(StoreError::Rejected(
                "current plan revision is not approved".into(),
            ));
        }
        tx.execute(
            "UPDATE workflow_runs SET pause_requested=0, updated_ms=?2 WHERE id=?1",
            params![run_id, now_ms()],
        )?;
        Self::event_tx(
            &tx,
            run_id,
            None,
            "resumed",
            json!({"by": truncate(operator, 120)}),
        )?;
        Self::transition_run_tx(
            &tx,
            run_id,
            run.state,
            RunState::Queued,
            reason::RESUMED,
            None,
        )?;
        tx.commit()?;
        self.get_run(run_id)
    }

    /// Operator resolution of a blocked task. Side-effecting tasks that are
    /// requeued must be re-approved; uncertain side effects need an explicit
    /// applied / not-applied confirmation first.
    pub fn override_blocked_task(
        &self,
        task_id: &str,
        resolution: OverrideResolution,
        operator: &str,
        approval_ttl_ms: i64,
    ) -> StoreResult<TaskRecord> {
        let tx = self.conn.unchecked_transaction()?;
        let task = self.get_task(task_id)?;
        if task.state != TaskState::Blocked {
            return Err(StoreError::Rejected(format!(
                "task is {}, not blocked",
                task.state
            )));
        }
        let uncertain: i64 = tx.query_row(
            "SELECT COUNT(*) FROM workflow_tool_invocations WHERE task_id=?1 AND status='uncertain'",
            [task_id],
            |r| r.get(0),
        )?;
        let now = now_ms();
        match resolution {
            OverrideResolution::Cancel => {
                Self::transition_task_tx(
                    &tx,
                    task_id,
                    TaskState::Blocked,
                    TaskState::Cancelled,
                    reason::OPERATOR_OVERRIDE,
                )?;
            }
            OverrideResolution::SideEffectApplied | OverrideResolution::SideEffectNotApplied => {
                if uncertain == 0 {
                    return Err(StoreError::Rejected(
                        "task has no uncertain side effects".into(),
                    ));
                }
                let status = if resolution == OverrideResolution::SideEffectApplied {
                    "succeeded"
                } else {
                    "failed"
                };
                tx.execute(
                    "UPDATE workflow_tool_invocations SET status=?2, finished_ms=?3,
                        decision_reason='operator_confirmed'
                     WHERE task_id=?1 AND status='uncertain'",
                    params![task_id, status, now],
                )?;
                Self::event_tx(
                    &tx,
                    &task.run_id,
                    Some(task_id),
                    "side_effect_resolved",
                    json!({"resolution": resolution, "by": truncate(operator, 120)}),
                )?;
            }
            OverrideResolution::Requeue => {
                if uncertain > 0 {
                    return Err(StoreError::Rejected(
                        "resolve uncertain side effects before requeueing".into(),
                    ));
                }
                if task.attempt_count >= task.max_attempts {
                    tx.execute(
                        "UPDATE workflow_tasks SET max_attempts=MIN(5, attempt_count+1) WHERE id=?1",
                        [task_id],
                    )?;
                }
                if task.side_effect.is_read_only() {
                    Self::transition_task_tx(
                        &tx,
                        task_id,
                        TaskState::Blocked,
                        TaskState::Queued,
                        reason::OPERATOR_OVERRIDE,
                    )?;
                } else {
                    Self::transition_task_tx(
                        &tx,
                        task_id,
                        TaskState::Blocked,
                        TaskState::AwaitingApproval,
                        reason::OPERATOR_OVERRIDE,
                    )?;
                    let summary = format!(
                        "Re-approval after override of `{}` ({})",
                        task.title, task.side_effect
                    );
                    Self::insert_approval_tx(
                        &tx,
                        &task.run_id,
                        Some(task_id),
                        "task_capability",
                        &task.capabilities,
                        &task.scope_digest,
                        task.plan_revision,
                        &summary,
                        now,
                        approval_ttl_ms,
                    )?;
                }
            }
        }
        tx.commit()?;
        self.get_task(task_id)
    }

    // ------------------------------------------------------------ execution

    /// Promote due retries, block tasks whose dependencies can no longer
    /// complete, and return dependency-ready queued tasks.
    pub fn ready_tasks(&self, run_id: &str) -> StoreResult<Vec<TaskRecord>> {
        let tx = self.conn.unchecked_transaction()?;
        let now = now_ms();
        let tasks = self.list_tasks(run_id)?;
        for task in tasks.iter().filter(|t| {
            t.state == TaskState::RetryWait && t.not_before_ms.is_none_or(|nb| nb <= now)
        }) {
            Self::transition_task_tx(
                &tx,
                &task.id,
                TaskState::RetryWait,
                TaskState::Queued,
                reason::RETRY_SCHEDULED,
            )?;
        }
        // Fixpoint: a failed/cancelled/blocked dependency blocks dependents.
        loop {
            let tasks = self.list_tasks(run_id)?;
            let state: BTreeMap<&str, TaskState> =
                tasks.iter().map(|t| (t.id.as_str(), t.state)).collect();
            let mut changed = false;
            for task in tasks.iter().filter(|t| {
                matches!(
                    t.state,
                    TaskState::Queued | TaskState::AwaitingApproval | TaskState::Planned
                )
            }) {
                let dead = task.depends_on.iter().any(|d| {
                    matches!(
                        state.get(d.as_str()),
                        Some(TaskState::Failed | TaskState::Cancelled | TaskState::Blocked)
                    )
                });
                if dead {
                    Self::transition_task_tx(
                        &tx,
                        &task.id,
                        task.state,
                        TaskState::Blocked,
                        reason::DEPENDENCY_FAILED,
                    )?;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        tx.commit()?;
        let tasks = self.list_tasks(run_id)?;
        let completed: BTreeSet<&str> = tasks
            .iter()
            .filter(|t| t.state == TaskState::Completed)
            .map(|t| t.id.as_str())
            .collect();
        let mut ready: Vec<TaskRecord> = tasks
            .iter()
            .filter(|t| t.state == TaskState::Queued)
            .filter(|t| t.depends_on.iter().all(|d| completed.contains(d.as_str())))
            .cloned()
            .collect();
        ready.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.created_ms.cmp(&b.created_ms))
                .then(a.id.cmp(&b.id))
        });
        Ok(ready)
    }

    /// Crash-safe claim: one live lease per task, attempt number bumped
    /// atomically. Returns `None` when another worker holds the task.
    pub fn claim(
        &self,
        task_id: &str,
        instance_id: &str,
        worker_id: &str,
        lease_ms: i64,
    ) -> StoreResult<Option<u32>> {
        // IMMEDIATE takes the write lock before reading, so two processes
        // cannot both observe "no lease" and race to insert one.
        let tx = rusqlite::Transaction::new_unchecked(
            self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let now = now_ms();
        let live: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM workflow_worker_leases WHERE task_id=?1 AND expires_ms > ?2)",
            params![task_id, now],
            |r| r.get(0),
        )?;
        if live {
            return Ok(None);
        }
        let task = self.get_task(task_id)?;
        if task.state != TaskState::Queued {
            return Ok(None);
        }
        if task.attempt_count >= task.max_attempts {
            Self::transition_task_tx(
                &tx,
                task_id,
                TaskState::Queued,
                TaskState::Blocked,
                reason::ATTEMPTS_EXHAUSTED,
            )?;
            tx.commit()?;
            return Ok(None);
        }
        let attempt = task.attempt_count + 1;
        tx.execute(
            "DELETE FROM workflow_worker_leases WHERE task_id=?1",
            [task_id],
        )?;
        tx.execute(
            "INSERT INTO workflow_worker_leases(task_id,run_id,instance_id,worker_id,attempt_no,
                acquired_ms,heartbeat_ms,expires_ms) VALUES (?1,?2,?3,?4,?5,?6,?6,?7)",
            params![
                task_id,
                task.run_id,
                instance_id,
                worker_id,
                attempt,
                now,
                now + lease_ms
            ],
        )?;
        tx.execute(
            "UPDATE workflow_tasks SET attempt_count=?2 WHERE id=?1",
            params![task_id, attempt],
        )?;
        tx.execute(
            "INSERT INTO workflow_task_attempts(task_id,attempt_no,worker_id,status,started_ms)
             VALUES (?1,?2,?3,'running',?4)",
            params![task_id, attempt, worker_id, now],
        )?;
        Self::transition_task_tx(
            &tx,
            task_id,
            TaskState::Queued,
            TaskState::Running,
            "claimed",
        )?;
        tx.commit()?;
        Ok(Some(attempt))
    }

    pub fn heartbeat(&self, task_id: &str, instance_id: &str, lease_ms: i64) -> StoreResult<bool> {
        let now = now_ms();
        Ok(self.conn.execute(
            "UPDATE workflow_worker_leases SET heartbeat_ms=?3, expires_ms=?4
             WHERE task_id=?1 AND instance_id=?2",
            params![task_id, instance_id, now, now + lease_ms],
        )? == 1)
    }

    /// Persist a worker's output and move the task into `validating`.
    pub fn record_output(
        &self,
        task_id: &str,
        output: &Value,
        summary: &str,
        evidence_class: EvidenceClass,
    ) -> StoreResult<String> {
        let tx = self.conn.unchecked_transaction()?;
        let text = serde_json::to_string(output)?;
        if text.len() > 262_144 {
            return Err(StoreError::Rejected("worker output exceeds 256 KiB".into()));
        }
        let digest = sha256_hex(text.as_bytes());
        tx.execute(
            "UPDATE workflow_tasks SET output_json=?2, output_sha256=?3, summary=?4, evidence_class=?5
             WHERE id=?1 AND state='running'",
            params![task_id, text, digest, truncate(summary, 2000), evidence_class.as_str()],
        )?;
        Self::transition_task_tx(
            &tx,
            task_id,
            TaskState::Running,
            TaskState::Validating,
            "output_recorded",
        )?;
        tx.commit()?;
        Ok(digest)
    }

    /// Close an attempt and release its lease.
    pub fn finish_attempt(
        &self,
        task_id: &str,
        attempt: u32,
        status: &str,
        error: Option<(ErrorCategory, &str)>,
    ) -> StoreResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE workflow_task_attempts SET status=?3, error_category=?4, error_detail=?5, finished_ms=?6
             WHERE task_id=?1 AND attempt_no=?2 AND status='running'",
            params![
                task_id,
                attempt,
                status,
                error.map(|(c, _)| c.as_str()),
                error.map(|(_, d)| truncate(d, 500)),
                now_ms()
            ],
        )?;
        tx.execute(
            "DELETE FROM workflow_worker_leases WHERE task_id=?1",
            [task_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_attempts(&self, run_id: &str) -> StoreResult<Vec<AttemptRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.task_id,a.attempt_no,a.worker_id,a.status,a.error_category,a.error_detail,
                    a.started_ms,a.finished_ms
             FROM workflow_task_attempts a JOIN workflow_tasks t ON t.id=a.task_id
             WHERE t.run_id=?1 ORDER BY a.started_ms, a.task_id, a.attempt_no",
        )?;
        let rows = stmt.query_map([run_id], |r| {
            Ok(AttemptRecord {
                task_id: r.get(0)?,
                attempt_no: r.get(1)?,
                worker_id: r.get(2)?,
                status: r.get(3)?,
                error_category: r.get(4)?,
                error_detail: r.get(5)?,
                started_ms: r.get(6)?,
                finished_ms: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Add provider credits; returns the new total.
    pub fn add_credits(&self, run_id: &str, credits: u32) -> StoreResult<u32> {
        self.conn.execute(
            "UPDATE workflow_runs SET credits_used=credits_used+?2 WHERE id=?1",
            params![run_id, credits],
        )?;
        Ok(self.get_run(run_id)?.credits_used)
    }

    /// Insert a delegated or runtime-added task under the current revision.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_delegated_task(
        &self,
        run: &RunRecord,
        parent: &TaskRecord,
        key: &str,
        role: &str,
        title: &str,
        input: &Value,
        capabilities: &BTreeSet<Capability>,
        timeout_ms: u64,
        auto_queue: bool,
        approval_ttl_ms: i64,
    ) -> StoreResult<TaskRecord> {
        let tx = self.conn.unchecked_transaction()?;
        let side_effect = capabilities
            .iter()
            .fold(SideEffect::ReadOnly, |acc, c| acc.max(c.side_effect()));
        let digest = task_scope_digest(&run.id, key, role, input, capabilities, side_effect);
        let id = new_id("task");
        let now = now_ms();
        tx.execute(
            "INSERT INTO workflow_tasks(id,run_id,plan_revision,idempotency_key,parent_task_id,
                delegation_depth,role,title,input_json,success_criteria_json,side_effect,
                capabilities_json,scope_digest,state,max_attempts,timeout_ms,created_ms,updated_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'[]',?10,?11,?12,'planned',?13,?14,?15,?15)",
            params![
                id,
                run.id,
                run.plan_revision,
                key,
                parent.id,
                parent.delegation_depth + 1,
                role,
                truncate(title, 200),
                serde_json::to_string(input)?,
                side_effect.as_str(),
                serde_json::to_string(capabilities)?,
                digest,
                run.budgets.max_attempts_per_task.clamp(1, 5),
                timeout_ms.clamp(100, 3_600_000) as i64,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO workflow_task_dependencies(run_id,task_id,depends_on) VALUES (?1,?2,?3)",
            params![run.id, id, parent.id],
        )?;
        if auto_queue {
            Self::transition_task_tx(
                &tx,
                &id,
                TaskState::Planned,
                TaskState::Queued,
                "delegated_within_approved_scope",
            )?;
        } else {
            Self::transition_task_tx(
                &tx,
                &id,
                TaskState::Planned,
                TaskState::AwaitingApproval,
                "delegation_requires_approval",
            )?;
            let summary = format!(
                "Delegated task `{title}` ({role}) from `{}` requests: {}",
                parent.title,
                capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Self::insert_approval_tx(
                &tx,
                &run.id,
                Some(&id),
                "task_capability",
                capabilities,
                &digest,
                run.plan_revision,
                &summary,
                now,
                approval_ttl_ms,
            )?;
        }
        tx.commit()?;
        self.get_task(&id)
    }

    // ------------------------------------------------------- tool invocations

    /// Record intent to invoke a tool *before* invoking it. For side-effecting
    /// tools the idempotency key is independent of attempt and revision, so a
    /// retried or recovered task can never repeat an applied side effect.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_tool(
        &self,
        task: &TaskRecord,
        attempt: u32,
        tool_id: &str,
        capability: Capability,
        side_effect: SideEffect,
        args: &Value,
    ) -> StoreResult<ToolBegin> {
        let args_sha = sha256_hex(args.to_string().as_bytes());
        let key = if side_effect.is_read_only() {
            format!(
                "{}:{}:{attempt}:{tool_id}:{args_sha}:{}",
                task.run_id,
                task.id,
                new_id("ro")
            )
        } else {
            format!("{}:{}:{tool_id}:{args_sha}", task.run_id, task.key)
        };
        let key = sha256_hex(key.as_bytes());
        let tx = self.conn.unchecked_transaction()?;
        let prior: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT status, output_sha256 FROM workflow_tool_invocations WHERE idempotency_key=?1",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match prior {
            Some((status, output)) if status == "succeeded" => {
                return Ok(ToolBegin::AlreadyApplied(output.unwrap_or_default()))
            }
            Some((status, _)) if status == "uncertain" || status == "started" => {
                return Err(StoreError::Rejected(
                    "a previous side effect is unresolved; operator review required".into(),
                ))
            }
            Some(_) => {
                tx.execute(
                    "DELETE FROM workflow_tool_invocations WHERE idempotency_key=?1",
                    [&key],
                )?;
            }
            None => {}
        }
        let id = new_id("tool");
        tx.execute(
            "INSERT INTO workflow_tool_invocations(id,run_id,task_id,attempt_no,tool_id,capability,
                side_effect,idempotency_key,args_sha256,status,decision_reason,started_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'started','allowed',?10)",
            params![
                id,
                task.run_id,
                task.id,
                attempt,
                tool_id,
                capability.as_str(),
                side_effect.as_str(),
                key,
                args_sha,
                now_ms()
            ],
        )?;
        Self::event_tx(
            &tx,
            &task.run_id,
            Some(&task.id),
            "tool_started",
            json!({"invocation_id": id, "tool": tool_id, "capability": capability}),
        )?;
        tx.commit()?;
        Ok(ToolBegin::Proceed(id))
    }

    pub fn finish_tool(
        &self,
        invocation_id: &str,
        ok: bool,
        output_sha256: Option<&str>,
        detail: &str,
    ) -> StoreResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE workflow_tool_invocations SET status=?2, output_sha256=?3, finished_ms=?4,
                decision_reason=?5 WHERE id=?1 AND status='started'",
            params![
                invocation_id,
                if ok { "succeeded" } else { "failed" },
                output_sha256,
                now_ms(),
                truncate(detail, 120)
            ],
        )?;
        let (run_id, task_id, tool): (String, String, String) = tx.query_row(
            "SELECT run_id, task_id, tool_id FROM workflow_tool_invocations WHERE id=?1",
            [invocation_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Self::event_tx(
            &tx,
            &run_id,
            Some(&task_id),
            "tool_finished",
            json!({"invocation_id": invocation_id, "tool": tool, "ok": ok}),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn deny_tool(
        &self,
        task: &TaskRecord,
        attempt: u32,
        tool_id: &str,
        capability: Option<Capability>,
        side_effect: SideEffect,
        args: &Value,
        reason_text: &str,
    ) -> StoreResult<()> {
        let args_sha = sha256_hex(args.to_string().as_bytes());
        let id = new_id("tool");
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO workflow_tool_invocations(id,run_id,task_id,attempt_no,tool_id,capability,
                side_effect,idempotency_key,args_sha256,status,decision_reason,started_ms,finished_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'denied',?10,?11,?11)",
            params![
                id,
                task.run_id,
                task.id,
                attempt,
                truncate(tool_id, 120),
                capability.map_or("unknown", Capability::as_str),
                side_effect.as_str(),
                id,
                args_sha,
                truncate(reason_text, 120),
                now_ms()
            ],
        )?;
        Self::event_tx(
            &tx,
            &task.run_id,
            Some(&task.id),
            "tool_denied",
            json!({"tool": truncate(tool_id, 120), "reason": truncate(reason_text, 120)}),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn tool_invocations(&self, run_id: &str) -> StoreResult<Vec<ToolInvocationRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,task_id,attempt_no,tool_id,capability,side_effect,args_sha256,status,
                    decision_reason,output_sha256,started_ms,finished_ms
             FROM workflow_tool_invocations WHERE run_id=?1 ORDER BY started_ms, id",
        )?;
        let rows = stmt.query_map([run_id], |r| {
            let side: String = r.get(5)?;
            Ok(ToolInvocationRecord {
                id: r.get(0)?,
                task_id: r.get(1)?,
                attempt_no: r.get(2)?,
                tool_id: r.get(3)?,
                capability: r.get(4)?,
                side_effect: SideEffect::parse(&side).ok_or_else(|| bad_enum(5, &side))?,
                args_sha256: r.get(6)?,
                status: r.get(7)?,
                decision_reason: r.get(8)?,
                output_sha256: r.get(9)?,
                started_ms: r.get(10)?,
                finished_ms: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Calls of `tool_id` with exactly these arguments already recorded for
    /// this task attempt (any status), for loop detection.
    pub fn identical_tool_calls(
        &self,
        task_id: &str,
        attempt: u32,
        tool_id: &str,
        args: &Value,
    ) -> StoreResult<usize> {
        let args_sha = sha256_hex(args.to_string().as_bytes());
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM workflow_tool_invocations
             WHERE task_id=?1 AND attempt_no=?2 AND tool_id=?3 AND args_sha256=?4",
            params![task_id, attempt, tool_id, args_sha],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as usize)
    }

    pub fn successful_tool_calls(&self, task_id: &str, attempt: u32) -> StoreResult<usize> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM workflow_tool_invocations WHERE task_id=?1 AND attempt_no=?2 AND status='succeeded'",
            params![task_id, attempt],
            |r| r.get::<_, i64>(0),
        )? as usize)
    }

    // --------------------------------------------------------------- events

    fn event_tx(
        tx: &Connection,
        run_id: &str,
        task_id: Option<&str>,
        kind: &str,
        detail: Value,
    ) -> StoreResult<()> {
        let mut text = detail.to_string();
        if text.len() > 4096 {
            text = json!({"truncated": true}).to_string();
        }
        tx.execute(
            "INSERT INTO workflow_events(run_id,task_id,kind,detail_json,correlation_id,created_ms)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                run_id,
                task_id,
                kind,
                text,
                task_id.unwrap_or(run_id),
                now_ms()
            ],
        )?;
        Ok(())
    }

    pub fn event(
        &self,
        run_id: &str,
        task_id: Option<&str>,
        kind: &str,
        detail: Value,
    ) -> StoreResult<()> {
        Self::event_tx(self.conn, run_id, task_id, kind, detail)
    }

    /// Durable replay: events with `seq > cursor`, oldest first.
    pub fn events_since(
        &self,
        run_id: &str,
        cursor: i64,
        limit: usize,
    ) -> StoreResult<Vec<EventRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq,run_id,task_id,kind,detail_json,correlation_id,created_ms
             FROM workflow_events WHERE run_id=?1 AND seq>?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![run_id, cursor, limit.clamp(1, 1000) as i64], |r| {
            Ok(EventRecord {
                seq: r.get(0)?,
                run_id: r.get(1)?,
                task_id: r.get(2)?,
                kind: r.get(3)?,
                detail: json_col(r, 4)?,
                correlation_id: r.get(5)?,
                created_ms: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // -------------------------------------------------------------- recovery

    /// Reconcile state left by a previous process. Leases owned by another
    /// instance or past expiry are stale. Tasks whose side effects may have
    /// started are blocked for operator review; read-only work is retried.
    /// Runs that were executing are paused until an operator resumes them.
    pub fn recover(&self, instance_id: &str) -> StoreResult<RecoveryReport> {
        let tx = self.conn.unchecked_transaction()?;
        let now = now_ms();
        let mut report = RecoveryReport::default();
        let orphaned: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT t.id, t.state FROM workflow_tasks t
                 LEFT JOIN workflow_worker_leases l ON l.task_id = t.id
                 WHERE t.state IN ('running','validating')
                   AND (l.task_id IS NULL OR l.instance_id <> ?1 OR l.expires_ms <= ?2)",
            )?;
            let rows = stmt.query_map(params![instance_id, now], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (task_id, state) in orphaned {
            let task = self.get_task(&task_id)?;
            let from = TaskState::parse(&state).expect("checked by SQL");
            let uncertain = tx.execute(
                "UPDATE workflow_tool_invocations SET status='uncertain', decision_reason='interrupted_by_restart'
                 WHERE task_id=?1 AND status='started' AND side_effect <> 'read_only'",
                [&task_id],
            )?;
            tx.execute(
                "UPDATE workflow_tool_invocations SET status='failed', finished_ms=?2, decision_reason='interrupted_by_restart'
                 WHERE task_id=?1 AND status='started'",
                params![task_id, now],
            )?;
            report.invocations_uncertain += uncertain;
            tx.execute(
                "UPDATE workflow_task_attempts SET status='abandoned', error_category='crash',
                    error_detail='process ended before the attempt finished', finished_ms=?2
                 WHERE task_id=?1 AND status='running'",
                params![task_id, now],
            )?;
            tx.execute(
                "DELETE FROM workflow_worker_leases WHERE task_id=?1",
                [&task_id],
            )?;
            if uncertain > 0 {
                Self::transition_task_tx(
                    &tx,
                    &task_id,
                    from,
                    TaskState::Blocked,
                    reason::UNCERTAIN_SIDE_EFFECT,
                )?;
                report.tasks_blocked += 1;
            } else if task.attempt_count < task.max_attempts {
                Self::transition_task_tx(
                    &tx,
                    &task_id,
                    from,
                    TaskState::RetryWait,
                    reason::RECOVERED_AFTER_RESTART,
                )?;
                tx.execute(
                    "UPDATE workflow_tasks SET not_before_ms=?2 WHERE id=?1",
                    params![task_id, now],
                )?;
                report.tasks_requeued += 1;
            } else {
                Self::transition_task_tx(
                    &tx,
                    &task_id,
                    from,
                    TaskState::Failed,
                    reason::ATTEMPTS_EXHAUSTED,
                )?;
                report.tasks_failed += 1;
            }
        }
        // Remove any remaining stale leases (e.g. from queued tasks).
        tx.execute(
            "DELETE FROM workflow_worker_leases WHERE instance_id <> ?1 OR expires_ms <= ?2",
            params![instance_id, now],
        )?;
        let runs: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, state FROM workflow_runs WHERE state IN ('running','validating')",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (run_id, state) in runs {
            let live: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM workflow_worker_leases WHERE run_id=?1)",
                [&run_id],
                |r| r.get(0),
            )?;
            if live {
                continue;
            }
            let from = RunState::parse(&state).expect("checked by SQL");
            if from == RunState::Validating {
                Self::transition_run_tx(
                    &tx,
                    &run_id,
                    from,
                    RunState::Running,
                    reason::RECOVERED_AFTER_RESTART,
                    None,
                )?;
                Self::transition_run_tx(
                    &tx,
                    &run_id,
                    RunState::Running,
                    RunState::Paused,
                    reason::RECOVERED_AFTER_RESTART,
                    None,
                )?;
            } else {
                Self::transition_run_tx(
                    &tx,
                    &run_id,
                    from,
                    RunState::Paused,
                    reason::RECOVERED_AFTER_RESTART,
                    None,
                )?;
            }
            report.runs_paused += 1;
        }
        tx.commit()?;
        Ok(report)
    }

    // --------------------------------------------------------------- reports

    pub fn save_report(&self, run_id: &str, format: &str, body: &str) -> StoreResult<String> {
        let digest = sha256_hex(body.as_bytes());
        self.conn.execute(
            "INSERT OR IGNORE INTO workflow_run_reports(run_id,format,sha256,body,created_ms)
             VALUES (?1,?2,?3,?4,?5)",
            params![run_id, format, digest, body, now_ms()],
        )?;
        Ok(digest)
    }

    pub fn latest_report(
        &self,
        run_id: &str,
        format: &str,
    ) -> StoreResult<Option<(String, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT sha256, body FROM workflow_run_reports WHERE run_id=?1 AND format=?2
                 ORDER BY created_ms DESC LIMIT 1",
                params![run_id, format],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }
}
