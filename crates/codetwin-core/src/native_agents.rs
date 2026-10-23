//! Native, durable, least-privilege autonomous review workflow.
//! The role planner operates only on existing passive CodeTwin analyzers.
//! It does not execute external commands, generate exploits or bypass user approvals.
use crate::{
    assessment_jobs::{AssessmentJobs, AssessmentPlanRequest},
    Database, DatabaseAnalysisService, QaDiscoveryService, RuntimeReliabilityService,
    SecretScanningService, WorkspaceService,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const STEP_TOOLS: [(&str, &str); 6] = [
    ("scout", "Project Recon"),
    ("source", "Source Auditor"),
    ("secrets", "Secrets Auditor"),
    ("qa", "Test Researcher"),
    ("database", "Database Reviewer"),
    ("runtime", "Runtime Reviewer"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStep {
    pub position: usize,
    pub role: String,
    pub tool: String,
    pub status: String,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRun {
    pub id: String,
    pub project_id: String,
    pub objective: String,
    pub status: String,
    pub message: Option<String>,
    pub max_files: usize,
    pub budget_seconds: u64,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub steps: Vec<AgentStep>,
}

pub struct NativeAgents<'a> {
    db: &'a Database,
}

impl<'a> NativeAgents<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn create(
        &self,
        project_id: &str,
        objective: &str,
        max_files: usize,
        budget_seconds: u64,
    ) -> Result<AgentRun, String> {
        let all_roles = STEP_TOOLS
            .iter()
            .map(|(id, _)| (*id).to_string())
            .collect::<Vec<_>>();
        self.create_with_roles(project_id, objective, max_files, budget_seconds, &all_roles)
    }

    pub fn create_with_roles(
        &self,
        project_id: &str,
        objective: &str,
        max_files: usize,
        budget_seconds: u64,
        roles: &[String],
    ) -> Result<AgentRun, String> {
        if !(2..=STEP_TOOLS.len()).contains(&roles.len())
            || !roles.iter().any(|role| role.as_str() == "scout")
            || !roles.iter().any(|role| role.as_str() == "source")
            || roles
                .iter()
                .any(|role| !STEP_TOOLS.iter().any(|(id, _)| role.as_str() == *id))
            || roles
                .iter()
                .enumerate()
                .any(|(i, role)| roles[..i].contains(role))
        {
            return Err(
                "Select unique supported roles; Project Recon and Source Auditor are required"
                    .into(),
            );
        }
        if objective.trim().is_empty() || objective.len() > 2000 {
            return Err("Give a review objective of at most 2000 bytes".into());
        }
        if !(1..=2000).contains(&max_files) || !(1..=3600).contains(&budget_seconds) {
            return Err("Allowed budgets: 1–2000 files and 1–3600 seconds".into());
        }
        let project = WorkspaceService::new(self.db)
            .get_project(project_id)
            .map_err(to_error)?
            .ok_or("Choose an indexed project")?;
        if project.root_path.is_empty() {
            return Err("Project root is missing".into());
        }
        let exists: bool = self.db.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM native_agent_runs WHERE project_id=?1 AND status IN ('approved','running'))",
            [project_id], |row| row.get(0),
        ).map_err(to_error)?;
        if exists {
            return Err("An approved or running review already exists for this project".into());
        }
        // The existing assessment planner hashes verified source inputs and indexes.
        // A stale or oversized project is rejected before creating an executable plan.
        let assessment = AssessmentJobs::new(self.db).create_plan(AssessmentPlanRequest {
            project_id: project_id.into(),
            tools: vec!["code.sast".into(), "code.quality".into()],
            max_files,
            budget_seconds,
        })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(to_error)?
            .as_nanos();
        let id = crate::deterministic_id(
            "native-agents",
            &[project_id, &assessment.id, &nonce.to_string()],
        );
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(to_error)?;
        tx.execute(
            "INSERT INTO native_agent_runs (id,project_id,objective,max_files,budget_seconds,assessment_id)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![id,project_id,objective.trim(),max_files,budget_seconds,assessment.id],
        ).map_err(to_error)?;
        for (position, (tool, role)) in STEP_TOOLS.iter().enumerate() {
            if !roles.iter().any(|chosen| chosen.as_str() == *tool) {
                continue;
            }
            tx.execute(
                "INSERT INTO native_agent_steps(run_id,position,role,tool) VALUES(?1,?2,?3,?4)",
                params![id, position, role, tool],
            )
            .map_err(to_error)?;
        }
        tx.commit().map_err(to_error)?;
        crate::native_agent_delegation::NativeDelegation::new(self.db).prepare(&id)?;
        self.get(&id)
    }

    pub fn get(&self, id: &str) -> Result<AgentRun, String> {
        let mut run = self.db.connection().query_row(
            "SELECT id,project_id,objective,status,message,max_files,budget_seconds,created_at,started_at,finished_at
             FROM native_agent_runs WHERE id=?1",
            [id],
            |r| Ok(AgentRun {
                id:r.get(0)?,project_id:r.get(1)?,objective:r.get(2)?,
                status:r.get(3)?,message:r.get(4)?,max_files:r.get(5)?,
                budget_seconds:r.get(6)?,created_at:r.get(7)?,
                started_at:r.get(8)?,finished_at:r.get(9)?,steps:vec![],
            }),
        ).optional().map_err(to_error)?.ok_or("Native agent review not found")?;
        let mut query = self
            .db
            .connection()
            .prepare(
                "SELECT position,role,tool,status,result_json FROM native_agent_steps
             WHERE run_id=?1 ORDER BY position",
            )
            .map_err(to_error)?;
        run.steps = query
            .query_map([id], |r| {
                Ok(AgentStep {
                    position: r.get(0)?,
                    role: r.get(1)?,
                    tool: r.get(2)?,
                    status: r.get(3)?,
                    result: r.get(4)?,
                })
            })
            .map_err(to_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_error)?;
        Ok(run)
    }

    pub fn list(&self, project_id: &str) -> Result<Vec<AgentRun>, String> {
        let mut statement = self
            .db
            .connection()
            .prepare(
                "SELECT id FROM native_agent_runs WHERE project_id=?1 ORDER BY rowid DESC LIMIT 30",
            )
            .map_err(to_error)?;
        let ids = statement
            .query_map([project_id], |r| r.get::<_, String>(0))
            .map_err(to_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_error)?;
        ids.iter().map(|id| self.get(id)).collect()
    }

    pub fn approve(&self, id: &str) -> Result<AgentRun, String> {
        let changed = self
            .db
            .connection()
            .execute(
                "UPDATE native_agent_runs SET status='approved' WHERE id=?1 AND status='planned'",
                [id],
            )
            .map_err(to_error)?;
        if changed != 1 {
            return Err("Only a fresh planned review can be approved".into());
        }
        self.get(id)
    }

    pub fn cancel(&self, id: &str) -> Result<AgentRun, String> {
        let assessment_id: String = self
            .db
            .connection()
            .query_row(
                "SELECT assessment_id FROM native_agent_runs WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(to_error)?;
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(to_error)?;
        let changed = tx
            .execute(
                "UPDATE native_agent_runs SET cancel_requested=1,
             status=CASE WHEN status IN ('planned','approved') THEN 'cancelled' ELSE status END,
             finished_at=CASE WHEN status IN ('planned','approved') THEN CURRENT_TIMESTAMP ELSE finished_at END
             WHERE id=?1 AND status IN ('planned','approved','running')",
                [id],
            )
            .map_err(to_error)?;
        if changed != 1 {
            return Err("Review is already finished or missing".into());
        }
        // For not-yet-running reviews, no specialist may remain queued after
        // cancellation. A running review is finalized by its own supervisor.
        tx.execute(
            "UPDATE native_agent_steps SET status='cancelled',
             finished_at=CURRENT_TIMESTAMP WHERE run_id=?1 AND status='pending'
             AND EXISTS (SELECT 1 FROM native_agent_runs
                         WHERE id=?1 AND status='cancelled')",
            [id],
        )
        .map_err(to_error)?;
        tx.execute(
            "UPDATE native_delegation_tasks SET status='cancelled'
             WHERE run_id=?1 AND status='pending'
             AND EXISTS (SELECT 1 FROM native_agent_runs
                         WHERE id=?1 AND status='cancelled')",
            [id],
        )
        .map_err(to_error)?;
        tx.commit().map_err(to_error)?;
        // A running assessment reads its own cancellation flag at analyzer boundaries.
        let _ = AssessmentJobs::new(self.db).cancel(&assessment_id);
        self.get(id)
    }

    fn boundary(&self, id: &str, start: Instant, budget: u64) -> Result<(), String> {
        let cancelled: bool = self
            .db
            .connection()
            .query_row(
                "SELECT cancel_requested FROM native_agent_runs WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(to_error)?;
        if cancelled {
            return Err("Cancelled at analyzer boundary".into());
        }
        if start.elapsed().as_secs() >= budget {
            return Err("Time budget expired at analyzer boundary".into());
        }
        Ok(())
    }

    pub fn execute(&self, id: &str) -> Result<AgentRun, String> {
        self.execute_internal(id, None)
    }

    /// Execute approved passive analyzers only when an external policy verifies
    /// the next role against the durable SQLite delegation graph at each boundary.
    /// The policy cannot add roles or invoke tools; the native Rust supervisor owns
    /// authorization, execution, cancellation and all database writes.
    pub fn execute_with_dispatch(
        &self,
        id: &str,
        dispatch: &dyn Fn(&Database, &AgentRun, &AgentStep) -> Result<(), String>,
    ) -> Result<AgentRun, String> {
        self.execute_internal(id, Some(dispatch))
    }

    fn execute_internal(
        &self,
        id: &str,
        dispatch: Option<&dyn Fn(&Database, &AgentRun, &AgentStep) -> Result<(), String>>,
    ) -> Result<AgentRun, String> {
        let run = self.get(id)?;
        if run.status != "approved" {
            return Err("Approve this review before running it".into());
        }
        // Atomic SQLite authorization gate: waiting queued reviews must
        // first be claimed by the FIFO runner. An interrupted queue receipt
        // cannot re-use a formerly approved review, including older databases
        // whose interrupted parent was not yet retired.
        let claimed = self
            .db
            .connection()
            .execute(
                "UPDATE native_agent_runs SET status='running',started_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='approved' AND cancel_requested=0
               AND NOT EXISTS (
                 SELECT 1 FROM native_flow_queue
                 WHERE review_id=?1 AND status IN ('queued','interrupted')
               )
               AND NOT EXISTS (
                 SELECT 1 FROM native_worker_audit
                 WHERE run_id=?1 AND status='running'
               )",
                [id],
            )
            .map_err(to_error)?;
        if claimed != 1 {
            return Err("Review state changed before execution".into());
        }
        let start = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.run_steps(&run, start, dispatch)))
            .unwrap_or_else(|_| Err("Review encountered a worker panic".into()));
        self.finalize_review(id, result.err())?;
        // Remember only non-sensitive role status and source-run provenance.
        crate::native_agent_memory::AgentMemory::new(self.db).record_run(id)?;
        crate::native_agent_knowledge::AgentKnowledge::new(self.db).ingest(id)?;
        self.get(id)
    }

    /// The initial terminal decision, cancellation check, evidence-chain
    /// verification and cleanup must have one SQLite commit boundary. A
    /// competing cancel() can either acquire the write lock first (and force
    /// cancelled) or will see an already terminal run after this commit.
    fn finalize_review(&self, id: &str, execution_error: Option<String>) -> Result<(), String> {
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(to_error)?;
        // This UPDATE obtains the SQLite write lock before classifying the
        // cancellation flag. Never read it on an earlier unlocked snapshot.
        let changed = tx
            .execute(
                "UPDATE native_agent_runs
                 SET status=CASE
                   WHEN cancel_requested=1 THEN 'cancelled'
                   WHEN ?2 IS NOT NULL THEN 'failed'
                   ELSE 'completed' END,
                   message=CASE
                     WHEN cancel_requested=1 THEN COALESCE(?2, 'Review cancelled')
                     ELSE ?2 END,
                   finished_at=CURRENT_TIMESTAMP
                 WHERE id=?1 AND status='running'",
                params![id, execution_error],
            )
            .map_err(to_error)?;
        if changed != 1 {
            return Err("Review state changed during finalization".into());
        }
        let mut status: String = tx
            .query_row(
                "SELECT status FROM native_agent_runs WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .map_err(to_error)?;
        if status == "completed" {
            // These readers share the same connection and see the tentative
            // status, but other SQLite connections cannot see it until commit.
            let verdict = crate::native_agent_handoffs::AgentHandoffs::new(self.db).verify(id)?;
            let delegation =
                crate::native_agent_delegation::NativeDelegation::new(self.db).verify(id);
            if !verdict.verified || delegation.is_err() {
                let reason = delegation
                    .err()
                    .unwrap_or_else(|| verdict.issues.join("; "));
                let downgraded = tx
                    .execute(
                        "UPDATE native_agent_runs
                         SET status='failed',message=?2
                         WHERE id=?1 AND status='completed'",
                        params![id, reason],
                    )
                    .map_err(to_error)?;
                if downgraded != 1 {
                    return Err("Evidence verification changed before finalization".into());
                }
                status = "failed".into();
            }
        }
        tx.execute(
            "UPDATE native_agent_steps
             SET status=CASE WHEN ?2='cancelled' THEN 'cancelled' ELSE 'skipped' END,
                 finished_at=CURRENT_TIMESTAMP
             WHERE run_id=?1 AND status IN ('pending','running')",
            params![id, status],
        )
        .map_err(to_error)?;
        if status != "completed" {
            tx.execute(
                "UPDATE native_action_log SET status='interrupted',
                 finished_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND status='running'",
                [id],
            )
            .map_err(to_error)?;
            tx.execute(
                "UPDATE native_delegation_tasks SET status='cancelled'
                 WHERE run_id=?1 AND status IN ('pending','running')",
                [id],
            )
            .map_err(to_error)?;
        }
        tx.commit().map_err(to_error)
    }

    fn run_steps(
        &self,
        run: &AgentRun,
        start: Instant,
        dispatch: Option<&dyn Fn(&Database, &AgentRun, &AgentStep) -> Result<(), String>>,
    ) -> Result<(), String> {
        let assessment_id: String = self
            .db
            .connection()
            .query_row(
                "SELECT assessment_id FROM native_agent_runs WHERE id=?1",
                [&run.id],
                |r| r.get(0),
            )
            .map_err(to_error)?;
        let mut prepared: BTreeMap<usize, Result<String, String>> = BTreeMap::new();
        for step in &run.steps {
            self.boundary(&run.id, start, run.budget_seconds)?;
            if let Some(policy) = dispatch {
                policy(self.db, run, step)?;
                // Cancellation may arrive while the external policy evaluates.
                // Revalidate before entering the native tool.
                self.boundary(&run.id, start, run.budget_seconds)?;
            }
            // Read and verify the exact predecessor evidence before dispatch.
            crate::native_agent_handoffs::AgentHandoffs::new(self.db)
                .check_incoming(&run.id, step.position)?;
            crate::native_action_log::NativeActionLog::new(self.db).begin_supervised(
                &run.id,
                step.position,
                &step.role,
                &step.tool,
            )?;
            let result = if let Some(prefetched) = prepared.remove(&step.position) {
                prefetched
            } else {
                match step.tool.as_str() {
                    "scout" => {
                        let project = WorkspaceService::new(self.db)
                            .get_project(&run.project_id)
                            .map_err(to_error)?
                            .ok_or("Project was removed")?;
                        Ok(serde_json::json!({
                            "project_id":project.id,
                            "indexed_files":project.file_count,
                            "indexed_symbols":project.symbol_count,
                            "language_count":project.language_count,
                        })
                        .to_string())
                    }
                    "source" => AssessmentJobs::new(self.db)
                        .execute(&assessment_id)
                        .and_then(|result| {
                            if result.status != "completed" {
                                Err(format!(
                                    "Source review is {}; {}",
                                    result.status,
                                    result
                                        .message
                                        .unwrap_or_else(|| "check persisted evidence".into())
                                ))
                            } else {
                                serde_json::to_string(&result.steps).map_err(to_error)
                            }
                        }),
                    "secrets" | "qa" | "database" | "runtime" => {
                        run_passive_specialist(self.db, &run.project_id, &step.tool)
                    }
                    _ => Err("Unregistered autonomous tool".into()),
                }
            };
            match result {
                Ok(summary) => {
                    crate::native_action_log::NativeActionLog::new(self.db).finish_supervised(
                        &run.id,
                        step.position,
                        &step.tool,
                        true,
                        &summary,
                    )?;
                }
                Err(error) => {
                    crate::native_action_log::NativeActionLog::new(self.db).finish_supervised(
                        &run.id,
                        step.position,
                        &step.tool,
                        false,
                        &error,
                    )?;
                    return Err(error);
                }
            }
            crate::native_agent_handoffs::AgentHandoffs::new(self.db)
                .record(&run.id, step.position)?;
            if step.tool == "source" {
                if let Some(policy) = dispatch {
                    // Each optional specialist is independently checked by Go
                    // *before* its durable running receipt and tool dispatch.
                    // The supervisor owns every claim, join and evidence write.
                    return self.run_verified_optional_batches(run, start, policy);
                }
                prepared = self.parallel_optional_specialists(run, start)?;
            }
            self.boundary(&run.id, start, run.budget_seconds)?;
        }
        Ok(())
    }

    /// Execute the exact dependency-ready set from the approved SQLite DAG.
    /// Go verifies each specialist in the set while all are still pending;
    /// Rust then commits both running receipts before starting native analyzers.
    /// No tools or unverified roles are accepted from Go. Joined workers finish
    /// before the supervisor commits evidence and admits another batch.
    fn run_verified_optional_batches(
        &self,
        run: &AgentRun,
        start: Instant,
        policy: &dyn Fn(&Database, &AgentRun, &AgentStep) -> Result<(), String>,
    ) -> Result<(), String> {
        let delegation = crate::native_agent_delegation::NativeDelegation::new(self.db);
        let handoffs = crate::native_agent_handoffs::AgentHandoffs::new(self.db);
        let log = crate::native_action_log::NativeActionLog::new(self.db);
        let mut remaining = run.steps.len().saturating_sub(2);
        while remaining != 0 {
            self.boundary(&run.id, start, run.budget_seconds)?;
            let mut ready = delegation.ready_batch(&run.id)?;
            // Handoff evidence is chained in registered role order. Only
            // consecutive independent positions can execute in one batch.
            // Other ready tasks run after the missing predecessor commits.
            if ready.len() == 2 && ready[1].position != ready[0].position + 1 {
                ready.truncate(1);
            }
            if ready.is_empty() || ready.len() > 2 || ready.len() > remaining {
                return Err("No bounded dependency-ready specialist batch".into());
            }
            let mut steps: Vec<&AgentStep> = Vec::with_capacity(ready.len());
            for task in &ready {
                let step = run
                    .steps
                    .iter()
                    .find(|step| step.position == task.position)
                    .ok_or("Ready specialist does not match the approved review")?;
                if !matches!(
                    step.tool.as_str(),
                    "secrets" | "qa" | "database" | "runtime"
                ) || step.role != task.role
                    || step.tool != task.tool
                {
                    return Err("Go-ready batch contained an unregistered specialist".into());
                }
                // Verify the full batch before claiming any running receipts.
                // Policy writes only its bounded decision audit, never tools.
                policy(self.db, run, step)?;
                self.boundary(&run.id, start, run.budget_seconds)?;
                if steps.is_empty() {
                    handoffs.check_incoming(&run.id, step.position)?;
                } else {
                    // The second task was independently ready in the same
                    // persisted DAG and has no dependency on the first task.
                    // Its handoff is signed after the predecessor completes,
                    // before the second result is accepted.
                    let predecessor = steps[0];
                    if step.position != predecessor.position + 1
                        || task.requires.contains(&predecessor.position)
                    {
                        return Err("Parallel specialists have dependent handoffs".into());
                    }
                }
                steps.push(step);
            }
            for step in &steps {
                self.boundary(&run.id, start, run.budget_seconds)?;
                log.begin_supervised(&run.id, step.position, &step.role, &step.tool)?;
            }

            // Claiming the second role can race with cancellation from
            // another SQLite connection; do not start workers if it arrived.
            self.boundary(&run.id, start, run.budget_seconds)?;

            let filename = self
                .db
                .connection()
                .path()
                .filter(|path| *path != ":memory:")
                .map(std::path::PathBuf::from);
            let outcomes: Vec<Result<String, String>> = if steps.len() == 2 {
                if let Some(path) = filename {
                    std::thread::scope(|scope| {
                        let handles = steps
                            .iter()
                            .map(|step| {
                                let path = path.clone();
                                let project = run.project_id.clone();
                                let tool = step.tool.clone();
                                scope.spawn(move || {
                                    Database::open_native_worker(&path)
                                        .map_err(to_error)
                                        .and_then(|db| run_passive_specialist(&db, &project, &tool))
                                })
                            })
                            .collect::<Vec<_>>();
                        handles
                            .into_iter()
                            .map(|handle| {
                                handle.join().unwrap_or_else(|_| {
                                    Err("Concurrent native specialist panicked".into())
                                })
                            })
                            .collect()
                    })
                } else {
                    steps
                        .iter()
                        .map(|step| run_passive_specialist(self.db, &run.project_id, &step.tool))
                        .collect()
                }
            } else {
                steps
                    .iter()
                    .map(|step| run_passive_specialist(self.db, &run.project_id, &step.tool))
                    .collect()
            };
            // Every native thread has joined. Cancellation and deadline checks
            // run before evidence is accepted; parent finalization will close
            // any claimed but unfinished action receipts on failure.
            self.boundary(&run.id, start, run.budget_seconds)?;
            // Accept or reject each joined worker independently; a failing
            // sibling cannot erase successful receipts or authorize a new DAG
            // branch. Failures are retained in the original role order.
            self.finish_verified_batch(run, &steps, outcomes)?;
            remaining -= steps.len();
        }
        Ok(())
    }

    fn finish_verified_batch(
        &self,
        run: &AgentRun,
        steps: &[&AgentStep],
        outcomes: Vec<Result<String, String>>,
    ) -> Result<(), String> {
        if outcomes.len() != steps.len() || steps.is_empty() || steps.len() > 2 {
            return Err("Invalid bounded specialist result count".into());
        }
        let handoffs = crate::native_agent_handoffs::AgentHandoffs::new(self.db);
        let log = crate::native_action_log::NativeActionLog::new(self.db);
        let mut first_failure = None;
        for (step, outcome) in steps.iter().zip(outcomes) {
            let passed = outcome.is_ok();
            let summary = match outcome {
                Ok(summary) => summary,
                Err(reason) => {
                    if first_failure.is_none() {
                        first_failure = Some(reason.clone());
                    }
                    reason
                }
            };
            log.finish_supervised(&run.id, step.position, &step.tool, passed, &summary)?;
            // Never create new downstream handoffs from a failed batch.
            // The successful sibling's evidence remains visible in its own
            // committed receipt, but dependent work cannot be dispatched.
            if passed && first_failure.is_none() {
                handoffs.record(&run.id, step.position)?;
            }
        }
        if let Some(error) = first_failure {
            return Err(error);
        }
        Ok(())
    }

    /// Execute up to two independent approved passive specialists at once.
    /// Database writes and evidence/handoffs are committed by the supervisor in
    /// the original deterministic role order. Memory databases and dependent
    /// optional tasks use the existing sequential path.
    fn parallel_optional_specialists(
        &self,
        run: &AgentRun,
        start: Instant,
    ) -> Result<BTreeMap<usize, Result<String, String>>, String> {
        let Some(filename) = self
            .db
            .connection()
            .path()
            .filter(|path| *path != ":memory:")
        else {
            return Ok(BTreeMap::new());
        };
        let graph =
            crate::native_agent_delegation::NativeDelegation::new(self.db).graph(&run.id)?;
        let optional = graph
            .tasks
            .iter()
            .filter(|task| {
                matches!(
                    task.tool.as_str(),
                    "secrets" | "qa" | "database" | "runtime"
                )
            })
            .collect::<Vec<_>>();
        if optional.len() < 2 {
            return Ok(BTreeMap::new());
        }
        let Some(source) = graph.tasks.iter().find(|task| task.tool == "source") else {
            return Err("Source review dependency was not found".into());
        };
        // A reviewed model may add optional dependencies. Such graphs must never
        // be speculatively executed in parallel.
        if optional
            .iter()
            .any(|task| task.requires != [source.position])
        {
            return Ok(BTreeMap::new());
        }
        let path = std::path::PathBuf::from(filename);
        let mut prepared = BTreeMap::new();
        for batch in optional.chunks(2) {
            self.boundary(&run.id, start, run.budget_seconds)?;
            let outputs = std::thread::scope(|scope| {
                let handles = batch
                    .iter()
                    .map(|task| {
                        let path = path.clone();
                        let project_id = run.project_id.clone();
                        let tool = task.tool.clone();
                        let position = task.position;
                        scope.spawn(move || {
                            let result = Database::open_native_worker(&path)
                                .map_err(to_error)
                                .and_then(|db| run_passive_specialist(&db, &project_id, &tool));
                            (position, result)
                        })
                    })
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle
                            .join()
                            .map_err(|_| "A concurrent specialist panicked".to_string())
                    })
                    .collect::<Vec<_>>()
            });
            for output in outputs {
                let (position, result) = output?;
                prepared.insert(position, result);
            }
            // Cancellation and deadlines are checked before committing any
            // batched evidence; active analyzers are joined, not detached.
            self.boundary(&run.id, start, run.budget_seconds)?;
        }
        Ok(prepared)
    }

    pub fn report(&self, id: &str) -> Result<String, String> {
        let run = self.get(id)?;
        let mut text = format!(
            "# CodeTwin ML Autonomous Review\n\nObjective: {}\n\nProject: {}\n\n\
             Status: {}\n\nStarted: {}\n\nFinished: {}\n\n\
             Note: A completed workflow does not prove a project is secure. Review all analyzer evidence.\n",
            run.objective,run.project_id,run.status,
            run.started_at.as_deref().unwrap_or("Not started"),
            run.finished_at.as_deref().unwrap_or("Not finished"),
        );
        for step in run.steps {
            text.push_str(&format!(
                "\n## {} — {}\n\nStatus: {}\n\n{}\n",
                step.role,
                step.tool,
                step.status,
                step.result.unwrap_or_else(|| "No verified result".into())
            ));
        }
        if let Some(message) = run.message {
            text.push_str(&format!("\n## Unresolved\n\n{message}\n"));
        }
        let verification = crate::native_agent_handoffs::AgentHandoffs::new(self.db).verify(id)?;
        text.push_str(&format!(
            "\n## Specialist Evidence Chain\n\nVerified: {}\n\nChecked specialists: {}\n\nVerified handoffs: {}\n",
            verification.verified, verification.checked_roles, verification.checked_handoffs
        ));
        for issue in verification.issues {
            text.push_str(&format!("\n- {}\n", issue));
        }
        Ok(text)
    }

    /// Mark interrupted tasks explicitly, never silently resume after restart.
    pub fn recover_interrupted(&self) -> Result<(), String> {
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(to_error)?;
        // Retire in-flight receipts before the parent review is made terminal.
        tx.execute(
            "UPDATE native_action_log SET status='interrupted',
             finished_at=CURRENT_TIMESTAMP WHERE status='running'
             AND run_id IN (SELECT id FROM native_agent_runs WHERE status='running')",
            [],
        )
        .map_err(to_error)?;
        // Finish the whole delegation graph before retiring its parent run.
        // A killed process cannot safely resume tasks that might have produced
        // partial results outside this transaction. Never replay on startup.
        tx.execute(
            "UPDATE native_delegation_tasks SET status='cancelled'
             WHERE status IN ('pending','running') AND run_id IN
             (SELECT id FROM native_agent_runs WHERE status='running')",
            [],
        )
        .map_err(to_error)?;
        tx.execute(
            "UPDATE native_agent_steps SET status='interrupted',finished_at=CURRENT_TIMESTAMP
             WHERE status='running' AND run_id IN
             (SELECT id FROM native_agent_runs WHERE status='running')",
            [],
        )
        .map_err(to_error)?;
        tx.execute(
            "UPDATE native_agent_steps SET status='cancelled',finished_at=CURRENT_TIMESTAMP
             WHERE status='pending' AND run_id IN
             (SELECT id FROM native_agent_runs WHERE status='running')",
            [],
        )
        .map_err(to_error)?;
        tx.execute(
            "UPDATE native_agent_runs SET status='interrupted',cancel_requested=1,
             finished_at=CURRENT_TIMESTAMP,
             message='Application closed during review; create a fresh plan'
             WHERE status='running'",
            [],
        )
        .map_err(to_error)?;
        tx.commit().map_err(to_error)
    }
}

/// Registered, passive project analyzers only. This function is also called
/// from worker threads with independently opened SQLite connections.
fn run_passive_specialist(db: &Database, project_id: &str, tool: &str) -> Result<String, String> {
    match tool {
        "secrets" => SecretScanningService::new(db)
            .scan_project(project_id)
            .map(|value| format!("{value:?}"))
            .map_err(to_error),
        "qa" => QaDiscoveryService::new(db)
            .discover_project(project_id)
            .map(|value| format!("{value:?}"))
            .map_err(to_error),
        "database" => DatabaseAnalysisService::new(db)
            .analyze_project(project_id)
            .map(|value| format!("{value:?}"))
            .map_err(to_error),
        "runtime" => RuntimeReliabilityService::new(db)
            .analyze_project(project_id)
            .map(|value| format!("{value:?}"))
            .map_err(to_error),
        _ => Err("Parallel dispatch rejected an unregistered tool".into()),
    }
}

fn to_error(err: impl std::fmt::Display) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_backed_restart_preserves_go_audit_and_retires_unfinished_roles() {
        let workspace = tempfile::tempdir().unwrap();
        let database_path = workspace.path().join("durable-review.sqlite3");
        let source_path = workspace.path().join("source");
        std::fs::create_dir_all(&source_path).unwrap();
        std::fs::write(source_path.join("safe.ts"), "export const safe = true;").unwrap();

        let run_id = {
            let db = Database::open(&database_path).unwrap();
            let project = crate::ProjectIndexService::new(&db)
                .index_project(&source_path)
                .unwrap()
                .project_id;
            let reviews = NativeAgents::new(&db);
            let run = reviews
                .create_with_roles(
                    &project,
                    "Authorized read-only review",
                    10,
                    120,
                    &["scout".into(), "source".into(), "qa".into()],
                )
                .unwrap();
            reviews.approve(&run.id).unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_steps SET status='completed',
                     result_json='{\"scope\":\"verified\"}' WHERE run_id=?1 AND position=0",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_delegation_tasks SET status='completed'
                     WHERE run_id=?1 AND position=0",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_steps SET status='running'
                     WHERE run_id=?1 AND position=1",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_delegation_tasks SET status='running'
                     WHERE run_id=?1 AND position=1",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "INSERT INTO go_dispatch_audit
                     (run_id,position,role,verdict,ready_json,reason)
                     VALUES (?1,0,'scout','allowed','[\"scout\"]','approved')",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "INSERT INTO native_action_log(run_id,position,role,status)
                     VALUES (?1,1,'source','running')",
                    [&run.id],
                )
                .unwrap();
            run.id
        };

        // The original database handle is gone, as after an application exit.
        {
            let db = Database::open(&database_path).unwrap();
            let reviews = NativeAgents::new(&db);
            reviews.recover_interrupted().unwrap();
            let run = reviews.get(&run_id).unwrap();
            assert_eq!(run.status, "interrupted");
            assert_eq!(
                run.steps[0].result.as_deref(),
                Some("{\"scope\":\"verified\"}")
            );
            assert_eq!(run.steps[0].status, "completed");
            assert_eq!(run.steps[1].status, "interrupted");
            assert_eq!(run.steps[2].status, "cancelled");
            let receipts = crate::native_action_log::NativeActionLog::new(&db)
                .list(&run_id)
                .unwrap();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].role, "source");
            assert_eq!(receipts[0].status, "interrupted");
            assert!(receipts[0].finished_at.is_some());
            let tasks = crate::native_agent_delegation::NativeDelegation::new(&db)
                .graph(&run_id)
                .unwrap();
            assert_eq!(tasks.tasks[0].status, "completed");
            assert!(tasks.tasks[1..]
                .iter()
                .all(|task| task.status == "cancelled"));
            let saved: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM go_dispatch_audit WHERE run_id=?1",
                    [&run_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(saved, 1);
            assert!(reviews.execute(&run_id).is_err());
        }

        // A second restart must not replay, reset or mutate terminal evidence.
        let db = Database::open(&database_path).unwrap();
        let reviews = NativeAgents::new(&db);
        reviews.recover_interrupted().unwrap();
        let persisted = reviews.get(&run_id).unwrap();
        assert_eq!(persisted.status, "interrupted");
        assert_eq!(
            persisted.steps[0].result.as_deref(),
            Some("{\"scope\":\"verified\"}")
        );
        let incomplete: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM native_delegation_tasks
                 WHERE run_id=?1 AND status IN ('pending','running')",
                [&run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(incomplete, 0);
    }

    #[test]
    fn crash_recovery_retires_unfinished_sqlite_delegation_without_reexecution() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("source.rs"), "pub fn safe() {}").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agent = NativeAgents::new(&db);
        let run = agent
            .create_with_roles(
                &project,
                "Review approved local source",
                10,
                120,
                &["scout".into(), "source".into(), "qa".into()],
            )
            .unwrap();
        agent.approve(&run.id).unwrap();

        // Simulate a crash after the first specialist completed and the
        // next specialist started; the final specialist was still queued.
        db.connection()
            .execute(
                "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                [&run.id],
            )
            .unwrap();
        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='completed',
                 result_json='{\"check\":\"preserved\"}'
                 WHERE run_id=?1 AND position=0",
                [&run.id],
            )
            .unwrap();
        db.connection()
            .execute(
                "UPDATE native_delegation_tasks SET status='completed' WHERE run_id=?1 AND position=0",
                [&run.id],
            )
            .unwrap();
        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='running' WHERE run_id=?1 AND position=1",
                [&run.id],
            )
            .unwrap();
        db.connection()
            .execute(
                "UPDATE native_delegation_tasks SET status='running' WHERE run_id=?1 AND position=1",
                [&run.id],
            )
            .unwrap();

        db.connection()
            .execute(
                "INSERT INTO go_dispatch_audit
                 (run_id,position,role,verdict,ready_json,reason)
                 VALUES (?1,0,'scout','allowed','[\"scout\"]','approved role was ready')",
                [&run.id],
            )
            .unwrap();

        agent.recover_interrupted().unwrap();
        let recovered = agent.get(&run.id).unwrap();
        assert_eq!(recovered.status, "interrupted");
        assert_eq!(recovered.steps.len(), 3);
        assert_eq!(recovered.steps[0].status, "completed");
        assert_eq!(
            recovered.steps[0].result.as_deref(),
            Some("{\"check\":\"preserved\"}")
        );
        assert_eq!(recovered.steps[1].status, "interrupted");
        assert_eq!(recovered.steps[2].status, "cancelled");
        let delegated = crate::native_agent_delegation::NativeDelegation::new(&db)
            .graph(&run.id)
            .unwrap();
        assert_eq!(delegated.tasks[0].status, "completed");
        assert_eq!(delegated.tasks[1].status, "cancelled");
        assert_eq!(delegated.tasks[2].status, "cancelled");
        let cancelled: bool = db
            .connection()
            .query_row(
                "SELECT cancel_requested FROM native_agent_runs WHERE id=?1",
                [&run.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(cancelled);
        let retained_audits: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM go_dispatch_audit WHERE run_id=?1",
                [&run.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_audits, 1);
        assert!(agent.execute(&run.id).is_err());
        agent.recover_interrupted().unwrap();
        assert_eq!(agent.get(&run.id).unwrap().status, "interrupted");
        assert!(agent
            .create_with_roles(
                &project,
                "Fresh review after restart",
                10,
                120,
                &["scout".into(), "source".into()],
            )
            .is_ok());
    }

    #[test]
    fn requires_indexed_project_and_explicit_approval() {
        let db = Database::open_in_memory().unwrap();
        let agent = NativeAgents::new(&db);
        assert!(agent.create("missing", "Review", 10, 60).is_err());
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sample.ts"), "export const safe = true;").unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        assert!(agent.create(&project_id, " ", 10, 60).is_err());
        let run = agent
            .create(&project_id, "Review security posture", 10, 60)
            .unwrap();
        assert_eq!(run.steps.len(), 6);
        assert!(agent.execute(&run.id).is_err());
        let approved = agent.approve(&run.id).unwrap();
        assert_eq!(approved.status, "approved");
        assert!(agent.create(&project_id, "Duplicate", 10, 60).is_err());
        let cancelled = agent.cancel(&run.id).unwrap();
        assert_eq!(cancelled.status, "cancelled");
        assert!(agent.execute(&run.id).is_err());
    }

    #[test]
    fn external_dispatch_cannot_bypass_approval_or_execute_unapproved_tools() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sample.ts"), "export const safe = true;").unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        let run = agents
            .create_with_roles(
                &project_id,
                "Review source",
                10,
                300,
                &["scout".to_string(), "source".to_string()],
            )
            .unwrap();
        let called = std::cell::Cell::new(0);
        let deny = |_database: &Database, _run: &AgentRun, _step: &AgentStep| {
            called.set(called.get() + 1);
            Err("Go scheduling denied an unverified role".to_string())
        };
        assert!(agents.execute_with_dispatch(&run.id, &deny).is_err());
        assert_eq!(called.get(), 0);
        agents.approve(&run.id).unwrap();
        let finished = agents.execute_with_dispatch(&run.id, &deny).unwrap();
        assert_eq!(finished.status, "failed");
        assert_eq!(called.get(), 1);
        assert!(finished.steps.iter().all(|step| step.status == "skipped"));
        let graph = crate::native_agent_delegation::NativeDelegation::new(&db)
            .graph(&run.id)
            .unwrap();
        assert!(graph.tasks.iter().all(|task| task.status == "cancelled"));
        assert!(agents.execute_with_dispatch(&run.id, &deny).is_err());
        assert_eq!(called.get(), 1);
    }

    #[test]
    fn finalization_honors_cross_connection_cancel_and_closes_receipts() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("cancel-before-finalize.sqlite3");
        let root = scratch.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("safe.ts"), "export const a = true;").unwrap();
        let id = {
            let db = Database::open(&path).unwrap();
            let project = crate::ProjectIndexService::new(&db)
                .index_project(&root)
                .unwrap()
                .project_id;
            let reviews = NativeAgents::new(&db);
            let run = reviews
                .create_with_roles(
                    &project,
                    "Reviewed scope",
                    10,
                    120,
                    &["scout".into(), "source".into()],
                )
                .unwrap();
            reviews.approve(&run.id).unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                    [&run.id],
                )
                .unwrap();
            crate::native_action_log::NativeActionLog::new(&db)
                .begin_supervised(&run.id, 0, &run.steps[0].role, "scout")
                .unwrap();
            let other = Database::open(&path).unwrap();
            NativeAgents::new(&other).cancel(&run.id).unwrap();
            // No execution error: a stale supervisor would previously have
            // recorded a completed review despite the independent cancellation.
            reviews.finalize_review(&run.id, None).unwrap();
            let updated = reviews.get(&run.id).unwrap();
            assert_eq!(updated.status, "cancelled");
            assert_eq!(updated.steps[0].status, "cancelled");
            assert_eq!(updated.steps[1].status, "cancelled");
            assert_eq!(
                crate::native_action_log::NativeActionLog::new(&db)
                    .list(&run.id)
                    .unwrap()[0]
                    .status,
                "interrupted"
            );
            let graph = crate::native_agent_delegation::NativeDelegation::new(&db)
                .graph(&run.id)
                .unwrap();
            assert!(graph.tasks.iter().all(|task| task.status == "cancelled"));
            assert!(reviews.execute(&run.id).is_err());
            run.id
        };
        let db = Database::open(&path).unwrap();
        let saved = NativeAgents::new(&db).get(&id).unwrap();
        assert_eq!(saved.status, "cancelled");
        assert!(saved.steps.iter().all(|step| step.status == "cancelled"));
    }

    #[test]
    fn invalid_evidence_never_commits_an_observable_completed_review() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("invalid-final-evidence.sqlite3");
        let root = scratch.path().join("project");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("safe.ts"), "export const a = true;").unwrap();
        let id = {
            let db = Database::open(&path).unwrap();
            let project = crate::ProjectIndexService::new(&db)
                .index_project(&root)
                .unwrap()
                .project_id;
            let reviews = NativeAgents::new(&db);
            let run = reviews
                .create_with_roles(
                    &project,
                    "Verify evidence before publishing",
                    10,
                    120,
                    &["scout".into(), "source".into()],
                )
                .unwrap();
            reviews.approve(&run.id).unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_steps SET status='completed',
                     result_json='persisted fixture evidence'
                     WHERE run_id=?1",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_delegation_tasks SET status='completed'
                     WHERE run_id=?1",
                    [&run.id],
                )
                .unwrap();
            // Omit the signed scout-to-source handoff. Step/delegation status
            // alone cannot authorize the parent to become completed.
            reviews.finalize_review(&run.id, None).unwrap();
            let saved = reviews.get(&run.id).unwrap();
            assert_eq!(saved.status, "failed");
            assert!(saved
                .message
                .as_ref()
                .is_some_and(|message| !message.is_empty()));
            assert!(saved.steps.iter().all(|step| step.status == "completed"));
            assert!(reviews.execute(&run.id).is_err());
            run.id
        };
        let db = Database::open(&path).unwrap();
        assert_eq!(NativeAgents::new(&db).get(&id).unwrap().status, "failed");
    }

    #[test]
    fn file_backed_go_verified_pair_finishes_with_signed_handoffs() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("go-batch.sqlite3");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("safe.ts"), "export const safe = true;").unwrap();
        let id = {
            let db = Database::open(&path).unwrap();
            let project = crate::ProjectIndexService::new(&db)
                .index_project(&source)
                .unwrap()
                .project_id;
            let run = NativeAgents::new(&db)
                .create_with_roles(
                    &project,
                    "Approved passive team review",
                    10,
                    300,
                    &[
                        "scout".into(),
                        "source".into(),
                        "secrets".into(),
                        "qa".into(),
                    ],
                )
                .unwrap();
            NativeAgents::new(&db).approve(&run.id).unwrap();
            let decisions = std::cell::RefCell::new(Vec::new());
            let allow = |db: &Database, run: &AgentRun, step: &AgentStep| {
                let ready = crate::native_agent_delegation::NativeDelegation::new(db)
                    .ready_batch(&run.id)?;
                if !ready.iter().any(|task| task.tool == step.tool) {
                    return Err("Go refused dependency-unready specialist".into());
                }
                decisions.borrow_mut().push(step.tool.clone());
                Ok(())
            };
            let result = NativeAgents::new(&db)
                .execute_with_dispatch(&run.id, &allow)
                .unwrap();
            assert_eq!(
                result.status,
                "completed",
                "Go-verified pair did not complete: message={:?}; steps={:?}; actions={:?}; delegation={:?}",
                result.message,
                result.steps,
                crate::native_action_log::NativeActionLog::new(&db)
                    .list(&run.id)
                    .unwrap(),
                crate::native_agent_delegation::NativeDelegation::new(&db)
                    .graph(&run.id)
                    .unwrap()
                    .tasks,
            );
            assert_eq!(
                decisions.into_inner(),
                vec!["scout", "source", "secrets", "qa"]
            );
            assert!(
                crate::native_agent_handoffs::AgentHandoffs::new(&db)
                    .verify(&run.id)
                    .unwrap()
                    .verified
            );
            let receipts = crate::native_action_log::NativeActionLog::new(&db)
                .list(&run.id)
                .unwrap();
            assert_eq!(receipts.len(), 4);
            assert!(receipts.iter().all(|item| item.status == "completed"));
            run.id
        };
        let db = Database::open(&path).unwrap();
        let saved = NativeAgents::new(&db).get(&id).unwrap();
        assert_eq!(saved.status, "completed");
        assert_eq!(saved.steps.len(), 4);
        assert!(saved.steps.iter().all(|step| step.status == "completed"));
        assert!(
            crate::native_agent_handoffs::AgentHandoffs::new(&db)
                .verify(&id)
                .unwrap()
                .verified
        );
    }

    #[test]
    fn joined_specialists_preserve_successful_sibling_evidence_on_failure() {
        for failure_position in [2, 3] {
            let fixture = tempfile::tempdir().unwrap();
            let db = Database::open(fixture.path().join("joined-failure.sqlite3")).unwrap();
            let source = fixture.path().join("source");
            std::fs::create_dir_all(&source).unwrap();
            std::fs::write(source.join("file.ts"), "export const safe = true;").unwrap();
            let project = crate::ProjectIndexService::new(&db)
                .index_project(&source)
                .unwrap()
                .project_id;
            let agents = NativeAgents::new(&db);
            let review = agents
                .create_with_roles(
                    &project,
                    "Independent joined specialist outcomes",
                    10,
                    120,
                    &[
                        "scout".into(),
                        "source".into(),
                        "secrets".into(),
                        "qa".into(),
                    ],
                )
                .unwrap();
            agents.approve(&review.id).unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                    [&review.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_steps SET status='completed',
                     result_json='previous reviewed evidence'
                     WHERE run_id=?1 AND position IN (0,1)",
                    [&review.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_delegation_tasks SET status='completed'
                     WHERE run_id=?1 AND position IN (0,1)",
                    [&review.id],
                )
                .unwrap();

            let delegation = crate::native_agent_delegation::NativeDelegation::new(&db);
            let log = crate::native_action_log::NativeActionLog::new(&db);
            for step in &review.steps[2..] {
                delegation
                    .start(&review.id, step.position, &step.role)
                    .unwrap();
                log.begin(&review.id, step.position, &step.tool).unwrap();
            }
            let outcomes = review.steps[2..]
                .iter()
                .map(|step| {
                    if step.position == failure_position {
                        Err("Injected isolated specialist failure".to_string())
                    } else {
                        Ok("Verified independent specialist evidence".to_string())
                    }
                })
                .collect();
            let error = agents
                .finish_verified_batch(&review, &[&review.steps[2], &review.steps[3]], outcomes)
                .unwrap_err();
            assert_eq!(error, "Injected isolated specialist failure");
            let current = agents.get(&review.id).unwrap();
            assert_eq!(current.steps[failure_position].status, "failed");
            assert_eq!(current.steps[5 - failure_position].status, "completed");
            let receipts = log.list(&review.id).unwrap();
            assert_eq!(receipts.len(), 2);
            assert_eq!(
                receipts
                    .iter()
                    .filter(|receipt| receipt.status == "failed")
                    .count(),
                1
            );
            assert_eq!(
                receipts
                    .iter()
                    .filter(|receipt| receipt.status == "completed")
                    .count(),
                1
            );
            assert!(receipts.iter().all(|receipt| {
                receipt
                    .result_sha256
                    .as_ref()
                    .is_some_and(|digest| digest.len() == 64)
            }));
            assert!(delegation.ready_batch(&review.id).unwrap().is_empty());
            let handoffs = crate::native_agent_handoffs::AgentHandoffs::new(&db)
                .list(&review.id)
                .unwrap();
            assert_eq!(handoffs.len(), if failure_position == 2 { 0 } else { 1 });
            agents.cancel(&review.id).unwrap();
            agents.recover_interrupted().unwrap();
            let retired = agents.get(&review.id).unwrap();
            assert_eq!(retired.status, "interrupted");
            assert_eq!(retired.steps[failure_position].status, "failed");
            assert_eq!(retired.steps[5 - failure_position].status, "completed");
            assert!(agents.execute(&review.id).is_err());
        }
    }

    #[test]
    fn go_denial_of_second_ready_specialist_starts_neither_optional_tool() {
        let temp = tempfile::tempdir().unwrap();
        let db = Database::open(temp.path().join("denied-pair.sqlite3")).unwrap();
        let project_root = temp.path().join("source");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::write(project_root.join("safe.ts"), "export const value = 1;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(&project_root)
            .unwrap()
            .project_id;
        let run = NativeAgents::new(&db)
            .create_with_roles(
                &project,
                "Deny unverified parallel reviewer",
                10,
                300,
                &[
                    "scout".into(),
                    "source".into(),
                    "secrets".into(),
                    "qa".into(),
                ],
            )
            .unwrap();
        NativeAgents::new(&db).approve(&run.id).unwrap();
        let policy = |_: &Database, _: &AgentRun, step: &AgentStep| {
            if step.tool == "qa" {
                Err("Go denied a parallel specialist".to_string())
            } else {
                Ok(())
            }
        };
        let result = NativeAgents::new(&db)
            .execute_with_dispatch(&run.id, &policy)
            .unwrap();
        assert_eq!(result.status, "failed");
        assert!(result.steps[2..]
            .iter()
            .all(|step| step.status == "skipped"));
        let receipts = crate::native_action_log::NativeActionLog::new(&db)
            .list(&run.id)
            .unwrap();
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|item| item.status == "completed"));
        assert!(NativeAgents::new(&db).execute(&run.id).is_err());
    }

    #[test]
    fn planned_cancellation_closes_queued_sqlite_specialists() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let run = reviews
            .create_with_roles(
                &project,
                "Review scope",
                10,
                120,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        let cancelled = reviews.cancel(&run.id).unwrap();
        assert_eq!(cancelled.status, "cancelled");
        assert!(cancelled
            .steps
            .iter()
            .all(|step| step.status == "cancelled"));
        let graph = crate::native_agent_delegation::NativeDelegation::new(&db)
            .graph(&run.id)
            .unwrap();
        assert!(graph.tasks.iter().all(|task| task.status == "cancelled"));
        assert!(reviews.execute(&run.id).is_err());
        assert!(reviews.cancel(&run.id).is_err());
    }

    #[test]
    fn cancelling_during_go_policy_cannot_enter_native_tool() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let run = reviews
            .create_with_roles(
                &project,
                "Review approved source",
                10,
                120,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        reviews.approve(&run.id).unwrap();
        let policy = |database: &Database, run: &AgentRun, _step: &AgentStep| {
            NativeAgents::new(database).cancel(&run.id)?;
            Ok(())
        };
        let result = reviews.execute_with_dispatch(&run.id, &policy).unwrap();
        assert_eq!(result.status, "cancelled");
        assert!(result.steps.iter().all(|step| step.status == "cancelled"));
        let graph = crate::native_agent_delegation::NativeDelegation::new(&db)
            .graph(&run.id)
            .unwrap();
        assert!(graph.tasks.iter().all(|task| task.status == "cancelled"));
    }

    #[test]
    fn approved_source_review_persists_evidence_and_project_memory() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sample.ts"), "export const safe = true;").unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        let roles = vec!["scout".to_string(), "source".to_string()];
        let run = agents
            .create_with_roles(&project_id, "Review source security", 10, 300, &roles)
            .unwrap();
        agents.approve(&run.id).unwrap();
        let result = agents.execute(&run.id).unwrap();
        assert_eq!(result.status, "completed", "{:?}", result.message);
        assert_eq!(result.steps.len(), 2);
        assert!(result.steps.iter().all(|step| step.status == "completed"));
        let memories = crate::native_agent_memory::AgentMemory::new(&db)
            .search(&project_id, "", 50)
            .unwrap();
        assert_eq!(memories.len(), 2);
        let verified = crate::native_agent_handoffs::AgentHandoffs::new(&db)
            .verify(&run.id)
            .unwrap();
        assert!(verified.verified, "{:?}", verified.issues);
        assert_eq!(verified.checked_handoffs, 1);
        assert!(agents
            .report(&run.id)
            .unwrap()
            .contains("Specialist Evidence Chain"));
    }

    #[test]
    fn file_backed_review_runs_independent_specialists_and_verifies_evidence() {
        let fixture = tempfile::tempdir().unwrap();
        let database = Database::open(fixture.path().join("reviews.sqlite3")).unwrap();
        let project_root = fixture.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        std::fs::write(project_root.join("sample.ts"), "export const safe = true;").unwrap();
        let project_id = crate::ProjectIndexService::new(&database)
            .index_project(&project_root)
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&database);
        let roles = ["scout", "source", "secrets", "qa"]
            .iter()
            .map(|role| (*role).to_string())
            .collect::<Vec<_>>();
        let review = agents
            .create_with_roles(
                &project_id,
                "Assess passive security and tests",
                10,
                300,
                &roles,
            )
            .unwrap();
        agents.approve(&review.id).unwrap();
        let result = agents.execute(&review.id).unwrap();
        assert_eq!(result.status, "completed", "{:?}", result.message);
        assert_eq!(result.steps.len(), 4);
        assert!(result.steps.iter().all(|step| step.status == "completed"));
        let receipts = crate::native_action_log::NativeActionLog::new(&database)
            .list(&review.id)
            .unwrap();
        assert_eq!(receipts.len(), 4);
        assert!(receipts.iter().all(|receipt| receipt.status == "completed"));
        assert!(receipts.iter().all(|receipt| {
            receipt
                .result_sha256
                .as_ref()
                .is_some_and(|hash| hash.len() == 64)
        }));
        let verification = crate::native_agent_handoffs::AgentHandoffs::new(&database)
            .verify(&review.id)
            .unwrap();
        assert!(verification.verified, "{:?}", verification.issues);
        assert_eq!(verification.checked_handoffs, 3);
        assert!(
            crate::native_agent_delegation::NativeDelegation::new(&database)
                .verify(&review.id)
                .is_ok()
        );
    }

    #[test]
    fn role_selection_rejects_unknown_duplicate_or_missing_required_roles() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sample.ts"), "export const a = 1;").unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        for bad in [
            vec!["scout".to_string(), "qa".to_string()],
            vec![
                "scout".to_string(),
                "source".to_string(),
                "unknown".to_string(),
            ],
            vec![
                "scout".to_string(),
                "source".to_string(),
                "source".to_string(),
            ],
        ] {
            assert!(agents
                .create_with_roles(&project_id, "Review", 10, 60, &bad)
                .is_err());
        }
        let roles = vec![
            "scout".to_string(),
            "source".to_string(),
            "secrets".to_string(),
        ];
        let review = agents
            .create_with_roles(&project_id, "Review", 10, 60, &roles)
            .unwrap();
        assert_eq!(
            review
                .steps
                .iter()
                .map(|step| step.tool.as_str())
                .collect::<Vec<_>>(),
            vec!["scout", "source", "secrets"]
        );
    }
}
