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
        let changed = self.db.connection().execute(
            "UPDATE native_agent_runs SET cancel_requested=1,
             status=CASE WHEN status IN ('planned','approved') THEN 'cancelled' ELSE status END,
             finished_at=CASE WHEN status IN ('planned','approved') THEN CURRENT_TIMESTAMP ELSE finished_at END
             WHERE id=?1 AND status IN ('planned','approved','running')",
            [id],
        ).map_err(to_error)?;
        if changed != 1 {
            return Err("Review is already finished or missing".into());
        }
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
        let claimed = self
            .db
            .connection()
            .execute(
                "UPDATE native_agent_runs SET status='running',started_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='approved' AND cancel_requested=0",
                [id],
            )
            .map_err(to_error)?;
        if claimed != 1 {
            return Err("Review state changed before execution".into());
        }
        let start = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.run_steps(&run, start, dispatch)))
            .unwrap_or_else(|_| Err("Review encountered a worker panic".into()));
        let message = result.err();
        let cancelled: bool = self
            .db
            .connection()
            .query_row(
                "SELECT cancel_requested FROM native_agent_runs WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .map_err(to_error)?;
        let status = if cancelled {
            "cancelled"
        } else if message.is_some() {
            "failed"
        } else {
            "completed"
        };
        self.db
            .connection()
            .execute(
                "UPDATE native_agent_runs SET status=?2,message=?3,finished_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='running'",
                params![id, status, message],
            )
            .map_err(to_error)?;
        self.db.connection().execute(
            "UPDATE native_agent_steps SET status=CASE WHEN ?2='cancelled' THEN 'cancelled' ELSE 'skipped' END
             WHERE run_id=?1 AND status IN ('pending','running')",
            params![id,status],
        ).map_err(to_error)?;
        // A completed run is only accepted after checking the whole handoff chain.
        if status == "completed" {
            let verdict = crate::native_agent_handoffs::AgentHandoffs::new(self.db).verify(id)?;
            let delegation =
                crate::native_agent_delegation::NativeDelegation::new(self.db).verify(id);
            if !verdict.verified || delegation.is_err() {
                let reason = delegation
                    .err()
                    .unwrap_or_else(|| verdict.issues.join("; "));
                self.db.connection().execute(
                    "UPDATE native_agent_runs SET status='failed',message=?2 WHERE id=?1 AND status='completed'",
                    params![id, reason],
                ).map_err(to_error)?;
            }
        }
        // Remember only non-sensitive role status and source-run provenance.
        crate::native_agent_memory::AgentMemory::new(self.db).record_run(id)?;
        crate::native_agent_knowledge::AgentKnowledge::new(self.db).ingest(id)?;
        self.get(id)
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
            }
            // Read and verify the exact predecessor evidence before dispatch.
            crate::native_agent_handoffs::AgentHandoffs::new(self.db)
                .check_incoming(&run.id, step.position)?;
            crate::native_agent_delegation::NativeDelegation::new(self.db).start(
                &run.id,
                step.position,
                &step.role,
            )?;
            self.db
                .connection()
                .execute(
                    "UPDATE native_agent_steps SET status='running',started_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND position=?2 AND status='pending'",
                    params![run.id, step.position],
                )
                .map_err(to_error)?;
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
                    crate::native_agent_delegation::NativeDelegation::new(self.db).finish(
                        &run.id,
                        step.position,
                        true,
                    )?;
                    self.db.connection().execute(
                        "UPDATE native_agent_steps SET status='completed',result_json=?3,finished_at=CURRENT_TIMESTAMP
                         WHERE run_id=?1 AND position=?2",
                        params![run.id,step.position,summary],
                    ).map_err(to_error)?;
                }
                Err(error) => {
                    crate::native_agent_delegation::NativeDelegation::new(self.db).finish(
                        &run.id,
                        step.position,
                        false,
                    )?;
                    self.db.connection().execute(
                        "UPDATE native_agent_steps SET status='failed',result_json=?3,finished_at=CURRENT_TIMESTAMP
                         WHERE run_id=?1 AND position=?2",
                        params![run.id,step.position,error],
                    ).map_err(to_error)?;
                    return Err(error);
                }
            }
            crate::native_agent_handoffs::AgentHandoffs::new(self.db)
                .record(&run.id, step.position)?;
            if step.tool == "source" && dispatch.is_none() {
                prepared = self.parallel_optional_specialists(run, start)?;
            }
            self.boundary(&run.id, start, run.budget_seconds)?;
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
                            let result = Database::open(&path)
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
        assert!(finished.steps.iter().all(|step| step.status != "completed"));
        assert!(agents.execute_with_dispatch(&run.id, &deny).is_err());
        assert_eq!(called.get(), 1);
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
