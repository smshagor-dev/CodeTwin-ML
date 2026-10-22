//! Native, durable, least-privilege autonomous review workflow.
//! The role planner operates only on existing passive CodeTwin analyzers.
//! It does not execute external commands, generate exploits or bypass user approvals.
use crate::{
    assessment_jobs::{AssessmentJobs, AssessmentPlanRequest}, Database, DatabaseAnalysisService, QaDiscoveryService,
    RuntimeReliabilityService, SecretScanningService, WorkspaceService,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
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
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).map_err(to_error)?.as_nanos();
        let id = crate::deterministic_id("native-agents", &[project_id, &assessment.id, &nonce.to_string()]);
        let tx = self.db.connection().unchecked_transaction().map_err(to_error)?;
        tx.execute(
            "INSERT INTO native_agent_runs (id,project_id,objective,max_files,budget_seconds,assessment_id)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![id,project_id,objective.trim(),max_files,budget_seconds,assessment.id],
        ).map_err(to_error)?;
        for (position, (tool, role)) in STEP_TOOLS.iter().enumerate() {
            tx.execute(
                "INSERT INTO native_agent_steps(run_id,position,role,tool) VALUES(?1,?2,?3,?4)",
                params![id,position,role,tool],
            ).map_err(to_error)?;
        }
        tx.commit().map_err(to_error)?;
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
        let mut query = self.db.connection().prepare(
            "SELECT position,role,tool,status,result_json FROM native_agent_steps
             WHERE run_id=?1 ORDER BY position"
        ).map_err(to_error)?;
        run.steps = query.query_map([id], |r| Ok(AgentStep {
            position:r.get(0)?,role:r.get(1)?,tool:r.get(2)?,
            status:r.get(3)?,result:r.get(4)?,
        })).map_err(to_error)?
            .collect::<Result<Vec<_>, _>>().map_err(to_error)?;
        Ok(run)
    }

    pub fn list(&self, project_id: &str) -> Result<Vec<AgentRun>, String> {
        let mut statement = self.db.connection().prepare(
            "SELECT id FROM native_agent_runs WHERE project_id=?1 ORDER BY rowid DESC LIMIT 30"
        ).map_err(to_error)?;
        let ids = statement.query_map([project_id], |r| r.get::<_, String>(0))
            .map_err(to_error)?.collect::<Result<Vec<_>, _>>().map_err(to_error)?;
        ids.iter().map(|id| self.get(id)).collect()
    }

    pub fn approve(&self, id: &str) -> Result<AgentRun, String> {
        let changed = self.db.connection().execute(
            "UPDATE native_agent_runs SET status='approved' WHERE id=?1 AND status='planned'",
            [id],
        ).map_err(to_error)?;
        if changed != 1 {
            return Err("Only a fresh planned review can be approved".into());
        }
        self.get(id)
    }

    pub fn cancel(&self, id: &str) -> Result<AgentRun, String> {
        let assessment_id: String = self.db.connection().query_row(
            "SELECT assessment_id FROM native_agent_runs WHERE id=?1",
            [id], |r| r.get(0),
        ).map_err(to_error)?;
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
        let cancelled: bool = self.db.connection().query_row(
            "SELECT cancel_requested FROM native_agent_runs WHERE id=?1",
            [id], |r| r.get(0),
        ).map_err(to_error)?;
        if cancelled {
            return Err("Cancelled at analyzer boundary".into());
        }
        if start.elapsed().as_secs() >= budget {
            return Err("Time budget expired at analyzer boundary".into());
        }
        Ok(())
    }

    pub fn execute(&self, id: &str) -> Result<AgentRun, String> {
        let run = self.get(id)?;
        if run.status != "approved" {
            return Err("Approve this review before running it".into());
        }
        let claimed = self.db.connection().execute(
            "UPDATE native_agent_runs SET status='running',started_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='approved' AND cancel_requested=0",
            [id],
        ).map_err(to_error)?;
        if claimed != 1 {
            return Err("Review state changed before execution".into());
        }
        let start = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.run_steps(&run, start)))
            .unwrap_or_else(|_| Err("Review encountered a worker panic".into()));
        let message = result.err();
        let cancelled: bool = self.db.connection().query_row(
            "SELECT cancel_requested FROM native_agent_runs WHERE id=?1",
            [id], |r| r.get(0),
        ).map_err(to_error)?;
        let status = if cancelled {"cancelled"} else if message.is_some() {"failed"} else {"completed"};
        self.db.connection().execute(
            "UPDATE native_agent_runs SET status=?2,message=?3,finished_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='running'",
            params![id,status,message],
        ).map_err(to_error)?;
        self.db.connection().execute(
            "UPDATE native_agent_steps SET status=CASE WHEN ?2='cancelled' THEN 'cancelled' ELSE 'skipped' END
             WHERE run_id=?1 AND status IN ('pending','running')",
            params![id,status],
        ).map_err(to_error)?;
        self.get(id)
    }

    fn run_steps(&self, run: &AgentRun, start: Instant) -> Result<(), String> {
        let assessment_id: String = self.db.connection().query_row(
            "SELECT assessment_id FROM native_agent_runs WHERE id=?1",
            [&run.id], |r| r.get(0),
        ).map_err(to_error)?;
        for step in &run.steps {
            self.boundary(&run.id, start, run.budget_seconds)?;
            self.db.connection().execute(
                "UPDATE native_agent_steps SET status='running',started_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND position=?2 AND status='pending'",
                params![run.id,step.position],
            ).map_err(to_error)?;
            let result = match step.tool.as_str() {
                "scout" => {
                    let project = WorkspaceService::new(self.db).get_project(&run.project_id)
                        .map_err(to_error)?.ok_or("Project was removed")?;
                    Ok(serde_json::json!({
                        "project_id":project.id,
                        "indexed_files":project.file_count,
                        "indexed_symbols":project.symbol_count,
                        "language_count":project.language_count,
                    }).to_string())
                }
                "source" => {
                    AssessmentJobs::new(self.db).execute(&assessment_id).and_then(|result| {
                        if result.status != "completed" {
                            Err(format!("Source review is {}; {}", result.status,
                                result.message.unwrap_or_else(|| "check persisted evidence".into())))
                        } else {
                            serde_json::to_string(&result.steps).map_err(to_error)
                        }
                    })
                }
                "secrets" => SecretScanningService::new(self.db)
                    .scan_project(&run.project_id)
                    .map(|value| format!("{value:?}")).map_err(to_error),
                "qa" => QaDiscoveryService::new(self.db)
                    .discover_project(&run.project_id)
                    .map(|value| format!("{value:?}")).map_err(to_error),
                "database" => DatabaseAnalysisService::new(self.db)
                    .analyze_project(&run.project_id)
                    .map(|value| format!("{value:?}")).map_err(to_error),
                "runtime" => RuntimeReliabilityService::new(self.db)
                    .analyze_project(&run.project_id)
                    .map(|value| format!("{value:?}")).map_err(to_error),
                _ => Err("Unregistered autonomous tool".into()),
            };
            match result {
                Ok(summary) => {
                    self.db.connection().execute(
                        "UPDATE native_agent_steps SET status='completed',result_json=?3,finished_at=CURRENT_TIMESTAMP
                         WHERE run_id=?1 AND position=?2",
                        params![run.id,step.position,summary],
                    ).map_err(to_error)?;
                }
                Err(error) => {
                    self.db.connection().execute(
                        "UPDATE native_agent_steps SET status='failed',result_json=?3,finished_at=CURRENT_TIMESTAMP
                         WHERE run_id=?1 AND position=?2",
                        params![run.id,step.position,error],
                    ).map_err(to_error)?;
                    return Err(error);
                }
            }
            self.boundary(&run.id, start, run.budget_seconds)?;
        }
        Ok(())
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
                step.role,step.tool,step.status,
                step.result.unwrap_or_else(|| "No verified result".into())
            ));
        }
        if let Some(message) = run.message {
            text.push_str(&format!("\n## Unresolved\n\n{message}\n"));
        }
        Ok(text)
    }

    /// Mark interrupted tasks explicitly, never silently resume after restart.
    pub fn recover_interrupted(&self) -> Result<(), String> {
        let tx = self.db.connection().unchecked_transaction().map_err(to_error)?;
        tx.execute(
            "UPDATE native_agent_steps SET status='interrupted',finished_at=CURRENT_TIMESTAMP
             WHERE status='running' AND run_id IN
             (SELECT id FROM native_agent_runs WHERE status='running')",
            [],
        ).map_err(to_error)?;
        tx.execute(
            "UPDATE native_agent_runs SET status='interrupted',finished_at=CURRENT_TIMESTAMP,
             message='Application closed during review; create a fresh plan'
             WHERE status='running'",
            [],
        ).map_err(to_error)?;
        tx.commit().map_err(to_error)
    }
}

fn to_error(err: impl std::fmt::Display) -> String {
    err.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_indexed_project_and_explicit_approval() {
        let db = Database::open_in_memory().unwrap();
        let agent = NativeAgents::new(&db);
        assert!(agent.create("missing","Review",10,60).is_err());
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("sample.ts"), "export const safe = true;").unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(root.path()).unwrap().project_id;
        assert!(agent.create(&project_id, " ", 10, 60).is_err());
        let run = agent.create(&project_id, "Review security posture", 10, 60).unwrap();
        assert_eq!(run.steps.len(), 6);
        assert!(agent.execute(&run.id).is_err());
        let approved = agent.approve(&run.id).unwrap();
        assert_eq!(approved.status, "approved");
        assert!(agent.create(&project_id, "Duplicate", 10, 60).is_err());
        let cancelled = agent.cancel(&run.id).unwrap();
        assert_eq!(cancelled.status, "cancelled");
        assert!(agent.execute(&run.id).is_err());
    }
}
