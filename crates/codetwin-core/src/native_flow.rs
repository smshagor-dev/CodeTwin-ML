//! Offline Flow -> Task -> Subtask -> Action orchestration backed by SQLite.
//! Automatic execution is restricted to a once-approved passive review.
//! Actual execution and cancellation remain owned by NativeAgents (Rust).
use crate::{
    native_action_log::{ActionReceipt, NativeActionLog},
    native_agent_delegation::NativeDelegation,
    native_agents::NativeAgents,
    native_task_plans::{validate_proposal, TaskProposal},
    Database,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSubtask {
    pub position: usize,
    pub role: String,
    pub status: String,
    pub requires: Vec<usize>,
    pub actions: Vec<ActionReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTask {
    pub title: String,
    pub subtasks: Vec<FlowSubtask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedFlow {
    pub review_id: String,
    pub project_id: String,
    pub objective: String,
    pub mode: String,
    pub status: String,
    pub created_at: String,
    pub approved_at: Option<String>,
    pub completed_subtasks: usize,
    pub total_subtasks: usize,
    pub tasks: Vec<FlowTask>,
}

/// Immutable proposed follow-up. This is not an approved review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFollowup {
    pub review_id: String,
    pub proposal: TaskProposal,
    pub created_at: String,
}

pub struct NativeFlow<'a> {
    db: &'a Database,
}

impl<'a> NativeFlow<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Attach automation only to a planned, indexed review. The reviewed
    /// specialist allowlist and dependency graph are never expanded here.
    pub fn prepare(&self, review_id: &str) -> Result<AutomatedFlow, String> {
        let review = NativeAgents::new(self.db).get(review_id)?;
        if review.status != "planned" {
            return Err("Prepare automation before approving the review".into());
        }
        let graph = NativeDelegation::new(self.db).graph(review_id)?;
        if graph.tasks.len() != review.steps.len()
            || graph.tasks.len() < 2
            || !graph.tasks.iter().any(|task| task.tool == "scout")
            || !graph.tasks.iter().any(|task| task.tool == "source")
        {
            return Err("The local specialist dependency graph is incomplete".into());
        }
        self.db
            .connection()
            .execute(
                "INSERT INTO native_security_flows(review_id,mode)
                 SELECT id,'go-verified' FROM native_agent_runs
                 WHERE id=?1 AND status='planned' AND cancel_requested=0",
                [review_id],
            )
            .map_err(|error| format!("Could not prepare a unique local flow: {error}"))?;
        self.get(review_id)?
            .ok_or("Prepared flow was not stored".into())
    }

    /// A single explicit human approval authorizes only the preplanned
    /// registered specialists. Flow metadata and review approval commit together.
    pub fn approve(&self, review_id: &str) -> Result<AutomatedFlow, String> {
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(to_error)?;
        let changed = tx
            .execute(
                "UPDATE native_agent_runs SET status='approved'
                 WHERE id=?1 AND status='planned' AND cancel_requested=0
                   AND EXISTS (SELECT 1 FROM native_security_flows
                               WHERE review_id=?1 AND approved_at IS NULL)",
                [review_id],
            )
            .map_err(to_error)?;
        if changed != 1 {
            return Err("Only an existing, unapproved local flow can be approved".into());
        }
        let marked = tx
            .execute(
                "UPDATE native_security_flows SET approved_at=CURRENT_TIMESTAMP
                 WHERE review_id=?1 AND approved_at IS NULL",
                [review_id],
            )
            .map_err(to_error)?;
        if marked != 1 {
            return Err("Flow approval changed during review".into());
        }
        tx.commit().map_err(to_error)?;
        self.get(review_id)?.ok_or("Approved flow not found".into())
    }

    /// Persist one restricted follow-up after a failed/interrupted automated
    /// review. A proposal can only reuse roles present in the previous review.
    /// It never inherits approval, execution rights, or a new target.
    pub fn suggest_followup(
        &self,
        review_id: &str,
        proposal: &TaskProposal,
    ) -> Result<FlowFollowup, String> {
        validate_proposal(proposal)?;
        let run = NativeAgents::new(self.db).get(review_id)?;
        if run.status != "failed" && run.status != "interrupted" {
            return Err("Follow-up requires a failed or interrupted flow".into());
        }
        if proposal
            .tasks
            .iter()
            .any(|task| !run.steps.iter().any(|step| step.tool == task.role))
        {
            return Err("Follow-up cannot add specialists beyond the prior reviewed scope".into());
        }
        let json = serde_json::to_string(proposal).map_err(to_error)?;
        if json.len() > 6000 {
            return Err("Follow-up task proposal is too large".into());
        }
        let inserted = self
            .db
            .connection()
            .execute(
                "INSERT INTO native_flow_followups(review_id,proposal_json)
                 SELECT ?1,?2 WHERE EXISTS(
                     SELECT 1 FROM native_security_flows f
                     JOIN native_agent_runs r ON r.id=f.review_id
                     WHERE f.review_id=?1 AND f.approved_at IS NOT NULL
                       AND r.status IN ('failed','interrupted')
                 )",
                params![review_id, json],
            )
            .map_err(to_error)?;
        if inserted != 1 {
            return Err("Only a completed flow can store a new follow-up suggestion".into());
        }
        self.get_followup(review_id)?
            .ok_or("Follow-up suggestion could not be loaded".into())
    }

    pub fn get_followup(&self, review_id: &str) -> Result<Option<FlowFollowup>, String> {
        let saved = self
            .db
            .connection()
            .query_row(
                "SELECT proposal_json,created_at FROM native_flow_followups
                 WHERE review_id=?1",
                [review_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(to_error)?;
        let Some((json, created_at)) = saved else {
            return Ok(None);
        };
        let proposal: TaskProposal = serde_json::from_str(&json).map_err(to_error)?;
        validate_proposal(&proposal)?;
        Ok(Some(FlowFollowup {
            review_id: review_id.to_string(),
            proposal,
            created_at,
        }))
    }

    /// Render an accurate, persisted hierarchy from the existing review DAG
    /// and action receipts; never maintain a second mutable task-state table.
    pub fn get(&self, review_id: &str) -> Result<Option<AutomatedFlow>, String> {
        let row = self
            .db
            .connection()
            .query_row(
                "SELECT mode,created_at,approved_at FROM native_security_flows
                 WHERE review_id=?1",
                [review_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(to_error)?;
        let Some((mode, created_at, approved_at)) = row else {
            return Ok(None);
        };
        let review = NativeAgents::new(self.db).get(review_id)?;
        let graph = NativeDelegation::new(self.db).graph(review_id)?;
        let receipts = NativeActionLog::new(self.db).list(review_id)?;
        let completed_subtasks = graph
            .tasks
            .iter()
            .filter(|task| task.status == "completed")
            .count();
        let total_subtasks = graph.tasks.len();
        let mut core = Vec::new();
        let mut specialists = Vec::new();
        for task in graph.tasks {
            let actions = receipts
                .iter()
                .filter(|action| action.position == task.position)
                .cloned()
                .collect();
            let subtask = FlowSubtask {
                position: task.position,
                role: task.tool.clone(),
                status: task.status,
                requires: task.requires,
                actions,
            };
            if task.tool == "scout" || task.tool == "source" {
                core.push(subtask);
            } else {
                specialists.push(subtask);
            }
        }
        let mut tasks = vec![FlowTask {
            title: "Project and source review".into(),
            subtasks: core,
        }];
        if !specialists.is_empty() {
            tasks.push(FlowTask {
                title: "Passive specialist analysis".into(),
                subtasks: specialists,
            });
        }
        Ok(Some(AutomatedFlow {
            review_id: review.id,
            project_id: review.project_id,
            objective: review.objective,
            mode,
            status: review.status,
            created_at,
            approved_at,
            completed_subtasks,
            total_subtasks,
            tasks,
        }))
    }
}

fn to_error(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProjectIndexService;

    #[test]
    fn flow_requires_single_approval_and_runs_approved_subtasks() {
        let db = Database::open_in_memory().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("safe.ts"), "export const safe = true;").unwrap();
        let project_id = ProjectIndexService::new(&db)
            .index_project(fixture.path())
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let review = reviews
            .create_with_roles(
                &project_id,
                "Review indexed project defensively",
                10,
                300,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        let flows = NativeFlow::new(&db);
        assert!(flows.get(&review.id).unwrap().is_none());
        assert!(reviews.execute(&review.id).is_err());
        let planned = flows.prepare(&review.id).unwrap();
        assert_eq!(planned.status, "planned");
        assert_eq!(planned.total_subtasks, 2);
        assert_eq!(planned.tasks.len(), 1);
        assert!(flows.prepare(&review.id).is_err());
        let approved = flows.approve(&review.id).unwrap();
        assert_eq!(approved.status, "approved");
        assert!(approved.approved_at.is_some());
        assert!(flows.approve(&review.id).is_err());
        let finished = reviews
            .execute_with_dispatch(&review.id, &|_db, _run, step| {
                if step.tool == "scout" || step.tool == "source" {
                    Ok(())
                } else {
                    Err("Role outside flow".into())
                }
            })
            .unwrap();
        assert_eq!(finished.status, "completed", "{:?}", finished.message);
        let snapshot = flows.get(&review.id).unwrap().unwrap();
        assert_eq!(snapshot.status, "completed");
        assert_eq!(snapshot.completed_subtasks, snapshot.total_subtasks);
        assert_eq!(snapshot.tasks[0].subtasks[0].role, "scout");
        assert_eq!(snapshot.tasks[0].subtasks[1].requires, vec![0]);
        assert_eq!(snapshot.tasks[0].subtasks[0].actions.len(), 1);
        assert_eq!(snapshot.tasks[0].subtasks[1].actions.len(), 1);
        assert!(reviews.execute(&review.id).is_err());
    }

    #[test]
    fn approved_automatic_flow_survives_real_sqlite_restart_without_replay() {
        let sandbox = tempfile::tempdir().unwrap();
        let database_path = sandbox.path().join("automated-flow.sqlite3");
        let project_path = sandbox.path().join("reviewed-project");
        std::fs::create_dir_all(&project_path).unwrap();
        std::fs::write(project_path.join("safe.rs"), "pub fn safe() {}").unwrap();
        let review_id = {
            let db = Database::open(&database_path).unwrap();
            let project_id = ProjectIndexService::new(&db)
                .index_project(&project_path)
                .unwrap()
                .project_id;
            let review = NativeAgents::new(&db)
                .create_with_roles(
                    &project_id,
                    "Automated offline source review",
                    10,
                    300,
                    &["scout".into(), "source".into()],
                )
                .unwrap();
            let flow = NativeFlow::new(&db);
            flow.prepare(&review.id).unwrap();
            flow.approve(&review.id).unwrap();
            review.id
        };

        {
            let db = Database::open(&database_path).unwrap();
            let flow = NativeFlow::new(&db).get(&review_id).unwrap().unwrap();
            assert_eq!(flow.status, "approved");
            assert_eq!(flow.total_subtasks, 2);
            let result = NativeAgents::new(&db).execute(&review_id).unwrap();
            assert_eq!(result.status, "completed", "{:?}", result.message);
        }

        let db = Database::open(&database_path).unwrap();
        NativeAgents::new(&db).recover_interrupted().unwrap();
        let flow = NativeFlow::new(&db).get(&review_id).unwrap().unwrap();
        assert_eq!(flow.status, "completed");
        assert_eq!(flow.completed_subtasks, 2);
        assert!(flow
            .tasks
            .iter()
            .flat_map(|task| &task.subtasks)
            .all(|subtask| subtask.actions.len() == 1));
        assert!(NativeAgents::new(&db).execute(&review_id).is_err());
    }

    #[test]
    fn adaptive_followup_is_unapproved_and_cannot_expand_roles() {
        let db = Database::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("code.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(dir.path())
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let review = reviews
            .create_with_roles(
                &project,
                "Local passive source review",
                10,
                120,
                &["scout".into(), "source".into(), "qa".into()],
            )
            .unwrap();
        let flow = NativeFlow::new(&db);
        flow.prepare(&review.id).unwrap();
        flow.approve(&review.id).unwrap();
        let proposal = TaskProposal {
            rationale: "Review incomplete approved QA evidence".into(),
            tasks: vec![
                crate::native_task_plans::PlannedSpecialist {
                    role: "scout".into(),
                    objective: "Inventory".into(),
                    depends_on: vec![],
                },
                crate::native_task_plans::PlannedSpecialist {
                    role: "source".into(),
                    objective: "Review".into(),
                    depends_on: vec!["scout".into()],
                },
                crate::native_task_plans::PlannedSpecialist {
                    role: "qa".into(),
                    objective: "QA".into(),
                    depends_on: vec!["source".into()],
                },
            ],
        };
        assert!(flow.suggest_followup(&review.id, &proposal).is_err());
        let deny = |_db: &Database,
                    _run: &crate::native_agents::AgentRun,
                    _step: &crate::native_agents::AgentStep| {
            Err("Denied role by policy".to_string())
        };
        assert_eq!(
            reviews
                .execute_with_dispatch(&review.id, &deny)
                .unwrap()
                .status,
            "failed"
        );
        let suggestion = flow.suggest_followup(&review.id, &proposal).unwrap();
        assert_eq!(suggestion.proposal.tasks.len(), 3);
        assert!(flow.suggest_followup(&review.id, &proposal).is_err());
        let mut expanded = proposal.clone();
        expanded
            .tasks
            .push(crate::native_task_plans::PlannedSpecialist {
                role: "runtime".into(),
                objective: "Runtime".into(),
                depends_on: vec!["source".into()],
            });
        assert!(flow.suggest_followup(&review.id, &expanded).is_err());
        assert_eq!(
            flow.get_followup(&review.id).unwrap().unwrap().review_id,
            review.id
        );
    }

    #[test]
    fn cancelled_flow_cannot_be_approved_or_executed() {
        let db = Database::open_in_memory().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project_id = ProjectIndexService::new(&db)
            .index_project(fixture.path())
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let review = reviews
            .create_with_roles(
                &project_id,
                "Source review",
                10,
                180,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        let flows = NativeFlow::new(&db);
        flows.prepare(&review.id).unwrap();
        reviews.cancel(&review.id).unwrap();
        assert!(flows.approve(&review.id).is_err());
        assert_eq!(flows.get(&review.id).unwrap().unwrap().status, "cancelled");
    }
}
