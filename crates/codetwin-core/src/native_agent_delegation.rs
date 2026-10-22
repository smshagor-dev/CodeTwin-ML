//! Bounded multi-step delegation across pre-approved, native specialist tools.
//! This is an auditable task DAG, not an untrusted LLM shell executor.
use crate::{native_agents::NativeAgents, Database};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedTask {
    pub position: usize,
    pub role: String,
    pub tool: String,
    pub status: String,
    pub objective: Option<String>,
    pub requires: Vec<usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGraph {
    pub run_id: String,
    pub tasks: Vec<DelegatedTask>,
}

pub struct NativeDelegation<'a> {
    db: &'a Database,
}
impl<'a> NativeDelegation<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Materialize a DAG for the user-selected specialist roles before any approval.
    /// Core source review is always a prerequisite of optional specialists.
    pub fn prepare(&self, run_id: &str) -> Result<DelegationGraph, String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        if run.status != "planned" {
            return Err("Only unapproved plans can be decomposed".into());
        }
        if !(2..=6).contains(&run.steps.len()) {
            return Err("Unsupported specialist count".into());
        }
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let already: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM native_delegation_tasks WHERE run_id=?1)",
                [run_id],
                |row| row.get(0),
            )
            .map_err(err)?;
        if already {
            return Err("Delegation plan is already immutable".into());
        }
        let source = run
            .steps
            .iter()
            .find(|step| step.tool == "source")
            .ok_or("Source auditor is required")?
            .position;
        let scout = run
            .steps
            .iter()
            .find(|step| step.tool == "scout")
            .ok_or("Project reconnaissance is required")?
            .position;
        if scout >= source {
            return Err("Source reviewer must follow project reconnaissance".into());
        }
        for step in &run.steps {
            tx.execute(
                "INSERT INTO native_delegation_tasks(run_id,position,role,tool)
                 VALUES(?1,?2,?3,?4)",
                params![run.id, step.position, step.role, step.tool],
            )
            .map_err(err)?;
        }
        for step in &run.steps {
            let predecessor = if step.position == scout {
                None
            } else if step.position == source {
                Some(scout)
            } else {
                Some(source)
            };
            if let Some(dep) = predecessor {
                tx.execute(
                    "INSERT INTO native_delegation_dependencies(run_id,position,requires_position)
                     VALUES(?1,?2,?3)",
                    params![run.id, step.position, dep],
                )
                .map_err(err)?;
            }
        }
        tx.commit().map_err(err)?;
        self.graph(run_id)
    }

    /// Replace the default DAG with a validated role-specific decomposition.
    /// This can only happen while the review is unapproved.
    pub fn apply_proposal(
        &self,
        run_id: &str,
        proposal: &crate::native_task_plans::TaskProposal,
    ) -> Result<DelegationGraph, String> {
        let _ = crate::native_task_plans::validate_proposal(proposal)?;
        let run = NativeAgents::new(self.db).get(run_id)?;
        if run.status != "planned" {
            return Err("Model task proposals cannot alter approved or running plans".into());
        }
        if run.steps.len() != proposal.tasks.len() {
            return Err("Task proposal must match the prepared specialist selection".into());
        }
        let positions = run
            .steps
            .iter()
            .map(|s| (s.tool.as_str(), s.position))
            .collect::<std::collections::BTreeMap<_, _>>();
        if proposal
            .tasks
            .iter()
            .any(|task| !positions.contains_key(task.role.as_str()))
        {
            return Err("Task proposal changed the approved tool allowlist".into());
        }
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        tx.execute(
            "DELETE FROM native_delegation_dependencies WHERE run_id=?1",
            [run_id],
        )
        .map_err(err)?;
        tx.execute("DELETE FROM native_task_intents WHERE run_id=?1", [run_id])
            .map_err(err)?;
        for task in &proposal.tasks {
            let position = positions[task.role.as_str()];
            tx.execute(
                "INSERT INTO native_task_intents(run_id,position,role,objective)
                 VALUES (?1,?2,?3,?4)",
                params![run_id, position, task.role, task.objective.trim()],
            )
            .map_err(err)?;
            for required in &task.depends_on {
                let predecessor = positions[required.as_str()];
                if predecessor >= position {
                    return Err("Task dependencies must follow the audited role order".into());
                }
                tx.execute(
                    "INSERT INTO native_delegation_dependencies(run_id,position,requires_position)
                     VALUES (?1,?2,?3)",
                    params![run_id, position, predecessor],
                )
                .map_err(err)?;
            }
        }
        tx.commit().map_err(err)?;
        self.graph(run_id)
    }

    pub fn graph(&self, run_id: &str) -> Result<DelegationGraph, String> {
        let _ = NativeAgents::new(self.db).get(run_id)?;
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT t.position,t.role,t.tool,t.status,i.objective
             FROM native_delegation_tasks t
             LEFT JOIN native_task_intents i ON i.run_id=t.run_id AND i.position=t.position
             WHERE t.run_id=?1 ORDER BY t.position",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map([run_id], |row| {
                Ok(DelegatedTask {
                    position: row.get(0)?,
                    role: row.get(1)?,
                    tool: row.get(2)?,
                    status: row.get(3)?,
                    objective: row.get(4)?,
                    requires: Vec::new(),
                })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        let mut tasks = rows;
        for task in &mut tasks {
            let mut depend = self
                .db
                .connection()
                .prepare(
                    "SELECT requires_position FROM native_delegation_dependencies
                 WHERE run_id=?1 AND position=?2 ORDER BY requires_position",
                )
                .map_err(err)?;
            task.requires = depend
                .query_map(params![run_id, task.position], |row| row.get(0))
                .map_err(err)?
                .collect::<Result<Vec<usize>, _>>()
                .map_err(err)?;
        }
        Ok(DelegationGraph {
            run_id: run_id.into(),
            tasks,
        })
    }

    /// Gate dispatch against an immutable role identity and all completed dependencies.
    pub fn start(&self, run_id: &str, position: usize, role: &str) -> Result<(), String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        if run.status != "running" {
            return Err("Review is not running".into());
        }
        let planned = self
            .db
            .connection()
            .query_row(
                "SELECT role,status FROM native_delegation_tasks WHERE run_id=?1 AND position=?2",
                params![run_id, position],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(err)?
            .ok_or("No authorized delegated task")?;
        if planned.0 != role || planned.1 != "pending" {
            return Err("Delegation role mismatch or duplicate execution".into());
        }
        let unfinished: i64 = self
            .db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM native_delegation_dependencies d
             LEFT JOIN native_delegation_tasks r
              ON r.run_id=d.run_id AND r.position=d.requires_position
             WHERE d.run_id=?1 AND d.position=?2 AND (r.status IS NULL OR r.status!='completed')",
                params![run_id, position],
                |row| row.get(0),
            )
            .map_err(err)?;
        if unfinished != 0 {
            return Err("Delegation dependencies have not completed".into());
        }
        let updated = self
            .db
            .connection()
            .execute(
                "UPDATE native_delegation_tasks SET status='running'
             WHERE run_id=?1 AND position=?2 AND status='pending'",
                params![run_id, position],
            )
            .map_err(err)?;
        if updated != 1 {
            return Err("Delegation state changed before dispatch".into());
        }
        Ok(())
    }

    pub fn finish(&self, run_id: &str, position: usize, success: bool) -> Result<(), String> {
        let status = if success { "completed" } else { "failed" };
        let rows = self
            .db
            .connection()
            .execute(
                "UPDATE native_delegation_tasks SET status=?3
             WHERE run_id=?1 AND position=?2 AND status='running'",
                params![run_id, position, status],
            )
            .map_err(err)?;
        if rows != 1 {
            return Err("Delegated task was not running".into());
        }
        Ok(())
    }

    pub fn verify(&self, run_id: &str) -> Result<(), String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        let graph = self.graph(run_id)?;
        if graph.tasks.len() != run.steps.len() {
            return Err("Delegation graph is incomplete".into());
        }
        for step in &run.steps {
            let task = graph
                .tasks
                .iter()
                .find(|task| task.position == step.position)
                .ok_or("A required delegated task is missing")?;
            if task.role != step.role
                || task.tool != step.tool
                || task.status != "completed"
                || step.status != "completed"
                || task.requires.iter().any(|dep| *dep >= step.position)
            {
                return Err("Delegation graph state or identity mismatch".into());
            }
        }
        Ok(())
    }
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_is_immutable_and_requires_approved_dependencies() {
        let db = Database::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.ts"), "export const a=1;").unwrap();
        let id = crate::ProjectIndexService::new(&db)
            .index_project(dir.path())
            .unwrap()
            .project_id;
        let run = NativeAgents::new(&db)
            .create_with_roles(
                &id,
                "Review",
                10,
                300,
                &["scout".into(), "source".into(), "qa".into()],
            )
            .unwrap();
        let service = NativeDelegation::new(&db);
        let graph = service.graph(&run.id).unwrap();
        assert_eq!(graph.tasks.len(), 3);
        assert_eq!(graph.tasks[2].position, 3);
        assert_eq!(graph.tasks[2].requires, vec![1]);
        assert!(service.prepare(&run.id).is_err());
        assert!(service.start(&run.id, 1, "Source Auditor").is_err());
        db.connection()
            .execute(
                "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                [&run.id],
            )
            .unwrap();
        assert!(service.start(&run.id, 1, "Source Auditor").is_err());
        service.start(&run.id, 0, "Project Recon").unwrap();
        service.finish(&run.id, 0, true).unwrap();
        service.start(&run.id, 1, "Source Auditor").unwrap();
        service.finish(&run.id, 1, true).unwrap();
        service.start(&run.id, 3, "Test Researcher").unwrap();
    }
}
