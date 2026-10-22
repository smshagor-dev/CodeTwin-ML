//! Auditable evidence handoffs between the approved native specialist roles.
//! No model output or source text is copied into this ledger.
use crate::{native_agents::NativeAgents, Database};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHandoff {
    pub run_id: String,
    pub from_position: usize,
    pub to_position: usize,
    pub from_role: String,
    pub to_role: String,
    pub evidence_sha256: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVerification {
    pub run_id: String,
    pub verified: bool,
    pub checked_roles: usize,
    pub checked_handoffs: usize,
    pub issues: Vec<String>,
}

pub struct AgentHandoffs<'a> {
    db: &'a Database,
}

impl<'a> AgentHandoffs<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn list(&self, run_id: &str) -> Result<Vec<AgentHandoff>, String> {
        let _ = NativeAgents::new(self.db).get(run_id)?;
        let mut query = self.db.connection().prepare(
            "SELECT run_id,from_position,to_position,from_role,to_role,evidence_sha256,created_at
             FROM native_agent_handoffs WHERE run_id=?1 ORDER BY from_position",
        ).map_err(err)?;
        let values = query.query_map([run_id], |row| {
            Ok(AgentHandoff {
                run_id: row.get(0)?,
                from_position: row.get(1)?,
                to_position: row.get(2)?,
                from_role: row.get(3)?,
                to_role: row.get(4)?,
                evidence_sha256: row.get(5)?,
                created_at: row.get(6)?,
            })
        }).map_err(err)?.collect::<Result<Vec<_>, _>>().map_err(err)?;
        Ok(values)
    }

    /// Save an immutable provenance edge after the source specialist completed.
    /// Next tool permissions come from the pre-approved plan, never a model response.
    pub fn record(&self, run_id: &str, from_position: usize) -> Result<bool, String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        if run.status != "running" {
            return Err("Handoffs can only be recorded during a running review".into());
        }
        let from = run.steps.iter().find(|s| s.position == from_position)
            .ok_or("Unknown source specialist")?;
        if from.status != "completed" {
            return Err("Source specialist has not completed".into());
        }
        let next = run.steps.iter().find(|s| s.position > from.position);
        let Some(to) = next else { return Ok(false) };
        if to.status != "pending" {
            return Err("Destination specialist is not pending".into());
        }
        let result = from.result.as_deref().ok_or("Missing source evidence")?;
        let evidence_sha256 = format!("{:x}", Sha256::digest(result.as_bytes()));
        self.db.connection().execute(
            "INSERT INTO native_agent_handoffs
             (run_id,from_position,to_position,from_role,to_role,evidence_sha256)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![run_id,from.position,to.position,from.role,to.role,evidence_sha256],
        ).map_err(err)?;
        Ok(true)
    }

    /// Fail closed if the prior result was modified, a role was changed, or
    /// the supervisor attempts to skip a required predecessor.
    pub fn check_incoming(&self, run_id: &str, to_position: usize) -> Result<(), String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        let dest = run.steps.iter().find(|s| s.position == to_position)
            .ok_or("Unknown destination specialist")?;
        let previous = run.steps.iter().take_while(|s| s.position < to_position).last();
        let Some(from) = previous else { return Ok(()) };
        if from.status != "completed" {
            return Err("Previous specialist has not completed".into());
        }
        let stored = self.db.connection().query_row(
            "SELECT from_position,from_role,to_role,evidence_sha256
             FROM native_agent_handoffs WHERE run_id=?1 AND to_position=?2",
            params![run_id,to_position],
            |row| Ok((row.get::<_,usize>(0)?,row.get::<_,String>(1)?,
                       row.get::<_,String>(2)?,row.get::<_,String>(3)?)),
        ).optional().map_err(err)?.ok_or("Verified specialist handoff is missing")?;
        let (from_position, from_role, to_role, fingerprint) = stored;
        let evidence = from.result.as_deref().ok_or("Predecessor evidence is missing")?;
        if from_position != from.position || from_role != from.role || to_role != dest.role
            || format!("{:x}", Sha256::digest(evidence.as_bytes())) != fingerprint {
            return Err("Specialist handoff or evidence fingerprint mismatch".into());
        }
        Ok(())
    }

    pub fn verify(&self, run_id: &str) -> Result<AgentVerification, String> {
        let run = NativeAgents::new(self.db).get(run_id)?;
        let mut issues = Vec::new();
        if run.status != "completed" {
            issues.push(format!("Review status is {}; it is not fully completed", run.status));
        }
        let mut checked = 0usize;
        for step in &run.steps {
            if step.status != "completed" || step.result.as_deref().is_none_or(str::is_empty) {
                issues.push(format!("{} has no completed evidence", step.role));
            }
        }
        for step in run.steps.iter().skip(1) {
            match self.check_incoming(run_id, step.position) {
                Ok(()) => checked += 1,
                Err(error) => issues.push(format!("{}: {error}", step.role)),
            }
        }
        let count = self.db.connection().query_row(
            "SELECT COUNT(*) FROM native_agent_handoffs WHERE run_id=?1",
            [run_id], |row| row.get::<_,usize>(0),
        ).map_err(err)?;
        if count != run.steps.len().saturating_sub(1) {
            issues.push("Unexpected specialist handoff count".into());
        }
        Ok(AgentVerification {
            run_id: run.id,
            verified: issues.is_empty(),
            checked_roles: run.steps.len(),
            checked_handoffs: checked,
            issues,
        })
    }
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_requires_completed_source_and_detects_tampering() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("x.ts"), "export const answer = 42;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path()).unwrap().project_id;
        let roles = vec!["scout".to_string(), "source".to_string()];
        let run = NativeAgents::new(&db)
            .create_with_roles(&project, "Review", 10, 300, &roles).unwrap();
        let store = AgentHandoffs::new(&db);
        assert!(store.record(&run.id, 0).is_err());
        assert!(store.check_incoming(&run.id, 1).is_err());
        db.connection().execute(
            "UPDATE native_agent_runs SET status='running' WHERE id=?1", [&run.id],
        ).unwrap();
        db.connection().execute(
            "UPDATE native_agent_steps SET status='completed',result_json='{}'
             WHERE run_id=?1 AND position=0", [&run.id],
        ).unwrap();
        assert!(store.record(&run.id, 0).unwrap());
        assert!(store.check_incoming(&run.id, 1).is_ok());
        assert_eq!(store.list(&run.id).unwrap().len(), 1);
        db.connection().execute(
            "UPDATE native_agent_steps SET result_json='changed' WHERE run_id=?1 AND position=0",
            [&run.id],
        ).unwrap();
        assert!(store.check_incoming(&run.id, 1).is_err());
        assert!(!store.verify(&run.id).unwrap().verified);
    }
}
