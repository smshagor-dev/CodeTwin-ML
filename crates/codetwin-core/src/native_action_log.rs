//! SQLite-owned, restart-safe action receipts for approved passive specialists.
//! The Go companion cannot execute arbitrary tools or mutate this ledger.
use crate::Database;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub position: usize,
    pub role: String,
    pub status: String,
    pub result_sha256: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

pub struct NativeActionLog<'a> {
    db: &'a Database,
}

impl<'a> NativeActionLog<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Atomically claim the existing approved step and log its dispatch.
    /// The registered role, active parent run and cancellation flag are
    /// re-checked inside SQLite; duplicate dispatches cannot be recorded.
    pub fn begin(&self, run_id: &str, position: usize, role: &str) -> Result<(), String> {
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let updated = tx
            .execute(
                "UPDATE native_agent_steps
                 SET status='running',started_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND position=?2 AND tool=?3 AND status='pending'
                   AND EXISTS (
                     SELECT 1 FROM native_agent_runs
                     WHERE id=?1 AND status='running' AND cancel_requested=0
                   )",
                params![run_id, position, role],
            )
            .map_err(err)?;
        if updated != 1 {
            return Err("Action dispatch is not an approved, pending specialist".into());
        }
        tx.execute(
            "INSERT INTO native_action_log(run_id,position,role,status)
             VALUES (?1,?2,?3,'running')",
            params![run_id, position, role],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }

    /// Complete both persisted step and action receipt in one transaction.
    /// The parent must still be running and uncancelled at commit time.
    /// A cancellation observed after a parallel worker begins rejects its
    /// result even if the worker has already returned.
    /// The receipt stores a digest, not source, secrets or raw scan output.
    pub fn finish(
        &self,
        run_id: &str,
        position: usize,
        role: &str,
        successful: bool,
        result: &str,
    ) -> Result<(), String> {
        let digest = format!("{:x}", Sha256::digest(result.as_bytes()));
        let state = if successful { "completed" } else { "failed" };
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let changed = tx
            .execute(
                "UPDATE native_action_log SET status=?4,result_sha256=?5,
                   finished_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND position=?2 AND role=?3 AND status='running'
                   AND EXISTS (
                     SELECT 1 FROM native_agent_runs
                     WHERE id=?1 AND status='running' AND cancel_requested=0
                   )",
                params![run_id, position, role, state, digest],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Action receipt cannot be completed twice".into());
        }
        let changed = tx
            .execute(
                "UPDATE native_agent_steps SET status=?4,result_json=?5,
                   finished_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND position=?2 AND tool=?3 AND status='running'",
                params![run_id, position, role, state, result],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Action step changed before completion".into());
        }
        tx.commit().map_err(err)
    }

    pub fn list(&self, run_id: &str) -> Result<Vec<ActionReceipt>, String> {
        let mut statement = self
            .db
            .connection()
            .prepare(
                "SELECT position,role,status,result_sha256,started_at,finished_at
                 FROM native_action_log WHERE run_id=?1 ORDER BY position",
            )
            .map_err(err)?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok(ActionReceipt {
                    position: row.get(0)?,
                    role: row.get(1)?,
                    status: row.get(2)?,
                    result_sha256: row.get(3)?,
                    started_at: row.get(4)?,
                    finished_at: row.get(5)?,
                })
            })
            .map_err(err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(err)
    }
}

fn err(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{native_agents::NativeAgents, ProjectIndexService};

    #[test]
    fn receipts_require_approval_and_commit_step_atomically() {
        let db = Database::open_in_memory().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("safe.ts"), "export const x = true;").unwrap();
        let project_id = ProjectIndexService::new(&db)
            .index_project(source.path())
            .unwrap()
            .project_id;
        let reviews = NativeAgents::new(&db);
        let run = reviews
            .create_with_roles(
                &project_id,
                "Review local indexed source",
                10,
                120,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        let log = NativeActionLog::new(&db);
        assert!(log.begin(&run.id, 0, "scout").is_err());
        assert!(log.begin(&run.id, 0, "runtime").is_err());
        assert!(log.list(&run.id).unwrap().is_empty());
        reviews.approve(&run.id).unwrap();
        // The native supervisor must claim a running review first.
        assert!(log.begin(&run.id, 0, "scout").is_err());
        db.connection()
            .execute(
                "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                [&run.id],
            )
            .unwrap();
        assert!(log.begin(&run.id, 0, "scout").is_ok());
        assert!(log.begin(&run.id, 0, "scout").is_err());
        assert_eq!(log.list(&run.id).unwrap()[0].status, "running");
        log.finish(&run.id, 0, "scout", true, "local report")
            .unwrap();
        assert!(log.finish(&run.id, 0, "scout", true, "again").is_err());
        let receipts = log.list(&run.id).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, "completed");
        assert_eq!(receipts[0].result_sha256.as_ref().unwrap().len(), 64);
        assert_eq!(reviews.get(&run.id).unwrap().steps[0].status, "completed");
    }
}
