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

    /// Atomically claim the immutable delegated role, specialist step and
    /// audit receipt. Dependencies, exact role identity and parent approval
    /// are checked under the same SQLite write transaction. A failed claim
    /// cannot leave a delegated role running without its action receipt.
    pub(crate) fn begin_supervised(
        &self,
        run_id: &str,
        position: usize,
        display_role: &str,
        tool: &str,
    ) -> Result<(), String> {
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let claimed = tx
            .execute(
                "UPDATE native_delegation_tasks SET status='running'
                 WHERE run_id=?1 AND position=?2 AND role=?3 AND tool=?4
                   AND status='pending'
                   AND EXISTS (
                     SELECT 1 FROM native_agent_runs
                     WHERE id=?1 AND status='running' AND cancel_requested=0
                   )
                   AND NOT EXISTS (
                     SELECT 1 FROM native_delegation_dependencies d
                     LEFT JOIN native_delegation_tasks required
                       ON required.run_id=d.run_id
                      AND required.position=d.requires_position
                     WHERE d.run_id=?1 AND d.position=?2
                       AND (required.status IS NULL OR required.status!='completed')
                   )",
                params![run_id, position, display_role, tool],
            )
            .map_err(err)?;
        if claimed != 1 {
            return Err("Delegation is not an approved dependency-ready role".into());
        }
        let changed = tx
            .execute(
                "UPDATE native_agent_steps SET status='running',
                   started_at=CURRENT_TIMESTAMP
                 WHERE run_id=?1 AND position=?2 AND role=?3 AND tool=?4
                   AND status='pending'
                   AND EXISTS (
                     SELECT 1 FROM native_agent_runs
                     WHERE id=?1 AND status='running' AND cancel_requested=0
                   )",
                params![run_id, position, display_role, tool],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Native specialist was not pending at claim".into());
        }
        tx.execute(
            "INSERT INTO native_action_log(run_id,position,role,status)
             VALUES (?1,?2,?3,'running')",
            params![run_id, position, tool],
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
        self.finish_internal(run_id, position, role, successful, result, false)
    }

    /// Used by the Rust review supervisor after a registered specialist joins.
    /// Commits delegation, step result and action digest together. This avoids
    /// a crashed supervisor leaving completed delegation without evidence.
    pub(crate) fn finish_supervised(
        &self,
        run_id: &str,
        position: usize,
        role: &str,
        successful: bool,
        result: &str,
    ) -> Result<(), String> {
        self.finish_internal(run_id, position, role, successful, result, true)
    }

    fn finish_internal(
        &self,
        run_id: &str,
        position: usize,
        role: &str,
        successful: bool,
        result: &str,
        supervised: bool,
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
        if supervised {
            let changed = tx
                .execute(
                    "UPDATE native_delegation_tasks SET status=?4
                     WHERE run_id=?1 AND position=?2 AND tool=?3 AND status='running'",
                    params![run_id, position, role, state],
                )
                .map_err(err)?;
            if changed != 1 {
                return Err("Delegated specialist changed before evidence commit".into());
            }
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
    fn supervisor_evidence_commit_rolls_back_when_delegation_state_changes() {
        let root = tempfile::tempdir().unwrap();
        let db = Database::open(root.path().join("atomic-specialists.sqlite3")).unwrap();
        let project_dir = root.path().join("source");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(&project_dir)
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        let run = agents
            .create_with_roles(
                &project,
                "Atomic specialist result",
                10,
                120,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        agents.approve(&run.id).unwrap();
        db.connection()
            .execute(
                "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                [&run.id],
            )
            .unwrap();
        let delegation = crate::native_agent_delegation::NativeDelegation::new(&db);
        let log = NativeActionLog::new(&db);
        // An unmet source dependency may not claim a receipt or delegation.
        assert!(log
            .begin_supervised(&run.id, 1, &run.steps[1].role, "source")
            .is_err());
        assert!(log.list(&run.id).unwrap().is_empty());
        assert_eq!(agents.get(&run.id).unwrap().steps[1].status, "pending");
        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='skipped'
                 WHERE run_id=?1 AND position=0",
                [&run.id],
            )
            .unwrap();
        // If one claim target changed, the preceding delegate update must
        // roll back rather than leave an orphaned running task.
        assert!(log
            .begin_supervised(&run.id, 0, &run.steps[0].role, "scout")
            .is_err());
        assert_eq!(
            delegation.graph(&run.id).unwrap().tasks[0].status,
            "pending"
        );
        assert!(log.list(&run.id).unwrap().is_empty());
        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='pending'
                 WHERE run_id=?1 AND position=0",
                [&run.id],
            )
            .unwrap();
        log.begin_supervised(&run.id, 0, &run.steps[0].role, "scout")
            .unwrap();
        assert_eq!(
            delegation.graph(&run.id).unwrap().tasks[0].status,
            "running"
        );
        // A corrupted or concurrently retired delegation must cause the
        // entire evidence transaction to roll back, not commit a partial step.
        db.connection()
            .execute(
                "UPDATE native_delegation_tasks SET status='failed'
                 WHERE run_id=?1 AND position=0",
                [&run.id],
            )
            .unwrap();
        assert!(log
            .finish_supervised(&run.id, 0, "scout", true, "unaccepted evidence")
            .is_err());
        assert_eq!(log.list(&run.id).unwrap()[0].status, "running");
        assert!(log.list(&run.id).unwrap()[0].result_sha256.is_none());
        assert_eq!(agents.get(&run.id).unwrap().steps[0].status, "running");
        db.connection()
            .execute(
                "UPDATE native_delegation_tasks SET status='running'
                 WHERE run_id=?1 AND position=0",
                [&run.id],
            )
            .unwrap();
        log.finish_supervised(&run.id, 0, "scout", true, "verified evidence")
            .unwrap();
        assert_eq!(log.list(&run.id).unwrap()[0].status, "completed");
        assert_eq!(agents.get(&run.id).unwrap().steps[0].status, "completed");
        assert_eq!(
            delegation.graph(&run.id).unwrap().tasks[0].status,
            "completed"
        );
        assert!(log
            .finish_supervised(&run.id, 0, "scout", true, "duplicate")
            .is_err());
    }

    #[test]
    fn concurrent_claimed_receipts_reject_late_results_after_cancel_and_restart() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("cancelled-parallel.sqlite3");
        let source = scratch.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("safe.ts"), "export const safe = true;").unwrap();

        let run_id = {
            let db = Database::open(&path).unwrap();
            let project = ProjectIndexService::new(&db)
                .index_project(&source)
                .unwrap()
                .project_id;
            let agents = NativeAgents::new(&db);
            let run = agents
                .create_with_roles(
                    &project,
                    "Bounded parallel cancellation",
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
            agents.approve(&run.id).unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_runs SET status='running' WHERE id=?1",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_steps SET status='completed',
                     result_json='verified evidence'
                     WHERE run_id=?1 AND position IN (0,1)",
                    [&run.id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_delegation_tasks SET status='completed'
                     WHERE run_id=?1 AND position IN (0,1)",
                    [&run.id],
                )
                .unwrap();
            let log = NativeActionLog::new(&db);
            log.begin(&run.id, 2, "secrets").unwrap();
            log.begin(&run.id, 3, "qa").unwrap();

            // A separate desktop connection requests cancellation while both
            // native analyzers could be running. Neither late result is valid.
            let second = Database::open(&path).unwrap();
            NativeAgents::new(&second).cancel(&run.id).unwrap();
            assert!(log
                .finish(&run.id, 2, "secrets", true, "late secret evidence")
                .is_err());
            assert!(log
                .finish(&run.id, 3, "qa", true, "late QA evidence")
                .is_err());
            let receipts = log.list(&run.id).unwrap();
            assert_eq!(receipts.len(), 2);
            assert!(receipts.iter().all(|receipt| receipt.status == "running"));
            assert!(receipts
                .iter()
                .all(|receipt| receipt.result_sha256.is_none()));
            run.id
        };

        // Simulated process death: recovery retires both in-flight receipts
        // and preserves already committed evidence without resuming tools.
        let db = Database::open(&path).unwrap();
        let agents = NativeAgents::new(&db);
        agents.recover_interrupted().unwrap();
        let run = agents.get(&run_id).unwrap();
        assert_eq!(run.status, "interrupted");
        assert!(run.steps[..2].iter().all(|step| step.status == "completed"));
        assert!(run.steps[2..]
            .iter()
            .all(|step| step.status == "interrupted"));
        assert!(run.steps[2..].iter().all(|step| step.result.is_none()));
        let receipts = NativeActionLog::new(&db).list(&run_id).unwrap();
        assert!(receipts.iter().all(|item| item.status == "interrupted"));
        assert!(receipts.iter().all(|item| item.result_sha256.is_none()));
        assert!(agents.execute(&run_id).is_err());
        agents.recover_interrupted().unwrap();
        assert_eq!(agents.get(&run_id).unwrap().status, "interrupted");
    }

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
