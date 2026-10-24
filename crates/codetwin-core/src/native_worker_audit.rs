//! Durable, privacy-reduced local audit for separately authorized container workers.
use crate::{native_agent_workers::IsolatedScanReceipt, Database};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerAuditRecord {
    pub id: i64,
    pub run_id: String,
    pub status: String,
    pub image_digest: Option<String>,
    pub report_sha256: Option<String>,
    pub vulnerability_count: Option<usize>,
    pub misconfiguration_count: Option<usize>,
    pub error_code: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

pub struct WorkerAudit<'a> {
    db: &'a Database,
}
impl<'a> WorkerAudit<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn begin(&self, run_id: &str) -> Result<i64, String> {
        let run = crate::native_agents::NativeAgents::new(self.db).get(run_id)?;
        if run.status != "approved" {
            return Err("Worker run requires an approved local review".into());
        }
        // The authorization check and insert must happen in the same SQLite
        // statement, so cancellation cannot race a previously read snapshot.
        let inserted = self
            .db
            .connection()
            .execute(
                "INSERT INTO native_worker_audit(run_id)
                 SELECT id FROM native_agent_runs
                 WHERE id=?1 AND status='approved' AND cancel_requested=0
                   AND NOT EXISTS (
                     SELECT 1 FROM native_worker_audit
                     WHERE run_id=?1 AND status='running'
                   )
                   AND NOT EXISTS (
                     SELECT 1 FROM native_flow_queue
                     WHERE review_id=?1 AND status IN ('queued','running')
                   )
                   AND NOT EXISTS (
                     SELECT 1 FROM native_worker_audit
                     WHERE error_code IN (
                       'application_restarted_cleanup_unconfirmed',
                       'worker_cleanup_unconfirmed',
                       'worker_cancelled_cleanup_unconfirmed'
                     )
                   )",
                [run_id],
            )
            .map_err(err)?;
        if inserted != 1 {
            return Err(
                "Worker requires an approved unqueued review, no active worker, and verified cleanup of earlier scans".into(),
            );
        }
        Ok(self.db.connection().last_insert_rowid())
    }

    pub fn finish(
        &self,
        audit_id: i64,
        outcome: &Result<IsolatedScanReceipt, String>,
    ) -> Result<(), String> {
        match outcome {
            Ok(receipt) => {
                // Never accept a receipt from another review. Atomic SQLite
                // authorization check prevents a cancellation/commit race.
                let changed = self
                    .db
                    .connection()
                    .execute(
                        "UPDATE native_worker_audit SET status='success',image_digest=?2,
                         report_sha256=?3,vulnerability_count=?4,misconfiguration_count=?5,
                         finished_at=CURRENT_TIMESTAMP
                         WHERE id=?1 AND run_id=?6 AND status='running'
                         AND EXISTS (
                           SELECT 1 FROM native_agent_runs
                           WHERE id=native_worker_audit.run_id
                             AND status='approved' AND cancel_requested=0
                         )",
                        params![
                            audit_id,
                            receipt.image_digest,
                            receipt.report_sha256,
                            receipt.vulnerability_count,
                            receipt.misconfiguration_count,
                            receipt.run_id
                        ],
                    )
                    .map_err(err)?;
                if changed == 1 {
                    return Ok(());
                }
                // A revoked review is a terminal failed attempt. Never
                // persist its scanner findings as a successful receipt.
                let revoked = self
                    .db
                    .connection()
                    .execute(
                        "UPDATE native_worker_audit
                         SET status='failed',error_code='worker_cancelled',
                             finished_at=CURRENT_TIMESTAMP
                         WHERE id=?1 AND status='running'
                         AND EXISTS (
                           SELECT 1 FROM native_agent_runs
                           WHERE id=native_worker_audit.run_id
                             AND (status!='approved' OR cancel_requested!=0)
                         )",
                        [audit_id],
                    )
                    .map_err(err)?;
                if revoked == 1 {
                    return Err("Worker receipt rejected after review authorization changed".into());
                }
                Err("Worker receipt does not match its active audit entry".into())
            }
            Err(reason) => {
                let cleanup_unconfirmed = cleanup_unconfirmed(reason);
                // Only fixed codes reach the durable ledger; never raw
                // Docker stderr, local paths, target data or credentials.
                let changed = self
                    .db
                    .connection()
                    .execute(
                        "UPDATE native_worker_audit
                         SET status='failed',
                             error_code=CASE WHEN EXISTS (
                               SELECT 1 FROM native_agent_runs
                               WHERE id=native_worker_audit.run_id
                                 AND (status!='approved' OR cancel_requested!=0)
                             ) THEN ?2 ELSE ?3 END,
                             finished_at=CURRENT_TIMESTAMP
                         WHERE id=?1 AND status='running'",
                        params![
                            audit_id,
                            if cleanup_unconfirmed {
                                "worker_cancelled_cleanup_unconfirmed"
                            } else {
                                "worker_cancelled"
                            },
                            if cleanup_unconfirmed {
                                "worker_cleanup_unconfirmed"
                            } else {
                                "worker_failed"
                            }
                        ],
                    )
                    .map_err(err)?;
                if changed != 1 {
                    return Err("Worker audit cannot be finalized twice".into());
                }
                Ok(())
            }
        }
    }

    pub fn list(&self, run_id: &str) -> Result<Vec<WorkerAuditRecord>, String> {
        let _ = crate::native_agents::NativeAgents::new(self.db).get(run_id)?;
        let mut statement = self
            .db
            .connection()
            .prepare(
                "SELECT id,run_id,status,image_digest,report_sha256,vulnerability_count,
             misconfiguration_count,error_code,started_at,finished_at
             FROM native_worker_audit WHERE run_id=?1 ORDER BY id DESC LIMIT 50",
            )
            .map_err(err)?;
        let records = statement
            .query_map([run_id], |row| {
                Ok(WorkerAuditRecord {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    status: row.get(2)?,
                    image_digest: row.get(3)?,
                    report_sha256: row.get(4)?,
                    vulnerability_count: row.get(5)?,
                    misconfiguration_count: row.get(6)?,
                    error_code: row.get(7)?,
                    started_at: row.get(8)?,
                    finished_at: row.get(9)?,
                })
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(records)
    }

    /// Close unfinished worker audits after a desktop restart. A killed Docker
    /// CLI does not prove daemon-side container removal; the fixed error code
    /// deliberately requires manual inspection of possible leftover workers.
    /// Its old parent approval is retired in the same SQLite transaction.
    pub fn recover_interrupted(&self) -> Result<usize, String> {
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        tx.execute(
            "UPDATE native_agent_runs
             SET status='interrupted',cancel_requested=1,
                 finished_at=CURRENT_TIMESTAMP,
                 message='Desktop stopped during isolated scan; approve a fresh review'
             WHERE status='approved'
               AND id IN (SELECT run_id FROM native_worker_audit
                          WHERE status='running')",
            [],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE native_agent_steps SET status='cancelled',
             finished_at=CURRENT_TIMESTAMP
             WHERE status='pending'
               AND run_id IN (SELECT run_id FROM native_worker_audit
                              WHERE status='running')
               AND EXISTS (
                 SELECT 1 FROM native_agent_runs r
                 WHERE r.id=native_agent_steps.run_id AND r.status='interrupted'
               )",
            [],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE native_delegation_tasks SET status='cancelled'
             WHERE status IN ('pending','running')
               AND run_id IN (SELECT run_id FROM native_worker_audit
                              WHERE status='running')
               AND EXISTS (
                 SELECT 1 FROM native_agent_runs r
                 WHERE r.id=native_delegation_tasks.run_id AND r.status='interrupted'
               )",
            [],
        )
        .map_err(err)?;
        let changed = tx
            .execute(
                "UPDATE native_worker_audit
                 SET status='interrupted',
                     error_code='application_restarted_cleanup_unconfirmed',
                     finished_at=CURRENT_TIMESTAMP
                 WHERE status='running'",
                [],
            )
            .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(changed)
    }

    /// Fail closed across the whole desktop profile until Docker cleanup has
    /// been explicitly verified. A different review may not bypass this hold.
    pub fn cleanup_hold_count(&self) -> Result<usize, String> {
        self.db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM native_worker_audit WHERE error_code IN (
                  'application_restarted_cleanup_unconfirmed',
                  'worker_cleanup_unconfirmed',
                  'worker_cancelled_cleanup_unconfirmed'
                 )",
                [],
                |row| row.get(0),
            )
            .map_err(err)
    }

    /// The public entrypoint always probes the configured Docker daemon. Take
    /// a snapshot of the exact unresolved audit IDs *before* the external
    /// probe: a second worker can report a fresh cleanup failure during the
    /// probe, and that later hold must never be cleared by an earlier result.
    pub fn verify_and_release_cleanup_hold(&self) -> Result<usize, String> {
        let observed = self.unconfirmed_cleanup_ids()?;
        if observed.is_empty() {
            return Ok(0);
        }
        crate::native_agent_workers::verify_no_leftover_containers()?;
        self.release_observed_cleanup_holds(&observed)
    }

    fn unconfirmed_cleanup_ids(&self) -> Result<Vec<i64>, String> {
        Self::unconfirmed_ids_on(self.db.connection())
    }

    fn unconfirmed_ids_on(connection: &Connection) -> Result<Vec<i64>, String> {
        let mut statement = connection
            .prepare(
                "SELECT id FROM native_worker_audit WHERE error_code IN (
                   'application_restarted_cleanup_unconfirmed',
                   'worker_cleanup_unconfirmed',
                   'worker_cancelled_cleanup_unconfirmed'
                 ) ORDER BY id",
            )
            .map_err(err)?;
        let rows = statement.query_map([], |row| row.get(0)).map_err(err)?;
        rows.collect::<Result<Vec<i64>, _>>().map_err(err)
    }

    /// All approval checks and the release are evaluated under one SQLite
    /// immediate writer transaction, so no concurrent audit commit can change
    /// the held set between the recheck and update.
    fn release_observed_cleanup_holds(&self, observed: &[i64]) -> Result<usize, String> {
        let tx = Transaction::new_unchecked(self.db.connection(), TransactionBehavior::Immediate)
            .map_err(err)?;
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM native_worker_audit WHERE status='running'",
                [],
                |row| row.get(0),
            )
            .map_err(err)?;
        if active != 0 {
            return Err("Cannot release cleanup hold while a worker is active".into());
        }
        if Self::unconfirmed_ids_on(&tx)? != observed {
            return Err(
                "Worker cleanup holds changed during Docker verification; probe again".into(),
            );
        }
        let updated = tx
            .execute(
                "UPDATE native_worker_audit
                 SET error_code=CASE error_code
                   WHEN 'application_restarted_cleanup_unconfirmed'
                     THEN 'application_restarted_cleanup_checked'
                   WHEN 'worker_cleanup_unconfirmed'
                     THEN 'worker_cleanup_checked'
                   WHEN 'worker_cancelled_cleanup_unconfirmed'
                     THEN 'worker_cancelled_cleanup_checked'
                 END
                 WHERE error_code IN (
                   'application_restarted_cleanup_unconfirmed',
                   'worker_cleanup_unconfirmed',
                   'worker_cancelled_cleanup_unconfirmed'
                 )",
                [],
            )
            .map_err(err)?;
        if updated != observed.len() {
            return Err("Worker cleanup holds changed during release; probe again".into());
        }
        tx.commit().map_err(err)?;
        Ok(updated)
    }

    // Only unit tests bypass the external Docker probe to exercise the
    // transaction itself. Production callers cannot invoke this shortcut.
    #[cfg(test)]
    fn release_after_confirmed_probe(&self) -> Result<usize, String> {
        self.release_observed_cleanup_holds(&self.unconfirmed_cleanup_ids()?)
    }

    pub fn latest(&self, run_id: &str) -> Result<Option<WorkerAuditRecord>, String> {
        Ok(self.list(run_id)?.into_iter().next())
    }
}

/// Recognize only our own fixed supervisor outcomes. Untrusted process
/// errors cannot inject arbitrary classifications or audit text.
fn cleanup_unconfirmed(reason: &str) -> bool {
    matches!(
        reason,
        "Worker stopped after authorization was revoked; container removal unconfirmed"
            | "Isolated scan timed out; Docker container removal could not be confirmed"
            | "Offline scanner exited unsuccessfully; container removal unconfirmed"
    )
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_records_failures_and_recovers_interrupted_workers() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.ts"), "export const a=1;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let run = agents.create(&project, "Review", 10, 120).unwrap();
        assert!(WorkerAudit::new(&db).begin(&run.id).is_err());
        agents.approve(&run.id).unwrap();
        let audit = WorkerAudit::new(&db);
        let id = audit.begin(&run.id).unwrap();
        audit
            .finish(id, &Err("secret path that must not persist".into()))
            .unwrap();
        assert_eq!(
            audit.list(&run.id).unwrap()[0].error_code.as_deref(),
            Some("worker_failed")
        );
        assert!(audit.finish(id, &Err("retry".into())).is_err());
        let cancelled = audit.begin(&run.id).unwrap();
        agents.cancel(&run.id).unwrap();
        audit
            .finish(cancelled, &Err("ignored raw worker output".into()))
            .unwrap();
        assert_eq!(
            audit
                .latest(&run.id)
                .unwrap()
                .unwrap()
                .error_code
                .as_deref(),
            Some("worker_cancelled")
        );
        // An already cancelled review must not start another worker.
        assert!(audit.begin(&run.id).is_err());
        // Restart recovery is checked on a separate approved review.
        let next = agents.create(&project, "Follow-up", 10, 120).unwrap();
        agents.approve(&next.id).unwrap();
        let unfinished = audit.begin(&next.id).unwrap();
        assert!(unfinished > cancelled);
        assert_eq!(audit.recover_interrupted().unwrap(), 1);
        assert_eq!(
            audit.latest(&next.id).unwrap().unwrap().status,
            "interrupted"
        );
    }
    #[test]
    fn a_review_cannot_claim_two_active_workers_or_a_queued_flow() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.ts"), "export const ok=true;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let run = agents.create(&project, "Local audit", 10, 120).unwrap();
        agents.approve(&run.id).unwrap();
        let audit = WorkerAudit::new(&db);
        let first = audit.begin(&run.id).unwrap();
        assert!(audit.begin(&run.id).is_err());
        assert!(agents.execute(&run.id).is_err());
        assert_eq!(audit.list(&run.id).unwrap().len(), 1);
        audit.finish(first, &Err("fixture failure".into())).unwrap();
        let second = audit.begin(&run.id).unwrap();
        audit
            .finish(second, &Err("fixture failure".into()))
            .unwrap();
        agents.cancel(&run.id).unwrap();

        // A review already added to the approved FIFO flow queue must not
        // separately launch an isolated scanner while it awaits dispatch.
        let planned = agents.create(&project, "Queued review", 10, 120).unwrap();
        crate::native_flow::NativeFlow::new(&db)
            .prepare(&planned.id)
            .unwrap();
        crate::native_flow::NativeFlow::new(&db)
            .approve(&planned.id)
            .unwrap();
        let overlapping = audit.begin(&planned.id).unwrap();
        assert!(crate::native_flow_queue::NativeFlowQueue::new(&db)
            .enqueue(&planned.id)
            .is_err());
        audit
            .finish(overlapping, &Err("fixture ended".into()))
            .unwrap();
        crate::native_flow_queue::NativeFlowQueue::new(&db)
            .enqueue(&planned.id)
            .unwrap();
        assert!(audit.begin(&planned.id).is_err());
        assert_eq!(audit.list(&planned.id).unwrap().len(), 1);
    }

    #[test]
    fn file_backed_restart_closes_worker_and_parent_without_replay() {
        let scratch = tempfile::tempdir().unwrap();
        let db_path = scratch.path().join("worker-crash.sqlite3");
        let source = scratch.path().join("indexed");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("safe.ts"), "export const yes=true;").unwrap();

        let (run_id, audit_id) = {
            let db = Database::open(&db_path).unwrap();
            let project = crate::ProjectIndexService::new(&db)
                .index_project(&source)
                .unwrap()
                .project_id;
            let agents = crate::native_agents::NativeAgents::new(&db);
            let review = agents.create(&project, "Authorized scan", 10, 120).unwrap();
            agents.approve(&review.id).unwrap();
            let ticket = WorkerAudit::new(&db).begin(&review.id).unwrap();
            (review.id, ticket)
        };

        let db = Database::open(&db_path).unwrap();
        let audit = WorkerAudit::new(&db);
        assert_eq!(audit.recover_interrupted().unwrap(), 1);
        let saved = audit.latest(&run_id).unwrap().unwrap();
        assert_eq!(saved.id, audit_id);
        assert_eq!(saved.status, "interrupted");
        assert_eq!(
            saved.error_code.as_deref(),
            Some("application_restarted_cleanup_unconfirmed")
        );
        assert!(saved.finished_at.is_some());
        assert!(saved.report_sha256.is_none());
        assert!(saved.vulnerability_count.is_none());
        let agents = crate::native_agents::NativeAgents::new(&db);
        let run = agents.get(&run_id).unwrap();
        assert_eq!(run.status, "interrupted");
        assert!(run.steps.iter().all(|step| step.status == "cancelled"));
        assert!(agents.execute(&run_id).is_err());
        assert!(audit.begin(&run_id).is_err());
        assert_eq!(audit.recover_interrupted().unwrap(), 0);

        // The previous review's unfinished approval must not lock its project.
        let replacement = agents
            .create(&run.project_id, "Fresh reviewed scope", 10, 120)
            .unwrap();
        agents.approve(&replacement.id).unwrap();
        // A fresh plan may be approved, but the abandoned Docker container
        // still needs a real cleanup verification before any new scan.
        assert_eq!(audit.cleanup_hold_count().unwrap(), 1);
        assert!(audit.begin(&replacement.id).is_err());
    }

    #[test]
    fn unconfirmed_cleanup_blocks_other_projects_until_verified() {
        let db = Database::open_in_memory().unwrap();
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        std::fs::write(first_root.path().join("one.ts"), "export const x=1;").unwrap();
        std::fs::write(second_root.path().join("two.ts"), "export const y=2;").unwrap();
        let first_project = crate::ProjectIndexService::new(&db)
            .index_project(first_root.path())
            .unwrap()
            .project_id;
        let second_project = crate::ProjectIndexService::new(&db)
            .index_project(second_root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let first = agents
            .create(&first_project, "First scan", 10, 120)
            .unwrap();
        agents.approve(&first.id).unwrap();
        let audit = WorkerAudit::new(&db);
        audit.begin(&first.id).unwrap();
        assert_eq!(audit.recover_interrupted().unwrap(), 1);
        assert_eq!(audit.cleanup_hold_count().unwrap(), 1);

        let second = agents
            .create(&second_project, "Second scan", 10, 120)
            .unwrap();
        agents.approve(&second.id).unwrap();
        assert!(audit.begin(&second.id).is_err());
        assert_eq!(audit.cleanup_hold_count().unwrap(), 1);
        // Explicit confirmation by the Docker probe is required before
        // changing the durable hold. These internal tests exercise only the
        // SQLite transition; the public method always performs the probe.
        assert_eq!(audit.release_after_confirmed_probe().unwrap(), 1);
        assert_eq!(audit.cleanup_hold_count().unwrap(), 0);
        assert_eq!(
            audit
                .latest(&first.id)
                .unwrap()
                .unwrap()
                .error_code
                .as_deref(),
            Some("application_restarted_cleanup_checked")
        );
        let ticket = audit.begin(&second.id).unwrap();
        audit
            .finish(ticket, &Err("fixture completed".into()))
            .unwrap();
        assert_eq!(audit.release_after_confirmed_probe().unwrap(), 0);
    }

    #[test]
    fn cleanup_probe_snapshot_rejects_new_unverified_worker_failure() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let first = agents.create(&project_id, "First worker", 10, 120).unwrap();
        agents.approve(&first.id).unwrap();
        let second = agents.create(&project_id, "Second worker", 10, 120).unwrap();
        agents.approve(&second.id).unwrap();

        let audit = WorkerAudit::new(&db);
        // Two independently approved workers are already active. The first
        // reports an unconfirmed cleanup, and an administrator starts a probe.
        let first_id = audit.begin(&first.id).unwrap();
        let second_id = audit.begin(&second.id).unwrap();
        let reason = "Offline scanner exited unsuccessfully; container removal unconfirmed";
        audit.finish(first_id, &Err(reason.into())).unwrap();
        let observed = audit.unconfirmed_cleanup_ids().unwrap();
        assert_eq!(observed, vec![first_id]);

        // While the external Docker probe runs, the second worker finishes
        // with another unresolved cleanup. An old empty-container result
        // must not clear this newly created hold or the previous one.
        audit.finish(second_id, &Err(reason.into())).unwrap();
        assert_eq!(audit.cleanup_hold_count().unwrap(), 2);
        assert!(audit
            .release_observed_cleanup_holds(&observed)
            .unwrap_err()
            .contains("changed during Docker verification"));
        assert_eq!(audit.cleanup_hold_count().unwrap(), 2);
        assert!(audit.begin(&first.id).is_err());

        // After a new probe covers both holds, the transaction can release
        // the exact observed set and preserves durable classification.
        let fresh = audit.unconfirmed_cleanup_ids().unwrap();
        assert_eq!(fresh, vec![first_id, second_id]);
        assert_eq!(audit.release_observed_cleanup_holds(&fresh).unwrap(), 2);
        assert_eq!(audit.cleanup_hold_count().unwrap(), 0);
    }

    #[test]
    fn verification_cannot_release_hold_while_a_worker_is_running() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let review = agents.create(&project, "Review", 10, 120).unwrap();
        agents.approve(&review.id).unwrap();
        let audit = WorkerAudit::new(&db);
        let ticket = audit.begin(&review.id).unwrap();
        assert!(audit.release_after_confirmed_probe().is_err());
        audit.finish(ticket, &Err("failed".into())).unwrap();
        assert_eq!(audit.release_after_confirmed_probe().unwrap(), 0);
    }

    #[test]
    fn rejected_success_after_cancellation_never_persists_findings() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.ts"), "export const ok=true;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let run = agents.create(&project, "Scope", 10, 120).unwrap();
        agents.approve(&run.id).unwrap();
        let audit = WorkerAudit::new(&db);
        let ticket = audit.begin(&run.id).unwrap();
        let receipt = IsolatedScanReceipt {
            run_id: run.id.clone(),
            image_digest: format!("scanner@sha256:{}", "a".repeat(64)),
            report_sha256: "b".repeat(64),
            vulnerability_count: 9,
            misconfiguration_count: 2,
            runtime_seconds: 1,
            warnings: Vec::new(),
        };
        agents.cancel(&run.id).unwrap();
        assert!(audit.finish(ticket, &Ok(receipt)).is_err());
        let record = audit.latest(&run.id).unwrap().unwrap();
        assert_eq!(record.status, "failed");
        assert_eq!(record.error_code.as_deref(), Some("worker_cancelled"));
        assert!(record.report_sha256.is_none());
        assert!(record.vulnerability_count.is_none());
    }

    #[test]
    fn mismatched_receipt_cannot_finish_another_reviews_audit() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.ts"), "export const test=1;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let run = agents.create(&project, "Scope", 10, 120).unwrap();
        agents.approve(&run.id).unwrap();
        let audit = WorkerAudit::new(&db);
        let ticket = audit.begin(&run.id).unwrap();
        let receipt = IsolatedScanReceipt {
            run_id: "different-review".into(),
            image_digest: format!("scanner@sha256:{}", "a".repeat(64)),
            report_sha256: "b".repeat(64),
            vulnerability_count: 1,
            misconfiguration_count: 0,
            runtime_seconds: 1,
            warnings: Vec::new(),
        };
        let mut outcome = Ok(receipt);
        assert!(audit.finish(ticket, &outcome).is_err());
        assert_eq!(audit.latest(&run.id).unwrap().unwrap().status, "running");
        outcome.as_mut().unwrap().run_id = run.id.clone();
        audit.finish(ticket, &outcome).unwrap();
        assert_eq!(audit.latest(&run.id).unwrap().unwrap().status, "success");
    }

    #[test]
    fn cleanup_failures_receive_fixed_audit_codes() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.ts"), "export const test=1;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = crate::native_agents::NativeAgents::new(&db);
        let run = agents.create(&project, "Scope", 10, 120).unwrap();
        agents.approve(&run.id).unwrap();
        let audit = WorkerAudit::new(&db);
        let ticket = audit.begin(&run.id).unwrap();
        audit
            .finish(
                ticket,
                &Err("Offline scanner exited unsuccessfully; container removal unconfirmed".into()),
            )
            .unwrap();
        assert_eq!(
            audit
                .latest(&run.id)
                .unwrap()
                .unwrap()
                .error_code
                .as_deref(),
            Some("worker_cleanup_unconfirmed")
        );
        // The unresolved first container must block all new worker claims.
        assert_eq!(audit.cleanup_hold_count().unwrap(), 1);
        assert!(audit.begin(&run.id).is_err());
        assert_eq!(audit.release_after_confirmed_probe().unwrap(), 1);
        let next = audit.begin(&run.id).unwrap();
        agents.cancel(&run.id).unwrap();
        audit
            .finish(
                next,
                &Err(
                    "Worker stopped after authorization was revoked; container removal unconfirmed"
                        .into(),
                ),
            )
            .unwrap();
        assert_eq!(
            audit
                .latest(&run.id)
                .unwrap()
                .unwrap()
                .error_code
                .as_deref(),
            Some("worker_cancelled_cleanup_unconfirmed")
        );
        assert!(!cleanup_unconfirmed(
            "untrusted error: container removal unconfirmed"
        ));
    }
}
