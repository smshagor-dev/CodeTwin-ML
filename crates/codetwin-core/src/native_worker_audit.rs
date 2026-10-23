//! Durable, privacy-reduced local audit for separately authorized container workers.
use crate::{native_agent_workers::IsolatedScanReceipt, Database};
use rusqlite::params;
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
                 WHERE id=?1 AND status='approved' AND cancel_requested=0",
                [run_id],
            )
            .map_err(err)?;
        if inserted != 1 {
            return Err("Worker authorization was revoked before starting".into());
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

    pub fn recover_interrupted(&self) -> Result<usize, String> {
        self.db
            .connection()
            .execute(
                "UPDATE native_worker_audit SET status='interrupted',
             error_code='application_restarted',finished_at=CURRENT_TIMESTAMP
             WHERE status='running'",
                [],
            )
            .map_err(err)
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
        let mut receipt = IsolatedScanReceipt {
            run_id: "different-review".into(),
            image_digest: format!("scanner@sha256:{}", "a".repeat(64)),
            report_sha256: "b".repeat(64),
            vulnerability_count: 1,
            misconfiguration_count: 0,
            runtime_seconds: 1,
            warnings: Vec::new(),
        };
        assert!(audit.finish(ticket, &Ok(receipt)).is_err());
        assert_eq!(audit.latest(&run.id).unwrap().unwrap().status, "running");
        receipt.run_id = run.id.clone();
        audit.finish(ticket, &Ok(receipt)).unwrap();
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
        audit.finish(
            ticket,
            &Err("Offline scanner exited unsuccessfully; container removal unconfirmed".into()),
        ).unwrap();
        assert_eq!(
            audit.latest(&run.id).unwrap().unwrap().error_code.as_deref(),
            Some("worker_cleanup_unconfirmed")
        );
        let next = audit.begin(&run.id).unwrap();
        agents.cancel(&run.id).unwrap();
        audit.finish(
            next,
            &Err("Worker stopped after authorization was revoked; container removal unconfirmed".into()),
        ).unwrap();
        assert_eq!(
            audit.latest(&run.id).unwrap().unwrap().error_code.as_deref(),
            Some("worker_cancelled_cleanup_unconfirmed")
        );
        assert!(!cleanup_unconfirmed("untrusted error: container removal unconfirmed"));
    }

}
