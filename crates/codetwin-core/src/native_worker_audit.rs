//! Durable, privacy-reduced local audit for separately authorized container workers.
use crate::{native_agent_workers::IsolatedScanReceipt, Database};
use rusqlite::{params, OptionalExtension};
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
        self.db
            .connection()
            .execute(
                "INSERT INTO native_worker_audit(run_id) VALUES(?1)",
                [run_id],
            )
            .map_err(err)?;
        Ok(self.db.connection().last_insert_rowid())
    }

    pub fn finish(
        &self,
        audit_id: i64,
        outcome: &Result<IsolatedScanReceipt, String>,
    ) -> Result<(), String> {
        let changed = match outcome {
            Ok(receipt) => self
                .db
                .connection()
                .execute(
                    "UPDATE native_worker_audit SET status='success',image_digest=?2,
                 report_sha256=?3,vulnerability_count=?4,misconfiguration_count=?5,
                 finished_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'",
                    params![
                        audit_id,
                        receipt.image_digest,
                        receipt.report_sha256,
                        receipt.vulnerability_count,
                        receipt.misconfiguration_count
                    ],
                )
                .map_err(err)?,
            Err(_) => self
                .db
                .connection()
                .execute(
                    "UPDATE native_worker_audit SET status='failed',error_code='worker_failed',
                 finished_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'",
                    [audit_id],
                )
                .map_err(err)?,
        };
        if changed != 1 {
            return Err("Worker audit cannot be finalized twice".into());
        }
        Ok(())
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
        statement
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
            .map_err(err)
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
        let unfinished = audit.begin(&run.id).unwrap();
        assert!(unfinished > id);
        assert_eq!(audit.recover_interrupted().unwrap(), 1);
        assert_eq!(
            audit.latest(&run.id).unwrap().unwrap().status,
            "interrupted"
        );
    }
}
