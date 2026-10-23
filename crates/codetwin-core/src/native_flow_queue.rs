//! Bounded, durable SQLite queue for *separately approved* passive flows.
//! Queue claims do not grant review approval or execute arbitrary tools.
use crate::Database;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedFlow {
    pub id: i64,
    pub review_id: String,
    pub project_id: String,
    pub status: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub detail: String,
}

pub struct NativeFlowQueue<'a> {
    db: &'a Database,
}

impl<'a> NativeFlowQueue<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// A queued item must refer to an existing, explicitly approved flow.
    /// At most eight unfinished items are permitted per desktop profile.
    pub fn enqueue(&self, review_id: &str) -> Result<QueuedFlow, String> {
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let waiting: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM native_flow_queue WHERE status IN ('queued','running')",
                [],
                |row| row.get(0),
            )
            .map_err(err)?;
        if waiting >= 8 {
            return Err("At most eight approved flows may be queued".into());
        }
        let inserted = tx
            .execute(
                "INSERT INTO native_flow_queue(review_id)
                 SELECT f.review_id FROM native_security_flows f
                 JOIN native_agent_runs r ON r.id=f.review_id
                 WHERE f.review_id=?1 AND f.approved_at IS NOT NULL
                   AND r.status='approved' AND r.cancel_requested=0",
                [review_id],
            )
            .map_err(err)?;
        if inserted != 1 {
            return Err("A separate flow approval is required before queuing".into());
        }
        tx.commit().map_err(err)?;
        self.get(review_id)?.ok_or("Queued flow not found".into())
    }

    pub fn get(&self, review_id: &str) -> Result<Option<QueuedFlow>, String> {
        self.db
            .connection()
            .query_row(
                "SELECT q.id,q.review_id,r.project_id,q.status,q.created_at,
                        q.started_at,q.finished_at,q.detail
                 FROM native_flow_queue q
                 JOIN native_agent_runs r ON r.id=q.review_id
                 WHERE q.review_id=?1",
                [review_id],
                decode,
            )
            .optional()
            .map_err(err)
    }

    pub fn list(&self) -> Result<Vec<QueuedFlow>, String> {
        let mut statement = self
            .db
            .connection()
            .prepare(
                "SELECT q.id,q.review_id,r.project_id,q.status,q.created_at,
                        q.started_at,q.finished_at,q.detail
                 FROM native_flow_queue q
                 JOIN native_agent_runs r ON r.id=q.review_id
                 ORDER BY q.id DESC LIMIT 64",
            )
            .map_err(err)?;
        let rows = statement.query_map([], decode).map_err(err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(err)
    }

    /// Claim exactly one FIFO item in a transaction. Never dispatch a second
    /// flow while the previous one is active or after a restart. No queued
    /// item can circumvent its parent review's explicit approval.
    pub fn claim_next(&self) -> Result<Option<QueuedFlow>, String> {
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let already_running: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM native_flow_queue WHERE status='running'",
                [],
                |row| row.get(0),
            )
            .map_err(err)?;
        if already_running != 0 {
            return Err("Another approved flow is already executing".into());
        }
        // A flow may be cancelled using the normal review controls while
        // queued; retire it without ever attempting to run its tools.
        tx.execute(
            "UPDATE native_flow_queue
             SET status='cancelled',finished_at=CURRENT_TIMESTAMP,
                 detail='Parent review was cancelled or changed before dispatch'
             WHERE status='queued' AND NOT EXISTS (
               SELECT 1 FROM native_agent_runs r
               JOIN native_security_flows f ON f.review_id=r.id
               WHERE r.id=native_flow_queue.review_id AND r.status='approved'
                 AND r.cancel_requested=0 AND f.approved_at IS NOT NULL
             )",
            [],
        )
        .map_err(err)?;
        let next: Option<String> = tx
            .query_row(
                "SELECT review_id FROM native_flow_queue
                 WHERE status='queued' ORDER BY id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(err)?;
        let Some(id) = next else {
            tx.commit().map_err(err)?;
            return Ok(None);
        };
        let claimed = tx
            .execute(
                "UPDATE native_flow_queue SET status='running',started_at=CURRENT_TIMESTAMP
                 WHERE review_id=?1 AND status='queued'",
                [&id],
            )
            .map_err(err)?;
        if claimed != 1 {
            return Err("Approved flow queue changed before dispatch".into());
        }
        tx.commit().map_err(err)?;
        self.get(&id)?
            .ok_or("Claimed flow not found".into())
            .map(Some)
    }

    pub fn finish(&self, review_id: &str, status: &str, detail: &str) -> Result<(), String> {
        if !matches!(status, "completed" | "failed" | "interrupted") || detail.len() > 240 {
            return Err("Invalid terminal flow receipt".into());
        }
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let actual: String = tx
            .query_row(
                "SELECT status FROM native_agent_runs WHERE id=?1",
                [review_id],
                |row| row.get(0),
            )
            .map_err(err)?;
        // The queue cannot report success if the reviewed flow failed. An
        // unexpected Rust execution error is recorded as interrupted.
        if status == "completed" && actual != "completed" {
            return Err("Cannot complete a flow without completed reviewed evidence".into());
        }
        let changed = tx
            .execute(
                "UPDATE native_flow_queue SET status=?2,finished_at=CURRENT_TIMESTAMP,
                 detail=?3 WHERE review_id=?1 AND status='running'",
                params![review_id, status, detail],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Flow queue item was not executing".into());
        }
        tx.commit().map_err(err)
    }

    pub fn cancel_queued(&self, review_id: &str) -> Result<(), String> {
        let changed = self
            .db
            .connection()
            .execute(
                "UPDATE native_flow_queue SET status='cancelled',
                 finished_at=CURRENT_TIMESTAMP,detail='Removed from approved flow queue'
                 WHERE review_id=?1 AND status='queued'",
                [review_id],
            )
            .map_err(err)?;
        if changed != 1 {
            return Err("Only a waiting flow can be removed from the queue".into());
        }
        Ok(())
    }

    /// Called on desktop startup, *after* native review recovery. A killed
    /// queue runner must never auto-replay an action after restart.
    pub fn recover_interrupted(&self) -> Result<(), String> {
        self.db
            .connection()
            .execute(
                "UPDATE native_flow_queue SET status='interrupted',
                 finished_at=CURRENT_TIMESTAMP,
                 detail='Desktop process stopped during queued execution'
                 WHERE status='running'",
                [],
            )
            .map_err(err)?;
        Ok(())
    }
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueuedFlow> {
    Ok(QueuedFlow {
        id: row.get(0)?,
        review_id: row.get(1)?,
        project_id: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        started_at: row.get(5)?,
        finished_at: row.get(6)?,
        detail: row.get(7)?,
    })
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{native_agents::NativeAgents, native_flow::NativeFlow, ProjectIndexService};

    fn approved(db: &Database, project: &str) -> String {
        let review = NativeAgents::new(db)
            .create_with_roles(
                project,
                "Review indexed local source",
                10,
                180,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        NativeFlow::new(db).prepare(&review.id).unwrap();
        NativeFlow::new(db).approve(&review.id).unwrap();
        review.id
    }

    #[test]
    fn multiple_approved_flows_are_fifo_and_never_double_claimed() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let second_root = tempfile::tempdir().unwrap();
        std::fs::write(second_root.path().join("other.rs"), "pub fn other() {}").unwrap();
        let second_project = ProjectIndexService::new(&db)
            .index_project(second_root.path())
            .unwrap()
            .project_id;
        let first = approved(&db, &project);
        let second = approved(&db, &second_project);
        let queue = NativeFlowQueue::new(&db);
        queue.enqueue(&first).unwrap();
        queue.enqueue(&second).unwrap();
        assert!(queue.enqueue(&first).is_err());
        let claimed = queue.claim_next().unwrap().unwrap();
        assert_eq!(claimed.review_id, first);
        assert!(queue.claim_next().is_err());
        assert!(queue.finish(&first, "completed", "No evidence").is_err());
        let outcome = NativeAgents::new(&db).execute(&first).unwrap();
        assert_eq!(outcome.status, "completed");
        queue
            .finish(&first, "completed", "Reviewed evidence committed")
            .unwrap();
        assert_eq!(queue.claim_next().unwrap().unwrap().review_id, second);
        assert!(queue.cancel_queued(&second).is_err());
        let outcome = NativeAgents::new(&db).execute(&second).unwrap();
        assert_eq!(outcome.status, "completed");
        queue
            .finish(&second, "completed", "Reviewed evidence committed")
            .unwrap();
        assert!(queue.claim_next().unwrap().is_none());
        assert_eq!(queue.list().unwrap().len(), 2);
    }

    #[test]
    fn unapproved_or_cancelled_flows_never_enter_execution_queue() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let planned = NativeAgents::new(&db)
            .create_with_roles(
                &project,
                "Unapproved review",
                10,
                180,
                &["scout".into(), "source".into()],
            )
            .unwrap();
        NativeFlow::new(&db).prepare(&planned.id).unwrap();
        let queue = NativeFlowQueue::new(&db);
        assert!(queue.enqueue(&planned.id).is_err());
        let allowed = approved(&db, &project);
        queue.enqueue(&allowed).unwrap();
        NativeAgents::new(&db).cancel(&allowed).unwrap();
        assert!(queue.claim_next().unwrap().is_none());
        assert_eq!(queue.get(&allowed).unwrap().unwrap().status, "cancelled");
        assert!(queue.enqueue(&allowed).is_err());
    }

    #[test]
    fn restart_interrupts_active_queue_without_replaying() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("flows.sqlite3");
        let source = temp.path().join("indexed");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("safe.ts"), "export const yes = true;").unwrap();
        let id = {
            let db = Database::open(&path).unwrap();
            let project = ProjectIndexService::new(&db)
                .index_project(&source)
                .unwrap()
                .project_id;
            let id = approved(&db, &project);
            let queue = NativeFlowQueue::new(&db);
            queue.enqueue(&id).unwrap();
            queue.claim_next().unwrap().unwrap();
            id
        };
        let db = Database::open(&path).unwrap();
        NativeAgents::new(&db).recover_interrupted().unwrap();
        NativeFlowQueue::new(&db).recover_interrupted().unwrap();
        let queue = NativeFlowQueue::new(&db);
        let receipt = queue.get(&id).unwrap().unwrap();
        assert_eq!(receipt.status, "interrupted");
        assert!(queue.claim_next().unwrap().is_none());
        assert!(queue.enqueue(&id).is_err());
        queue.recover_interrupted().unwrap();
        assert_eq!(queue.get(&id).unwrap().unwrap().status, "interrupted");
    }
}
