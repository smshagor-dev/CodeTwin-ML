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
    /// Derived from existing specialist steps; no duplicated mutable progress.
    pub completed_steps: usize,
    pub total_steps: usize,
    pub active_role: Option<String>,
    /// Every simultaneously running specialist in reviewed role order.
    /// These labels are read from SQLite; no results or source files included.
    pub active_roles: Vec<String>,
    pub review_status: String,
    /// First failed/interrupted specialist, or first cancelled specialist.
    /// Only the registered role and state are exposed, never analyzer output.
    pub issue_role: Option<String>,
    pub issue_status: Option<String>,
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
                   AND r.status='approved' AND r.cancel_requested=0
                   AND NOT EXISTS (
                     SELECT 1 FROM native_worker_audit
                     WHERE run_id=?1 AND status='running'
                   )",
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
                        q.started_at,q.finished_at,q.detail,
                        (SELECT COUNT(*) FROM native_agent_steps s
                         WHERE s.run_id=q.review_id AND s.status='completed'),
                        (SELECT COUNT(*) FROM native_agent_steps s
                         WHERE s.run_id=q.review_id),
                        (SELECT s.role FROM native_agent_steps s
                         WHERE s.run_id=q.review_id AND s.status='running'
                         ORDER BY s.position LIMIT 1),
                        r.status,
                        (SELECT GROUP_CONCAT(role, char(31)) FROM
                           (SELECT role FROM native_agent_steps
                            WHERE run_id=q.review_id AND status='running'
                            ORDER BY position)),
                        (SELECT s.role FROM native_agent_steps s
                         WHERE s.run_id=q.review_id
                           AND s.status IN ('failed','interrupted','cancelled')
                         ORDER BY CASE s.status
                           WHEN 'failed' THEN 0 WHEN 'interrupted' THEN 1
                           ELSE 2 END, s.position LIMIT 1),
                        (SELECT s.status FROM native_agent_steps s
                         WHERE s.run_id=q.review_id
                           AND s.status IN ('failed','interrupted','cancelled')
                         ORDER BY CASE s.status
                           WHEN 'failed' THEN 0 WHEN 'interrupted' THEN 1
                           ELSE 2 END, s.position LIMIT 1)
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
                        q.started_at,q.finished_at,q.detail,
                        (SELECT COUNT(*) FROM native_agent_steps s
                         WHERE s.run_id=q.review_id AND s.status='completed'),
                        (SELECT COUNT(*) FROM native_agent_steps s
                         WHERE s.run_id=q.review_id),
                        (SELECT s.role FROM native_agent_steps s
                         WHERE s.run_id=q.review_id AND s.status='running'
                         ORDER BY s.position LIMIT 1),
                        r.status,
                        (SELECT GROUP_CONCAT(role, char(31)) FROM
                           (SELECT role FROM native_agent_steps
                            WHERE run_id=q.review_id AND status='running'
                            ORDER BY position)),
                        (SELECT s.role FROM native_agent_steps s
                         WHERE s.run_id=q.review_id
                           AND s.status IN ('failed','interrupted','cancelled')
                         ORDER BY CASE s.status
                           WHEN 'failed' THEN 0 WHEN 'interrupted' THEN 1
                           ELSE 2 END, s.position LIMIT 1),
                        (SELECT s.status FROM native_agent_steps s
                         WHERE s.run_id=q.review_id
                           AND s.status IN ('failed','interrupted','cancelled')
                         ORDER BY CASE s.status
                           WHEN 'failed' THEN 0 WHEN 'interrupted' THEN 1
                           ELSE 2 END, s.position LIMIT 1)
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
        if !matches!(status, "completed" | "failed" | "cancelled" | "interrupted")
            || detail.len() > 240
        {
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
        // Completed, failed and cancelled receipts must agree with the
        // authoritative parent review. An execution-layer error may instead
        // leave an interrupted queue receipt for manual inspection.
        if status != "interrupted" && actual != status {
            return Err("Queue receipt does not match the reviewed flow status".into());
        }
        if status == "interrupted" && actual == "completed" {
            return Err("Cannot interrupt a flow with completed reviewed evidence".into());
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
        // If an execution-layer error happens after a queue claim but before
        // the supervisor starts, the parent may still be approved. Retire it
        // atomically with the queue receipt so it cannot execute on a retry.
        if status == "interrupted" {
            retire_aborted_review(&tx, review_id)?;
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
    /// queue runner must never auto-replay an action after restart. Recover
    /// legacy interrupted receipts whose parent remained approved as well.
    pub fn recover_interrupted(&self) -> Result<(), String> {
        let tx = self.db.connection().unchecked_transaction().map_err(err)?;
        let stranded = {
            let mut statement = tx
                .prepare(
                    "SELECT q.review_id FROM native_flow_queue q
                     JOIN native_agent_runs r ON r.id=q.review_id
                     WHERE q.status='running'
                        OR (q.status='interrupted'
                            AND r.status IN ('approved','running'))",
                )
                .map_err(err)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(err)?
        };
        for review_id in &stranded {
            retire_aborted_review(&tx, review_id)?;
        }
        tx.execute(
            "UPDATE native_flow_queue SET status='interrupted',
             finished_at=CURRENT_TIMESTAMP,
             detail='Desktop process stopped during queued execution'
             WHERE status='running'",
            [],
        )
        .map_err(err)?;
        tx.commit().map_err(err)
    }
}

/// An interrupted queue must never leave a runnable parent behind. This
/// executes inside the caller's transaction with its terminal queue receipt.
fn retire_aborted_review(tx: &rusqlite::Transaction<'_>, review_id: &str) -> Result<(), String> {
    let changed = tx
        .execute(
            "UPDATE native_agent_runs SET status='interrupted',cancel_requested=1,
             finished_at=CURRENT_TIMESTAMP,
             message='Approved queue execution interrupted; create a fresh review'
             WHERE id=?1 AND status IN ('approved','running')",
            [review_id],
        )
        .map_err(err)?;
    if changed != 0 {
        tx.execute(
            "UPDATE native_agent_steps
             SET status=CASE WHEN status='running' THEN 'interrupted'
                             ELSE 'cancelled' END,
                 finished_at=CURRENT_TIMESTAMP
             WHERE run_id=?1 AND status IN ('running','pending')",
            [review_id],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE native_action_log SET status='interrupted',
             finished_at=CURRENT_TIMESTAMP
             WHERE run_id=?1 AND status='running'",
            [review_id],
        )
        .map_err(err)?;
        tx.execute(
            "UPDATE native_delegation_tasks SET status='cancelled'
             WHERE run_id=?1 AND status IN ('pending','running')",
            [review_id],
        )
        .map_err(err)?;
    }
    Ok(())
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
        completed_steps: row.get(8)?,
        total_steps: row.get(9)?,
        active_role: row.get(10)?,
        review_status: row.get(11)?,
        active_roles: row
            .get::<_, Option<String>>(12)?
            .unwrap_or_default()
            .split('\u{1f}')
            .filter(|role| !role.is_empty())
            .map(str::to_string)
            .collect(),
        issue_role: row.get(13)?,
        issue_status: row.get(14)?,
    })
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{native_agents::NativeAgents, native_flow::NativeFlow, ProjectIndexService};

    fn cancellation_requested(db: &Database, review_id: &str) -> bool {
        db.connection()
            .query_row(
                "SELECT cancel_requested FROM native_agent_runs WHERE id=?1",
                [review_id],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
    }

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
    fn claimed_flow_cancellation_has_a_matching_terminal_receipt() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let id = approved(&db, &project);
        let queue = NativeFlowQueue::new(&db);
        queue.enqueue(&id).unwrap();
        queue.claim_next().unwrap().unwrap();

        NativeAgents::new(&db).cancel(&id).unwrap();
        assert!(queue.finish(&id, "failed", "incorrect status").is_err());
        assert!(queue.finish(&id, "completed", "incorrect status").is_err());
        queue
            .finish(&id, "cancelled", "Parent review was cancelled")
            .unwrap();
        let receipt = queue.get(&id).unwrap().unwrap();
        assert_eq!(receipt.status, "cancelled");
        assert!(receipt.finished_at.is_some());
        assert!(queue.claim_next().unwrap().is_none());
    }

    #[test]
    fn an_unclaimed_queue_item_cannot_run_through_the_native_review_path() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let id = approved(&db, &project);
        let queue = NativeFlowQueue::new(&db);
        queue.enqueue(&id).unwrap();

        assert!(NativeAgents::new(&db).execute(&id).is_err());
        assert_eq!(NativeAgents::new(&db).get(&id).unwrap().status, "approved");
        assert_eq!(queue.get(&id).unwrap().unwrap().status, "queued");

        queue.claim_next().unwrap().unwrap();
        assert_eq!(
            NativeAgents::new(&db).execute(&id).unwrap().status,
            "completed"
        );
        queue
            .finish(&id, "completed", "Reviewed evidence committed")
            .unwrap();
    }

    #[test]
    fn queue_progress_tracks_durable_steps_without_changing_the_flow() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("progress.sqlite3");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("safe.rs"), "pub fn safe() {}").unwrap();
        let id = {
            let db = Database::open(&path).unwrap();
            let project = ProjectIndexService::new(&db)
                .index_project(&source)
                .unwrap()
                .project_id;
            let id = approved(&db, &project);
            let queue = NativeFlowQueue::new(&db);
            let initial = queue.enqueue(&id).unwrap();
            assert_eq!(initial.completed_steps, 0);
            assert_eq!(initial.total_steps, 2);
            assert!(initial.active_role.is_none());
            assert_eq!(initial.review_status, "approved");
            queue.claim_next().unwrap().unwrap();

            // Simulate an in-progress specialist snapshot between boundaries.
            db.connection()
                .execute(
                    "UPDATE native_agent_steps
                     SET status='completed' WHERE run_id=?1 AND position=0",
                    [&id],
                )
                .unwrap();
            db.connection()
                .execute(
                    "UPDATE native_agent_steps
                     SET status='running' WHERE run_id=?1 AND position=1",
                    [&id],
                )
                .unwrap();
            let snapshot = queue.get(&id).unwrap().unwrap();
            assert_eq!(snapshot.completed_steps, 1);
            assert_eq!(snapshot.total_steps, 2);
            // Roles are user-facing specialist labels (e.g. Source Auditor),
            // whereas the registered tool key is "source".
            let label: String = db
                .connection()
                .query_row(
                    "SELECT role FROM native_agent_steps
                     WHERE run_id=?1 AND position=1 AND tool='source'",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(snapshot.active_role.as_deref(), Some(label.as_str()));
            assert!(snapshot.issue_role.is_none());
            assert!(snapshot.issue_status.is_none());

            // A failed specialist becomes visible without exposing its report.
            db.connection()
                .execute(
                    "UPDATE native_agent_steps SET status='failed'
                     WHERE run_id=?1 AND position=1",
                    [&id],
                )
                .unwrap();
            let failure = queue.get(&id).unwrap().unwrap();
            assert_eq!(failure.issue_role.as_deref(), Some(label.as_str()));
            assert_eq!(failure.issue_status.as_deref(), Some("failed"));
            assert!(failure.active_role.is_none());

            // Restore the fixture before executing the real Rust review.
            db.connection()
                .execute(
                    "UPDATE native_agent_steps
                     SET status='pending' WHERE run_id=?1",
                    [&id],
                )
                .unwrap();
            let completed = NativeAgents::new(&db).execute(&id).unwrap();
            assert_eq!(completed.status, "completed");
            queue
                .finish(&id, "completed", "Reviewed evidence committed")
                .unwrap();
            id
        };
        // Progress is read from persisted SQLite state after closing the first DB.
        let db = Database::open(&path).unwrap();
        let saved = NativeFlowQueue::new(&db).get(&id).unwrap().unwrap();
        assert_eq!(saved.status, "completed");
        assert_eq!(saved.review_status, "completed");
        assert_eq!(saved.completed_steps, saved.total_steps);
        assert_eq!(saved.total_steps, 2);
        assert!(saved.active_role.is_none());
        assert!(saved.issue_role.is_none());
        assert!(saved.issue_status.is_none());
    }

    #[test]
    fn sqlite_queue_progress_exposes_both_concurrent_roles_and_failures() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let run = NativeAgents::new(&db)
            .create_with_roles(
                &project,
                "Concurrent approved review",
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
        NativeFlow::new(&db).prepare(&run.id).unwrap();
        NativeFlow::new(&db).approve(&run.id).unwrap();
        let queue = NativeFlowQueue::new(&db);
        queue.enqueue(&run.id).unwrap();
        queue.claim_next().unwrap().unwrap();

        // Two separately claimed native specialists are visible at once.
        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='running'
                 WHERE run_id=?1 AND position IN (2,3)",
                [&run.id],
            )
            .unwrap();
        let current = queue.get(&run.id).unwrap().unwrap();
        assert_eq!(current.active_role.as_deref(), Some("Secrets Auditor"));
        assert_eq!(
            current.active_roles,
            vec!["Secrets Auditor", "Test Researcher"]
        );
        assert_eq!(queue.list().unwrap()[0].active_roles, current.active_roles);
        assert_eq!(current.total_steps, 4);

        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='failed'
                 WHERE run_id=?1 AND position=2",
                [&run.id],
            )
            .unwrap();
        let failed = queue.get(&run.id).unwrap().unwrap();
        assert_eq!(failed.active_roles, vec!["Test Researcher"]);
        assert_eq!(failed.issue_role.as_deref(), Some("Secrets Auditor"));
        assert_eq!(failed.issue_status.as_deref(), Some("failed"));

        db.connection()
            .execute(
                "UPDATE native_agent_steps SET status='interrupted'
                 WHERE run_id=?1 AND position=3",
                [&run.id],
            )
            .unwrap();
        assert!(queue.get(&run.id).unwrap().unwrap().active_roles.is_empty());
    }

    #[test]
    fn interrupted_claim_retires_approval_without_dispatching_tools() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.rs"), "pub fn safe() {}").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let id = approved(&db, &project);
        let queue = NativeFlowQueue::new(&db);
        queue.enqueue(&id).unwrap();
        queue.claim_next().unwrap().unwrap();

        // The external Go preflight fails after the claim, before any step.
        queue
            .finish(&id, "interrupted", "Go policy verification unavailable")
            .unwrap();
        let receipt = queue.get(&id).unwrap().unwrap();
        assert_eq!(receipt.status, "interrupted");
        assert_eq!(receipt.review_status, "interrupted");
        assert_eq!(receipt.completed_steps, 0);
        assert!(receipt.finished_at.is_some());
        let run = NativeAgents::new(&db).get(&id).unwrap();
        assert!(cancellation_requested(&db, &id));
        assert!(run.steps.iter().all(|step| step.status == "cancelled"));
        assert!(NativeAgents::new(&db).execute(&id).is_err());
        assert!(queue
            .finish(&id, "completed", "cannot finish twice")
            .is_err());
        assert!(queue.claim_next().unwrap().is_none());

        // The interrupted approval does not lock a fresh reviewed plan.
        let replacement = approved(&db, &project);
        assert_ne!(replacement, id);
        assert_eq!(
            NativeAgents::new(&db).get(&replacement).unwrap().status,
            "approved"
        );
    }

    #[test]
    fn legacy_interrupted_receipt_cannot_be_replayed_and_is_reconciled() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("safe.ts"), "export const ok = true;").unwrap();
        let project = ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let id = approved(&db, &project);
        let queue = NativeFlowQueue::new(&db);
        queue.enqueue(&id).unwrap();
        queue.claim_next().unwrap().unwrap();

        // Old desktop versions could record an interrupted queue but leave the
        // parent approved. The direct-run guard protects the legacy DB even
        // before the recovery routine reconciles it.
        db.connection()
            .execute(
                "UPDATE native_flow_queue SET status='interrupted'
                 WHERE review_id=?1 AND status='running'",
                [&id],
            )
            .unwrap();
        assert_eq!(NativeAgents::new(&db).get(&id).unwrap().status, "approved");
        assert!(NativeAgents::new(&db).execute(&id).is_err());

        queue.recover_interrupted().unwrap();
        assert_eq!(
            NativeAgents::new(&db).get(&id).unwrap().status,
            "interrupted"
        );
        assert_eq!(queue.get(&id).unwrap().unwrap().status, "interrupted");
        queue.recover_interrupted().unwrap();
        assert_eq!(
            NativeAgents::new(&db).get(&id).unwrap().status,
            "interrupted"
        );
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
        assert_eq!(receipt.review_status, "interrupted");
        assert_eq!(receipt.completed_steps, 0);
        let original = NativeAgents::new(&db).get(&id).unwrap();
        assert!(cancellation_requested(&db, &id));
        assert!(original.steps.iter().all(|step| step.status == "cancelled"));
        assert!(NativeAgents::new(&db).execute(&id).is_err());
        assert!(queue.claim_next().unwrap().is_none());
        assert!(queue.enqueue(&id).is_err());
        queue.recover_interrupted().unwrap();
        assert_eq!(queue.get(&id).unwrap().unwrap().status, "interrupted");

        // Unfinished approvals can no longer block a fresh explicit approval
        // for the same indexed project after the desktop is restarted.
        let project = ProjectIndexService::new(&db)
            .index_project(&source)
            .unwrap()
            .project_id;
        let fresh = approved(&db, &project);
        assert_ne!(fresh, id);
    }
}
