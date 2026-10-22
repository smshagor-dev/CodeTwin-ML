//! Project-scoped review memory with evidence provenance only.
//! Never store source bytes, secrets, raw tool output, or model-generated claims.
use crate::Database;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

const MAX_HISTORY: i64 = 500;
const MAX_SEARCH: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub project_id: String,
    pub run_id: String,
    pub position: usize,
    pub role: String,
    pub tool: String,
    pub status: String,
    pub created_at: String,
}

pub struct AgentMemory<'a> {
    db: &'a Database,
}

impl<'a> AgentMemory<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Snapshot only the role/status/provenance of a finished review.
    /// Idempotent even if a worker retries recording after a database busy error.
    pub fn record_run(&self, run_id: &str) -> Result<usize, String> {
        let run: Option<(String, String)> = self
            .db
            .connection()
            .query_row(
                "SELECT project_id,status FROM native_agent_runs WHERE id=?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(to_error)?;
        let (project_id, status) = run.ok_or("Review not found")?;
        if !matches!(status.as_str(), "completed" | "failed" | "cancelled" | "interrupted") {
            return Err("Only finished reviews can be saved to memory".into());
        }
        let transaction = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(to_error)?;
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO native_agent_memory(project_id,run_id,position,role,tool,status)
             SELECT r.project_id,s.run_id,s.position,s.role,s.tool,s.status
             FROM native_agent_steps s JOIN native_agent_runs r ON r.id=s.run_id
             WHERE s.run_id=?1 AND s.status IN ('completed','failed')
             AND r.status IN ('completed','failed','cancelled','interrupted')",
            [run_id],
        ).map_err(to_error)?;
        transaction.execute(
            "DELETE FROM native_agent_memory
             WHERE rowid IN (SELECT rowid FROM native_agent_memory
                 WHERE project_id=?1 ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET ?2)",
            params![project_id,MAX_HISTORY],
        ).map_err(to_error)?;
        transaction.commit().map_err(to_error)?;
        Ok(changed)
    }

    pub fn search(&self, project_id: &str, query: &str, limit: usize) -> Result<Vec<MemoryEntry>, String> {
        if project_id.trim().is_empty() || project_id.len() > 256 {
            return Err("Select a valid project".into());
        }
        if query.len() > 120 {
            return Err("Search must be 120 bytes or fewer".into());
        }
        let escaped = query.trim().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let limit = limit.clamp(1, MAX_SEARCH) as i64;
        let mut statement = self.db.connection().prepare(
            "SELECT project_id,run_id,position,role,tool,status,created_at
             FROM native_agent_memory
             WHERE project_id=?1 AND (role LIKE ?2 ESCAPE '\\'
                                  OR tool LIKE ?2 ESCAPE '\\'
                                  OR status LIKE ?2 ESCAPE '\\'
                                  OR run_id LIKE ?2 ESCAPE '\\')
             ORDER BY created_at DESC,rowid DESC LIMIT ?3",
        ).map_err(to_error)?;
        let results = statement.query_map(params![project_id,pattern,limit], |row| {
            Ok(MemoryEntry {
                project_id: row.get(0)?,
                run_id: row.get(1)?,
                position: row.get(2)?,
                role: row.get(3)?,
                tool: row.get(4)?,
                status: row.get(5)?,
                created_at: row.get(6)?,
            })
        }).map_err(to_error)?
            .collect::<Result<Vec<_>, _>>().map_err(to_error)?;
        Ok(results)
    }

    /// Explicit user action, scoped to one project. The original review history remains intact.
    pub fn clear(&self, project_id: &str) -> Result<usize, String> {
        if project_id.is_empty() || project_id.len() > 256 {
            return Err("Select a valid project".into());
        }
        self.db.connection().execute(
            "DELETE FROM native_agent_memory WHERE project_id=?1",
            [project_id],
        ).map_err(to_error)
    }
}

fn to_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_project_scoped_idempotent_and_deletable() {
        let db = Database::open_in_memory().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let a = fixture.path().join("a");
        let b = fixture.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("a.ts"), "export const a=1;").unwrap();
        std::fs::write(b.join("b.ts"), "export const b=1;").unwrap();
        let a_id = crate::ProjectIndexService::new(&db).index_project(&a).unwrap().project_id;
        let b_id = crate::ProjectIndexService::new(&db).index_project(&b).unwrap().project_id;
        let run = crate::native_agents::NativeAgents::new(&db)
            .create(&a_id, "Review", 10, 300).unwrap();
        let store = AgentMemory::new(&db);
        assert!(store.record_run(&run.id).is_err());
        db.connection().execute(
            "UPDATE native_agent_steps SET status='completed' WHERE run_id=?1 AND position=0",
            [&run.id],
        ).unwrap();
        db.connection().execute(
            "UPDATE native_agent_runs SET status='completed' WHERE id=?1",
            [&run.id],
        ).unwrap();
        assert_eq!(store.record_run(&run.id).unwrap(), 1);
        assert_eq!(store.record_run(&run.id).unwrap(), 0);
        assert_eq!(store.search(&a_id, "Recon", 50).unwrap().len(), 1);
        assert!(store.search(&a_id, "Rec_n", 50).unwrap().is_empty());
        assert!(store.search(&b_id, "", 50).unwrap().is_empty());
        assert_eq!(store.clear(&b_id).unwrap(), 0);
        assert_eq!(store.clear(&a_id).unwrap(), 1);
        assert!(store.search(&a_id, "", 50).unwrap().is_empty());
    }
}
