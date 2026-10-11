//! Revision-bound passive assessments. Active network and external execution adapters are excluded.
use crate::{CodeQualityService, CodeSecurityService, Database};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentPlanRequest {
    pub project_id: String,
    pub tools: Vec<String>,
    pub max_files: usize,
    pub budget_seconds: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct AssessmentStep {
    pub position: usize,
    pub tool_id: String,
    pub status: String,
    pub run_id: Option<String>,
    pub coverage_complete: Option<bool>,
}
#[derive(Debug, Clone, Serialize)]
pub struct AssessmentJob {
    pub id: String,
    pub project_id: String,
    pub scope_revision: i64,
    pub root_path: String,
    pub input_hash: String,
    pub file_count: usize,
    pub max_files: usize,
    pub budget_seconds: u64,
    pub definition_version: usize,
    pub status: String,
    pub cancel_requested: bool,
    pub message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub steps: Vec<AssessmentStep>,
}

pub struct AssessmentJobs<'a> {
    database: &'a Database,
}
impl<'a> AssessmentJobs<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    /// A new saved plan creates a scope revision and supersedes older unstarted plans.
    pub fn create_plan(&self, request: AssessmentPlanRequest) -> Result<AssessmentJob, String> {
        if !(1..=2000).contains(&request.max_files) || !(1..=3600).contains(&request.budget_seconds)
        {
            return Err("file budget must be 1–2000; time budget must be 1–3600 seconds".into());
        }
        if request.tools.is_empty()
            || request.tools.len() > 2
            || request
                .tools
                .iter()
                .any(|id| id != "code.sast" && id != "code.quality")
            || (request.tools.len() == 2 && request.tools[0] == request.tools[1])
        {
            return Err(
                "select unique supported passive tools: code.sast and/or code.quality".into(),
            );
        }
        let (root, hash, file_count) = self.snapshot(&request.project_id, request.max_files)?;
        let connection = self.database.connection();
        let tx = connection.unchecked_transaction().map_err(err)?;
        let running: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM assessment_jobs WHERE project_id=?1 AND status='running')", [&request.project_id], |r| r.get(0)).map_err(err)?;
        if running {
            return Err("cannot revise scope while an assessment is running".into());
        }
        let revision: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(revision),0)+1 FROM assessment_scopes WHERE project_id=?1",
                [&request.project_id],
                |r| r.get(0),
            )
            .map_err(err)?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(err)?
            .as_nanos()
            .to_string();
        let id = crate::deterministic_id(
            "assessment",
            &[&request.project_id, &revision.to_string(), &nonce],
        );
        tx.execute("INSERT INTO assessment_scopes(project_id,revision,root_path,input_hash,file_count,max_files,budget_seconds) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![request.project_id,revision,root,hash,file_count,request.max_files,request.budget_seconds]).map_err(err)?;
        tx.execute(
            "INSERT INTO assessment_jobs(id,project_id,scope_revision) VALUES(?1,?2,?3)",
            params![id, request.project_id, revision],
        )
        .map_err(err)?;
        for (position, tool) in request.tools.iter().enumerate() {
            tx.execute(
                "INSERT INTO assessment_steps(job_id,position,tool_id) VALUES(?1,?2,?3)",
                params![id, position, tool],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        self.get(&id)
    }

    pub fn get(&self, id: &str) -> Result<AssessmentJob, String> {
        let mut job = self.database.connection().query_row(
            "SELECT j.id,j.project_id,j.scope_revision,s.root_path,s.input_hash,s.file_count,s.max_files,s.budget_seconds,j.definition_version,j.status,j.cancel_requested,j.message,j.created_at,j.started_at,j.finished_at FROM assessment_jobs j JOIN assessment_scopes s ON s.project_id=j.project_id AND s.revision=j.scope_revision WHERE j.id=?1", [id],
            |r| Ok(AssessmentJob { id:r.get(0)?,project_id:r.get(1)?,scope_revision:r.get(2)?,root_path:r.get(3)?,input_hash:r.get(4)?,file_count:r.get(5)?,max_files:r.get(6)?,budget_seconds:r.get(7)?,definition_version:r.get(8)?,status:r.get(9)?,cancel_requested:r.get(10)?,message:r.get(11)?,created_at:r.get(12)?,started_at:r.get(13)?,finished_at:r.get(14)?,steps:vec![] }),
        ).optional().map_err(err)?.ok_or("assessment not found")?;
        let mut statement = self.database.connection().prepare("SELECT position,tool_id,status,run_id,coverage_complete FROM assessment_steps WHERE job_id=?1 ORDER BY position").map_err(err)?;
        job.steps = statement
            .query_map([id], |r| {
                Ok(AssessmentStep {
                    position: r.get(0)?,
                    tool_id: r.get(1)?,
                    status: r.get(2)?,
                    run_id: r.get(3)?,
                    coverage_complete: r.get(4)?,
                })
            })
            .map_err(err)?
            .collect::<Result<_, _>>()
            .map_err(err)?;
        Ok(job)
    }

    pub fn list(&self, project_id: &str) -> Result<Vec<AssessmentJob>, String> {
        let mut statement = self
            .database
            .connection()
            .prepare(
                "SELECT id FROM assessment_jobs WHERE project_id=?1 ORDER BY rowid DESC LIMIT 20",
            )
            .map_err(err)?;
        let ids = statement
            .query_map([project_id], |r| r.get::<_, String>(0))
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        ids.iter().map(|id| self.get(id)).collect()
    }

    pub fn cancel(&self, id: &str) -> Result<(), String> {
        let tx = self
            .database
            .connection()
            .unchecked_transaction()
            .map_err(err)?;
        let changed = tx.execute("UPDATE assessment_jobs SET cancel_requested=1,status=CASE WHEN status='planned' THEN 'cancelled' ELSE status END,finished_at=CASE WHEN status='planned' THEN CURRENT_TIMESTAMP ELSE finished_at END WHERE id=?1 AND status IN ('planned','running')", [id]).map_err(err)?;
        if changed != 1 {
            return Err("assessment is already terminal or missing".into());
        }
        tx.execute("UPDATE assessment_steps SET status='cancelled',finished_at=CURRENT_TIMESTAMP WHERE job_id=?1 AND status='pending' AND EXISTS(SELECT 1 FROM assessment_jobs WHERE id=?1 AND status='cancelled')", [id]).map_err(err)?;
        tx.commit().map_err(err)
    }

    /// Caller must serialize this worker with indexing, semantic enrichment and these analyzers.
    pub fn execute(&self, id: &str) -> Result<AssessmentJob, String> {
        let job = self.get(id)?;
        if job.status != "planned" {
            return Err("only a saved, unstarted plan can run".into());
        }
        if let Err(error) = self.validate_scope(&job) {
            self.fail_planned(id, &error)?;
            return self.get(id);
        }
        let claimed = self.database.connection().execute("UPDATE assessment_jobs SET status='running',started_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='planned' AND cancel_requested=0 AND scope_revision=(SELECT MAX(revision) FROM assessment_scopes WHERE project_id=assessment_jobs.project_id)", [id]).map_err(err)?;
        if claimed != 1 {
            return Err("assessment scope or state changed before start".into());
        }
        let started = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.execute_steps(&job, started)
        }))
        .unwrap_or_else(|_| {
            Err("assessment analyzer panicked; unfinished steps were interrupted".into())
        });
        match result {
            Ok(()) => self.finish(id, None)?,
            Err(message) => self.finish(id, Some(&message))?,
        }
        self.get(id)
    }

    fn execute_steps(&self, job: &AssessmentJob, started: Instant) -> Result<(), String> {
        for step in &job.steps {
            self.boundary(job, started)?;
            self.database.connection().execute("UPDATE assessment_steps SET status='running',started_at=CURRENT_TIMESTAMP WHERE job_id=?1 AND position=?2 AND status='pending'", params![job.id,step.position]).map_err(err)?;
            let result = match step.tool_id.as_str() {
                "code.sast" => CodeSecurityService::new(self.database)
                    .analyze_project(&job.project_id)
                    .map(|run| (run.run_id, Some(run.coverage_complete)))
                    .map_err(err),
                "code.quality" => CodeQualityService::new(self.database)
                    .analyze_project(&job.project_id)
                    .map(|run| (run.run_id, None))
                    .map_err(err),
                _ => Err("unsupported assessment adapter".into()),
            };
            match result {
                Ok((run_id, coverage)) => {
                    self.database.connection().execute("UPDATE assessment_steps SET status='completed',run_id=?3,coverage_complete=?4,finished_at=CURRENT_TIMESTAMP WHERE job_id=?1 AND position=?2", params![job.id,step.position,run_id,coverage]).map_err(err)?;
                    if coverage == Some(false) {
                        return Err(
                            "source analysis returned partial coverage; inspect its persisted run"
                                .into(),
                        );
                    }
                }
                Err(error) => {
                    self.database.connection().execute("UPDATE assessment_steps SET status='failed',finished_at=CURRENT_TIMESTAMP WHERE job_id=?1 AND position=?2", params![job.id,step.position]).map_err(err)?;
                    return Err(error);
                }
            }
            self.boundary(job, started)?;
        }
        Ok(())
    }

    fn boundary(&self, job: &AssessmentJob, started: Instant) -> Result<(), String> {
        self.check_limits(job, started)?;
        self.validate_scope(job)?;
        self.check_limits(job, started)
    }

    fn check_limits(&self, job: &AssessmentJob, started: Instant) -> Result<(), String> {
        let cancelled: bool = self
            .database
            .connection()
            .query_row(
                "SELECT cancel_requested FROM assessment_jobs WHERE id=?1",
                [&job.id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if cancelled {
            return Err("cancellation requested; stopped at analyzer boundary".into());
        }
        if started.elapsed().as_secs() >= job.budget_seconds {
            return Err("time budget exceeded at analyzer boundary".into());
        }
        Ok(())
    }

    fn finish(&self, id: &str, error: Option<&str>) -> Result<(), String> {
        let tx = self
            .database
            .connection()
            .unchecked_transaction()
            .map_err(err)?;
        let changed = tx.execute("UPDATE assessment_jobs SET status=CASE WHEN cancel_requested=1 THEN 'cancelled' WHEN ?2 IS NULL THEN 'completed' ELSE 'failed' END,message=?2,finished_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'", params![id,error]).map_err(err)?;
        if changed != 1 {
            return Err("assessment is not running".into());
        }
        tx.execute("UPDATE assessment_steps SET status=CASE WHEN (SELECT status FROM assessment_jobs WHERE id=?1)='cancelled' THEN 'cancelled' ELSE 'interrupted' END,finished_at=CURRENT_TIMESTAMP WHERE job_id=?1 AND status IN ('pending','running')", [id]).map_err(err)?;
        tx.commit().map_err(err)
    }
    fn fail_planned(&self, id: &str, message: &str) -> Result<(), String> {
        let tx = self
            .database
            .connection()
            .unchecked_transaction()
            .map_err(err)?;
        tx.execute("UPDATE assessment_jobs SET status='failed',message=?2,finished_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='planned'", params![id,message]).map_err(err)?;
        tx.execute("UPDATE assessment_steps SET status='interrupted',finished_at=CURRENT_TIMESTAMP WHERE job_id=?1 AND status='pending' AND EXISTS(SELECT 1 FROM assessment_jobs WHERE id=?1 AND status='failed')", [id]).map_err(err)?;
        tx.commit().map_err(err)
    }

    /// Explicit startup recovery. Saved plans remain available; executing work is never resumed.
    pub fn recover_interrupted(&self) -> Result<usize, String> {
        let tx = self
            .database
            .connection()
            .unchecked_transaction()
            .map_err(err)?;
        tx.execute("UPDATE assessment_steps SET status='interrupted',finished_at=CURRENT_TIMESTAMP WHERE status IN ('running','pending') AND job_id IN (SELECT id FROM assessment_jobs WHERE status='running')", []).map_err(err)?;
        let changed = tx.execute("UPDATE assessment_jobs SET status='interrupted',message='Application stopped before assessment finished; create a fresh plan',finished_at=CURRENT_TIMESTAMP WHERE status='running'", []).map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(changed)
    }

    fn validate_scope(&self, job: &AssessmentJob) -> Result<(), String> {
        let current: i64 = self
            .database
            .connection()
            .query_row(
                "SELECT MAX(revision) FROM assessment_scopes WHERE project_id=?1",
                [&job.project_id],
                |r| r.get(0),
            )
            .map_err(err)?;
        if current != job.scope_revision {
            return Err("scope revision superseded; create a fresh plan".into());
        }
        let (root, hash, count) = self.snapshot(&job.project_id, job.max_files)?;
        if root != job.root_path || hash != job.input_hash || count != job.file_count {
            return Err(
                "assessment inputs or root changed; reindex and create a fresh plan".into(),
            );
        }
        Ok(())
    }

    fn snapshot(
        &self,
        project_id: &str,
        max_files: usize,
    ) -> Result<(String, String, usize), String> {
        let stored: String = self
            .database
            .connection()
            .query_row(
                "SELECT root_path FROM projects WHERE id=?1",
                [project_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?
            .ok_or("project not found")?;
        let latest_index: Option<String> = self.database.connection().query_row(
            "SELECT status FROM analysis_runs WHERE project_id=?1 AND run_kind='source_index' ORDER BY rowid DESC LIMIT 1", [project_id], |r| r.get(0),
        ).optional().map_err(err)?;
        if latest_index.as_deref() != Some("completed") {
            return Err(
                "latest indexing run is absent or unfinished; complete indexing before planning"
                    .into(),
            );
        }
        let root = fs::canonicalize(&stored).map_err(err)?;
        if !root.is_dir() {
            return Err("project root is not a directory".into());
        }
        let mut statement = self.database.connection().prepare("SELECT relative_path,content_hash,byte_size,COALESCE(language,''),COALESCE(parse_state,''),COALESCE(last_index_run_id,'') FROM files WHERE project_id=?1 AND is_active=1 ORDER BY relative_path,id LIMIT ?2").map_err(err)?;
        let files = statement
            .query_map(params![project_id, max_files + 1], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        if files.is_empty() || files.len() > max_files {
            return Err("indexed file count is empty or exceeds plan budget; index the project or raise the file limit".into());
        }
        let mut digest = Sha256::new();
        digest.update(b"assessment-v1:appsec-v1:code-quality-v1");
        digest.update(serde_json::to_vec(&(stored, root.to_string_lossy())).map_err(err)?);
        let mut total = 0u64;
        for file in &files {
            let relative = Path::new(&file.0);
            if relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err("unsafe indexed path".into());
            }
            let mut path = root.clone();
            for part in relative.components() {
                path.push(part.as_os_str());
                if fs::symlink_metadata(&path)
                    .map_err(err)?
                    .file_type()
                    .is_symlink()
                {
                    return Err("assessment input symlinks are not supported".into());
                }
            }
            // Reject FIFOs/devices/directories before opening, so static special files cannot block planning.
            if !fs::symlink_metadata(&path).map_err(err)?.is_file() {
                return Err("assessment inputs must be regular files".into());
            }
            let mut handle = fs::File::open(&path).map_err(err)?;
            let metadata = handle.metadata().map_err(err)?;
            total = total.saturating_add(metadata.len());
            if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES {
                return Err(
                    "assessment input exceeds regular-file/5 MiB per-file/32 MiB total bounds"
                        .into(),
                );
            }
            let mut bytes = Vec::new();
            handle
                .by_ref()
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(err)?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if bytes.len() as u64 != file.2 || actual != file.1 {
                return Err("indexed source is stale; reindex before planning or running".into());
            }
            digest.update(serde_json::to_vec(file).map_err(err)?);
        }
        // Bind the actual quality inputs, including graph edits outside the index/LSP worker.
        for (sql, limit) in [
            ("SELECT json_array(s.id,s.file_id,s.kind,s.name,s.qualified_name,s.parent_symbol_id,s.start_line,s.end_line) FROM symbols s JOIN files f ON f.id=s.file_id WHERE s.project_id=?1 AND s.is_active=1 AND f.is_active=1 ORDER BY s.id LIMIT 200001", 200_000),
            ("SELECT json_array(i.id,i.source_file_id,i.resolved_target_file_id,i.raw_specifier,i.start_line,i.end_line) FROM import_references i JOIN files source ON source.id=i.source_file_id JOIN files target ON target.id=i.resolved_target_file_id WHERE i.project_id=?1 AND i.resolution_state='resolved_local' AND source.is_active=1 AND target.is_active=1 ORDER BY i.id LIMIT 50001", 50_000),
        ] {
            let mut statement = self.database.connection().prepare(sql).map_err(err)?;
            for (count, row) in statement.query_map([project_id], |r| r.get::<_,String>(0)).map_err(err)?.enumerate() {
                if count >= limit { return Err("assessment quality graph exceeds bounded analyzer inputs".into()); }
                let value = row.map_err(err)?;
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value.as_bytes());
            }
        }
        // Reindex or semantic refresh invalidates plans even when source bytes are unchanged.
        let provenance: Vec<String> = self.database.connection().prepare("SELECT id FROM analysis_runs WHERE rowid IN (SELECT MAX(rowid) FROM analysis_runs WHERE project_id=?1 AND run_kind IN ('source_index','lsp_semantic') AND status='completed' GROUP BY run_kind) ORDER BY run_kind").map_err(err)?.query_map([project_id], |r| r.get(0)).map_err(err)?.collect::<Result<_,_>>().map_err(err)?;
        digest.update(serde_json::to_vec(&provenance).map_err(err)?);
        Ok((
            root.to_string_lossy().into_owned(),
            format!("{:x}", digest.finalize()),
            files.len(),
        ))
    }
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_wins_completion_and_budget_is_checked_at_boundaries() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.ts"), "export const a=1;").unwrap();
        let db = Database::open_in_memory().unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let jobs = AssessmentJobs::new(&db);
        let plan = jobs
            .create_plan(AssessmentPlanRequest {
                project_id: project,
                tools: vec!["code.sast".into()],
                max_files: 10,
                budget_seconds: 1,
            })
            .unwrap();
        db.connection()
            .execute(
                "UPDATE assessment_jobs SET status='running' WHERE id=?1",
                [&plan.id],
            )
            .unwrap();
        let expired = Instant::now() - std::time::Duration::from_secs(2);
        assert!(jobs
            .boundary(&plan, expired)
            .unwrap_err()
            .contains("time budget"));
        jobs.cancel(&plan.id).unwrap();
        assert!(jobs
            .boundary(&plan, Instant::now())
            .unwrap_err()
            .contains("cancellation"));
        jobs.finish(&plan.id, None).unwrap();
        assert_eq!(jobs.get(&plan.id).unwrap().status, "cancelled");
        assert!(jobs.finish(&plan.id, None).is_err());
    }
}
