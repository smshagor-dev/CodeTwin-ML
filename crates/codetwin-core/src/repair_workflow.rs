use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{deterministic_id, Database};

const MAX_TITLE_BYTES: usize = 512;
const MAX_RATIONALE_BYTES: usize = 16_384;
const MAX_PROPOSED_FILE_BYTES: usize = 1_048_576;
const MAX_PLANS_QUERY: usize = 200;
const MAX_CHANGES_QUERY: usize = 500;
const MAX_VERIFICATION_QUERY: usize = 200;

#[derive(Debug, Error)]
pub enum RepairWorkflowError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("finding not found: {0}")]
    FindingNotFound(String),
    #[error("finding does not belong to the requested project")]
    FindingProjectMismatch,
    #[error("repair plan not found: {0}")]
    PlanNotFound(String),
    #[error("repair plan is not editable in status: {0}")]
    PlanNotDraft(String),
    #[error("repair plan cannot be verified in status: {0}")]
    PlanNotApproved(String),
    #[error("repair plan has no proposed changes")]
    NoChanges,
    #[error("active indexed file not found: {0}")]
    FileNotFound(String),
    #[error("indexed file does not belong to the repair project")]
    FileProjectMismatch,
    #[error("repair base is stale for {0}; re-index and create a new proposal")]
    StaleBase(String),
    #[error("invalid repair input: {0}")]
    InvalidInput(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlanRecord {
    pub id: String,
    pub project_id: String,
    pub finding_id: Option<String>,
    pub title: String,
    pub rationale: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub approved_at: Option<String>,
    pub verified_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairChangeRecord {
    pub id: String,
    pub repair_id: String,
    pub file_id: Option<String>,
    pub relative_path: String,
    pub base_content_hash: String,
    pub proposed_content_hash: String,
    pub proposed_content: String,
    pub proposed_byte_size: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairVerificationRunRecord {
    pub id: String,
    pub repair_id: String,
    pub project_id: String,
    pub status: String,
    pub finding_status: Option<String>,
    pub matched_changes: usize,
    pub mismatched_changes: usize,
    pub missing_changes: usize,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairVerificationItemRecord {
    pub run_id: String,
    pub change_id: String,
    pub state: String,
    pub expected_hash: String,
    pub observed_hash: Option<String>,
}

pub struct VerifiedRepairService<'a> {
    database: &'a Database,
}

impl<'a> VerifiedRepairService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn create_plan(
        &self,
        project_id: &str,
        finding_id: Option<&str>,
        title: &str,
        rationale: &str,
    ) -> Result<RepairPlanRecord, RepairWorkflowError> {
        validate_text("title", title, MAX_TITLE_BYTES)?;
        validate_text("rationale", rationale, MAX_RATIONALE_BYTES)?;
        ensure_project(self.database.connection(), project_id)?;
        if let Some(finding_id) = finding_id {
            let finding_project = project_for_finding(self.database.connection(), finding_id)?
                .ok_or_else(|| RepairWorkflowError::FindingNotFound(finding_id.to_owned()))?;
            if finding_project != project_id {
                return Err(RepairWorkflowError::FindingProjectMismatch);
            }
        }

        let id = deterministic_id(
            "repair-plan",
            &[project_id, finding_id.unwrap_or(""), title, &time_nonce()],
        );
        self.database.connection().execute(
            "INSERT INTO repair_plans(id, project_id, finding_id, title, rationale) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, project_id, finding_id, title, rationale],
        )?;
        self.get_plan(&id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(id))
    }

    pub fn add_file_replacement(
        &self,
        repair_id: &str,
        file_id: &str,
        proposed_content: &str,
    ) -> Result<RepairChangeRecord, RepairWorkflowError> {
        if proposed_content.len() > MAX_PROPOSED_FILE_BYTES {
            return Err(RepairWorkflowError::InvalidInput(format!(
                "proposed file exceeds {MAX_PROPOSED_FILE_BYTES} UTF-8 bytes"
            )));
        }
        let plan = self
            .get_plan(repair_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))?;
        if plan.status != "draft" {
            return Err(RepairWorkflowError::PlanNotDraft(plan.status));
        }
        let file = current_file(self.database.connection(), file_id)?
            .ok_or_else(|| RepairWorkflowError::FileNotFound(file_id.to_owned()))?;
        if file.project_id != plan.project_id {
            return Err(RepairWorkflowError::FileProjectMismatch);
        }

        let proposed_hash = sha256_hex(proposed_content.as_bytes());
        if proposed_hash == file.content_hash {
            return Err(RepairWorkflowError::InvalidInput(
                "proposed replacement is byte-identical to the indexed file".to_owned(),
            ));
        }
        let id = deterministic_id("repair-change", &[repair_id, &file.relative_path]);
        self.database.connection().execute(
            "INSERT INTO repair_changes(id, repair_id, file_id, relative_path, base_content_hash, proposed_content_hash, proposed_content, proposed_byte_size) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(repair_id, relative_path) DO UPDATE SET \
               file_id=excluded.file_id, base_content_hash=excluded.base_content_hash, \
               proposed_content_hash=excluded.proposed_content_hash, proposed_content=excluded.proposed_content, \
               proposed_byte_size=excluded.proposed_byte_size",
            params![
                id,
                repair_id,
                file_id,
                file.relative_path,
                file.content_hash,
                proposed_hash,
                proposed_content,
                to_i64(proposed_content.len()),
            ],
        )?;
        self.change_by_path(repair_id, &file.relative_path)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))
    }

    pub fn approve_plan(&self, repair_id: &str) -> Result<RepairPlanRecord, RepairWorkflowError> {
        let plan = self
            .get_plan(repair_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))?;
        if plan.status != "draft" {
            return Err(RepairWorkflowError::PlanNotDraft(plan.status));
        }
        let changes = self.list_changes(repair_id, MAX_CHANGES_QUERY)?;
        if changes.is_empty() {
            return Err(RepairWorkflowError::NoChanges);
        }
        for change in &changes {
            let observed = current_file_by_path(
                self.database.connection(),
                &plan.project_id,
                &change.relative_path,
            )?;
            if observed
                .as_ref()
                .is_none_or(|file| file.content_hash != change.base_content_hash)
            {
                return Err(RepairWorkflowError::StaleBase(change.relative_path.clone()));
            }
        }
        self.database.connection().execute(
            "UPDATE repair_plans SET status='approved', approved_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            [repair_id],
        )?;
        self.get_plan(repair_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))
    }

    pub fn reject_plan(&self, repair_id: &str) -> Result<RepairPlanRecord, RepairWorkflowError> {
        let plan = self
            .get_plan(repair_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))?;
        if !matches!(plan.status.as_str(), "draft" | "approved" | "applied") {
            return Err(RepairWorkflowError::PlanNotDraft(plan.status));
        }
        self.database.connection().execute(
            "UPDATE repair_plans SET status='rejected', updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            [repair_id],
        )?;
        self.get_plan(repair_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))
    }

    pub fn verify_plan(
        &self,
        repair_id: &str,
    ) -> Result<RepairVerificationRunRecord, RepairWorkflowError> {
        let plan = self
            .get_plan(repair_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(repair_id.to_owned()))?;
        if !matches!(plan.status.as_str(), "approved" | "applied") {
            return Err(RepairWorkflowError::PlanNotApproved(plan.status));
        }
        let changes = self.list_changes(repair_id, MAX_CHANGES_QUERY)?;
        if changes.is_empty() {
            return Err(RepairWorkflowError::NoChanges);
        }

        let mut items = Vec::with_capacity(changes.len());
        let mut matched = 0usize;
        let mut mismatched = 0usize;
        let mut missing = 0usize;
        for change in &changes {
            let observed = current_file_by_path(
                self.database.connection(),
                &plan.project_id,
                &change.relative_path,
            )?;
            let (state, observed_hash) = match observed {
                Some(file) if file.content_hash == change.proposed_content_hash => {
                    matched += 1;
                    ("matched", Some(file.content_hash))
                }
                Some(file) => {
                    mismatched += 1;
                    ("mismatch", Some(file.content_hash))
                }
                None => {
                    missing += 1;
                    ("missing", None)
                }
            };
            items.push((
                change.id.clone(),
                state.to_owned(),
                change.proposed_content_hash.clone(),
                observed_hash,
            ));
        }

        let finding_status = match plan.finding_id.as_deref() {
            Some(finding_id) => finding_status(self.database.connection(), finding_id)?,
            None => None,
        };
        let all_matched = matched == changes.len();
        let (verification_status, next_plan_status) = if missing > 0 {
            ("incomplete", None)
        } else if !all_matched {
            ("mismatch", None)
        } else if plan.finding_id.is_some() && finding_status.as_deref() != Some("resolved") {
            ("applied_finding_open", Some("applied"))
        } else {
            ("verified", Some("verified"))
        };

        let run_id = deterministic_id(
            "repair-verification",
            &[repair_id, verification_status, &time_nonce()],
        );
        let tx = self.database.connection().unchecked_transaction()?;
        tx.execute(
            "INSERT INTO repair_verification_runs(id, repair_id, project_id, status, finding_status, matched_changes, mismatched_changes, missing_changes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run_id,
                repair_id,
                plan.project_id,
                verification_status,
                finding_status,
                to_i64(matched),
                to_i64(mismatched),
                to_i64(missing),
            ],
        )?;
        for (change_id, state, expected_hash, observed_hash) in &items {
            tx.execute(
                "INSERT INTO repair_verification_items(run_id, change_id, state, expected_hash, observed_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![run_id, change_id, state, expected_hash, observed_hash],
            )?;
        }
        if let Some(next_status) = next_plan_status {
            if next_status == "verified" {
                tx.execute(
                    "UPDATE repair_plans SET status='verified', verified_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?1",
                    [repair_id],
                )?;
            } else {
                tx.execute(
                    "UPDATE repair_plans SET status=?2, updated_at=CURRENT_TIMESTAMP WHERE id=?1",
                    params![repair_id, next_status],
                )?;
            }
        }
        tx.commit()?;
        self.get_verification(&run_id)?
            .ok_or_else(|| RepairWorkflowError::PlanNotFound(run_id))
    }

    pub fn get_plan(
        &self,
        repair_id: &str,
    ) -> Result<Option<RepairPlanRecord>, RepairWorkflowError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, project_id, finding_id, title, rationale, status, created_at, updated_at, approved_at, verified_at FROM repair_plans WHERE id=?1",
                [repair_id],
                map_plan,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_plans(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RepairPlanRecord>, RepairWorkflowError> {
        ensure_project(self.database.connection(), project_id)?;
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, finding_id, title, rationale, status, created_at, updated_at, approved_at, verified_at \
             FROM repair_plans WHERE project_id=?1 AND (?2 IS NULL OR status=?2) \
             ORDER BY updated_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![project_id, status, bounded(limit, MAX_PLANS_QUERY)],
            map_plan,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_changes(
        &self,
        repair_id: &str,
        limit: usize,
    ) -> Result<Vec<RepairChangeRecord>, RepairWorkflowError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, repair_id, file_id, relative_path, base_content_hash, proposed_content_hash, proposed_content, proposed_byte_size, created_at \
             FROM repair_changes WHERE repair_id=?1 ORDER BY relative_path, id LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![repair_id, bounded(limit, MAX_CHANGES_QUERY)],
            map_change,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn verification_history(
        &self,
        repair_id: &str,
        limit: usize,
    ) -> Result<Vec<RepairVerificationRunRecord>, RepairWorkflowError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, repair_id, project_id, status, finding_status, matched_changes, mismatched_changes, missing_changes, created_at \
             FROM repair_verification_runs WHERE repair_id=?1 ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![repair_id, bounded(limit, MAX_VERIFICATION_QUERY)],
            map_verification,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn verification_items(
        &self,
        run_id: &str,
        limit: usize,
    ) -> Result<Vec<RepairVerificationItemRecord>, RepairWorkflowError> {
        let mut statement = self.database.connection().prepare(
            "SELECT run_id, change_id, state, expected_hash, observed_hash FROM repair_verification_items \
             WHERE run_id=?1 ORDER BY change_id LIMIT ?2",
        )?;
        let rows =
            statement.query_map(params![run_id, bounded(limit, MAX_CHANGES_QUERY)], |row| {
                Ok(RepairVerificationItemRecord {
                    run_id: row.get(0)?,
                    change_id: row.get(1)?,
                    state: row.get(2)?,
                    expected_hash: row.get(3)?,
                    observed_hash: row.get(4)?,
                })
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn change_by_path(
        &self,
        repair_id: &str,
        relative_path: &str,
    ) -> Result<Option<RepairChangeRecord>, RepairWorkflowError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, repair_id, file_id, relative_path, base_content_hash, proposed_content_hash, proposed_content, proposed_byte_size, created_at \
                 FROM repair_changes WHERE repair_id=?1 AND relative_path=?2",
                params![repair_id, relative_path],
                map_change,
            )
            .optional()
            .map_err(Into::into)
    }

    fn get_verification(
        &self,
        run_id: &str,
    ) -> Result<Option<RepairVerificationRunRecord>, RepairWorkflowError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, repair_id, project_id, status, finding_status, matched_changes, mismatched_changes, missing_changes, created_at \
                 FROM repair_verification_runs WHERE id=?1",
                [run_id],
                map_verification,
            )
            .optional()
            .map_err(Into::into)
    }
}

struct CurrentFile {
    project_id: String,
    relative_path: String,
    content_hash: String,
}

fn current_file(
    connection: &Connection,
    file_id: &str,
) -> Result<Option<CurrentFile>, RepairWorkflowError> {
    connection
        .query_row(
            "SELECT project_id, relative_path, content_hash FROM files WHERE id=?1 AND is_active=1",
            [file_id],
            |row| {
                Ok(CurrentFile {
                    project_id: row.get(0)?,
                    relative_path: row.get(1)?,
                    content_hash: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn current_file_by_path(
    connection: &Connection,
    project_id: &str,
    relative_path: &str,
) -> Result<Option<CurrentFile>, RepairWorkflowError> {
    connection
        .query_row(
            "SELECT project_id, relative_path, content_hash FROM files WHERE project_id=?1 AND relative_path=?2 AND is_active=1",
            params![project_id, relative_path],
            |row| {
                Ok(CurrentFile {
                    project_id: row.get(0)?,
                    relative_path: row.get(1)?,
                    content_hash: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn ensure_project(connection: &Connection, project_id: &str) -> Result<(), RepairWorkflowError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
        [project_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(RepairWorkflowError::ProjectNotFound(project_id.to_owned()))
    }
}

fn project_for_finding(
    connection: &Connection,
    finding_id: &str,
) -> Result<Option<String>, RepairWorkflowError> {
    connection
        .query_row(
            "SELECT project_id FROM findings WHERE id=?1",
            [finding_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn finding_status(
    connection: &Connection,
    finding_id: &str,
) -> Result<Option<String>, RepairWorkflowError> {
    connection
        .query_row(
            "SELECT status FROM findings WHERE id=?1",
            [finding_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn validate_text(name: &str, value: &str, max_bytes: usize) -> Result<(), RepairWorkflowError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(RepairWorkflowError::InvalidInput(format!(
            "{name} must contain 1-{max_bytes} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn time_nonce() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

fn bounded(value: usize, max: usize) -> i64 {
    i64::try_from(value.clamp(1, max)).unwrap_or(i64::MAX)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or_default()
}

fn map_plan(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepairPlanRecord> {
    Ok(RepairPlanRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        finding_id: row.get(2)?,
        title: row.get(3)?,
        rationale: row.get(4)?,
        status: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        approved_at: row.get(8)?,
        verified_at: row.get(9)?,
    })
}

fn map_change(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepairChangeRecord> {
    let byte_size: i64 = row.get(7)?;
    Ok(RepairChangeRecord {
        id: row.get(0)?,
        repair_id: row.get(1)?,
        file_id: row.get(2)?,
        relative_path: row.get(3)?,
        base_content_hash: row.get(4)?,
        proposed_content_hash: row.get(5)?,
        proposed_content: row.get(6)?,
        proposed_byte_size: to_usize(byte_size),
        created_at: row.get(8)?,
    })
}

fn map_verification(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepairVerificationRunRecord> {
    let matched: i64 = row.get(5)?;
    let mismatched: i64 = row.get(6)?;
    let missing: i64 = row.get(7)?;
    Ok(RepairVerificationRunRecord {
        id: row.get(0)?,
        repair_id: row.get(1)?,
        project_id: row.get(2)?,
        status: row.get(3)?,
        finding_status: row.get(4)?,
        matched_changes: to_usize(matched),
        mismatched_changes: to_usize(mismatched),
        missing_changes: to_usize(missing),
        created_at: row.get(8)?,
    })
}
