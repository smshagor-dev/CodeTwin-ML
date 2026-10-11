use rusqlite::params;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Database;

#[derive(Debug, Error)]
pub enum SecurityReviewError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("review requires a valid verdict and a note of 1–2000 characters")]
    InvalidReview,
    #[error(
        "finding is unavailable, belongs to another project, or its scan changed; reload evidence"
    )]
    StaleFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFindingReview {
    pub id: i64,
    pub finding_id: String,
    pub project_id: String,
    pub scan_run_id: String,
    pub indexed_content_hash: Option<String>,
    pub verdict: String,
    pub note: String,
    pub created_at: String,
    pub is_current: bool,
}

pub struct SecurityReviewService<'a> {
    database: &'a Database,
}

impl<'a> SecurityReviewService<'a> {
    pub fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn review(
        &self,
        project_id: &str,
        finding_id: &str,
        expected_run_id: &str,
        expected_content_hash: Option<&str>,
        verdict: &str,
        note: &str,
    ) -> Result<SecurityFindingReview, SecurityReviewError> {
        let note = note.trim();
        if !matches!(verdict, "confirmed" | "false_positive" | "needs_review")
            || note.is_empty()
            || note.chars().count() > 2000
        {
            return Err(SecurityReviewError::InvalidReview);
        }
        // One INSERT...SELECT binds the event to the current finding and indexed bytes.
        // Review feedback never updates analyzer-owned status or suppresses findings.
        let inserted = self.database.connection().execute(
            "INSERT INTO security_finding_reviews(finding_id, project_id, scan_run_id, indexed_content_hash, verdict, note) \
             SELECT f.id, f.project_id, f.run_id, files.content_hash, ?4, ?5 \
             FROM findings f LEFT JOIN files ON files.id=f.file_id \
             WHERE f.id=?1 AND f.project_id=?2 AND f.run_id=?3 AND f.analyzer_key='appsec' AND files.content_hash IS ?6",
            params![finding_id, project_id, expected_run_id, verdict, note, expected_content_hash],
        )?;
        if inserted != 1 {
            return Err(SecurityReviewError::StaleFinding);
        }
        let id = self.database.connection().last_insert_rowid();
        self.database
            .connection()
            .query_row(
                &format!("{} WHERE r.id=?1", Self::select()),
                [id],
                Self::read,
            )
            .map_err(SecurityReviewError::from)
    }

    pub fn list(
        &self,
        project_id: &str,
        finding_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SecurityFindingReview>, SecurityReviewError> {
        let mut statement = self.database.connection().prepare(&format!(
            "{} WHERE r.project_id=?1 AND (?2 IS NULL OR r.finding_id=?2) ORDER BY r.id DESC LIMIT ?3",
            Self::select(),
        ))?;
        let records = statement.query_map(
            params![project_id, finding_id, limit.clamp(1, 500) as i64],
            Self::read,
        )?;
        records
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityReviewError::from)
    }

    fn select() -> &'static str {
        "SELECT r.id, r.finding_id, r.project_id, r.scan_run_id, r.indexed_content_hash, r.verdict, r.note, r.created_at, \
         (r.scan_run_id=f.run_id AND r.indexed_content_hash IS files.content_hash) \
         FROM security_finding_reviews r JOIN findings f ON f.id=r.finding_id LEFT JOIN files ON files.id=f.file_id"
    }

    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityFindingReview> {
        Ok(SecurityFindingReview {
            id: row.get(0)?,
            finding_id: row.get(1)?,
            project_id: row.get(2)?,
            scan_run_id: row.get(3)?,
            indexed_content_hash: row.get(4)?,
            verdict: row.get(5)?,
            note: row.get(6)?,
            created_at: row.get(7)?,
            is_current: row.get(8)?,
        })
    }
}
