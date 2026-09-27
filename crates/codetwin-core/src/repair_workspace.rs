use std::{
    fs,
    path::{Component, Path},
};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::Database;

const MAX_SOURCE_BYTES: u64 = 1_048_576;
const MAX_FINDINGS_QUERY: usize = 200;

#[derive(Debug, Error)]
pub enum RepairWorkspaceError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("active indexed file not found: {0}")]
    FileNotFound(String),
    #[error("indexed repair source exceeds {MAX_SOURCE_BYTES} bytes")]
    SourceTooLarge,
    #[error("indexed repair source path is unsafe")]
    UnsafePath,
    #[error("indexed repair source is a symlink or not a regular file")]
    InvalidFileType,
    #[error("indexed repair source escaped the project root")]
    PathEscape,
    #[error("indexed repair source changed since the last index")]
    StaleSource,
    #[error("indexed repair source is not UTF-8 text")]
    NonUtf8,
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairSourceSnapshot {
    pub file_id: String,
    pub project_id: String,
    pub relative_path: String,
    pub language: Option<String>,
    pub content_hash: String,
    pub byte_size: usize,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairFindingRecord {
    pub id: String,
    pub project_id: String,
    pub analyzer_key: Option<String>,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub status: String,
    pub file_id: Option<String>,
    pub source_start_line: Option<usize>,
    pub source_end_line: Option<usize>,
    pub last_seen: String,
}

pub struct RepairWorkspaceQueryService<'a> {
    database: &'a Database,
}

impl<'a> RepairWorkspaceQueryService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn read_source_snapshot(
        &self,
        file_id: &str,
    ) -> Result<RepairSourceSnapshot, RepairWorkspaceError> {
        let row = self
            .database
            .connection()
            .query_row(
                "SELECT f.id, f.project_id, f.relative_path, f.language, f.content_hash, f.byte_size, p.root_path \
                 FROM files f JOIN projects p ON p.id=f.project_id \
                 WHERE f.id=?1 AND f.is_active=1",
                [file_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| RepairWorkspaceError::FileNotFound(file_id.to_owned()))?;
        let (file_id, project_id, relative_path, language, expected_hash, stored_size, root_path) =
            row;
        if stored_size < 0 || stored_size as u64 > MAX_SOURCE_BYTES {
            return Err(RepairWorkspaceError::SourceTooLarge);
        }

        let relative = Path::new(&relative_path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(RepairWorkspaceError::UnsafePath);
        }

        let root = Path::new(&root_path).canonicalize()?;
        let candidate = root.join(relative);
        let metadata = fs::symlink_metadata(&candidate)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(RepairWorkspaceError::InvalidFileType);
        }
        if metadata.len() > MAX_SOURCE_BYTES || metadata.len() != stored_size as u64 {
            return Err(RepairWorkspaceError::StaleSource);
        }
        let canonical = candidate.canonicalize()?;
        if !canonical.starts_with(&root) {
            return Err(RepairWorkspaceError::PathEscape);
        }

        let bytes = fs::read(&canonical)?;
        if bytes.len() as u64 > MAX_SOURCE_BYTES || bytes.len() != stored_size as usize {
            return Err(RepairWorkspaceError::StaleSource);
        }
        let observed_hash = format!("{:x}", Sha256::digest(&bytes));
        if observed_hash != expected_hash {
            return Err(RepairWorkspaceError::StaleSource);
        }
        let content = String::from_utf8(bytes).map_err(|_| RepairWorkspaceError::NonUtf8)?;
        Ok(RepairSourceSnapshot {
            file_id,
            project_id,
            relative_path,
            language,
            content_hash: expected_hash,
            byte_size: content.len(),
            content,
        })
    }

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RepairFindingRecord>, RepairWorkspaceError> {
        let exists: bool = self.database.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id=?1)",
            [project_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(RepairWorkspaceError::ProjectNotFound(project_id.to_owned()));
        }
        let limit =
            i64::try_from(limit.clamp(1, MAX_FINDINGS_QUERY)).unwrap_or(MAX_FINDINGS_QUERY as i64);
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, analyzer_key, category, severity, title, status, file_id, source_start_line, source_end_line, last_seen \
             FROM findings WHERE project_id=?1 AND (?2 IS NULL OR status=?2) \
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC, id \
             LIMIT ?3",
        )?;
        let rows = statement.query_map(params![project_id, status, limit], |row| {
            let start: Option<i64> = row.get(8)?;
            let end: Option<i64> = row.get(9)?;
            Ok(RepairFindingRecord {
                id: row.get(0)?,
                project_id: row.get(1)?,
                analyzer_key: row.get(2)?,
                category: row.get(3)?,
                severity: row.get(4)?,
                title: row.get(5)?,
                status: row.get(6)?,
                file_id: row.get(7)?,
                source_start_line: start.and_then(|value| usize::try_from(value).ok()),
                source_end_line: end.and_then(|value| usize::try_from(value).ok()),
                last_seen: row.get(10)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}
