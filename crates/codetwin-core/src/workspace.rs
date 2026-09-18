use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{deterministic_id, AnalysisStatus, Database};

const MAX_LIST_LIMIT: usize = 500;
const MAX_SEARCH_LIMIT: usize = 100;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid website URL: {0}")]
    InvalidWebsiteUrl(String),
    #[error("website is already registered: {0}")]
    DuplicateWebsite(String),
    #[error("website not found: {0}")]
    WebsiteNotFound(String),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("invalid website status: {0}")]
    InvalidWebsiteStatus(String),
    #[error("invalid preference: {0}")]
    InvalidPreference(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectOverview {
    pub id: String,
    pub display_name: String,
    pub root_path: String,
    pub path_identity: String,
    pub git_remote: Option<String>,
    pub last_opened_at: Option<String>,
    pub last_indexed_at: Option<String>,
    pub file_count: usize,
    pub symbol_count: usize,
    pub language_count: usize,
    pub last_index_status: Option<AnalysisStatus>,
    pub last_index_duration_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebsiteInput {
    pub url: String,
    pub display_name: Option<String>,
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebsiteRecord {
    pub id: String,
    pub url: String,
    pub normalized_url: String,
    pub display_name: String,
    pub project_id: Option<String>,
    pub project_name: Option<String>,
    pub status: String,
    pub http_status: Option<u16>,
    pub last_checked_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorkspaceSummary {
    pub project_count: usize,
    pub website_count: usize,
    pub active_agents: usize,
    pub security_scan_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceActivity {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub status: String,
    pub occurred_at: String,
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSearchResult {
    pub kind: String,
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub project_id: Option<String>,
    pub file_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppPreferences {
    pub display_name: String,
    pub theme: String,
    pub auto_run_security_on_import: bool,
    pub auto_discover_tests_on_import: bool,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            display_name: "Local User".to_string(),
            theme: "system".to_string(),
            auto_run_security_on_import: false,
            auto_discover_tests_on_import: false,
        }
    }
}

pub struct WorkspaceService<'a> {
    database: &'a Database,
}

impl<'a> WorkspaceService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn list_projects(
        &self,
        search: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ProjectOverview>, WorkspaceError> {
        let limit = bounded_limit(limit, MAX_LIST_LIMIT);
        let search = search.map(str::trim).filter(|value| !value.is_empty());
        let connection = self.database.connection();
        let mut rows = Vec::new();

        if let Some(search) = search {
            let pattern = format!("%{}%", escape_like(search));
            let mut statement = connection.prepare(PROJECT_LIST_SQL_SEARCH)?;
            let mapped = statement.query_map(params![pattern, limit as i64], map_project_overview)?;
            for row in mapped {
                rows.push(row?);
            }
        } else {
            let mut statement = connection.prepare(PROJECT_LIST_SQL)?;
            let mapped = statement.query_map([limit as i64], map_project_overview)?;
            for row in mapped {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    pub fn get_project(&self, project_id: &str) -> Result<Option<ProjectOverview>, WorkspaceError> {
        self.database
            .connection()
            .query_row(
                PROJECT_GET_SQL,
                [project_id],
                map_project_overview,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn remove_project(&self, project_id: &str) -> Result<bool, WorkspaceError> {
        Ok(self
            .database
            .connection()
            .execute("DELETE FROM projects WHERE id = ?1", [project_id])?
            > 0)
    }

    pub fn list_websites(
        &self,
        search: Option<&str>,
        limit: usize,
    ) -> Result<Vec<WebsiteRecord>, WorkspaceError> {
        let limit = bounded_limit(limit, MAX_LIST_LIMIT);
        let search = search.map(str::trim).filter(|value| !value.is_empty());
        let connection = self.database.connection();
        let mut records = Vec::new();
        if let Some(search) = search {
            let pattern = format!("%{}%", escape_like(search));
            let mut statement = connection.prepare(
                "SELECT w.id, w.url, w.normalized_url, w.display_name, w.project_id, p.display_name,                        w.status, w.http_status, w.last_checked_at, w.last_error, w.created_at, w.updated_at                 FROM websites w LEFT JOIN projects p ON p.id = w.project_id                 WHERE w.display_name LIKE ?1 ESCAPE '\\' OR w.url LIKE ?1 ESCAPE '\\'                 ORDER BY w.updated_at DESC, w.created_at DESC LIMIT ?2",
            )?;
            let mapped = statement.query_map(params![pattern, limit as i64], map_website)?;
            for row in mapped {
                records.push(row?);
            }
        } else {
            let mut statement = connection.prepare(
                "SELECT w.id, w.url, w.normalized_url, w.display_name, w.project_id, p.display_name,                        w.status, w.http_status, w.last_checked_at, w.last_error, w.created_at, w.updated_at                 FROM websites w LEFT JOIN projects p ON p.id = w.project_id                 ORDER BY w.updated_at DESC, w.created_at DESC LIMIT ?1",
            )?;
            let mapped = statement.query_map([limit as i64], map_website)?;
            for row in mapped {
                records.push(row?);
            }
        }
        Ok(records)
    }

    pub fn get_website(&self, website_id: &str) -> Result<Option<WebsiteRecord>, WorkspaceError> {
        self.database
            .connection()
            .query_row(
                "SELECT w.id, w.url, w.normalized_url, w.display_name, w.project_id, p.display_name,                        w.status, w.http_status, w.last_checked_at, w.last_error, w.created_at, w.updated_at                 FROM websites w LEFT JOIN projects p ON p.id = w.project_id WHERE w.id = ?1",
                [website_id],
                map_website,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn add_website(&self, input: &WebsiteInput) -> Result<WebsiteRecord, WorkspaceError> {
        let normalized_url = normalize_website_url(&input.url)?;
        if let Some(existing) = self
            .database
            .connection()
            .query_row(
                "SELECT id FROM websites WHERE normalized_url = ?1",
                [&normalized_url],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(WorkspaceError::DuplicateWebsite(existing));
        }

        if let Some(project_id) = input.project_id.as_deref() {
            let exists: bool = self.database.connection().query_row(
                "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
                [project_id],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(WorkspaceError::ProjectNotFound(project_id.to_string()));
            }
        }

        let parsed = Url::parse(&normalized_url)
            .map_err(|error| WorkspaceError::InvalidWebsiteUrl(error.to_string()))?;
        let display_name = input
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| parsed.host_str().unwrap_or("Website").to_string());
        let id = deterministic_id("website", &[&normalized_url]);

        self.database.connection().execute(
            "INSERT INTO websites(id, url, normalized_url, display_name, project_id)             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, input.url.trim(), normalized_url, display_name, input.project_id],
        )?;

        self.get_website(&id)?
            .ok_or_else(|| WorkspaceError::WebsiteNotFound(id))
    }

    pub fn update_website_check(
        &self,
        website_id: &str,
        status: &str,
        http_status: Option<u16>,
        last_error: Option<&str>,
    ) -> Result<WebsiteRecord, WorkspaceError> {
        if !matches!(status, "online" | "degraded" | "offline" | "not_checked") {
            return Err(WorkspaceError::InvalidWebsiteStatus(status.to_string()));
        }
        let changed = self.database.connection().execute(
            "UPDATE websites             SET status = ?2, http_status = ?3, last_error = ?4,                 last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP             WHERE id = ?1",
            params![website_id, status, http_status.map(i64::from), last_error],
        )?;
        if changed == 0 {
            return Err(WorkspaceError::WebsiteNotFound(website_id.to_string()));
        }
        self.get_website(website_id)?
            .ok_or_else(|| WorkspaceError::WebsiteNotFound(website_id.to_string()))
    }

    pub fn remove_website(&self, website_id: &str) -> Result<bool, WorkspaceError> {
        Ok(self
            .database
            .connection()
            .execute("DELETE FROM websites WHERE id = ?1", [website_id])?
            > 0)
    }

    pub fn summary(&self) -> Result<WorkspaceSummary, WorkspaceError> {
        let connection = self.database.connection();
        let project_count = count_query(connection, "SELECT COUNT(*) FROM projects")?;
        let website_count = count_query(connection, "SELECT COUNT(*) FROM websites")?;
        let security_scan_count = count_query(
            connection,
            "SELECT COUNT(*) FROM analysis_runs WHERE run_kind = 'security_analysis'",
        )?;
        Ok(WorkspaceSummary {
            project_count,
            website_count,
            active_agents: 0,
            security_scan_count,
        })
    }

    pub fn recent_activity(&self, limit: usize) -> Result<Vec<WorkspaceActivity>, WorkspaceError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, kind, title, detail, status, occurred_at, project_id FROM (               SELECT 'project:' || p.id AS id, 'project' AS kind, p.display_name AS title,                      p.root_path AS detail, 'indexed' AS status,                      COALESCE(p.last_indexed_at, p.last_opened_at, p.updated_at, p.created_at) AS occurred_at,                      p.id AS project_id               FROM projects p               UNION ALL               SELECT 'website:' || w.id AS id, 'website' AS kind, w.display_name AS title,                      w.url AS detail, w.status AS status,                      COALESCE(w.last_checked_at, w.updated_at, w.created_at) AS occurred_at,                      w.project_id AS project_id               FROM websites w               UNION ALL               SELECT 'analysis:' || a.id AS id, 'analysis' AS kind, p.display_name AS title,                      REPLACE(a.run_kind, '_', ' ') AS detail, a.status AS status,                      COALESCE(a.finished_at, a.started_at, p.updated_at) AS occurred_at,                      a.project_id AS project_id               FROM analysis_runs a JOIN projects p ON p.id = a.project_id             ) ORDER BY occurred_at DESC LIMIT ?1",
        )?;
        let mapped = statement.query_map(
            [bounded_limit(limit, MAX_LIST_LIMIT) as i64],
            |row| {
                Ok(WorkspaceActivity {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    title: row.get(2)?,
                    detail: row.get(3)?,
                    status: row.get(4)?,
                    occurred_at: row.get(5)?,
                    project_id: row.get(6)?,
                })
            },
        )?;
        let mut records = Vec::new();
        for row in mapped {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<WorkspaceSearchResult>, WorkspaceError> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let pattern = format!("%{}%", escape_like(query));
        let per_group = bounded_limit(limit.max(4) / 4 + 1, MAX_SEARCH_LIMIT);
        let connection = self.database.connection();
        let mut results = Vec::new();

        {
            let mut statement = connection.prepare(
                "SELECT id, display_name, root_path FROM projects                 WHERE display_name LIKE ?1 ESCAPE '\\' OR root_path LIKE ?1 ESCAPE '\\'                 ORDER BY COALESCE(last_opened_at, updated_at, created_at) DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![pattern, per_group as i64], |row| {
                let id: String = row.get(0)?;
                Ok(WorkspaceSearchResult {
                    kind: "project".to_string(),
                    id: id.clone(),
                    title: row.get(1)?,
                    subtitle: row.get(2)?,
                    project_id: Some(id),
                    file_id: None,
                })
            })?;
            for row in rows {
                results.push(row?);
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT id, display_name, url, project_id FROM websites                 WHERE display_name LIKE ?1 ESCAPE '\\' OR url LIKE ?1 ESCAPE '\\'                 ORDER BY updated_at DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![pattern, per_group as i64], |row| {
                Ok(WorkspaceSearchResult {
                    kind: "website".to_string(),
                    id: row.get(0)?,
                    title: row.get(1)?,
                    subtitle: row.get(2)?,
                    project_id: row.get(3)?,
                    file_id: None,
                })
            })?;
            for row in rows {
                results.push(row?);
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT f.id, f.relative_path, COALESCE(f.language, 'Unknown'), f.project_id                 FROM files f WHERE f.is_active = 1 AND f.relative_path LIKE ?1 ESCAPE '\\'                 ORDER BY f.relative_path LIMIT ?2",
            )?;
            let rows = statement.query_map(params![pattern, per_group as i64], |row| {
                let file_id: String = row.get(0)?;
                Ok(WorkspaceSearchResult {
                    kind: "file".to_string(),
                    id: file_id.clone(),
                    title: row.get(1)?,
                    subtitle: row.get(2)?,
                    project_id: row.get(3)?,
                    file_id: Some(file_id),
                })
            })?;
            for row in rows {
                results.push(row?);
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT s.id, s.name, f.relative_path, s.project_id, s.file_id                 FROM symbols s JOIN files f ON f.id = s.file_id                 WHERE s.is_active = 1 AND f.is_active = 1                   AND (s.name LIKE ?1 ESCAPE '\\' OR COALESCE(s.qualified_name, '') LIKE ?1 ESCAPE '\\')                 ORDER BY s.name, f.relative_path LIMIT ?2",
            )?;
            let rows = statement.query_map(params![pattern, per_group as i64], |row| {
                Ok(WorkspaceSearchResult {
                    kind: "symbol".to_string(),
                    id: row.get(0)?,
                    title: row.get(1)?,
                    subtitle: row.get(2)?,
                    project_id: row.get(3)?,
                    file_id: row.get(4)?,
                })
            })?;
            for row in rows {
                results.push(row?);
            }
        }

        let query_lower = query.to_ascii_lowercase();
        results.sort_by(|left, right| {
            let left_prefix = left.title.to_ascii_lowercase().starts_with(&query_lower);
            let right_prefix = right.title.to_ascii_lowercase().starts_with(&query_lower);
            right_prefix
                .cmp(&left_prefix)
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.title.cmp(&right.title))
        });
        results.truncate(bounded_limit(limit, MAX_SEARCH_LIMIT));
        Ok(results)
    }

    pub fn preferences(&self) -> Result<AppPreferences, WorkspaceError> {
        let value: Option<String> = self
            .database
            .connection()
            .query_row(
                "SELECT value_json FROM settings WHERE scope = 'app' AND key = 'preferences'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match value {
            Some(value) => Ok(serde_json::from_str(&value)?),
            None => Ok(AppPreferences::default()),
        }
    }

    pub fn save_preferences(
        &self,
        preferences: &AppPreferences,
    ) -> Result<AppPreferences, WorkspaceError> {
        let theme = preferences.theme.trim().to_ascii_lowercase();
        if !matches!(theme.as_str(), "system" | "light" | "dark") {
            return Err(WorkspaceError::InvalidPreference(format!(
                "unsupported theme {}",
                preferences.theme
            )));
        }
        let mut display_name = preferences.display_name.trim().to_string();
        if display_name.is_empty() {
            display_name = AppPreferences::default().display_name;
        }
        if display_name.chars().count() > 80 {
            return Err(WorkspaceError::InvalidPreference(
                "display name must be 80 characters or fewer".to_string(),
            ));
        }
        let sanitized = AppPreferences {
            display_name,
            theme,
            auto_run_security_on_import: preferences.auto_run_security_on_import,
            auto_discover_tests_on_import: preferences.auto_discover_tests_on_import,
        };
        let value_json = serde_json::to_string(&sanitized)?;
        self.database.connection().execute(
            "INSERT INTO settings(scope, key, value_json, updated_at)             VALUES ('app', 'preferences', ?1, CURRENT_TIMESTAMP)             ON CONFLICT(scope, key) DO UPDATE SET               value_json = excluded.value_json, updated_at = CURRENT_TIMESTAMP",
            [value_json],
        )?;
        Ok(sanitized)
    }
}

const PROJECT_LIST_SQL: &str = "SELECT p.id, p.display_name, p.root_path, COALESCE(p.path_identity, p.root_path), p.git_remote, p.last_opened_at, p.last_indexed_at, (SELECT COUNT(*) FROM files f WHERE f.project_id = p.id AND f.is_active = 1), (SELECT COUNT(*) FROM symbols s WHERE s.project_id = p.id AND s.is_active = 1), (SELECT COUNT(DISTINCT f.language) FROM files f WHERE f.project_id = p.id AND f.is_active = 1 AND f.language IS NOT NULL), (SELECT a.status FROM analysis_runs a WHERE a.project_id = p.id AND a.run_kind = 'source_index' ORDER BY COALESCE(a.started_at, '') DESC, a.id DESC LIMIT 1), (SELECT a.duration_ms FROM analysis_runs a WHERE a.project_id = p.id AND a.run_kind = 'source_index' ORDER BY COALESCE(a.started_at, '') DESC, a.id DESC LIMIT 1) FROM projects p ORDER BY COALESCE(p.last_opened_at, p.last_indexed_at, p.updated_at, p.created_at) DESC LIMIT ?1";

const PROJECT_LIST_SQL_SEARCH: &str = "SELECT p.id, p.display_name, p.root_path, COALESCE(p.path_identity, p.root_path), p.git_remote, p.last_opened_at, p.last_indexed_at, (SELECT COUNT(*) FROM files f WHERE f.project_id = p.id AND f.is_active = 1), (SELECT COUNT(*) FROM symbols s WHERE s.project_id = p.id AND s.is_active = 1), (SELECT COUNT(DISTINCT f.language) FROM files f WHERE f.project_id = p.id AND f.is_active = 1 AND f.language IS NOT NULL), (SELECT a.status FROM analysis_runs a WHERE a.project_id = p.id AND a.run_kind = 'source_index' ORDER BY COALESCE(a.started_at, '') DESC, a.id DESC LIMIT 1), (SELECT a.duration_ms FROM analysis_runs a WHERE a.project_id = p.id AND a.run_kind = 'source_index' ORDER BY COALESCE(a.started_at, '') DESC, a.id DESC LIMIT 1) FROM projects p WHERE p.display_name LIKE ?1 ESCAPE '\\' OR p.root_path LIKE ?1 ESCAPE '\\' OR COALESCE(p.git_remote, '') LIKE ?1 ESCAPE '\\' ORDER BY COALESCE(p.last_opened_at, p.last_indexed_at, p.updated_at, p.created_at) DESC LIMIT ?2";

const PROJECT_GET_SQL: &str = "SELECT p.id, p.display_name, p.root_path, COALESCE(p.path_identity, p.root_path), p.git_remote, p.last_opened_at, p.last_indexed_at, (SELECT COUNT(*) FROM files f WHERE f.project_id = p.id AND f.is_active = 1), (SELECT COUNT(*) FROM symbols s WHERE s.project_id = p.id AND s.is_active = 1), (SELECT COUNT(DISTINCT f.language) FROM files f WHERE f.project_id = p.id AND f.is_active = 1 AND f.language IS NOT NULL), (SELECT a.status FROM analysis_runs a WHERE a.project_id = p.id AND a.run_kind = 'source_index' ORDER BY COALESCE(a.started_at, '') DESC, a.id DESC LIMIT 1), (SELECT a.duration_ms FROM analysis_runs a WHERE a.project_id = p.id AND a.run_kind = 'source_index' ORDER BY COALESCE(a.started_at, '') DESC, a.id DESC LIMIT 1) FROM projects p WHERE p.id = ?1";

fn map_project_overview(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectOverview> {
    let status: Option<String> = row.get(10)?;
    let duration: Option<i64> = row.get(11)?;
    Ok(ProjectOverview {
        id: row.get(0)?,
        display_name: row.get(1)?,
        root_path: row.get(2)?,
        path_identity: row.get(3)?,
        git_remote: row.get(4)?,
        last_opened_at: row.get(5)?,
        last_indexed_at: row.get(6)?,
        file_count: nonnegative_usize(row.get::<_, i64>(7)?),
        symbol_count: nonnegative_usize(row.get::<_, i64>(8)?),
        language_count: nonnegative_usize(row.get::<_, i64>(9)?),
        last_index_status: status.as_deref().and_then(AnalysisStatus::from_db),
        last_index_duration_ms: duration.map(nonnegative_u64),
    })
}

fn map_website(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebsiteRecord> {
    let http_status: Option<i64> = row.get(7)?;
    Ok(WebsiteRecord {
        id: row.get(0)?,
        url: row.get(1)?,
        normalized_url: row.get(2)?,
        display_name: row.get(3)?,
        project_id: row.get(4)?,
        project_name: row.get(5)?,
        status: row.get(6)?,
        http_status: http_status.and_then(|value| u16::try_from(value).ok()),
        last_checked_at: row.get(8)?,
        last_error: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

pub fn normalize_website_url(raw: &str) -> Result<String, WorkspaceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WorkspaceError::InvalidWebsiteUrl(
            "URL is required".to_string(),
        ));
    }
    let mut url = Url::parse(trimmed)
        .map_err(|error| WorkspaceError::InvalidWebsiteUrl(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(WorkspaceError::InvalidWebsiteUrl(
            "only http:// and https:// URLs are supported".to_string(),
        ));
    }
    if url.host_str().is_none() {
        return Err(WorkspaceError::InvalidWebsiteUrl(
            "URL must contain a host".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WorkspaceError::InvalidWebsiteUrl(
            "URLs containing credentials are not accepted".to_string(),
        ));
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

fn count_query(
    connection: &rusqlite::Connection,
    sql: &str,
) -> Result<usize, rusqlite::Error> {
    let count: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    Ok(nonnegative_usize(count))
}

fn bounded_limit(requested: usize, max: usize) -> usize {
    requested.clamp(1, max)
}

fn nonnegative_usize(value: i64) -> usize {
    usize::try_from(value.max(0)).unwrap_or(usize::MAX)
}

fn nonnegative_u64(value: i64) -> u64 {
    u64::try_from(value.max(0)).unwrap_or(u64::MAX)
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{AppPreferences, WebsiteInput, WorkspaceError, WorkspaceService};
    use crate::{Database, ProjectIndexService};

    #[test]
    fn website_validation_and_duplicate_detection_are_persistent() {
        let database = Database::open_in_memory().expect("database");
        let service = WorkspaceService::new(&database);
        let first = service
            .add_website(&WebsiteInput {
                url: "https://Example.com/docs#section".to_string(),
                display_name: None,
                project_id: None,
            })
            .expect("add website");
        assert_eq!(first.normalized_url, "https://example.com/docs");
        assert_eq!(first.status, "not_checked");

        let duplicate = service.add_website(&WebsiteInput {
            url: "https://example.com/docs".to_string(),
            display_name: Some("Duplicate".to_string()),
            project_id: None,
        });
        assert!(matches!(duplicate, Err(WorkspaceError::DuplicateWebsite(_))));

        let invalid = service.add_website(&WebsiteInput {
            url: "file:///tmp/index.html".to_string(),
            display_name: None,
            project_id: None,
        });
        assert!(matches!(invalid, Err(WorkspaceError::InvalidWebsiteUrl(_))));
    }

    #[test]
    fn websites_persist_across_database_reopen() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("workspace.sqlite3");
        {
            let database = Database::open(&path).expect("database");
            WorkspaceService::new(&database)
                .add_website(&WebsiteInput {
                    url: "https://persist.example.com".to_string(),
                    display_name: Some("Persistent website".to_string()),
                    project_id: None,
                })
                .expect("add website");
        }
        {
            let database = Database::open(&path).expect("reopen database");
            let websites = WorkspaceService::new(&database)
                .list_websites(None, 20)
                .expect("list websites");
            assert_eq!(websites.len(), 1);
            assert_eq!(websites[0].display_name, "Persistent website");
        }
    }

    #[test]
    fn indexed_projects_remain_visible_after_database_reopen() {
        let project = tempdir().expect("project");
        fs::write(
            project.path().join("lib.ts"),
            "export const persistedProject = true;",
        )
        .expect("fixture");
        let storage = tempdir().expect("storage");
        let database_path = storage.path().join("workspace.sqlite3");

        let project_id = {
            let database = Database::open(&database_path).expect("database");
            ProjectIndexService::new(&database)
                .index_project(project.path())
                .expect("index")
                .project_id
        };

        let reopened = Database::open(&database_path).expect("reopen");
        let projects = WorkspaceService::new(&reopened)
            .list_projects(None, 20)
            .expect("projects");
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, project_id);
    }

    #[test]
    fn project_listing_search_and_removal_use_existing_index_identity() {
        let database = Database::open_in_memory().expect("database");
        let root = tempdir().expect("project");
        fs::write(
            root.path().join("main.ts"),
            "export function dashboardValue() { return 1; }",
        )
        .expect("fixture");
        let summary = ProjectIndexService::new(&database)
            .index_project(root.path())
            .expect("index");
        let service = WorkspaceService::new(&database);
        let projects = service.list_projects(None, 20).expect("projects");
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, summary.project_id);
        assert_eq!(projects[0].file_count, 1);
        assert!(projects[0].symbol_count >= 1);

        let results = service.search("dashboardValue", 20).expect("search");
        assert!(results.iter().any(|result| result.kind == "symbol"));
        assert!(service.search("   ", 20).expect("empty search").is_empty());
        assert!(service.search(&"z".repeat(4096), 20).expect("long search").is_empty());

        assert!(service
            .remove_project(&summary.project_id)
            .expect("remove project"));
        assert!(service.list_projects(None, 20).expect("projects").is_empty());
    }

    #[test]
    fn preferences_round_trip_through_settings_table() {
        let database = Database::open_in_memory().expect("database");
        let service = WorkspaceService::new(&database);
        assert_eq!(service.preferences().expect("defaults"), AppPreferences::default());

        let saved = service
            .save_preferences(&AppPreferences {
                display_name: " Developer ".to_string(),
                theme: "DARK".to_string(),
                auto_run_security_on_import: true,
                auto_discover_tests_on_import: true,
            })
            .expect("save");
        assert_eq!(saved.display_name, "Developer");
        assert_eq!(saved.theme, "dark");
        assert_eq!(service.preferences().expect("load"), saved);
    }
}
