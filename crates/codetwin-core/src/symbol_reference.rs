use std::{fs, path::PathBuf};

use reference_indexer::{extract_references, ANALYZER_VERSION};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{deterministic_id, Database};

const MAX_REFERENCE_RESULTS: usize = 500;

#[derive(Debug, Error)]
pub enum SymbolReferenceError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("reference index error: {0}")]
    Index(#[from] reference_indexer::ReferenceIndexError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolReferenceObservationRecord {
    pub id: String,
    pub project_id: String,
    pub source_file_id: String,
    pub name: String,
    pub kind: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub analyzer_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceRefreshSummary {
    pub project_id: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub observations_written: usize,
}

#[derive(Debug, Clone)]
struct ActiveFile {
    id: String,
    relative_path: String,
    language: String,
}

#[derive(Debug, Clone)]
struct PendingObservation {
    source_file_id: String,
    name: String,
    kind: String,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

pub struct SymbolReferenceService<'a> {
    database: &'a Database,
}

impl<'a> SymbolReferenceService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn refresh_project(
        &self,
        project_id: &str,
    ) -> Result<Option<ReferenceRefreshSummary>, SymbolReferenceError> {
        let connection = self.database.connection();
        let root_path: Option<String> = connection
            .query_row(
                "SELECT root_path FROM projects WHERE id = ?1",
                [project_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(root_path) = root_path else {
            return Ok(None);
        };
        let root = fs::canonicalize(root_path)?;
        let files = load_active_files(connection, project_id)?;
        let mut pending = Vec::new();
        let mut files_scanned = 0usize;
        let mut files_skipped = 0usize;

        for file in files {
            if !is_supported_language(&file.language) {
                files_skipped += 1;
                continue;
            }
            let joined = root.join(PathBuf::from(&file.relative_path));
            let Ok(canonical) = fs::canonicalize(&joined) else {
                files_skipped += 1;
                continue;
            };
            if !canonical.starts_with(&root) || !canonical.is_file() {
                files_skipped += 1;
                continue;
            }
            let source = match fs::read_to_string(&canonical) {
                Ok(source) => source,
                Err(_) => {
                    files_skipped += 1;
                    continue;
                }
            };
            let observations = extract_references(&file.language, &source)?;
            files_scanned += 1;
            pending.extend(
                observations
                    .into_iter()
                    .map(|observation| PendingObservation {
                        source_file_id: file.id.clone(),
                        name: observation.name,
                        kind: observation.kind,
                        start_line: observation.start_line,
                        start_column: observation.start_column,
                        end_line: observation.end_line,
                        end_column: observation.end_column,
                    }),
            );
        }

        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "DELETE FROM symbol_reference_observations WHERE project_id = ?1",
            [project_id],
        )?;
        for observation in &pending {
            let id = deterministic_id(
                "symbol-reference-observation",
                &[
                    project_id,
                    &observation.source_file_id,
                    &observation.kind,
                    &observation.name,
                    &observation.start_line.to_string(),
                    &observation.start_column.to_string(),
                    &observation.end_line.to_string(),
                    &observation.end_column.to_string(),
                ],
            );
            transaction.execute(
                "INSERT INTO symbol_reference_observations( \
                   id, project_id, source_file_id, name, kind, start_line, start_column, end_line, end_column, analyzer_version \
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    id,
                    project_id,
                    observation.source_file_id,
                    observation.name,
                    observation.kind,
                    to_i64(observation.start_line),
                    to_i64(observation.start_column),
                    to_i64(observation.end_line),
                    to_i64(observation.end_column),
                    ANALYZER_VERSION,
                ],
            )?;
        }
        transaction.commit()?;

        Ok(Some(ReferenceRefreshSummary {
            project_id: project_id.to_string(),
            files_scanned,
            files_skipped,
            observations_written: pending.len(),
        }))
    }

    pub fn list_file_observations(
        &self,
        file_id: &str,
        limit: usize,
    ) -> Result<Vec<SymbolReferenceObservationRecord>, SymbolReferenceError> {
        let limit = limit.clamp(1, MAX_REFERENCE_RESULTS);
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, source_file_id, name, kind, start_line, start_column, end_line, end_column, analyzer_version \
             FROM symbol_reference_observations \
             WHERE source_file_id = ?1 \
             ORDER BY start_line, start_column, end_line, end_column, kind, name, id \
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![file_id, to_i64(limit)], |row| {
            Ok(SymbolReferenceObservationRecord {
                id: row.get(0)?,
                project_id: row.get(1)?,
                source_file_id: row.get(2)?,
                name: row.get(3)?,
                kind: row.get(4)?,
                start_line: to_usize(row.get(5)?),
                start_column: to_usize(row.get(6)?),
                end_line: to_usize(row.get(7)?),
                end_column: to_usize(row.get(8)?),
                analyzer_version: row.get(9)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn load_active_files(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> Result<Vec<ActiveFile>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT id, relative_path, COALESCE(language, '') \
         FROM files WHERE project_id = ?1 AND is_active = 1 \
         ORDER BY relative_path, id",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok(ActiveFile {
            id: row.get(0)?,
            relative_path: row.get(1)?,
            language: row.get(2)?,
        })
    })?;
    rows.collect()
}

fn is_supported_language(language: &str) -> bool {
    matches!(language, "TypeScript" | "TypeScript TSX" | "JavaScript")
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{Database, ProjectIndexService, ProjectQueryService};

    use super::SymbolReferenceService;

    #[test]
    fn persists_only_supported_direct_call_observations() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("main.ts"),
            "function local() { return 1; }\nclass Service {}\nlocal();\nnew Service();\nobj.method();\n",
        )
        .expect("write ts");
        fs::write(dir.path().join("helper.py"), "print('ignored for now')\n").expect("write py");

        let database = Database::open_in_memory().expect("database");
        let indexed = ProjectIndexService::new(&database)
            .index_project(dir.path())
            .expect("index project");
        let files = ProjectQueryService::new(&database)
            .list_files(&indexed.project_id, Some("main.ts"), 10)
            .expect("files");
        let file = files.first().expect("main file");

        let summary = SymbolReferenceService::new(&database)
            .refresh_project(&indexed.project_id)
            .expect("refresh")
            .expect("project");
        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.files_skipped, 1);
        assert_eq!(summary.observations_written, 2);

        let observations = SymbolReferenceService::new(&database)
            .list_file_observations(&file.id, 50)
            .expect("observations");
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].name, "local");
        assert_eq!(observations[0].kind, "call");
        assert_eq!(observations[1].name, "Service");
        assert_eq!(observations[1].kind, "constructor");
        assert!(!observations.iter().any(|item| item.name == "method"));
    }

    #[test]
    fn refresh_replaces_stale_observations() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("main.js");
        fs::write(&path, "function run() {}\nrun();\n").expect("initial source");

        let database = Database::open_in_memory().expect("database");
        let first = ProjectIndexService::new(&database)
            .index_project(dir.path())
            .expect("first index");
        let service = SymbolReferenceService::new(&database);
        let initial = service
            .refresh_project(&first.project_id)
            .expect("first refresh")
            .expect("project");
        assert_eq!(initial.observations_written, 1);

        fs::write(&path, "function run() {}\n").expect("updated source");
        ProjectIndexService::new(&database)
            .index_project(dir.path())
            .expect("second index");
        let refreshed = service
            .refresh_project(&first.project_id)
            .expect("second refresh")
            .expect("project");
        assert_eq!(refreshed.observations_written, 0);

        let count: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM symbol_reference_observations WHERE project_id = ?1",
                [&first.project_id],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 0);
    }
}
