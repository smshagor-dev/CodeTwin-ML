use rusqlite::params;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Database;

const MAX_RESOLUTION_RESULTS: usize = 500;

#[derive(Debug, Error)]
pub enum SemanticResolutionError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticResolutionSummary {
    pub project_id: String,
    pub observations_examined: usize,
    pub resolved_same_file: usize,
    pub ambiguous: usize,
    pub unresolved: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticReferenceRecord {
    pub observation_id: String,
    pub project_id: String,
    pub source_file_id: String,
    pub name: String,
    pub kind: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub resolution_state: String,
    pub resolved_target_symbol_id: Option<String>,
}

#[derive(Debug)]
struct Observation {
    id: String,
    source_file_id: String,
    name: String,
    kind: String,
}

pub struct SemanticSymbolResolver<'a> {
    database: &'a Database,
}

impl<'a> SemanticSymbolResolver<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn resolve_project(
        &self,
        project_id: &str,
    ) -> Result<Option<SemanticResolutionSummary>, SemanticResolutionError> {
        let connection = self.database.connection();
        let project_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?1)",
            [project_id],
            |row| row.get(0),
        )?;
        if !project_exists {
            return Ok(None);
        }

        let observations = load_observations(connection, project_id)?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE symbol_reference_observations\
             SET resolution_state = 'observed', resolved_target_symbol_id = NULL, updated_at = CURRENT_TIMESTAMP\
             WHERE project_id = ?1",
            [project_id],
        )?;

        let mut resolved_same_file = 0usize;
        let mut ambiguous = 0usize;
        let mut unresolved = 0usize;

        for observation in &observations {
            let Some(expected_symbol_kind) = expected_symbol_kind(&observation.kind) else {
                update_resolution(&transaction, &observation.id, "unresolved", None)?;
                unresolved += 1;
                continue;
            };

            let candidates = load_candidates(
                &transaction,
                &observation.source_file_id,
                &observation.name,
                expected_symbol_kind,
            )?;
            match candidates.as_slice() {
                [symbol_id] => {
                    update_resolution(
                        &transaction,
                        &observation.id,
                        "resolved_same_file",
                        Some(symbol_id),
                    )?;
                    resolved_same_file += 1;
                }
                [] => {
                    update_resolution(&transaction, &observation.id, "unresolved", None)?;
                    unresolved += 1;
                }
                _ => {
                    update_resolution(&transaction, &observation.id, "ambiguous", None)?;
                    ambiguous += 1;
                }
            }
        }

        transaction.commit()?;
        Ok(Some(SemanticResolutionSummary {
            project_id: project_id.to_string(),
            observations_examined: observations.len(),
            resolved_same_file,
            ambiguous,
            unresolved,
        }))
    }

    pub fn list_file_resolutions(
        &self,
        file_id: &str,
        limit: usize,
    ) -> Result<Vec<SemanticReferenceRecord>, SemanticResolutionError> {
        let limit = limit.clamp(1, MAX_RESOLUTION_RESULTS);
        let mut statement = self.database.connection().prepare(
            "SELECT id, project_id, source_file_id, name, kind, start_line, start_column, end_line, end_column,\
                    resolution_state, resolved_target_symbol_id\
             FROM symbol_reference_observations\
             WHERE source_file_id = ?1\
             ORDER BY start_line, start_column, end_line, end_column, kind, name, id\
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![file_id, to_i64(limit)], |row| {
            Ok(SemanticReferenceRecord {
                observation_id: row.get(0)?,
                project_id: row.get(1)?,
                source_file_id: row.get(2)?,
                name: row.get(3)?,
                kind: row.get(4)?,
                start_line: to_usize(row.get(5)?),
                start_column: to_usize(row.get(6)?),
                end_line: to_usize(row.get(7)?),
                end_column: to_usize(row.get(8)?),
                resolution_state: row.get(9)?,
                resolved_target_symbol_id: row.get(10)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn load_observations(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> Result<Vec<Observation>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT o.id, o.source_file_id, o.name, o.kind\
         FROM symbol_reference_observations o\
         JOIN files f ON f.id = o.source_file_id\
         WHERE o.project_id = ?1 AND f.is_active = 1\
         ORDER BY f.relative_path, o.start_line, o.start_column, o.end_line, o.end_column, o.kind, o.name, o.id",
    )?;
    let rows = statement.query_map([project_id], |row| {
        Ok(Observation {
            id: row.get(0)?,
            source_file_id: row.get(1)?,
            name: row.get(2)?,
            kind: row.get(3)?,
        })
    })?;
    rows.collect()
}

fn load_candidates(
    connection: &rusqlite::Connection,
    file_id: &str,
    name: &str,
    kind: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT id FROM symbols\
         WHERE file_id = ?1 AND is_active = 1 AND name = ?2 AND kind = ?3\
         ORDER BY id LIMIT 2",
    )?;
    let rows = statement.query_map(params![file_id, name, kind], |row| row.get(0))?;
    rows.collect()
}

fn update_resolution(
    connection: &rusqlite::Connection,
    observation_id: &str,
    state: &str,
    target_symbol_id: Option<&String>,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "UPDATE symbol_reference_observations\
         SET resolution_state = ?2, resolved_target_symbol_id = ?3, updated_at = CURRENT_TIMESTAMP\
         WHERE id = ?1",
        params![observation_id, state, target_symbol_id],
    )?;
    Ok(())
}

fn expected_symbol_kind(reference_kind: &str) -> Option<&'static str> {
    match reference_kind {
        "call" => Some("function"),
        "constructor" => Some("class"),
        _ => None,
    }
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

    use crate::{Database, ProjectIndexService, ProjectQueryService, SymbolReferenceService};

    use super::SemanticSymbolResolver;

    #[test]
    fn resolves_only_unique_same_file_function_and_class_targets() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("main.ts"),
            "function run() { return 1; }\nclass Service {}\nrun();\nnew Service();\nmissing();\n",
        )
        .expect("write source");

        let database = Database::open_in_memory().expect("database");
        let indexed = ProjectIndexService::new(&database)
            .index_project(dir.path())
            .expect("index");
        SymbolReferenceService::new(&database)
            .refresh_project(&indexed.project_id)
            .expect("reference refresh")
            .expect("project");

        let summary = SemanticSymbolResolver::new(&database)
            .resolve_project(&indexed.project_id)
            .expect("resolve")
            .expect("project");
        assert_eq!(summary.observations_examined, 3);
        assert_eq!(summary.resolved_same_file, 2);
        assert_eq!(summary.ambiguous, 0);
        assert_eq!(summary.unresolved, 1);

        let file = ProjectQueryService::new(&database)
            .list_files(&indexed.project_id, Some("main.ts"), 10)
            .expect("files")
            .into_iter()
            .next()
            .expect("main.ts");
        let records = SemanticSymbolResolver::new(&database)
            .list_file_resolutions(&file.id, 20)
            .expect("records");
        let run = records.iter().find(|item| item.name == "run").expect("run");
        let service = records
            .iter()
            .find(|item| item.name == "Service")
            .expect("Service");
        let missing = records
            .iter()
            .find(|item| item.name == "missing")
            .expect("missing");
        assert_eq!(run.resolution_state, "resolved_same_file");
        assert!(run.resolved_target_symbol_id.is_some());
        assert_eq!(service.resolution_state, "resolved_same_file");
        assert!(service.resolved_target_symbol_id.is_some());
        assert_eq!(missing.resolution_state, "unresolved");
        assert!(missing.resolved_target_symbol_id.is_none());
    }

    #[test]
    fn marks_duplicate_same_file_names_ambiguous_instead_of_guessing() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("main.js"),
            "function run() {}\nfunction wrapper() { function run() {} return run(); }\nrun();\n",
        )
        .expect("write source");

        let database = Database::open_in_memory().expect("database");
        let indexed = ProjectIndexService::new(&database)
            .index_project(dir.path())
            .expect("index");
        SymbolReferenceService::new(&database)
            .refresh_project(&indexed.project_id)
            .expect("reference refresh")
            .expect("project");

        let summary = SemanticSymbolResolver::new(&database)
            .resolve_project(&indexed.project_id)
            .expect("resolve")
            .expect("project");
        assert_eq!(summary.resolved_same_file, 0);
        assert_eq!(summary.ambiguous, 2);
        assert_eq!(summary.unresolved, 0);

        let resolved_count: i64 = database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM symbol_reference_observations\
                 WHERE project_id = ?1 AND resolved_target_symbol_id IS NOT NULL",
                [&indexed.project_id],
                |row| row.get(0),
            )
            .expect("resolved count");
        assert_eq!(resolved_count, 0);
    }

    #[test]
    fn does_not_resolve_cross_file_name_matches_without_binding_evidence() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("target.ts"), "export function run() {}\n")
            .expect("target");
        fs::write(dir.path().join("main.ts"), "run();\n").expect("main");

        let database = Database::open_in_memory().expect("database");
        let indexed = ProjectIndexService::new(&database)
            .index_project(dir.path())
            .expect("index");
        SymbolReferenceService::new(&database)
            .refresh_project(&indexed.project_id)
            .expect("reference refresh")
            .expect("project");

        let summary = SemanticSymbolResolver::new(&database)
            .resolve_project(&indexed.project_id)
            .expect("resolve")
            .expect("project");
        assert_eq!(summary.resolved_same_file, 0);
        assert_eq!(summary.ambiguous, 0);
        assert_eq!(summary.unresolved, 1);
    }
}
