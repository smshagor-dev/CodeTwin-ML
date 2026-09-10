use std::collections::{BTreeSet, VecDeque};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Database, SourceFileRecord};

const MAX_IMPACT_FILES: usize = 500;
const MAX_IMPACT_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactedFileRecord {
    pub file_id: String,
    pub relative_path: String,
    pub language: Option<String>,
    pub depth: usize,
    pub via_import_id: String,
    pub via_source_file_id: String,
    pub via_raw_specifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactReport {
    pub root: SourceFileRecord,
    pub affected_files: Vec<ImpactedFileRecord>,
    pub requested_depth: usize,
    pub effective_depth: usize,
    pub limit: usize,
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum ImpactAnalysisError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub struct ImpactAnalysisService<'a> {
    database: &'a Database,
}

impl<'a> ImpactAnalysisService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    /// Returns files that can be proven to depend on `file_id` through resolved local imports.
    ///
    /// This intentionally does not infer call edges, dynamic imports, package aliases, or runtime
    /// behavior. Every returned hop is backed by a persisted `import_references` row whose
    /// resolution state is `resolved_local`.
    pub fn analyze_file(
        &self,
        file_id: &str,
        max_depth: usize,
        limit: usize,
    ) -> Result<Option<ImpactReport>, ImpactAnalysisError> {
        let connection = self.database.connection();
        let root = connection
            .query_row(
                "SELECT id, project_id, relative_path, COALESCE(relative_path_identity, relative_path), language, content_hash, byte_size, ast_root_kind, parse_state, is_active\
                 FROM files WHERE id = ?1 AND is_active = 1",
                [file_id],
                map_file,
            )
            .optional()?;
        let Some(root) = root else {
            return Ok(None);
        };

        let effective_depth = max_depth.clamp(1, MAX_IMPACT_DEPTH);
        let limit = limit.clamp(1, MAX_IMPACT_FILES);
        let mut visited = BTreeSet::new();
        visited.insert(root.id.clone());
        let mut queue = VecDeque::new();
        queue.push_back((root.id.clone(), 0usize));
        let mut affected_files = Vec::new();
        let mut truncated = false;

        let mut statement = connection.prepare(
            "SELECT ir.id, ir.source_file_id, ir.raw_specifier, f.relative_path, f.language\
             FROM import_references ir\
             JOIN files f ON f.id = ir.source_file_id\
             WHERE ir.project_id = ?1\
               AND ir.resolved_target_file_id = ?2\
               AND ir.resolution_state = 'resolved_local'\
               AND f.is_active = 1\
             ORDER BY f.relative_path, ir.start_line, ir.start_column, ir.id",
        )?;

        while let Some((target_file_id, depth)) = queue.pop_front() {
            if depth >= effective_depth {
                continue;
            }

            let rows = statement.query_map(params![root.project_id, target_file_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?;

            for row in rows {
                let (import_id, source_file_id, raw_specifier, relative_path, language) = row?;
                if visited.contains(&source_file_id) {
                    continue;
                }
                if affected_files.len() >= limit {
                    truncated = true;
                    break;
                }

                visited.insert(source_file_id.clone());
                let next_depth = depth + 1;
                affected_files.push(ImpactedFileRecord {
                    file_id: source_file_id.clone(),
                    relative_path,
                    language,
                    depth: next_depth,
                    via_import_id: import_id,
                    via_source_file_id: source_file_id.clone(),
                    via_raw_specifier: raw_specifier,
                });
                if next_depth < effective_depth {
                    queue.push_back((source_file_id, next_depth));
                }
            }

            if truncated {
                break;
            }
        }

        Ok(Some(ImpactReport {
            root,
            affected_files,
            requested_depth: max_depth,
            effective_depth,
            limit,
            truncated,
        }))
    }
}

fn map_file(row: &rusqlite::Row<'_>) -> Result<SourceFileRecord, rusqlite::Error> {
    Ok(SourceFileRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        relative_path: row.get(2)?,
        relative_path_identity: row.get(3)?,
        language: row.get(4)?,
        content_hash: row.get(5)?,
        byte_size: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
        ast_root_kind: row.get(7)?,
        parse_state: row.get(8)?,
        is_active: row.get::<_, i64>(9)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::{Database, ProjectIndexService, ProjectQueryService};

    use super::ImpactAnalysisService;

    #[test]
    fn reports_only_evidenced_transitive_dependents_in_deterministic_order() {
        let repository = tempdir().expect("repository");
        fs::write(repository.path().join("a.ts"), "export const a = 1;\n").expect("a");
        fs::write(
            repository.path().join("b.ts"),
            "import { a } from './a';\nexport const b = a;\n",
        )
        .expect("b");
        fs::write(
            repository.path().join("c.ts"),
            "import { b } from './b';\nexport const c = b;\n",
        )
        .expect("c");
        fs::write(
            repository.path().join("d.ts"),
            "import { a } from './a';\nexport const d = a;\n",
        )
        .expect("d");
        fs::write(
            repository.path().join("external.ts"),
            "import React from 'react';\nexport const external = React;\n",
        )
        .expect("external");

        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(repository.path())
            .expect("index");
        let files = ProjectQueryService::new(&database)
            .list_files(&summary.project_id, Some("a.ts"), 10)
            .expect("files");
        let root = files.iter().find(|file| file.relative_path == "a.ts").expect("a file");

        let report = ImpactAnalysisService::new(&database)
            .analyze_file(&root.id, 8, 500)
            .expect("impact")
            .expect("root");
        let observed: Vec<(&str, usize)> = report
            .affected_files
            .iter()
            .map(|file| (file.relative_path.as_str(), file.depth))
            .collect();

        assert_eq!(observed, vec![("b.ts", 1), ("d.ts", 1), ("c.ts", 2)]);
        assert!(!report.truncated);
        assert!(report
            .affected_files
            .iter()
            .all(|file| file.via_raw_specifier.starts_with("./")));
        assert!(!report
            .affected_files
            .iter()
            .any(|file| file.relative_path == "external.ts"));
    }

    #[test]
    fn bounds_depth_and_result_count_without_fabricating_more_edges() {
        let repository = tempdir().expect("repository");
        fs::write(repository.path().join("a.ts"), "export const a = 1;\n").expect("a");
        fs::write(
            repository.path().join("b.ts"),
            "import { a } from './a';\nexport const b = a;\n",
        )
        .expect("b");
        fs::write(
            repository.path().join("c.ts"),
            "import { b } from './b';\nexport const c = b;\n",
        )
        .expect("c");

        let database = Database::open_in_memory().expect("database");
        let summary = ProjectIndexService::new(&database)
            .index_project(repository.path())
            .expect("index");
        let root = ProjectQueryService::new(&database)
            .list_files(&summary.project_id, Some("a.ts"), 10)
            .expect("files")
            .into_iter()
            .find(|file| file.relative_path == "a.ts")
            .expect("a file");

        let shallow = ImpactAnalysisService::new(&database)
            .analyze_file(&root.id, 1, 500)
            .expect("impact")
            .expect("root");
        assert_eq!(shallow.affected_files.len(), 1);
        assert_eq!(shallow.affected_files[0].relative_path, "b.ts");

        let limited = ImpactAnalysisService::new(&database)
            .analyze_file(&root.id, 8, 1)
            .expect("impact")
            .expect("root");
        assert_eq!(limited.affected_files.len(), 1);
        assert!(limited.truncated);
    }
}
