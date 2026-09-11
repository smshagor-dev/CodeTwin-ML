use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;

const MIGRATION_0001: &str = include_str!("../migrations/0001_initial.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_digital_twin_persistence.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_symbol_reference_observations.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_semantic_symbol_resolution.sql");
const MIGRATION_0005: &str = include_str!("../migrations/0005_lsp_semantic_enrichment.sql");
const MIGRATION_0006: &str = include_str!("../migrations/0006_code_quality_analysis.sql");
const MIGRATION_0007: &str = include_str!("../migrations/0007_security_analysis.sql");
const MIGRATION_0008: &str = include_str!("../migrations/0008_database_analysis.sql");
const MIGRATION_0009: &str = include_str!("../migrations/0009_runtime_reliability.sql");
const MIGRATION_0011: &str = include_str!("../migrations/0011_verified_repair_workflow.sql");

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self { connection };
        database.migrate()?;
        Ok(database)
    }

    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self { connection };
        database.migrate()?;
        Ok(database)
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    fn migrate(&self) -> Result<(), DatabaseError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);",
        )?;
        self.apply_migration(1, MIGRATION_0001)?;
        self.apply_migration(2, MIGRATION_0002)?;
        self.apply_migration(3, MIGRATION_0003)?;
        self.apply_migration(4, MIGRATION_0004)?;
        self.apply_migration(5, MIGRATION_0005)?;
        self.apply_migration(6, MIGRATION_0006)?;
        self.apply_migration(7, MIGRATION_0007)?;
        self.apply_migration(8, MIGRATION_0008)?;
        self.apply_migration(9, MIGRATION_0009)?;
        // Version 10 is intentionally reserved by the open ML-provenance work.
        self.apply_migration(11, MIGRATION_0011)?;
        Ok(())
    }

    fn apply_migration(&self, version: i64, sql: &str) -> Result<(), DatabaseError> {
        let applied: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
            [version],
            |row| row.get(0),
        )?;
        if applied {
            return Ok(());
        }

        let tx = self.connection.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations(version) VALUES (?1)",
            [version],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::Database;

    #[test]
    fn creates_expected_foundation_and_analysis_tables() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projects','analysis_runs','files','symbols','graph_nodes','graph_edges','import_references','symbol_reference_observations','semantic_run_metrics','semantic_relations','semantic_symbol_states','semantic_import_resolutions','quality_run_metrics','security_run_metrics','database_artifacts','database_run_metrics','runtime_artifacts','runtime_run_metrics','repair_plans','repair_changes','repair_verification_runs','repair_verification_items')",
                [],
                |row| row.get(0),
            )
            .expect("query tables");
        assert_eq!(count, 22);
    }

    #[test]
    fn migrations_are_idempotent_and_numbered() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .expect("query migrations");
        assert_eq!(count, 10);
        let repair_version: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=11",
                [],
                |row| row.get(0),
            )
            .expect("repair migration");
        assert_eq!(repair_version, 1);
    }

    #[test]
    fn symbol_reference_resolution_columns_exist() {
        let db = Database::open_in_memory().expect("open db");
        let mut statement = db
            .connection()
            .prepare("PRAGMA table_info(symbol_reference_observations)")
            .expect("table info");
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect columns");
        assert!(columns.iter().any(|name| name == "resolution_state"));
        assert!(columns
            .iter()
            .any(|name| name == "resolved_target_symbol_id"));
    }

    #[test]
    fn finding_lifecycle_columns_exist() {
        let db = Database::open_in_memory().expect("open db");
        let mut statement = db
            .connection()
            .prepare("PRAGMA table_info(findings)")
            .expect("table info");
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect columns");
        assert!(columns.iter().any(|name| name == "analyzer_key"));
        assert!(columns.iter().any(|name| name == "last_run_id"));
        assert!(columns.iter().any(|name| name == "resolved_at"));
    }

    #[test]
    fn artifact_identity_is_project_scoped() {
        let db = Database::open_in_memory().expect("open db");
        for table in ["database_artifacts", "runtime_artifacts"] {
            let sql: String = db
                .connection()
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .expect("artifact schema");
            assert!(sql.contains("UNIQUE(project_id, path_identity)"));
        }
    }

    #[test]
    fn repair_change_identity_is_plan_scoped() {
        let db = Database::open_in_memory().expect("open db");
        let sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='repair_changes'",
                [],
                |row| row.get(0),
            )
            .expect("repair schema");
        assert!(sql.contains("UNIQUE(repair_id, relative_path)"));
    }

    #[test]
    fn file_database_uses_wal_and_foreign_keys() {
        let file = NamedTempFile::new().expect("temp db");
        let db = Database::open(file.path()).expect("open file db");
        let journal_mode: String = db
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        let foreign_keys: i64 = db
            .connection()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("foreign keys");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(foreign_keys, 1);
    }
}
