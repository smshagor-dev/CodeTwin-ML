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
const MIGRATION_0010: &str = include_str!("../migrations/0010_ml_inference_provenance.sql");
const MIGRATION_0011: &str = include_str!("../migrations/0011_verified_repair_workflow.sql");
const MIGRATION_0012: &str = include_str!("../migrations/0012_repair_transactional_application.sql");
const MIGRATION_0013: &str = include_str!("../migrations/0013_qa_test_discovery.sql");
const MIGRATION_0014: &str = include_str!("../migrations/0014_qa_test_execution.sql");
const MIGRATION_0015: &str = include_str!("../migrations/0015_qa_execution_manifest_binding.sql");
const MIGRATION_0016: &str = include_str!("../migrations/0016_qa_external_read_provenance.sql");
const MIGRATION_0017: &str = include_str!("../migrations/0017_dashboard_workspace.sql");
const MIGRATION_0018: &str = include_str!("../migrations/0018_authorized_web_security.sql");
const MIGRATION_0019: &str = include_str!("../migrations/0019_guided_security_operator.sql");

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
        self.apply_migration(10, MIGRATION_0010)?;
        self.apply_migration(11, MIGRATION_0011)?;
        self.apply_migration(12, MIGRATION_0012)?;
        self.apply_migration(13, MIGRATION_0013)?;
        self.apply_migration(14, MIGRATION_0014)?;
        self.apply_migration(15, MIGRATION_0015)?;
        self.apply_migration(16, MIGRATION_0016)?;
        self.apply_migration(17, MIGRATION_0017)?;
        self.apply_migration(18, MIGRATION_0018)?;
        self.apply_migration(19, MIGRATION_0019)?;
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
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projects','analysis_runs','files','symbols','graph_nodes','graph_edges','import_references','symbol_reference_observations','semantic_run_metrics','semantic_relations','semantic_symbol_states','semantic_import_resolutions','quality_run_metrics','security_run_metrics','database_artifacts','database_run_metrics','runtime_artifacts','runtime_run_metrics','ml_inference_records','ml_finding_links','repair_plans','repair_changes','repair_verification_runs','repair_verification_items','repair_application_runs','repair_application_items','qa_test_artifacts','qa_discovery_run_metrics','qa_execution_plans','qa_execution_runs','websites','web_security_scans','web_security_endpoints','web_security_findings','web_security_evidence','guided_security_sessions','guided_security_plan_items','guided_security_activity','guided_security_source_candidates','guided_security_finding_lifecycle','guided_security_retests','guided_security_comparisons','guided_security_fix_links')",
                [],
                |row| row.get(0),
            )
            .expect("query tables");
        assert_eq!(count, 43);
    }

    #[test]
    fn migrations_are_idempotent_and_numbered() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .expect("query migrations");
        assert_eq!(count, 19);
        for version in [10i64, 11, 12, 13, 14, 15, 16, 17, 18, 19] {
            let applied: i64 = db
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
                    [version],
                    |row| row.get(0),
                )
                .expect("query migration version");
            assert_eq!(applied, 1);
        }
    }

    #[test]
    fn upgrades_existing_v16_database_with_dashboard_workspace_schema() {
        let file = NamedTempFile::new().expect("temp db");
        {
            let db = Database::open(file.path()).expect("create current db");
            db.connection()
                .execute_batch(
                    "DROP TABLE websites;
                     DELETE FROM schema_migrations WHERE version = 17;",
                )
                .expect("rewind dashboard migration");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v16 db");
        let website_table: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='websites'",
                [],
                |row| row.get(0),
            )
            .expect("website table");
        let migration: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 17",
                [],
                |row| row.get(0),
            )
            .expect("migration 17");
        let indexes: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='index'
                   AND name IN ('idx_websites_project_updated','idx_websites_status_checked')",
                [],
                |row| row.get(0),
            )
            .expect("website indexes");
        assert_eq!(website_table, 1);
        assert_eq!(migration, 1);
        assert_eq!(indexes, 2);
    }

    #[test]
    fn upgrades_existing_v17_database_with_authorized_web_security_schema() {
        let file = NamedTempFile::new().expect("temp db");
        {
            let db = Database::open(file.path()).expect("create current db");
            db.connection()
                .execute_batch(
                    "DROP TABLE web_security_evidence;
                     DROP TABLE web_security_findings;
                     DROP TABLE web_security_endpoints;
                     DROP TABLE web_security_scans;
                     DELETE FROM schema_migrations WHERE version = 18;",
                )
                .expect("rewind web security migration");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v17 db");
        let tables: i64 = upgraded.connection().query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
             AND name IN ('web_security_scans','web_security_endpoints','web_security_findings','web_security_evidence')",
            [],
            |row| row.get(0),
        ).expect("web security tables");
        let migration: i64 = upgraded.connection().query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 18",
            [],
            |row| row.get(0),
        ).expect("migration 18");
        assert_eq!(tables, 4);
        assert_eq!(migration, 1);
    }

    #[test]
    fn upgrades_existing_v18_database_with_guided_security_operator_schema() {
        let file = NamedTempFile::new().expect("temp db");
        {
            let db = Database::open(file.path()).expect("create current db");
            db.connection()
                .execute_batch(
                    "DROP TABLE guided_security_fix_links;
                     DROP TABLE guided_security_comparisons;
                     DROP TABLE guided_security_retests;
                     DROP TABLE guided_security_finding_lifecycle;
                     DROP TABLE guided_security_source_candidates;
                     DROP TABLE guided_security_activity;
                     DROP TABLE guided_security_plan_items;
                     DROP TABLE guided_security_sessions;
                     DELETE FROM schema_migrations WHERE version = 19;",
                )
                .expect("rewind guided security migration");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v18 db");
        let tables: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
                 AND name IN ('guided_security_sessions','guided_security_plan_items',
                              'guided_security_activity','guided_security_source_candidates',
                              'guided_security_finding_lifecycle','guided_security_retests',
                              'guided_security_comparisons','guided_security_fix_links')",
                [],
                |row| row.get(0),
            )
            .expect("guided security tables");
        let migration: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 19",
                [],
                |row| row.get(0),
            )
            .expect("migration 19");
        assert_eq!(tables, 8);
        assert_eq!(migration, 1);
    }

    #[test]
    fn authorized_web_security_schema_has_bounded_inventory_and_finding_constraints() {
        let db = Database::open_in_memory().expect("database");
        let endpoint_columns = db
            .connection()
            .prepare("PRAGMA table_info(web_security_endpoints)")
            .expect("endpoint columns")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("endpoint column rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("endpoint columns");
        for expected in [
            "parameter_locations_json",
            "response_header_names_json",
            "cookie_names_json",
        ] {
            assert!(endpoint_columns.iter().any(|name| name == expected));
        }

        let index_count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (
                    'idx_web_security_scans_website_created',
                    'idx_web_security_scans_project_created',
                    'idx_web_security_scans_status_created',
                    'idx_web_security_endpoints_scan_method',
                    'idx_web_security_findings_scan_severity',
                    'idx_web_security_findings_endpoint',
                    'idx_web_security_evidence_finding'
                )",
                [],
                |row| row.get(0),
            )
            .expect("web security indexes");
        assert_eq!(index_count, 7);

        let scan_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='web_security_scans'",
                [],
                |row| row.get(0),
            )
            .expect("scan schema");
        assert!(scan_sql.contains("authorization_confirmed = 1"));

        let finding_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='web_security_findings'",
                [],
                |row| row.get(0),
            )
            .expect("finding schema");
        assert!(finding_sql.contains("'Potential','Likely','Confirmed'"));
        assert!(finding_sql.contains("'critical','high','medium','low','informational'"));
    }

    #[test]
    fn ml_inference_schema_does_not_store_raw_input_text() {
        let db = Database::open_in_memory().expect("open db");
        let mut statement = db
            .connection()
            .prepare("PRAGMA table_info(ml_inference_records)")
            .expect("table info");
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("columns")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect columns");
        assert!(columns.iter().any(|name| name == "input_sha256"));
        assert!(!columns
            .iter()
            .any(|name| name == "input_text" || name == "source_text"));
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
    fn repair_application_item_identity_is_run_scoped() {
        let db = Database::open_in_memory().expect("open db");
        let sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='repair_application_items'",
                [],
                |row| row.get(0),
            )
            .expect("application schema");
        assert!(sql.contains("PRIMARY KEY(run_id, change_id)"));
        assert!(sql.contains("UNIQUE(run_id, relative_path)"));
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
        let qa_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='qa_test_artifacts'",
                [],
                |row| row.get(0),
            )
            .expect("QA artifact schema");
        assert!(qa_sql.contains("UNIQUE(project_id, path_identity, framework, evidence_kind)"));
    }

    #[test]
    fn qa_execution_schema_separates_plans_from_runs() {
        let db = Database::open_in_memory().expect("open db");
        let plan_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='qa_execution_plans'",
                [],
                |row| row.get(0),
            )
            .expect("plan schema");
        assert!(plan_sql.contains("'blocked','planned','approved'"));
        let run_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='qa_execution_runs'",
                [],
                |row| row.get(0),
            )
            .expect("run schema");
        assert!(run_sql.contains("'timed_out'"));
        assert!(run_sql.contains("'infrastructure_error'"));

        let mut plan_columns = db
            .connection()
            .prepare("PRAGMA table_info(qa_execution_plans)")
            .expect("plan columns");
        let plan_columns = plan_columns
            .query_map([], |row| row.get::<_, String>(1))
            .expect("plan column rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("plan column list");
        for expected in [
            "approved_project_manifest_sha256",
            "approved_project_manifest_json",
            "approved_external_read_surface_sha256",
            "approved_external_read_surface_json",
        ] {
            assert!(plan_columns.iter().any(|name| name == expected));
        }

        let mut run_columns = db
            .connection()
            .prepare("PRAGMA table_info(qa_execution_runs)")
            .expect("run columns");
        let run_columns = run_columns
            .query_map([], |row| row.get::<_, String>(1))
            .expect("run column rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("run column list");
        for expected in ["project_manifest_sha256", "external_read_surface_sha256"] {
            assert!(run_columns.iter().any(|name| name == expected));
        }

        let trigger_count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (\
                 'qa_execution_approval_requires_manifest',\
                 'qa_execution_approved_manifest_immutable',\
                 'qa_execution_run_manifest_matches_plan',\
                 'qa_execution_approval_requires_external_surface',\
                 'qa_execution_approved_external_surface_immutable',\
                 'qa_execution_plan_spec_immutable',\
                 'qa_execution_approved_provenance_immutable',\
                 'qa_execution_run_external_surface_matches_plan')",
                [],
                |row| row.get(0),
            )
            .expect("QA provenance triggers");
        assert_eq!(trigger_count, 8);
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
