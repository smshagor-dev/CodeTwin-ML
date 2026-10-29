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
const MIGRATION_0012: &str =
    include_str!("../migrations/0012_repair_transactional_application.sql");
const MIGRATION_0013: &str = include_str!("../migrations/0013_qa_test_discovery.sql");
const MIGRATION_0014: &str = include_str!("../migrations/0014_qa_test_execution.sql");
const MIGRATION_0015: &str = include_str!("../migrations/0015_qa_execution_manifest_binding.sql");
const MIGRATION_0016: &str = include_str!("../migrations/0016_qa_external_read_provenance.sql");
const MIGRATION_0017: &str = include_str!("../migrations/0017_dashboard_workspace.sql");
const MIGRATION_0018: &str = include_str!("../migrations/0018_authorized_web_security.sql");
const MIGRATION_0019: &str = include_str!("../migrations/0019_guided_security_operator.sql");
const MIGRATION_0020: &str = include_str!("../migrations/0020_security_fix_verify.sql");
const MIGRATION_0021: &str = include_str!("../migrations/0021_security_remediation_campaigns.sql");
const MIGRATION_0022: &str = include_str!("../migrations/0022_source_route_mapping.sql");
const MIGRATION_0023: &str = include_str!("../migrations/0023_route_prefix_semantics.sql");
const MIGRATION_0024: &str = include_str!("../migrations/0024_campaign_regression_transitions.sql");
const MIGRATION_0025: &str = include_str!("../migrations/0025_supply_chain_scanning.sql");
const MIGRATION_0028: &str = include_str!("../migrations/0028_assessment_jobs.sql");
const MIGRATION_0029: &str = include_str!("../migrations/0029_native_agents.sql");
const MIGRATION_0030: &str = include_str!("../migrations/0030_native_agent_insights.sql");
const MIGRATION_0031: &str = include_str!("../migrations/0031_native_agent_memory.sql");
const MIGRATION_0032: &str = include_str!("../migrations/0032_native_agent_handoffs.sql");
const MIGRATION_0033: &str = include_str!("../migrations/0033_native_knowledge.sql");
const MIGRATION_0034: &str = include_str!("../migrations/0034_native_delegation.sql");
const MIGRATION_0035: &str = include_str!("../migrations/0035_native_task_intents.sql");
const MIGRATION_0036: &str = include_str!("../migrations/0036_native_worker_audit.sql");
const MIGRATION_0037: &str = include_str!("../migrations/0037_native_neural_embeddings.sql");
const MIGRATION_0038: &str = include_str!("../migrations/0038_network_assessment.sql");
const MIGRATION_0039: &str = include_str!("../migrations/0039_network_inspection.sql");
const MIGRATION_0040: &str = include_str!("../migrations/0040_network_https_posture.sql");
const MIGRATION_0041: &str = include_str!("../migrations/0041_network_https_diagnostics.sql");
const MIGRATION_0042: &str = include_str!("../migrations/0042_go_dispatch_audit.sql");
const MIGRATION_0043: &str = include_str!("../migrations/0043_native_action_log.sql");
const MIGRATION_0044: &str = include_str!("../migrations/0044_native_security_flows.sql");
const MIGRATION_0045: &str = include_str!("../migrations/0045_native_flow_followups.sql");
const MIGRATION_0046: &str = include_str!("../migrations/0046_native_flow_queue.sql");
const MIGRATION_0027: &str = include_str!("../migrations/0027_security_finding_reviews.sql");
const MIGRATION_0026: &str = include_str!("../migrations/0026_secret_history_scanning.sql");
const MIGRATION_0047: &str = include_str!("../migrations/0047_workflow_orchestration.sql");
const MIGRATION_0048: &str = include_str!("../migrations/0048_model_gateway.sql");
const MIGRATION_0049: &str = include_str!("../migrations/0049_knowledge_memory.sql");
const MIGRATION_0050: &str = include_str!("../migrations/0050_research_sources.sql");
const MIGRATION_0051: &str = include_str!("../migrations/0051_collaboration_automation.sql");
const MIGRATION_0052: &str = include_str!("../migrations/0052_security_intelligence.sql");
const MIGRATION_0053: &str = include_str!("../migrations/0053_temporal_memory.sql");

/// Highest schema version this build applies.
pub const LATEST_SCHEMA_VERSION: i64 = 53;
/// Pre-migration backups retained next to the database file.
const MIGRATION_BACKUPS_KEPT: usize = 3;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database backup failed: {0}")]
    Backup(String),
}

/// Indexing reuses a few dozen statements per file; with rusqlite's default of 16
/// they evicted each other and SQL preparation dominated indexing time.
const STATEMENT_CACHE_CAPACITY: usize = 128;

pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let existed = path.metadata().is_ok_and(|m| m.len() > 0);
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self { connection };
        if existed {
            database.backup_before_migration(path)?;
        }
        database.migrate()?;
        Ok(database)
    }

    /// Current applied schema version, or `None` for an empty/non-CodeTwin file.
    pub fn schema_version(&self) -> Result<Option<i64>, DatabaseError> {
        let has_table: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",
            [],
            |row| row.get(0),
        )?;
        if !has_table {
            return Ok(None);
        }
        Ok(self
            .connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })?)
    }

    /// Write a consistent copy of the database (`VACUUM INTO`). Used for
    /// pre-migration backups and exportable diagnostics.
    pub fn backup_to(&self, destination: &Path) -> Result<(), DatabaseError> {
        if destination.exists() {
            return Err(DatabaseError::Backup(
                "backup destination already exists".into(),
            ));
        }
        let target = destination
            .to_str()
            .ok_or_else(|| DatabaseError::Backup("backup path is not valid UTF-8".into()))?;
        self.connection.execute("VACUUM INTO ?1", [target])?;
        Ok(())
    }

    /// Before applying pending migrations to an existing database, keep a
    /// restorable copy. The upgrade does not proceed if the backup fails.
    fn backup_before_migration(
        &self,
        path: &Path,
    ) -> Result<Option<std::path::PathBuf>, DatabaseError> {
        let Some(current) = self.schema_version()? else {
            return Ok(None);
        };
        if current >= LATEST_SCHEMA_VERSION {
            return Ok(None);
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| DatabaseError::Backup("database path has no file name".into()))?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let backup = path.with_file_name(format!(
            "{name}.pre-v{current}-v{LATEST_SCHEMA_VERSION}-{stamp}.bak"
        ));
        self.backup_to(&backup)?;
        let prefix = format!("{name}.pre-v");
        if let Some(dir) = path.parent() {
            let mut backups: Vec<(String, std::path::PathBuf)> = std::fs::read_dir(dir)
                .map_err(|e| DatabaseError::Backup(e.to_string()))?
                .filter_map(Result::ok)
                .filter_map(|e| {
                    let file = e.file_name().into_string().ok()?;
                    (file.starts_with(&prefix) && file.ends_with(".bak")).then(|| (file, e.path()))
                })
                .collect();
            // Names end in a nanosecond timestamp; sort oldest first by it.
            backups.sort_by_key(|(file, _)| {
                file.trim_end_matches(".bak")
                    .rsplit('-')
                    .next()
                    .and_then(|t| t.parse::<u128>().ok())
                    .unwrap_or(0)
            });
            while backups.len() > MIGRATION_BACKUPS_KEPT {
                let (_, oldest) = backups.remove(0);
                let _ = std::fs::remove_file(oldest);
            }
        }
        Ok(Some(backup))
    }

    /// Open an already migrated file-backed SQLite database for a short-lived
    /// approved native specialist worker. Do not initialize schema, change
    /// journal mode or accidentally create a missing database while two
    /// analyzers start concurrently. The parent connection owns migrations.
    pub(crate) fn open_native_worker(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        // Passive specialists may persist independent analyzer results at the
        // same time. On Windows, short-lived SQLite WAL write contention can
        // exceed the generic five-second timeout. Wait for the active writer
        // rather than marking an approved review failed solely due to a lock.
        // This is bounded and applies only to native specialist connections.
        connection.busy_timeout(std::time::Duration::from_secs(30))?;
        connection.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
        connection.pragma_update(None, "foreign_keys", "ON")?;
        // Fail closed if called with an unrelated or uninitialized SQLite file.
        let _: i64 = connection.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
        Ok(Self { connection })
    }

    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let connection = Connection::open_in_memory()?;
        connection.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
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
        self.apply_migration(20, MIGRATION_0020)?;
        self.apply_migration(21, MIGRATION_0021)?;
        self.apply_migration(22, MIGRATION_0022)?;
        self.apply_migration(23, MIGRATION_0023)?;
        self.apply_migration(24, MIGRATION_0024)?;
        self.apply_migration(25, MIGRATION_0025)?;
        self.apply_migration(26, MIGRATION_0026)?;
        self.apply_migration(27, MIGRATION_0027)?;
        self.apply_migration(28, MIGRATION_0028)?;
        self.apply_migration(29, MIGRATION_0029)?;
        self.apply_migration(30, MIGRATION_0030)?;
        self.apply_migration(31, MIGRATION_0031)?;
        self.apply_migration(32, MIGRATION_0032)?;
        self.apply_migration(33, MIGRATION_0033)?;
        self.apply_migration(34, MIGRATION_0034)?;
        self.apply_migration(35, MIGRATION_0035)?;
        self.apply_migration(36, MIGRATION_0036)?;
        self.apply_migration(37, MIGRATION_0037)?;
        self.apply_migration(38, MIGRATION_0038)?;
        self.apply_migration(39, MIGRATION_0039)?;
        self.apply_migration(40, MIGRATION_0040)?;
        self.apply_migration(41, MIGRATION_0041)?;
        self.apply_migration(42, MIGRATION_0042)?;
        self.apply_migration(43, MIGRATION_0043)?;
        self.apply_migration(44, MIGRATION_0044)?;
        self.apply_migration(45, MIGRATION_0045)?;
        self.apply_migration(46, MIGRATION_0046)?;
        self.apply_migration(47, MIGRATION_0047)?;
        self.apply_migration(48, MIGRATION_0048)?;
        self.apply_migration(49, MIGRATION_0049)?;
        self.apply_migration(50, MIGRATION_0050)?;
        self.apply_migration(51, MIGRATION_0051)?;
        self.apply_migration(52, MIGRATION_0052)?;
        self.apply_migration(53, MIGRATION_0053)?;
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

    use super::{Database, LATEST_SCHEMA_VERSION};

    fn backups(dir: &std::path::Path, prefix: &str) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path())
            .collect()
    }

    #[test]
    fn upgrades_take_a_restorable_backup_and_prune_old_ones() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("codetwin.sqlite3");
        for _ in 0..5 {
            {
                let db = Database::open(&path).expect("open");
                // Simulate an older schema so the next open must upgrade.
                db.connection()
                    .execute_batch(
                        "DROP TABLE knowledge_conflicts; DROP TABLE memory_item_versions;
                         DROP TABLE memory_neural_vectors;
                         DROP INDEX idx_kg_edges_current;
                         ALTER TABLE kg_edges DROP COLUMN superseded_by;
                         ALTER TABLE kg_edges DROP COLUMN invalidated_ms;
                         ALTER TABLE kg_edges DROP COLUMN valid_from_ms;
                         ALTER TABLE memory_items DROP COLUMN version;
                         DELETE FROM schema_migrations WHERE version = 53;",
                    )
                    .expect("downgrade");
            }
            let db = Database::open(&path).expect("upgrade");
            assert_eq!(db.schema_version().unwrap(), Some(LATEST_SCHEMA_VERSION));
        }
        let kept = backups(dir.path(), "codetwin.sqlite3.pre-v52-v53-");
        assert_eq!(kept.len(), 3, "older backups are pruned");
        let restored = Database::open(&kept[0]).expect("backup opens and migrates");
        assert_eq!(
            restored.schema_version().unwrap(),
            Some(LATEST_SCHEMA_VERSION)
        );
        drop(restored);
        // A database already at the latest version takes no backup.
        let fresh = dir.path().join("fresh.sqlite3");
        Database::open(&fresh).expect("fresh");
        Database::open(&fresh).expect("reopen");
        assert!(backups(dir.path(), "fresh.sqlite3.pre-v").is_empty());
    }

    #[test]
    fn creates_expected_foundation_and_analysis_tables() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projects','analysis_runs','files','symbols','graph_nodes','graph_edges','import_references','symbol_reference_observations','semantic_run_metrics','semantic_relations','semantic_symbol_states','semantic_import_resolutions','quality_run_metrics','security_run_metrics','database_artifacts','database_run_metrics','runtime_artifacts','runtime_run_metrics','ml_inference_records','ml_finding_links','repair_plans','repair_changes','repair_verification_runs','repair_verification_items','repair_application_runs','repair_application_items','qa_test_artifacts','qa_discovery_run_metrics','qa_execution_plans','qa_execution_runs','websites','web_security_scans','web_security_endpoints','web_security_findings','web_security_evidence','guided_security_sessions','guided_security_plan_items','guided_security_activity','guided_security_source_candidates','guided_security_finding_lifecycle','guided_security_retests','guided_security_comparisons','guided_security_fix_links','security_fix_attempts','security_fix_validation_results','security_fix_events',
                              'security_remediation_campaigns','security_remediation_campaign_findings',
                              'security_remediation_campaign_relationships','security_remediation_campaign_events',
                              'source_routes','source_handler_inputs','source_route_mounts','web_source_endpoint_links',
                              'secret_scan_run_metrics','dependency_inventory','osv_advisories','dependency_audit_run_metrics',
                              'secret_history_run_metrics')",
                [],
                |row| row.get(0),
            )
            .expect("query tables");
        assert_eq!(count, 59);
    }

    #[test]
    fn migrations_are_idempotent_and_numbered() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("query migrations");
        assert_eq!(count, LATEST_SCHEMA_VERSION);
        for version in [
            10i64, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        ] {
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
                    "ALTER TABLE import_references DROP COLUMN bindings_json;
                     DROP TABLE web_source_endpoint_links;
                     DROP TABLE source_route_mounts;
                     DROP TABLE source_handler_inputs;
                     DROP TABLE source_routes;
                     DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DROP TABLE security_fix_events;
                     DROP TABLE security_fix_validation_results;
                     DROP TABLE security_fix_attempts;
                     DROP TABLE guided_security_fix_links;
                     DROP TABLE guided_security_comparisons;
                     DROP TABLE guided_security_retests;
                     DROP TABLE guided_security_finding_lifecycle;
                     DROP TABLE guided_security_source_candidates;
                     DROP TABLE guided_security_activity;
                     DROP TABLE guided_security_plan_items;
                     DROP TABLE guided_security_sessions;
                     DROP TABLE web_security_evidence;
                     DROP TABLE web_security_findings;
                     DROP TABLE web_security_endpoints;
                     DROP TABLE web_security_scans;
                     DROP TABLE websites;
                     DELETE FROM schema_migrations WHERE version IN (17,18,19,20,21,22,23);",
                )
                .expect("rewind dashboard and later migrations");
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
                    "ALTER TABLE import_references DROP COLUMN bindings_json;
                     DROP TABLE web_source_endpoint_links;
                     DROP TABLE source_route_mounts;
                     DROP TABLE source_handler_inputs;
                     DROP TABLE source_routes;
                     DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DROP TABLE security_fix_events;
                     DROP TABLE security_fix_validation_results;
                     DROP TABLE security_fix_attempts;
                     DROP TABLE guided_security_fix_links;
                     DROP TABLE guided_security_comparisons;
                     DROP TABLE guided_security_retests;
                     DROP TABLE guided_security_finding_lifecycle;
                     DROP TABLE guided_security_source_candidates;
                     DROP TABLE guided_security_activity;
                     DROP TABLE guided_security_plan_items;
                     DROP TABLE guided_security_sessions;
                     DROP TABLE web_security_evidence;
                     DROP TABLE web_security_findings;
                     DROP TABLE web_security_endpoints;
                     DROP TABLE web_security_scans;
                     DELETE FROM schema_migrations WHERE version IN (18,19,20,21,22,23);",
                )
                .expect("rewind web security and guided migrations");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v17 db");
        let tables: i64 = upgraded.connection().query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
             AND name IN ('web_security_scans','web_security_endpoints','web_security_findings','web_security_evidence')",
            [],
            |row| row.get(0),
        ).expect("web security tables");
        let migration: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 18",
                [],
                |row| row.get(0),
            )
            .expect("migration 18");
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
                    "ALTER TABLE import_references DROP COLUMN bindings_json;
                     ALTER TABLE web_security_endpoints DROP COLUMN route_template;
                     DROP TABLE web_source_endpoint_links;
                     DROP TABLE source_route_mounts;
                     DROP TABLE source_handler_inputs;
                     DROP TABLE source_routes;
                     DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DROP TABLE security_fix_events;
                     DROP TABLE security_fix_validation_results;
                     DROP TABLE security_fix_attempts;
                     DROP TABLE guided_security_fix_links;
                     DROP TABLE guided_security_comparisons;
                     DROP TABLE guided_security_retests;
                     DROP TABLE guided_security_finding_lifecycle;
                     DROP TABLE guided_security_source_candidates;
                     DROP TABLE guided_security_activity;
                     DROP TABLE guided_security_plan_items;
                     DROP TABLE guided_security_sessions;
                     DELETE FROM schema_migrations WHERE version IN (19,20,21,22,23);",
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

        upgraded
            .connection()
            .execute(
                "INSERT INTO guided_security_sessions(
                    id,target_url,environment,testing_depth,auth_mode,status,
                    authorization_confirmed,config_json
                 ) VALUES ('guided-reopen','http://localhost:3000','local','standard',
                           'none','awaiting_approval',1,'{}')",
                [],
            )
            .expect("persist guided session");
        drop(upgraded);

        let reopened = Database::open(file.path()).expect("reopen upgraded v19 db");
        let migration_after_reopen: i64 = reopened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 19",
                [],
                |row| row.get(0),
            )
            .expect("migration 19 after reopen");
        let persisted: i64 = reopened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM guided_security_sessions WHERE id='guided-reopen'",
                [],
                |row| row.get(0),
            )
            .expect("persisted guided session");
        assert_eq!(migration_after_reopen, 1);
        assert_eq!(persisted, 1);
    }

    #[test]
    fn upgrades_existing_v19_database_with_security_fix_history_and_reopens() {
        let file = NamedTempFile::new().expect("temp db");
        {
            let db = Database::open(file.path()).expect("create current db");
            db.connection()
                .execute_batch(
                    "ALTER TABLE import_references DROP COLUMN bindings_json;
                     ALTER TABLE web_security_endpoints DROP COLUMN route_template;
                     DROP TABLE web_source_endpoint_links;
                     DROP TABLE source_route_mounts;
                     DROP TABLE source_handler_inputs;
                     DROP TABLE source_routes;
                     DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DROP TABLE security_fix_events;
                     DROP TABLE security_fix_validation_results;
                     DROP TABLE security_fix_attempts;
                     DELETE FROM schema_migrations WHERE version IN (20,21,22,23);",
                )
                .expect("rewind security fix migration");
            db.connection()
                .execute_batch(
                    "INSERT INTO web_security_scans(
                        id,target_url,status,phase,authorization_confirmed,
                        scope_json,config_json,auth_metadata_json
                     ) VALUES ('scan-v19','http://localhost:3000','completed','completed',1,'{}','{}','{}');
                     INSERT INTO web_security_findings(
                        id,scan_id,fingerprint,category,severity,confidence,target,
                        endpoint_url,method,parameter_name,title,description,
                        reproduction_summary,impact,remediation,references_json
                     ) VALUES (
                        'finding-v19','scan-v19','fingerprint-v19','sql_injection','high','Likely',
                        'http://localhost:3000','http://localhost:3000/search?q=hello','GET','q',
                        'Preserved finding','Preserved runtime finding','Local reproduction',
                        'Local impact','Parameterize query','[]'
                     );
                     INSERT INTO web_security_evidence(
                        id,finding_id,summary,request_metadata_json,response_metadata_json
                     ) VALUES ('evidence-v19','finding-v19','Preserved evidence','{}','{}');
                     INSERT INTO guided_security_sessions(
                        id,target_url,environment,testing_depth,auth_mode,status,
                        authorization_confirmed,config_json,scan_id
                     ) VALUES (
                        'guided-v19','http://localhost:3000','local','standard','none',
                        'completed',1,'{}','scan-v19'
                     );
                     INSERT INTO guided_security_finding_lifecycle(
                        finding_id,session_id,state
                     ) VALUES ('finding-v19','guided-v19','open');",
                )
                .expect("persist schema-19 guided and web-security history");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v19 db");
        let tables: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
                 AND name IN ('security_fix_attempts','security_fix_validation_results','security_fix_events')",
                [],
                |row| row.get(0),
            )
            .expect("security fix tables");
        let migration: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 20",
                [],
                |row| row.get(0),
            )
            .expect("migration 20");
        let preserved: i64 = upgraded
            .connection()
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM web_security_scans WHERE id='scan-v19') +
                    (SELECT COUNT(*) FROM web_security_findings WHERE id='finding-v19') +
                    (SELECT COUNT(*) FROM web_security_evidence WHERE id='evidence-v19') +
                    (SELECT COUNT(*) FROM guided_security_sessions WHERE id='guided-v19') +
                    (SELECT COUNT(*) FROM guided_security_finding_lifecycle WHERE finding_id='finding-v19')",
                [],
                |row| row.get(0),
            )
            .expect("schema-19 data preserved");
        assert_eq!(tables, 3);
        assert_eq!(migration, 1);
        assert_eq!(preserved, 5);
        drop(upgraded);

        let reopened = Database::open(file.path()).expect("reopen upgraded v20 db");
        let migration_after_reopen: i64 = reopened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 20",
                [],
                |row| row.get(0),
            )
            .expect("migration 20 after reopen");
        assert_eq!(migration_after_reopen, 1);
    }

    #[test]
    fn upgrades_existing_v20_database_with_remediation_campaign_schema_and_preserves_fix_history() {
        let file = NamedTempFile::new().expect("temp db");
        {
            let db = Database::open(file.path()).expect("create current db");
            db.connection()
                .execute_batch(
                    "INSERT INTO projects(id,root_path,display_name)
                     VALUES ('project-v20','/tmp/codetwin-v20','v20');
                     INSERT INTO web_security_scans(
                        id,project_id,target_url,status,phase,authorization_confirmed,
                        scope_json,config_json,auth_metadata_json
                     ) VALUES (
                        'scan-v20','project-v20','http://localhost:3000','completed','completed',
                        1,'{}','{}','{}'
                     );
                     INSERT INTO web_security_findings(
                        id,scan_id,fingerprint,category,severity,confidence,target,
                        endpoint_url,method,title,description,reproduction_summary,
                        impact,remediation,references_json
                     ) VALUES (
                        'finding-v20','scan-v20','fp-v20','sql_injection','high','Likely',
                        'http://localhost:3000','http://localhost:3000/search?q=a','GET',
                        'v20 finding','fixture','fixture','fixture','parameterize','[]'
                     );
                     INSERT INTO guided_security_sessions(
                        id,project_id,target_url,environment,testing_depth,auth_mode,status,
                        authorization_confirmed,config_json,scan_id
                     ) VALUES (
                        'session-v20','project-v20','http://localhost:3000','local','standard',
                        'none','completed',1,'{}','scan-v20'
                     );
                     INSERT INTO security_fix_attempts(
                        id,finding_id,session_id,project_id,attempt_number,eligibility,
                        category,status,root_cause_json,strategy_json,test_plan_json
                     ) VALUES (
                        'attempt-v20','finding-v20','session-v20','project-v20',1,
                        'INSUFFICIENT_EVIDENCE','sql_injection','prepared','[]','{}','{}'
                     );
                     ALTER TABLE import_references DROP COLUMN bindings_json;
                     ALTER TABLE web_security_endpoints DROP COLUMN route_template;
                     DROP TABLE web_source_endpoint_links;
                     DROP TABLE source_route_mounts;
                     DROP TABLE source_handler_inputs;
                     DROP TABLE source_routes;
                     DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DELETE FROM schema_migrations WHERE version IN (21,22,23);",
                )
                .expect("rewind campaign migration while preserving schema-20 data");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v20 db");
        let tables: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN (
                    'security_remediation_campaigns',
                    'security_remediation_campaign_findings',
                    'security_remediation_campaign_relationships',
                    'security_remediation_campaign_events'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("campaign tables");
        let migration: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=21",
                [],
                |row| row.get(0),
            )
            .expect("migration 21");
        let preserved: i64 = upgraded
            .connection()
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM web_security_scans WHERE id='scan-v20') +
                    (SELECT COUNT(*) FROM web_security_findings WHERE id='finding-v20') +
                    (SELECT COUNT(*) FROM guided_security_sessions WHERE id='session-v20') +
                    (SELECT COUNT(*) FROM security_fix_attempts WHERE id='attempt-v20')",
                [],
                |row| row.get(0),
            )
            .expect("schema-20 security evidence and fix history preserved");
        assert_eq!(tables, 4);
        assert_eq!(migration, 1);
        assert_eq!(preserved, 4);
        drop(upgraded);

        let reopened = Database::open(file.path()).expect("reopen upgraded v21 db");
        let migration_after_reopen: i64 = reopened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=21",
                [],
                |row| row.get(0),
            )
            .expect("migration 21 after reopen");
        assert_eq!(migration_after_reopen, 1);
    }

    #[test]
    fn upgrades_existing_v21_database_with_source_route_mapping_and_reopens() {
        let file = NamedTempFile::new().expect("temp db");
        {
            let db = Database::open(file.path()).expect("create current db");
            db.connection()
                .execute_batch(
                    "ALTER TABLE import_references DROP COLUMN bindings_json;
                     ALTER TABLE web_security_endpoints DROP COLUMN route_template;
                     DROP TABLE web_source_endpoint_links;
                     DROP TABLE source_route_mounts;
                     DROP TABLE source_handler_inputs;
                     DROP TABLE source_routes;
                     DELETE FROM schema_migrations WHERE version IN (22,23);",
                )
                .expect("rewind source route mapping migration");
        }

        let upgraded = Database::open(file.path()).expect("upgrade v21 db");
        let tables: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
                 AND name IN ('source_routes','source_handler_inputs','source_route_mounts','web_source_endpoint_links')",
                [],
                |row| row.get(0),
            )
            .expect("source route mapping tables");
        let migration: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=22",
                [],
                |row| row.get(0),
            )
            .expect("migration 22");
        let migration_23: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=23",
                [],
                |row| row.get(0),
            )
            .expect("migration 23");
        let route_prefix_column: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('source_routes') WHERE name='router_prefix'",
                [],
                |row| row.get(0),
            )
            .expect("route prefix column");
        let mount_mode_column: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('source_route_mounts') WHERE name='prefix_mode'",
                [],
                |row| row.get(0),
            )
            .expect("mount prefix mode column");
        let import_bindings_column: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('import_references') WHERE name='bindings_json'",
                [],
                |row| row.get(0),
            )
            .expect("import bindings column");
        let endpoint_template_column: i64 = upgraded
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('web_security_endpoints') WHERE name='route_template'",
                [],
                |row| row.get(0),
            )
            .expect("route template column");
        assert_eq!(tables, 4);
        assert_eq!(migration, 1);
        assert_eq!(migration_23, 1);
        assert_eq!(route_prefix_column, 1);
        assert_eq!(mount_mode_column, 1);
        assert_eq!(import_bindings_column, 1);
        assert_eq!(endpoint_template_column, 1);
        drop(upgraded);

        let reopened = Database::open(file.path()).expect("reopen upgraded v22 db");
        let migration_after_reopen: i64 = reopened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=22",
                [],
                |row| row.get(0),
            )
            .expect("migration 22 after reopen");
        let migration_23_after_reopen: i64 = reopened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=23",
                [],
                |row| row.get(0),
            )
            .expect("migration 23 after reopen");
        assert_eq!(migration_after_reopen, 1);
        assert_eq!(migration_23_after_reopen, 1);
    }

    #[test]
    fn security_fix_schema_constrains_history_and_has_no_secret_columns() {
        let db = Database::open_in_memory().expect("database");
        let indexes: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (
                    'idx_security_fix_attempts_finding',
                    'idx_security_fix_attempts_project_status',
                    'idx_security_fix_validation_attempt',
                    'idx_security_fix_events_attempt'
                )",
                [],
                |row| row.get(0),
            )
            .expect("security fix indexes");
        assert_eq!(indexes, 4);

        let attempt_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='security_fix_attempts'",
                [],
                |row| row.get(0),
            )
            .expect("security fix attempt schema");
        assert!(attempt_sql.contains("'AUTO_FIX_CANDIDATE','GUIDED_FIX_CANDIDATE','MANUAL_REMEDIATION','INSUFFICIENT_EVIDENCE'"));
        assert!(attempt_sql.contains(
            "'FIX_VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY','REGRESSION_DETECTED'"
        ));
        assert!(attempt_sql.contains("UNIQUE(finding_id, attempt_number)"));
        assert!(attempt_sql.contains("approved_safety_class"));
        assert!(attempt_sql.contains("caution_acknowledged"));
        assert!(attempt_sql.contains("retest_floor_rowid"));

        let trigger_count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='trigger' AND name IN (
                    'security_fix_attempt_approval_identity_immutable',
                    'security_fix_verified_requires_retest',
                    'security_fix_verified_insert_guard',
                    'security_fix_validation_results_immutable',
                    'security_fix_events_immutable',
                    'security_fix_attempt_status_transition_guard',
                    'security_fix_retest_state_transition_guard',
                    'security_fix_application_identity_guard'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("security fix triggers");
        assert_eq!(trigger_count, 8);

        for table in [
            "security_fix_attempts",
            "security_fix_validation_results",
            "security_fix_events",
        ] {
            let mut statement = db
                .connection()
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("security fix columns");
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("security fix column rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("security fix columns");
            assert!(columns.iter().all(|column| {
                !matches!(
                    column.as_str(),
                    "cookie"
                        | "cookie_header"
                        | "authorization"
                        | "bearer_token"
                        | "api_key"
                        | "password"
                        | "secret"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                )
            }));
        }
    }

    #[test]
    fn remediation_campaign_schema_enforces_guards_and_has_no_secret_columns() {
        let db = Database::open_in_memory().expect("database");

        let campaign_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type='table' AND name='security_remediation_campaigns'",
                [],
                |row| row.get(0),
            )
            .expect("campaign schema");
        assert!(campaign_sql.contains("completion_retest_floor_rowid"));
        assert!(campaign_sql.contains("completion_verification_started_at"));
        assert!(campaign_sql.contains("completion_verification_completed_at"));
        assert!(campaign_sql.contains("completion_source_hashes_json"));
        assert!(campaign_sql.contains("'COMPLETED_WITH_UNRESOLVED_FINDINGS'"));

        let indexes: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (
                    'idx_security_remediation_campaigns_project_created',
                    'idx_security_remediation_campaigns_scan_status',
                    'idx_security_remediation_campaign_findings_state',
                    'idx_security_remediation_campaign_findings_attempt',
                    'idx_security_remediation_relationships_campaign',
                    'idx_security_remediation_campaign_events_campaign'
                )",
                [],
                |row| row.get(0),
            )
            .expect("campaign indexes");
        assert_eq!(indexes, 6);

        let triggers: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (
                    'security_remediation_campaign_finding_scope_guard',
                    'security_remediation_campaign_approved_plan_immutable',
                    'security_remediation_campaign_finding_plan_immutable',
                    'security_remediation_campaign_status_transition_guard',
                    'security_remediation_campaign_finding_transition_guard',
                    'security_remediation_campaign_verified_requires_evidence',
                    'security_remediation_campaign_completion_verification_guard',
                    'security_remediation_campaign_events_immutable',
                    'security_remediation_campaign_events_delete_guard'
                )",
                [],
                |row| row.get(0),
            )
            .expect("campaign triggers");
        assert_eq!(triggers, 9);

        for table in [
            "security_remediation_campaigns",
            "security_remediation_campaign_findings",
            "security_remediation_campaign_relationships",
            "security_remediation_campaign_events",
        ] {
            let mut statement = db
                .connection()
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("campaign columns");
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("campaign column rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("campaign columns");
            assert!(columns.iter().all(|column| {
                !matches!(
                    column.as_str(),
                    "cookie"
                        | "cookie_header"
                        | "authorization"
                        | "bearer_token"
                        | "api_key"
                        | "password"
                        | "secret"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                )
            }));
        }
    }

    #[test]
    fn guided_security_schema_enforces_constraints_indexes_and_foreign_keys() {
        let db = Database::open_in_memory().expect("database");

        let index_count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN (
                    'idx_guided_security_sessions_project_created',
                    'idx_guided_security_sessions_status_created',
                    'idx_guided_security_plan_session',
                    'idx_guided_security_activity_session',
                    'idx_guided_security_source_finding',
                    'idx_guided_security_retests_finding'
                )",
                [],
                |row| row.get(0),
            )
            .expect("guided indexes");
        assert_eq!(index_count, 6);

        let session_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='guided_security_sessions'",
                [],
                |row| row.get(0),
            )
            .expect("guided session schema");
        assert!(session_sql.contains("'local','development','staging','authorized_production'"));
        assert!(session_sql.contains("'quick','standard','deep','custom'"));
        assert!(session_sql.contains(
            "'preparing','awaiting_approval','approved','running','completed','failed','cancelled'"
        ));
        assert!(session_sql
            .contains("scan_id TEXT UNIQUE REFERENCES web_security_scans(id) ON DELETE SET NULL"));
        assert!(session_sql.contains("authorization_confirmed = 1"));

        let retest_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='guided_security_retests'",
                [],
                |row| row.get(0),
            )
            .expect("guided retest schema");
        assert!(retest_sql.contains("'retest_passed','still_vulnerable','unable_to_verify'"));
        assert!(retest_sql.contains("'Potential','Likely','Confirmed'"));

        let lifecycle_sql: String = db
            .connection()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='guided_security_finding_lifecycle'",
                [],
                |row| row.get(0),
            )
            .expect("guided lifecycle schema");
        assert!(lifecycle_sql.contains("'open','fix_proposed','fix_applied','retest_passed','still_vulnerable','unable_to_verify'"));

        for table in [
            "guided_security_sessions",
            "guided_security_plan_items",
            "guided_security_activity",
            "guided_security_source_candidates",
            "guided_security_finding_lifecycle",
            "guided_security_retests",
            "guided_security_comparisons",
            "guided_security_fix_links",
        ] {
            let mut statement = db
                .connection()
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("guided table columns");
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("guided column rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("guided columns");
            assert!(columns.iter().all(|column| {
                !matches!(
                    column.as_str(),
                    "cookie"
                        | "cookie_header"
                        | "authorization"
                        | "bearer_token"
                        | "api_key"
                        | "password"
                        | "secret"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                )
            }));
        }

        db.connection()
            .execute(
                "INSERT INTO web_security_scans(
                    id,target_url,status,phase,authorization_confirmed,
                    scope_json,config_json,auth_metadata_json
                 ) VALUES ('scan-fk','http://localhost:3000','completed','completed',1,'{}','{}','{}')",
                [],
            )
            .expect("scan fixture");
        db.connection()
            .execute(
                "INSERT INTO guided_security_sessions(
                    id,target_url,environment,testing_depth,auth_mode,status,
                    authorization_confirmed,config_json,scan_id
                 ) VALUES ('session-fk','http://localhost:3000','local','standard',
                           'none','completed',1,'{}','scan-fk')",
                [],
            )
            .expect("guided session fixture");
        db.connection()
            .execute(
                "INSERT INTO guided_security_plan_items(
                    id,session_id,operation_key,endpoint_url,method,category,risk,selected,reason
                 ) VALUES ('plan-fk','session-fk','op','http://localhost:3000','GET',
                           'passive_analysis','SAFE',1,'fixture')",
                [],
            )
            .expect("guided plan fixture");

        db.connection()
            .execute("DELETE FROM web_security_scans WHERE id='scan-fk'", [])
            .expect("delete linked scan");
        let linked_scan: Option<String> = db
            .connection()
            .query_row(
                "SELECT scan_id FROM guided_security_sessions WHERE id='session-fk'",
                [],
                |row| row.get(0),
            )
            .expect("scan link after delete");
        assert!(linked_scan.is_none());

        db.connection()
            .execute(
                "DELETE FROM guided_security_sessions WHERE id='session-fk'",
                [],
            )
            .expect("delete guided session");
        let plan_count: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM guided_security_plan_items WHERE id='plan-fk'",
                [],
                |row| row.get(0),
            )
            .expect("cascade plan delete");
        assert_eq!(plan_count, 0);
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
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN ( \
                 'qa_execution_approval_requires_manifest', \
                 'qa_execution_approved_manifest_immutable', \
                 'qa_execution_run_manifest_matches_plan', \
                 'qa_execution_approval_requires_external_surface', \
                 'qa_execution_approved_external_surface_immutable', \
                 'qa_execution_plan_spec_immutable', \
                 'qa_execution_approved_provenance_immutable', \
                 'qa_execution_run_external_surface_matches_plan')",
                [],
                |row| row.get(0),
            )
            .expect("QA provenance triggers");
        assert_eq!(trigger_count, 8);
    }

    #[test]
    fn specialist_worker_opens_only_a_prepared_existing_sqlite_database() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("review.sqlite3");
        // A worker must not create a database or bootstrap its own schema.
        assert!(Database::open_native_worker(&path).is_err());
        assert!(!path.exists());
        let owner = Database::open(&path).unwrap();
        let worker = Database::open_native_worker(&path).unwrap();
        let foreign_keys: i64 = worker
            .connection()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        let wal: String = worker
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        assert_eq!(wal.to_ascii_lowercase(), "wal");
        let worker_timeout_ms: i64 = worker
            .connection()
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(worker_timeout_ms, 30_000);
        let migration_count: i64 = worker
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(migration_count > 0);
        // No worker connection needs a new migration or database file.
        assert!(owner.connection().is_autocommit());
        assert!(worker.connection().is_autocommit());

        let invalid = root.path().join("uninitialized.sqlite3");
        rusqlite::Connection::open(&invalid).unwrap();
        assert!(Database::open_native_worker(&invalid).is_err());
    }

    #[test]
    fn native_worker_waits_for_concurrent_sqlite_writer() {
        use std::sync::mpsc;
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("parallel-writes.sqlite3");
        let owner = Database::open(&path).unwrap();
        owner
            .connection()
            .execute_batch("CREATE TABLE native_lock_probe (value INTEGER NOT NULL);")
            .unwrap();
        // The worker opens after migrations and before the owner holds a
        // write transaction. Only the owner may apply migrations.
        let worker = Database::open_native_worker(&path).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            start_rx.recv().unwrap();
            worker
                .connection()
                .execute("INSERT INTO native_lock_probe(value) VALUES (2)", [])
                .unwrap();
        });
        ready_rx.recv().unwrap();
        let transaction = owner.connection().unchecked_transaction().unwrap();
        transaction
            .execute("INSERT INTO native_lock_probe(value) VALUES (1)", [])
            .unwrap();
        start_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        transaction.commit().unwrap();
        handle.join().unwrap();
        let values = owner
            .connection()
            .prepare("SELECT value FROM native_lock_probe ORDER BY value")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(values, vec![1, 2]);
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
