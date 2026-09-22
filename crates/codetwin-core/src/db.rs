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
const MIGRATION_0020: &str = include_str!("../migrations/0020_security_fix_verify.sql");
const MIGRATION_0021: &str = include_str!("../migrations/0021_security_remediation_campaigns.sql");
const MIGRATION_0022: &str = include_str!("../migrations/0022_source_route_mapping.sql");

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
        self.apply_migration(20, MIGRATION_0020)?;
        self.apply_migration(21, MIGRATION_0021)?;
        self.apply_migration(22, MIGRATION_0022)?;
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
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('projects','analysis_runs','files','symbols','graph_nodes','graph_edges','import_references','symbol_reference_observations','semantic_run_metrics','semantic_relations','semantic_symbol_states','semantic_import_resolutions','quality_run_metrics','security_run_metrics','database_artifacts','database_run_metrics','runtime_artifacts','runtime_run_metrics','ml_inference_records','ml_finding_links','repair_plans','repair_changes','repair_verification_runs','repair_verification_items','repair_application_runs','repair_application_items','qa_test_artifacts','qa_discovery_run_metrics','qa_execution_plans','qa_execution_runs','websites','web_security_scans','web_security_endpoints','web_security_findings','web_security_evidence','guided_security_sessions','guided_security_plan_items','guided_security_activity','guided_security_source_candidates','guided_security_finding_lifecycle','guided_security_retests','guided_security_comparisons','guided_security_fix_links','security_fix_attempts','security_fix_validation_results','security_fix_events',
                              'security_remediation_campaigns','security_remediation_campaign_findings',
                              'security_remediation_campaign_relationships','security_remediation_campaign_events',
                              'source_routes')",
                [],
                |row| row.get(0),
            )
            .expect("query tables");
        assert_eq!(count, 51);
    }

    #[test]
    fn migrations_are_idempotent_and_numbered() {
        let db = Database::open_in_memory().expect("open db");
        let count: i64 = db
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .expect("query migrations");
        assert_eq!(count, 22);
        for version in [10i64, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22] {
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
                    "DROP TABLE security_remediation_campaign_events;
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
                     DELETE FROM schema_migrations WHERE version IN (17,18,19,20,21,22);",
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
                    "DROP TABLE security_remediation_campaign_events;
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
                     DELETE FROM schema_migrations WHERE version IN (18,19,20,21,22);",
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
                    "DROP TABLE security_remediation_campaign_events;
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
                     DELETE FROM schema_migrations WHERE version IN (19,20,21,22);",
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
                    "DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DROP TABLE security_fix_events;
                     DROP TABLE security_fix_validation_results;
                     DROP TABLE security_fix_attempts;
                     DELETE FROM schema_migrations WHERE version IN (20,21,22);",
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
                     DROP TABLE security_remediation_campaign_events;
                     DROP TABLE security_remediation_campaign_relationships;
                     DROP TABLE security_remediation_campaign_findings;
                     DROP TABLE security_remediation_campaigns;
                     DELETE FROM schema_migrations WHERE version=21;",
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
        assert!(attempt_sql.contains("'FIX_VERIFIED','STILL_VULNERABLE','UNABLE_TO_VERIFY','REGRESSION_DETECTED'"));
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
        assert!(session_sql.contains("'preparing','awaiting_approval','approved','running','completed','failed','cancelled'"));
        assert!(session_sql.contains("scan_id TEXT UNIQUE REFERENCES web_security_scans(id) ON DELETE SET NULL"));
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
            .execute("DELETE FROM guided_security_sessions WHERE id='session-fk'", [])
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
