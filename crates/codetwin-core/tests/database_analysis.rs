use std::fs;

use codetwin_core::{Database, DatabaseAnalysisService, ProjectIndexService};
use tempfile::tempdir;

#[test]
fn database_artifacts_and_review_findings_are_persisted_with_redaction() {
    let root = tempdir().expect("project");
    fs::create_dir_all(root.path().join("migrations")).expect("migrations");
    fs::create_dir_all(root.path().join("prisma")).expect("prisma");
    fs::write(
        root.path().join("migrations/001_release.sql"),
        "PRAGMA foreign_keys = OFF;\nDELETE FROM audit_log;\nDROP TABLE legacy_sessions;\n",
    )
    .expect("sql");
    fs::write(
        root.path().join("prisma/schema.prisma"),
        "datasource db {\n  provider = \"postgresql\"\n  url = \"postgresql://app:super_secret@db.internal/app\"\n}\n",
    )
    .expect("prisma");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = DatabaseAnalysisService::new(&database);
    let run = service.analyze_project(&project.id).expect("database analysis");

    assert!(run.coverage_complete);
    assert_eq!(run.artifacts_analyzed, 2);
    assert_eq!(run.sql_files, 1);
    assert_eq!(run.prisma_schemas, 1);
    assert_eq!(run.destructive_statements, 1);
    assert_eq!(run.unscoped_writes, 1);
    assert_eq!(run.foreign_keys_disabled, 1);
    assert_eq!(run.literal_datasource_urls, 1);

    let artifacts = service.list_artifacts(&project.id, true, 20).expect("artifacts");
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().any(|item| item.artifact_kind == "sql_migration"));
    assert!(artifacts.iter().any(|item| item.artifact_kind == "prisma_schema"));

    let findings = service
        .list_findings(&project.id, Some("open"), 100)
        .expect("findings");
    let datasource = findings
        .iter()
        .find(|item| item.rule_id == "database.literal_datasource_url")
        .expect("datasource finding");
    let evidence = service
        .finding_evidence(&datasource.id, 20)
        .expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert!(!evidence[0].summary.contains("super_secret"));
    assert!(!evidence[0].metadata_json.contains("super_secret"));
    assert!(evidence[0].metadata_json.contains("\"literal_redacted\":true"));
}

#[test]
fn complete_rescan_resolves_disappeared_database_finding() {
    let root = tempdir().expect("project");
    fs::create_dir_all(root.path().join("migrations")).expect("migrations");
    let migration = root.path().join("migrations/002_cleanup.sql");
    fs::write(&migration, "DELETE FROM sessions;\n").expect("risky migration");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = DatabaseAnalysisService::new(&database);
    service.analyze_project(&project.id).expect("first run");
    let original = service
        .list_findings(&project.id, Some("open"), 20)
        .expect("open findings")
        .into_iter()
        .find(|item| item.rule_id == "database.unscoped_data_write")
        .expect("unscoped finding");

    fs::write(&migration, "DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP;\n")
        .expect("safe migration");
    let second = service.analyze_project(&project.id).expect("second run");
    assert!(second.coverage_complete);
    assert_eq!(second.unscoped_writes, 0);
    assert!(second.findings_resolved >= 1);

    let resolved = service
        .list_findings(&project.id, Some("resolved"), 20)
        .expect("resolved findings");
    assert!(resolved
        .iter()
        .any(|item| item.id == original.id && item.resolved_at.is_some()));
}

#[test]
fn incomplete_coverage_does_not_resolve_previous_finding() {
    let root = tempdir().expect("project");
    fs::create_dir_all(root.path().join("migrations")).expect("migrations");
    let migration = root.path().join("migrations/003_large.sql");
    fs::write(&migration, "UPDATE accounts SET enabled = 0;\n").expect("risky migration");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = DatabaseAnalysisService::new(&database);
    service.analyze_project(&project.id).expect("first run");

    fs::write(&migration, vec![b'x'; 2 * 1024 * 1024 + 1]).expect("oversized artifact");
    let second = service.analyze_project(&project.id).expect("second run");
    assert!(!second.coverage_complete);
    assert_eq!(second.artifacts_skipped, 1);
    assert_eq!(second.findings_resolved, 0);

    let open = service
        .list_findings(&project.id, Some("open"), 20)
        .expect("open findings");
    assert!(open
        .iter()
        .any(|item| item.rule_id == "database.unscoped_data_write"));
}

#[test]
fn deleted_artifact_becomes_inactive_after_complete_scan() {
    let root = tempdir().expect("project");
    let schema = root.path().join("schema.sql");
    fs::write(&schema, "CREATE TABLE users(id INTEGER PRIMARY KEY);\n").expect("schema");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = DatabaseAnalysisService::new(&database);
    service.analyze_project(&project.id).expect("first run");
    assert_eq!(service.list_artifacts(&project.id, true, 20).expect("active").len(), 1);

    fs::remove_file(schema).expect("remove schema");
    let second = service.analyze_project(&project.id).expect("second run");
    assert!(second.coverage_complete);
    assert!(service.list_artifacts(&project.id, true, 20).expect("active").is_empty());
    let all = service.list_artifacts(&project.id, false, 20).expect("all artifacts");
    assert_eq!(all.len(), 1);
    assert!(!all[0].is_active);
}
