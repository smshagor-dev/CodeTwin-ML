use std::fs;

use codetwin_core::{Database, ProjectIndexService, SecretScanningService};
use tempfile::tempdir;

// Tokens are built at runtime so this repository never contains a literal token.
fn github_token() -> String {
    let body: String = "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0"
        .chars()
        .cycle()
        .take(36)
        .collect();
    format!("ghp_{body}")
}

fn database_password() -> String {
    "Qx7vB2mK9pL4sR8tN3wZ".to_string()
}

/// Every text value stored anywhere in the database, for leak checks.
fn all_stored_text(database: &Database) -> String {
    let connection = database.connection();
    let mut tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .expect("tables");
    let names: Vec<String> = tables
        .query_map([], |row| row.get(0))
        .expect("names")
        .collect::<Result<_, _>>()
        .expect("collect");
    let mut output = String::new();
    for table in names {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .expect("select");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("rows");
        while let Some(row) = rows.next().expect("row") {
            for index in 0..columns {
                if let Ok(Some(value)) = row.get::<_, Option<String>>(index) {
                    output.push_str(&value);
                    output.push('\n');
                }
            }
        }
    }
    output
}

#[test]
fn secret_findings_are_persisted_redacted_and_follow_their_lifecycle() {
    let project = tempdir().expect("project");
    fs::create_dir_all(project.path().join("src")).expect("src");
    let token = github_token();
    let password = database_password();
    fs::write(
        project.path().join("src/client.ts"),
        format!("export const token = \"{token}\";\n"),
    )
    .expect("source");
    fs::write(
        project.path().join(".env"),
        format!("DATABASE_PASSWORD={password}\n"),
    )
    .expect("env");
    fs::write(
        project.path().join(".env.example"),
        format!("DATABASE_PASSWORD={password}\n"),
    )
    .expect("template");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index");
    let service = SecretScanningService::new(&database);

    let first = service.scan_project(&index.project_id).expect("scan");
    assert!(first.coverage_complete);
    assert_eq!(first.findings_opened, 2, "{first:?}");
    let findings = service
        .list_findings(&index.project_id, Some("open"), 50)
        .expect("findings");
    let github = findings
        .iter()
        .find(|finding| finding.rule_id == "secret.github_token")
        .expect("github finding");
    assert_eq!(github.relative_path, "src/client.ts");
    assert_eq!(github.line, Some(1));
    assert_eq!(github.severity, "critical");
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "secret.env_file_assignment"
            && finding.relative_path == ".env"));
    assert!(
        !findings
            .iter()
            .any(|finding| finding.relative_path == ".env.example"),
        "templates are not reported"
    );

    let stored = all_stored_text(&database);
    assert!(
        !stored.contains(&token),
        "raw token must never be persisted"
    );
    assert!(
        !stored.contains(&password),
        "raw password must never be persisted"
    );

    // Re-scanning unchanged content refreshes rather than duplicating.
    let second = service.scan_project(&index.project_id).expect("rescan");
    assert_eq!(second.findings_opened, 0);
    assert_eq!(second.findings_refreshed, 2);

    // Removing the token resolves exactly that finding.
    fs::write(
        project.path().join("src/client.ts"),
        "export const token = process.env.GITHUB_TOKEN;\n",
    )
    .expect("fix source");
    let third = service
        .scan_project(&index.project_id)
        .expect("post-fix scan");
    assert_eq!(third.findings_resolved, 1);
    let open = service
        .list_findings(&index.project_id, Some("open"), 50)
        .expect("open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].relative_path, ".env");
    let resolved = service
        .list_findings(&index.project_id, Some("resolved"), 50)
        .expect("resolved");
    assert_eq!(resolved[0].rule_id, "secret.github_token");
    assert!(resolved[0].resolved_at.is_some());

    let history = service.history(&index.project_id, 10).expect("history");
    assert_eq!(history.len(), 3);
    assert!(history.iter().all(|run| run.status == "completed"));
}

#[test]
fn suppression_marker_and_skipped_directories_are_respected() {
    let project = tempdir().expect("project");
    let token = github_token();
    fs::create_dir_all(project.path().join("node_modules/pkg")).expect("deps");
    fs::write(
        project.path().join("node_modules/pkg/index.js"),
        format!("module.exports = \"{token}\";\n"),
    )
    .expect("dependency file");
    fs::write(
        project.path().join("fixture.ts"),
        format!("const t = \"{token}\"; // codetwin:ignore-secret\n"),
    )
    .expect("suppressed");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index");
    let summary = SecretScanningService::new(&database)
        .scan_project(&index.project_id)
        .expect("scan");
    assert_eq!(summary.observations, 0, "{summary:?}");
}
