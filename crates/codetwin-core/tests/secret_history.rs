use std::{fs, path::Path, process::Command};

use codetwin_core::{
    Database, ProjectIndexService, SecretHistoryError, SecretHistoryService, DEFAULT_MAX_COMMITS,
};
use tempfile::tempdir;

// Values are built at runtime so this repository never contains a literal credential.
fn github_token() -> String {
    let body: String = "Zq8Xw2Ve5Rt7Yu1Io4Pa9Sd3Fg6Hj0"
        .chars()
        .cycle()
        .take(36)
        .collect();
    format!("ghp_{body}")
}

fn database_url() -> (String, String) {
    let password = ["Nv4Kp8Wq", "2Lx7Rz5T"].concat();
    (
        format!("postgres://app:{password}@db.internal:5432/app"),
        password,
    )
}

fn git(root: &Path, args: &[&str], date: &str) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .env("GIT_AUTHOR_DATE", date)
        .env("GIT_COMMITTER_DATE", date)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn commit_all(root: &Path, message: &str, date: &str) -> String {
    git(root, &["add", "-A"], date);
    git(root, &["commit", "-q", "-m", message], date);
    git(root, &["rev-parse", "HEAD"], date)
}

fn all_stored_text(database: &Database) -> String {
    let connection = database.connection();
    let names: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .expect("tables")
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
fn history_scan_finds_deleted_and_current_secrets_without_storing_them() {
    let project = tempdir().expect("project");
    let root = project.path();
    git(root, &["init", "-q"], "2020-01-01T00:00:00Z");

    let token = github_token();
    fs::write(root.join("config.py"), format!("TOKEN = \"{token}\"\n")).expect("config");
    fs::write(root.join("README.md"), "demo\n").expect("readme");
    let introduced = commit_all(root, "add config", "2020-01-02T00:00:00Z");

    fs::remove_file(root.join("config.py")).expect("remove");
    fs::create_dir_all(root.join("src")).expect("src");
    let (url, password) = database_url();
    fs::write(
        root.join("src/db.ts"),
        format!("// db\nexport const url = \"{url}\";\n"),
    )
    .expect("db");
    let db_commit = commit_all(root, "remove token, add db", "2021-01-02T00:00:00Z");

    // Same token again later under another path: still one finding, introduced in 2020.
    fs::write(root.join("notes.txt"), format!("old token was {token}\n")).expect("notes");
    commit_all(root, "notes", "2022-01-02T00:00:00Z");
    fs::remove_file(root.join("notes.txt")).expect("remove notes");
    commit_all(root, "drop notes", "2022-02-02T00:00:00Z");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root)
        .expect("index");
    let service = SecretHistoryService::new(&database);

    let summary = service
        .scan_project(&index.project_id, DEFAULT_MAX_COMMITS)
        .expect("scan");
    assert!(summary.coverage_complete, "{summary:?}");
    assert_eq!(summary.commits_scanned, 4);
    assert!(!summary.commit_limit_reached);
    assert!(!summary.shallow_clone);
    assert_eq!(summary.findings_opened, 2, "{summary:?}");
    assert_eq!(summary.still_in_working_tree, 1);

    let findings = service
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("findings");
    let github = findings
        .iter()
        .find(|finding| finding.rule_id == "secret.github_token")
        .expect("github token finding");
    assert_eq!(github.introduced_commit, introduced);
    assert_eq!(github.relative_path, "config.py");
    assert_eq!(github.line, Some(1));
    assert_eq!(github.commit_count, 2);
    assert_eq!(github.paths, vec!["config.py", "notes.txt"]);
    assert!(!github.still_in_working_tree);
    assert!(github
        .description
        .contains("no longer in the current files"));
    assert!(github.remediation.contains("rotate"));

    let db = findings
        .iter()
        .find(|finding| finding.relative_path == "src/db.ts")
        .expect("db finding");
    assert_eq!(db.introduced_commit, db_commit);
    assert_eq!(db.line, Some(2));
    assert!(db.still_in_working_tree);

    let stored = all_stored_text(&database);
    assert!(!stored.contains(&token), "raw token persisted");
    assert!(!stored.contains(&password), "raw password persisted");

    let again = service
        .scan_project(&index.project_id, DEFAULT_MAX_COMMITS)
        .expect("rescan");
    assert_eq!((again.findings_opened, again.findings_refreshed), (0, 2));

    // Only the newest commit: nothing found, and nothing may be resolved from partial coverage.
    let partial = service.scan_project(&index.project_id, 1).expect("partial");
    assert!(partial.commit_limit_reached);
    assert!(!partial.coverage_complete);
    assert_eq!(partial.findings_resolved, 0);
    assert_eq!(
        service
            .list_findings(&index.project_id, Some("open"), 100)
            .expect("open")
            .len(),
        2
    );
    let runs = service.history(&index.project_id, 10).expect("history");
    assert_eq!(runs.len(), 3);
    assert!(runs[0].commit_limit_reached);
}

#[test]
fn shallow_clones_are_flagged() {
    let origin = tempdir().expect("origin");
    git(origin.path(), &["init", "-q"], "2020-01-01T00:00:00Z");
    for (index, date) in ["2020-01-02T00:00:00Z", "2020-01-03T00:00:00Z"]
        .iter()
        .enumerate()
    {
        fs::write(origin.path().join("a.txt"), format!("{index}\n")).expect("file");
        commit_all(origin.path(), "c", date);
    }
    let clone = tempdir().expect("clone");
    let target = clone.path().join("shallow");
    let url = format!("file://{}", origin.path().display());
    git(
        clone.path(),
        &["clone", "-q", "--depth", "1", &url, "shallow"],
        "2020-01-04T00:00:00Z",
    );
    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(&target)
        .expect("index");
    let summary = SecretHistoryService::new(&database)
        .scan_project(&index.project_id, 100)
        .expect("scan");
    assert!(summary.shallow_clone);
    assert_eq!(summary.commits_scanned, 1);
}

#[test]
fn non_repository_is_rejected() {
    let project = tempdir().expect("project");
    fs::write(project.path().join("a.txt"), "x\n").expect("file");
    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index");
    let error = SecretHistoryService::new(&database)
        .scan_project(&index.project_id, 10)
        .expect_err("not a repo");
    assert!(matches!(error, SecretHistoryError::NotARepository));
}

/// A cloned repository controls its own `.git/config` and `.gitattributes`. None of the
/// programs they can name may run during a history scan.
#[cfg(unix)]
#[test]
fn repository_configured_programs_never_run() {
    use std::os::unix::fs::PermissionsExt;

    let project = tempdir().expect("project");
    let root = project.path();
    git(root, &["init", "-q"], "2020-01-01T00:00:00Z");
    let marker = root.join("PWNED");
    let script = root.join(".git/evil.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display()),
    )
    .expect("script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
    let script = script.display().to_string();
    for (key, value) in [
        ("diff.external", script.as_str()),
        ("diff.evil.textconv", script.as_str()),
        ("diff.evil.command", script.as_str()),
        ("core.pager", script.as_str()),
        ("pager.log", script.as_str()),
        ("log.showSignature", "true"),
        ("gpg.program", script.as_str()),
        ("core.fsmonitor", script.as_str()),
    ] {
        git(root, &["config", key, value], "2020-01-01T00:00:00Z");
    }
    fs::write(root.join(".gitattributes"), "* diff=evil\n").expect("attributes");
    fs::write(
        root.join("app.py"),
        format!("TOKEN = \"{}\"\n", github_token()),
    )
    .expect("app");
    // The fixture commit itself must not trigger the hook either; commit with it disabled.
    git(
        root,
        &["-c", "core.fsmonitor=false", "add", "-A"],
        "2020-01-02T00:00:00Z",
    );
    git(
        root,
        &["-c", "core.fsmonitor=false", "commit", "-q", "-m", "x"],
        "2020-01-02T00:00:00Z",
    );
    assert!(!marker.exists(), "fixture setup ran the script");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root)
        .expect("index");
    let summary = SecretHistoryService::new(&database)
        .scan_project(&index.project_id, 100)
        .expect("scan");
    assert!(!marker.exists(), "a repository-configured program ran");
    // Content still came through the plain diff, not a textconv filter.
    assert_eq!(summary.findings_opened, 1, "{summary:?}");
}
