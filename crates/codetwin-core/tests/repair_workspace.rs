use std::fs;

use codetwin_core::{deterministic_id, Database, RepairWorkspaceQueryService};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn seed_disk_project() -> (TempDir, Database, String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(temp.path().join("src")).expect("src");
    let bytes = b"fn main() { println!(\"hello\"); }\n";
    fs::write(temp.path().join("src/main.rs"), bytes).expect("source");

    let db = Database::open_in_memory().expect("db");
    let project_id = "repair-workspace-project".to_owned();
    let file_id = deterministic_id("file", &[&project_id, "src/main.rs"]);
    let root = temp.path().to_string_lossy().into_owned();
    db.connection()
        .execute(
            "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES (?1, ?2, 'repair workspace', ?2)",
            rusqlite::params![project_id, root],
        )
        .expect("project");
    db.connection()
        .execute(
            "INSERT INTO files( \
               id, project_id, relative_path, relative_path_identity, language, content_hash, byte_size, is_active \
             ) VALUES (?1, ?2, 'src/main.rs', 'src/main.rs', 'rust', ?3, ?4, 1)",
            rusqlite::params![file_id, project_id, hash(bytes), bytes.len() as i64],
        )
        .expect("file");
    (temp, db, project_id, file_id)
}

#[test]
fn reads_only_hash_matching_indexed_utf8_source() {
    let (_temp, db, project_id, file_id) = seed_disk_project();
    let snapshot = RepairWorkspaceQueryService::new(&db)
        .read_source_snapshot(&file_id)
        .expect("snapshot");
    assert_eq!(snapshot.project_id, project_id);
    assert_eq!(snapshot.relative_path, "src/main.rs");
    assert_eq!(snapshot.language.as_deref(), Some("rust"));
    assert!(snapshot.content.contains("println"));
    assert_eq!(snapshot.content_hash, hash(snapshot.content.as_bytes()));
}

#[test]
fn rejects_source_that_drifted_after_indexing() {
    let (temp, db, _project_id, file_id) = seed_disk_project();
    fs::write(temp.path().join("src/main.rs"), "fn main() {}\n").expect("drift");
    let error = RepairWorkspaceQueryService::new(&db)
        .read_source_snapshot(&file_id)
        .expect_err("stale source");
    assert!(error.to_string().contains("changed since the last index"));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_source_even_if_target_bytes_match() {
    use std::os::unix::fs::symlink;

    let (temp, db, _project_id, file_id) = seed_disk_project();
    let source = temp.path().join("src/main.rs");
    let target = temp.path().join("real.rs");
    fs::rename(&source, &target).expect("move source");
    symlink(&target, &source).expect("symlink");

    let error = RepairWorkspaceQueryService::new(&db)
        .read_source_snapshot(&file_id)
        .expect_err("symlink rejected");
    assert!(error.to_string().contains("symlink"));
}

#[test]
fn lists_project_findings_with_status_filter() {
    let (_temp, db, project_id, file_id) = seed_disk_project();
    db.connection()
        .execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, run_kind) \
             VALUES ('repair-workspace-run', ?1, 'completed', 'repair-workspace-test', 'code_quality')",
            [&project_id],
        )
        .expect("run");
    db.connection()
        .execute(
            "INSERT INTO findings( \
               id, project_id, run_id, category, severity, title, description, file_id, source_start_line, source_end_line, status, fingerprint, analyzer_key \
             ) VALUES ('repair-workspace-finding', ?1, 'repair-workspace-run', 'quality', 'high', 'Repair me', 'Evidence-backed finding', ?2, 1, 1, 'open', 'repair-workspace-fingerprint', 'code_quality')",
            rusqlite::params![project_id, file_id],
        )
        .expect("finding");

    let service = RepairWorkspaceQueryService::new(&db);
    let open = service
        .list_findings(&project_id, Some("open"), 20)
        .expect("open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].title, "Repair me");
    assert_eq!(open[0].analyzer_key.as_deref(), Some("code_quality"));

    let resolved = service
        .list_findings(&project_id, Some("resolved"), 20)
        .expect("resolved");
    assert!(resolved.is_empty());
}
