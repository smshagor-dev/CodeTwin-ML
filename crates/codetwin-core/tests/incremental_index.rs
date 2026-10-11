use codetwin_core::{Database, ProjectIndexService};
use std::{fs, sync::atomic::AtomicBool};

#[test]
fn same_size_edits_rename_and_delete_update_only_changed_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.ts"), "export const a = 1;").unwrap();
    fs::write(dir.path().join("b.ts"), "export const b = 1;").unwrap();
    let db = Database::open_in_memory().unwrap();
    let service = ProjectIndexService::new(&db);
    let first = service.index_project(dir.path()).unwrap();
    let unchanged = service.index_project(dir.path()).unwrap();
    assert_eq!(unchanged.delta.files_unchanged, 2);
    let file_runs: Vec<String> = db
        .connection()
        .prepare("SELECT last_index_run_id FROM files ORDER BY relative_path")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(file_runs, vec![first.run_id.clone(), first.run_id]);
    fs::write(dir.path().join("a.ts"), "export const a = 2;").unwrap();
    let edit = service.index_project(dir.path()).unwrap();
    assert_eq!(edit.delta.files_modified, 1);
    assert_eq!(edit.delta.files_unchanged, 1);
    fs::rename(dir.path().join("a.ts"), dir.path().join("renamed.ts")).unwrap();
    let rename = service.index_project(dir.path()).unwrap();
    assert_eq!(rename.delta.files_added, 1);
    assert_eq!(rename.delta.files_deleted, 1);
    assert_eq!(rename.delta.files_unchanged, 1);
    fs::remove_file(dir.path().join("b.ts")).unwrap();
    let deletion = service.index_project(dir.path()).unwrap();
    assert_eq!(deletion.delta.files_deleted, 1);
    assert_eq!(deletion.delta.files_unchanged, 1);
    let active: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM files WHERE is_active=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(active, 1);
}

#[test]
fn full_rebuild_reparses_unchanged_files_and_is_recorded_without_poisoning_cache() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.ts"), "export const a = 1;").unwrap();
    let db = Database::open_in_memory().unwrap();
    let service = ProjectIndexService::new(&db);
    service.index_project(dir.path()).unwrap();
    db.connection()
        .execute("UPDATE files SET ast_root_kind='damaged-cache'", [])
        .unwrap();
    let refresh = service.index_project(dir.path()).unwrap();
    let cached: String = db
        .connection()
        .query_row("SELECT ast_root_kind FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(cached, "damaged-cache");
    assert_eq!(refresh.delta.files_unchanged, 1);
    let rebuilt = service.rebuild_project(dir.path()).unwrap();
    let (root, run): (String, String) = db
        .connection()
        .query_row(
            "SELECT ast_root_kind,last_index_run_id FROM files",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_ne!(root, "damaged-cache");
    assert_eq!(run, rebuilt.run_id);
    assert_eq!(rebuilt.delta.files_unchanged, 1); // Content delta is distinct from reparse work.
    let config: String = db
        .connection()
        .query_row(
            "SELECT configuration_json FROM analysis_runs WHERE id=?1",
            [&run],
            |row| row.get(0),
        )
        .unwrap();
    assert!(config.contains("full_rebuild"));
    service.index_project(dir.path()).unwrap();
    let reused_run: String = db
        .connection()
        .query_row("SELECT last_index_run_id FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reused_run, run);
}

#[test]
fn changed_analysis_version_invalidates_cache_and_cancelled_rebuild_keeps_index() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.ts"), "export const a = 1;").unwrap();
    let db = Database::open_in_memory().unwrap();
    let service = ProjectIndexService::new(&db);
    service.index_project(dir.path()).unwrap();
    db.connection()
        .execute(
            "UPDATE files SET analysis_fingerprint='previous-version'",
            [],
        )
        .unwrap();
    let refreshed = service.index_project(dir.path()).unwrap();
    let run: String = db
        .connection()
        .query_row("SELECT last_index_run_id FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(run, refreshed.run_id);
    let cancelled = AtomicBool::new(true);
    assert!(service
        .rebuild_project_with_cancel(dir.path(), &cancelled)
        .is_err());
    let after: String = db
        .connection()
        .query_row("SELECT last_index_run_id FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, run);
}
