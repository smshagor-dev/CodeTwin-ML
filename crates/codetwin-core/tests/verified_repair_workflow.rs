use codetwin_core::{deterministic_id, Database, VerifiedRepairService};
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn seed_project(db: &Database) -> (String, String) {
    let project_id = "project-repair".to_owned();
    let file_id = deterministic_id("file", &[&project_id, "src/main.rs"]);
    db.connection()
        .execute(
            "INSERT INTO projects(id, root_path, display_name, path_identity) \
             VALUES (?1, '/tmp/codetwin-repair', 'repair', '/tmp/codetwin-repair')",
            [&project_id],
        )
        .expect("project");
    db.connection()
        .execute(
            "INSERT INTO files( \
               id, project_id, relative_path, relative_path_identity, content_hash, byte_size, is_active \
             ) VALUES (?1, ?2, 'src/main.rs', 'src/main.rs', ?3, 3, 1)",
            rusqlite::params![file_id, project_id, hash(b"old")],
        )
        .expect("file");
    (project_id, file_id)
}

fn seed_open_finding(db: &Database, project_id: &str, file_id: &str) -> String {
    let run_id = "repair-finding-run";
    let finding_id = "repair-finding";
    db.connection()
        .execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, run_kind) \
             VALUES (?1, ?2, 'completed', 'repair-test', 'code_quality')",
            rusqlite::params![run_id, project_id],
        )
        .expect("run");
    db.connection()
        .execute(
            "INSERT INTO findings( \
               id, project_id, run_id, category, severity, title, description, file_id, status, fingerprint, analyzer_key \
             ) VALUES (?1, ?2, ?3, 'quality', 'medium', 'Finding', 'Finding under repair', ?4, 'open', 'repair-test-fingerprint', 'code_quality')",
            rusqlite::params![finding_id, project_id, run_id, file_id],
        )
        .expect("finding");
    finding_id.to_owned()
}

#[test]
fn approval_rejects_a_stale_indexed_base() {
    let db = Database::open_in_memory().expect("db");
    let (project_id, file_id) = seed_project(&db);
    let service = VerifiedRepairService::new(&db);
    let plan = service
        .create_plan(
            &project_id,
            None,
            "Replace file",
            "Repair proposal uses the current indexed file as its precondition.",
        )
        .expect("plan");
    service
        .add_file_replacement(&plan.id, &file_id, "new")
        .expect("change");

    db.connection()
        .execute(
            "UPDATE files SET content_hash=?2 WHERE id=?1",
            rusqlite::params![file_id, hash(b"drift")],
        )
        .expect("drift");

    let error = service.approve_plan(&plan.id).expect_err("stale base");
    assert!(error.to_string().contains("stale"));
    assert_eq!(
        service
            .get_plan(&plan.id)
            .expect("query")
            .expect("plan")
            .status,
        "draft"
    );
}

#[test]
fn verification_observes_reindexed_hashes_without_applying_files() {
    let db = Database::open_in_memory().expect("db");
    let (project_id, file_id) = seed_project(&db);
    let service = VerifiedRepairService::new(&db);
    let plan = service
        .create_plan(
            &project_id,
            None,
            "Replace file",
            "Application is external; CodeTwin only verifies indexed post-state.",
        )
        .expect("plan");
    let change = service
        .add_file_replacement(&plan.id, &file_id, "new")
        .expect("change");
    service.approve_plan(&plan.id).expect("approve");

    let first = service.verify_plan(&plan.id).expect("mismatch run");
    assert_eq!(first.status, "mismatch");
    assert_eq!(first.mismatched_changes, 1);

    db.connection()
        .execute(
            "UPDATE files SET content_hash=?2, byte_size=3 WHERE id=?1",
            rusqlite::params![file_id, change.proposed_content_hash],
        )
        .expect("simulate external application followed by reindex");

    let second = service.verify_plan(&plan.id).expect("verified run");
    assert_eq!(second.status, "verified");
    assert_eq!(second.matched_changes, 1);
    assert_eq!(
        service
            .get_plan(&plan.id)
            .expect("query")
            .expect("plan")
            .status,
        "verified"
    );
}

#[test]
fn linked_finding_must_be_resolved_before_plan_is_verified() {
    let db = Database::open_in_memory().expect("db");
    let (project_id, file_id) = seed_project(&db);
    let finding_id = seed_open_finding(&db, &project_id, &file_id);
    let service = VerifiedRepairService::new(&db);
    let plan = service
        .create_plan(
            &project_id,
            Some(&finding_id),
            "Repair finding",
            "The target finding must be resolved by a later analyzer refresh.",
        )
        .expect("plan");
    let change = service
        .add_file_replacement(&plan.id, &file_id, "new")
        .expect("change");
    service.approve_plan(&plan.id).expect("approve");
    db.connection()
        .execute(
            "UPDATE files SET content_hash=?2 WHERE id=?1",
            rusqlite::params![file_id, change.proposed_content_hash],
        )
        .expect("simulate reindex");

    let first = service.verify_plan(&plan.id).expect("applied run");
    assert_eq!(first.status, "applied_finding_open");
    assert_eq!(
        service
            .get_plan(&plan.id)
            .expect("query")
            .expect("plan")
            .status,
        "applied"
    );

    db.connection()
        .execute(
            "UPDATE findings SET status='resolved', resolved_at=CURRENT_TIMESTAMP WHERE id=?1",
            [&finding_id],
        )
        .expect("resolve finding");
    let second = service.verify_plan(&plan.id).expect("verified run");
    assert_eq!(second.status, "verified");
}
