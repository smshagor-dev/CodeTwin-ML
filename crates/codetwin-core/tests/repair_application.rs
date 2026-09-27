use std::fs;

use codetwin_core::{deterministic_id, Database, RepairApplicationService, VerifiedRepairService};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct Fixture {
    db: Database,
    project_id: String,
    file_id: String,
    repair_id: String,
    repository: TempDir,
    backups: TempDir,
}

fn fixture() -> Fixture {
    let repository = TempDir::new().expect("repository");
    let backups = TempDir::new().expect("backups");
    let source_dir = repository.path().join("src");
    fs::create_dir_all(&source_dir).expect("source dir");
    fs::write(source_dir.join("main.rs"), b"old\n").expect("source");

    let db = Database::open_in_memory().expect("db");
    let project_id = "repair-application-project".to_owned();
    let file_id = deterministic_id("file", &[&project_id, "src/main.rs"]);
    let root = repository.path().to_string_lossy().to_string();
    db.connection()
        .execute(
            "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES (?1, ?2, 'repair', ?2)",
            rusqlite::params![&project_id, &root],
        )
        .expect("project");
    db.connection()
        .execute(
            "INSERT INTO files(id, project_id, relative_path, relative_path_identity, content_hash, byte_size, is_active) \
             VALUES (?1, ?2, 'src/main.rs', 'src/main.rs', ?3, 4, 1)",
            rusqlite::params![&file_id, &project_id, hash(b"old\n")],
        )
        .expect("file");

    let workflow = VerifiedRepairService::new(&db);
    let plan = workflow
        .create_plan(
            &project_id,
            None,
            "Replace source",
            "Apply only after exact base-hash approval.",
        )
        .expect("plan");
    workflow
        .add_file_replacement(&plan.id, &file_id, "new\n")
        .expect("change");
    workflow.approve_plan(&plan.id).expect("approve");

    Fixture {
        db,
        project_id,
        file_id,
        repair_id: plan.id,
        repository,
        backups,
    }
}

#[test]
fn approved_plan_applies_and_rolls_back_without_commands() {
    let fixture = fixture();
    let service = RepairApplicationService::new(&fixture.db);

    let applied = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("apply");
    assert_eq!(applied.status, "applied");
    assert_eq!(applied.changes_total, 1);
    assert_eq!(applied.changes_applied, 1);
    assert_eq!(
        fs::read(fixture.repository.path().join("src/main.rs")).expect("applied bytes"),
        b"new\n"
    );
    let plan = VerifiedRepairService::new(&fixture.db)
        .get_plan(&fixture.repair_id)
        .expect("plan query")
        .expect("plan");
    assert_eq!(plan.status, "applied");

    let items = service.application_items(&applied.id, 10).expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].state, "applied");
    assert_eq!(items[0].backup_content_hash, hash(b"old\n"));
    let backup = fixture
        .backups
        .path()
        .join(&applied.backup_dir_name)
        .join(&items[0].backup_file_name);
    assert_eq!(fs::read(backup).expect("backup bytes"), b"old\n");

    let rolled_back = service
        .rollback_application(&applied.id, fixture.backups.path())
        .expect("rollback");
    assert_eq!(rolled_back.status, "rolled_back");
    assert!(rolled_back.rollback_performed);
    assert_eq!(
        fs::read(fixture.repository.path().join("src/main.rs")).expect("restored bytes"),
        b"old\n"
    );
    let plan = VerifiedRepairService::new(&fixture.db)
        .get_plan(&fixture.repair_id)
        .expect("plan query")
        .expect("plan");
    assert_eq!(plan.status, "draft");
}

#[test]
fn live_base_drift_fails_before_any_repository_write() {
    let fixture = fixture();
    let target = fixture.repository.path().join("src/main.rs");
    fs::write(&target, b"manual\n").expect("manual drift");

    let service = RepairApplicationService::new(&fixture.db);
    let run = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("record failed application");
    assert_eq!(run.status, "failed");
    assert_eq!(run.changes_applied, 0);
    assert_eq!(fs::read(&target).expect("preserved bytes"), b"manual\n");
    let plan = VerifiedRepairService::new(&fixture.db)
        .get_plan(&fixture.repair_id)
        .expect("plan query")
        .expect("plan");
    assert_eq!(plan.status, "approved");
}

#[test]
fn rollback_refuses_to_overwrite_a_post_apply_manual_edit() {
    let fixture = fixture();
    let target = fixture.repository.path().join("src/main.rs");
    let service = RepairApplicationService::new(&fixture.db);
    let applied = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("apply");
    assert_eq!(applied.status, "applied");

    fs::write(&target, b"after-apply-user-edit\n").expect("manual edit");
    let error = service
        .rollback_application(&applied.id, fixture.backups.path())
        .expect_err("rollback conflict");
    assert!(error.to_string().contains("rollback refused"));
    assert_eq!(
        fs::read(&target).expect("preserved manual edit"),
        b"after-apply-user-edit\n"
    );
    assert_eq!(
        service
            .get_run(&applied.id)
            .expect("run")
            .expect("run")
            .status,
        "applied"
    );
}

#[test]
fn interrupted_application_recovers_exact_proposed_bytes_from_verified_backup() {
    let fixture = fixture();
    let target = fixture.repository.path().join("src/main.rs");
    let service = RepairApplicationService::new(&fixture.db);
    let applied = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("apply");
    assert_eq!(fs::read(&target).expect("applied bytes"), b"new\n");

    fixture
        .db
        .connection()
        .execute(
            "UPDATE repair_application_runs
             SET status='running', completed_at=NULL, error_message=NULL
             WHERE id=?1",
            [&applied.id],
        )
        .expect("simulate interrupted run");
    fixture
        .db
        .connection()
        .execute(
            "UPDATE repair_plans SET status='approved' WHERE id=?1",
            [&fixture.repair_id],
        )
        .expect("simulate pre-finalized plan");

    assert_eq!(
        service
            .recover_interrupted_applications(fixture.backups.path())
            .expect("recover"),
        1
    );
    assert_eq!(
        fs::read(&target).expect("restored bytes"),
        b"old\n",
        "verified backup must restore the approved base bytes"
    );

    let recovered = service
        .get_run(&applied.id)
        .expect("run lookup")
        .expect("run");
    assert_eq!(recovered.status, "failed");
    assert_eq!(recovered.changes_applied, 0);
    assert!(recovered.rollback_performed);
    assert!(recovered
        .error_message
        .as_deref()
        .is_some_and(|message| message.contains("restored every affected path")));

    let items = service.application_items(&applied.id, 10).expect("items");
    assert_eq!(items[0].state, "rolled_back");
    let plan = VerifiedRepairService::new(&fixture.db)
        .get_plan(&fixture.repair_id)
        .expect("plan query")
        .expect("plan");
    assert_eq!(plan.status, "draft");
}

#[test]
fn interrupted_application_never_overwrites_unknown_manual_edits() {
    let fixture = fixture();
    let target = fixture.repository.path().join("src/main.rs");
    let service = RepairApplicationService::new(&fixture.db);
    let applied = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("apply");

    fixture
        .db
        .connection()
        .execute(
            "UPDATE repair_application_runs
             SET status='running', completed_at=NULL, error_message=NULL
             WHERE id=?1",
            [&applied.id],
        )
        .expect("simulate interrupted run");
    fixture
        .db
        .connection()
        .execute(
            "UPDATE repair_plans SET status='approved' WHERE id=?1",
            [&fixture.repair_id],
        )
        .expect("simulate pre-finalized plan");
    fs::write(&target, b"manual-after-crash\n").expect("manual edit");

    assert_eq!(
        service
            .recover_interrupted_applications(fixture.backups.path())
            .expect("recover"),
        1
    );
    assert_eq!(
        fs::read(&target).expect("manual bytes preserved"),
        b"manual-after-crash\n"
    );

    let recovered = service
        .get_run(&applied.id)
        .expect("run lookup")
        .expect("run");
    assert_eq!(recovered.status, "rollback_failed");
    assert!(!recovered.rollback_performed);
    assert!(recovered
        .error_message
        .as_deref()
        .is_some_and(|message| message.contains("left it untouched")));
    let plan = VerifiedRepairService::new(&fixture.db)
        .get_plan(&fixture.repair_id)
        .expect("plan query")
        .expect("plan");
    assert_eq!(plan.status, "superseded");
}

#[test]
fn application_history_is_repair_scoped_and_bounded() {
    let fixture = fixture();
    let service = RepairApplicationService::new(&fixture.db);
    let applied = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("apply");
    let history = service.history(&fixture.repair_id, 10).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, applied.id);
    assert_eq!(history[0].project_id, fixture.project_id);
    assert!(!fixture.file_id.is_empty());
}

#[cfg(unix)]
#[test]
fn application_refuses_a_symlink_target() {
    use std::os::unix::fs::symlink;

    let fixture = fixture();
    let target = fixture.repository.path().join("src/main.rs");
    let elsewhere = fixture.repository.path().join("elsewhere.rs");
    fs::write(&elsewhere, b"old\n").expect("elsewhere");
    fs::remove_file(&target).expect("remove target");
    symlink(&elsewhere, &target).expect("symlink");

    let service = RepairApplicationService::new(&fixture.db);
    let run = service
        .apply_plan(&fixture.repair_id, fixture.backups.path())
        .expect("failed application record");
    assert_eq!(run.status, "failed");
    assert_eq!(fs::read(&elsewhere).expect("elsewhere bytes"), b"old\n");
}
