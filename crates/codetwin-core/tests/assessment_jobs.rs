use codetwin_core::{
    assessment_jobs::{AssessmentJobs, AssessmentPlanRequest},
    Database, ProjectIndexService,
};
use std::fs;
fn request(project: &str) -> AssessmentPlanRequest {
    AssessmentPlanRequest {
        project_id: project.into(),
        tools: vec!["code.sast".into(), "code.quality".into()],
        max_files: 100,
        budget_seconds: 60,
    }
}
fn fixture() -> (tempfile::TempDir, Database, String) {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("app.ts"),
        "export function run(source: string) { return eval(source); }",
    )
    .unwrap();
    let db = Database::open_in_memory().unwrap();
    let index = ProjectIndexService::new(&db)
        .index_project(root.path())
        .unwrap();
    (root, db, index.project_id)
}
#[test]
fn actual_passive_analyzers_preserve_evidence_and_complete_both_steps() {
    let (_root, db, project) = fixture();
    let jobs = AssessmentJobs::new(&db);
    let plan = jobs.create_plan(request(&project)).unwrap();
    assert_eq!(plan.status, "planned");
    assert_eq!(plan.file_count, 1);
    let job = jobs.execute(&plan.id).unwrap();
    assert_eq!(job.status, "completed");
    assert!(job
        .steps
        .iter()
        .all(|s| s.status == "completed" && s.run_id.is_some()));
    assert_eq!(job.steps[0].coverage_complete, Some(true));
    assert_eq!(job.steps[1].coverage_complete, None);
    let evidence: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM findings WHERE project_id=?1 AND category='security'",
            [&project],
            |r| r.get(0),
        )
        .unwrap();
    assert!(evidence > 0);
    assert!(jobs.execute(&plan.id).is_err());
    assert_eq!(jobs.list(&project).unwrap().len(), 1);
    assert!(jobs.list("other").unwrap().is_empty());
}
#[test]
fn edits_and_reindexing_invalidate_saved_plans_without_running_analyzers() {
    let (root, db, project) = fixture();
    let jobs = AssessmentJobs::new(&db);
    let plan = jobs.create_plan(request(&project)).unwrap();
    fs::write(root.path().join("app.ts"), "export const safe = true;").unwrap();
    let failed = jobs.execute(&plan.id).unwrap();
    assert_eq!(failed.status, "failed");
    assert!(failed.steps.iter().all(|s| s.run_id.is_none()));
    assert!(jobs.create_plan(request(&project)).is_err());
    ProjectIndexService::new(&db)
        .index_project(root.path())
        .unwrap();
    let plan = jobs.create_plan(request(&project)).unwrap();
    ProjectIndexService::new(&db)
        .rebuild_project(root.path())
        .unwrap();
    assert_eq!(jobs.execute(&plan.id).unwrap().status, "failed");
}
#[test]
fn revisions_and_immutable_binding_prevent_old_plan_execution() {
    let (_root, db, project) = fixture();
    let jobs = AssessmentJobs::new(&db);
    let old = jobs.create_plan(request(&project)).unwrap();
    let new = jobs.create_plan(request(&project)).unwrap();
    assert_eq!(new.scope_revision, old.scope_revision + 1);
    assert_eq!(jobs.execute(&old.id).unwrap().status, "failed");
    assert!(db
        .connection()
        .execute(
            "UPDATE assessment_jobs SET scope_revision=?2 WHERE id=?1",
            rusqlite::params![old.id, new.scope_revision]
        )
        .is_err());
    assert!(db
        .connection()
        .execute("UPDATE assessment_scopes SET budget_seconds=1", [])
        .is_err());
    assert_eq!(jobs.execute(&new.id).unwrap().status, "completed");
}
#[test]
fn rejects_unsupported_tools_duplicates_budget_overflow_and_scope_path_changes() {
    let (_root, db, project) = fixture();
    let jobs = AssessmentJobs::new(&db);
    for tools in [
        vec![],
        vec!["web.scoped-scan".into()],
        vec!["code.sast".into(), "code.sast".into()],
    ] {
        let mut req = request(&project);
        req.tools = tools;
        assert!(jobs.create_plan(req).is_err());
    }
    let mut req = request(&project);
    req.max_files = 2001;
    assert!(jobs.create_plan(req).is_err());
    let mut req = request(&project);
    req.budget_seconds = 0;
    assert!(jobs.create_plan(req).is_err());
    let plan = jobs.create_plan(request(&project)).unwrap();
    db.connection()
        .execute(
            "UPDATE projects SET root_path='/nonexistent-assessment-path' WHERE id=?1",
            [&project],
        )
        .unwrap();
    assert_eq!(jobs.execute(&plan.id).unwrap().status, "failed");
}
#[test]
fn disk_reopen_does_not_recover_workers_until_explicit_startup() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("workspace.db");
    fs::write(root.path().join("a.ts"), "export const a=1;").unwrap();
    let db = Database::open(&path).unwrap();
    let project = ProjectIndexService::new(&db)
        .index_project(root.path())
        .unwrap()
        .project_id;
    let plan = AssessmentJobs::new(&db)
        .create_plan(request(&project))
        .unwrap();
    db.connection()
        .execute(
            "UPDATE assessment_jobs SET status='running' WHERE id=?1",
            [&plan.id],
        )
        .unwrap();
    db.connection()
        .execute(
            "UPDATE assessment_steps SET status='running' WHERE job_id=?1 AND position=0",
            [&plan.id],
        )
        .unwrap();
    drop(db);
    let db = Database::open(&path).unwrap();
    let jobs = AssessmentJobs::new(&db);
    assert_eq!(jobs.get(&plan.id).unwrap().status, "running");
    assert!(jobs.create_plan(request(&project)).is_err());
    assert_eq!(jobs.recover_interrupted().unwrap(), 1);
    let recovered = jobs.get(&plan.id).unwrap();
    assert_eq!(recovered.status, "interrupted");
    assert!(recovered.steps.iter().all(|s| s.status == "interrupted"));
    assert!(jobs.execute(&plan.id).is_err());
    assert_eq!(jobs.recover_interrupted().unwrap(), 0);
    let next = jobs.create_plan(request(&project)).unwrap();
    jobs.cancel(&next.id).unwrap();
    assert_eq!(jobs.get(&next.id).unwrap().status, "cancelled");
    assert!(jobs.execute(&next.id).is_err());
}
#[cfg(unix)]
#[test]
fn symlink_inputs_and_unsafe_index_paths_are_rejected() {
    let (root, db, project) = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("app.ts"), "export const secret=1;").unwrap();
    fs::remove_file(root.path().join("app.ts")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("app.ts"), root.path().join("app.ts")).unwrap();
    assert!(AssessmentJobs::new(&db)
        .create_plan(request(&project))
        .is_err());
    db.connection()
        .execute(
            "UPDATE files SET relative_path='../app.ts' WHERE project_id=?1",
            [project.clone()],
        )
        .unwrap();
    assert!(AssessmentJobs::new(&db)
        .create_plan(request(&project))
        .is_err());
}

#[test]
fn changed_quality_graph_and_incomplete_index_invalidate_plans() {
    let (_root, db, project) = fixture();
    let jobs = AssessmentJobs::new(&db);
    let plan = jobs.create_plan(request(&project)).unwrap();
    db.connection()
        .execute(
            "UPDATE symbols SET end_line=end_line+1 WHERE project_id=?1",
            [&project],
        )
        .unwrap();
    assert_eq!(jobs.execute(&plan.id).unwrap().status, "failed");
    db.connection().execute("UPDATE analysis_runs SET status='interrupted' WHERE project_id=?1 AND run_kind='source_index'", [&project]).unwrap();
    assert!(jobs.create_plan(request(&project)).is_err());
}

#[test]
fn file_count_and_non_regular_inputs_are_bounded_before_execution() {
    let (root, db, project) = fixture();
    fs::write(root.path().join("b.ts"), "export const b=1;").unwrap();
    ProjectIndexService::new(&db)
        .index_project(root.path())
        .unwrap();
    let mut limited = request(&project);
    limited.max_files = 1;
    assert!(AssessmentJobs::new(&db).create_plan(limited).is_err());
    fs::remove_file(root.path().join("app.ts")).unwrap();
    fs::create_dir(root.path().join("app.ts")).unwrap();
    assert!(AssessmentJobs::new(&db)
        .create_plan(request(&project))
        .is_err());
}
