use codetwin_core::{Database, SecurityReviewError, SecurityReviewService};

fn seed(db: &Database) {
    db.connection().execute_batch(
        "INSERT INTO projects(id,root_path,display_name,path_identity) VALUES ('p','/review','review','/review');
         INSERT INTO projects(id,root_path,display_name,path_identity) VALUES ('other','/other','other','/other');
         INSERT INTO files(id,project_id,relative_path,relative_path_identity,content_hash,byte_size) VALUES ('file','p','a.ts','a.ts','hash-one',1);
         INSERT INTO analysis_runs(id,project_id,status,analyzer_version) VALUES ('scan','p','completed','v1');
         INSERT INTO analysis_runs(id,project_id,status,analyzer_version) VALUES ('scan-two','p','completed','v1');
         INSERT INTO findings(id,project_id,run_id,category,severity,title,description,file_id,status,fingerprint,analyzer_key)
         VALUES ('finding','p','scan','security','medium','eval','review input','file','open','fingerprint','appsec');"
    ).unwrap();
}

#[test]
fn review_persists_without_resolving_and_retains_append_only_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("review.sqlite3");
    {
        let db = Database::open(&path).unwrap();
        seed(&db);
        let service = SecurityReviewService::new(&db);
        let review = service
            .review(
                "p",
                "finding",
                "scan",
                Some("hash-one"),
                "false_positive",
                "  input is a trusted literal  ",
            )
            .unwrap();
        assert!(review.is_current);
        assert_eq!(review.note, "input is a trusted literal");
        assert_eq!(review.indexed_content_hash.as_deref(), Some("hash-one"));
        service
            .review(
                "p",
                "finding",
                "scan",
                Some("hash-one"),
                "needs_review",
                "Need another review",
            )
            .unwrap();
        let status: String = db
            .connection()
            .query_row(
                "SELECT status FROM findings WHERE id='finding'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "open");
    }
    let reopened = Database::open(&path).unwrap();
    let records = SecurityReviewService::new(&reopened)
        .list("p", Some("finding"), 50)
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].verdict, "needs_review");
    assert_eq!(records[1].verdict, "false_positive");
}

#[test]
fn rejects_other_project_stale_scan_invalid_verdict_and_invalid_note() {
    let db = Database::open_in_memory().unwrap();
    seed(&db);
    let service = SecurityReviewService::new(&db);
    for (project, finding, run) in [
        ("other", "finding", "scan"),
        ("p", "missing", "scan"),
        ("p", "finding", "scan-two"),
    ] {
        assert!(matches!(
            service.review(
                project,
                finding,
                run,
                Some("hash-one"),
                "confirmed",
                "reason"
            ),
            Err(SecurityReviewError::StaleFinding)
        ));
    }
    for (verdict, note) in [("resolved", "reason"), ("confirmed", " \n ")] {
        assert!(matches!(
            service.review("p", "finding", "scan", Some("hash-one"), verdict, note),
            Err(SecurityReviewError::InvalidReview)
        ));
    }
    assert!(matches!(
        service.review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            &"a".repeat(2001)
        ),
        Err(SecurityReviewError::InvalidReview)
    ));
    assert!(service.list("p", None, 50).unwrap().is_empty());
    db.connection()
        .execute("UPDATE findings SET analyzer_key='code_quality'", [])
        .unwrap();
    assert!(matches!(
        service.review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            "reason"
        ),
        Err(SecurityReviewError::StaleFinding)
    ));
}

#[test]
fn source_or_scan_change_makes_previous_feedback_stale_and_reset_is_an_event() {
    let db = Database::open_in_memory().unwrap();
    seed(&db);
    let service = SecurityReviewService::new(&db);
    service
        .review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            "Input may reach eval",
        )
        .unwrap();
    db.connection()
        .execute(
            "UPDATE files SET content_hash='hash-two' WHERE id='file'",
            [],
        )
        .unwrap();
    assert!(!service.list("p", None, 50).unwrap()[0].is_current);
    assert!(matches!(
        service.review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            "old source"
        ),
        Err(SecurityReviewError::StaleFinding)
    ));
    db.connection()
        .execute(
            "UPDATE findings SET run_id='scan-two' WHERE id='finding'",
            [],
        )
        .unwrap();
    assert!(!service.list("p", None, 50).unwrap()[0].is_current);
    service
        .review(
            "p",
            "finding",
            "scan-two",
            Some("hash-two"),
            "needs_review",
            "Changed source needs fresh evidence",
        )
        .unwrap();
    let reviews = service.list("p", Some("finding"), 50).unwrap();
    assert!(reviews[0].is_current);
    assert!(!reviews[1].is_current);
    assert!(service
        .list("other", Some("finding"), 50)
        .unwrap()
        .is_empty());
}

#[test]
fn version_26_database_upgrades_without_changing_existing_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("upgrade.sqlite3");
    {
        let db = Database::open(&path).unwrap();
        seed(&db);
        db.connection().execute_batch("DROP TABLE security_finding_reviews; DELETE FROM schema_migrations WHERE version=27;").unwrap();
    }
    let upgraded = Database::open(&path).unwrap();
    let review = SecurityReviewService::new(&upgraded)
        .review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            "Reviewed after upgrade",
        )
        .unwrap();
    assert!(review.is_current);
    let status: String = upgraded
        .connection()
        .query_row(
            "SELECT status FROM findings WHERE id='finding'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "open");
}

#[test]
fn resolved_finding_invalidates_review_even_if_detection_run_is_unchanged() {
    let db = Database::open_in_memory().unwrap();
    seed(&db);
    let service = SecurityReviewService::new(&db);
    service
        .review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            "Reviewed open finding",
        )
        .unwrap();
    db.connection()
        .execute(
            "UPDATE findings SET status='resolved', last_run_id='scan-two' WHERE id='finding'",
            [],
        )
        .unwrap();
    assert!(!service.list("p", None, 50).unwrap()[0].is_current);
    assert!(matches!(
        service.review(
            "p",
            "finding",
            "scan",
            Some("hash-one"),
            "confirmed",
            "outdated detection"
        ),
        Err(SecurityReviewError::StaleFinding)
    ));
}
