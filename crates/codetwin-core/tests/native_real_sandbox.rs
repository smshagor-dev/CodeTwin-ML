//! Run with CODETWIN_TEST_REAL_SANDBOX=1 and preloaded pinned offline scan image.
//! This is an actual Docker integration test, not a mocked process.
use codetwin_core::{
    native_agent_workers::{IsolatedScanReceipt, IsolatedWorker},
    native_agents::NativeAgents,
    native_worker_audit::WorkerAudit,
    Database, ProjectIndexService,
};

#[test]
fn real_docker_offline_scan_records_a_durable_receipt() {
    if std::env::var("CODETWIN_TEST_REAL_SANDBOX").ok().as_deref() != Some("1") {
        eprintln!("SKIPPED: set CODETWIN_TEST_REAL_SANDBOX=1 with a digest-pinned, preloaded offline scanner image");
        return;
    }
    let configured = IsolatedWorker::readiness();
    assert!(configured.configured, "{}", configured.detail);
    let db = Database::open_in_memory().unwrap();
    let source = tempfile::tempdir().unwrap();
    std::fs::write(
        source.path().join("package.json"),
        r#"{"name":"codetwin-sandbox-fixture","version":"1.0.0","dependencies":{}}"#,
    )
    .unwrap();
    let id = ProjectIndexService::new(&db)
        .index_project(source.path())
        .unwrap()
        .project_id;
    let run = NativeAgents::new(&db)
        .create_with_roles(
            &id,
            "Authorized offline sandbox smoke test",
            10,
            300,
            &["scout".into(), "source".into()],
        )
        .unwrap();
    NativeAgents::new(&db).approve(&run.id).unwrap();
    let audit = WorkerAudit::new(&db);
    let ticket = audit.begin(&run.id).unwrap();
    let result: Result<IsolatedScanReceipt, String> = IsolatedWorker::new(&db).scan(&run.id, true);
    audit.finish(ticket, &result).unwrap();
    let receipt =
        result.expect("A pinned offline Trivy image with a preloaded vulnerability DB is required");
    assert_eq!(receipt.run_id, run.id);
    assert_eq!(receipt.report_sha256.len(), 64);
    assert!(receipt.report_sha256.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        receipt.image_digest,
        std::env::var("CODETWIN_TRIVY_IMAGE").unwrap()
    );
    let saved = audit.latest(&run.id).unwrap().unwrap();
    assert_eq!(saved.status, "success");
    assert_eq!(
        saved.image_digest.as_deref(),
        Some(receipt.image_digest.as_str())
    );
    assert_eq!(
        saved.report_sha256.as_deref(),
        Some(receipt.report_sha256.as_str())
    );
    assert_eq!(saved.vulnerability_count, Some(receipt.vulnerability_count));
    assert_eq!(
        saved.misconfiguration_count,
        Some(receipt.misconfiguration_count)
    );
    assert_eq!(audit.recover_interrupted().unwrap(), 0);
}
