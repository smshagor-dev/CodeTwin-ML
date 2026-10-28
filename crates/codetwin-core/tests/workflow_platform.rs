//! End-to-end: a real indexed fixture project goes through the read-only
//! investigation workflow (plan → approval → concurrent specialists →
//! deterministic evidence verification → report → memory/graph indexing).
use std::fs;
use std::sync::Arc;

use codetwin_core::agent_tools::CoreToolRuntime;
use codetwin_core::knowledge_memory::{KnowledgeMemory, MemoryLayer, RetrievalBudget};
use codetwin_core::specialist_workers::InvestigationOptions;
use codetwin_core::workflow_platform::WorkflowPlatform;
use codetwin_core::{
    CodeSecurityService, Database, ProjectIndexService, QaDiscoveryService, SecretScanningService,
};
use serde_json::json;
use task_orchestrator::{CancelToken, GlobalLimits, Outcome, RunState, ToolRuntime};

struct Fixture {
    _root: tempfile::TempDir,
    _data: tempfile::TempDir,
    db_path: std::path::PathBuf,
    project_id: String,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("app.ts"),
        "const apiKey = \"sk_live_super_secret_value\";\nexport function runUserCode(source: string) { return eval(source); }\n",
    )
    .unwrap();
    fs::write(root.path().join("app.test.ts"), "import { runUserCode } from './app';\ntest('runs', () => { expect(runUserCode('1')).toBe(1); });\n").unwrap();
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"fixture","devDependencies":{"jest":"29.0.0"},"scripts":{"test":"jest"}}"#,
    )
    .unwrap();
    let data = tempfile::tempdir().unwrap();
    let db_path = data.path().join("codetwin.sqlite3");
    let db = Database::open(&db_path).unwrap();
    let index = ProjectIndexService::new(&db)
        .index_project(root.path())
        .unwrap();
    CodeSecurityService::new(&db)
        .analyze_project(&index.project_id)
        .unwrap();
    SecretScanningService::new(&db)
        .scan_project(&index.project_id)
        .unwrap();
    QaDiscoveryService::new(&db)
        .discover_project(&index.project_id)
        .unwrap();
    Fixture {
        project_id: index.project_id,
        _root: root,
        _data: data,
        db_path,
    }
}

fn platform(f: &Fixture) -> WorkflowPlatform {
    WorkflowPlatform::new(
        f.db_path.clone(),
        "test-instance".into(),
        Arc::new(GlobalLimits::new(4)),
        None,
    )
}

#[test]
fn read_only_investigation_runs_end_to_end_and_is_verified() {
    let f = fixture();
    let p = platform(&f);
    let (run, approvals) = p
        .create_investigation(
            &f.project_id,
            "Review eval usage in runUserCode and apiKey handling",
            "operator",
            &InvestigationOptions::default(),
            None,
        )
        .unwrap();
    assert_eq!(run.state, RunState::AwaitingApproval);
    assert_eq!(approvals.len(), 1, "read-only plan needs one plan approval");
    assert!(
        p.execute(&run.id, None).is_err(),
        "planning is not execution"
    );
    p.decide(
        &approvals[0].id,
        true,
        "operator",
        &approvals[0].scope_digest,
        None,
    )
    .unwrap();

    let run = p.execute(&run.id, Some(&CancelToken::new())).unwrap();
    let detail = p.detail(&run.id).unwrap();
    for t in &detail.tasks {
        eprintln!("{} {} {:?} {:?}", t.key, t.state, t.reason_code, t.summary);
    }
    assert_eq!(run.state, RunState::Completed);
    assert_eq!(run.outcome, Some(Outcome::Verified));

    let security = detail.tasks.iter().find(|t| t.key == "security").unwrap();
    assert!(security
        .summary
        .as_deref()
        .unwrap()
        .contains("open AppSec finding"));
    let output = serde_json::to_string(&security.output).unwrap();
    assert!(
        !output.contains("sk_live_super_secret_value"),
        "secret values never reach workflow outputs"
    );
    let source = detail.tasks.iter().find(|t| t.key == "source").unwrap();
    assert!(serde_json::to_string(&source.output)
        .unwrap()
        .contains("runUserCode"));
    assert!(detail
        .tool_invocations
        .iter()
        .all(|t| t.status == "succeeded"));
    assert!(detail
        .tool_invocations
        .iter()
        .all(|t| t.side_effect.is_read_only()));

    let md = p.report(&run.id, "markdown").unwrap();
    assert!(md.contains("Outcome: **verified**") && md.contains("Validated results"));
    assert!(md.contains("Recommendations (not evidence)"));

    // Episodic memory and the evidence graph were populated, project-scoped.
    let db = Database::open(&f.db_path).unwrap();
    let memory = KnowledgeMemory::new(&db);
    assert!(!memory
        .list(&f.project_id, Some(MemoryLayer::Episodic), 50)
        .unwrap()
        .is_empty());
    let hits = memory
        .retrieve(
            &f.project_id,
            "security findings",
            RetrievalBudget::default(),
        )
        .unwrap();
    assert!(!hits.items.is_empty());
    assert!(memory
        .retrieve(
            "other-project",
            "security findings",
            RetrievalBudget::default()
        )
        .unwrap()
        .items
        .is_empty());
    let run_node = memory
        .find_node(&f.project_id, "run", &run.id)
        .unwrap()
        .unwrap();
    let graph = memory.neighborhood(&f.project_id, &run_node, 2).unwrap();
    assert!(graph
        .edges
        .iter()
        .any(|e| e.relation == "references" && e.provenance == "verified"));

    // Restart reconciliation on a clean database is a no-op.
    assert_eq!(p.recover().unwrap(), Default::default());
}

#[test]
fn research_and_cloud_require_consent_and_fail_closed() {
    let f = fixture();
    let p = platform(&f);
    let research = InvestigationOptions {
        research_urls: vec!["https://example.org/".into()],
        cloud_review: false,
    };
    let err = p
        .create_investigation(&f.project_id, "goal", "operator", &research, None)
        .unwrap_err();
    assert!(err.contains("web_research_not_enabled"), "{err}");
    let cloud = InvestigationOptions {
        research_urls: vec![],
        cloud_review: true,
    };
    let err = p
        .create_investigation(&f.project_id, "goal", "operator", &cloud, None)
        .unwrap_err();
    assert!(err.contains("cloud_disclosure_consent_missing"), "{err}");
    let matrix = p.capability_matrix(&f.project_id).unwrap();
    let sub = matrix
        .iter()
        .find(|c| c.capability == "subprocess")
        .unwrap();
    assert!(!sub.enabled && sub.reason.contains("never spawn"));
    assert!(
        !matrix
            .iter()
            .find(|c| c.capability == "web_research")
            .unwrap()
            .enabled
    );
    assert!(
        matrix
            .iter()
            .find(|c| c.capability == "read_findings")
            .unwrap()
            .enabled
    );
}

#[test]
fn evidence_verification_detects_drift() {
    let f = fixture();
    let db = Database::open(&f.db_path).unwrap();
    let (file_id, hash): (String, String) = db
        .connection()
        .query_row(
            "SELECT id, content_hash FROM files WHERE project_id=?1 LIMIT 1",
            [&f.project_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let tools = CoreToolRuntime::new(f.db_path.clone(), None, None);
    let check = |sha: &str| {
        tools
            .invoke(
                &f.project_id,
                "evidence.verify",
                &json!({"refs": [{"kind": "file", "id": file_id, "sha256": sha}]}),
                &CancelToken::new(),
            )
            .unwrap()
    };
    assert_eq!(check(&hash)["verified"], 1);
    assert_eq!(check(&"0".repeat(64))["drifted"], 1);
    let other = tools
        .invoke(
            "someone-elses-project",
            "evidence.verify",
            &json!({"refs": [{"kind": "file", "id": file_id}]}),
            &CancelToken::new(),
        )
        .unwrap();
    assert_eq!(other["missing"], 1, "evidence is project-scoped");
}
