use std::fs;

use tempfile::{tempdir, TempDir};

use super::*;
use crate::{
    AuthorizedWebSecurityStore, ProjectIndexService, RepairApplicationService, WebEvidenceInput,
    WebFindingInput, WebScanCreate,
};

struct Fixture {
    _root: TempDir,
    database: Database,
    project_id: String,
    finding_id: String,
    file_id: String,
    source_path: std::path::PathBuf,
}

fn fixture(
    category: &str,
    endpoint: &str,
    parameter: Option<&str>,
    confidence: &str,
    relative_path: &str,
    source: &str,
) -> Fixture {
    let root = tempdir().expect("temp project");
    let path = root.path().join(relative_path);
    fs::create_dir_all(path.parent().expect("parent")).expect("create source dir");
    fs::write(&path, source).expect("write source");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root.path())
        .expect("index project");
    let file_id: String = database
        .connection()
        .query_row(
            "SELECT id FROM files WHERE project_id=?1 AND relative_path=?2 AND is_active=1",
            rusqlite::params![index.project_id, relative_path],
            |row| row.get(0),
        )
        .expect("indexed file");

    let web = AuthorizedWebSecurityStore::new(&database);
    let scan = web
        .create_scan(&WebScanCreate {
            website_id: None,
            project_id: Some(index.project_id.clone()),
            target_url: "http://127.0.0.1:3000".into(),
            authorization_confirmed: true,
            scope_json: "{}".into(),
            config_json: "{}".into(),
            auth_metadata_json: "{}".into(),
        })
        .expect("scan");
    let finding = web
        .record_finding(
            &scan.id,
            &WebFindingInput {
                fingerprint: format!("fixture-{category}-{endpoint}"),
                category: category.into(),
                severity: "high".into(),
                confidence: confidence.into(),
                target: "http://127.0.0.1:3000".into(),
                endpoint_url: format!("http://127.0.0.1:3000{endpoint}"),
                method: "GET".into(),
                parameter_name: parameter.map(str::to_string),
                title: format!("Fixture {category}"),
                description: format!("Runtime evidence for {category}."),
                reproduction_summary: "Local fixture reproduction.".into(),
                impact: "Security boundary may be bypassed.".into(),
                remediation: "Use the framework-native server-side remediation.".into(),
                references: Vec::new(),
                source: None,
            },
        )
        .expect("finding");
    web.record_evidence(
        &finding.id,
        &WebEvidenceInput {
            summary: "local runtime evidence".into(),
            request_metadata_json: "{}".into(),
            response_metadata_json: "{}".into(),
        },
    )
    .expect("evidence");

    Fixture {
        _root: root,
        database,
        project_id: index.project_id,
        finding_id: finding.id,
        file_id,
        source_path: path,
    }
}

fn sql_fixture() -> Fixture {
    let tick = char::from(96);
    let source = format!(
        "export async function getSearch(q: string) {{\n  return db.query({tick}SELECT * FROM products WHERE name = '\\x24{{q}}'{tick});\n}}\n"
    )
    .replace("\\x24", "$");
    fixture(
        "sql_injection",
        "/api/search",
        Some("q"),
        "Likely",
        "src/api/searchController.ts",
        &source,
    )
}

fn xss_fixture() -> Fixture {
    fixture(
        "xss",
        "/api/render",
        Some("q"),
        "Likely",
        "src/api/renderController.ts",
        "export function getRender(q: string) {\n  output.innerHTML = q;\n}\n",
    )
}

#[test]
fn potential_finding_is_not_patch_eligible() {
    let fixture = fixture(
        "sql_injection",
        "/api/search",
        Some("q"),
        "Potential",
        "src/api/searchController.ts",
        "export function getSearch(q: string) { return q; }\n",
    );
    let assessment = SecurityFixService::new(&fixture.database)
        .evaluate_eligibility(&fixture.finding_id)
        .expect("eligibility");
    assert_eq!(assessment.result, FixEligibility::InsufficientEvidence);
    assert!(!assessment.bounded_patch_available);
}

#[test]
fn sql_injection_fix_uses_parameter_binding_and_exact_approval_hash() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    assert_eq!(prepared.eligibility.result, FixEligibility::AutoFixCandidate);
    assert!(prepared.root_causes[0].confidence >= 0.82);
    assert!(prepared.strategy.change_summary.contains("parameter"));

    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("generate patch");
    assert_eq!(review.safety.classification, PatchSafetyClass::SafeToReview);
    assert!(review.unified_diff.contains("WHERE name = ?"));
    assert!(review.unified_diff.contains("[q]"));
    assert!(!review.unified_diff.contains("quote escaping"));

    let approved = service
        .approve_attempt(&prepared.attempt.id, false)
        .expect("approve");
    assert_eq!(approved.status, "approved");
    assert_eq!(approved.patch_hash, approved.approved_patch_hash);
    assert!(service
        .assert_application_allowed(&prepared.attempt.id)
        .is_ok());
}

#[test]
fn source_change_after_approval_is_rejected() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    service
        .generate_patch(&prepared.attempt.id)
        .expect("patch");
    service
        .approve_attempt(&prepared.attempt.id, false)
        .expect("approve");

    fs::write(
        &fixture.source_path,
        "export function getSearch(q: string) { return q; }\n",
    )
    .expect("modify source after approval");

    let error = service
        .assert_application_allowed(&prepared.attempt.id)
        .expect_err("stale approval");
    assert!(matches!(error, SecurityFixError::StaleApproval));
}

#[test]
fn dangerous_patch_is_rejected_and_cannot_be_approved() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let unsafe_source = fs::read_to_string(&fixture.source_path)
        .expect("source")
        + "\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n";
    let review = service
        .propose_replacement(
            &prepared.attempt.id,
            &fixture.file_id,
            &unsafe_source,
        )
        .expect("review unsafe patch");
    assert_eq!(review.safety.classification, PatchSafetyClass::Rejected);
    assert!(!review.safety.rejected_reasons.is_empty());
    assert!(matches!(
        service.approve_attempt(&prepared.attempt.id, false),
        Err(SecurityFixError::AttemptNotApprovable(_))
    ));
}

#[test]
fn xss_plain_text_sink_gets_context_bounded_text_content_patch() {
    let fixture = xss_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    assert_eq!(prepared.eligibility.result, FixEligibility::AutoFixCandidate);
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("generate patch");
    assert!(review.unified_diff.contains(".textContent = q"));
    assert!(!review.unified_diff.contains("+   output.innerHTML"));
    assert_ne!(review.safety.classification, PatchSafetyClass::Rejected);
}

#[test]
fn authorization_frontend_only_patch_is_rejected() {
    let root = tempdir().expect("temp project");
    let controller = root.path().join("src/api/objectController.ts");
    let frontend = root.path().join("src/ObjectView.tsx");
    fs::create_dir_all(controller.parent().expect("parent")).expect("source dir");
    fs::write(
        &controller,
        "export function getObject(id: string) { return repository.find(id); }\n",
    )
    .expect("controller");
    fs::write(
        &frontend,
        "export function ObjectView() { return <button>Delete</button>; }\n",
    )
    .expect("frontend");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root.path())
        .expect("index");
    let frontend_id: String = database
        .connection()
        .query_row(
            "SELECT id FROM files WHERE project_id=?1 AND relative_path='src/ObjectView.tsx'",
            [&index.project_id],
            |row| row.get(0),
        )
        .expect("frontend id");

    let web = AuthorizedWebSecurityStore::new(&database);
    let scan = web
        .create_scan(&WebScanCreate {
            website_id: None,
            project_id: Some(index.project_id.clone()),
            target_url: "http://127.0.0.1:3000".into(),
            authorization_confirmed: true,
            scope_json: "{}".into(),
            config_json: "{}".into(),
            auth_metadata_json: "{}".into(),
        })
        .expect("scan");
    let finding = web
        .record_finding(
            &scan.id,
            &WebFindingInput {
                fingerprint: "auth-fixture".into(),
                category: "access_control".into(),
                severity: "high".into(),
                confidence: "Likely".into(),
                target: "http://127.0.0.1:3000".into(),
                endpoint_url: "http://127.0.0.1:3000/api/object".into(),
                method: "GET".into(),
                parameter_name: Some("id".into()),
                title: "Authorization inconsistency".into(),
                description: "User B observed User A object.".into(),
                reproduction_summary: "Two local test identities.".into(),
                impact: "Cross-account access.".into(),
                remediation: "Enforce server-side ownership.".into(),
                references: Vec::new(),
                source: None,
            },
        )
        .expect("finding");
    web.record_evidence(
        &finding.id,
        &WebEvidenceInput {
            summary: "A/B comparison".into(),
            request_metadata_json: "{}".into(),
            response_metadata_json: "{}".into(),
        },
    )
    .expect("evidence");

    let service = SecurityFixService::new(&database);
    let prepared = service
        .prepare_fix(&finding.id, false)
        .expect("prepare");
    assert_eq!(
        prepared.eligibility.result,
        FixEligibility::GuidedFixCandidate
    );
    let review = service
        .propose_replacement(
            &prepared.attempt.id,
            &frontend_id,
            "export function ObjectView() { return null; }\n",
        )
        .expect("review");
    assert_eq!(review.safety.classification, PatchSafetyClass::Rejected);
    assert!(review
        .safety
        .rejected_reasons
        .iter()
        .any(|reason| reason.contains("frontend")));
}

#[test]
fn apply_validation_retest_and_rollback_keep_history() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    service
        .generate_patch(&prepared.attempt.id)
        .expect("patch");
    service
        .approve_attempt(&prepared.attempt.id, false)
        .expect("approve");
    let repair_id = service
        .assert_application_allowed(&prepared.attempt.id)
        .expect("application allowed");

    let backups = tempdir().expect("backup root");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    assert_eq!(run.status, "applied");
    let applied = service
        .record_application(&prepared.attempt.id, &run.id)
        .expect("record application");
    assert_eq!(applied.status, "applied");
    assert!(fs::read_to_string(&fixture.source_path)
        .expect("patched source")
        .contains("WHERE name = ?"));

    let targets = vec!["src/api/searchController.ts".to_string()];
    service
        .add_validation_result(
            &prepared.attempt.id,
            ValidationResultInput {
                command_label: "CodeTwin source re-index",
                runner_kind: "codetwin_index",
                targets: &targets,
                status: "PASS",
                exit_code: Some(0),
                duration_ms: Some(1),
                classification: "NONE",
                stdout_summary: "index ok",
                stderr_summary: "",
            },
        )
        .expect("validation");
    service
        .add_validation_result(
            &prepared.attempt.id,
            ValidationResultInput {
                command_label: "repository unit test",
                runner_kind: "vitest",
                targets: &targets,
                status: "NOT_EXECUTED",
                exit_code: None,
                duration_ms: None,
                classification: "INFRASTRUCTURE_FAILURE",
                stdout_summary: "",
                stderr_summary: "trusted QA execution unavailable in test fixture",
            },
        )
        .expect("not executed validation");
    let validated = service
        .complete_validation(&prepared.attempt.id)
        .expect("complete validation");
    assert_eq!(validated.validation_state, "partial");
    assert_eq!(validated.status, "verification_pending");

    let verified = service
        .sync_retest_result(&fixture.finding_id, "retest_passed")
        .expect("sync retest")
        .expect("attempt");
    assert_eq!(verified.status, "fix_verified");
    assert_eq!(verified.retest_state, "FIX_VERIFIED");

    let rolled = RepairApplicationService::new(&fixture.database)
        .rollback_application(&run.id, backups.path())
        .expect("rollback");
    assert_eq!(rolled.status, "rolled_back");
    let rolled_attempt = service
        .record_rollback(&prepared.attempt.id, &run.id)
        .expect("record rollback");
    assert_eq!(rolled_attempt.status, "rolled_back");
    assert!(fs::read_to_string(&fixture.source_path)
        .expect("restored source")
        .contains(&format!("{}{{q}}", char::from(36))));
    assert!(service
        .events(&prepared.attempt.id, 100)
        .expect("events")
        .len()
        >= 5);
}

#[test]
fn patch_introduced_failure_blocks_fix_verified() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    service
        .add_validation_result(
            &prepared.attempt.id,
            ValidationResultInput {
                command_label: "targeted tests",
                runner_kind: "test",
                targets: &[],
                status: "FAIL",
                exit_code: Some(1),
                duration_ms: Some(2),
                classification: "PATCH_INTRODUCED_FAILURE",
                stdout_summary: "",
                stderr_summary: "fixture regression",
            },
        )
        .expect("failure");
    fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET status='applied' WHERE id=?1",
            [&prepared.attempt.id],
        )
        .expect("mark applied");
    let completed = service
        .complete_validation(&prepared.attempt.id)
        .expect("validation state");
    assert_eq!(completed.status, "validation_failed");

    let retested = service
        .sync_retest_result(&fixture.finding_id, "retest_passed")
        .expect("sync")
        .expect("attempt");
    assert_eq!(retested.retest_state, "REGRESSION_DETECTED");
    assert_ne!(retested.status, "fix_verified");
}

#[test]
fn still_vulnerable_creates_revised_attempt_and_default_limit_is_three() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let first = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("first");
    fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET status='applied' WHERE id=?1",
            [&first.attempt.id],
        )
        .expect("applied");
    service
        .sync_retest_result(&fixture.finding_id, "still_vulnerable")
        .expect("still vulnerable");

    let second = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("second");
    assert_eq!(second.attempt.attempt_number, 2);
    assert!(second
        .strategy
        .rationale
        .contains("previous guided fix attempt remained vulnerable"));

    let third = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("third");
    assert_eq!(third.attempt.attempt_number, 3);
    assert!(matches!(
        service.prepare_fix(&fixture.finding_id, false),
        Err(SecurityFixError::AttemptLimitReached)
    ));
    let fourth = service
        .prepare_fix(&fixture.finding_id, true)
        .expect("explicit fourth investigation");
    assert_eq!(fourth.attempt.attempt_number, 4);
}

#[test]
fn fix_history_rejects_secret_bearing_event_details() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    assert!(service
        .append_event(
            &prepared.attempt.id,
            "test",
            "should reject secret",
            r#"{"bearer_token":"must-not-persist"}"#,
        )
        .is_err());
    let serialized = serde_json::to_string(
        &service
            .events(&prepared.attempt.id, 100)
            .expect("events"),
    )
    .expect("json");
    assert!(!serialized.contains("must-not-persist"));
}

#[test]
fn configuration_finding_without_in_project_target_is_manual() {
    let fixture = fixture(
        "hsts",
        "/",
        None,
        "Likely",
        "src/api/homeController.ts",
        "export function getHome() { return 'ok'; }\n",
    );
    let assessment = SecurityFixService::new(&fixture.database)
        .evaluate_eligibility(&fixture.finding_id)
        .expect("eligibility");
    assert_eq!(assessment.result, FixEligibility::ManualRemediation);
    assert!(!assessment.bounded_patch_available);
    assert_eq!(assessment.finding_id, fixture.finding_id);
    assert!(!fixture.project_id.is_empty());
}
