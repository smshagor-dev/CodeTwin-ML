use std::fs;

use tempfile::{tempdir, TempDir};

use super::*;
use crate::{
    AuthorizedWebSecurityStore, GuidedRetestInput, GuidedSecurityStore, ProjectIndexService,
    QaDiscoveryService, RepairApplicationService, SecurityRemediationCampaignCreate,
    SecurityRemediationCampaignService, WebEvidenceInput, WebFindingInput, WebScanCreate,
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
        .approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, false)
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
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("patch");
    service
        .approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, false)
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
        service.approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, false),
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
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("patch");
    service
        .approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, false)
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

    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync applied guided lifecycle");
    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: None,
            status: "retest_passed",
            original_confidence: "Likely",
            observed_confidence: None,
            requests_performed: 3,
            detail_json: r#"{"fixture":"core-fix-verified"}"#,
        })
        .expect("persist targeted retest");
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
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync rolled-back guided lifecycle");
    assert_eq!(rolled_attempt.status, "rolled_back");
    assert_eq!(rolled_attempt.retest_state, "FIX_VERIFIED");
    let lifecycle: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT state FROM guided_security_finding_lifecycle WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("rolled-back lifecycle");
    assert_eq!(lifecycle, "fix_proposed");
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
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    let service = SecurityFixService::new(&fixture.database);
    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    service
        .record_application(&attempt_id, &run.id)
        .expect("record application");
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync applied lifecycle");

    service
        .add_validation_result(
            &attempt_id,
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
    let completed = service
        .complete_validation(&attempt_id)
        .expect("validation state");
    assert_eq!(completed.status, "validation_failed");

    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: None,
            status: "retest_passed",
            original_confidence: "Likely",
            observed_confidence: None,
            requests_performed: 4,
            detail_json: r#"{"fixture":"patch-regression"}"#,
        })
        .expect("runtime retest");
    let retested = service
        .sync_retest_result(&fixture.finding_id, "retest_passed")
        .expect("sync")
        .expect("attempt");
    assert_eq!(retested.retest_state, "REGRESSION_DETECTED");
    assert_ne!(retested.status, "fix_verified");
}

#[test]
fn still_vulnerable_creates_revised_attempt_and_default_limit_is_three() {
    let (fixture, first_attempt_id, repair_id) = approved_sql_attempt();
    let service = SecurityFixService::new(&fixture.database);
    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    service
        .record_application(&first_attempt_id, &run.id)
        .expect("record application");
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync lifecycle");
    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: None,
            status: "still_vulnerable",
            original_confidence: "Likely",
            observed_confidence: Some("Likely"),
            requests_performed: 4,
            detail_json: r#"{"fixture":"still-vulnerable-unit"}"#,
        })
        .expect("persist retest");
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


fn approved_sql_attempt() -> (Fixture, String, String) {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare approved fixture");
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("generate approved fixture patch");
    service
        .approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, false)
        .expect("approve fixture patch");
    let repair_id = prepared
        .attempt
        .repair_id
        .clone()
        .expect("repair id");
    (fixture, prepared.attempt.id, repair_id)
}

#[test]
fn fix_verified_cannot_be_forged_by_status_or_validation_only() {
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    let service = SecurityFixService::new(&fixture.database);

    let direct = fixture.database.connection().execute(
        "UPDATE security_fix_attempts
         SET status='fix_verified',retest_state='FIX_VERIFIED'
         WHERE id=?1",
        [&attempt_id],
    );
    assert!(direct.is_err(), "persistence must reject direct FIX_VERIFIED");

    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: None,
            status: "retest_passed",
            original_confidence: "Likely",
            observed_confidence: None,
            requests_performed: 4,
            detail_json: r#"{"fixture":"pre-apply-retest-must-not-count"}"#,
        })
        .expect("persist pre-apply retest");
    let pre_apply_rowid: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT MAX(rowid) FROM guided_security_retests WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("pre-apply retest row");

    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    let applied = service
        .record_application(&attempt_id, &run.id)
        .expect("record application");
    assert!(applied.retest_floor_rowid >= pre_apply_rowid);
    service
        .add_validation_result(
            &attempt_id,
            ValidationResultInput {
                command_label: "repository tests",
                runner_kind: "fixture",
                targets: &[],
                status: "PASS",
                exit_code: Some(0),
                duration_ms: Some(1),
                classification: "NONE",
                stdout_summary: "pass",
                stderr_summary: "",
            },
        )
        .expect("validation");
    service
        .complete_validation(&attempt_id)
        .expect("complete validation");

    let validation_only = fixture.database.connection().execute(
        "UPDATE security_fix_attempts
         SET status='fix_verified',retest_state='FIX_VERIFIED'
         WHERE id=?1",
        [&attempt_id],
    );
    assert!(
        validation_only.is_err(),
        "tests/static validation without a post-apply runtime retest must not forge FIX_VERIFIED"
    );

    assert!(
        service
            .sync_retest_result(&fixture.finding_id, "retest_passed")
            .is_err(),
        "a pre-apply retest row must not satisfy the post-apply runtime invariant"
    );
    let after_failed_service_transition = service
        .get_attempt(&attempt_id)
        .expect("attempt")
        .expect("attempt exists");
    assert_eq!(after_failed_service_transition.status, "verification_pending");
    assert_eq!(after_failed_service_transition.retest_state, "not_executed");
}

#[test]
fn caution_patch_requires_and_persists_explicit_acknowledgement() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    service
        .generate_patch(&prepared.attempt.id)
        .expect("generate safe base proposal");
    let repair_id = prepared.attempt.repair_id.as_deref().expect("repair");
    let safe_proposal: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT proposed_content FROM repair_changes WHERE repair_id=?1 LIMIT 1",
            [repair_id],
            |row| row.get(0),
        )
        .expect("safe proposal");
    let cautious = safe_proposal.replace(
        "}\n",
        "  try { audit(); } catch {}\n}\n",
    );
    let review = service
        .propose_replacement(&prepared.attempt.id, &fixture.file_id, &cautious)
        .expect("caution review");
    assert_eq!(review.safety.classification, PatchSafetyClass::Caution);
    assert!(matches!(
        service.approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, false),
        Err(SecurityFixError::CautionAcknowledgementRequired)
    ));

    let approved = service
        .approve_attempt(&prepared.attempt.id, &review.safety.patch_hash, true)
        .expect("approve caution");
    assert_eq!(
        approved.approved_safety_class,
        Some(PatchSafetyClass::Caution)
    );
    assert!(approved.caution_acknowledged);
    assert!(service
        .assert_application_allowed(&prepared.attempt.id)
        .is_ok());
}

#[test]
fn approval_rejects_patch_hash_base_hash_proposed_hash_and_file_set_substitution() {
    for mutation in ["proposed_hash", "base_hash", "delete_file", "add_file"] {
        let (fixture, attempt_id, repair_id) = approved_sql_attempt();
        let service = SecurityFixService::new(&fixture.database);
        match mutation {
            "proposed_hash" => {
                fixture
                    .database
                    .connection()
                    .execute(
                        "UPDATE repair_changes
                         SET proposed_content_hash=lower(hex(randomblob(32)))
                         WHERE repair_id=?1",
                        [&repair_id],
                    )
                    .expect("tamper proposed hash");
            }
            "base_hash" => {
                fixture
                    .database
                    .connection()
                    .execute(
                        "UPDATE repair_changes
                         SET base_content_hash=lower(hex(randomblob(32)))
                         WHERE repair_id=?1",
                        [&repair_id],
                    )
                    .expect("tamper base hash");
            }
            "delete_file" => {
                fixture
                    .database
                    .connection()
                    .execute("DELETE FROM repair_changes WHERE repair_id=?1", [&repair_id])
                    .expect("delete approved file");
            }
            "add_file" => {
                let (base_hash, proposed_hash, proposed_content, proposed_size): (
                    String,
                    String,
                    String,
                    i64,
                ) = fixture
                    .database
                    .connection()
                    .query_row(
                        "SELECT base_content_hash,proposed_content_hash,proposed_content,proposed_byte_size
                         FROM repair_changes WHERE repair_id=?1 LIMIT 1",
                        [&repair_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .expect("approved change");
                fixture
                    .database
                    .connection()
                    .execute(
                        "INSERT INTO repair_changes(
                            id,repair_id,file_id,relative_path,base_content_hash,
                            proposed_content_hash,proposed_content,proposed_byte_size
                         ) VALUES ('tampered-extra',?1,?2,'src/api/unapproved-extra.ts',?3,?4,?5,?6)",
                        rusqlite::params![
                            repair_id,
                            fixture.file_id,
                            base_hash,
                            proposed_hash,
                            proposed_content,
                            proposed_size
                        ],
                    )
                    .expect("add unapproved file");
            }
            _ => unreachable!(),
        }

        assert!(
            matches!(
                service.assert_application_allowed(&attempt_id),
                Err(SecurityFixError::StaleApproval)
            ),
            "approval must not survive {mutation} substitution"
        );
    }
}

#[test]
fn approved_attempt_identity_and_safety_fields_are_immutable() {
    let (fixture, attempt_id, _) = approved_sql_attempt();
    for statement in [
        "UPDATE security_fix_attempts SET finding_id='different' WHERE id=?1",
        "UPDATE security_fix_attempts SET patch_hash=lower(hex(randomblob(32))) WHERE id=?1",
        "UPDATE security_fix_attempts SET safety_class='CAUTION' WHERE id=?1",
        "UPDATE security_fix_attempts SET approved_patch_hash=lower(hex(randomblob(32))) WHERE id=?1",
        "UPDATE security_fix_attempts SET caution_acknowledged=1 WHERE id=?1",
    ] {
        assert!(
            fixture
                .database
                .connection()
                .execute(statement, [&attempt_id])
                .is_err(),
            "approved attempt identity mutation must be rejected: {statement}"
        );
    }
}

#[test]
fn patch_safety_rejects_high_risk_generated_or_proposed_changes() {
    let cases = [
        (
            "tls",
            "\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
            "TLS",
        ),
        ("eval", "\neval(userInput);\n", "evaluation"),
        (
            "shell",
            "\nconst cp = require('child_process'); cp.exec(userInput);\n",
            "process",
        ),
        (
            "html",
            "\nview.dangerouslySetInnerHTML = { __html: q };\n",
            "HTML",
        ),
        (
            "cors",
            "\nres.setHeader('Access-Control-Allow-Origin', '*');\n",
            "CORS",
        ),
        (
            "secret",
            "\nconst api_key = 'super-secret-value';\n",
            "secret",
        ),
    ];

    for (name, addition, expected) in cases {
        let fixture = sql_fixture();
        let service = SecurityFixService::new(&fixture.database);
        let prepared = service
            .prepare_fix(&fixture.finding_id, false)
            .expect("prepare safety fixture");
        let proposed = fs::read_to_string(&fixture.source_path).expect("source") + addition;
        let review = service
            .propose_replacement(&prepared.attempt.id, &fixture.file_id, &proposed)
            .expect("review unsafe proposal");
        assert_eq!(
            review.safety.classification,
            PatchSafetyClass::Rejected,
            "{name} patch must be rejected"
        );
        assert!(
            review
                .safety
                .rejected_reasons
                .iter()
                .any(|reason| reason.to_ascii_lowercase().contains(&expected.to_ascii_lowercase())),
            "{name} rejection should explain the {expected} risk"
        );
    }
}

#[test]
fn sql_fake_fixes_using_concatenation_or_manual_escaping_are_rejected() {
    for proposed in [
        "export async function getSearch(q: string) {\n  return db.query('SELECT * FROM products WHERE name = ' + q);\n}\n",
        "export async function getSearch(q: string) {\n  const safe = q.replace(\"'\", \"''\");\n  return db.query('SELECT * FROM products WHERE name = ' + safe);\n}\n",
    ] {
        let fixture = sql_fixture();
        let service = SecurityFixService::new(&fixture.database);
        let prepared = service
            .prepare_fix(&fixture.finding_id, false)
            .expect("prepare");
        let review = service
            .propose_replacement(&prepared.attempt.id, &fixture.file_id, proposed)
            .expect("review fake SQL fix");
        assert_eq!(review.safety.classification, PatchSafetyClass::Rejected);
        assert!(review
            .safety
            .rejected_reasons
            .iter()
            .any(|reason| reason.contains("parameter binding")));
    }
}

#[test]
fn validation_and_event_records_cannot_be_rewritten() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let validation = service
        .add_validation_result(
            &prepared.attempt.id,
            ValidationResultInput {
                command_label: "fixture",
                runner_kind: "fixture",
                targets: &[],
                status: "NOT_EXECUTED",
                exit_code: None,
                duration_ms: None,
                classification: "INFRASTRUCTURE_FAILURE",
                stdout_summary: "",
                stderr_summary: "unavailable",
            },
        )
        .expect("validation");
    let event = service
        .events(&prepared.attempt.id, 20)
        .expect("events")
        .into_iter()
        .next()
        .expect("event");

    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_validation_results SET status='PASS' WHERE id=?1",
            [&validation.id],
        )
        .is_err());
    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_events SET message='rewritten' WHERE id=?1",
            [&event.id],
        )
        .is_err());
}


#[test]
fn secret_storage_rejects_jwt_bearer_cookie_and_redacts_validation_output() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");

    for detail in [
        r#"{"note":"Bearer top-secret-value"}"#,
        r#"{"note":"session=private-cookie-value"}"#,
        r#"{"note":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.signature123456"}"#,
    ] {
        assert!(
            service
                .append_event(&prepared.attempt.id, "unsafe", "safe message", detail)
                .is_err(),
            "secret-shaped detail must be rejected"
        );
    }
    assert!(service
        .append_event(
            &prepared.attempt.id,
            "unsafe",
            "Authorization: Bearer top-secret-value",
            "{}",
        )
        .is_err());

    let validation = service
        .add_validation_result(
            &prepared.attempt.id,
            ValidationResultInput {
                command_label: "fixture output",
                runner_kind: "fixture",
                targets: &[],
                status: "FAIL",
                exit_code: Some(1),
                duration_ms: Some(1),
                classification: "UNKNOWN",
                stdout_summary: "Cookie: session=private-cookie-value",
                stderr_summary: "Authorization: Bearer top-secret-value",
            },
        )
        .expect("validation output is redacted rather than rejected");
    assert_eq!(
        validation.stdout_summary,
        "[redacted: sensitive validation output]"
    );
    assert_eq!(
        validation.stderr_summary,
        "[redacted: sensitive validation output]"
    );

    let persisted = serde_json::to_string(
        &service
            .validation_results(&prepared.attempt.id, 20)
            .expect("validation history"),
    )
    .expect("serialize history");
    assert!(!persisted.contains("private-cookie-value"));
    assert!(!persisted.contains("top-secret-value"));
}


#[test]
fn overlapping_findings_require_fresh_hashes_and_do_not_share_approval() {
    let fixture = sql_fixture();
    let scan_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT scan_id FROM web_security_findings WHERE id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("scan id");
    let web = AuthorizedWebSecurityStore::new(&fixture.database);
    let second = web
        .record_finding(
            &scan_id,
            &WebFindingInput {
                fingerprint: "second-overlapping-sqli".into(),
                category: "sql_injection".into(),
                severity: "high".into(),
                confidence: "Likely".into(),
                target: "http://127.0.0.1:3000".into(),
                endpoint_url: "http://127.0.0.1:3000/api/search?q=second".into(),
                method: "GET".into(),
                parameter_name: Some("q".into()),
                title: "Second overlapping SQL finding".into(),
                description: "Same source region, separate runtime observation.".into(),
                reproduction_summary: "Local fixture.".into(),
                impact: "Query structure manipulation.".into(),
                remediation: "Parameterize query.".into(),
                references: Vec::new(),
                source: None,
            },
        )
        .expect("second finding");
    web.record_evidence(
        &second.id,
        &WebEvidenceInput {
            summary: "second runtime evidence".into(),
            request_metadata_json: "{}".into(),
            response_metadata_json: "{}".into(),
        },
    )
    .expect("second evidence");

    let service = SecurityFixService::new(&fixture.database);
    let overlap = service
        .analyze_multi_finding_overlap(&[
            fixture.finding_id.clone(),
            second.id.clone(),
        ])
        .expect("overlap");
    assert!(overlap.requires_combined_review);
    assert!(overlap
        .overlapping_files
        .iter()
        .any(|path| path.ends_with("src/api/searchController.ts")));

    let first = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare A");
    let review_a = service.generate_patch(&first.attempt.id).expect("patch A");
    service
        .approve_attempt(&first.attempt.id, &review_a.safety.patch_hash, false)
        .expect("approve A");

    let second_fix = service
        .prepare_fix(&second.id, false)
        .expect("prepare B");
    let review_b = service
        .generate_patch(&second_fix.attempt.id)
        .expect("patch B");
    service
        .approve_attempt(&second_fix.attempt.id, &review_b.safety.patch_hash, false)
        .expect("approve B");
    let second_repair = service
        .assert_application_allowed(&second_fix.attempt.id)
        .expect("B allowed");

    let backups = tempdir().expect("B backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&second_repair, backups.path())
        .expect("apply B");
    assert_eq!(run.status, "applied");
    service
        .record_application(&second_fix.attempt.id, &run.id)
        .expect("record B");

    assert!(
        matches!(
            service.assert_application_allowed(&first.attempt.id),
            Err(SecurityFixError::StaleApproval)
        ),
        "A approval must become stale after B changes the overlapping source"
    );
}

#[test]
fn remediation_campaign_blocks_overlapping_approved_patch_after_prior_source_mutation() {
    let fixture = sql_fixture();
    let second_id = add_overlapping_sql_finding(&fixture, "campaign-overlap");
    let scan_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT scan_id FROM web_security_findings WHERE id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("scan id");
    fixture
        .database
        .connection()
        .execute(
            "INSERT INTO guided_security_sessions(
                id,project_id,target_url,environment,testing_depth,auth_mode,status,
                authorization_confirmed,config_json,scan_id
             ) VALUES (
                'campaign-overlap-session',?1,'http://127.0.0.1:3000','local',
                'standard','none','completed',1,'{}',?2
             )",
            rusqlite::params![fixture.project_id, scan_id],
        )
        .expect("guided campaign session");

    let campaigns = SecurityRemediationCampaignService::new(&fixture.database);
    let campaign = campaigns
        .create(&SecurityRemediationCampaignCreate {
            session_id: "campaign-overlap-session".into(),
            finding_ids: vec![fixture.finding_id.clone(), second_id.clone()],
        })
        .expect("campaign");
    let analyzed = campaigns.analyze(&campaign.id).expect("analyze campaign overlap");
    let relationships = campaigns
        .relationships(&campaign.id)
        .expect("campaign relationships");
    assert!(relationships.iter().any(|relationship| {
        matches!(
            relationship.relationship.as_str(),
            "SHARED_ROOT_CAUSE" | "SOURCE_OVERLAP" | "POTENTIAL_CONFLICT"
        )
    }));
    campaigns
        .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("plan hash"))
        .expect("approve campaign");
    campaigns.start(&campaign.id).expect("start campaign");

    let fixes = SecurityFixService::new(&fixture.database);
    let first = fixes
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare first");
    let first_review = fixes.generate_patch(&first.attempt.id).expect("first patch");
    fixes
        .approve_attempt(
            &first.attempt.id,
            &first_review.safety.patch_hash,
            first_review.safety.classification == PatchSafetyClass::Caution,
        )
        .expect("approve first");

    let second = fixes
        .prepare_fix(&second_id, false)
        .expect("prepare second");
    let second_review = fixes.generate_patch(&second.attempt.id).expect("second patch");
    fixes
        .approve_attempt(
            &second.attempt.id,
            &second_review.safety.patch_hash,
            second_review.safety.classification == PatchSafetyClass::Caution,
        )
        .expect("approve second");
    let second_repair = fixes
        .assert_application_allowed(&second.attempt.id)
        .expect("second application allowed");

    let backups = tempdir().expect("overlap campaign backups");
    let application = RepairApplicationService::new(&fixture.database)
        .apply_plan(&second_repair, backups.path())
        .expect("apply second overlapping fix");
    fixes
        .record_application(&second.attempt.id, &application.id)
        .expect("record second application");

    assert!(matches!(
        fixes.assert_application_allowed(&first.attempt.id),
        Err(SecurityFixError::StaleApproval)
    ));
    campaigns.sync(&campaign.id).expect("sync campaign overlap");
    let first_member = campaigns
        .findings(&campaign.id)
        .expect("campaign findings")
        .into_iter()
        .find(|finding| finding.finding_id == fixture.finding_id)
        .expect("first campaign finding");
    assert_eq!(
        first_member.status, "BLOCKED",
        "campaign must not silently rebase or apply an overlapping stale approval"
    );
}

#[test]
fn remediation_campaign_resume_blocks_approved_patch_after_external_source_change() {
    let fixture = sql_fixture();
    let scan_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT scan_id FROM web_security_findings WHERE id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("scan id");
    fixture
        .database
        .connection()
        .execute(
            "INSERT INTO guided_security_sessions(
                id,project_id,target_url,environment,testing_depth,auth_mode,status,
                authorization_confirmed,config_json,scan_id
             ) VALUES (
                'campaign-stale-resume-session',?1,'http://127.0.0.1:3000','local',
                'standard','none','completed',1,'{}',?2
             )",
            rusqlite::params![fixture.project_id, scan_id],
        )
        .expect("guided campaign session");

    let campaigns = SecurityRemediationCampaignService::new(&fixture.database);
    let campaign = campaigns
        .create(&SecurityRemediationCampaignCreate {
            session_id: "campaign-stale-resume-session".into(),
            finding_ids: vec![fixture.finding_id.clone()],
        })
        .expect("campaign");
    let analyzed = campaigns.analyze(&campaign.id).expect("analyze");
    campaigns
        .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
        .expect("approve campaign");
    campaigns.start(&campaign.id).expect("start campaign");

    let fixes = SecurityFixService::new(&fixture.database);
    let prepared = fixes
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare fix");
    let review = fixes.generate_patch(&prepared.attempt.id).expect("generate patch");
    fixes
        .approve_attempt(
            &prepared.attempt.id,
            &review.safety.patch_hash,
            review.safety.classification == PatchSafetyClass::Caution,
        )
        .expect("approve exact patch");
    campaigns.sync(&campaign.id).expect("sync approved attempt");
    campaigns.pause(&campaign.id).expect("pause campaign");

    fs::write(
        &fixture.source_path,
        "export async function getSearch(q: string) { return db.query('SELECT 1'); }\n",
    )
    .expect("external source change");

    assert!(matches!(
        fixes.assert_application_allowed(&prepared.attempt.id),
        Err(SecurityFixError::StaleApproval)
    ));
    let resumed = campaigns
        .resume(&campaign.id)
        .expect("resume should block rather than reuse stale approval");
    assert_eq!(resumed.status, "BLOCKED");
    let member = campaigns
        .findings(&campaign.id)
        .expect("campaign findings")
        .into_iter()
        .find(|finding| finding.finding_id == fixture.finding_id)
        .expect("campaign finding");
    assert_eq!(member.status, "BLOCKED");
    assert_eq!(member.active_attempt_id.as_deref(), Some(prepared.attempt.id.as_str()));
    assert!(campaigns
        .events(&campaign.id, 100)
        .expect("campaign events")
        .iter()
        .any(|event| event.event_type == "resume_blocked_stale_source"));
}

#[test]
fn remediation_campaign_completion_rejects_external_source_change_after_final_verification() {
    let fixture = sql_fixture();
    let scan_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT scan_id FROM web_security_findings WHERE id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("scan id");
    fixture
        .database
        .connection()
        .execute(
            "INSERT INTO guided_security_sessions(
                id,project_id,target_url,environment,testing_depth,auth_mode,status,
                authorization_confirmed,config_json,scan_id
             ) VALUES (
                'campaign-final-source-session',?1,'http://127.0.0.1:3000','local',
                'standard','none','completed',1,'{}',?2
             )",
            rusqlite::params![fixture.project_id, scan_id],
        )
        .expect("guided campaign session");

    let campaigns = SecurityRemediationCampaignService::new(&fixture.database);
    let campaign = campaigns
        .create(&SecurityRemediationCampaignCreate {
            session_id: "campaign-final-source-session".into(),
            finding_ids: vec![fixture.finding_id.clone()],
        })
        .expect("campaign");
    let analyzed = campaigns.analyze(&campaign.id).expect("analyze");
    campaigns
        .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
        .expect("approve");
    campaigns.start(&campaign.id).expect("start");
    campaigns
        .skip_finding(&campaign.id, &fixture.finding_id, "deferred for final source guard")
        .expect("skip");

    campaigns
        .begin_completion_verification(&campaign.id)
        .expect("begin final verification");
    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: Some("campaign-final-source-session"),
            status: "still_vulnerable",
            original_confidence: "Likely",
            observed_confidence: Some("Likely"),
            requests_performed: 4,
            detail_json: r#"{"fixture":"final-source-guard"}"#,
        })
        .expect("fresh final retest");
    campaigns
        .finalize_completion_verification(&campaign.id)
        .expect("finalize final verification");

    fs::write(
        &fixture.source_path,
        "export async function getSearch(q: string) { return db.query('externally changed'); }\n",
    )
    .expect("external source change after verification");

    let synced = campaigns
        .sync(&campaign.id)
        .expect("polling sync must invalidate stale final verification");
    assert!(
        synced.completion_verification_completed_at.is_none(),
        "stale final verification must disappear from the campaign state before completion"
    );
    assert!(campaigns
        .events(&campaign.id, 100)
        .expect("campaign events")
        .iter()
        .any(|event| event.event_type == "completion_verification_invalidated"));

    let error = campaigns
        .complete(&campaign.id)
        .expect_err("external source change must require a new final verification pass");
    assert!(
        error
            .to_string()
            .contains("requires a fresh bounded verification pass"),
        "completion must fail closed after sync invalidates stale verification: {error}"
    );
}

#[test]
fn security_fix_apply_boundary_rejects_duplicate_application() {
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    let fixes = SecurityFixService::new(&fixture.database);
    let backups = tempdir().expect("duplicate apply backups");
    let application = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("first apply");
    fixes
        .record_application(&attempt_id, &application.id)
        .expect("record first apply");

    assert!(
        matches!(
            fixes.assert_application_allowed(&attempt_id),
            Err(SecurityFixError::AttemptNotApproved)
        ),
        "an applied security fix cannot pass the exact approval gate a second time"
    );
    let run_count: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM repair_application_runs WHERE repair_id=?1",
            [&repair_id],
            |row| row.get(0),
        )
        .expect("repair application run count");
    assert_eq!(run_count, 1);
}

#[test]
fn remediation_campaign_blocks_rollback_when_verified_dependent_relies_on_applied_fix() {
    let fixture = sql_fixture();
    let second_id = add_overlapping_sql_finding(&fixture, "campaign-rollback-dependency");
    let scan_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT scan_id FROM web_security_findings WHERE id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("scan id");
    fixture
        .database
        .connection()
        .execute(
            "INSERT INTO guided_security_sessions(
                id,project_id,target_url,environment,testing_depth,auth_mode,status,
                authorization_confirmed,config_json,scan_id
             ) VALUES (
                'campaign-rollback-session',?1,'http://127.0.0.1:3000','local',
                'standard','none','completed',1,'{}',?2
             )",
            rusqlite::params![fixture.project_id, scan_id],
        )
        .expect("guided campaign session");

    let campaigns = SecurityRemediationCampaignService::new(&fixture.database);
    let campaign = campaigns
        .create(&SecurityRemediationCampaignCreate {
            session_id: "campaign-rollback-session".into(),
            finding_ids: vec![fixture.finding_id.clone(), second_id.clone()],
        })
        .expect("campaign");
    let analyzed = campaigns.analyze(&campaign.id).expect("analyze");
    campaigns
        .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
        .expect("approve");
    campaigns.start(&campaign.id).expect("start");

    let members = campaigns.findings(&campaign.id).expect("members");
    let dependent = members
        .iter()
        .find(|finding| !finding.depends_on.is_empty())
        .expect("overlap analysis must create an ordered dependency")
        .clone();
    let prerequisite_id = dependent.depends_on[0].clone();

    let fixes = SecurityFixService::new(&fixture.database);
    let prepared = fixes
        .prepare_fix(&prerequisite_id, false)
        .expect("prepare prerequisite");
    let review = fixes.generate_patch(&prepared.attempt.id).expect("review prerequisite");
    fixes
        .approve_attempt(
            &prepared.attempt.id,
            &review.safety.patch_hash,
            review.safety.classification == PatchSafetyClass::Caution,
        )
        .expect("approve prerequisite");
    let repair_id = fixes
        .assert_application_allowed(&prepared.attempt.id)
        .expect("prerequisite allowed");
    let backups = tempdir().expect("campaign rollback prerequisite backups");
    let application = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply prerequisite");
    fixes
        .record_application(&prepared.attempt.id, &application.id)
        .expect("record prerequisite application");
    campaigns.sync(&campaign.id).expect("sync prerequisite");

    fixture
        .database
        .connection()
        .execute(
            "INSERT INTO guided_security_retests(
                id,finding_id,session_id,status,original_confidence,
                observed_confidence,requests_performed,detail_json
             ) VALUES (
                'campaign-dependent-retest',?1,'campaign-rollback-session',
                'retest_passed','Likely','Likely',2,'{}'
             )",
            [&dependent.finding_id],
        )
        .expect("persist dependent targeted retest");
    campaigns.sync(&campaign.id).expect("sync verified dependent");

    let assessment = campaigns
        .rollback_assessment(&campaign.id, &prerequisite_id)
        .expect("rollback assessment");
    assert!(!assessment.allowed);
    assert!(assessment
        .blocking_findings
        .iter()
        .any(|finding_id| finding_id == &dependent.finding_id));
    assert!(assessment.reason.contains("depend"));
}

#[cfg(unix)]
#[test]
fn approved_security_fix_rejects_symlink_substitution_before_application() {
    use std::os::unix::fs::symlink;

    let (fixture, attempt_id, _) = approved_sql_attempt();
    let outside = tempdir().expect("outside");
    let outside_file = outside.path().join("outside.ts");
    fs::write(&outside_file, "export const outside = true;\n").expect("outside file");
    fs::remove_file(&fixture.source_path).expect("remove approved source");
    symlink(&outside_file, &fixture.source_path).expect("substitute symlink");

    assert!(
        matches!(
            SecurityFixService::new(&fixture.database)
                .assert_application_allowed(&attempt_id),
            Err(SecurityFixError::StaleApproval)
        ),
        "symlink substitution must fail before repair application"
    );
}


#[test]
fn persistence_rejects_invalid_security_fix_lifecycle_transitions() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");

    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET status='approved' WHERE id=?1",
            [&prepared.attempt.id],
        )
        .is_err(), "prepared must not skip patch review");

    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts
             SET retest_state='FIX_VERIFIED' WHERE id=?1",
            [&prepared.attempt.id],
        )
        .is_err(), "runtime verification state must not be set without the matching verified lifecycle");
}


#[test]
fn patch_safety_rejects_removed_server_security_controls() {
    for (category, source, proposed, endpoint) in [
        (
            "access_control",
            "export function getObject(id: string, user: User) {\n  authorize(user, id);\n  return repository.find(id);\n}\n",
            "export function getObject(id: string, user: User) {\n  return repository.find(id);\n}\n",
            "/api/object",
        ),
        (
            "csrf",
            "export function postUpdate(token: string) {\n  csrf.validate(token);\n  return update();\n}\n",
            "export function postUpdate(token: string) {\n  return update();\n}\n",
            "/api/update",
        ),
        (
            "api_input_validation",
            "export function postInput(body: Input) {\n  validator.validate(body);\n  return save(body);\n}\n",
            "export function postInput(body: Input) {\n  return save(body);\n}\n",
            "/api/input",
        ),
    ] {
        let fixture = fixture(
            category,
            endpoint,
            Some(if category == "access_control" { "id" } else { "body" }),
            "Likely",
            "src/api/securityController.ts",
            source,
        );
        let service = SecurityFixService::new(&fixture.database);
        let prepared = service
            .prepare_fix(&fixture.finding_id, false)
            .expect("prepare control-removal fixture");
        let review = service
            .propose_replacement(&prepared.attempt.id, &fixture.file_id, proposed)
            .expect("review control removal");
        assert_eq!(
            review.safety.classification,
            PatchSafetyClass::Rejected,
            "{category} control removal must be rejected"
        );
        assert!(review
            .safety
            .rejected_reasons
            .iter()
            .any(|reason| reason.contains("security control")));
    }
}

#[test]
fn patch_safety_rejects_large_test_deletion() {
    let fixture = sql_fixture();
    let test_path = fixture._root.path().join("tests/search.test.ts");
    fs::create_dir_all(test_path.parent().expect("test parent")).expect("test dir");
    fs::write(
        &test_path,
        "test('a',()=>expect(1).toBe(1));\n\
         test('b',()=>expect(2).toBe(2));\n\
         test('c',()=>expect(3).toBe(3));\n\
         test('d',()=>expect(4).toBe(4));\n\
         test('e',()=>expect(5).toBe(5));\n\
         test('f',()=>expect(6).toBe(6));\n",
    )
    .expect("test file");
    ProjectIndexService::new(&fixture.database)
        .index_project(fixture._root.path())
        .expect("reindex tests");
    let test_file_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT id FROM files WHERE project_id=?1 AND relative_path='tests/search.test.ts' AND is_active=1",
            [&fixture.project_id],
            |row| row.get(0),
        )
        .expect("test file id");

    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let review = service
        .propose_replacement(
            &prepared.attempt.id,
            &test_file_id,
            "test('kept',()=>expect(1).toBe(1));\n",
        )
        .expect("review test deletion");
    assert_eq!(review.safety.classification, PatchSafetyClass::Rejected);
    assert!(review
        .safety
        .rejected_reasons
        .iter()
        .any(|reason| reason.contains("more than half")));
}

#[test]
fn patch_safety_rejects_excessive_file_spread() {
    let fixture = sql_fixture();
    for index in 0..4 {
        let path = fixture
            ._root
            .path()
            .join(format!("config/security-{index}.ts"));
        fs::create_dir_all(path.parent().expect("config parent")).expect("config dir");
        fs::write(&path, format!("export const setting{index} = false;\n"))
            .expect("config file");
    }
    ProjectIndexService::new(&fixture.database)
        .index_project(fixture._root.path())
        .expect("reindex configs");

    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let mut final_review = None;
    for index in 0..4 {
        let relative = format!("config/security-{index}.ts");
        let file_id: String = fixture
            .database
            .connection()
            .query_row(
                "SELECT id FROM files WHERE project_id=?1 AND relative_path=?2 AND is_active=1",
                rusqlite::params![fixture.project_id, relative],
                |row| row.get(0),
            )
            .expect("config file id");
        final_review = Some(
            service
                .propose_replacement(
                    &prepared.attempt.id,
                    &file_id,
                    &format!("export const setting{index} = true;\n"),
                )
                .expect("review spread"),
        );
    }
    let final_review = final_review.expect("final review");
    assert_eq!(final_review.safety.classification, PatchSafetyClass::Rejected);
    assert!(final_review
        .safety
        .rejected_reasons
        .iter()
        .any(|reason| reason.contains("bounded to")));
}


fn add_overlapping_sql_finding(fixture: &Fixture, suffix: &str) -> String {
    let scan_id: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT scan_id FROM web_security_findings WHERE id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("scan id");
    let web = AuthorizedWebSecurityStore::new(&fixture.database);
    let finding = web
        .record_finding(
            &scan_id,
            &WebFindingInput {
                fingerprint: format!("overlap-{suffix}"),
                category: "sql_injection".into(),
                severity: "high".into(),
                confidence: "Likely".into(),
                target: "http://127.0.0.1:3000".into(),
                endpoint_url: format!("http://127.0.0.1:3000/api/search?q={suffix}"),
                method: "GET".into(),
                parameter_name: Some("q".into()),
                title: format!("Overlapping SQL finding {suffix}"),
                description: "Same local source path, separate runtime observation.".into(),
                reproduction_summary: "Local fixture.".into(),
                impact: "Query manipulation.".into(),
                remediation: "Use parameter binding.".into(),
                references: Vec::new(),
                source: None,
            },
        )
        .expect("overlapping finding");
    web.record_evidence(
        &finding.id,
        &WebEvidenceInput {
            summary: "runtime evidence".into(),
            request_metadata_json: "{}".into(),
            response_metadata_json: "{}".into(),
        },
    )
    .expect("overlapping evidence");
    finding.id
}

#[test]
fn approval_rejects_wrong_displayed_expected_patch_hash() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("review");

    let wrong_hash = if review.safety.patch_hash.starts_with('a') {
        "b".repeat(64)
    } else {
        "a".repeat(64)
    };
    assert!(matches!(
        service.approve_attempt(&prepared.attempt.id, &wrong_hash, false),
        Err(SecurityFixError::StaleApproval)
    ));
    assert_eq!(
        service
            .get_attempt(&prepared.attempt.id)
            .expect("attempt")
            .expect("attempt exists")
            .status,
        "patch_proposed"
    );
}

#[test]
fn approval_rejects_patch_file_base_and_proposed_hash_changes_after_display() {
    for mutation in ["patch_content", "file_list", "base_hash", "proposed_hash"] {
        let fixture = sql_fixture();
        let service = SecurityFixService::new(&fixture.database);
        let prepared = service
            .prepare_fix(&fixture.finding_id, false)
            .expect("prepare");
        let displayed = service
            .generate_patch(&prepared.attempt.id)
            .expect("displayed review");
        let repair_id = prepared.attempt.repair_id.as_deref().expect("repair");

        match mutation {
            "patch_content" => {
                let current: String = fixture
                    .database
                    .connection()
                    .query_row(
                        "SELECT proposed_content FROM repair_changes WHERE repair_id=?1 LIMIT 1",
                        [repair_id],
                        |row| row.get(0),
                    )
                    .expect("proposal");
                let changed = format!("{current}\n// changed after preview\n");
                service
                    .propose_replacement(&prepared.attempt.id, &fixture.file_id, &changed)
                    .expect("changed proposal");
            }
            "file_list" => {
                let (base_hash, proposed_hash, proposed_content, proposed_size): (
                    String,
                    String,
                    String,
                    i64,
                ) = fixture
                    .database
                    .connection()
                    .query_row(
                        "SELECT base_content_hash,proposed_content_hash,proposed_content,proposed_byte_size
                         FROM repair_changes WHERE repair_id=?1 LIMIT 1",
                        [repair_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .expect("change");
                fixture
                    .database
                    .connection()
                    .execute(
                        "INSERT INTO repair_changes(
                            id,repair_id,file_id,relative_path,base_content_hash,
                            proposed_content_hash,proposed_content,proposed_byte_size
                         ) VALUES ('preview-extra',?1,?2,'src/api/preview-extra.ts',?3,?4,?5,?6)",
                        rusqlite::params![
                            repair_id,
                            fixture.file_id,
                            base_hash,
                            proposed_hash,
                            proposed_content,
                            proposed_size
                        ],
                    )
                    .expect("insert extra file");
            }
            "base_hash" => {
                fixture
                    .database
                    .connection()
                    .execute(
                        "UPDATE repair_changes SET base_content_hash=lower(hex(randomblob(32)))
                         WHERE repair_id=?1",
                        [repair_id],
                    )
                    .expect("mutate base hash");
            }
            "proposed_hash" => {
                fixture
                    .database
                    .connection()
                    .execute(
                        "UPDATE repair_changes SET proposed_content_hash=lower(hex(randomblob(32)))
                         WHERE repair_id=?1",
                        [repair_id],
                    )
                    .expect("mutate proposed hash");
            }
            _ => unreachable!(),
        }

        assert!(
            matches!(
                service.approve_attempt(
                    &prepared.attempt.id,
                    &displayed.safety.patch_hash,
                    false,
                ),
                Err(SecurityFixError::StaleApproval)
            ),
            "displayed approval must become stale after {mutation}"
        );
    }
}

#[test]
fn approval_rejects_wrong_attempt_id_and_preapproval_finding_project_substitution() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("review");

    assert!(matches!(
        service.approve_attempt(
            "secfix_nonexistent_attempt",
            &review.safety.patch_hash,
            false,
        ),
        Err(SecurityFixError::AttemptNotFound(_))
    ));

    let other_finding = add_overlapping_sql_finding(&fixture, "other-finding");
    fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET finding_id=?2 WHERE id=?1",
            rusqlite::params![prepared.attempt.id, other_finding],
        )
        .expect("preapproval finding substitution");
    assert!(matches!(
        service.approve_attempt(
            &prepared.attempt.id,
            &review.safety.patch_hash,
            false,
        ),
        Err(SecurityFixError::StaleApproval)
    ));

    fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET finding_id=?2 WHERE id=?1",
            rusqlite::params![prepared.attempt.id, fixture.finding_id],
        )
        .expect("restore finding");
    let other_root = tempdir().expect("other project");
    fs::write(other_root.path().join("other.ts"), "export const other = true;\n")
        .expect("other source");
    let other_project = ProjectIndexService::new(&fixture.database)
        .index_project(other_root.path())
        .expect("other project");
    fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET project_id=?2 WHERE id=?1",
            rusqlite::params![prepared.attempt.id, other_project.project_id],
        )
        .expect("preapproval project substitution");
    assert!(matches!(
        service.approve_attempt(
            &prepared.attempt.id,
            &review.safety.patch_hash,
            false,
        ),
        Err(SecurityFixError::StaleApproval)
    ));
}

#[test]
fn approved_attempt_identity_rejects_project_mutation_too() {
    let (fixture, attempt_id, _) = approved_sql_attempt();
    let other_root = tempdir().expect("other project");
    fs::write(other_root.path().join("other.ts"), "export const other = true;\n")
        .expect("other source");
    let other_project = ProjectIndexService::new(&fixture.database)
        .index_project(other_root.path())
        .expect("other project");

    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET project_id=?2 WHERE id=?1",
            rusqlite::params![attempt_id, other_project.project_id],
        )
        .is_err());
}


#[test]
fn patch_safety_rejects_project_root_escape_path() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let displayed = service
        .generate_patch(&prepared.attempt.id)
        .expect("patch");
    let repair_id = prepared.attempt.repair_id.as_deref().expect("repair");
    fixture
        .database
        .connection()
        .execute(
            "UPDATE repair_changes SET relative_path='../outside.ts' WHERE repair_id=?1",
            [repair_id],
        )
        .expect("tamper path");

    let review = service
        .review_attempt(&prepared.attempt.id)
        .expect("review unsafe path");
    assert_eq!(review.safety.classification, PatchSafetyClass::Rejected);
    assert!(review
        .safety
        .rejected_reasons
        .iter()
        .any(|reason| reason.contains("project root")));
    assert!(matches!(
        service.approve_attempt(
            &prepared.attempt.id,
            &displayed.safety.patch_hash,
            false,
        ),
        Err(SecurityFixError::StaleApproval)
    ));
}


#[test]
fn regression_test_plan_uses_recommendation_only_when_no_safe_test_location_is_known() {
    let fixture = sql_fixture();
    let prepared = SecurityFixService::new(&fixture.database)
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    assert_eq!(
        prepared.test_plan.regression_generation_status,
        "RECOMMENDATION_ONLY"
    );
    assert!(prepared
        .test_plan
        .regression_generation_reason
        .contains("No existing test file/framework location"));
    assert!(prepared
        .test_plan
        .targeted
        .iter()
        .all(|item| !item.repository_command_execution_required));
}

#[test]
fn regression_test_plan_selects_relevant_existing_test_without_inventing_new_file() {
    let fixture = sql_fixture();
    let test_path = fixture
        ._root
        .path()
        .join("tests/searchController.test.ts");
    fs::create_dir_all(test_path.parent().expect("test parent")).expect("test dir");
    fs::write(
        &test_path,
        "import { describe, expect, it } from 'vitest';\n\
         describe('search', () => { it('keeps SQL-shaped input as data', () => expect(true).toBe(true)); });\n",
    )
    .expect("test file");
    let discovery = QaDiscoveryService::new(&fixture.database)
        .discover_project(&fixture.project_id)
        .expect("QA discovery");
    assert!(discovery.test_files >= 1);

    let prepared = SecurityFixService::new(&fixture.database)
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    assert_eq!(
        prepared.test_plan.regression_generation_status,
        "EXISTING_TEST_SELECTED"
    );
    assert!(prepared
        .test_plan
        .targeted
        .iter()
        .any(|item| {
            item.repository_command_execution_required
                && item.runner_kind == "vitest"
                && item.targets.iter().any(|target| target.ends_with("tests/searchController.test.ts"))
        }));
}


#[test]
fn applied_retest_floor_cannot_be_lowered_or_rebound() {
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: None,
            status: "unable_to_verify",
            original_confidence: "Likely",
            observed_confidence: None,
            requests_performed: 1,
            detail_json: r#"{"fixture":"pre-apply-floor"}"#,
        })
        .expect("pre-apply retest");
    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    let applied = SecurityFixService::new(&fixture.database)
        .record_application(&attempt_id, &run.id)
        .expect("record application");
    assert!(applied.retest_floor_rowid > 0);

    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET retest_floor_rowid=0 WHERE id=?1",
            [&attempt_id],
        )
        .is_err());
    assert!(fixture
        .database
        .connection()
        .execute(
            "UPDATE security_fix_attempts SET application_run_id=NULL WHERE id=?1",
            [&attempt_id],
        )
        .is_err());
}

#[test]
fn failed_security_approval_rolls_back_underlying_repair_approval_atomically() {
    let fixture = sql_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("review");
    let repair_id = prepared.attempt.repair_id.as_deref().expect("repair");

    fixture
        .database
        .connection()
        .execute_batch(
            "CREATE TRIGGER test_reject_security_fix_approval
             BEFORE UPDATE OF status ON security_fix_attempts
             WHEN NEW.status='approved'
             BEGIN
               SELECT RAISE(ABORT, 'injected approval failure');
             END;",
        )
        .expect("install injected failure");

    assert!(service
        .approve_attempt(
            &prepared.attempt.id,
            &review.safety.patch_hash,
            false,
        )
        .is_err());

    let repair_status: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT status FROM repair_plans WHERE id=?1",
            [repair_id],
            |row| row.get(0),
        )
        .expect("repair status");
    let attempt_status: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT status FROM security_fix_attempts WHERE id=?1",
            [&prepared.attempt.id],
            |row| row.get(0),
        )
        .expect("attempt status");
    assert_eq!(repair_status, "draft");
    assert_eq!(attempt_status, "patch_proposed");
}


#[test]
fn validation_can_retry_after_unable_to_verify_without_skipping_runtime_verification() {
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    let service = SecurityFixService::new(&fixture.database);
    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    service
        .record_application(&attempt_id, &run.id)
        .expect("record application");
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync lifecycle");

    GuidedSecurityStore::new(&fixture.database)
        .record_retest(GuidedRetestInput {
            finding_id: &fixture.finding_id,
            session_id: None,
            status: "unable_to_verify",
            original_confidence: "Likely",
            observed_confidence: None,
            requests_performed: 1,
            detail_json: r#"{"fixture":"unable-before-validation-retry"}"#,
        })
        .expect("persist unable retest");
    let unable = service
        .sync_retest_result(&fixture.finding_id, "unable_to_verify")
        .expect("sync unable")
        .expect("attempt");
    assert_eq!(unable.status, "unable_to_verify");

    service
        .add_validation_result(
            &attempt_id,
            ValidationResultInput {
                command_label: "retry repository validation",
                runner_kind: "fixture",
                targets: &[],
                status: "PASS",
                exit_code: Some(0),
                duration_ms: Some(1),
                classification: "NONE",
                stdout_summary: "pass",
                stderr_summary: "",
            },
        )
        .expect("validation result");
    let retried = service
        .complete_validation(&attempt_id)
        .expect("complete validation retry");
    assert_eq!(retried.status, "verification_pending");
    assert_eq!(
        retried.retest_state, "UNABLE_TO_VERIFY",
        "historical runtime outcome remains visible until a new targeted retest executes"
    );
    assert_ne!(retried.status, "fix_verified");
}


#[test]
fn bookkeeping_failure_recovery_records_rolled_back_application_without_stranding_approval() {
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    let service = SecurityFixService::new(&fixture.database);
    let backups = tempdir().expect("backups");

    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    assert_eq!(run.status, "applied");

    let rolled = RepairApplicationService::new(&fixture.database)
        .rollback_application(&run.id, backups.path())
        .expect("automatic rollback");
    assert_eq!(rolled.status, "rolled_back");

    let recovered = service
        .record_application_recovery_rollback(&attempt_id, &run.id)
        .expect("record recovery rollback");
    assert_eq!(recovered.status, "rolled_back");
    assert_eq!(recovered.application_run_id.as_deref(), Some(run.id.as_str()));
    assert_eq!(recovered.retest_state, "not_executed");

    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync guided lifecycle");
    let lifecycle: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT state FROM guided_security_finding_lifecycle WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("guided lifecycle");
    assert_eq!(lifecycle, "fix_proposed");

    let events = service.events(&attempt_id, 100).expect("events");
    assert!(events
        .iter()
        .any(|event| event.event_type == "application_bookkeeping_rollback"));
}


#[test]
fn failed_fix_preparation_rolls_back_repair_link_lifecycle_and_attempt_atomically() {
    let fixture = sql_fixture();
    fixture
        .database
        .connection()
        .execute_batch(
            "CREATE TRIGGER test_reject_security_fix_prepare
             BEFORE INSERT ON security_fix_attempts
             BEGIN
               SELECT RAISE(ABORT, 'injected prepare failure');
             END;",
        )
        .expect("install prepare failure");

    let service = SecurityFixService::new(&fixture.database);
    assert!(service.prepare_fix(&fixture.finding_id, false).is_err());

    let attempt_count: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM security_fix_attempts WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("attempt count");
    let link_count: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM guided_security_fix_links WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("link count");
    let lifecycle_count: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM guided_security_finding_lifecycle WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("lifecycle count");
    let repair_count: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM repair_plans WHERE project_id=?1",
            [&fixture.project_id],
            |row| row.get(0),
        )
        .expect("repair count");

    assert_eq!(attempt_count, 0);
    assert_eq!(link_count, 0);
    assert_eq!(lifecycle_count, 0);
    assert_eq!(repair_count, 0);
}


#[test]
fn xss_guided_proposal_that_leaves_inner_html_sink_is_rejected() {
    let fixture = xss_fixture();
    let service = SecurityFixService::new(&fixture.database);
    let prepared = service
        .prepare_fix(&fixture.finding_id, false)
        .expect("prepare");
    let source = fs::read_to_string(&fixture.source_path).expect("source");
    let insufficient = source.replace(
        "export function getRender",
        "/* attempted remediation without changing the sink */\nexport function getRender",
    );
    let review = service
        .propose_replacement(
            &prepared.attempt.id,
            &fixture.file_id,
            &insufficient,
        )
        .expect("review");
    assert_eq!(review.safety.classification, PatchSafetyClass::Rejected);
    assert!(review
        .safety
        .rejected_reasons
        .iter()
        .any(|reason| reason.contains("unsafe rendering sink")));
}


#[test]
fn rollback_bookkeeping_can_be_retried_after_files_are_already_restored() {
    let (fixture, attempt_id, repair_id) = approved_sql_attempt();
    let service = SecurityFixService::new(&fixture.database);
    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    service
        .record_application(&attempt_id, &run.id)
        .expect("record application");
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync applied lifecycle");

    let rolled = RepairApplicationService::new(&fixture.database)
        .rollback_application(&run.id, backups.path())
        .expect("rollback files");
    assert_eq!(rolled.status, "rolled_back");

    let first = service
        .record_rollback(&attempt_id, &run.id)
        .expect("record rollback");
    assert_eq!(first.status, "rolled_back");
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("sync rollback");

    let retry = service
        .record_rollback(&attempt_id, &run.id)
        .expect("retry rollback bookkeeping");
    assert_eq!(retry.status, "rolled_back");
    GuidedSecurityStore::new(&fixture.database)
        .sync_repair_application_state(&repair_id)
        .expect("retry guided rollback sync");

    let rollback_events = service
        .events(&attempt_id, 100)
        .expect("events")
        .into_iter()
        .filter(|event| event.event_type == "fix_rolled_back")
        .count();
    assert_eq!(rollback_events, 1, "retry must not duplicate rollback history");

    let lifecycle: String = fixture
        .database
        .connection()
        .query_row(
            "SELECT state FROM guided_security_finding_lifecycle WHERE finding_id=?1",
            [&fixture.finding_id],
            |row| row.get(0),
        )
        .expect("lifecycle");
    assert_eq!(lifecycle, "fix_proposed");
}
