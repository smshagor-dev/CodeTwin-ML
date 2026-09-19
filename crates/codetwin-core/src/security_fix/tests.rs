use std::fs;

use tempfile::{tempdir, TempDir};

use super::*;
use crate::{
    AuthorizedWebSecurityStore, GuidedRetestInput, GuidedSecurityStore, ProjectIndexService,
    RepairApplicationService, WebEvidenceInput, WebFindingInput, WebScanCreate,
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

    let backups = tempdir().expect("backups");
    let run = RepairApplicationService::new(&fixture.database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    service
        .record_application(&attempt_id, &run.id)
        .expect("record application");
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
