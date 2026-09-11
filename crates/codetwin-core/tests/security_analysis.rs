use std::fs;

use codetwin_core::{CodeSecurityService, Database, ProjectIndexService};
use tempfile::tempdir;

#[test]
fn appsec_findings_are_persisted_with_redacted_secret_evidence() {
    let root = tempdir().expect("project");
    fs::write(
        root.path().join("app.ts"),
        "const apiKey = \"sk_live_super_secret_value\";\nexport function run(source: string) { return eval(source); }\n",
    )
    .expect("source");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root.path())
        .expect("index");
    let security = CodeSecurityService::new(&database);
    let run = security
        .analyze_project(&index.project_id)
        .expect("security analysis");

    assert!(run.coverage_complete);
    assert_eq!(run.files_analyzed, 1);
    assert!(run.hardcoded_credentials >= 1);
    assert!(run.dynamic_execution >= 1);

    let findings = security
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("findings");
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "security.hardcoded_credential_literal"
            && finding.cwe.as_deref() == Some("CWE-798")));
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "security.dynamic_code_execution"
            && finding.cwe.as_deref() == Some("CWE-95")));

    let hardcoded = findings
        .iter()
        .find(|finding| finding.rule_id == "security.hardcoded_credential_literal")
        .expect("hardcoded finding");
    let evidence = security
        .finding_evidence(&hardcoded.id, 20)
        .expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert!(!evidence[0].summary.contains("sk_live_super_secret_value"));
    assert!(!evidence[0]
        .metadata_json
        .contains("sk_live_super_secret_value"));
    assert!(evidence[0].metadata_json.contains("\"literal_redacted\":true"));
}

#[test]
fn disappeared_security_evidence_resolves_existing_finding_after_reindex() {
    let root = tempdir().expect("project");
    let source = root.path().join("hashing.py");
    fs::write(
        &source,
        "import hashlib\ndef digest(data):\n    return hashlib.sha1(data).hexdigest()\n",
    )
    .expect("source");

    let database = Database::open_in_memory().expect("database");
    let indexer = ProjectIndexService::new(&database);
    let first_index = indexer.index_project(root.path()).expect("first index");
    let security = CodeSecurityService::new(&database);
    let first_run = security
        .analyze_project(&first_index.project_id)
        .expect("first security run");
    assert!(first_run.coverage_complete);
    assert_eq!(first_run.weak_crypto, 1);

    let first_findings = security
        .list_findings(&first_index.project_id, Some("open"), 100)
        .expect("open findings");
    let original_id = first_findings
        .iter()
        .find(|finding| finding.rule_id == "security.weak_cryptographic_hash")
        .expect("weak hash finding")
        .id
        .clone();

    fs::write(
        &source,
        "import hashlib\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n",
    )
    .expect("updated source");
    indexer.index_project(root.path()).expect("second index");
    let second_run = security
        .analyze_project(&first_index.project_id)
        .expect("second security run");
    assert!(second_run.coverage_complete);
    assert_eq!(second_run.weak_crypto, 0);
    assert!(second_run.findings_resolved >= 1);

    let resolved = security
        .list_findings(&first_index.project_id, Some("resolved"), 100)
        .expect("resolved findings");
    assert!(resolved
        .iter()
        .any(|finding| finding.id == original_id && finding.resolved_at.is_some()));
}

#[test]
fn source_changed_after_index_is_stale_and_cannot_create_findings() {
    let root = tempdir().expect("project");
    let source = root.path().join("app.js");
    fs::write(&source, "const value = 1;\n").expect("source");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root.path())
        .expect("index");

    fs::write(
        &source,
        "const clientSecret = \"new_real_secret\";\neval(input);\n",
    )
    .expect("changed without reindex");

    let security = CodeSecurityService::new(&database);
    let run = security
        .analyze_project(&index.project_id)
        .expect("security analysis");
    assert!(!run.coverage_complete);
    assert_eq!(run.files_analyzed, 0);
    assert_eq!(run.files_stale, 1);
    assert_eq!(run.observations, 0);
    assert!(security
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("findings")
        .is_empty());
}

#[test]
fn incomplete_coverage_never_resolves_a_previous_finding() {
    let root = tempdir().expect("project");
    let source = root.path().join("app.js");
    fs::write(&source, "eval(input);\n").expect("source");

    let database = Database::open_in_memory().expect("database");
    let indexer = ProjectIndexService::new(&database);
    let index = indexer.index_project(root.path()).expect("index");
    let security = CodeSecurityService::new(&database);
    let first = security
        .analyze_project(&index.project_id)
        .expect("first security analysis");
    assert!(first.coverage_complete);
    let original = security
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("open findings")
        .into_iter()
        .find(|finding| finding.rule_id == "security.dynamic_code_execution")
        .expect("dynamic finding");

    fs::write(&source, "const clean = true;\n").expect("changed without index");
    let stale = security
        .analyze_project(&index.project_id)
        .expect("stale security analysis");
    assert!(!stale.coverage_complete);
    assert_eq!(stale.findings_resolved, 0);

    let open = security
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("still open");
    assert!(open.iter().any(|finding| finding.id == original.id));
}

#[test]
fn unsafe_c_api_is_review_finding_not_exploit_claim() {
    let root = tempdir().expect("project");
    fs::write(
        root.path().join("copy.c"),
        "#include <string.h>\nvoid copy(char *dst, char *src) { strcpy(dst, src); }\n",
    )
    .expect("source");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(root.path())
        .expect("index");
    let security = CodeSecurityService::new(&database);
    security
        .analyze_project(&index.project_id)
        .expect("security analysis");
    let findings = security
        .list_findings(&index.project_id, Some("open"), 100)
        .expect("findings");
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "security.unsafe_c_string_api")
        .expect("unsafe C API finding");
    assert_eq!(finding.cwe.as_deref(), Some("CWE-120"));
    assert!(finding.description.contains("not proof"));
}
