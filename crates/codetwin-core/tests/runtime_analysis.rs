use std::fs;

use codetwin_core::{Database, ProjectIndexService, RuntimeReliabilityService};
use tempfile::tempdir;

#[test]
fn runtime_artifacts_and_review_findings_are_persisted() {
    let root = tempdir().expect("project");
    fs::write(
        root.path().join("Dockerfile"),
        "FROM node:latest\nRUN echo ready\n",
    )
    .expect("dockerfile");
    fs::write(
        root.path().join("compose.yaml"),
        "services:\n  api:\n    image: example/api:1.2.3\n    restart: \"no\"\n    healthcheck:\n      disable: true\n",
    )
    .expect("compose");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = RuntimeReliabilityService::new(&database);
    let run = service
        .analyze_project(&project.id)
        .expect("runtime analysis");

    assert!(run.coverage_complete);
    assert_eq!(run.artifacts_analyzed, 2);
    assert_eq!(run.dockerfiles, 1);
    assert_eq!(run.compose_files, 1);
    assert_eq!(run.mutable_images, 1);
    assert_eq!(run.healthchecks_missing, 1);
    assert_eq!(run.healthchecks_disabled, 1);
    assert_eq!(run.restarts_disabled, 1);

    let artifacts = service
        .list_artifacts(&project.id, true, 20)
        .expect("artifacts");
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts
        .iter()
        .any(|item| item.artifact_kind == "dockerfile"));
    assert!(artifacts
        .iter()
        .any(|item| item.artifact_kind == "docker_compose"));

    let findings = service
        .list_findings(&project.id, Some("open"), 100)
        .expect("findings");
    let mutable = findings
        .iter()
        .find(|item| item.rule_id == "runtime.mutable_container_image")
        .expect("mutable image finding");
    let evidence = service.finding_evidence(&mutable.id, 20).expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert!(evidence[0]
        .metadata_json
        .contains("\"live_runtime_observed\":false"));
    assert!(evidence[0]
        .metadata_json
        .contains("\"source_executed\":false"));
}

#[test]
fn complete_rescan_resolves_disappeared_runtime_finding() {
    let root = tempdir().expect("project");
    let dockerfile = root.path().join("Dockerfile");
    fs::write(
        &dockerfile,
        "FROM node:latest\nHEALTHCHECK CMD node health.js\n",
    )
    .expect("mutable dockerfile");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = RuntimeReliabilityService::new(&database);
    service.analyze_project(&project.id).expect("first run");
    let original = service
        .list_findings(&project.id, Some("open"), 20)
        .expect("open findings")
        .into_iter()
        .find(|item| item.rule_id == "runtime.mutable_container_image")
        .expect("mutable finding");

    fs::write(
        &dockerfile,
        "FROM node@sha256:0123456789abcdef\nHEALTHCHECK CMD node health.js\n",
    )
    .expect("pinned dockerfile");
    let second = service.analyze_project(&project.id).expect("second run");
    assert!(second.coverage_complete);
    assert_eq!(second.mutable_images, 0);
    assert!(second.findings_resolved >= 1);

    let resolved = service
        .list_findings(&project.id, Some("resolved"), 20)
        .expect("resolved findings");
    assert!(resolved
        .iter()
        .any(|item| item.id == original.id && item.resolved_at.is_some()));
}

#[test]
fn incomplete_coverage_does_not_resolve_previous_runtime_finding() {
    let root = tempdir().expect("project");
    let compose = root.path().join("compose.yaml");
    fs::write(
        &compose,
        "services:\n  api:\n    image: example/api:latest\n",
    )
    .expect("compose");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = RuntimeReliabilityService::new(&database);
    service.analyze_project(&project.id).expect("first run");

    fs::write(&compose, vec![b'x'; 2 * 1024 * 1024 + 1]).expect("oversized artifact");
    let second = service.analyze_project(&project.id).expect("second run");
    assert!(!second.coverage_complete);
    assert_eq!(second.artifacts_skipped, 1);
    assert_eq!(second.findings_resolved, 0);

    let open = service
        .list_findings(&project.id, Some("open"), 20)
        .expect("open findings");
    assert!(open
        .iter()
        .any(|item| item.rule_id == "runtime.mutable_container_image"));
}

#[test]
fn deleted_runtime_artifact_becomes_inactive_after_complete_scan() {
    let root = tempdir().expect("project");
    let dockerfile = root.path().join("Dockerfile");
    fs::write(&dockerfile, "FROM alpine:3.20\nHEALTHCHECK CMD true\n").expect("dockerfile");

    let database = Database::open_in_memory().expect("database");
    let project = ProjectIndexService::new(&database)
        .open_project(root.path())
        .expect("project");
    let service = RuntimeReliabilityService::new(&database);
    service.analyze_project(&project.id).expect("first run");
    assert_eq!(
        service
            .list_artifacts(&project.id, true, 20)
            .expect("active")
            .len(),
        1
    );

    fs::remove_file(dockerfile).expect("remove dockerfile");
    let second = service.analyze_project(&project.id).expect("second run");
    assert!(second.coverage_complete);
    assert!(service
        .list_artifacts(&project.id, true, 20)
        .expect("active")
        .is_empty());
    let all = service
        .list_artifacts(&project.id, false, 20)
        .expect("all artifacts");
    assert_eq!(all.len(), 1);
    assert!(!all[0].is_active);
}
