//! Headless end-to-end smoke: index a real repository and run every
//! deterministic analyzer against it, reporting timings and failures.
//!
//! Usage: cargo run --release -p codetwin-core --example e2e_smoke -- <repo> [<db>]
//!
//! Exits non-zero if any stage fails, so it can gate a release.

use std::{path::PathBuf, time::Instant};

use codetwin_core::{
    AdvisorySource, AuthorizedWebSecurityStore, CodeQualityService, CodeSecurityService, Database,
    DatabaseAnalysisService, DependencyAuditService, ImpactAnalysisService, ProjectIndexService,
    ProjectQueryService, QaDiscoveryService, RuntimeReliabilityService, SecretScanningService,
    SymbolReferenceService,
};

fn stage<T: std::fmt::Debug, E: std::fmt::Display>(
    failures: &mut Vec<String>,
    name: &str,
    run: impl FnOnce() -> Result<T, E>,
) -> Option<T> {
    let started = Instant::now();
    let result = run();
    let elapsed = started.elapsed();
    match result {
        Ok(value) => {
            let summary = format!("{value:?}");
            let summary: String = summary.chars().take(220).collect();
            println!("ok    {name:<20} {:>8.2?}  {summary}", elapsed);
            Some(value)
        }
        Err(error) => {
            println!("FAIL  {name:<20} {:>8.2?}  {error}", elapsed);
            failures.push(format!("{name}: {error}"));
            None
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let repo = PathBuf::from(args.next().expect("usage: e2e_smoke <repo> [<db>]"));
    let database = match args.next() {
        Some(path) => {
            let path = PathBuf::from(path);
            let _ = std::fs::remove_file(&path);
            Database::open(path).expect("open database")
        }
        None => Database::open_in_memory().expect("open database"),
    };

    let mut failures = Vec::new();
    let Some(index) = stage(&mut failures, "index", || {
        ProjectIndexService::new(&database).index_project(&repo)
    }) else {
        std::process::exit(1);
    };
    let project_id = index.project_id.clone();

    stage(&mut failures, "reindex (no-op)", || {
        ProjectIndexService::new(&database).index_project(&repo)
    });
    stage(&mut failures, "references", || {
        SymbolReferenceService::new(&database).refresh_project(&project_id)
    });
    stage(&mut failures, "graph", || {
        ProjectQueryService::new(&database).graph_summary(&project_id)
    });
    stage(&mut failures, "quality", || {
        CodeQualityService::new(&database).analyze_project(&project_id)
    });
    stage(&mut failures, "appsec", || {
        CodeSecurityService::new(&database).analyze_project(&project_id)
    });
    stage(&mut failures, "database", || {
        DatabaseAnalysisService::new(&database).analyze_project(&project_id)
    });
    stage(&mut failures, "runtime", || {
        RuntimeReliabilityService::new(&database).analyze_project(&project_id)
    });
    stage(&mut failures, "qa discovery", || {
        QaDiscoveryService::new(&database).discover_project(&project_id)
    });
    stage(&mut failures, "secret scan", || {
        SecretScanningService::new(&database)
            .scan_project(&project_id)
            .map(|summary| {
                (
                    summary.files_scanned,
                    summary.observations,
                    summary.coverage_complete,
                )
            })
    });
    // Offline mode with an empty advisory directory: exercises lockfile inventory
    // without network access.
    let advisories = std::env::temp_dir().join("codetwin-e2e-empty-osv");
    let _ = std::fs::create_dir_all(&advisories);
    stage(&mut failures, "dependency audit", || {
        DependencyAuditService::new(&database)
            .audit_project(
                &project_id,
                &AdvisorySource::OfflineDirectory {
                    path: advisories.clone(),
                },
            )
            .map(|summary| (summary.manifests, summary.packages, summary.manifest_errors))
    });
    stage(&mut failures, "source routes", || {
        AuthorizedWebSecurityStore::new(&database)
            .list_source_routes(&project_id, 1_000)
            .map(|routes| routes.len())
    });
    if let Some(files) = stage(&mut failures, "list files", || {
        ProjectQueryService::new(&database).list_files(&project_id, None, 1_000)
    }) {
        if let Some(file) = files.first() {
            stage(&mut failures, "impact", || {
                ImpactAnalysisService::new(&database)
                    .analyze_file(&file.id, 4, 200)
                    .map(|report| report.map(|report| report.affected_files.len()))
            });
        }
    }

    if failures.is_empty() {
        println!("\nall stages passed");
    } else {
        println!("\n{} stage(s) failed", failures.len());
        std::process::exit(1);
    }
}
