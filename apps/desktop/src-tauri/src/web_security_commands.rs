use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use codetwin_core::{
    AuthorizedWebSecurityStore, Database, GuidedSecurityStore, WebEndpointInput, WebEndpointRecord,
    WebEvidenceInput, WebEvidenceRecord, WebFindingFilter, WebFindingInput, WebFindingRecord,
    WebScanCreate, WebScanRecord,
};
use serde::Deserialize;
use web_security_testing::{
    apply_approved_execution_policy, run_authorized_scan_with_seeds, source_endpoint_seed,
    ApprovedExecutionPolicy, AuthContext, ScanConfig, ScanError, ScanPhase, ScopePolicy,
    SourceEndpointSeed,
};

use crate::{with_database, AppState};

#[derive(Clone, Deserialize)]
pub struct WebScanStartRequest {
    pub website_id: Option<String>,
    pub project_id: Option<String>,
    pub config: ScanConfig,
    #[serde(default)]
    pub primary_auth: AuthContext,
    pub secondary_auth: Option<AuthContext>,
    #[serde(default)]
    pub guided_session_id: Option<String>,
}

pub(crate) fn source_endpoint_seeds_for_project(
    database: &Database,
    project_id: Option<&str>,
    target_url: &str,
) -> Result<Vec<SourceEndpointSeed>, String> {
    let Some(project_id) = project_id else {
        return Ok(Vec::new());
    };
    let routes = AuthorizedWebSecurityStore::new(database)
        .list_source_routes(project_id, 1_000)
        .map_err(|error| error.to_string())?;
    let seeds = routes
        .into_iter()
        .filter_map(|route| {
            source_endpoint_seed(
                target_url,
                &route.http_method,
                &route.path_template,
                &route.parameter_names,
                &route.parameter_locations,
                route.request_content_type.as_deref(),
                &format!(
                    "source_route:{}:{}:{}",
                    route.framework, route.relative_path, route.start_line
                ),
            )
        })
        .collect();
    Ok(seeds)
}

#[tauri::command]
pub fn start_web_security_scan(
    request: WebScanStartRequest,
    state: tauri::State<'_, AppState>,
) -> Result<WebScanRecord, String> {
    ScopePolicy::new(request.config.scope.clone()).map_err(|error| error.to_string())?;

    let scope_json = serde_json::to_string(&request.config.scope).map_err(|error| error.to_string())?;
    let config_json = serde_json::to_string(&request.config).map_err(|error| error.to_string())?;
    let auth_metadata_json = serde_json::to_string(&serde_json::json!({
        "primary": request.primary_auth.metadata(),
        "secondary": request.secondary_auth.as_ref().map(AuthContext::metadata),
    }))
    .map_err(|error| error.to_string())?;

    if let Some(session_id) = request.guided_session_id.as_deref() {
        with_database(&state, |database| {
            GuidedSecurityStore::new(database)
                .assert_execution_allowed(
                    session_id,
                    &request.config.scope.target_url,
                    &config_json,
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
        })?;
    }

    let scan = with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .create_scan(&WebScanCreate {
                website_id: request.website_id.clone(),
                project_id: request.project_id.clone(),
                target_url: request.config.scope.target_url.clone(),
                authorization_confirmed: request.config.scope.authorization_confirmed,
                scope_json,
                config_json,
                auth_metadata_json,
            })
            .map_err(|error| error.to_string())
    })?;

    if let Some(session_id) = request.guided_session_id.as_deref() {
        with_database(&state, |database| {
            GuidedSecurityStore::new(database)
                .link_scan(session_id, &scan.id)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })?;
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut registry = state
            .web_security_cancellations
            .lock()
            .map_err(|_| "web security cancellation registry lock is poisoned".to_string())?;
        registry.insert(scan.id.clone(), Arc::clone(&cancelled));
    }

    let database_path = state.database_path.clone();
    let scan_id = scan.id.clone();
    let registry = Arc::clone(&state.web_security_cancellations);
    tauri::async_runtime::spawn_blocking(move || {
        let result = run_scan_background(
            database_path,
            &scan_id,
            request,
            Arc::clone(&cancelled),
        );
        if let Ok(mut entries) = registry.lock() {
            entries.remove(&scan_id);
        }
        result
    });

    Ok(scan)
}

fn run_scan_background(
    database_path: PathBuf,
    scan_id: &str,
    request: WebScanStartRequest,
    cancelled: Arc<AtomicBool>,
) -> Result<(), String> {
    let database = Database::open(database_path).map_err(|error| error.to_string())?;
    let store = AuthorizedWebSecurityStore::new(&database);
    let guided = GuidedSecurityStore::new(&database);
    let guided_session_id = request.guided_session_id.clone();
    let mut last_guided_phase = String::new();
    let mut execution_config = request.config.clone();

    if let Some(session_id) = guided_session_id.as_deref() {
        let selected_categories = guided
            .selected_plan_categories(session_id)
            .map_err(|error| error.to_string())?;
        let state_changing_selected = guided
            .has_selected_state_changing(session_id)
            .map_err(|error| error.to_string())?;
        execution_config = apply_approved_execution_policy(
            &execution_config,
            &ApprovedExecutionPolicy {
                selected_categories,
                state_changing_selected,
            },
        );
    }

    let source_seeds = source_endpoint_seeds_for_project(
        &database,
        request.project_id.as_deref(),
        &execution_config.scope.target_url,
    )?;

    let outcome = run_authorized_scan_with_seeds(
        &execution_config,
        &request.primary_auth,
        request.secondary_auth.as_ref(),
        &source_seeds,
        Arc::clone(&cancelled),
        |progress| {
            if cancelled.load(Ordering::SeqCst) {
                let _ = store.cancel_scan(scan_id);
                return;
            }
            let phase = if progress.phase == ScanPhase::Completed {
                "correlating"
            } else {
                progress.phase.as_str()
            };
            let _ = store.update_progress(
                scan_id,
                "running",
                phase,
                progress.endpoints_discovered,
                progress.requests_performed,
                progress.findings_observed,
            );
            if let Some(session_id) = guided_session_id.as_deref() {
                if last_guided_phase != phase {
                    last_guided_phase = phase.to_string();
                    let _ = guided.append_activity(
                        session_id,
                        "phase_changed",
                        phase,
                        &format!("Guided security execution entered phase {}.", phase.replace('_', " ")),
                        &serde_json::json!({
                            "endpoints_discovered": progress.endpoints_discovered,
                            "requests_performed": progress.requests_performed,
                            "findings_observed": progress.findings_observed,
                        }).to_string(),
                    );
                }
            }
        },
    );

    match outcome {
        Ok(outcome) => {
            if cancelled.load(Ordering::SeqCst) {
                store.cancel_scan(scan_id).map_err(|error| error.to_string())?;
                return Ok(());
            }

            for endpoint in &outcome.endpoints {
                let persisted_endpoint = store
                    .record_endpoint(
                        scan_id,
                        &WebEndpointInput {
                            url: endpoint.url.clone(),
                            method: endpoint.method.clone(),
                            depth: endpoint.depth,
                            source: endpoint.source.clone(),
                            parameter_names: endpoint.parameter_names.clone(),
                            parameter_locations: endpoint.parameter_locations.clone(),
                            response_header_names: endpoint.response_header_names.clone(),
                            cookie_names: endpoint.cookie_names.clone(),
                            content_type: endpoint.content_type.clone(),
                            status_code: endpoint.status_code,
                            redirect_to: endpoint.redirect_to.clone(),
                        },
                    )
                    .map_err(|error| error.to_string())?;
                store
                    .link_endpoint_to_source_route(
                        request.project_id.as_deref(),
                        &persisted_endpoint,
                    )
                    .map_err(|error| error.to_string())?;
            }

            let mut persisted_findings = 0usize;
            for finding in outcome.findings {
                let source = store
                    .correlate_source_for_request(
                        request.project_id.as_deref(),
                        &finding.endpoint,
                        Some(&finding.method),
                        finding.parameter.as_deref(),
                    )
                    .map_err(|error| error.to_string())?;
                let persisted = store
                    .record_finding(
                        scan_id,
                        &WebFindingInput {
                            fingerprint: finding.stable_fingerprint(),
                            category: finding.category,
                            severity: finding.severity,
                            confidence: finding.confidence,
                            target: finding.target,
                            endpoint_url: finding.endpoint,
                            method: finding.method,
                            parameter_name: finding.parameter,
                            title: finding.title,
                            description: finding.description,
                            reproduction_summary: finding.reproduction_summary,
                            impact: finding.impact,
                            remediation: finding.remediation,
                            references: finding.references,
                            source,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                persisted_findings += 1;
                if let Some(session_id) = guided_session_id.as_deref() {
                    let _ = guided.set_finding_lifecycle(&persisted.id, Some(session_id), "open");
                    let _ = guided.correlate_source_candidates(&persisted.id, 5);
                    let _ = guided.append_activity(
                        session_id,
                        "anomaly_observed",
                        "verification",
                        "Security-relevant behavior was observed and recorded for verification.",
                        &serde_json::json!({
                            "finding_id": &persisted.id,
                            "category": &persisted.category,
                            "endpoint": &persisted.endpoint_url,
                            "method": &persisted.method,
                        }).to_string(),
                    );
                    if matches!(persisted.confidence.as_str(), "Likely" | "Confirmed") {
                        let _ = guided.append_activity(
                            session_id,
                            "verification_performed",
                            "verification",
                            "Control/reproduction evidence supported classification above Potential.",
                            &serde_json::json!({
                                "finding_id": &persisted.id,
                                "confidence": &persisted.confidence,
                            }).to_string(),
                        );
                    }
                    let _ = guided.append_activity(
                        session_id,
                        "finding_classified",
                        "verification",
                        &format!("Finding classified as {} confidence.", persisted.confidence),
                        &serde_json::json!({
                            "finding_id": &persisted.id,
                            "severity": &persisted.severity,
                            "confidence": &persisted.confidence,
                        }).to_string(),
                    );
                }
                for evidence in finding.evidence {
                    store
                        .record_evidence(
                            &persisted.id,
                            &WebEvidenceInput {
                                summary: evidence.summary,
                                request_metadata_json: evidence.request_metadata.to_string(),
                                response_metadata_json: evidence.response_metadata.to_string(),
                            },
                        )
                        .map_err(|error| error.to_string())?;
                }
            }

            store
                .update_progress(
                    scan_id,
                    "completed",
                    "completed",
                    outcome.endpoints.len(),
                    outcome.requests_performed,
                    persisted_findings,
                )
                .map_err(|error| error.to_string())?;
            if let Some(session_id) = guided_session_id.as_deref() {
                guided
                    .update_from_scan(session_id, "completed", "completed", None)
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        Err(ScanError::Cancelled) => {
            store.cancel_scan(scan_id).map_err(|error| error.to_string())?;
            if let Some(session_id) = guided_session_id.as_deref() {
                let _ = guided.update_from_scan(session_id, "cancelled", "cancelled", None);
            }
            Ok(())
        }
        Err(error) => {
            store
                .fail_scan(scan_id, &error.to_string())
                .map_err(|store_error| store_error.to_string())?;
            if let Some(session_id) = guided_session_id.as_deref() {
                let _ = guided.update_from_scan(
                    session_id,
                    "failed",
                    "failed",
                    Some(&error.to_string()),
                );
            }
            Err(error.to_string())
        }
    }
}

#[tauri::command]
pub fn cancel_web_security_scan(
    scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let cancelled = {
        let registry = state
            .web_security_cancellations
            .lock()
            .map_err(|_| "web security cancellation registry lock is poisoned".to_string())?;
        registry.get(&scan_id).cloned()
    };
    if let Some(cancelled) = cancelled {
        cancelled.store(true, Ordering::SeqCst);
        with_database(&state, |database| {
            AuthorizedWebSecurityStore::new(database)
                .cancel_scan(&scan_id)
                .map_err(|error| error.to_string())
        })?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
pub fn get_web_security_scan(
    scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<WebScanRecord>, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .get_scan(&scan_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_web_security_scans(
    website_id: Option<String>,
    project_id: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WebScanRecord>, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .list_scans(website_id.as_deref(), project_id.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_web_security_endpoints(
    scan_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WebEndpointRecord>, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .list_endpoints(&scan_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_web_security_findings(
    scan_id: String,
    filter: WebFindingFilter,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WebFindingRecord>, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .list_findings(&scan_id, &filter, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_web_security_evidence(
    finding_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<WebEvidenceRecord>, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .finding_evidence(&finding_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn update_web_security_finding_status(
    finding_id: String,
    status: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .update_finding_status(&finding_id, &status)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn generate_web_security_report(
    scan_id: String,
    format: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    with_database(&state, |database| {
        AuthorizedWebSecurityStore::new(database)
            .generate_report(&scan_id, &format)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn export_web_security_report(
    scan_id: String,
    format: String,
    path: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let report = generate_web_security_report(scan_id, format.clone(), state)?;
    let destination = PathBuf::from(path);
    let expected_extension = if format.eq_ignore_ascii_case("json") {
        "json"
    } else if format.eq_ignore_ascii_case("markdown") {
        "md"
    } else {
        return Err("report format must be markdown or json".to_string());
    };
    if destination
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| !value.eq_ignore_ascii_case(expected_extension))
    {
        return Err(format!("report path must use .{expected_extension}"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "report destination has no parent directory".to_string())?;
    if !parent.is_dir() {
        return Err("report destination directory does not exist".to_string());
    }
    fs::write(&destination, report).map_err(|error| error.to_string())?;
    Ok(destination.to_string_lossy().to_string())
}
