use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use codetwin_core::{
    AuthorizedWebSecurityStore, Database, WebEndpointInput, WebEndpointRecord, WebEvidenceInput,
    WebEvidenceRecord, WebFindingFilter, WebFindingInput, WebFindingRecord, WebScanCreate,
    WebScanRecord,
};
use serde::Deserialize;
use web_security_testing::{
    run_authorized_scan, AuthContext, ScanConfig, ScanError, ScanPhase, ScopePolicy,
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

    let outcome = run_authorized_scan(
        &request.config,
        &request.primary_auth,
        request.secondary_auth.as_ref(),
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
        },
    );

    match outcome {
        Ok(outcome) => {
            if cancelled.load(Ordering::SeqCst) {
                store.cancel_scan(scan_id).map_err(|error| error.to_string())?;
                return Ok(());
            }

            for endpoint in &outcome.endpoints {
                store
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
            }

            let mut persisted_findings = 0usize;
            for finding in outcome.findings {
                let source = store
                    .correlate_source(
                        request.project_id.as_deref(),
                        &finding.endpoint,
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
            Ok(())
        }
        Err(ScanError::Cancelled) => {
            store.cancel_scan(scan_id).map_err(|error| error.to_string())?;
            Ok(())
        }
        Err(error) => {
            store
                .fail_scan(scan_id, &error.to_string())
                .map_err(|store_error| store_error.to_string())?;
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
