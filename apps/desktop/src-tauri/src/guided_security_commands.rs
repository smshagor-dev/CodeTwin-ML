use std::collections::BTreeMap;
use std::sync::{atomic::AtomicBool, Arc};

use codetwin_core::{
    AuthorizedWebSecurityStore, Database, GuidedActivityRecord, GuidedFixPreparation,
    GuidedPlanItemInput, GuidedPlanItemRecord,
    GuidedRetestRecord, GuidedRiskGraph, GuidedScanComparison, GuidedSecurityScorecard,
    GuidedSecuritySessionRecord, GuidedSecurityStore, GuidedSessionCreate, GuidedSourceCandidate,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use web_security_testing::{
    prepare_guided_security, run_targeted_retest, ApplicationSourceHint, AuthContext, ScanConfig,
    SecurityEnvironment, TargetedRetestRequest,
};

use crate::{with_database, AppState};

#[derive(Clone, Deserialize)]
pub struct GuidedSecurityPrepareRequest {
    pub website_id: Option<String>,
    pub project_id: Option<String>,
    pub environment: String,
    pub testing_depth: String,
    pub auth_mode: String,
    pub config: ScanConfig,
    #[serde(default)]
    pub primary_auth: AuthContext,
    pub secondary_auth: Option<AuthContext>,
}

#[derive(Clone, Deserialize)]
pub struct GuidedRetestRequest {
    pub finding_id: String,
    #[serde(default)]
    pub primary_auth: AuthContext,
    pub secondary_auth: Option<AuthContext>,
}

#[tauri::command]
pub async fn prepare_guided_security_test(
    request: GuidedSecurityPrepareRequest,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedSecuritySessionRecord, String> {
    validate_auth_mode(
        &request.auth_mode,
        &request.primary_auth,
        request.secondary_auth.as_ref(),
    )?;
    validate_environment_policy(&request.environment, &request.config)?;
    let config_json = serde_json::to_string(&request.config).map_err(|error| error.to_string())?;
    let session = with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .create_session(&GuidedSessionCreate {
                website_id: request.website_id.clone(),
                project_id: request.project_id.clone(),
                target_url: request.config.scope.target_url.clone(),
                environment: request.environment.clone(),
                testing_depth: request.testing_depth.clone(),
                auth_mode: request.auth_mode.clone(),
                authorization_confirmed: request.config.scope.authorization_confirmed,
                config_json: config_json.clone(),
            })
            .map_err(|error| error.to_string())
    })?;

    let database_path = state.database_path.clone();
    let session_id = session.id.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(database_path).map_err(|error| error.to_string())?;
        let store = GuidedSecurityStore::new(&database);
        let environment = parse_environment(&request.environment)?;
        let prepared = prepare_guided_security(
            &request.config,
            &request.primary_auth,
            request.secondary_auth.as_ref(),
            environment,
            Arc::new(AtomicBool::new(false)),
        );
        match prepared {
            Ok(mut prepared) => {
                if let Some(project_id) = request.project_id.as_deref() {
                    let source_store = AuthorizedWebSecurityStore::new(&database);
                    let mut correlated = 0usize;
                    'groups: for group in &mut prepared.application_map.groups {
                        for route in &mut group.routes {
                            if correlated >= 500 {
                                break 'groups;
                            }
                            correlated += 1;
                            if let Ok(Some(source)) = source_store.correlate_source(
                                Some(project_id),
                                &route.url,
                                route.parameters.first().map(String::as_str),
                            ) {
                                if source.confidence >= 0.50 {
                                    route.source_hints.push(ApplicationSourceHint {
                                        relative_path: source.relative_path,
                                        symbol_name: source.symbol_name,
                                        confidence: source.confidence,
                                    });
                                }
                            }
                        }
                    }
                }
                let preflight_json =
                    serde_json::to_string(&prepared.preflight).map_err(|error| error.to_string())?;
                let map_json = serde_json::to_string(&prepared.application_map)
                    .map_err(|error| error.to_string())?;
                let plan_json =
                    serde_json::to_string(&prepared.plan).map_err(|error| error.to_string())?;
                let plan_items: Vec<GuidedPlanItemInput> = prepared
                    .plan
                    .operations
                    .iter()
                    .map(|item| GuidedPlanItemInput {
                        operation_key: item.operation_key.clone(),
                        endpoint_url: item.endpoint_url.clone(),
                        method: item.method.clone(),
                        parameter_name: item.parameter_name.clone(),
                        category: item.category.clone(),
                        risk: match item.risk {
                            web_security_testing::OperationRisk::SAFE => "SAFE",
                            web_security_testing::OperationRisk::CAUTION => "CAUTION",
                            web_security_testing::OperationRisk::RESTRICTED => "RESTRICTED",
                        }
                        .to_string(),
                        selected: item.selected,
                        reason: item.reason.clone(),
                        skip_reason: item.skip_reason.clone(),
                    })
                    .collect();
                store
                    .complete_preparation(
                        &session_id,
                        &preflight_json,
                        &map_json,
                        &plan_json,
                        prepared.mapping_requests,
                        &plan_items,
                    )
                    .map_err(|error| error.to_string())
            }
            Err(error) => {
                let message = error.to_string();
                let _ = store.fail_preparation(&session_id, &message);
                Err(message)
            }
        }
    })
    .await
    .map_err(|error| error.to_string())?;
    task
}

#[tauri::command]
pub fn approve_guided_security_plan(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedSecuritySessionRecord, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .approve_session(&session_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn get_guided_security_session(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Option<GuidedSecuritySessionRecord>, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .get_session(&session_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_guided_security_sessions(
    project_id: Option<String>,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuidedSecuritySessionRecord>, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .list_sessions(project_id.as_deref(), limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_guided_security_plan_items(
    session_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuidedPlanItemRecord>, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .list_plan_items(&session_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn list_guided_security_activity(
    session_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuidedActivityRecord>, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .list_activity(&session_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn correlate_guided_security_sources(
    finding_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuidedSourceCandidate>, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .correlate_source_candidates(&finding_id, limit)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn guided_security_scorecard(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedSecurityScorecard, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .scorecard(&session_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn guided_security_risk_graph(
    session_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedRiskGraph, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .risk_graph(&session_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn compare_guided_security_scans(
    session_id: Option<String>,
    previous_scan_id: String,
    current_scan_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedScanComparison, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .compare_scans(
                session_id.as_deref(),
                &previous_scan_id,
                &current_scan_id,
            )
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn prepare_guided_security_fix(
    finding_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedFixPreparation, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .prepare_fix(&finding_id)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub fn update_guided_finding_lifecycle(
    finding_id: String,
    session_id: Option<String>,
    lifecycle: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .set_finding_lifecycle(&finding_id, session_id.as_deref(), &lifecycle)
            .map_err(|error| error.to_string())
    })
}

#[tauri::command]
pub async fn retest_guided_security_finding(
    request: GuidedRetestRequest,
    state: tauri::State<'_, AppState>,
) -> Result<GuidedRetestRecord, String> {
    let database_path = state.database_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let database = Database::open(database_path).map_err(|error| error.to_string())?;
        let context = database
            .connection()
            .query_row(
                "SELECT wf.scan_id, wf.category, wf.confidence, wf.endpoint_url, wf.method,
                        wf.parameter_name, ws.config_json, gs.id
                 FROM web_security_findings wf
                 JOIN web_security_scans ws ON ws.id=wf.scan_id
                 LEFT JOIN guided_security_sessions gs ON gs.scan_id=wf.scan_id
                 WHERE wf.id=?1",
                [&request.finding_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "web security finding not found".to_string())?;

        let (scan_id, category, original_confidence, endpoint_url, method, parameter_name, config_json, session_id) =
            context;
        let config: ScanConfig =
            serde_json::from_str(&config_json).map_err(|error| error.to_string())?;
        let parameter_location = if let Some(parameter) = parameter_name.as_deref() {
            database
                .connection()
                .query_row(
                    "SELECT parameter_locations_json
                     FROM web_security_endpoints
                     WHERE scan_id=?1 AND method=?2 AND url=?3 LIMIT 1",
                    params![scan_id, method, endpoint_url],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .and_then(|raw| serde_json::from_str::<BTreeMap<String, String>>(&raw).ok())
                .and_then(|values| values.get(parameter).cloned())
        } else {
            None
        };
        let retest_request = TargetedRetestRequest {
            endpoint_url,
            method,
            parameter_name,
            parameter_location,
            category: category.clone(),
        };
        let store = GuidedSecurityStore::new(&database);
        match run_targeted_retest(
            &config,
            &request.primary_auth,
            request.secondary_auth.as_ref(),
            &retest_request,
            Arc::new(AtomicBool::new(false)),
        ) {
            Ok(outcome) => {
                let matching: Vec<_> = outcome
                    .findings
                    .iter()
                    .filter(|finding| same_category(&category, &finding.category))
                    .collect();
                let observed_confidence = matching
                    .iter()
                    .map(|finding| finding.confidence.as_str())
                    .max_by_key(|confidence| confidence_rank(confidence))
                    .map(str::to_string);
                let status = if outcome.requests_performed == 0 {
                    "unable_to_verify"
                } else if matching.is_empty() {
                    "retest_passed"
                } else {
                    "still_vulnerable"
                };
                let detail = serde_json::json!({
                    "category": category,
                    "endpoint": retest_request.endpoint_url,
                    "finding_titles": matching.iter().map(|finding| finding.title.clone()).collect::<Vec<_>>(),
                    "evidence_count": matching.iter().map(|finding| finding.evidence.len()).sum::<usize>(),
                    "note": "Targeted retest used the minimum bounded detector family for this finding; authentication secrets were not persisted."
                })
                .to_string();
                store
                    .record_retest(
                        &request.finding_id,
                        session_id.as_deref(),
                        status,
                        &original_confidence,
                        observed_confidence.as_deref(),
                        outcome.requests_performed,
                        &detail,
                    )
                    .map_err(|error| error.to_string())
            }
            Err(error) => {
                let detail = serde_json::json!({
                    "error": error.to_string(),
                    "note": "Retest failed safely; CodeTwin did not increase request budget or testing aggression."
                })
                .to_string();
                store
                    .record_retest(
                        &request.finding_id,
                        session_id.as_deref(),
                        "unable_to_verify",
                        &original_confidence,
                        None,
                        0,
                        &detail,
                    )
                    .map_err(|store_error| store_error.to_string())
            }
        }
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn list_guided_security_retests(
    finding_id: String,
    limit: usize,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuidedRetestRecord>, String> {
    with_database(&state, |database| {
        GuidedSecurityStore::new(database)
            .list_retests(&finding_id, limit)
            .map_err(|error| error.to_string())
    })
}

fn validate_environment_policy(
    environment: &str,
    config: &ScanConfig,
) -> Result<(), String> {
    if environment != "authorized_production" {
        return Ok(());
    }
    if config.scope.allow_non_idempotent_methods {
        return Err(
            "authorized production Developer Mode cannot enable state-changing active probes"
                .to_string(),
        );
    }
    if config.scope.enable_timing_probes {
        return Err(
            "authorized production Developer Mode cannot enable timing probes".to_string(),
        );
    }
    if config.scope.max_requests > 350 {
        return Err(
            "authorized production Developer Mode is capped at 350 requests".to_string(),
        );
    }
    if config.scope.concurrency > 2 {
        return Err(
            "authorized production Developer Mode is capped at concurrency 2".to_string(),
        );
    }
    Ok(())
}

fn validate_auth_mode(
    mode: &str,
    primary: &AuthContext,
    secondary: Option<&AuthContext>,
) -> Result<(), String> {
    match mode {
        "none" => Ok(()),
        "existing_session" | "test_account_a" if auth_present(primary) => Ok(()),
        "test_accounts_a_b"
            if auth_present(primary) && secondary.is_some_and(auth_present) =>
        {
            Ok(())
        }
        "existing_session" => Err(
            "Existing session mode requires a cookie, bearer token, or custom authentication header."
                .to_string(),
        ),
        "test_account_a" => Err(
            "Test account A mode requires an authenticated test session.".to_string(),
        ),
        "test_accounts_a_b" => Err(
            "Authorization comparison requires authenticated test sessions for both account A and account B."
                .to_string(),
        ),
        _ => Err("unsupported guided security authentication mode".to_string()),
    }
}

fn auth_present(auth: &AuthContext) -> bool {
    auth.cookie_header
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty())
        || auth
            .bearer_token
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty())
        || !auth.custom_headers.is_empty()
}

fn parse_environment(value: &str) -> Result<SecurityEnvironment, String> {
    match value {
        "local" => Ok(SecurityEnvironment::Local),
        "development" => Ok(SecurityEnvironment::Development),
        "staging" => Ok(SecurityEnvironment::Staging),
        "authorized_production" => Ok(SecurityEnvironment::AuthorizedProduction),
        _ => Err("unsupported guided security environment".to_string()),
    }
}

fn same_category(expected: &str, observed: &str) -> bool {
    expected == observed
        || matches!(
            (expected, observed),
            ("api_input_validation", "api_validation") | ("api_validation", "api_input_validation")
        )
}

fn confidence_rank(value: &str) -> u8 {
    match value {
        "Confirmed" => 3,
        "Likely" => 2,
        "Potential" => 1,
        _ => 0,
    }
}
