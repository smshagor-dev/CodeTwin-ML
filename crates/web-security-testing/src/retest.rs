use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    active, insert_parameter_location, passive, query_parameters, AuthContext, CheckConfig,
    EndpointObservation, FindingObservation, ParameterLocations, RequestBudget, RequestError,
    ScanConfig, ScanError, ScopePolicy, ScopedRequester,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TargetedRetestRequest {
    pub endpoint_url: String,
    #[serde(default)]
    pub route_template: Option<String>,
    pub method: String,
    #[serde(default)]
    pub parameter_names: Vec<String>,
    #[serde(default, deserialize_with = "crate::deserialize_parameter_locations")]
    pub parameter_locations: ParameterLocations,
    pub parameter_name: Option<String>,
    pub parameter_location: Option<String>,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TargetedRetestOutcome {
    pub requests_performed: usize,
    pub responses_observed: usize,
    pub baseline_status: Option<u16>,
    pub verification_completed: bool,
    pub failure_reason: Option<String>,
    pub findings: Vec<FindingObservation>,
}

pub fn run_targeted_retest(
    config: &ScanConfig,
    primary_auth: &AuthContext,
    secondary_auth: Option<&AuthContext>,
    request: &TargetedRetestRequest,
    cancelled: Arc<AtomicBool>,
) -> Result<TargetedRetestOutcome, ScanError> {
    let mut targeted = config.clone();
    targeted.scope.max_requests = targeted.scope.max_requests.clamp(1, 12);
    targeted.scope.max_crawl_depth = 0;
    targeted.scope.retry_limit = 0;
    targeted.checks = checks_for(&request.category);

    let policy = ScopePolicy::new(targeted.scope.clone())?;
    let url = policy.normalize_and_assert(&request.endpoint_url)?;
    let method = request.method.trim().to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "HEAD" | "POST" | "PUT" | "PATCH") {
        return Ok(TargetedRetestOutcome {
            requests_performed: 0,
            responses_observed: 0,
            baseline_status: None,
            verification_completed: false,
            failure_reason: Some("unsupported HTTP method for targeted retest".into()),
            findings: Vec::new(),
        });
    }
    if !matches!(method.as_str(), "GET" | "HEAD") && !targeted.scope.allow_non_idempotent_methods {
        return Ok(TargetedRetestOutcome {
            requests_performed: 0,
            responses_observed: 0,
            baseline_status: None,
            verification_completed: false,
            failure_reason: Some("state-changing targeted retest is disabled by the approved scope".into()),
            findings: Vec::new(),
        });
    }

    let budget = RequestBudget::new(targeted.scope.max_requests);
    let requester = ScopedRequester::new(
        policy.clone(),
        primary_auth.clone(),
        budget.clone(),
        Arc::clone(&cancelled),
    );

    let mut parameter_names = request.parameter_names.clone();
    parameter_names.extend(query_parameters(&url));
    parameter_names.sort();
    parameter_names.dedup();
    let mut parameter_locations = request.parameter_locations.clone();
    for name in query_parameters(&url) {
        insert_parameter_location(&mut parameter_locations, name, "query");
    }
    if let Some(parameter) = request
        .parameter_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        if !parameter_names.iter().any(|value| value == parameter) {
            parameter_names.push(parameter.to_string());
        }
        if let Some(location) = request
            .parameter_location
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            insert_parameter_location(
                &mut parameter_locations,
                parameter.to_string(),
                location.to_string(),
            );
        } else if !parameter_locations.contains_key(parameter) {
            return Ok(TargetedRetestOutcome {
                requests_performed: 0,
                responses_observed: 0,
                baseline_status: None,
                verification_completed: false,
                failure_reason: Some(format!(
                    "targeted retest requires proven location evidence for parameter {parameter}"
                )),
                findings: Vec::new(),
            });
        }
    }

    let endpoint = EndpointObservation {
        url: url.to_string(),
        route_template: request.route_template.clone(),
        method: method.clone(),
        depth: 0,
        source: if matches!(request.category.as_str(), "api_input_validation" | "api_validation") {
            "openapi".to_string()
        } else {
            "targeted_retest".to_string()
        },
        parameter_names,
        parameter_locations,
        response_header_names: Vec::new(),
        cookie_names: Vec::new(),
        content_type: None,
        status_code: None,
        redirect_to: None,
    };

    let mut baselines = HashMap::new();
    let mut passive_findings = Vec::new();
    let baseline = match active::send_endpoint_baseline(
        &requester,
        &endpoint,
        &url,
        request.parameter_name.as_deref(),
    ) {
        Ok(response) => response,
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(error) => {
            return Ok(TargetedRetestOutcome {
                requests_performed: budget.used(),
                responses_observed: budget.responses_observed(),
                baseline_status: None,
                verification_completed: false,
                failure_reason: Some(format!(
                    "targeted retest baseline request could not be completed safely: {error}"
                )),
                findings: Vec::new(),
            });
        }
    };
    let baseline_status = Some(baseline.status);
    if !(200..400).contains(&baseline.status) {
        let authentication_rejected = matches!(baseline.status, 401 | 403 | 407);
        return Ok(TargetedRetestOutcome {
            requests_performed: budget.used(),
            responses_observed: budget.responses_observed(),
            baseline_status,
            verification_completed: false,
            failure_reason: Some(if authentication_rejected {
                format!(
                    "targeted retest baseline returned HTTP {}; authentication/authorization evidence is insufficient to conclude the vulnerability disappeared",
                    baseline.status
                )
            } else {
                format!(
                    "targeted retest baseline did not return a usable success/redirect response (status: {})",
                    baseline.status
                )
            }),
            findings: Vec::new(),
        });
    }
    if is_passive_retest_category(&request.category) {
        passive_findings.extend(
            passive::analyze_response(&url, &endpoint, &baseline, &targeted.checks)
                .into_iter()
                .filter(|finding| finding.category == request.category),
        );
    }
    baselines.insert(active::baseline_key(&method, &endpoint.url), baseline);

    let mut ignored_progress = |_| {};
    let endpoints = [endpoint];
    let request_seeds = HashMap::new();
    let mut findings = active::run_active_checks(
        active::ActiveCheckContext {
            policy: &policy,
            requester: &requester,
            secondary_auth,
            config: &targeted,
            endpoints: &endpoints,
            baselines: &baselines,
            request_seeds: &request_seeds,
            cancelled,
        },
        &mut ignored_progress,
    )?;
    findings.extend(passive_findings);

    let responses_observed = budget.responses_observed();
    let minimum_responses = minimum_responses_for(&request.category);
    let identity_missing = request.category == "access_control" && secondary_auth.is_none();
    let verification_completed =
        !identity_missing && responses_observed >= minimum_responses;
    let failure_reason = if identity_missing {
        Some("targeted authorization verification requires the approved secondary test identity".into())
    } else if verification_completed {
        None
    } else {
        Some(format!(
            "targeted retest observed only {responses_observed} successful response(s); at least {minimum_responses} are required for this detector family"
        ))
    };

    Ok(TargetedRetestOutcome {
        requests_performed: budget.used(),
        responses_observed,
        baseline_status,
        verification_completed,
        failure_reason,
        findings,
    })
}

fn minimum_responses_for(category: &str) -> usize {
    match category {
        "sql_injection" => 4,
        "csp" | "hsts" | "security_headers" | "session_cookie" | "sensitive_cache_control" => 1,
        "xss"
        | "open_redirect"
        | "path_traversal"
        | "ssrf"
        | "template_injection"
        | "cors"
        | "http_method"
        | "access_control"
        | "api_input_validation"
        | "api_validation" => 2,
        _ => 2,
    }
}

fn is_passive_retest_category(category: &str) -> bool {
    matches!(
        category,
        "csp" | "hsts" | "security_headers" | "session_cookie" | "sensitive_cache_control"
    )
}

fn checks_for(category: &str) -> CheckConfig {
    let mut checks = CheckConfig {
        sql_injection: false,
        xss: false,
        csrf: false,
        open_redirect: false,
        path_traversal: false,
        ssrf_indicators: false,
        template_command_indicators: false,
        method_misconfiguration: false,
        cors: false,
        session: false,
        access_control: false,
        api_validation: false,
    };
    match category {
        "sql_injection" => checks.sql_injection = true,
        "xss" => checks.xss = true,
        "open_redirect" => checks.open_redirect = true,
        "path_traversal" => checks.path_traversal = true,
        "ssrf" => checks.ssrf_indicators = true,
        "template_injection" => checks.template_command_indicators = true,
        "cors" => checks.cors = true,
        "session_cookie" | "sensitive_cache_control" => checks.session = true,
        "http_method" => checks.method_misconfiguration = true,
        "access_control" => checks.access_control = true,
        "api_input_validation" | "api_validation" => checks.api_validation = true,
        _ => {}
    }
    checks
}

fn normalized_key(url: &Url) -> String {
    let mut value = url.clone();
    value.set_fragment(None);
    value.to_string()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{atomic::AtomicBool, Arc},
    };

    use super::{checks_for, run_targeted_retest, TargetedRetestRequest};
    use crate::{AuthContext, CheckConfig, ScanConfig, ScopeConfig};

    #[test]
    fn targeted_retest_refuses_to_guess_missing_parameter_location() {
        let config = ScanConfig {
            scope: ScopeConfig {
                target_url: "http://127.0.0.1:9/".into(),
                allowed_hostnames: vec!["127.0.0.1".into()],
                allowed_subdomains: Vec::new(),
                allowed_paths: vec!["/".into()],
                excluded_paths: Vec::new(),
                max_crawl_depth: 0,
                max_requests: 12,
                concurrency: 1,
                timeout_ms: 500,
                response_limit_bytes: 16_384,
                redirect_limit: 0,
                retry_limit: 0,
                active_testing: true,
                allow_non_idempotent_methods: true,
                allow_private_networks: true,
                enable_timing_probes: false,
                authorization_confirmed: true,
            },
            checks: CheckConfig::default(),
        };
        let outcome = run_targeted_retest(
            &config,
            &AuthContext::default(),
            None,
            &TargetedRetestRequest {
                endpoint_url: "http://127.0.0.1:9/update".into(),
                route_template: None,
                method: "POST".into(),
                parameter_names: vec!["email".into()],
                parameter_locations: BTreeMap::new(),
                parameter_name: Some("email".into()),
                parameter_location: None,
                category: "xss".into(),
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("fail-closed retest outcome");

        assert_eq!(outcome.requests_performed, 0);
        assert_eq!(outcome.responses_observed, 0);
        assert!(!outcome.verification_completed);
        assert!(outcome
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("proven location evidence")));
    }

    #[test]
    fn detector_families_require_enough_observed_responses() {
        assert_eq!(super::minimum_responses_for("sql_injection"), 4);
        assert_eq!(super::minimum_responses_for("xss"), 2);
        assert_eq!(super::minimum_responses_for("access_control"), 2);
        assert_eq!(super::minimum_responses_for("security_headers"), 1);
        assert_eq!(super::minimum_responses_for("csp"), 1);
    }

    #[test]
    fn passive_header_families_use_bounded_baseline_retest() {
        assert!(super::is_passive_retest_category("security_headers"));
        assert!(super::is_passive_retest_category("csp"));
        assert!(super::is_passive_retest_category("hsts"));
        assert!(!super::is_passive_retest_category("sql_injection"));
    }

    #[test]
    fn targeted_retest_enables_only_requested_detector_family() {
        let checks = checks_for("xss");
        assert!(checks.xss);
        assert!(!checks.sql_injection);
        assert!(!checks.access_control);
        assert!(!checks.api_validation);
    }
}
