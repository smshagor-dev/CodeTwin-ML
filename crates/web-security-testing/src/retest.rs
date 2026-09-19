use std::collections::{BTreeMap, HashMap};
use std::sync::{atomic::AtomicBool, Arc};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    active, query_parameters, AuthContext, CheckConfig, EndpointObservation, FindingObservation,
    RequestBudget, ScanConfig, ScanError, ScopePolicy, ScopedRequester,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TargetedRetestRequest {
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub parameter_location: Option<String>,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TargetedRetestOutcome {
    pub requests_performed: usize,
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
            findings: Vec::new(),
        });
    }
    if !matches!(method.as_str(), "GET" | "HEAD") && !targeted.scope.allow_non_idempotent_methods {
        return Ok(TargetedRetestOutcome {
            requests_performed: 0,
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

    let mut parameter_names = query_parameters(&url);
    let mut parameter_locations = BTreeMap::new();
    for name in &parameter_names {
        parameter_locations.insert(name.clone(), "query".to_string());
    }
    if let Some(parameter) = request
        .parameter_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        if !parameter_names.iter().any(|value| value == parameter) {
            parameter_names.push(parameter.to_string());
        }
        parameter_locations.insert(
            parameter.to_string(),
            request
                .parameter_location
                .clone()
                .unwrap_or_else(|| if method == "GET" { "query".to_string() } else { "form".to_string() }),
        );
    }

    let endpoint = EndpointObservation {
        url: url.to_string(),
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
    if method == "GET" {
        if let Ok(response) = requester.get(&url) {
            baselines.insert(normalized_key(&url), response);
        }
    }

    let mut ignored_progress = |_| {};
    let endpoints = [endpoint];
    let findings = active::run_active_checks(
        active::ActiveCheckContext {
            policy: &policy,
            requester: &requester,
            secondary_auth,
            config: &targeted,
            endpoints: &endpoints,
            baselines: &baselines,
            cancelled,
        },
        &mut ignored_progress,
    )?;

    Ok(TargetedRetestOutcome {
        requests_performed: budget.used(),
        findings,
    })
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
    use super::checks_for;

    #[test]
    fn targeted_retest_enables_only_requested_detector_family() {
        let checks = checks_for("xss");
        assert!(checks.xss);
        assert!(!checks.sql_injection);
        assert!(!checks.access_control);
        assert!(!checks.api_validation);
    }
}
