use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{atomic::AtomicBool, Arc};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    fingerprint, run_authorized_scan_with_seeds, single_parameter_location, AuthContext,
    EndpointObservation, FindingObservation, ParameterLocations, ScanConfig, ScanError,
    ScopePolicy, SourceEndpointSeed,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEnvironment {
    Local,
    Development,
    Staging,
    AuthorizedProduction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestingDepth {
    Quick,
    Standard,
    Deep,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMode {
    None,
    ExistingSession,
    TestAccountA,
    TestAccountsAB,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationRisk {
    SAFE,
    CAUTION,
    RESTRICTED,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedPreflight {
    pub authorized_target: String,
    pub resolved_address: String,
    pub ip_classification: String,
    pub allowed_hostnames: Vec<String>,
    pub allowed_subdomains: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub port: u16,
    pub https_behavior: String,
    pub redirect_limit: usize,
    pub max_requests: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub authentication_available: bool,
    pub destructive_actions: bool,
    pub state_changing_testing: bool,
    pub timing_probes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationSourceHint {
    pub relative_path: String,
    pub symbol_name: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationRoute {
    pub url: String,
    pub method: String,
    pub source: String,
    pub parameters: Vec<String>,
    pub parameter_locations: ParameterLocations,
    pub content_type: Option<String>,
    pub status_code: Option<u16>,
    pub cookies: Vec<String>,
    pub authentication_boundary: bool,
    #[serde(default)]
    pub source_hints: Vec<ApplicationSourceHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationGroup {
    pub label: String,
    pub routes: Vec<ApplicationRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationMap {
    pub groups: Vec<ApplicationGroup>,
    pub endpoint_count: usize,
    pub page_count: usize,
    pub form_count: usize,
    pub api_endpoint_count: usize,
    pub parameter_count: usize,
    pub authenticated_endpoint_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlannedOperation {
    pub operation_key: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub category: String,
    pub risk: OperationRisk,
    pub selected: bool,
    pub reason: String,
    pub skip_reason: Option<String>,
}

#[derive(Debug)]
struct OperationSpec<'a> {
    endpoint: &'a EndpointObservation,
    parameter_name: Option<&'a str>,
    category: &'a str,
    risk: OperationRisk,
    selected: bool,
    reason: &'a str,
    skip_reason: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedExecutionPolicy {
    pub selected_categories: BTreeSet<String>,
    pub state_changing_selected: bool,
}

pub fn apply_approved_execution_policy(
    config: &ScanConfig,
    policy: &ApprovedExecutionPolicy,
) -> ScanConfig {
    let mut constrained = config.clone();
    let selected = &policy.selected_categories;

    constrained.checks.sql_injection &= selected.contains("sql_injection");
    constrained.checks.xss &= selected.contains("xss");
    constrained.checks.csrf &= selected.contains("csrf");
    constrained.checks.open_redirect &= selected.contains("open_redirect");
    constrained.checks.path_traversal &= selected.contains("path_traversal");
    constrained.checks.ssrf_indicators &= selected.contains("ssrf");
    constrained.checks.template_command_indicators &= selected.contains("template_injection");
    constrained.checks.api_validation &= selected.contains("api_validation");
    constrained.checks.access_control &= selected.contains("access_control");

    let http_policy = selected.contains("http_policy");
    constrained.checks.cors &= http_policy;
    constrained.checks.method_misconfiguration &= http_policy;
    constrained.scope.enable_timing_probes = false;
    constrained.scope.allow_non_idempotent_methods &= policy.state_changing_selected;
    constrained
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedTestPlan {
    pub endpoint_count: usize,
    pub form_count: usize,
    pub parameter_count: usize,
    pub selected_count: usize,
    pub skipped_count: usize,
    pub counts_by_category: BTreeMap<String, usize>,
    pub counts_by_risk: BTreeMap<String, usize>,
    pub operations: Vec<PlannedOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedPreparation {
    pub preflight: GuidedPreflight,
    pub application_map: ApplicationMap,
    pub plan: GuidedTestPlan,
    pub passive_findings: Vec<FindingObservation>,
    pub mapping_requests: usize,
}

pub fn preflight(
    config: &ScanConfig,
    authentication_available: bool,
) -> Result<GuidedPreflight, ScanError> {
    let policy = ScopePolicy::new(config.scope.clone())?;
    let pinned = policy.resolve_and_pin(policy.target())?;
    let port =
        policy
            .target()
            .port_or_known_default()
            .unwrap_or(if policy.target().scheme() == "https" {
                443
            } else {
                80
            });
    Ok(GuidedPreflight {
        authorized_target: policy.target().to_string(),
        resolved_address: pinned.ip().to_string(),
        ip_classification: classify_ip(pinned.ip()).to_string(),
        allowed_hostnames: policy.config().allowed_hostnames.clone(),
        allowed_subdomains: policy.config().allowed_subdomains.clone(),
        allowed_paths: policy.config().allowed_paths.clone(),
        excluded_paths: policy.config().excluded_paths.clone(),
        port,
        https_behavior: if policy.target().scheme() == "https" {
            "HTTPS required; redirects may not downgrade to HTTP.".to_string()
        } else {
            "HTTP target explicitly configured; HTTPS downgrade protection is not applicable."
                .to_string()
        },
        redirect_limit: policy.config().redirect_limit,
        max_requests: policy.config().max_requests,
        concurrency: policy.config().concurrency,
        timeout_ms: policy.config().timeout_ms,
        authentication_available,
        destructive_actions: false,
        state_changing_testing: policy.config().allow_non_idempotent_methods,
        timing_probes: policy.config().enable_timing_probes,
    })
}

pub fn prepare_guided_security(
    config: &ScanConfig,
    primary_auth: &AuthContext,
    secondary_auth: Option<&AuthContext>,
    environment: SecurityEnvironment,
    cancelled: Arc<AtomicBool>,
) -> Result<GuidedPreparation, ScanError> {
    prepare_guided_security_with_seeds(
        config,
        primary_auth,
        secondary_auth,
        &[],
        environment,
        cancelled,
    )
}

pub fn prepare_guided_security_with_seeds(
    config: &ScanConfig,
    primary_auth: &AuthContext,
    secondary_auth: Option<&AuthContext>,
    source_seeds: &[SourceEndpointSeed],
    environment: SecurityEnvironment,
    cancelled: Arc<AtomicBool>,
) -> Result<GuidedPreparation, ScanError> {
    let authentication_available = has_auth(primary_auth) || secondary_auth.is_some_and(has_auth);
    let preflight = preflight(config, authentication_available)?;

    let mut mapping_config = config.clone();
    mapping_config.scope.active_testing = false;
    mapping_config.scope.allow_non_idempotent_methods = false;
    mapping_config.scope.enable_timing_probes = false;
    let outcome = run_authorized_scan_with_seeds(
        &mapping_config,
        primary_auth,
        None,
        source_seeds,
        cancelled,
        |_| {},
    )?;
    let application_map = build_application_map(&outcome.endpoints);
    let plan = build_test_plan(
        config,
        &outcome.endpoints,
        secondary_auth.is_some_and(has_auth),
        environment,
    );
    Ok(GuidedPreparation {
        preflight,
        application_map,
        plan,
        passive_findings: outcome.findings,
        mapping_requests: outcome.requests_performed,
    })
}

pub fn build_application_map(endpoints: &[EndpointObservation]) -> ApplicationMap {
    let mut groups: BTreeMap<String, Vec<ApplicationRoute>> = BTreeMap::new();
    let mut page_count = 0usize;
    let mut form_count = 0usize;
    let mut api_endpoint_count = 0usize;
    let mut parameter_count = 0usize;
    let mut authenticated_endpoint_count = 0usize;

    for endpoint in endpoints {
        let parsed = Url::parse(&endpoint.url).ok();
        let label = parsed
            .as_ref()
            .and_then(|url| url.path_segments())
            .and_then(|mut parts| parts.find(|part| !part.is_empty()))
            .map(title_case)
            .unwrap_or_else(|| "Root".to_string());
        let content_type = endpoint
            .content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_page = endpoint.method == "GET" && content_type.contains("text/html");
        let is_form = endpoint.source == "form";
        let is_api = endpoint.source == "openapi"
            || parsed.as_ref().is_some_and(|url| {
                url.path().starts_with("/api/")
                    || url.path().starts_with("/v1/")
                    || url.path().starts_with("/v2/")
            });
        let authenticated = !endpoint.cookie_names.is_empty();
        page_count += usize::from(is_page);
        form_count += usize::from(is_form);
        api_endpoint_count += usize::from(is_api);
        parameter_count += endpoint.parameter_names.len();
        authenticated_endpoint_count += usize::from(authenticated);
        groups.entry(label).or_default().push(ApplicationRoute {
            url: endpoint.url.clone(),
            method: endpoint.method.clone(),
            source: endpoint.source.clone(),
            parameters: endpoint.parameter_names.clone(),
            parameter_locations: endpoint.parameter_locations.clone(),
            content_type: endpoint.content_type.clone(),
            status_code: endpoint.status_code,
            cookies: endpoint.cookie_names.clone(),
            authentication_boundary: authenticated,
            source_hints: Vec::new(),
        });
    }

    let groups = groups
        .into_iter()
        .map(|(label, mut routes)| {
            routes.sort_by(|left, right| {
                left.url
                    .cmp(&right.url)
                    .then(left.method.cmp(&right.method))
            });
            ApplicationGroup { label, routes }
        })
        .collect();

    ApplicationMap {
        groups,
        endpoint_count: endpoints.len(),
        page_count,
        form_count,
        api_endpoint_count,
        parameter_count,
        authenticated_endpoint_count,
    }
}

pub fn build_test_plan(
    config: &ScanConfig,
    endpoints: &[EndpointObservation],
    secondary_auth_available: bool,
    environment: SecurityEnvironment,
) -> GuidedTestPlan {
    let mut operations = Vec::new();

    for endpoint in endpoints {
        // Passive analysis reviews an already-observed response. Endpoints that were
        // mapped but never requested (e.g. POST forms, which discovery does not submit)
        // have nothing to review, so do not list work that cannot happen.
        if endpoint.status_code.is_some() {
            push_operation(
                &mut operations,
                OperationSpec {
                    endpoint,
                    parameter_name: None,
                    category: "passive_analysis",
                    risk: OperationRisk::SAFE,
                    selected: true,
                    reason:
                        "Review response headers, cookies, cache behavior and passive security signals.",
                    skip_reason: None,
                },
            );
        }

        if endpoint.source == "form"
            && matches!(
                endpoint.method.as_str(),
                "POST" | "PUT" | "PATCH" | "DELETE"
            )
            && config.checks.csrf
        {
            push_operation(
                &mut operations,
                OperationSpec {
                    endpoint,
                    parameter_name: None,
                    category: "csrf",
                    risk: OperationRisk::SAFE,
                    selected: true,
                    reason: "Inspect the discovered state-changing form for anti-CSRF controls without submitting it.",
                    skip_reason: None,
                },
            );
        }

        if endpoint.method == "DELETE" {
            push_operation(
                &mut operations,
                OperationSpec {
                    endpoint,
                    parameter_name: None,
                    category: "state_changing_request",
                    risk: OperationRisk::RESTRICTED,
                    selected: false,
                    reason: "DELETE may change persistent state.",
                    skip_reason: Some("Restricted destructive/state-changing operation; Developer Mode does not execute it automatically."),
                },
            );
        }

        for parameter in &endpoint.parameter_names {
            let Some(location) =
                single_parameter_location(&endpoint.parameter_locations, parameter)
            else {
                continue;
            };
            let (risk, selected, skip_reason) = mutation_policy(endpoint, config, &environment);

            if config.checks.sql_injection && injection_candidate(endpoint, location) {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "sql_injection",
                        risk,
                        selected,
                        reason: "Compare baseline and bounded SQL parser/boolean behavior for an input-bearing endpoint.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }

            if config.checks.xss && xss_candidate(endpoint, location) {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "xss",
                        risk,
                        selected,
                        reason: "Check whether a harmless marker is reflected and classify its HTML context.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }

            if config.checks.open_redirect && looks_redirect_parameter(parameter) {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "open_redirect",
                        risk,
                        selected,
                        reason: "Parameter name indicates a redirect destination; verify only with a harmless external marker.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }

            if config.checks.path_traversal && looks_path_parameter(parameter) {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "path_traversal",
                        risk,
                        selected,
                        reason: "Path-like parameter is eligible for a nonexistent-file traversal indicator.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }

            if config.checks.ssrf_indicators && looks_url_parameter(parameter) {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "ssrf",
                        risk,
                        selected,
                        reason: "URL-like parameter is eligible for a reserved TEST-NET outbound-request indicator.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }

            if config.checks.template_command_indicators
                && matches!(location, "query" | "form" | "json")
            {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "template_injection",
                        risk,
                        selected,
                        reason: "Use an arithmetic-only template marker; command execution is not attempted.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }

            if config.checks.api_validation
                && (endpoint.source == "openapi"
                    || endpoint
                        .content_type
                        .as_deref()
                        .is_some_and(|value| value.contains("json"))
                    || location == "json")
            {
                push_operation(
                    &mut operations,
                    OperationSpec {
                        endpoint,
                        parameter_name: Some(parameter),
                        category: "api_validation",
                        risk,
                        selected,
                        reason: "Send bounded malformed input to an API-described input and compare deterministic error handling.",
                        skip_reason: skip_reason.as_deref(),
                    },
                );
            }
        }

        if endpoint.method == "GET" && (config.checks.cors || config.checks.method_misconfiguration)
        {
            push_operation(
                &mut operations,
                OperationSpec {
                    endpoint,
                    parameter_name: None,
                    category: "http_policy",
                    risk: OperationRisk::SAFE,
                    selected: true,
                    reason: "Inspect a bounded OPTIONS response for CORS and advertised HTTP method policy.",
                    skip_reason: None,
                },
            );
        }

        if config.checks.access_control
            && secondary_auth_available
            && looks_object_specific(endpoint)
        {
            let selected = !matches!(environment, SecurityEnvironment::AuthorizedProduction);
            push_operation(
                &mut operations,
                OperationSpec {
                    endpoint,
                    parameter_name: None,
                    category: "access_control",
                    risk: OperationRisk::CAUTION,
                    selected,
                    reason: "Compare the same explicitly encountered object request using the two supplied test identities.",
                    skip_reason: (!selected).then_some("Authorization comparison is disabled by default for authorized production in Developer Mode."),
                },
            );
        }
    }

    operations.sort_by(|left, right| {
        left.endpoint_url
            .cmp(&right.endpoint_url)
            .then(left.method.cmp(&right.method))
            .then(left.category.cmp(&right.category))
            .then(left.parameter_name.cmp(&right.parameter_name))
    });
    operations.dedup_by(|left, right| left.operation_key == right.operation_key);

    let mut counts_by_category = BTreeMap::new();
    let mut counts_by_risk = BTreeMap::new();
    for item in &operations {
        if item.selected {
            *counts_by_category.entry(item.category.clone()).or_insert(0) += 1;
        }
        let key = match item.risk {
            OperationRisk::SAFE => "SAFE",
            OperationRisk::CAUTION => "CAUTION",
            OperationRisk::RESTRICTED => "RESTRICTED",
        };
        *counts_by_risk.entry(key.to_string()).or_insert(0) += 1;
    }

    GuidedTestPlan {
        endpoint_count: endpoints.len(),
        form_count: endpoints
            .iter()
            .filter(|item| item.source == "form")
            .count(),
        parameter_count: endpoints
            .iter()
            .map(|item| item.parameter_names.len())
            .sum(),
        selected_count: operations.iter().filter(|item| item.selected).count(),
        skipped_count: operations.iter().filter(|item| !item.selected).count(),
        counts_by_category,
        counts_by_risk,
        operations,
    }
}

pub(crate) fn check_applicable(
    endpoint: &EndpointObservation,
    parameter: &str,
    category: &str,
) -> bool {
    let Some(location) = single_parameter_location(&endpoint.parameter_locations, parameter) else {
        return false;
    };
    match category {
        "sql_injection" => injection_candidate(endpoint, location),
        "xss" => xss_candidate(endpoint, location),
        "open_redirect" => looks_redirect_parameter(parameter),
        "path_traversal" => looks_path_parameter(parameter),
        "ssrf" => looks_url_parameter(parameter),
        "template_injection" => matches!(location, "query" | "form" | "json"),
        "api_validation" => {
            endpoint.source == "openapi"
                || endpoint
                    .content_type
                    .as_deref()
                    .is_some_and(|value| value.contains("json"))
                || location == "json"
        }
        _ => true,
    }
}

pub(crate) fn looks_redirect_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "next",
        "url",
        "redirect",
        "redirect_uri",
        "return",
        "return_to",
        "callback",
    ]
    .iter()
    .any(|value| lower == *value || lower.contains(value))
}

pub(crate) fn looks_path_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["file", "path", "template", "page", "download", "folder"]
        .iter()
        .any(|value| lower.contains(value))
}

pub(crate) fn looks_url_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "url", "uri", "endpoint", "webhook", "callback", "image", "avatar", "feed",
    ]
    .iter()
    .any(|value| lower.contains(value))
}

pub(crate) fn looks_object_specific(endpoint: &EndpointObservation) -> bool {
    let Ok(url) = Url::parse(&endpoint.url) else {
        return false;
    };
    if endpoint.parameter_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        [
            "id", "user", "account", "order", "document", "file", "record",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    }) {
        return true;
    }
    url.path_segments().into_iter().flatten().any(|segment| {
        segment.len() >= 2 && segment.chars().all(|character| character.is_ascii_digit())
    })
}

fn mutation_policy(
    endpoint: &EndpointObservation,
    config: &ScanConfig,
    environment: &SecurityEnvironment,
) -> (OperationRisk, bool, Option<String>) {
    if matches!(endpoint.method.as_str(), "GET" | "HEAD") {
        return (OperationRisk::SAFE, true, None);
    }
    if endpoint.method == "DELETE" {
        return (
            OperationRisk::RESTRICTED,
            false,
            Some("DELETE is never automatically probed by Developer Mode.".to_string()),
        );
    }
    let production = matches!(environment, SecurityEnvironment::AuthorizedProduction);
    if config.scope.allow_non_idempotent_methods && !production {
        (
            OperationRisk::CAUTION,
            true,
            Some("Explicit safe state-changing testing is enabled for this non-production environment.".to_string()),
        )
    } else {
        (
            OperationRisk::CAUTION,
            false,
            Some(if production {
                "State-changing active probes are disabled by default for authorized production."
                    .to_string()
            } else {
                "Safe mode: state-changing active probes were not enabled.".to_string()
            }),
        )
    }
}

fn injection_candidate(_endpoint: &EndpointObservation, location: &str) -> bool {
    matches!(location, "query" | "form" | "json" | "path")
}

fn xss_candidate(endpoint: &EndpointObservation, location: &str) -> bool {
    if !matches!(location, "query" | "form" | "path") {
        return false;
    }
    endpoint.source == "form"
        || (location == "form" && endpoint.source.starts_with("source_route:"))
        || endpoint.content_type.as_deref().is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("text/html") || value.contains("application/xhtml")
        })
        || (endpoint.content_type.is_none() && endpoint.method == "GET")
}

fn push_operation(output: &mut Vec<PlannedOperation>, spec: OperationSpec<'_>) {
    let parameter = spec.parameter_name.unwrap_or("");
    output.push(PlannedOperation {
        operation_key: fingerprint(&[
            &spec.endpoint.url,
            &spec.endpoint.method,
            parameter,
            spec.category,
        ]),
        endpoint_url: spec.endpoint.url.clone(),
        method: spec.endpoint.method.clone(),
        parameter_name: spec.parameter_name.map(str::to_string),
        category: spec.category.to_string(),
        risk: spec.risk,
        selected: spec.selected,
        reason: spec.reason.to_string(),
        skip_reason: spec.skip_reason.map(str::to_string),
    });
}

fn has_auth(auth: &AuthContext) -> bool {
    auth.cookie_header
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty())
        || auth
            .bearer_token
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty())
        || !auth.custom_headers.is_empty()
}

fn classify_ip(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(value) if value.is_loopback() => "loopback",
        IpAddr::V4(value) if value.is_private() => "private",
        IpAddr::V6(value) if value.is_loopback() => "loopback",
        IpAddr::V6(value) if value.segments()[0] & 0xfe00 == 0xfc00 => "private",
        _ => "public",
    }
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => "Root".to_string(),
    }
}

#[cfg(test)]
mod tests {

    use super::{
        apply_approved_execution_policy, build_test_plan, ApprovedExecutionPolicy, OperationRisk,
        SecurityEnvironment,
    };
    use crate::{CheckConfig, EndpointObservation, ParameterLocations, ScanConfig, ScopeConfig};
    use std::collections::BTreeSet;

    fn config() -> ScanConfig {
        ScanConfig {
            scope: ScopeConfig {
                target_url: "http://localhost:3000".into(),
                allowed_hostnames: vec!["localhost".into()],
                allowed_subdomains: vec![],
                allowed_paths: vec!["/".into()],
                excluded_paths: vec!["/logout".into(), "/payment".into()],
                max_crawl_depth: 2,
                max_requests: 200,
                concurrency: 2,
                timeout_ms: 5_000,
                response_limit_bytes: 128_000,
                redirect_limit: 3,
                retry_limit: 0,
                active_testing: true,
                allow_non_idempotent_methods: false,
                allow_private_networks: true,
                enable_timing_probes: false,
                authorization_confirmed: true,
            },
            checks: CheckConfig::default(),
        }
    }

    fn endpoint(
        method: &str,
        source: &str,
        url: &str,
        parameter: &str,
        location: &str,
    ) -> EndpointObservation {
        EndpointObservation {
            url: url.into(),
            route_template: None,
            method: method.into(),
            depth: 1,
            source: source.into(),
            parameter_names: vec![parameter.into()],
            parameter_locations: ParameterLocations::from([(
                parameter.into(),
                vec![location.into()],
            )]),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: Some(
                if source == "openapi" {
                    "application/json"
                } else {
                    "text/html"
                }
                .into(),
            ),
            status_code: Some(200),
            redirect_to: None,
        }
    }

    #[test]
    fn approved_policy_disables_skipped_detector_families() {
        let mut source = config();
        source.scope.active_testing = true;
        source.scope.allow_non_idempotent_methods = true;
        source.scope.enable_timing_probes = true;
        let policy = ApprovedExecutionPolicy {
            selected_categories: BTreeSet::from(["xss".to_string(), "http_policy".to_string()]),
            state_changing_selected: false,
        };

        let constrained = apply_approved_execution_policy(&source, &policy);
        assert!(constrained.checks.xss);
        assert!(constrained.checks.cors);
        assert!(constrained.checks.method_misconfiguration);
        assert!(!constrained.checks.sql_injection);
        assert!(!constrained.checks.open_redirect);
        assert!(!constrained.checks.path_traversal);
        assert!(!constrained.checks.ssrf_indicators);
        assert!(!constrained.checks.template_command_indicators);
        assert!(!constrained.checks.api_validation);
        assert!(!constrained.checks.access_control);
        assert!(!constrained.scope.enable_timing_probes);
        assert!(!constrained.scope.allow_non_idempotent_methods);
    }

    #[test]
    fn source_backed_form_input_can_enter_xss_plan_when_state_changes_are_approved() {
        let mut source = config();
        source.scope.allow_non_idempotent_methods = true;
        let endpoints = vec![endpoint(
            "POST",
            "source_route:express:src/login.ts:10",
            "http://localhost:3000/login",
            "username",
            "form",
        )];
        let plan = build_test_plan(&source, &endpoints, false, SecurityEnvironment::Staging);
        assert!(plan.operations.iter().any(|item| {
            item.category == "xss"
                && item.parameter_name.as_deref() == Some("username")
                && item.selected
        }));
    }

    #[test]
    fn planner_does_not_blindly_run_every_check() {
        let endpoints = vec![
            endpoint(
                "GET",
                "html",
                "http://localhost:3000/search?q=a",
                "q",
                "query",
            ),
            endpoint(
                "GET",
                "openapi",
                "http://localhost:3000/api/items?id=1",
                "id",
                "query",
            ),
        ];
        let plan = build_test_plan(&config(), &endpoints, true, SecurityEnvironment::Staging);
        assert!(plan
            .operations
            .iter()
            .any(|item| item.category == "xss" && item.endpoint_url.contains("/search")));
        assert!(plan
            .operations
            .iter()
            .any(|item| item.category == "api_validation"
                && item.endpoint_url.contains("/api/items")));
        assert!(!plan
            .operations
            .iter()
            .any(|item| item.category == "open_redirect"
                && item.parameter_name.as_deref() == Some("q")));
    }

    #[test]
    fn legacy_timing_flag_never_enters_plan() {
        let mut source = config();
        source.scope.enable_timing_probes = true;
        let endpoints = vec![endpoint(
            "GET",
            "html",
            "http://localhost:3000/search?q=a",
            "q",
            "query",
        )];
        let plan = build_test_plan(&source, &endpoints, false, SecurityEnvironment::Staging);
        assert!(!plan
            .operations
            .iter()
            .any(|item| item.category == "sql_timing_indicator"));
    }

    #[test]
    fn state_changing_operations_are_skipped_in_safe_mode() {
        let endpoints = vec![endpoint(
            "POST",
            "form",
            "http://localhost:3000/account",
            "display_name",
            "form",
        )];
        let plan = build_test_plan(&config(), &endpoints, false, SecurityEnvironment::Staging);
        assert!(plan
            .operations
            .iter()
            .any(|item| { item.risk == OperationRisk::CAUTION && !item.selected }));
    }

    #[test]
    fn delete_is_restricted() {
        let endpoints = vec![endpoint(
            "DELETE",
            "openapi",
            "http://localhost:3000/api/items/{id}",
            "id",
            "path",
        )];
        let plan = build_test_plan(&config(), &endpoints, false, SecurityEnvironment::Staging);
        assert!(plan
            .operations
            .iter()
            .any(|item| { item.risk == OperationRisk::RESTRICTED && !item.selected }));
    }
}
