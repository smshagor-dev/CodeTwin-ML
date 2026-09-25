mod active;
mod discover;
mod evidence;
mod passive;
mod payload_policy;
mod operator;
mod request;
mod retest;
mod scope;

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::AtomicBool,
    Arc,
};

use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;

pub use evidence::{body_hash, fingerprint, redact_body, redact_headers, redact_url, response_evidence};
pub use operator::{
    apply_approved_execution_policy, build_application_map, build_test_plan, preflight,
    prepare_guided_security, prepare_guided_security_with_seeds, ApplicationGroup, ApplicationMap, ApplicationRoute,
    ApplicationSourceHint, ApprovedExecutionPolicy, AuthenticationMode, GuidedPreflight,
    GuidedPreparation,
    GuidedTestPlan, OperationRisk, PlannedOperation, SecurityEnvironment, TestingDepth,
};
pub use request::{RequestBudget, RequestError, ScopedRequester};
pub use retest::{run_targeted_retest, TargetedRetestOutcome, TargetedRetestRequest};
pub use scope::{normalize_url, ScopeError, ScopePolicy};

pub type ParameterLocations = BTreeMap<String, Vec<String>>;

pub(crate) type RequestSeedValues = BTreeMap<String, serde_json::Value>;

#[derive(Debug, Clone, Default)]
pub(crate) struct RequestSeedContext {
    pub values: RequestSeedValues,
    pub redaction_secrets: Vec<String>,
}

pub(crate) fn endpoint_request_key(method: &str, raw: &str) -> String {
    let normalized = url::Url::parse(raw)
        .map(|mut url| {
            url.set_fragment(None);
            url.to_string()
        })
        .unwrap_or_else(|_| raw.to_string());
    format!("{} {normalized}", method.trim().to_ascii_uppercase())
}

pub fn insert_parameter_location(
    locations: &mut ParameterLocations,
    name: impl Into<String>,
    location: impl Into<String>,
) {
    let name = name.into();
    let location = location.into();
    let values = locations.entry(name).or_default();
    if !values.iter().any(|value| value == &location) {
        values.push(location);
        values.sort();
    }
}

pub fn parameter_has_location(
    locations: &ParameterLocations,
    name: &str,
    expected: &str,
) -> bool {
    locations
        .get(name)
        .is_some_and(|values| values.iter().any(|value| value == expected))
}

pub fn single_parameter_location<'a>(
    locations: &'a ParameterLocations,
    name: &str,
) -> Option<&'a str> {
    let values = locations.get(name)?;
    (values.len() == 1).then(|| values[0].as_str())
}

pub(crate) fn deserialize_parameter_locations<'de, D>(
    deserializer: D,
) -> Result<ParameterLocations, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    let object = value
        .as_object()
        .ok_or_else(|| de::Error::custom("parameter locations must be a JSON object"))?;
    let mut output = ParameterLocations::new();
    for (name, raw) in object {
        match raw {
            serde_json::Value::String(location) => {
                insert_parameter_location(&mut output, name.clone(), location.clone());
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    let Some(location) = value.as_str() else {
                        return Err(de::Error::custom(
                            "parameter location arrays must contain only strings",
                        ));
                    };
                    insert_parameter_location(
                        &mut output,
                        name.clone(),
                        location.to_string(),
                    );
                }
            }
            _ => {
                return Err(de::Error::custom(
                    "parameter location values must be strings or string arrays",
                ));
            }
        }
    }
    Ok(output)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeConfig {
    pub target_url: String,
    pub allowed_hostnames: Vec<String>,
    pub allowed_subdomains: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub excluded_paths: Vec<String>,
    pub max_crawl_depth: usize,
    pub max_requests: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub response_limit_bytes: usize,
    pub redirect_limit: usize,
    pub retry_limit: usize,
    pub active_testing: bool,
    pub allow_non_idempotent_methods: bool,
    pub allow_private_networks: bool,
    pub enable_timing_probes: bool,
    pub authorization_confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckConfig {
    pub sql_injection: bool,
    pub xss: bool,
    pub csrf: bool,
    pub open_redirect: bool,
    pub path_traversal: bool,
    pub ssrf_indicators: bool,
    pub template_command_indicators: bool,
    pub method_misconfiguration: bool,
    pub cors: bool,
    pub session: bool,
    pub access_control: bool,
    pub api_validation: bool,
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            sql_injection: true,
            xss: true,
            csrf: true,
            open_redirect: true,
            path_traversal: true,
            ssrf_indicators: true,
            template_command_indicators: true,
            method_misconfiguration: true,
            cors: true,
            session: true,
            access_control: true,
            api_validation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanConfig {
    pub scope: ScopeConfig,
    #[serde(default)]
    pub checks: CheckConfig,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthContext {
    pub cookie_header: Option<String>,
    pub bearer_token: Option<String>,
    pub custom_headers: Vec<(String, String)>,
}

impl AuthContext {
    pub fn metadata(&self) -> AuthMetadata {
        AuthMetadata {
            cookie_supplied: self.cookie_header.as_ref().is_some_and(|value| !value.trim().is_empty()),
            bearer_supplied: self.bearer_token.as_ref().is_some_and(|value| !value.trim().is_empty()),
            custom_header_names: self
                .custom_headers
                .iter()
                .map(|(name, _)| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
        }
    }

    pub(crate) fn redaction_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        if let Some(value) = self
            .cookie_header
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            values.push(value.to_string());
        }
        if let Some(value) = self
            .bearer_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            values.push(value.to_string());
        }
        values.extend(
            self.custom_headers
                .iter()
                .map(|(_, value)| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
        values.sort();
        values.dedup();
        values
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthMetadata {
    pub cookie_supplied: bool,
    pub bearer_supplied: bool,
    pub custom_header_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Queued,
    Discovering,
    Crawling,
    PassiveAnalysis,
    ActiveTesting,
    Correlating,
    Completed,
    Failed,
    Cancelled,
}

impl ScanPhase {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Discovering => "discovering",
            Self::Crawling => "crawling",
            Self::PassiveAnalysis => "passive_analysis",
            Self::ActiveTesting => "active_testing",
            Self::Correlating => "correlating",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub endpoints_discovered: usize,
    pub requests_performed: usize,
    pub findings_observed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceEndpointSeed {
    pub url: String,
    pub discovery_url: Option<String>,
    pub method: String,
    pub parameter_names: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_parameter_locations")]
    pub parameter_locations: ParameterLocations,
    pub content_type: Option<String>,
    pub source_label: String,
}

pub fn source_endpoint_seed(
    target_url: &str,
    method: &str,
    path_template: &str,
    parameter_names: &[String],
    parameter_locations: &ParameterLocations,
    content_type: Option<&str>,
    source_label: &str,
) -> Option<SourceEndpointSeed> {
    let mut base = url::Url::parse(target_url).ok()?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return None;
    }
    let normalized_template = normalize_route_template(path_template)?;
    let parameter_samples = route_parameter_samples(path_template);
    let deployment_prefix = normalize_deployment_prefix(base.path());
    let effective_template =
        apply_deployment_prefix(&deployment_prefix, &normalized_template);
    let materialized_path = materialize_route_path(&effective_template, &parameter_samples)?;
    base.set_path("/");
    base.set_query(None);
    base.set_fragment(None);

    let mut template_url = base.join(effective_template.trim_start_matches('/')).ok()?;
    let mut discovery_url = base.join(materialized_path.trim_start_matches('/')).ok()?;
    for url in [&mut template_url, &mut discovery_url] {
        let mut query = url.query_pairs_mut();
        for name in parameter_names {
            if parameter_has_location(parameter_locations, name, "query") {
                query.append_pair(name, "codetwin-test");
            }
        }
    }

    Some(SourceEndpointSeed {
        url: template_url.to_string(),
        discovery_url: Some(discovery_url.to_string()),
        method: method.trim().to_ascii_uppercase(),
        parameter_names: parameter_names.to_vec(),
        parameter_locations: parameter_locations.clone(),
        content_type: content_type.map(ToString::to_string),
        source_label: source_label.to_string(),
    })
}

fn normalize_deployment_prefix(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return String::new();
    }
    let mut prefix = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    if prefix.len() > 1 {
        prefix = prefix.trim_end_matches('/').to_string();
    }
    prefix
}

fn apply_deployment_prefix(prefix: &str, route: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        return route.to_string();
    }
    if route == prefix || route.starts_with(&format!("{prefix}/")) {
        return route.to_string();
    }
    format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        route.trim_start_matches('/')
    )
}

fn normalize_route_template(template: &str) -> Option<String> {
    let trimmed = template.trim();
    if trimmed.contains('*') {
        return None;
    }
    let preserve_trailing_slash = trimmed.len() > 1 && trimmed.ends_with('/');
    let mut segments = Vec::new();
    for segment in trimmed.trim_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        if let Some(rest) = segment.strip_prefix(':') {
            let name = rest
                .split(['?', '(', '.'])
                .next()
                .unwrap_or(rest)
                .trim();
            if name.is_empty() {
                return None;
            }
            segments.push(format!("{{{name}}}"));
            continue;
        }
        if segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2 {
            let name = segment[1..segment.len() - 1]
                .split([':', '?'])
                .next()
                .unwrap_or("")
                .trim();
            if name.is_empty() {
                return None;
            }
            segments.push(format!("{{{name}}}"));
            continue;
        }
        if segment.starts_with('<') && segment.ends_with('>') && segment.len() > 2 {
            let inner = &segment[1..segment.len() - 1];
            let name = inner
                .rsplit_once(':')
                .map(|(_, name)| name)
                .unwrap_or(inner)
                .trim();
            if name.is_empty() {
                return None;
            }
            segments.push(format!("{{{name}}}"));
            continue;
        }
        segments.push(segment.to_string());
    }
    Some(if segments.is_empty() {
        "/".to_string()
    } else {
        let mut path = format!("/{}", segments.join("/"));
        if preserve_trailing_slash {
            path.push('/');
        }
        path
    })
}

fn route_parameter_samples(template: &str) -> BTreeMap<String, String> {
    let mut samples = BTreeMap::new();
    for segment in template.trim_matches('/').split('/') {
        if let Some(rest) = segment.strip_prefix(':') {
            let name = rest
                .split(['?', '(', '.'])
                .next()
                .unwrap_or(rest)
                .trim();
            if !name.is_empty() {
                samples.insert(name.to_string(), route_sample_value(segment));
            }
            continue;
        }
        if segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2 {
            let inner = &segment[1..segment.len() - 1];
            let name = inner.split([':', '?']).next().unwrap_or("").trim();
            if !name.is_empty() {
                samples.insert(name.to_string(), route_sample_value(segment));
            }
            continue;
        }
        if segment.starts_with('<') && segment.ends_with('>') && segment.len() > 2 {
            let inner = &segment[1..segment.len() - 1];
            let name = inner
                .rsplit_once(':')
                .map(|(_, name)| name)
                .unwrap_or(inner)
                .trim();
            if !name.is_empty() {
                samples.insert(name.to_string(), route_sample_value(segment));
            }
        }
    }
    samples
}

fn route_sample_value(segment: &str) -> String {
    let lower = segment.to_ascii_lowercase();
    if lower.contains("uuid") {
        return "00000000-0000-4000-8000-000000000001".to_string();
    }
    if lower.contains(":float}")
        || lower.contains(":double}")
        || lower.starts_with("<float:")
    {
        return "1.0".to_string();
    }
    if lower.contains(":bool}") || lower.starts_with("<bool:") {
        return "true".to_string();
    }
    if lower.contains(":int}")
        || lower.contains(":integer}")
        || lower.starts_with("<int:")
        || lower.starts_with("<integer:")
        || lower.contains("\\d")
        || lower.contains("[0-9]")
    {
        return "1".to_string();
    }
    if (lower.contains("[a-f0-9]") || lower.contains("[0-9a-f]"))
        && lower.contains("{24}")
    {
        return "0".repeat(24);
    }
    "codetwin-test".to_string()
}

fn materialize_route_path(
    template: &str,
    parameter_samples: &BTreeMap<String, String>,
) -> Option<String> {
    if template.contains('*') {
        return None;
    }
    let preserve_trailing_slash = template.len() > 1 && template.ends_with('/');
    let mut segments = Vec::new();
    for segment in template.trim_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        let dynamic = segment.starts_with('{') && segment.ends_with('}');
        segments.push(if dynamic {
            let name = &segment[1..segment.len() - 1];
            parameter_samples
                .get(name)
                .cloned()
                .unwrap_or_else(|| "codetwin-test".to_string())
        } else {
            segment.to_string()
        });
    }
    Some(if segments.is_empty() {
        "/".to_string()
    } else {
        let mut path = format!("/{}", segments.join("/"));
        if preserve_trailing_slash {
            path.push('/');
        }
        path
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointObservation {
    pub url: String,
    #[serde(default)]
    pub route_template: Option<String>,
    pub method: String,
    pub depth: usize,
    pub source: String,
    pub parameter_names: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_parameter_locations")]
    pub parameter_locations: ParameterLocations,
    #[serde(default)]
    pub response_header_names: Vec<String>,
    #[serde(default)]
    pub cookie_names: Vec<String>,
    pub content_type: Option<String>,
    pub status_code: Option<u16>,
    pub redirect_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceObservation {
    pub summary: String,
    pub request_metadata: serde_json::Value,
    pub response_metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingObservation {
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub target: String,
    pub endpoint: String,
    pub method: String,
    pub parameter: Option<String>,
    pub title: String,
    pub description: String,
    pub reproduction_summary: String,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub evidence: Vec<EvidenceObservation>,
}

impl FindingObservation {
    pub fn stable_fingerprint(&self) -> String {
        fingerprint(&[
            &self.category,
            &self.endpoint,
            &self.method,
            self.parameter.as_deref().unwrap_or(""),
            &self.title,
        ])
    }
}

#[derive(Debug, Clone)]
pub struct ObservedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub body: Vec<u8>,
    pub elapsed_ms: u64,
    pub truncated: bool,
    pub(crate) redaction_secrets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub endpoints: Vec<EndpointObservation>,
    pub findings: Vec<FindingObservation>,
    pub requests_performed: usize,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("{0}")]
    Scope(#[from] ScopeError),
    #[error("{0}")]
    Request(#[from] RequestError),
    #[error("scan cancelled")]
    Cancelled,
    #[error("discovery error: {0}")]
    Discovery(String),
}

pub fn run_authorized_scan(
    config: &ScanConfig,
    primary_auth: &AuthContext,
    secondary_auth: Option<&AuthContext>,
    cancelled: Arc<AtomicBool>,
    on_progress: impl FnMut(ScanProgress),
) -> Result<ScanOutcome, ScanError> {
    run_authorized_scan_with_seeds(
        config,
        primary_auth,
        secondary_auth,
        &[],
        cancelled,
        on_progress,
    )
}

pub fn run_authorized_scan_with_seeds(
    config: &ScanConfig,
    primary_auth: &AuthContext,
    secondary_auth: Option<&AuthContext>,
    source_seeds: &[SourceEndpointSeed],
    cancelled: Arc<AtomicBool>,
    mut on_progress: impl FnMut(ScanProgress),
) -> Result<ScanOutcome, ScanError> {
    let policy = ScopePolicy::new(config.scope.clone())?;
    // A global shared token bucket caps scan request rate even when detector
    // concurrency is higher. This is intentionally conservative and not user-bypassable.
    let budget = RequestBudget::with_rate(policy.config().max_requests, 4.0, 2);
    let requester = ScopedRequester::new(
        policy.clone(),
        primary_auth.clone(),
        budget.clone(),
        Arc::clone(&cancelled),
    );

    on_progress(ScanProgress {
        phase: ScanPhase::Discovering,
        endpoints_discovered: 0,
        requests_performed: 0,
        findings_observed: 0,
    });

    let mut progress_callback = |endpoints: usize, findings: usize| {
        on_progress(ScanProgress {
            phase: ScanPhase::Crawling,
            endpoints_discovered: endpoints,
            requests_performed: budget.used(),
            findings_observed: findings,
        });
    };
    let discovery = discover::crawl_with_seeds(
        &policy,
        &requester,
        config,
        source_seeds,
        Arc::clone(&cancelled),
        &mut progress_callback,
    )?;

    let mut findings = discovery.findings;
    on_progress(ScanProgress {
        phase: ScanPhase::PassiveAnalysis,
        endpoints_discovered: discovery.endpoints.len(),
        requests_performed: budget.used(),
        findings_observed: findings.len(),
    });

    if config.scope.active_testing {
        on_progress(ScanProgress {
            phase: ScanPhase::ActiveTesting,
            endpoints_discovered: discovery.endpoints.len(),
            requests_performed: budget.used(),
            findings_observed: findings.len(),
        });
        let passive_count = findings.len();
        let mut active_progress = |active_count: usize| {
            on_progress(ScanProgress {
                phase: ScanPhase::ActiveTesting,
                endpoints_discovered: discovery.endpoints.len(),
                requests_performed: budget.used(),
                findings_observed: passive_count + active_count,
            });
        };
        let active_findings = active::run_active_checks(
            active::ActiveCheckContext {
                policy: &policy,
                requester: &requester,
                secondary_auth,
                config,
                endpoints: &discovery.endpoints,
                baselines: &discovery.responses,
                request_seeds: &discovery.request_seeds,
                cancelled: Arc::clone(&cancelled),
            },
            &mut active_progress,
        )?;
        findings.extend(active_findings);
    }

    on_progress(ScanProgress {
        phase: ScanPhase::Correlating,
        endpoints_discovered: discovery.endpoints.len(),
        requests_performed: budget.used(),
        findings_observed: findings.len(),
    });
    let findings = correlate_findings(findings);

    on_progress(ScanProgress {
        phase: ScanPhase::Completed,
        endpoints_discovered: discovery.endpoints.len(),
        requests_performed: budget.used(),
        findings_observed: findings.len(),
    });
    Ok(ScanOutcome {
        endpoints: discovery.endpoints,
        findings,
        requests_performed: budget.used(),
    })
}

fn correlate_findings(findings: Vec<FindingObservation>) -> Vec<FindingObservation> {
    let mut correlated: BTreeMap<String, FindingObservation> = BTreeMap::new();
    for finding in findings {
        let key = finding.stable_fingerprint();
        match correlated.get_mut(&key) {
            Some(existing) => {
                existing.evidence.extend(finding.evidence);
                existing.evidence.truncate(8);
                if confidence_rank(&finding.confidence) > confidence_rank(&existing.confidence) {
                    existing.confidence = finding.confidence;
                }
                if severity_rank(&finding.severity) > severity_rank(&existing.severity) {
                    existing.severity = finding.severity;
                }
            }
            None => {
                correlated.insert(key, finding);
            }
        }
    }
    correlated.into_values().collect()
}

fn confidence_rank(value: &str) -> u8 {
    match value.to_ascii_lowercase().as_str() {
        "confirmed" => 3,
        "likely" => 2,
        _ => 1,
    }
}

fn severity_rank(value: &str) -> u8 {
    match value.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

pub(crate) fn query_parameters(url: &url::Url) -> Vec<String> {
    let mut names: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    names.sort();
    names.dedup();
    names
}

pub(crate) fn response_header(response: &ObservedResponse, name: &str) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

pub(crate) fn headers_map(response: &ObservedResponse) -> HashMap<String, String> {
    response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}


#[cfg(test)]
mod source_seed_tests {
    use std::collections::BTreeMap;

    use super::source_endpoint_seed;

    #[test]
    fn materializes_dynamic_path_and_query_fields_without_body_execution() {
        let names = vec![
            "tenant".to_string(),
            "next".to_string(),
            "email".to_string(),
        ];
        let locations = BTreeMap::from([
            ("tenant".to_string(), vec!["path".to_string()]),
            ("next".to_string(), vec!["query".to_string()]),
            ("email".to_string(), vec!["json".to_string()]),
        ]);
        let seed = source_endpoint_seed(
            "https://example.test/root",
            "POST",
            "/api/login/:tenant",
            &names,
            &locations,
            Some("application/json"),
            "source_route:express:src/server.ts:10",
        )
        .expect("seed");
        assert_eq!(seed.method, "POST");
        assert!(seed.url.contains("/root/api/login/%7Btenant%7D"));
        assert!(seed.url.contains("next=codetwin-test"));
        assert!(!seed.url.contains("email="));
        let discovery = seed.discovery_url.as_deref().expect("discovery url");
        assert!(discovery.starts_with("https://example.test/root/api/login/codetwin-test"));
        assert!(discovery.contains("next=codetwin-test"));
        assert_eq!(
            seed.parameter_locations
                .get("email")
                .and_then(|values| values.first())
                .map(String::as_str),
            Some("json")
        );
    }

    #[test]
    fn source_seed_preserves_same_parameter_name_across_path_and_query() {
        let names = vec!["id".to_string()];
        let locations = BTreeMap::from([(
            "id".to_string(),
            vec!["path".to_string(), "query".to_string()],
        )]);
        let seed = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/api/items/:id",
            &names,
            &locations,
            None,
            "source_route:express:server.ts:1",
        )
        .expect("seed");

        assert_eq!(
            seed.parameter_locations.get("id"),
            Some(&vec!["path".to_string(), "query".to_string()])
        );
        assert!(seed.url.contains("/api/items/%7Bid%7D"));
        assert!(seed.url.contains("id=codetwin-test"));
        assert!(seed
            .discovery_url
            .as_deref()
            .is_some_and(|url| url.contains("/api/items/codetwin-test")));
    }

    #[test]
    fn materializes_typed_source_routes_with_constraint_compatible_values() {
        let locations = BTreeMap::from([("id".to_string(), vec!["path".to_string()])]);

        let fastapi = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/api/users/{id:int}",
            &["id".to_string()],
            &locations,
            None,
            "source_route:fastapi:app.py:1",
        )
        .expect("fastapi seed");
        assert_eq!(
            fastapi.discovery_url.as_deref(),
            Some("https://example.test/api/users/1")
        );

        let express = source_endpoint_seed(
            "https://example.test",
            "GET",
            r"/api/users/:id(\\d+)",
            &["id".to_string()],
            &locations,
            None,
            "source_route:express:server.ts:1",
        )
        .expect("express seed");
        assert_eq!(
            express.discovery_url.as_deref(),
            Some("https://example.test/api/users/1")
        );

        let uuid = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/api/items/{id:uuid}",
            &["id".to_string()],
            &locations,
            None,
            "source_route:fastapi:app.py:2",
        )
        .expect("uuid seed");
        assert_eq!(
            uuid.discovery_url.as_deref(),
            Some("https://example.test/api/items/00000000-0000-4000-8000-000000000001")
        );
    }

    #[test]
    fn materializes_optional_laravel_parameters() {
        let locations = BTreeMap::from([("id".to_string(), vec!["path".to_string()])]);
        let seed = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/users/{id?}",
            &["id".to_string()],
            &locations,
            None,
            "source_route:laravel:routes/web.php:1",
        )
        .expect("laravel optional seed");
        assert_eq!(
            seed.discovery_url.as_deref(),
            Some("https://example.test/users/codetwin-test")
        );
    }

    #[test]
    fn materializes_flask_converter_routes_with_compatible_values() {
        let locations = BTreeMap::from([("user_id".to_string(), "path".to_string())]);

        let integer = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/api/users/<int:user_id>",
            &["user_id".to_string()],
            &locations,
            None,
            "source_route:flask:app.py:1",
        )
        .expect("flask integer seed");
        assert_eq!(
            integer.discovery_url.as_deref(),
            Some("https://example.test/api/users/1")
        );

        let uuid = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/api/users/<uuid:user_id>",
            &["user_id".to_string()],
            &locations,
            None,
            "source_route:flask:app.py:2",
        )
        .expect("flask uuid seed");
        assert_eq!(
            uuid.discovery_url.as_deref(),
            Some("https://example.test/api/users/00000000-0000-4000-8000-000000000001")
        );
    }

    #[test]
    fn preserves_trailing_slash_when_materializing_live_route_seed() {
        let locations = BTreeMap::from([("id".to_string(), vec!["path".to_string()])]);
        let seed = source_endpoint_seed(
            "https://example.test",
            "GET",
            "/users/{id}/",
            &["id".to_string()],
            &locations,
            None,
            "source_route:fastapi:app.py:1",
        )
        .expect("seed");
        assert_eq!(seed.route_template, "/users/{id}/");
        assert_eq!(
            seed.discovery_url.as_deref(),
            Some("https://example.test/users/codetwin-test/")
        );
    }
    #[test]
    fn preserves_deployment_base_path_without_double_prefix() {
        let parameters = vec!["id".to_string()];
        let locations = BTreeMap::from([("id".to_string(), vec!["path".to_string()])]);

        let prefixed = source_endpoint_seed(
            "https://example.test/app",
            "GET",
            "/api/users/:id",
            &parameters,
            &locations,
            None,
            "source_route:test",
        )
        .expect("seed");
        assert_eq!(
            prefixed.discovery_url.as_deref(),
            Some("https://example.test/app/api/users/codetwin-test")
        );

        let already_prefixed = source_endpoint_seed(
            "https://example.test/app",
            "GET",
            "/app/api/users/:id",
            &parameters,
            &locations,
            None,
            "source_route:test",
        )
        .expect("seed");
        assert_eq!(
            already_prefixed.discovery_url.as_deref(),
            Some("https://example.test/app/api/users/codetwin-test")
        );
    }

    #[test]
    fn refuses_wildcard_source_routes_for_automatic_live_seeding() {
        assert!(source_endpoint_seed(
            "https://example.test",
            "GET",
            "/files/*",
            &[],
            &BTreeMap::new(),
            None,
            "source_route:express:src/files.ts:1",
        )
        .is_none());
    }
}
