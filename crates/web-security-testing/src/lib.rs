mod active;
mod discover;
mod evidence;
mod passive;
mod operator;
mod request;
mod retest;
mod scope;

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::AtomicBool,
    Arc,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use evidence::{body_hash, fingerprint, redact_body, redact_headers, redact_url, response_evidence};
pub use operator::{
    build_application_map, build_test_plan, preflight, prepare_guided_security, ApplicationGroup,
    ApplicationMap, ApplicationRoute, AuthenticationMode, GuidedPreflight, GuidedPreparation,
    GuidedTestPlan, OperationRisk, PlannedOperation, SecurityEnvironment, TestingDepth,
};
pub use request::{RequestBudget, RequestError, ScopedRequester};
pub use retest::{run_targeted_retest, TargetedRetestOutcome, TargetedRetestRequest};
pub use scope::{normalize_url, ScopeError, ScopePolicy};

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
pub struct EndpointObservation {
    pub url: String,
    pub method: String,
    pub depth: usize,
    pub source: String,
    pub parameter_names: Vec<String>,
    #[serde(default)]
    pub parameter_locations: BTreeMap<String, String>,
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
    mut on_progress: impl FnMut(ScanProgress),
) -> Result<ScanOutcome, ScanError> {
    let policy = ScopePolicy::new(config.scope.clone())?;
    let budget = RequestBudget::new(policy.config().max_requests);
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
    let discovery = discover::crawl(
        &policy,
        &requester,
        config,
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
            &policy,
            &requester,
            secondary_auth,
            config,
            &discovery.endpoints,
            &discovery.responses,
            Arc::clone(&cancelled),
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
