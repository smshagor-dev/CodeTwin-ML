//! Explicit, bounded object-policy checks. No object identifier enumeration.
use crate::evidence::response_evidence;
use crate::{
    AuthContext, FindingObservation, ObservedResponse, RequestBudget, ScanConfig, ScanError,
    ScopePolicy, ScopedRequester,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{atomic::AtomicBool, Arc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectAccessPolicy {
    pub identity_url: String,
    pub identity_json_pointer: String,
    pub primary_identity: Value,
    pub secondary_identity: Value,
    pub object_url: String,
    pub object_json_pointer: String,
    pub expected_object: Value,
    pub secondary_access_allowed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessPolicyStatus {
    ViolationConfirmed,
    AccessDenied,
    SharedAccessObserved,
    UnableToVerify,
}
#[derive(Debug, Clone)]
pub struct AccessPolicyOutcome {
    pub status: AccessPolicyStatus,
    pub finding: Option<FindingObservation>,
    pub requests_performed: usize,
    pub reason: String,
}

pub fn run_object_access_policy(
    config: &ScanConfig,
    primary: &AuthContext,
    secondary: &AuthContext,
    expected: &ObjectAccessPolicy,
    cancelled: Arc<AtomicBool>,
) -> Result<AccessPolicyOutcome, ScanError> {
    let scope = ScopePolicy::new(config.scope.clone())?;
    let identity_url = scope.normalize_and_assert(&expected.identity_url)?;
    let object_url = scope.normalize_and_assert(&expected.object_url)?;
    let budget = RequestBudget::with_rate(scope.config().max_requests, 4.0, 2);
    let outcome = |status, finding, reason: &str| AccessPolicyOutcome {
        status,
        finding,
        requests_performed: budget.used(),
        reason: reason.into(),
    };
    if !config.scope.active_testing || !config.checks.access_control {
        return Ok(outcome(
            AccessPolicyStatus::UnableToVerify,
            None,
            "Active access-control testing is disabled.",
        ));
    }
    if !scope.credentials_allowed_for(&identity_url)
        || !scope.credentials_allowed_for(&object_url)
        || primary.comparison_key().is_empty()
        || secondary.comparison_key().is_empty()
        || primary.comparison_key() == secondary.comparison_key()
        || expected.primary_identity == expected.secondary_identity
        || expected.primary_identity.is_null()
        || expected.secondary_identity.is_null()
        || !expected
            .expected_object
            .as_object()
            .is_some_and(|object| !object.is_empty())
        || !expected.identity_json_pointer.starts_with('/')
        || !expected.object_json_pointer.starts_with('/')
    {
        return Ok(outcome(AccessPolicyStatus::UnableToVerify, None, "Distinct authenticated principals, credential-eligible origins and explicit nonempty JSON object evidence are required."));
    }
    let primary_client = ScopedRequester::new(
        scope.clone(),
        primary.clone(),
        budget.clone(),
        Arc::clone(&cancelled),
    );
    let secondary_client = ScopedRequester::new(
        scope.clone(),
        secondary.clone(),
        budget.clone(),
        Arc::clone(&cancelled),
    );
    let anonymous = ScopedRequester::new(scope, AuthContext::default(), budget.clone(), cancelled);
    let mut records = Vec::new();
    macro_rules! get {
        ($client:expr, $url:expr, $label:expr) => {{
            match $client.get($url) {
                Ok(response) => {
                    records.push(($label, $url.clone(), response.clone()));
                    response
                }
                Err(crate::RequestError::Cancelled) => return Err(ScanError::Cancelled),
                Err(_) => {
                    return Ok(outcome(
                        AccessPolicyStatus::UnableToVerify,
                        None,
                        "A required control request failed or the shared budget was exhausted.",
                    ))
                }
            }
        }};
    }
    let first_primary = get!(primary_client, &identity_url, "primary principal");
    let first_secondary = get!(secondary_client, &identity_url, "secondary principal");
    if !matches_json(
        &first_primary,
        &expected.identity_json_pointer,
        &expected.primary_identity,
    ) || !matches_json(
        &first_secondary,
        &expected.identity_json_pointer,
        &expected.secondary_identity,
    ) {
        return Ok(outcome(
            AccessPolicyStatus::UnableToVerify,
            None,
            "The supplied sessions did not prove the expected distinct principals.",
        ));
    }
    let p1 = get!(primary_client, &object_url, "primary object");
    let s1 = get!(secondary_client, &object_url, "secondary object");
    let p2 = get!(primary_client, &object_url, "primary object repeat");
    let s2 = get!(secondary_client, &object_url, "secondary object repeat");
    let last_primary = get!(primary_client, &identity_url, "primary principal repeat");
    let last_secondary = get!(
        secondary_client,
        &identity_url,
        "secondary principal repeat"
    );
    if !matches_json(
        &last_primary,
        &expected.identity_json_pointer,
        &expected.primary_identity,
    ) || !matches_json(
        &last_secondary,
        &expected.identity_json_pointer,
        &expected.secondary_identity,
    ) || !matches_json(
        &p1,
        &expected.object_json_pointer,
        &expected.expected_object,
    ) || !same_success(&p1, &p2)
    {
        return Ok(outcome(
            AccessPolicyStatus::UnableToVerify,
            None,
            "Principal identity or the authorized object control was incomplete or changed.",
        ));
    }
    if !s1.truncated && !s2.truncated && s1.status == s2.status && matches!(s1.status, 403 | 404) {
        return Ok(outcome(
            if expected.secondary_access_allowed {
                AccessPolicyStatus::UnableToVerify
            } else {
                AccessPolicyStatus::AccessDenied
            },
            None,
            "The secondary principal was denied on both object requests.",
        ));
    }
    if !matches_json(
        &s1,
        &expected.object_json_pointer,
        &expected.expected_object,
    ) || !same_success(&p1, &s1)
        || !same_success(&p1, &s2)
    {
        return Ok(outcome(
            AccessPolicyStatus::UnableToVerify,
            None,
            "Secondary object access was not proven with stable matching JSON evidence.",
        ));
    }
    if expected.secondary_access_allowed {
        return Ok(outcome(
            AccessPolicyStatus::SharedAccessObserved,
            None,
            "Both authenticated principals received the explicitly shared object.",
        ));
    }
    let public = get!(anonymous, &object_url, "anonymous object control");
    if public.truncated || !matches!(public.status, 401 | 403 | 404) {
        return Ok(outcome(AccessPolicyStatus::UnableToVerify, None, "The anonymous control did not establish a protected object; review public-access policy separately."));
    }
    let mut secrets = primary.redaction_values();
    secrets.extend(secondary.redaction_values());
    let evidence = records
        .into_iter()
        .map(|(label, url, mut response)| {
            response.redaction_secrets.extend(secrets.clone());
            response_evidence(label, "GET", &url, &response)
        })
        .collect();
    let finding = FindingObservation {
        category: "access_control".into(), severity: "high".into(), confidence: "Confirmed".into(),
        target: config.scope.target_url.clone(), endpoint: object_url.to_string(), method: "GET".into(), parameter: None,
        title: "Explicit object access policy violated by verified secondary principal".into(),
        description: "Distinct principals were verified before and after repeated exact object reads. The secondary principal received the protected object despite the supplied deny policy; anonymous access was denied. Confirmation is conditional on the supplied policy being correct.".into(),
        reproduction_summary: "Repeat only the supplied object URL and principal controls using the two authorized test sessions. No identifiers were generated or enumerated.".into(),
        impact: "A principal denied by the supplied object policy can read the protected object.".into(),
        remediation: "Enforce server-side object authorization against the authenticated principal on every read.".into(),
        references: vec!["CWE-639".into()], evidence,
    };
    Ok(outcome(
        AccessPolicyStatus::ViolationConfirmed,
        Some(finding),
        "Repeated protected-object access contradicted the explicit deny policy.",
    ))
}
fn matches_json(response: &ObservedResponse, pointer: &str, expected: &Value) -> bool {
    let mime = response
        .content_type
        .as_deref()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    !response.truncated
        && (200..300).contains(&response.status)
        && (mime == "application/json"
            || (mime.starts_with("application/") && mime.ends_with("+json")))
        && serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|json| json.pointer(pointer).cloned())
            .as_ref()
            == Some(expected)
}
fn same_success(left: &ObservedResponse, right: &ObservedResponse) -> bool {
    !left.truncated
        && !right.truncated
        && (200..300).contains(&left.status)
        && left.status == right.status
        && left.content_type == right.content_type
        && left.body == right.body
}
