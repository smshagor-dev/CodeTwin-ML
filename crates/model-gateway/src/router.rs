//! Deterministic model routing. Cloud use needs project consent; fallback
//! from cloud to local happens only when the operator allowed it, and there
//! is never an automatic fallback from local to cloud.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::consent::CloudConsent;
use crate::error::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Local,
    Cloud,
}

/// Per-role model selection, e.g. `planner → openmindai-super`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleModels {
    pub default_cloud: Option<String>,
    pub default_local: Option<String>,
    pub cloud_by_role: BTreeMap<String, String>,
    #[serde(default)]
    pub local_by_role: BTreeMap<String, String>,
}

impl RoleModels {
    pub fn model_for(&self, role: &str, route: Route) -> Option<&str> {
        match route {
            Route::Cloud => self
                .cloud_by_role
                .get(role)
                .or(self.default_cloud.as_ref())
                .map(String::as_str),
            Route::Local => self
                .local_by_role
                .get(role)
                .or(self.default_local.as_ref())
                .map(String::as_str),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoutingInput<'a> {
    pub preferred: Route,
    pub consent: Option<&'a CloudConsent>,
    pub local_configured: bool,
    pub cloud_configured: bool,
}

pub fn choose_route(input: &RoutingInput<'_>) -> Result<Route, ProviderError> {
    match input.preferred {
        Route::Local if input.local_configured => Ok(Route::Local),
        Route::Local => Err(ProviderError::Config(
            "no local model endpoint configured".into(),
        )),
        Route::Cloud => {
            if !input.consent.is_some_and(|c| c.allow_cloud) {
                return Err(ProviderError::ConsentRequired(
                    "project is offline-only".into(),
                ));
            }
            if !input.cloud_configured {
                return Err(ProviderError::Config(
                    "cloud provider not configured".into(),
                ));
            }
            Ok(Route::Cloud)
        }
    }
}

/// After a failed cloud call: may the request be retried locally?
pub fn fallback_after(
    route: Route,
    error: &ProviderError,
    input: &RoutingInput<'_>,
) -> Option<Route> {
    let infra =
        error.retryable() || matches!(error, ProviderError::CircuitOpen | ProviderError::Saturated);
    (route == Route::Cloud
        && infra
        && input.local_configured
        && input.consent.is_some_and(|c| c.allow_local_fallback))
    .then_some(Route::Local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consent(fallback: bool) -> CloudConsent {
        CloudConsent {
            project_id: "p".into(),
            allow_cloud: true,
            allow_source_excerpts: false,
            allow_local_fallback: fallback,
            max_payload_bytes: 1000,
            granted_by: "op".into(),
            granted_ms: 0,
        }
    }

    #[test]
    fn never_routes_to_cloud_without_consent_or_from_local() {
        let input = RoutingInput {
            preferred: Route::Cloud,
            consent: None,
            local_configured: true,
            cloud_configured: true,
        };
        assert!(
            choose_route(&input).is_err(),
            "no silent local substitution either"
        );
        let local = RoutingInput {
            preferred: Route::Local,
            consent: None,
            local_configured: false,
            cloud_configured: true,
        };
        assert!(choose_route(&local).is_err(), "no local → cloud fallback");
        assert_eq!(
            fallback_after(Route::Local, &ProviderError::Timeout, &local),
            None
        );
    }

    #[test]
    fn cloud_to_local_fallback_only_when_allowed() {
        let c = consent(false);
        let input = RoutingInput {
            preferred: Route::Cloud,
            consent: Some(&c),
            local_configured: true,
            cloud_configured: true,
        };
        assert_eq!(choose_route(&input).unwrap(), Route::Cloud);
        assert_eq!(
            fallback_after(Route::Cloud, &ProviderError::Unavailable(503), &input),
            None
        );
        let c = consent(true);
        let input = RoutingInput {
            consent: Some(&c),
            ..input
        };
        assert_eq!(
            fallback_after(Route::Cloud, &ProviderError::Unavailable(503), &input),
            Some(Route::Local)
        );
        assert_eq!(
            fallback_after(
                Route::Cloud,
                &ProviderError::Unauthorized("x".into()),
                &input
            ),
            None
        );
    }

    #[test]
    fn role_models_resolve() {
        let m = RoleModels {
            default_cloud: Some("openmindai-lite".into()),
            default_local: Some("local".into()),
            cloud_by_role: [("planner".to_owned(), "openmindai-super".to_owned())].into(),
            local_by_role: [("reviewer".to_owned(), "qwen-local".to_owned())].into(),
        };
        assert_eq!(m.model_for("reviewer", Route::Local), Some("qwen-local"));
        assert_eq!(
            m.model_for("planner", Route::Cloud),
            Some("openmindai-super")
        );
        assert_eq!(
            m.model_for("reviewer", Route::Cloud),
            Some("openmindai-lite")
        );
        assert_eq!(m.model_for("planner", Route::Local), Some("local"));
    }
}
