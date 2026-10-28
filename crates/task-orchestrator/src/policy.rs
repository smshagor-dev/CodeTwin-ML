//! Deterministic authorization policy. This module, not a model, a worker or a
//! plugin, is the final authority for tool permissions. Nothing in a task's
//! input, a tool result or model output can add a capability: capabilities are
//! fixed when the operator approves a plan and are intersected with the worker
//! role's contract.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::state::{string_enum, SideEffect};

string_enum!(Capability {
    ReadProject => "read_project",
    ReadGit => "read_git",
    SearchCode => "search_code",
    ReadDependencies => "read_dependencies",
    ReadFindings => "read_findings",
    ReadTests => "read_tests",
    ReadEvidence => "read_evidence",
    ReadMemory => "read_memory",
    RecordMemory => "record_memory",
    WebResearch => "web_research",
    CloudInference => "cloud_inference",
    LocalMutation => "local_mutation",
    Subprocess => "subprocess",
    ActiveSecurity => "active_security",
    CredentialUse => "credential_use",
});

impl Capability {
    pub const fn side_effect(self) -> SideEffect {
        match self {
            Self::ReadProject
            | Self::ReadGit
            | Self::SearchCode
            | Self::ReadDependencies
            | Self::ReadFindings
            | Self::ReadTests
            | Self::ReadEvidence
            | Self::ReadMemory
            // Writes only CodeTwin's own provenance memory, never the project.
            | Self::RecordMemory => SideEffect::ReadOnly,
            Self::LocalMutation | Self::Subprocess => SideEffect::LocalMutation,
            Self::WebResearch | Self::CloudInference | Self::ActiveSecurity | Self::CredentialUse => {
                SideEffect::External
            }
        }
    }
}

/// Whether the host can enforce process isolation for subprocess tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxSupport {
    Enforced,
    Unavailable,
}

/// Facts the policy needs that are outside the task itself. All are set by
/// the operator or detected by Rust, never by model output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub sandbox: SandboxSupport,
    /// Project-level, explicit cloud data-disclosure consent.
    pub cloud_consent: bool,
    /// Operator opted in to bounded web research for this project.
    pub research_enabled: bool,
}

impl PolicyContext {
    /// Fail-closed default: offline, no research, no sandbox.
    pub const fn offline() -> Self {
        Self {
            sandbox: SandboxSupport::Unavailable,
            cloud_consent: false,
            research_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalNeed {
    /// Covered by the operator's approval of the whole plan.
    PlanApproval,
    /// Requires an additional, scope-bound approval for this specific task.
    TaskApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", content = "reason", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny(String),
}

pub mod deny {
    pub const NOT_IN_ROLE_CONTRACT: &str = "capability_not_in_role_contract";
    pub const NOT_GRANTED: &str = "capability_not_granted";
    pub const ACTIVE_SECURITY: &str = "active_security_requires_dedicated_authorized_workflow";
    pub const CREDENTIAL_USE: &str = "credential_use_is_not_delegable";
    pub const SANDBOX_UNAVAILABLE: &str = "sandbox_enforcement_unavailable";
    pub const CLOUD_CONSENT: &str = "cloud_disclosure_consent_missing";
    pub const RESEARCH_DISABLED: &str = "web_research_not_enabled";
    pub const APPROVAL_MISSING: &str = "task_approval_missing_or_stale";
    pub const UNKNOWN_TOOL: &str = "tool_not_registered";
    pub const TOOL_UNAVAILABLE: &str = "tool_unavailable_on_platform";
    pub const INVALID_ARGUMENTS: &str = "tool_arguments_schema_violation";
}

pub struct PolicyEngine;

impl PolicyEngine {
    /// Hard denials that no approval can lift.
    fn hard_deny(capability: Capability, ctx: &PolicyContext) -> Option<&'static str> {
        match capability {
            Capability::ActiveSecurity => Some(deny::ACTIVE_SECURITY),
            Capability::CredentialUse => Some(deny::CREDENTIAL_USE),
            Capability::Subprocess if ctx.sandbox != SandboxSupport::Enforced => {
                Some(deny::SANDBOX_UNAVAILABLE)
            }
            Capability::CloudInference if !ctx.cloud_consent => Some(deny::CLOUD_CONSENT),
            Capability::WebResearch if !ctx.research_enabled => Some(deny::RESEARCH_DISABLED),
            _ => None,
        }
    }

    /// Plan-time evaluation: which approval a task needs, or why it is denied.
    pub fn plan_requirement(
        requested: &BTreeSet<Capability>,
        role_contract: &BTreeSet<Capability>,
        ctx: &PolicyContext,
    ) -> Result<ApprovalNeed, &'static str> {
        let mut need = ApprovalNeed::PlanApproval;
        for capability in requested {
            if !role_contract.contains(capability) {
                return Err(deny::NOT_IN_ROLE_CONTRACT);
            }
            if let Some(reason) = Self::hard_deny(*capability, ctx) {
                return Err(reason);
            }
            if !capability.side_effect().is_read_only() {
                need = ApprovalNeed::TaskApproval;
            }
        }
        Ok(need)
    }

    /// Run-time evaluation of one tool call by a running task.
    pub fn authorize_call(
        granted: &BTreeSet<Capability>,
        capability: Capability,
        has_live_task_approval: bool,
        ctx: &PolicyContext,
    ) -> Decision {
        if !granted.contains(&capability) {
            return Decision::Deny(deny::NOT_GRANTED.into());
        }
        if let Some(reason) = Self::hard_deny(capability, ctx) {
            return Decision::Deny(reason.into());
        }
        if !capability.side_effect().is_read_only() && !has_live_task_approval {
            return Decision::Deny(deny::APPROVAL_MISSING.into());
        }
        Decision::Allow
    }
}

/// Platform availability of a registered tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolAvailability {
    pub available: bool,
    pub reason: Option<String>,
}

/// Typed tool descriptor. Arguments are validated against `input_schema`
/// (a bounded JSON-Schema subset) before the policy is consulted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub id: String,
    pub description: String,
    pub capability: Capability,
    pub side_effect: SideEffect,
    pub input_schema: serde_json::Value,
    pub output_kind: String,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    /// Permitted network destinations (empty = no network).
    pub network_destinations: Vec<String>,
    /// Filesystem roots the tool may read, symbolic (e.g. "project_root").
    pub filesystem_roots: Vec<String>,
    pub audit: String,
    pub availability: ToolAvailability,
}

/// Validate `value` against a bounded JSON-Schema subset: `type`
/// (object/string/integer/number/boolean/array), `properties`, `required`,
/// `additionalProperties: false`, `maxLength`, `minimum`, `maximum`,
/// `maxItems`, `items` and `enum` of strings. Unknown keywords are rejected so
/// that a schema cannot silently become permissive.
pub fn validate_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), String> {
    validate_at(schema, value, "$", 0)
}

fn validate_at(
    schema: &serde_json::Value,
    value: &serde_json::Value,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    use serde_json::Value;
    if depth > 8 {
        return Err(format!("{path}: schema nesting too deep"));
    }
    let schema = schema
        .as_object()
        .ok_or_else(|| format!("{path}: schema must be an object"))?;
    for key in schema.keys() {
        if !matches!(
            key.as_str(),
            "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "maxLength"
                | "minimum"
                | "maximum"
                | "maxItems"
                | "items"
                | "enum"
                | "description"
        ) {
            return Err(format!("{path}: unsupported schema keyword `{key}`"));
        }
    }
    let ty = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("object");
    match (ty, value) {
        ("object", Value::Object(map)) => {
            let props = schema.get("properties").and_then(Value::as_object);
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                for name in required.iter().filter_map(Value::as_str) {
                    if !map.contains_key(name) {
                        return Err(format!("{path}.{name}: required"));
                    }
                }
            }
            let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
            for (name, child) in map {
                match props.and_then(|p| p.get(name)) {
                    Some(child_schema) => {
                        validate_at(child_schema, child, &format!("{path}.{name}"), depth + 1)?
                    }
                    None if closed => return Err(format!("{path}.{name}: not allowed")),
                    None => {}
                }
            }
            Ok(())
        }
        ("string", Value::String(text)) => {
            if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
                if text.chars().count() as u64 > max {
                    return Err(format!("{path}: longer than {max}"));
                }
            }
            if let Some(options) = schema.get("enum").and_then(Value::as_array) {
                if !options.iter().any(|o| o.as_str() == Some(text)) {
                    return Err(format!("{path}: not an allowed value"));
                }
            }
            Ok(())
        }
        ("integer", Value::Number(n)) if n.is_i64() || n.is_u64() => bounds(schema, n, path),
        ("number", Value::Number(n)) => bounds(schema, n, path),
        ("boolean", Value::Bool(_)) => Ok(()),
        ("array", Value::Array(items)) => {
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
                if items.len() as u64 > max {
                    return Err(format!("{path}: more than {max} items"));
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (i, item) in items.iter().enumerate() {
                    validate_at(item_schema, item, &format!("{path}[{i}]"), depth + 1)?;
                }
            }
            Ok(())
        }
        _ => Err(format!("{path}: expected {ty}")),
    }
}

fn bounds(
    schema: &serde_json::Map<String, serde_json::Value>,
    n: &serde_json::Number,
    path: &str,
) -> Result<(), String> {
    let v = n.as_f64().unwrap_or(f64::NAN);
    if !v.is_finite() {
        return Err(format!("{path}: not finite"));
    }
    if let Some(min) = schema.get("minimum").and_then(serde_json::Value::as_f64) {
        if v < min {
            return Err(format!("{path}: below minimum"));
        }
    }
    if let Some(max) = schema.get("maximum").and_then(serde_json::Value::as_f64) {
        if v > max {
            return Err(format!("{path}: above maximum"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(caps: &[Capability]) -> BTreeSet<Capability> {
        caps.iter().copied().collect()
    }

    #[test]
    fn read_only_tasks_need_only_plan_approval() {
        let caps = set(&[Capability::ReadProject, Capability::SearchCode]);
        assert_eq!(
            PolicyEngine::plan_requirement(&caps, &caps, &PolicyContext::offline()),
            Ok(ApprovalNeed::PlanApproval)
        );
    }

    #[test]
    fn capabilities_outside_role_contract_are_denied() {
        let requested = set(&[Capability::ReadProject, Capability::LocalMutation]);
        let contract = set(&[Capability::ReadProject]);
        assert_eq!(
            PolicyEngine::plan_requirement(&requested, &contract, &PolicyContext::offline()),
            Err(deny::NOT_IN_ROLE_CONTRACT)
        );
    }

    #[test]
    fn hard_denials_fail_closed() {
        let ctx = PolicyContext::offline();
        for (cap, reason) in [
            (Capability::ActiveSecurity, deny::ACTIVE_SECURITY),
            (Capability::CredentialUse, deny::CREDENTIAL_USE),
            (Capability::Subprocess, deny::SANDBOX_UNAVAILABLE),
            (Capability::CloudInference, deny::CLOUD_CONSENT),
            (Capability::WebResearch, deny::RESEARCH_DISABLED),
        ] {
            let caps = set(&[cap]);
            assert_eq!(
                PolicyEngine::plan_requirement(&caps, &caps, &ctx),
                Err(reason)
            );
            assert_eq!(
                PolicyEngine::authorize_call(&caps, cap, true, &ctx),
                Decision::Deny(reason.into())
            );
        }
    }

    #[test]
    fn consented_cloud_needs_task_approval_and_live_grant() {
        let ctx = PolicyContext {
            cloud_consent: true,
            ..PolicyContext::offline()
        };
        let caps = set(&[Capability::CloudInference]);
        assert_eq!(
            PolicyEngine::plan_requirement(&caps, &caps, &ctx),
            Ok(ApprovalNeed::TaskApproval)
        );
        assert_eq!(
            PolicyEngine::authorize_call(&caps, Capability::CloudInference, false, &ctx),
            Decision::Deny(deny::APPROVAL_MISSING.into())
        );
        assert_eq!(
            PolicyEngine::authorize_call(&caps, Capability::CloudInference, true, &ctx),
            Decision::Allow
        );
        // Not granted to this task: approval elsewhere does not transfer.
        assert_eq!(
            PolicyEngine::authorize_call(&set(&[]), Capability::CloudInference, true, &ctx),
            Decision::Deny(deny::NOT_GRANTED.into())
        );
    }

    #[test]
    fn schema_rejects_malicious_arguments() {
        let schema = json!({"type":"object","additionalProperties":false,
            "required":["query"],
            "properties":{"query":{"type":"string","maxLength":10},
                          "limit":{"type":"integer","minimum":1,"maximum":50}}});
        assert!(validate_schema(&schema, &json!({"query":"abc","limit":5})).is_ok());
        assert!(validate_schema(&schema, &json!({"query":"abc","cmd":"rm -rf /"})).is_err());
        assert!(validate_schema(&schema, &json!({"limit":5})).is_err());
        assert!(validate_schema(&schema, &json!({"query":"x".repeat(11)})).is_err());
        assert!(validate_schema(&schema, &json!({"query":"a","limit":500})).is_err());
        assert!(validate_schema(&schema, &json!({"query":"a","limit":"5"})).is_err());
        assert!(validate_schema(&json!({"type":"object","pattern":".*"}), &json!({})).is_err());
    }
}
