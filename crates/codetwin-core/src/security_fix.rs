use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    Database, GuidedSecurityStore, QaDiscoveryService, QaExecutionService, RepairChangeRecord,
    RepairPlanRecord, RepairWorkspaceQueryService, VerifiedRepairService,
};

mod analysis;
mod patch;
mod store;

#[cfg(test)]
mod tests;

const MAX_FIX_ATTEMPTS: usize = 3;
const MAX_ROOT_CAUSES: usize = 5;
const MAX_PATCH_FILES: usize = 3;
const MAX_CHANGED_LINES_REVIEW: usize = 160;
const MAX_CHANGED_LINES_REJECT: usize = 240;
const MAX_EVENTS: usize = 500;
const MAX_VALIDATIONS: usize = 200;

#[derive(Debug, Error)]
pub enum SecurityFixError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("guided security error: {0}")]
    Guided(String),
    #[error("repair workflow error: {0}")]
    Repair(String),
    #[error("repair source error: {0}")]
    Source(String),
    #[error("QA discovery error: {0}")]
    QaDiscovery(String),
    #[error("security fix finding not found: {0}")]
    FindingNotFound(String),
    #[error("security fix attempt not found: {0}")]
    AttemptNotFound(String),
    #[error("security fix attempt is not editable in status: {0}")]
    AttemptNotEditable(String),
    #[error("security fix attempt cannot be approved in status: {0}")]
    AttemptNotApprovable(String),
    #[error("security fix attempt is not approved for application")]
    AttemptNotApproved,
    #[error("security fix patch is rejected by the safety analyzer")]
    PatchRejected,
    #[error("security fix patch requires explicit caution acknowledgement")]
    CautionAcknowledgementRequired,
    #[error("no safe bounded patch can be generated for this finding")]
    PatchGenerationUnavailable,
    #[error("Source changed since approval. Regenerate/review the fix.")]
    StaleApproval,
    #[error("security fix attempt limit reached; explicit additional investigation is required")]
    AttemptLimitReached,
    #[error("invalid security fix state: {0}")]
    State(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FixEligibility {
    AutoFixCandidate,
    GuidedFixCandidate,
    ManualRemediation,
    InsufficientEvidence,
}

impl FixEligibility {
    pub(crate) fn as_db(self) -> &'static str {
        match self {
            Self::AutoFixCandidate => "AUTO_FIX_CANDIDATE",
            Self::GuidedFixCandidate => "GUIDED_FIX_CANDIDATE",
            Self::ManualRemediation => "MANUAL_REMEDIATION",
            Self::InsufficientEvidence => "INSUFFICIENT_EVIDENCE",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, SecurityFixError> {
        match value {
            "AUTO_FIX_CANDIDATE" => Ok(Self::AutoFixCandidate),
            "GUIDED_FIX_CANDIDATE" => Ok(Self::GuidedFixCandidate),
            "MANUAL_REMEDIATION" => Ok(Self::ManualRemediation),
            "INSUFFICIENT_EVIDENCE" => Ok(Self::InsufficientEvidence),
            _ => Err(SecurityFixError::State(format!("unknown eligibility {value}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchSafetyClass {
    SafeToReview,
    Caution,
    Rejected,
}

impl PatchSafetyClass {
    pub(crate) fn as_db(self) -> &'static str {
        match self {
            Self::SafeToReview => "SAFE_TO_REVIEW",
            Self::Caution => "CAUTION",
            Self::Rejected => "REJECTED",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, SecurityFixError> {
        match value {
            "SAFE_TO_REVIEW" => Ok(Self::SafeToReview),
            "CAUTION" => Ok(Self::Caution),
            "REJECTED" => Ok(Self::Rejected),
            _ => Err(SecurityFixError::State(format!(
                "unknown patch safety class {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FixEligibilityAssessment {
    pub finding_id: String,
    pub result: FixEligibility,
    pub reasons: Vec<String>,
    pub evidence_count: usize,
    pub source_candidate_count: usize,
    pub best_source_confidence: Option<f64>,
    pub supported_language: Option<String>,
    pub bounded_patch_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RootCauseCandidate {
    pub file_id: String,
    pub relative_path: String,
    pub symbol_id: Option<String>,
    pub symbol_name: Option<String>,
    pub source_start_line: Option<usize>,
    pub source_end_line: Option<usize>,
    pub confidence: f64,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixStrategy {
    pub category: String,
    pub change_summary: String,
    pub rationale: String,
    pub likely_files: Vec<String>,
    pub expected_behavior: String,
    pub compatibility_risks: Vec<String>,
    pub prohibited_shortcuts: Vec<String>,
    pub regression_test_suggestion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchSafetyReport {
    pub classification: PatchSafetyClass,
    pub patch_hash: String,
    pub files_changed: usize,
    pub changed_lines: usize,
    pub risk_notes: Vec<String>,
    pub rejected_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectedValidation {
    pub label: String,
    pub runner_kind: String,
    pub targets: Vec<String>,
    pub reason: String,
    pub repository_command_execution_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFixTestPlan {
    pub targeted: Vec<SelectedValidation>,
    pub full_suite_optional: bool,
    pub qa_execution_available: bool,
    pub qa_execution_reason: String,
    pub security_retest: String,
    pub regression_test_proposal: String,
    pub regression_generation_status: String,
    pub regression_generation_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityFixAttemptRecord {
    pub id: String,
    pub finding_id: String,
    pub session_id: Option<String>,
    pub project_id: String,
    pub repair_id: Option<String>,
    pub attempt_number: usize,
    pub eligibility: FixEligibility,
    pub category: String,
    pub status: String,
    pub root_causes: Vec<RootCauseCandidate>,
    pub strategy: FixStrategy,
    pub test_plan: SecurityFixTestPlan,
    pub patch_hash: Option<String>,
    pub safety_class: Option<PatchSafetyClass>,
    pub safety: Option<PatchSafetyReport>,
    pub approved_patch_hash: Option<String>,
    pub approved_files_json: Option<String>,
    pub approved_safety_class: Option<PatchSafetyClass>,
    pub caution_acknowledged: bool,
    pub approved_at: Option<String>,
    pub application_run_id: Option<String>,
    pub validation_state: String,
    pub retest_state: String,
    pub static_before_json: String,
    pub static_after_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityFixPreparation {
    pub attempt: SecurityFixAttemptRecord,
    pub eligibility: FixEligibilityAssessment,
    pub root_causes: Vec<RootCauseCandidate>,
    pub strategy: FixStrategy,
    pub test_plan: SecurityFixTestPlan,
    pub repair: Option<RepairPlanRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchReview {
    pub attempt_id: String,
    pub repair_id: String,
    pub unified_diff: String,
    pub safety: PatchSafetyReport,
    pub affected_files: Vec<String>,
    pub expected_behavior: String,
    pub tests_to_run: Vec<String>,
    pub security_retest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFixValidationRecord {
    pub id: String,
    pub attempt_id: String,
    pub sequence: usize,
    pub command_label: String,
    pub runner_kind: String,
    pub targets: Vec<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub classification: String,
    pub stdout_summary: String,
    pub stderr_summary: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFixEventRecord {
    pub id: String,
    pub attempt_id: String,
    pub sequence: usize,
    pub event_type: String,
    pub message: String,
    pub detail_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiFindingOverlap {
    pub finding_ids: Vec<String>,
    pub overlapping_files: Vec<String>,
    pub requires_combined_review: bool,
    pub message: String,
}

#[derive(Debug)]
pub struct ValidationResultInput<'a> {
    pub command_label: &'a str,
    pub runner_kind: &'a str,
    pub targets: &'a [String],
    pub status: &'a str,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub classification: &'a str,
    pub stdout_summary: &'a str,
    pub stderr_summary: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct FindingContext {
    pub finding_id: String,
    pub session_id: Option<String>,
    pub project_id: Option<String>,
    pub category: String,
    pub confidence: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub evidence_count: usize,
}

pub struct SecurityFixService<'a> {
    pub(crate) database: &'a Database,
}

impl<'a> SecurityFixService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }
}

pub(crate) fn bounded_text(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_string()
}

pub(crate) fn bounded_limit(value: usize, max: usize) -> i64 {
    i64::try_from(value.clamp(1, max)).unwrap_or(i64::MAX)
}

pub(crate) fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(crate) fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or_default()
}

pub(crate) fn reject_sensitive_json(value: &serde_json::Value) -> Result<(), SecurityFixError> {
    fn visit(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                matches!(
                    key.as_str(),
                    "authorization"
                        | "cookie"
                        | "set_cookie"
                        | "bearer_token"
                        | "api_key"
                        | "password"
                        | "secret"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                        | "session_token"
                        | "custom_headers"
                ) || visit(value)
            }),
            serde_json::Value::Array(values) => values.iter().any(visit),
            _ => false,
        }
    }
    if visit(value) {
        return Err(SecurityFixError::State(
            "security fix history must not persist authentication or secret material".into(),
        ));
    }
    Ok(())
}
