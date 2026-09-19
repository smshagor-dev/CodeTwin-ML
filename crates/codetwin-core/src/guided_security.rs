use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use url::Url;

use crate::{Database, RepairPlanRecord, VerifiedRepairService};

const MAX_LIST: usize = 500;

#[derive(Debug, Error)]
pub enum GuidedSecurityError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid guided security configuration: {0}")]
    InvalidConfig(String),
    #[error("guided security session not found: {0}")]
    SessionNotFound(String),
    #[error("guided security finding not found: {0}")]
    FindingNotFound(String),
    #[error("guided security state conflict: {0}")]
    State(String),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("repair workflow error: {0}")]
    Repair(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedSessionCreate {
    pub website_id: Option<String>,
    pub project_id: Option<String>,
    pub target_url: String,
    pub environment: String,
    pub testing_depth: String,
    pub auth_mode: String,
    pub authorization_confirmed: bool,
    pub config_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedSecuritySessionRecord {
    pub id: String,
    pub website_id: Option<String>,
    pub project_id: Option<String>,
    pub target_url: String,
    pub environment: String,
    pub testing_depth: String,
    pub auth_mode: String,
    pub status: String,
    pub authorization_confirmed: bool,
    pub config_json: String,
    pub preflight_json: String,
    pub application_map_json: String,
    pub plan_json: String,
    pub mapping_requests: usize,
    pub scan_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub prepared_at: Option<String>,
    pub approved_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedPlanItemInput {
    pub operation_key: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub category: String,
    pub risk: String,
    pub selected: bool,
    pub reason: String,
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedPlanItemRecord {
    pub id: String,
    pub session_id: String,
    pub operation_key: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameter_name: Option<String>,
    pub category: String,
    pub risk: String,
    pub selected: bool,
    pub reason: String,
    pub skip_reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug)]
pub struct PreparationCompletion<'a> {
    pub session_id: &'a str,
    pub preflight_json: &'a str,
    pub application_map_json: &'a str,
    pub plan_json: &'a str,
    pub mapping_requests: usize,
    pub plan_items: &'a [GuidedPlanItemInput],
}

#[derive(Debug)]
pub struct GuidedRetestInput<'a> {
    pub finding_id: &'a str,
    pub session_id: Option<&'a str>,
    pub status: &'a str,
    pub original_confidence: &'a str,
    pub observed_confidence: Option<&'a str>,
    pub requests_performed: usize,
    pub detail_json: &'a str,
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedActivityRecord {
    pub id: String,
    pub session_id: String,
    pub sequence: usize,
    pub event_type: String,
    pub phase: String,
    pub message: String,
    pub detail_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedSourceCandidate {
    pub id: String,
    pub finding_id: String,
    pub rank: usize,
    pub file_id: String,
    pub relative_path: String,
    pub symbol_id: Option<String>,
    pub symbol_name: Option<String>,
    pub confidence: f64,
    pub rationale: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedRetestRecord {
    pub id: String,
    pub finding_id: String,
    pub session_id: Option<String>,
    pub status: String,
    pub original_confidence: String,
    pub observed_confidence: Option<String>,
    pub requests_performed: usize,
    pub detail_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedScanComparison {
    pub id: String,
    pub session_id: Option<String>,
    pub previous_scan_id: String,
    pub current_scan_id: String,
    pub comparison_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedFixPreparation {
    pub finding_id: String,
    pub project_id: String,
    pub repair: RepairPlanRecord,
    pub source_candidates: Vec<GuidedSourceCandidate>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedSecurityScorecard {
    pub endpoints_mapped: usize,
    pub endpoints_tested: usize,
    pub coverage_percent: f64,
    pub confirmed_findings: usize,
    pub likely_findings: usize,
    pub potential_findings: usize,
    pub rejected_anomalies: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub authentication_context_supplied: bool,
    pub authenticated_endpoints_mapped: usize,
    pub planned_authorization_checks: usize,
    pub authorization_plan_coverage_percent: f64,
    pub planned_api_validation_checks: usize,
    pub api_validation_plan_coverage_percent: f64,
    pub planned_input_checks: usize,
    pub input_plan_coverage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedRiskNode {
    pub id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedRiskEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuidedRiskGraph {
    pub nodes: Vec<GuidedRiskNode>,
    pub edges: Vec<GuidedRiskEdge>,
}

pub struct GuidedSecurityStore<'a> {
    database: &'a Database,
}

impl<'a> GuidedSecurityStore<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn recover_interrupted_sessions(&self) -> Result<usize, GuidedSecurityError> {
        Ok(self.database.connection().execute(
            "UPDATE guided_security_sessions
             SET status='failed',
                 last_error='CodeTwin restarted before this guided security session completed.',
                 finished_at=COALESCE(finished_at, CURRENT_TIMESTAMP),
                 updated_at=CURRENT_TIMESTAMP
             WHERE status IN ('preparing','running')",
            [],
        )?)
    }

    pub fn create_session(
        &self,
        input: &GuidedSessionCreate,
    ) -> Result<GuidedSecuritySessionRecord, GuidedSecurityError> {
        validate_session_input(input)?;
        let target = Url::parse(input.target_url.trim())
            .map_err(|error| GuidedSecurityError::InvalidConfig(error.to_string()))?;
        let config_value: serde_json::Value = serde_json::from_str(&input.config_json)?;
        reject_sensitive_json(&config_value, "guided scan config")?;
        if config_value
            .pointer("/scope/authorization_confirmed")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            return Err(GuidedSecurityError::InvalidConfig(
                "scan config must contain explicit authorization confirmation".to_string(),
            ));
        }
        let id = self.random_id("guided")?;
        self.database.connection().execute(
            "INSERT INTO guided_security_sessions(
                id, website_id, project_id, target_url, environment, testing_depth,
                auth_mode, status, authorization_confirmed, config_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'preparing', 1, ?8)",
            params![
                id,
                input.website_id,
                input.project_id,
                target.to_string(),
                input.environment,
                input.testing_depth,
                input.auth_mode,
                input.config_json,
            ],
        )?;
        self.append_activity(
            &id,
            "authorization_confirmed",
            "preflight",
            "Authorization confirmed and guided security session created.",
            "{}",
        )?;
        self.get_session(&id)?
            .ok_or(GuidedSecurityError::SessionNotFound(id))
    }

    pub fn complete_preparation(
        &self,
        input: PreparationCompletion<'_>,
    ) -> Result<GuidedSecuritySessionRecord, GuidedSecurityError> {
        let preflight_value =
            serde_json::from_str::<serde_json::Value>(input.preflight_json)?;
        let application_map_value =
            serde_json::from_str::<serde_json::Value>(input.application_map_json)?;
        let plan_value = serde_json::from_str::<serde_json::Value>(input.plan_json)?;
        reject_sensitive_json(&preflight_value, "guided preflight")?;
        reject_sensitive_json(&application_map_value, "guided application map")?;
        reject_sensitive_json(&plan_value, "guided test plan")?;
        let current = self
            .get_session(input.session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(input.session_id.to_string()))?;
        if current.status != "preparing" {
            return Err(GuidedSecurityError::State(format!(
                "session must be preparing before plan creation; observed {}",
                current.status
            )));
        }

        let tx = self.database.connection().unchecked_transaction()?;
        tx.execute(
            "UPDATE guided_security_sessions
             SET status='awaiting_approval', preflight_json=?2, application_map_json=?3,
                 plan_json=?4, mapping_requests=?5, prepared_at=CURRENT_TIMESTAMP,
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            params![
                input.session_id,
                bounded_text(input.preflight_json, 256_000),
                bounded_text(input.application_map_json, 1_000_000),
                bounded_text(input.plan_json, 1_000_000),
                input.mapping_requests as i64,
            ],
        )?;
        tx.execute(
            "DELETE FROM guided_security_plan_items WHERE session_id=?1",
            [input.session_id],
        )?;
        for item in input.plan_items.iter().take(10_000) {
            validate_plan_item(item)?;
            let id = random_id_from_connection(&tx, "guideop")?;
            tx.execute(
                "INSERT INTO guided_security_plan_items(
                    id, session_id, operation_key, endpoint_url, method, parameter_name,
                    category, risk, selected, reason, skip_reason
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    id,
                    input.session_id,
                    item.operation_key,
                    item.endpoint_url,
                    item.method,
                    item.parameter_name,
                    item.category,
                    item.risk,
                    i64::from(item.selected),
                    bounded_text(&item.reason, 4_000),
                    item.skip_reason.as_deref().map(|value| bounded_text(value, 4_000)),
                ],
            )?;
        }
        tx.commit()?;

        self.append_activity(
            input.session_id,
            "target_resolved",
            "preflight",
            "Pre-flight safety checks completed within the configured authorization boundary.",
            input.preflight_json,
        )?;
        self.append_activity(
            input.session_id,
            "application_mapped",
            "mapping",
            "Authorized application mapping completed.",
            &json!({"mapping_requests": input.mapping_requests}).to_string(),
        )?;
        self.append_activity(
            input.session_id,
            "plan_created",
            "planning",
            "Risk-aware security test plan created and waiting for developer approval.",
            input.plan_json,
        )?;
        self.get_session(input.session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(input.session_id.to_string()))
    }

    pub fn fail_preparation(
        &self,
        session_id: &str,
        error: &str,
    ) -> Result<(), GuidedSecurityError> {
        self.database.connection().execute(
            "UPDATE guided_security_sessions
             SET status='failed', last_error=?2, finished_at=CURRENT_TIMESTAMP,
                 updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![session_id, bounded_text(error, 2_000)],
        )?;
        self.append_activity(
            session_id,
            "preparation_failed",
            "preflight",
            "Guided security preparation failed safely.",
            &json!({"error": bounded_text(error, 1_000)}).to_string(),
        )?;
        Ok(())
    }

    pub fn approve_session(
        &self,
        session_id: &str,
    ) -> Result<GuidedSecuritySessionRecord, GuidedSecurityError> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))?;
        if session.status != "awaiting_approval" {
            return Err(GuidedSecurityError::State(format!(
                "session is not awaiting plan approval: {}",
                session.status
            )));
        }
        self.database.connection().execute(
            "UPDATE guided_security_sessions
             SET status='approved', approved_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            [session_id],
        )?;
        self.append_activity(
            session_id,
            "plan_approved",
            "planning",
            "Developer approved the bounded security test plan.",
            "{}",
        )?;
        self.get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))
    }

    pub fn assert_execution_allowed(
        &self,
        session_id: &str,
        target_url: &str,
        config_json: &str,
    ) -> Result<GuidedSecuritySessionRecord, GuidedSecurityError> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))?;
        if session.status != "approved" {
            return Err(GuidedSecurityError::State(format!(
                "guided plan must be approved before active execution; observed {}",
                session.status
            )));
        }
        let expected_target = normalized_url(&session.target_url)?;
        let observed_target = normalized_url(target_url)?;
        if expected_target != observed_target {
            return Err(GuidedSecurityError::InvalidConfig(
                "execution target differs from the approved guided target".to_string(),
            ));
        }
        let approved: serde_json::Value = serde_json::from_str(&session.config_json)?;
        let observed: serde_json::Value = serde_json::from_str(config_json)?;
        if approved != observed {
            return Err(GuidedSecurityError::InvalidConfig(
                "execution configuration differs from the approved guided plan".to_string(),
            ));
        }
        Ok(session)
    }

    pub fn link_scan(
        &self,
        session_id: &str,
        scan_id: &str,
    ) -> Result<GuidedSecuritySessionRecord, GuidedSecurityError> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))?;
        if session.status != "approved" {
            return Err(GuidedSecurityError::State(format!(
                "session must be approved before scan linkage; observed {}",
                session.status
            )));
        }
        self.database.connection().execute(
            "UPDATE guided_security_sessions
             SET status='running', scan_id=?2, started_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            params![session_id, scan_id],
        )?;
        self.append_activity(
            session_id,
            "execution_started",
            "execution",
            "Controlled security execution started.",
            &json!({"scan_id": scan_id}).to_string(),
        )?;
        self.get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))
    }

    pub fn update_from_scan(
        &self,
        session_id: &str,
        scan_status: &str,
        scan_phase: &str,
        last_error: Option<&str>,
    ) -> Result<GuidedSecuritySessionRecord, GuidedSecurityError> {
        let next = match scan_status {
            "completed" => "completed",
            "cancelled" => "cancelled",
            "failed" => "failed",
            "queued" | "running" => "running",
            other => {
                return Err(GuidedSecurityError::InvalidConfig(format!(
                    "unsupported scan status {other}"
                )))
            }
        };
        self.database.connection().execute(
            "UPDATE guided_security_sessions
             SET status=?2, last_error=COALESCE(?3,last_error),
                 finished_at=CASE WHEN ?2 IN ('completed','failed','cancelled')
                                  THEN COALESCE(finished_at,CURRENT_TIMESTAMP) ELSE finished_at END,
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            params![session_id, next, last_error.map(|value| bounded_text(value, 2_000))],
        )?;
        if matches!(next, "completed" | "failed" | "cancelled") {
            self.append_activity(
                session_id,
                &format!("scan_{next}"),
                scan_phase,
                &format!("Guided security scan {next}."),
                "{}",
            )?;
        }
        self.get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))
    }

    pub fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<GuidedSecuritySessionRecord>, GuidedSecurityError> {
        self.database
            .connection()
            .query_row(
                "SELECT id, website_id, project_id, target_url, environment, testing_depth,
                        auth_mode, status, authorization_confirmed, config_json, preflight_json,
                        application_map_json, plan_json, mapping_requests, scan_id, last_error,
                        created_at, prepared_at, approved_at, started_at, finished_at, updated_at
                 FROM guided_security_sessions WHERE id=?1",
                [session_id],
                map_session,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_sessions(
        &self,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<GuidedSecuritySessionRecord>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, website_id, project_id, target_url, environment, testing_depth,
                    auth_mode, status, authorization_confirmed, config_json, preflight_json,
                    application_map_json, plan_json, mapping_requests, scan_id, last_error,
                    created_at, prepared_at, approved_at, started_at, finished_at, updated_at
             FROM guided_security_sessions
             WHERE (?1 IS NULL OR project_id=?1)
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![project_id, bounded_limit(limit) as i64],
            map_session,
        )?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn list_plan_items(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<GuidedPlanItemRecord>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, session_id, operation_key, endpoint_url, method, parameter_name,
                    category, risk, selected, reason, skip_reason, created_at
             FROM guided_security_plan_items WHERE session_id=?1
             ORDER BY selected DESC,
                      CASE risk WHEN 'SAFE' THEN 1 WHEN 'CAUTION' THEN 2 ELSE 3 END,
                      endpoint_url, category
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![session_id, bounded_limit(limit) as i64],
            |row| {
                Ok(GuidedPlanItemRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    operation_key: row.get(2)?,
                    endpoint_url: row.get(3)?,
                    method: row.get(4)?,
                    parameter_name: row.get(5)?,
                    category: row.get(6)?,
                    risk: row.get(7)?,
                    selected: row.get::<_, i64>(8)? != 0,
                    reason: row.get(9)?,
                    skip_reason: row.get(10)?,
                    created_at: row.get(11)?,
                })
            },
        )?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn selected_plan_categories(
        &self,
        session_id: &str,
    ) -> Result<BTreeSet<String>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT DISTINCT category
             FROM guided_security_plan_items
             WHERE session_id=?1 AND selected=1
             ORDER BY category",
        )?;
        let rows = statement.query_map([session_id], |row| row.get::<_, String>(0))?;
        let mut output = BTreeSet::new();
        for row in rows {
            output.insert(row?);
        }
        Ok(output)
    }

    pub fn has_selected_state_changing(
        &self,
        session_id: &str,
    ) -> Result<bool, GuidedSecurityError> {
        self.database
            .connection()
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM guided_security_plan_items
                   WHERE session_id=?1 AND selected=1 AND method IN ('POST','PUT','PATCH')
                 )",
                [session_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn append_activity(
        &self,
        session_id: &str,
        event_type: &str,
        phase: &str,
        message: &str,
        detail_json: &str,
    ) -> Result<GuidedActivityRecord, GuidedSecurityError> {
        let detail_value = serde_json::from_str::<serde_json::Value>(detail_json)?;
        reject_sensitive_json(&detail_value, "guided activity")?;
        let session_exists: bool = self.database.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM guided_security_sessions WHERE id=?1)",
            [session_id],
            |row| row.get(0),
        )?;
        if !session_exists {
            return Err(GuidedSecurityError::SessionNotFound(session_id.to_string()));
        }
        let sequence: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM guided_security_activity WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )?;
        let id = self.random_id("guideevt")?;
        self.database.connection().execute(
            "INSERT INTO guided_security_activity(
                id, session_id, sequence, event_type, phase, message, detail_json
             ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id,
                session_id,
                sequence,
                bounded_text(event_type, 128),
                bounded_text(phase, 128),
                bounded_text(message, 2_000),
                bounded_text(detail_json, 32_000),
            ],
        )?;
        self.database.connection().query_row(
            "SELECT id, session_id, sequence, event_type, phase, message, detail_json, created_at
             FROM guided_security_activity WHERE id=?1",
            [id],
            |row| {
                Ok(GuidedActivityRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    sequence: row.get::<_, i64>(2)? as usize,
                    event_type: row.get(3)?,
                    phase: row.get(4)?,
                    message: row.get(5)?,
                    detail_json: row.get(6)?,
                    created_at: row.get(7)?,
                })
            },
        ).map_err(Into::into)
    }

    pub fn list_activity(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<GuidedActivityRecord>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, session_id, sequence, event_type, phase, message, detail_json, created_at
             FROM guided_security_activity WHERE session_id=?1
             ORDER BY sequence ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![session_id, bounded_limit(limit) as i64],
            |row| {
                Ok(GuidedActivityRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    sequence: row.get::<_, i64>(2)? as usize,
                    event_type: row.get(3)?,
                    phase: row.get(4)?,
                    message: row.get(5)?,
                    detail_json: row.get(6)?,
                    created_at: row.get(7)?,
                })
            },
        )?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn correlate_source_candidates(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<GuidedSourceCandidate>, GuidedSecurityError> {
        let finding = self.finding_context(finding_id)?;
        let Some(project_id) = finding.project_id.as_deref() else {
            return Ok(Vec::new());
        };
        let url = Url::parse(&finding.endpoint_url)
            .map_err(|error| GuidedSecurityError::InvalidConfig(error.to_string()))?;
        let segments: Vec<String> = url
            .path_segments()
            .into_iter()
            .flatten()
            .filter(|value| {
                value.len() >= 2
                    && value.chars().any(|character| character.is_ascii_alphabetic())
                    && !matches!(*value, "api" | "v1" | "v2" | "www")
            })
            .map(|value| value.to_ascii_lowercase())
            .collect();
        let terminal = segments.last().cloned().unwrap_or_default();
        let parent = segments.iter().rev().nth(1).cloned().unwrap_or_default();
        let parameter = finding.parameter_name.clone().unwrap_or_default().to_ascii_lowercase();
        let method = finding.method.to_ascii_lowercase();

        let mut statement = self.database.connection().prepare(
            "SELECT f.id, f.relative_path, f.language, s.id, s.name, s.qualified_name
             FROM files f
             LEFT JOIN symbols s ON s.file_id=f.id AND s.is_active=1
             WHERE f.project_id=?1 AND f.is_active=1
             ORDER BY f.relative_path, COALESCE(s.start_line,0)
             LIMIT 6000",
        )?;
        let rows = statement.query_map([project_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;

        #[derive(Clone)]
        struct Ranked {
            file_id: String,
            relative_path: String,
            symbol_id: Option<String>,
            symbol_name: Option<String>,
            score: f64,
            reasons: Vec<String>,
        }

        let mut best: HashMap<(String, Option<String>), Ranked> = HashMap::new();
        for row in rows {
            let (file_id, relative_path, language, symbol_id, symbol_name, qualified_name) = row?;
            let path_lower = relative_path.to_ascii_lowercase();
            let symbol_lower = symbol_name.clone().unwrap_or_default().to_ascii_lowercase();
            let qualified_lower = qualified_name.unwrap_or_default().to_ascii_lowercase();
            let mut score = 0.20f64;
            let mut reasons = Vec::new();

            if !terminal.is_empty()
                && (path_lower.contains(&terminal)
                    || symbol_lower.contains(&terminal)
                    || qualified_lower.contains(&terminal))
            {
                score += 0.28;
                reasons.push(format!("matches route segment '{terminal}'"));
            }
            if !parent.is_empty()
                && (path_lower.contains(&parent)
                    || symbol_lower.contains(&parent)
                    || qualified_lower.contains(&parent))
            {
                score += 0.16;
                reasons.push(format!("matches parent route segment '{parent}'"));
            }
            if !parameter.is_empty()
                && (symbol_lower.contains(&parameter) || qualified_lower.contains(&parameter))
            {
                score += 0.16;
                reasons.push(format!("matches parameter '{parameter}'"));
            }
            if path_lower.contains("controller")
                || path_lower.contains("handler")
                || path_lower.contains("route")
                || path_lower.contains("api")
            {
                score += 0.10;
                reasons.push("file path resembles a route/controller/handler".to_string());
            }
            if !method.is_empty()
                && (symbol_lower.starts_with(&method)
                    || qualified_lower.contains(&format!(".{method}")))
            {
                score += 0.06;
                reasons.push(format!("symbol naming is compatible with HTTP {method}"));
            }
            if language.as_deref().is_some() {
                score += 0.02;
            }
            score = score.min(0.94);
            if score < 0.38 {
                continue;
            }
            let key = (file_id.clone(), symbol_id.clone());
            let ranked = Ranked {
                file_id,
                relative_path,
                symbol_id,
                symbol_name,
                score,
                reasons,
            };
            match best.get(&key) {
                Some(existing) if existing.score >= ranked.score => {}
                _ => {
                    best.insert(key, ranked);
                }
            }
        }

        let mut ranked: Vec<Ranked> = best.into_values().collect();
        ranked.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(left.relative_path.cmp(&right.relative_path))
                .then(left.symbol_name.cmp(&right.symbol_name))
        });
        ranked.truncate(bounded_limit(limit).min(8));

        let tx = self.database.connection().unchecked_transaction()?;
        tx.execute(
            "DELETE FROM guided_security_source_candidates WHERE finding_id=?1",
            [finding_id],
        )?;
        for (index, item) in ranked.iter().enumerate() {
            let id = random_id_from_connection(&tx, "guidesrc")?;
            tx.execute(
                "INSERT INTO guided_security_source_candidates(
                    id, finding_id, rank, file_id, symbol_id, confidence, rationale
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    finding_id,
                    (index + 1) as i64,
                    item.file_id,
                    item.symbol_id,
                    item.score,
                    bounded_text(
                        &if item.reasons.is_empty() {
                            "Heuristic source correlation from the imported project index.".to_string()
                        } else {
                            item.reasons.join("; ")
                        },
                        2_000,
                    ),
                ],
            )?;
        }
        tx.commit()?;
        self.list_source_candidates(finding_id, limit)
    }

    pub fn list_source_candidates(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<GuidedSourceCandidate>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT g.id, g.finding_id, g.rank, g.file_id, f.relative_path,
                    g.symbol_id, s.name, g.confidence, g.rationale, g.created_at
             FROM guided_security_source_candidates g
             JOIN files f ON f.id=g.file_id
             LEFT JOIN symbols s ON s.id=g.symbol_id
             WHERE g.finding_id=?1
             ORDER BY g.rank ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![finding_id, bounded_limit(limit) as i64],
            |row| {
                Ok(GuidedSourceCandidate {
                    id: row.get(0)?,
                    finding_id: row.get(1)?,
                    rank: row.get::<_, i64>(2)? as usize,
                    file_id: row.get(3)?,
                    relative_path: row.get(4)?,
                    symbol_id: row.get(5)?,
                    symbol_name: row.get(6)?,
                    confidence: row.get(7)?,
                    rationale: row.get(8)?,
                    created_at: row.get(9)?,
                })
            },
        )?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn set_finding_lifecycle(
        &self,
        finding_id: &str,
        session_id: Option<&str>,
        state: &str,
    ) -> Result<(), GuidedSecurityError> {
        if !matches!(
            state,
            "open"
                | "fix_proposed"
                | "fix_applied"
                | "retest_passed"
                | "still_vulnerable"
                | "unable_to_verify"
        ) {
            return Err(GuidedSecurityError::InvalidConfig(
                "unsupported guided finding lifecycle state".to_string(),
            ));
        }
        self.database.connection().execute(
            "INSERT INTO guided_security_finding_lifecycle(finding_id, session_id, state)
             VALUES (?1,?2,?3)
             ON CONFLICT(finding_id) DO UPDATE SET
               session_id=COALESCE(excluded.session_id,guided_security_finding_lifecycle.session_id),
               state=excluded.state,
               updated_at=CURRENT_TIMESTAMP",
            params![finding_id, session_id, state],
        )?;
        Ok(())
    }

    pub fn record_retest(
        &self,
        input: GuidedRetestInput<'_>,
    ) -> Result<GuidedRetestRecord, GuidedSecurityError> {
        if !matches!(
            input.status,
            "retest_passed" | "still_vulnerable" | "unable_to_verify"
        ) {
            return Err(GuidedSecurityError::InvalidConfig(
                "unsupported retest status".to_string(),
            ));
        }
        let detail_value = serde_json::from_str::<serde_json::Value>(input.detail_json)?;
        reject_sensitive_json(&detail_value, "guided retest")?;
        let id = self.random_id("guideretest")?;
        self.database.connection().execute(
            "INSERT INTO guided_security_retests(
                id, finding_id, session_id, status, original_confidence,
                observed_confidence, requests_performed, detail_json
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id,
                input.finding_id,
                input.session_id,
                input.status,
                input.original_confidence,
                input.observed_confidence,
                input.requests_performed as i64,
                bounded_text(input.detail_json, 64_000),
            ],
        )?;
        self.set_finding_lifecycle(input.finding_id, input.session_id, input.status)?;
        if let Some(session_id) = input.session_id {
            self.append_activity(
                session_id,
                "finding_retested",
                "retest",
                &format!("Finding retest completed with status {}.", input.status),
                &json!({"finding_id": input.finding_id, "requests_performed": input.requests_performed}).to_string(),
            )?;
        }
        self.database.connection().query_row(
            "SELECT id, finding_id, session_id, status, original_confidence,
                    observed_confidence, requests_performed, detail_json, created_at
             FROM guided_security_retests WHERE id=?1",
            [id],
            map_retest,
        ).map_err(Into::into)
    }

    pub fn list_retests(
        &self,
        finding_id: &str,
        limit: usize,
    ) -> Result<Vec<GuidedRetestRecord>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id, finding_id, session_id, status, original_confidence,
                    observed_confidence, requests_performed, detail_json, created_at
             FROM guided_security_retests WHERE finding_id=?1
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![finding_id, bounded_limit(limit) as i64],
            map_retest,
        )?;
        let mut output = Vec::new();
        for row in rows {
            output.push(row?);
        }
        Ok(output)
    }

    pub fn compare_scans(
        &self,
        session_id: Option<&str>,
        previous_scan_id: &str,
        current_scan_id: &str,
    ) -> Result<GuidedScanComparison, GuidedSecurityError> {
        if previous_scan_id == current_scan_id {
            return Err(GuidedSecurityError::InvalidConfig(
                "scan comparison requires two different scans".to_string(),
            ));
        }
        let previous = self.finding_snapshot(previous_scan_id)?;
        let current = self.finding_snapshot(current_scan_id)?;
        let previous_keys: BTreeSet<String> = previous.keys().cloned().collect();
        let current_keys: BTreeSet<String> = current.keys().cloned().collect();

        let new_findings: Vec<String> = current_keys
            .difference(&previous_keys)
            .cloned()
            .collect();
        let resolved_findings: Vec<String> = previous_keys
            .difference(&current_keys)
            .cloned()
            .collect();
        let persistent_findings: Vec<String> = previous_keys
            .intersection(&current_keys)
            .cloned()
            .collect();
        let mut changed_confidence = Vec::new();
        for fingerprint in &persistent_findings {
            let before = previous.get(fingerprint).map(|value| value.1.clone()).unwrap_or_default();
            let after = current.get(fingerprint).map(|value| value.1.clone()).unwrap_or_default();
            if before != after {
                changed_confidence.push(json!({
                    "fingerprint": fingerprint,
                    "before": before,
                    "after": after,
                }));
            }
        }
        let (previous_endpoints, previous_requests) = self.scan_coverage(previous_scan_id)?;
        let (current_endpoints, current_requests) = self.scan_coverage(current_scan_id)?;
        let comparison = json!({
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "persistent_findings": persistent_findings,
            "changed_confidence": changed_confidence,
            "coverage": {
                "previous": {
                    "endpoints": previous_endpoints,
                    "requests": previous_requests,
                },
                "current": {
                    "endpoints": current_endpoints,
                    "requests": current_requests,
                },
                "endpoint_delta": current_endpoints as i64 - previous_endpoints as i64,
                "request_delta": current_requests as i64 - previous_requests as i64,
            }
        });
        let id = self.random_id("guidecmp")?;
        let serialized = serde_json::to_string(&comparison)?;
        self.database.connection().execute(
            "INSERT INTO guided_security_comparisons(
                id, session_id, previous_scan_id, current_scan_id, comparison_json
             ) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(previous_scan_id,current_scan_id) DO UPDATE SET
                session_id=COALESCE(excluded.session_id,guided_security_comparisons.session_id),
                comparison_json=excluded.comparison_json",
            params![
                id,
                session_id,
                previous_scan_id,
                current_scan_id,
                serialized,
            ],
        )?;
        self.database.connection().query_row(
            "SELECT id, session_id, previous_scan_id, current_scan_id, comparison_json, created_at
             FROM guided_security_comparisons
             WHERE previous_scan_id=?1 AND current_scan_id=?2",
            params![previous_scan_id, current_scan_id],
            |row| {
                Ok(GuidedScanComparison {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    previous_scan_id: row.get(2)?,
                    current_scan_id: row.get(3)?,
                    comparison_json: row.get(4)?,
                    created_at: row.get(5)?,
                })
            },
        ).map_err(Into::into)
    }

    pub fn scorecard(
        &self,
        session_id: &str,
    ) -> Result<GuidedSecurityScorecard, GuidedSecurityError> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))?;
        let Some(scan_id) = session.scan_id.as_deref() else {
            return Ok(GuidedSecurityScorecard {
                endpoints_mapped: 0,
                endpoints_tested: 0,
                coverage_percent: 0.0,
                confirmed_findings: 0,
                likely_findings: 0,
                potential_findings: 0,
                rejected_anomalies: 0,
                by_severity: BTreeMap::new(),
                authentication_context_supplied: false,
                authenticated_endpoints_mapped: mapped_auth_endpoints(&session.application_map_json),
                planned_authorization_checks: count_plan(self.database, session_id, "access_control")?,
                authorization_plan_coverage_percent: plan_coverage(
                    self.database,
                    session_id,
                    &["access_control"],
                )?,
                planned_api_validation_checks: count_plan(self.database, session_id, "api_validation")?,
                api_validation_plan_coverage_percent: plan_coverage(
                    self.database,
                    session_id,
                    &["api_validation"],
                )?,
                planned_input_checks: count_input_plan(self.database, session_id)?,
                input_plan_coverage_percent: plan_coverage(
                    self.database,
                    session_id,
                    &[
                        "sql_injection",
                        "xss",
                        "path_traversal",
                        "ssrf",
                        "template_injection",
                        "api_validation",
                    ],
                )?,
            });
        };
        let endpoints_mapped: i64 = self.database.connection().query_row(
            "SELECT COUNT(*) FROM web_security_endpoints WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        let endpoints_tested: i64 = self.database.connection().query_row(
            "SELECT COUNT(*) FROM web_security_endpoints WHERE scan_id=?1 AND status_code IS NOT NULL",
            [scan_id],
            |row| row.get(0),
        )?;
        let mut by_severity = BTreeMap::new();
        let mut statement = self.database.connection().prepare(
            "SELECT severity, COUNT(*) FROM web_security_findings WHERE scan_id=?1 GROUP BY severity",
        )?;
        for row in statement.query_map([scan_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))? {
            let (severity, count) = row?;
            by_severity.insert(severity, count as usize);
        }
        let confidence_count = |confidence: &str| -> Result<usize, GuidedSecurityError> {
            let value: i64 = self.database.connection().query_row(
                "SELECT COUNT(*) FROM web_security_findings WHERE scan_id=?1 AND confidence=?2",
                params![scan_id, confidence],
                |row| row.get(0),
            )?;
            Ok(value as usize)
        };
        let rejected: i64 = self.database.connection().query_row(
            "SELECT COUNT(*) FROM web_security_findings wf
             LEFT JOIN guided_security_finding_lifecycle gl ON gl.finding_id=wf.id
             WHERE wf.scan_id=?1 AND (wf.status='false_positive' OR gl.state='retest_passed')",
            [scan_id],
            |row| row.get(0),
        )?;
        let auth_metadata: String = self.database.connection().query_row(
            "SELECT auth_metadata_json FROM web_security_scans WHERE id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        let auth_value: serde_json::Value = serde_json::from_str(&auth_metadata).unwrap_or_default();
        let auth_supplied = auth_value
            .pointer("/primary/cookie_supplied")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || auth_value
                .pointer("/primary/bearer_supplied")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            || auth_value
                .pointer("/primary/custom_header_names")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|value| !value.is_empty());

        let mapped = endpoints_mapped.max(0) as usize;
        let tested = endpoints_tested.max(0) as usize;
        Ok(GuidedSecurityScorecard {
            endpoints_mapped: mapped,
            endpoints_tested: tested,
            coverage_percent: if mapped == 0 {
                0.0
            } else {
                ((tested as f64 / mapped as f64) * 1000.0).round() / 10.0
            },
            confirmed_findings: confidence_count("Confirmed")?,
            likely_findings: confidence_count("Likely")?,
            potential_findings: confidence_count("Potential")?,
            rejected_anomalies: rejected.max(0) as usize,
            by_severity,
            authentication_context_supplied: auth_supplied,
            authenticated_endpoints_mapped: mapped_auth_endpoints(&session.application_map_json),
            planned_authorization_checks: count_plan(self.database, session_id, "access_control")?,
            authorization_plan_coverage_percent: plan_coverage(
                self.database,
                session_id,
                &["access_control"],
            )?,
            planned_api_validation_checks: count_plan(self.database, session_id, "api_validation")?,
            api_validation_plan_coverage_percent: plan_coverage(
                self.database,
                session_id,
                &["api_validation"],
            )?,
            planned_input_checks: count_input_plan(self.database, session_id)?,
            input_plan_coverage_percent: plan_coverage(
                self.database,
                session_id,
                &[
                    "sql_injection",
                    "xss",
                    "path_traversal",
                    "ssrf",
                    "template_injection",
                    "api_validation",
                ],
            )?,
        })
    }

    pub fn risk_graph(
        &self,
        session_id: &str,
    ) -> Result<GuidedRiskGraph, GuidedSecurityError> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| GuidedSecurityError::SessionNotFound(session_id.to_string()))?;
        let Some(scan_id) = session.scan_id.as_deref() else {
            return Ok(GuidedRiskGraph {
                nodes: Vec::new(),
                edges: Vec::new(),
            });
        };
        let auth_metadata: String = self.database.connection().query_row(
            "SELECT auth_metadata_json FROM web_security_scans WHERE id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        let auth_value: serde_json::Value = serde_json::from_str(&auth_metadata).unwrap_or_default();
        let authenticated = auth_value
            .pointer("/primary/cookie_supplied")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            || auth_value
                .pointer("/primary/bearer_supplied")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        let actor_id = "actor".to_string();
        let mut nodes = vec![GuidedRiskNode {
            id: actor_id.clone(),
            kind: "actor".to_string(),
            label: if authenticated {
                "Authenticated test user".to_string()
            } else {
                "Unauthenticated user".to_string()
            },
        }];
        let mut edges = Vec::new();
        let mut seen_nodes = BTreeSet::new();
        seen_nodes.insert(actor_id.clone());

        let mut statement = self.database.connection().prepare(
            "SELECT id, endpoint_url, category, title, confidence
             FROM web_security_findings
             WHERE scan_id=?1 AND status<>'false_positive'
             ORDER BY endpoint_url, category LIMIT 200",
        )?;
        let rows = statement.query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (finding_id, endpoint, category, title, confidence) = row?;
            let endpoint_id = format!("endpoint:{endpoint}");
            if seen_nodes.insert(endpoint_id.clone()) {
                nodes.push(GuidedRiskNode {
                    id: endpoint_id.clone(),
                    kind: "endpoint".to_string(),
                    label: endpoint.clone(),
                });
                edges.push(GuidedRiskEdge {
                    from: actor_id.clone(),
                    to: endpoint_id.clone(),
                    relationship: "authorized request path".to_string(),
                });
            }
            let finding_node = format!("finding:{finding_id}");
            nodes.push(GuidedRiskNode {
                id: finding_node.clone(),
                kind: "observed_finding".to_string(),
                label: format!("{title} ({confidence})"),
            });
            edges.push(GuidedRiskEdge {
                from: endpoint_id,
                to: finding_node.clone(),
                relationship: "observed security signal".to_string(),
            });
            let boundary = boundary_for_category(&category);
            let boundary_id = format!("boundary:{boundary}");
            if seen_nodes.insert(boundary_id.clone()) {
                nodes.push(GuidedRiskNode {
                    id: boundary_id.clone(),
                    kind: "defensive_boundary".to_string(),
                    label: boundary.to_string(),
                });
            }
            edges.push(GuidedRiskEdge {
                from: finding_node,
                to: boundary_id,
                relationship: "may weaken defensive boundary".to_string(),
            });
        }
        Ok(GuidedRiskGraph { nodes, edges })
    }

    pub fn prepare_fix(
        &self,
        finding_id: &str,
    ) -> Result<GuidedFixPreparation, GuidedSecurityError> {
        let finding = self.finding_context(finding_id)?;
        let project_id = finding
            .project_id
            .clone()
            .ok_or_else(|| GuidedSecurityError::InvalidConfig(
                "Prepare Fix requires an associated imported CodeTwin project".to_string(),
            ))?;
        let candidates = self.correlate_source_candidates(finding_id, 5)?;
        if candidates.is_empty() {
            return Err(GuidedSecurityError::InvalidConfig(
                "no source candidate could be correlated strongly enough to prepare a repair plan"
                    .to_string(),
            ));
        }
        let title = format!("Security fix: {}", bounded_text(&finding.title, 180));
        let rationale = format!(
            "Runtime finding: {} {}\nCategory: {}\nConfidence: {}\nObserved: {}\nRemediation: {}\n\nSource candidates are heuristic and must be reviewed before any file replacement is added.",
            finding.method,
            finding.endpoint_url,
            finding.category,
            finding.confidence,
            finding.description,
            finding.remediation,
        );
        let repair = VerifiedRepairService::new(self.database)
            .create_plan(&project_id, None, &title, &rationale)
            .map_err(|error| GuidedSecurityError::Repair(error.to_string()))?;
        self.database.connection().execute(
            "INSERT INTO guided_security_fix_links(finding_id, repair_id, state)
             VALUES (?1,?2,'fix_proposed')
             ON CONFLICT(finding_id) DO UPDATE SET
                repair_id=excluded.repair_id, state='fix_proposed', updated_at=CURRENT_TIMESTAMP",
            params![finding_id, repair.id],
        )?;
        self.set_finding_lifecycle(finding_id, finding.session_id.as_deref(), "fix_proposed")?;
        if let Some(session_id) = finding.session_id.as_deref() {
            self.append_activity(
                session_id,
                "fix_prepared",
                "remediation",
                "Draft repair plan prepared from the runtime finding. No source file was modified.",
                &json!({"finding_id": finding_id, "repair_id": repair.id}).to_string(),
            )?;
        }
        Ok(GuidedFixPreparation {
            finding_id: finding_id.to_string(),
            project_id,
            repair,
            source_candidates: candidates,
            remediation: finding.remediation,
        })
    }

    fn finding_snapshot(
        &self,
        scan_id: &str,
    ) -> Result<BTreeMap<String, (String, String)>, GuidedSecurityError> {
        let mut statement = self.database.connection().prepare(
            "SELECT fingerprint, severity, confidence
             FROM web_security_findings
             WHERE scan_id=?1 AND status<>'false_positive'",
        )?;
        let rows = statement.query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut output = BTreeMap::new();
        for row in rows {
            let (fingerprint, severity, confidence) = row?;
            output.insert(fingerprint, (severity, confidence));
        }
        Ok(output)
    }

    fn scan_coverage(&self, scan_id: &str) -> Result<(usize, usize), GuidedSecurityError> {
        self.database.connection().query_row(
            "SELECT endpoints_discovered, requests_performed FROM web_security_scans WHERE id=?1",
            [scan_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as usize,
                    row.get::<_, i64>(1)?.max(0) as usize,
                ))
            },
        ).optional()?
        .ok_or_else(|| GuidedSecurityError::InvalidConfig(format!("scan not found: {scan_id}")))
    }

    fn finding_context(&self, finding_id: &str) -> Result<FindingContext, GuidedSecurityError> {
        self.database.connection().query_row(
            "SELECT ws.project_id, gs.id,
                    wf.category, wf.confidence, wf.endpoint_url, wf.method,
                    wf.parameter_name, wf.title, wf.description, wf.remediation
             FROM web_security_findings wf
             JOIN web_security_scans ws ON ws.id=wf.scan_id
             LEFT JOIN guided_security_sessions gs ON gs.scan_id=wf.scan_id
             WHERE wf.id=?1",
            [finding_id],
            |row| {
                Ok(FindingContext {
                    project_id: row.get(0)?,
                    session_id: row.get(1)?,
                    category: row.get(2)?,
                    confidence: row.get(3)?,
                    endpoint_url: row.get(4)?,
                    method: row.get(5)?,
                    parameter_name: row.get(6)?,
                    title: row.get(7)?,
                    description: row.get(8)?,
                    remediation: row.get(9)?,
                })
            },
        ).optional()?
        .ok_or_else(|| GuidedSecurityError::FindingNotFound(finding_id.to_string()))
    }

    fn random_id(&self, prefix: &str) -> Result<String, GuidedSecurityError> {
        random_id_from_connection(self.database.connection(), prefix)
    }
}

#[derive(Debug)]
struct FindingContext {
    project_id: Option<String>,
    session_id: Option<String>,
    category: String,
    confidence: String,
    endpoint_url: String,
    method: String,
    parameter_name: Option<String>,
    title: String,
    description: String,
    remediation: String,
}

fn reject_sensitive_json(
    value: &serde_json::Value,
    context: &str,
) -> Result<(), GuidedSecurityError> {
    fn visit(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
                let normalized = key
                    .trim()
                    .to_ascii_lowercase()
                    .replace('-', "_");
                matches!(
                    normalized.as_str(),
                    "authorization"
                        | "proxy_authorization"
                        | "cookie"
                        | "set_cookie"
                        | "cookie_header"
                        | "bearer_token"
                        | "api_key"
                        | "x_api_key"
                        | "password"
                        | "passwd"
                        | "secret"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                        | "session_token"
                ) || visit(value)
            }),
            serde_json::Value::Array(items) => items.iter().any(visit),
            _ => false,
        }
    }

    if visit(value) {
        return Err(GuidedSecurityError::InvalidConfig(format!(
            "{context} must not persist authentication or secret material"
        )));
    }
    Ok(())
}

fn validate_session_input(input: &GuidedSessionCreate) -> Result<(), GuidedSecurityError> {
    if !input.authorization_confirmed {
        return Err(GuidedSecurityError::InvalidConfig(
            "explicit authorization confirmation is required".to_string(),
        ));
    }
    if !matches!(
        input.environment.as_str(),
        "local" | "development" | "staging" | "authorized_production"
    ) {
        return Err(GuidedSecurityError::InvalidConfig(
            "unsupported environment".to_string(),
        ));
    }
    if !matches!(
        input.testing_depth.as_str(),
        "quick" | "standard" | "deep" | "custom"
    ) {
        return Err(GuidedSecurityError::InvalidConfig(
            "unsupported testing depth".to_string(),
        ));
    }
    if !matches!(
        input.auth_mode.as_str(),
        "none" | "existing_session" | "test_account_a" | "test_accounts_a_b"
    ) {
        return Err(GuidedSecurityError::InvalidConfig(
            "unsupported authentication mode".to_string(),
        ));
    }
    let target = Url::parse(input.target_url.trim())
        .map_err(|error| GuidedSecurityError::InvalidConfig(error.to_string()))?;
    if !matches!(target.scheme(), "http" | "https") || target.host_str().is_none() {
        return Err(GuidedSecurityError::InvalidConfig(
            "target must be an absolute HTTP(S) URL".to_string(),
        ));
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err(GuidedSecurityError::InvalidConfig(
            "target URL must not contain credentials".to_string(),
        ));
    }
    Ok(())
}

fn validate_plan_item(item: &GuidedPlanItemInput) -> Result<(), GuidedSecurityError> {
    if !matches!(item.risk.as_str(), "SAFE" | "CAUTION" | "RESTRICTED") {
        return Err(GuidedSecurityError::InvalidConfig(
            "unsupported plan risk".to_string(),
        ));
    }
    if item.risk == "RESTRICTED" && item.selected {
        return Err(GuidedSecurityError::InvalidConfig(
            "restricted plan operations cannot be selected".to_string(),
        ));
    }
    Ok(())
}

fn normalized_url(raw: &str) -> Result<String, GuidedSecurityError> {
    let mut url = Url::parse(raw.trim())
        .map_err(|error| GuidedSecurityError::InvalidConfig(error.to_string()))?;
    url.set_fragment(None);
    Ok(url.to_string())
}

fn map_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<GuidedSecuritySessionRecord> {
    Ok(GuidedSecuritySessionRecord {
        id: row.get(0)?,
        website_id: row.get(1)?,
        project_id: row.get(2)?,
        target_url: row.get(3)?,
        environment: row.get(4)?,
        testing_depth: row.get(5)?,
        auth_mode: row.get(6)?,
        status: row.get(7)?,
        authorization_confirmed: row.get::<_, i64>(8)? != 0,
        config_json: row.get(9)?,
        preflight_json: row.get(10)?,
        application_map_json: row.get(11)?,
        plan_json: row.get(12)?,
        mapping_requests: row.get::<_, i64>(13)?.max(0) as usize,
        scan_id: row.get(14)?,
        last_error: row.get(15)?,
        created_at: row.get(16)?,
        prepared_at: row.get(17)?,
        approved_at: row.get(18)?,
        started_at: row.get(19)?,
        finished_at: row.get(20)?,
        updated_at: row.get(21)?,
    })
}

fn map_retest(row: &rusqlite::Row<'_>) -> rusqlite::Result<GuidedRetestRecord> {
    Ok(GuidedRetestRecord {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        session_id: row.get(2)?,
        status: row.get(3)?,
        original_confidence: row.get(4)?,
        observed_confidence: row.get(5)?,
        requests_performed: row.get::<_, i64>(6)?.max(0) as usize,
        detail_json: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn random_id_from_connection(
    connection: &rusqlite::Connection,
    prefix: &str,
) -> Result<String, GuidedSecurityError> {
    let random: String = connection.query_row(
        "SELECT lower(hex(randomblob(16)))",
        [],
        |row| row.get(0),
    )?;
    Ok(format!("{prefix}_{random}"))
}

fn bounded_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_LIST)
}

fn bounded_text(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn mapped_auth_endpoints(application_map_json: &str) -> usize {
    serde_json::from_str::<serde_json::Value>(application_map_json)
        .ok()
        .and_then(|value| value.get("authenticated_endpoint_count").and_then(serde_json::Value::as_u64))
        .unwrap_or(0) as usize
}

fn plan_coverage(
    database: &Database,
    session_id: &str,
    categories: &[&str],
) -> Result<f64, GuidedSecurityError> {
    let mut total = 0i64;
    let mut selected = 0i64;
    for category in categories {
        let (category_total, category_selected): (i64, i64) = database
            .connection()
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN selected=1 THEN 1 ELSE 0 END),0)
                 FROM guided_security_plan_items
                 WHERE session_id=?1 AND category=?2",
                params![session_id, category],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
        total += category_total;
        selected += category_selected;
    }
    if total <= 0 {
        return Ok(0.0);
    }
    Ok(((selected.max(0) as f64 / total as f64) * 1000.0).round() / 10.0)
}

fn count_plan(
    database: &Database,
    session_id: &str,
    category: &str,
) -> Result<usize, GuidedSecurityError> {
    let count: i64 = database.connection().query_row(
        "SELECT COUNT(*) FROM guided_security_plan_items
         WHERE session_id=?1 AND category=?2 AND selected=1",
        params![session_id, category],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as usize)
}

fn count_input_plan(
    database: &Database,
    session_id: &str,
) -> Result<usize, GuidedSecurityError> {
    let count: i64 = database.connection().query_row(
        "SELECT COUNT(*) FROM guided_security_plan_items
         WHERE session_id=?1 AND selected=1
           AND category IN ('sql_injection','xss','path_traversal','ssrf','template_injection','api_validation')",
        [session_id],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as usize)
}

fn boundary_for_category(category: &str) -> &'static str {
    match category {
        "sql_injection" | "template_injection" => "Server-side query/execution boundary",
        "xss" => "Browser rendering boundary",
        "csrf" | "access_control" => "Authorization and state-change boundary",
        "open_redirect" => "Navigation trust boundary",
        "path_traversal" => "Filesystem boundary",
        "ssrf" => "Server outbound-network boundary",
        "cors" => "Cross-origin data boundary",
        "session_cookie" => "Session boundary",
        "api_input_validation" => "API validation boundary",
        _ => "Application trust boundary",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GuidedPlanItemInput, GuidedRetestInput, GuidedSecurityStore, GuidedSessionCreate,
        PreparationCompletion,
    };
    use crate::{
        AuthorizedWebSecurityStore, Database, WebFindingInput, WebScanCreate,
    };

    fn create() -> GuidedSessionCreate {
        GuidedSessionCreate {
            website_id: None,
            project_id: None,
            target_url: "http://localhost:3000".into(),
            environment: "local".into(),
            testing_depth: "deep".into(),
            auth_mode: "none".into(),
            authorization_confirmed: true,
            config_json: r#"{"scope":{"authorization_confirmed":true}}"#.into(),
        }
    }

    #[test]
    fn guided_persistence_rejects_secret_bearing_json() {
        let database = Database::open_in_memory().expect("database");
        let store = GuidedSecurityStore::new(&database);
        let mut input = create();
        input.config_json =
            r#"{"scope":{"authorization_confirmed":true},"bearer_token":"should-not-persist"}"#
                .into();
        assert!(store.create_session(&input).is_err());

        let session = store.create_session(&create()).expect("session");
        assert!(store
            .append_activity(
                &session.id,
                "test",
                "preflight",
                "sensitive detail rejected",
                r#"{"cookie":"session=should-not-persist"}"#,
            )
            .is_err());
    }

    #[test]
    fn guided_session_requires_approval_before_execution() {
        let database = Database::open_in_memory().expect("database");
        let store = GuidedSecurityStore::new(&database);
        let session = store.create_session(&create()).expect("session");
        let item = GuidedPlanItemInput {
            operation_key: "op".into(),
            endpoint_url: "http://localhost:3000/search?q=a".into(),
            method: "GET".into(),
            parameter_name: Some("q".into()),
            category: "sql_injection".into(),
            risk: "SAFE".into(),
            selected: true,
            reason: "input check".into(),
            skip_reason: None,
        };
        let prepared = store
            .complete_preparation(PreparationCompletion {
                session_id: &session.id,
                preflight_json: "{}",
                application_map_json: r#"{"endpoint_count":1}"#,
                plan_json: r#"{"selected_count":1}"#,
                mapping_requests: 1,
                plan_items: &[item],
            })
            .expect("prepared");
        assert_eq!(prepared.status, "awaiting_approval");
        assert!(store
            .assert_execution_allowed(
                &session.id,
                "http://localhost:3000",
                &create().config_json,
            )
            .is_err());
        let approved = store.approve_session(&session.id).expect("approved");
        assert_eq!(approved.status, "approved");
        assert!(store
            .assert_execution_allowed(
                &session.id,
                "http://localhost:3000",
                &create().config_json,
            )
            .is_ok());
    }

    #[test]
    fn restricted_plan_items_cannot_be_selected() {
        let database = Database::open_in_memory().expect("database");
        let store = GuidedSecurityStore::new(&database);
        let session = store.create_session(&create()).expect("session");
        let item = GuidedPlanItemInput {
            operation_key: "restricted".into(),
            endpoint_url: "http://localhost:3000/delete".into(),
            method: "DELETE".into(),
            parameter_name: None,
            category: "state_changing_request".into(),
            risk: "RESTRICTED".into(),
            selected: true,
            reason: "destructive".into(),
            skip_reason: None,
        };
        assert!(store
            .complete_preparation(PreparationCompletion {
                session_id: &session.id,
                preflight_json: "{}",
                application_map_json: "{}",
                plan_json: "{}",
                mapping_requests: 0,
                plan_items: &[item],
            })
            .is_err());
    }

    fn create_scan_with_finding(
        database: &Database,
        endpoint: &str,
        confidence: &str,
    ) -> (String, String) {
        let web = AuthorizedWebSecurityStore::new(database);
        let scan = web
            .create_scan(&WebScanCreate {
                website_id: None,
                project_id: None,
                target_url: "http://localhost:3000".into(),
                authorization_confirmed: true,
                scope_json: r#"{"target_url":"http://localhost:3000"}"#.into(),
                config_json: r#"{"scope":{"authorization_confirmed":true}}"#.into(),
                auth_metadata_json: r#"{"primary":{"cookie_supplied":false,"bearer_supplied":false,"custom_header_names":[]}}"#.into(),
            })
            .expect("scan");
        let finding = web
            .record_finding(
                &scan.id,
                &WebFindingInput {
                    fingerprint: format!("fingerprint-{endpoint}"),
                    category: "sql_injection".into(),
                    severity: "high".into(),
                    confidence: confidence.into(),
                    target: "http://localhost:3000".into(),
                    endpoint_url: endpoint.into(),
                    method: "GET".into(),
                    parameter_name: Some("q".into()),
                    title: "Possible SQL injection".into(),
                    description: "test observation".into(),
                    reproduction_summary: "bounded control comparison".into(),
                    impact: "test impact".into(),
                    remediation: "parameterize query".into(),
                    references: vec!["CWE-89".into()],
                    source: None,
                },
            )
            .expect("finding");
        (scan.id, finding.id)
    }

    #[test]
    fn finding_lifecycle_and_retest_history_are_persistent() {
        let database = Database::open_in_memory().expect("database");
        let store = GuidedSecurityStore::new(&database);
        let (scan_id, finding_id) = create_scan_with_finding(
            &database,
            "http://localhost:3000/search?q=hello",
            "Likely",
        );
        let session = store.create_session(&create()).expect("session");
        store
            .complete_preparation(PreparationCompletion {
                session_id: &session.id,
                preflight_json: "{}",
                application_map_json: "{}",
                plan_json: "{}",
                mapping_requests: 1,
                plan_items: &[],
            })
            .expect("prepared");
        store.approve_session(&session.id).expect("approved");
        store.link_scan(&session.id, &scan_id).expect("link scan");

        let retest = store
            .record_retest(GuidedRetestInput {
                finding_id: &finding_id,
                session_id: Some(&session.id),
                status: "retest_passed",
                original_confidence: "Likely",
                observed_confidence: None,
                requests_performed: 3,
                detail_json: r#"{"control":"no anomaly"}"#,
            })
            .expect("retest");
        assert_eq!(retest.status, "retest_passed");
        assert_eq!(retest.requests_performed, 3);
        let history = store.list_retests(&finding_id, 10).expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, retest.id);

        let lifecycle: String = database
            .connection()
            .query_row(
                "SELECT state FROM guided_security_finding_lifecycle WHERE finding_id=?1",
                [&finding_id],
                |row| row.get(0),
            )
            .expect("lifecycle");
        assert_eq!(lifecycle, "retest_passed");
    }

    #[test]
    fn scan_comparison_reports_new_resolved_and_confidence_changes() {
        let database = Database::open_in_memory().expect("database");
        let store = GuidedSecurityStore::new(&database);
        let (previous_scan, _) = create_scan_with_finding(
            &database,
            "http://localhost:3000/search?q=hello",
            "Potential",
        );
        let (current_scan, _) = create_scan_with_finding(
            &database,
            "http://localhost:3000/search?q=hello",
            "Confirmed",
        );

        let comparison = store
            .compare_scans(None, &previous_scan, &current_scan)
            .expect("comparison");
        let value: serde_json::Value =
            serde_json::from_str(&comparison.comparison_json).expect("comparison json");
        assert_eq!(
            value["changed_confidence"]
                .as_array()
                .expect("changed confidence")
                .len(),
            1
        );
        assert_eq!(
            value["persistent_findings"]
                .as_array()
                .expect("persistent")
                .len(),
            1
        );
    }

    #[test]
    fn restart_recovery_does_not_rewrite_completed_history() {
        let database = Database::open_in_memory().expect("database");
        let store = GuidedSecurityStore::new(&database);
        let first = store.create_session(&create()).expect("first");
        let second = store.create_session(&create()).expect("second");
        database
            .connection()
            .execute(
                "UPDATE guided_security_sessions SET status='completed', finished_at=CURRENT_TIMESTAMP WHERE id=?1",
                [&second.id],
            )
            .expect("complete second");
        assert_eq!(store.recover_interrupted_sessions().expect("recover"), 1);
        assert_eq!(store.get_session(&first.id).expect("first").unwrap().status, "failed");
        assert_eq!(store.get_session(&second.id).expect("second").unwrap().status, "completed");
    }
}
