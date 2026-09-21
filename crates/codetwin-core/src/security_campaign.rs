use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    security_fix::{contains_sensitive_text, reject_sensitive_json},
    Database, FixEligibility, SecurityFixAttemptRecord, SecurityFixError, SecurityFixService,
};

const MAX_CAMPAIGN_FINDINGS: usize = 500;
const MAX_EVENTS: usize = 2_000;
const MAX_LIST: usize = 1_000;

#[derive(Debug, Error)]
pub enum SecurityRemediationCampaignError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("security fix error: {0}")]
    SecurityFix(#[from] SecurityFixError),
    #[error("remediation campaign not found: {0}")]
    CampaignNotFound(String),
    #[error("invalid remediation campaign state: {0}")]
    State(String),
    #[error("invalid remediation campaign scope: {0}")]
    Scope(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationCampaignCreate {
    pub session_id: String,
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityRemediationCampaignRecord {
    pub id: String,
    pub session_id: String,
    pub scan_id: String,
    pub project_id: String,
    pub target_url: String,
    pub environment: String,
    pub scope_json: String,
    pub status: String,
    pub selected_count: usize,
    pub plan_revision: usize,
    pub plan_json: String,
    pub plan_hash: Option<String>,
    pub approved_plan_hash: Option<String>,
    pub baseline_json: String,
    pub completion_json: String,
    pub completion_retest_floor_rowid: i64,
    pub completion_verification_started_at: Option<String>,
    pub completion_verification_completed_at: Option<String>,
    pub completion_source_hashes_json: String,
    pub created_at: String,
    pub analyzed_at: Option<String>,
    pub approved_at: Option<String>,
    pub started_at: Option<String>,
    pub paused_at: Option<String>,
    pub finished_at: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityRemediationCampaignFindingRecord {
    pub campaign_id: String,
    pub finding_id: String,
    pub ordinal: usize,
    pub status: String,
    pub eligibility: FixEligibility,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub endpoint_url: String,
    pub source_file_id: Option<String>,
    pub source_symbol_id: Option<String>,
    pub root_file_id: Option<String>,
    pub root_symbol_id: Option<String>,
    pub shared_root_primary_finding_id: Option<String>,
    pub order_reason: String,
    pub depends_on: Vec<String>,
    pub expected_affected: Vec<String>,
    pub retest_floor_rowid: i64,
    pub active_attempt_id: Option<String>,
    pub skip_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityRemediationRelationshipRecord {
    pub id: String,
    pub campaign_id: String,
    pub from_finding_id: String,
    pub to_finding_id: String,
    pub relationship: String,
    pub confidence: f64,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationCampaignEventRecord {
    pub id: String,
    pub campaign_id: String,
    pub sequence: usize,
    pub event_type: String,
    pub message: String,
    pub detail_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationPlanItem {
    pub finding_id: String,
    pub ordinal: usize,
    pub eligibility: FixEligibility,
    pub order_reason: String,
    pub depends_on: Vec<String>,
    pub expected_affected: Vec<String>,
    pub shared_root_primary_finding_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationCampaignPlan {
    pub version: usize,
    pub project_id: String,
    pub scan_id: String,
    pub target_url: String,
    pub environment: String,
    pub scope_sha256: String,
    pub ordered_findings: Vec<SecurityRemediationPlanItem>,
    pub relationship_count: usize,
    pub mutation_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecurityRemediationCampaignSummary {
    pub selected_findings: usize,
    pub verified_fixed: usize,
    pub still_vulnerable: usize,
    pub manual_action_required: usize,
    pub unable_to_verify: usize,
    pub regression_detected: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub queued_or_in_progress: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationBeforeAfterItem {
    pub finding_id: String,
    pub title: String,
    pub endpoint_url: String,
    pub severity: String,
    pub confidence: String,
    pub baseline_status: String,
    pub campaign_status: String,
    pub comparison_status: String,
    pub selected: bool,
    pub attempt_id: Option<String>,
    pub validation_state: Option<String>,
    pub retest_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationRegressionTracking {
    pub finding_id: String,
    pub attempt_id: Option<String>,
    pub generation_status: String,
    pub recommendation: String,
    pub execution_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemediationRollbackAssessment {
    pub finding_id: String,
    pub attempt_id: Option<String>,
    pub allowed: bool,
    pub blocking_findings: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecurityRemediationDebtView {
    pub unresolved_total: usize,
    pub by_severity: BTreeMap<String, usize>,
    pub by_eligibility: BTreeMap<String, usize>,
    pub by_module: BTreeMap<String, usize>,
    pub by_endpoint: BTreeMap<String, usize>,
    pub by_reason: BTreeMap<String, usize>,
}

#[derive(Debug, Clone)]
struct AnalysisNode {
    finding_id: String,
    severity: String,
    confidence: String,
    category: String,
    endpoint_url: String,
    remediation: String,
    source_file_id: Option<String>,
    source_symbol_id: Option<String>,
    root_file_id: Option<String>,
    root_symbol_id: Option<String>,
    root_start_line: Option<usize>,
    root_end_line: Option<usize>,
    root_path: Option<String>,
    eligibility: FixEligibility,
}

#[derive(Debug, Clone)]
struct RelationshipInput {
    from: String,
    to: String,
    relationship: &'static str,
    confidence: f64,
    reason: String,
}

pub struct SecurityRemediationCampaignService<'a> {
    database: &'a Database,
}

impl<'a> SecurityRemediationCampaignService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn create(
        &self,
        input: &SecurityRemediationCampaignCreate,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let finding_ids = dedup_ids(&input.finding_ids);
        if finding_ids.is_empty() {
            return Err(SecurityRemediationCampaignError::Scope(
                "select at least one finding".into(),
            ));
        }
        if finding_ids.len() > MAX_CAMPAIGN_FINDINGS {
            return Err(SecurityRemediationCampaignError::Scope(format!(
                "campaigns are bounded to {MAX_CAMPAIGN_FINDINGS} findings"
            )));
        }

        let session: Option<(Option<String>, String, String, String, Option<String>, i64)> = self
            .database
            .connection()
            .query_row(
                "SELECT project_id,target_url,environment,config_json,scan_id,authorization_confirmed
                 FROM guided_security_sessions WHERE id=?1",
                [&input.session_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let (project_id, session_target, environment, _config_json, scan_id, authorized) = session
            .ok_or_else(|| {
                SecurityRemediationCampaignError::Scope(
                    "campaign requires an existing guided security session".into(),
                )
            })?;
        if authorized != 1 {
            return Err(SecurityRemediationCampaignError::Scope(
                "guided security session is not authorization-bound".into(),
            ));
        }
        let project_id = project_id.ok_or_else(|| {
            SecurityRemediationCampaignError::Scope(
                "campaign requires a project-bound security session".into(),
            )
        })?;
        let scan_id = scan_id.ok_or_else(|| {
            SecurityRemediationCampaignError::Scope(
                "campaign requires a completed security scan".into(),
            )
        })?;

        let scan: Option<(Option<String>, String, String, String, i64)> = self
            .database
            .connection()
            .query_row(
                "SELECT project_id,target_url,status,scope_json,authorization_confirmed
                 FROM web_security_scans WHERE id=?1",
                [&scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let (scan_project_id, target_url, scan_status, scope_json, scan_authorized) = scan
            .ok_or_else(|| {
                SecurityRemediationCampaignError::Scope(
                    "campaign scan no longer exists".into(),
                )
            })?;
        if scan_authorized != 1
            || scan_status != "completed"
            || scan_project_id.as_deref() != Some(project_id.as_str())
            || target_url != session_target
        {
            return Err(SecurityRemediationCampaignError::Scope(
                "campaign session, project, target and completed scan must match exactly".into(),
            ));
        }

        let mut selected = Vec::with_capacity(finding_ids.len());
        let fix_service = SecurityFixService::new(self.database);
        for finding_id in &finding_ids {
            let row: Option<(
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
            )> = self
                .database
                .connection()
                .query_row(
                    "SELECT severity,confidence,category,endpoint_url,status,
                            source_file_id,source_symbol_id,remediation
                     FROM web_security_findings
                     WHERE id=?1 AND scan_id=?2",
                    params![finding_id, scan_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                severity,
                confidence,
                category,
                endpoint_url,
                finding_status,
                source_file_id,
                source_symbol_id,
                remediation,
            )) = row
            else {
                return Err(SecurityRemediationCampaignError::Scope(format!(
                    "finding {finding_id} does not belong to campaign scan {scan_id}"
                )));
            };
            let eligibility = fix_service.evaluate_eligibility(finding_id)?.result;
            let retest_floor_rowid: i64 = self.database.connection().query_row(
                "SELECT COALESCE(MAX(rowid),0) FROM guided_security_retests WHERE finding_id=?1",
                [finding_id],
                |row| row.get(0),
            )?;
            selected.push((
                finding_id.clone(),
                severity,
                confidence,
                category,
                endpoint_url,
                finding_status,
                source_file_id,
                source_symbol_id,
                remediation,
                eligibility,
                retest_floor_rowid,
            ));
        }

        let baseline = json!({
            "scan_id": scan_id,
            "project_id": project_id,
            "target_url": target_url,
            "findings": selected.iter().map(|item| json!({
                "finding_id": item.0,
                "severity": item.1,
                "confidence": item.2,
                "category": item.3,
                "endpoint_url": item.4,
                "status": item.5,
                "source_file_id": item.6,
                "source_symbol_id": item.7,
                "eligibility": item.9,
                "retest_floor_rowid": item.10,
            })).collect::<Vec<_>>(),
        });
        reject_sensitive_json(&baseline)?;
        let baseline_json = serde_json::to_string(&baseline)?;
        let campaign_id = random_id(self.database.connection(), "seccampaign")?;

        let tx = self.database.connection().unchecked_transaction()?;
        tx.execute(
            "INSERT INTO security_remediation_campaigns(
                id,session_id,scan_id,project_id,target_url,environment,scope_json,
                status,selected_count,baseline_json
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,'DRAFT',?8,?9)",
            params![
                campaign_id,
                input.session_id,
                scan_id,
                project_id,
                target_url,
                environment,
                scope_json,
                to_i64(selected.len()),
                baseline_json,
            ],
        )?;
        for (index, item) in selected.iter().enumerate() {
            let initial_status = match item.9 {
                FixEligibility::ManualRemediation => "MANUAL_ACTION_REQUIRED",
                FixEligibility::InsufficientEvidence => "BLOCKED",
                FixEligibility::AutoFixCandidate | FixEligibility::GuidedFixCandidate => "QUEUED",
            };
            tx.execute(
                "INSERT INTO security_remediation_campaign_findings(
                    campaign_id,finding_id,ordinal,status,eligibility,severity,confidence,
                    category,endpoint_url,source_file_id,source_symbol_id,retest_floor_rowid
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    campaign_id,
                    item.0,
                    to_i64(index + 1),
                    initial_status,
                    item.9.as_db(),
                    item.1,
                    item.2,
                    item.3,
                    item.4,
                    item.6,
                    item.7,
                    item.10,
                ],
            )?;
        }
        let event_id = random_id(&tx, "seccampevent")?;
        tx.execute(
            "INSERT INTO security_remediation_campaign_events(
                id,campaign_id,sequence,event_type,message,detail_json
             ) VALUES (?1,?2,1,'campaign_created',
                'Remediation campaign created from explicitly selected findings.',
                ?3)",
            params![
                event_id,
                campaign_id,
                serde_json::to_string(&json!({
                    "selected_count": selected.len(),
                    "scan_id": scan_id,
                }))?
            ],
        )?;
        tx.commit()?;

        self.get(&campaign_id)?
            .ok_or_else(|| SecurityRemediationCampaignError::CampaignNotFound(campaign_id))
    }

    pub fn analyze(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        if campaign.status != "DRAFT" {
            return Err(SecurityRemediationCampaignError::State(format!(
                "relationship analysis requires DRAFT; observed {}",
                campaign.status
            )));
        }
        let mut nodes = self.analysis_nodes(campaign_id)?;
        if nodes.is_empty() {
            return Err(SecurityRemediationCampaignError::State(
                "campaign has no findings".into(),
            ));
        }

        let mut shared_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for node in &nodes {
            if let Some(key) = shared_root_key(node) {
                shared_groups
                    .entry(key)
                    .or_default()
                    .push(node.finding_id.clone());
            }
        }

        nodes.sort_by(|left, right| priority(left).cmp(&priority(right)));
        let position = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.finding_id.clone(), index))
            .collect::<HashMap<_, _>>();

        let mut relationships = Vec::new();
        let mut shared_primary: HashMap<String, String> = HashMap::new();
        let mut expected_affected: HashMap<String, Vec<String>> = HashMap::new();

        for group in shared_groups.values().filter(|group| group.len() > 1) {
            let mut ordered = group.clone();
            ordered.sort_by_key(|id| position.get(id).copied().unwrap_or(usize::MAX));
            let primary = ordered[0].clone();
            expected_affected.insert(primary.clone(), ordered[1..].to_vec());
            for finding_id in ordered.iter().skip(1) {
                shared_primary.insert(finding_id.clone(), primary.clone());
                relationships.push(RelationshipInput {
                    from: primary.clone(),
                    to: finding_id.clone(),
                    relationship: "SHARED_ROOT_CAUSE",
                    confidence: 0.92,
                    reason: "Findings resolve to the same source symbol or the same category/remediation source root; one bounded fix may affect several observations, but each finding still requires independent retest.".into(),
                });
            }
        }

        for left_index in 0..nodes.len() {
            for right_index in (left_index + 1)..nodes.len() {
                let left = &nodes[left_index];
                let right = &nodes[right_index];
                let already_shared = relationships.iter().any(|edge| {
                    edge.relationship == "SHARED_ROOT_CAUSE"
                        && ((edge.from == left.finding_id && edge.to == right.finding_id)
                            || (edge.from == right.finding_id && edge.to == left.finding_id))
                });
                if same_source_overlap(left, right) {
                    relationships.push(RelationshipInput {
                        from: left.finding_id.clone(),
                        to: right.finding_id.clone(),
                        relationship: "SOURCE_OVERLAP",
                        confidence: 0.88,
                        reason: "Ranked root-cause ranges overlap in the same source file; a prior mutation can invalidate the later patch base hash.".into(),
                    });
                } else if left.root_file_id.is_some()
                    && left.root_file_id == right.root_file_id
                    && !already_shared
                {
                    relationships.push(RelationshipInput {
                        from: left.finding_id.clone(),
                        to: right.finding_id.clone(),
                        relationship: "POTENTIAL_CONFLICT",
                        confidence: 0.72,
                        reason: "Findings map to the same source file but not the same proven root-cause range; sequential mutation and fresh patch review are required.".into(),
                    });
                }
                if left.endpoint_url == right.endpoint_url {
                    relationships.push(RelationshipInput {
                        from: left.finding_id.clone(),
                        to: right.finding_id.clone(),
                        relationship: "RETEST_DEPENDENCY",
                        confidence: 0.75,
                        reason: "Findings share an endpoint; the bounded verification pass should retest both observations after relevant source changes.".into(),
                    });
                }
                if left.root_file_id.is_some()
                    && left.root_file_id == right.root_file_id
                    && (is_validation_category(&left.category)
                        || is_validation_category(&right.category))
                {
                    relationships.push(RelationshipInput {
                        from: left.finding_id.clone(),
                        to: right.finding_id.clone(),
                        relationship: "VALIDATION_DEPENDENCY",
                        confidence: 0.66,
                        reason: "A validation or authorization control and another finding share the same source root; validate the foundational control before relying on endpoint-specific behavior.".into(),
                    });
                }
            }
        }

        let mut dependencies: HashMap<String, BTreeSet<String>> = HashMap::new();
        for relationship in &relationships {
            if matches!(
                relationship.relationship,
                "SOURCE_OVERLAP"
                    | "POTENTIAL_CONFLICT"
                    | "VALIDATION_DEPENDENCY"
                    | "SHARED_ROOT_CAUSE"
            ) {
                let from_pos = position
                    .get(&relationship.from)
                    .copied()
                    .unwrap_or(usize::MAX);
                let to_pos = position
                    .get(&relationship.to)
                    .copied()
                    .unwrap_or(usize::MAX);
                let (earlier, later) = if from_pos <= to_pos {
                    (&relationship.from, &relationship.to)
                } else {
                    (&relationship.to, &relationship.from)
                };
                dependencies
                    .entry(later.clone())
                    .or_default()
                    .insert(earlier.clone());
            }
        }

        let plan_items = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let depends_on = dependencies
                    .get(&node.finding_id)
                    .map(|values| values.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                let expected = expected_affected
                    .get(&node.finding_id)
                    .cloned()
                    .unwrap_or_default();
                SecurityRemediationPlanItem {
                    finding_id: node.finding_id.clone(),
                    ordinal: index + 1,
                    eligibility: node.eligibility,
                    order_reason: order_reason(node, &depends_on, &expected),
                    depends_on,
                    expected_affected: expected,
                    shared_root_primary_finding_id: shared_primary
                        .get(&node.finding_id)
                        .cloned(),
                }
            })
            .collect::<Vec<_>>();
        let plan = SecurityRemediationCampaignPlan {
            version: campaign.plan_revision + 1,
            project_id: campaign.project_id.clone(),
            scan_id: campaign.scan_id.clone(),
            target_url: campaign.target_url.clone(),
            environment: campaign.environment.clone(),
            scope_sha256: sha256_hex(campaign.scope_json.as_bytes()),
            ordered_findings: plan_items.clone(),
            relationship_count: relationships.len(),
            mutation_strategy:
                "Sequential source mutation only. Analysis may be parallelized, but each exact patch remains independently reviewed, approved, applied, validated and retested through Fix & Verify."
                    .into(),
        };
        let plan_json = serde_json::to_string(&plan)?;
        let plan_hash = sha256_hex(plan_json.as_bytes());

        let tx = self.database.connection().unchecked_transaction()?;
        let transitioned = tx.execute(
            "UPDATE security_remediation_campaigns
             SET status='ANALYZING',updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='DRAFT'",
            [campaign_id],
        )?;
        if transitioned != 1 {
            return Err(SecurityRemediationCampaignError::State(
                "campaign changed while relationship analysis was being prepared".into(),
            ));
        }
        tx.execute(
            "DELETE FROM security_remediation_campaign_relationships WHERE campaign_id=?1",
            [campaign_id],
        )?;
        for relationship in &relationships {
            let id = random_id(&tx, "seccamprel")?;
            tx.execute(
                "INSERT INTO security_remediation_campaign_relationships(
                    id,campaign_id,from_finding_id,to_finding_id,relationship,confidence,reason
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    campaign_id,
                    relationship.from,
                    relationship.to,
                    relationship.relationship,
                    relationship.confidence,
                    relationship.reason,
                ],
            )?;
        }
        for item in &plan_items {
            let node = nodes
                .iter()
                .find(|node| node.finding_id == item.finding_id)
                .expect("plan item comes from analysis node");
            tx.execute(
                "UPDATE security_remediation_campaign_findings
                 SET ordinal=?3,eligibility=?4,root_file_id=?5,root_symbol_id=?6,
                     shared_root_primary_finding_id=?7,order_reason=?8,depends_on_json=?9,
                     expected_affected_json=?10,updated_at=CURRENT_TIMESTAMP
                 WHERE campaign_id=?1 AND finding_id=?2",
                params![
                    campaign_id,
                    item.finding_id,
                    to_i64(item.ordinal),
                    item.eligibility.as_db(),
                    node.root_file_id,
                    node.root_symbol_id,
                    item.shared_root_primary_finding_id,
                    item.order_reason,
                    serde_json::to_string(&item.depends_on)?,
                    serde_json::to_string(&item.expected_affected)?,
                ],
            )?;
        }
        tx.execute(
            "UPDATE security_remediation_campaigns
             SET status='READY_FOR_REVIEW',plan_revision=?2,plan_json=?3,plan_hash=?4,
                 analyzed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='ANALYZING'",
            params![campaign_id, to_i64(plan.version), plan_json, plan_hash],
        )?;
        tx.commit()?;

        self.append_event(
            campaign_id,
            "relationship_analysis_completed",
            "Finding relationships and deterministic remediation order were generated.",
            &json!({
                "relationship_count": relationships.len(),
                "plan_hash": plan_hash,
                "plan_revision": plan.version,
            }),
        )?;
        self.get(campaign_id)?
            .ok_or_else(|| SecurityRemediationCampaignError::CampaignNotFound(campaign_id.into()))
    }

    pub fn approve_plan(
        &self,
        campaign_id: &str,
        expected_plan_hash: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        if campaign.status != "READY_FOR_REVIEW" {
            return Err(SecurityRemediationCampaignError::State(format!(
                "campaign plan approval requires READY_FOR_REVIEW; observed {}",
                campaign.status
            )));
        }
        let Some(plan_hash) = campaign.plan_hash.as_deref() else {
            return Err(SecurityRemediationCampaignError::State(
                "campaign has no reviewed plan hash".into(),
            ));
        };
        self.assert_plan_integrity(&campaign)?;
        if expected_plan_hash != plan_hash
            || expected_plan_hash.len() != 64
            || !expected_plan_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SecurityRemediationCampaignError::State(
                "campaign plan changed since review".into(),
            ));
        }
        let updated = self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET status='APPROVED',approved_plan_hash=plan_hash,approved_at=CURRENT_TIMESTAMP,
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='READY_FOR_REVIEW' AND plan_hash=?2",
            params![campaign_id, expected_plan_hash],
        )?;
        if updated != 1 {
            return Err(SecurityRemediationCampaignError::State(
                "campaign plan changed since review".into(),
            ));
        }
        self.append_event(
            campaign_id,
            "plan_approved",
            "Developer approved the campaign order and dependency plan. No future code patch was pre-authorized.",
            &json!({"plan_hash": expected_plan_hash}),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn start(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        if campaign.status != "APPROVED" {
            return Err(SecurityRemediationCampaignError::State(format!(
                "campaign start requires APPROVED; observed {}",
                campaign.status
            )));
        }
        self.assert_plan_integrity(&campaign)?;
        if campaign.approved_plan_hash != campaign.plan_hash {
            return Err(SecurityRemediationCampaignError::State(
                "approved campaign plan identity is stale".into(),
            ));
        }
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET status='IN_PROGRESS',started_at=COALESCE(started_at,CURRENT_TIMESTAMP),
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='APPROVED'",
            [campaign_id],
        )?;
        self.append_event(
            campaign_id,
            "campaign_started",
            "Campaign started. Source mutation remains sequential and each patch still requires Fix & Verify approval.",
            &json!({"concurrency": "sequential_mutation"}),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn pause(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        if campaign.status != "IN_PROGRESS" {
            return Err(SecurityRemediationCampaignError::State(format!(
                "campaign pause requires IN_PROGRESS; observed {}",
                campaign.status
            )));
        }
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET status='PAUSED',paused_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='IN_PROGRESS'",
            [campaign_id],
        )?;
        self.append_event(
            campaign_id,
            "campaign_paused",
            "Campaign paused. Existing Fix & Verify history was preserved.",
            &json!({}),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn resume(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        if !matches!(campaign.status.as_str(), "PAUSED" | "BLOCKED") {
            return Err(SecurityRemediationCampaignError::State(format!(
                "campaign resume requires PAUSED or BLOCKED; observed {}",
                campaign.status
            )));
        }
        self.sync(campaign_id)?;

        let findings = self.findings(campaign_id)?;
        let mut stale_attempts = Vec::new();
        let fix = SecurityFixService::new(self.database);
        for finding in &findings {
            let Some(attempt_id) = finding.active_attempt_id.as_deref() else {
                continue;
            };
            let Some(attempt) = fix.get_attempt(attempt_id)? else {
                continue;
            };
            if attempt.status == "approved" && fix.assert_application_allowed(&attempt.id).is_err() {
                stale_attempts.push(attempt.id);
                self.set_finding_state(campaign_id, &finding.finding_id, "BLOCKED")?;
            }
        }
        if !stale_attempts.is_empty() {
            if campaign.status == "PAUSED" {
                self.database.connection().execute(
                    "UPDATE security_remediation_campaigns
                     SET status='BLOCKED',updated_at=CURRENT_TIMESTAMP WHERE id=?1",
                    [campaign_id],
                )?;
            }
            self.append_event(
                campaign_id,
                "resume_blocked_stale_source",
                "Resume detected stale approved patch identity. Affected fixes require regeneration and review.",
                &json!({"attempt_ids": stale_attempts}),
            )?;
            return self.require_campaign(campaign_id);
        }

        let has_regression = findings
            .iter()
            .any(|finding| finding.status == "REGRESSION_DETECTED");
        if has_regression {
            return Err(SecurityRemediationCampaignError::State(
                "campaign remains blocked by a regression-detected finding".into(),
            ));
        }
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET status='IN_PROGRESS',paused_at=NULL,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status IN ('PAUSED','BLOCKED')",
            [campaign_id],
        )?;
        self.append_event(
            campaign_id,
            "campaign_resumed",
            "Campaign resumed after source and approved-patch identity revalidation.",
            &json!({}),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn cancel(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        if matches!(
            campaign.status.as_str(),
            "COMPLETED" | "COMPLETED_WITH_UNRESOLVED_FINDINGS" | "CANCELLED"
        ) {
            return Err(SecurityRemediationCampaignError::State(format!(
                "campaign is already terminal: {}",
                campaign.status
            )));
        }
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET status='CANCELLED',finished_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1",
            [campaign_id],
        )?;
        self.append_event(
            campaign_id,
            "campaign_cancelled",
            "Campaign cancelled without changing immutable Fix & Verify history.",
            &json!({}),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn skip_finding(
        &self,
        campaign_id: &str,
        finding_id: &str,
        reason: &str,
    ) -> Result<SecurityRemediationCampaignFindingRecord, SecurityRemediationCampaignError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(SecurityRemediationCampaignError::State(
                "skipping a finding requires a factual reason".into(),
            ));
        }
        if contains_sensitive_text(reason) {
            return Err(SecurityRemediationCampaignError::State(
                "campaign history must not persist credentials or secret material".into(),
            ));
        }
        let current = self.require_finding(campaign_id, finding_id)?;
        if current.status == "VERIFIED" {
            return Err(SecurityRemediationCampaignError::State(
                "verified findings cannot be replaced with a skipped outcome".into(),
            ));
        }
        self.set_finding_state(campaign_id, finding_id, "SKIPPED")?;
        self.database.connection().execute(
            "UPDATE security_remediation_campaign_findings
             SET skip_reason=?3,updated_at=CURRENT_TIMESTAMP
             WHERE campaign_id=?1 AND finding_id=?2",
            params![campaign_id, finding_id, bounded_text(reason, 2_000)],
        )?;
        self.append_event(
            campaign_id,
            "finding_skipped",
            "Developer explicitly skipped a selected finding.",
            &json!({"finding_id": finding_id, "reason": bounded_text(reason, 2_000)}),
        )?;
        self.require_finding(campaign_id, finding_id)
    }

    pub fn sync(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        let existing = self.findings(campaign_id)?;
        let fix = SecurityFixService::new(self.database);

        // First synchronize each finding strictly from persisted Fix & Verify / targeted-retest
        // evidence. Campaign orchestration never invents a successful security outcome.
        for finding in existing {
            if finding.status == "SKIPPED" {
                continue;
            }
            let attempt = fix.latest_attempt_for_finding(&finding.finding_id)?;
            let latest_retest = self.latest_campaign_retest(
                &finding.finding_id,
                finding.retest_floor_rowid,
            )?;
            let mut target = target_state(&finding, attempt.as_ref(), latest_retest.as_deref());

            if let Some(attempt) = attempt.as_ref() {
                if attempt.status == "approved"
                    && fix.assert_application_allowed(&attempt.id).is_err()
                {
                    target = "BLOCKED";
                }
                self.database.connection().execute(
                    "UPDATE security_remediation_campaign_findings
                     SET active_attempt_id=?3,updated_at=CURRENT_TIMESTAMP
                     WHERE campaign_id=?1 AND finding_id=?2",
                    params![campaign_id, finding.finding_id, attempt.id],
                )?;
            }

            if target != finding.status {
                self.set_finding_state(campaign_id, &finding.finding_id, target)?;
            }
        }

        // Then evaluate dependencies against the just-synchronized state. This prevents a
        // newly detected regression/stale prerequisite from leaving a dependent finding runnable
        // until a later polling cycle.
        let evidence_synced = self.findings(campaign_id)?;
        let evidence_map = evidence_synced
            .iter()
            .map(|finding| (finding.finding_id.clone(), finding.clone()))
            .collect::<HashMap<_, _>>();
        for finding in &evidence_synced {
            if matches!(
                finding.status.as_str(),
                "VERIFIED" | "SKIPPED" | "REGRESSION_DETECTED"
            ) {
                continue;
            }
            let dependency_failed = finding.depends_on.iter().any(|dependency_id| {
                evidence_map.get(dependency_id).is_some_and(|dependency| {
                    matches!(
                        dependency.status.as_str(),
                        "REGRESSION_DETECTED" | "BLOCKED"
                    )
                })
            });
            if dependency_failed && finding.status != "BLOCKED" {
                self.set_finding_state(campaign_id, &finding.finding_id, "BLOCKED")?;
            }
        }

        let refreshed = self.findings(campaign_id)?;
        if campaign.status == "IN_PROGRESS"
            && refreshed
                .iter()
                .any(|finding| finding.status == "REGRESSION_DETECTED")
        {
            self.database.connection().execute(
                "UPDATE security_remediation_campaigns
                 SET status='BLOCKED',updated_at=CURRENT_TIMESTAMP
                 WHERE id=?1 AND status='IN_PROGRESS'",
                [campaign_id],
            )?;
            self.append_event(
                campaign_id,
                "campaign_blocked",
                "Campaign paused dependent work because a remediation produced a regression-detected outcome.",
                &json!({"reason": "REGRESSION_DETECTED"}),
            )?;
        }

        self.require_campaign(campaign_id)
    }

    pub fn begin_completion_verification(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        self.sync(campaign_id)?;
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        if !matches!(campaign.status.as_str(), "IN_PROGRESS" | "BLOCKED") {
            return Err(SecurityRemediationCampaignError::State(format!(
                "final campaign verification requires IN_PROGRESS or BLOCKED; observed {}",
                campaign.status
            )));
        }
        let summary = self.summary(campaign_id)?;
        if summary.queued_or_in_progress > 0 {
            return Err(SecurityRemediationCampaignError::State(
                "finish or explicitly resolve/skip current campaign work before starting final verification".into(),
            ));
        }
        let floor: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(rowid),0) FROM guided_security_retests",
            [],
            |row| row.get(0),
        )?;
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET completion_retest_floor_rowid=?2,
                 completion_verification_started_at=CURRENT_TIMESTAMP,
                 completion_verification_completed_at=NULL,
                 completion_source_hashes_json='{}',
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status IN ('IN_PROGRESS','BLOCKED')",
            params![campaign_id, floor],
        )?;
        self.append_event(
            campaign_id,
            "completion_verification_started",
            "Bounded final verification started for every selected finding within the authorized campaign scope.",
            &json!({
                "selected_count": campaign.selected_count,
                "retest_floor_rowid": floor,
            }),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn finalize_completion_verification(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        if !matches!(campaign.status.as_str(), "IN_PROGRESS" | "BLOCKED") {
            return Err(SecurityRemediationCampaignError::State(format!(
                "final campaign verification requires IN_PROGRESS or BLOCKED; observed {}",
                campaign.status
            )));
        }
        if campaign.completion_verification_started_at.is_none() {
            return Err(SecurityRemediationCampaignError::State(
                "begin final campaign verification before recording completion evidence".into(),
            ));
        }
        let missing = self.completion_retest_missing(
            campaign_id,
            campaign.completion_retest_floor_rowid,
        )?;
        if !missing.is_empty() {
            return Err(SecurityRemediationCampaignError::State(format!(
                "final campaign verification is incomplete; {} selected finding(s) have no fresh persisted targeted retest evidence: {}",
                missing.len(),
                missing.join(", ")
            )));
        }

        self.sync(campaign_id)?;
        let source_hashes = self.completion_source_snapshot(campaign_id)?;
        let source_hashes_json = serde_json::to_string(&source_hashes)?;
        reject_sensitive_json(&serde_json::from_str(&source_hashes_json)?)?;
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET completion_verification_completed_at=CURRENT_TIMESTAMP,
                 completion_source_hashes_json=?2,
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status IN ('IN_PROGRESS','BLOCKED')",
            params![campaign_id, source_hashes_json],
        )?;
        self.append_event(
            campaign_id,
            "completion_verification_completed",
            "Fresh targeted retest evidence was persisted for every selected finding; source identity was snapshotted for completion.",
            &json!({
                "selected_count": campaign.selected_count,
                "source_file_count": source_hashes.len(),
            }),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn complete(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        self.sync(campaign_id)?;
        let campaign = self.require_campaign(campaign_id)?;
        if !matches!(campaign.status.as_str(), "IN_PROGRESS" | "BLOCKED") {
            return Err(SecurityRemediationCampaignError::State(format!(
                "campaign completion requires IN_PROGRESS or BLOCKED; observed {}",
                campaign.status
            )));
        }
        self.assert_scope_binding(&campaign)?;
        if campaign.completion_verification_completed_at.is_none() {
            return Err(SecurityRemediationCampaignError::State(
                "campaign completion requires a fresh bounded verification pass covering every selected finding".into(),
            ));
        }
        let missing = self.completion_retest_missing(
            campaign_id,
            campaign.completion_retest_floor_rowid,
        )?;
        if !missing.is_empty() {
            return Err(SecurityRemediationCampaignError::State(
                "campaign completion verification evidence is incomplete or no longer available".into(),
            ));
        }
        let persisted_hashes: BTreeMap<String, String> =
            serde_json::from_str(&campaign.completion_source_hashes_json)?;
        let current_hashes = self.completion_source_snapshot(campaign_id)?;
        if persisted_hashes != current_hashes {
            return Err(SecurityRemediationCampaignError::State(
                "project source changed after final campaign verification; rerun the bounded selected-finding verification pass".into(),
            ));
        }
        let summary = self.summary(campaign_id)?;
        if summary.queued_or_in_progress > 0 {
            return Err(SecurityRemediationCampaignError::State(
                "campaign still contains queued or in-progress findings; verify, resolve, or explicitly skip them before completion".into(),
            ));
        }
        let final_status = if summary.verified_fixed == summary.selected_findings {
            "COMPLETED"
        } else {
            "COMPLETED_WITH_UNRESOLVED_FINDINGS"
        };
        let completion_json = serde_json::to_string(&summary)?;
        self.database.connection().execute(
            "UPDATE security_remediation_campaigns
             SET status=?2,completion_json=?3,finished_at=CURRENT_TIMESTAMP,
                 updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status IN ('IN_PROGRESS','BLOCKED')",
            params![campaign_id, final_status, completion_json],
        )?;
        self.append_event(
            campaign_id,
            "campaign_completed",
            "Campaign completion recorded from verified per-finding outcomes within the tested scope.",
            &json!({
                "selected_findings": summary.selected_findings,
                "verified_fixed": summary.verified_fixed,
                "still_vulnerable": summary.still_vulnerable,
                "manual_action_required": summary.manual_action_required,
                "unable_to_verify": summary.unable_to_verify,
                "regression_detected": summary.regression_detected,
                "blocked": summary.blocked,
                "skipped": summary.skipped,
            }),
        )?;
        self.require_campaign(campaign_id)
    }

    pub fn get(
        &self,
        campaign_id: &str,
    ) -> Result<Option<SecurityRemediationCampaignRecord>, SecurityRemediationCampaignError> {
        self.database
            .connection()
            .query_row(
                "SELECT id,session_id,scan_id,project_id,target_url,environment,scope_json,status,
                        selected_count,plan_revision,plan_json,plan_hash,approved_plan_hash,
                        baseline_json,completion_json,completion_retest_floor_rowid,
                        completion_verification_started_at,completion_verification_completed_at,
                        completion_source_hashes_json,created_at,analyzed_at,approved_at,started_at,
                        paused_at,finished_at,updated_at
                 FROM security_remediation_campaigns WHERE id=?1",
                [campaign_id],
                map_campaign,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list(
        &self,
        project_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SecurityRemediationCampaignRecord>, SecurityRemediationCampaignError> {
        let limit = to_i64(limit.clamp(1, 200));
        let mut values = Vec::new();
        if let Some(project_id) = project_id {
            let mut statement = self.database.connection().prepare(
                "SELECT id,session_id,scan_id,project_id,target_url,environment,scope_json,status,
                        selected_count,plan_revision,plan_json,plan_hash,approved_plan_hash,
                        baseline_json,completion_json,completion_retest_floor_rowid,
                        completion_verification_started_at,completion_verification_completed_at,
                        completion_source_hashes_json,created_at,analyzed_at,approved_at,started_at,
                        paused_at,finished_at,updated_at
                 FROM security_remediation_campaigns WHERE project_id=?1
                 ORDER BY created_at DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![project_id, limit], map_campaign)?;
            values.extend(rows.collect::<Result<Vec<_>, _>>()?);
        } else {
            let mut statement = self.database.connection().prepare(
                "SELECT id,session_id,scan_id,project_id,target_url,environment,scope_json,status,
                        selected_count,plan_revision,plan_json,plan_hash,approved_plan_hash,
                        baseline_json,completion_json,completion_retest_floor_rowid,
                        completion_verification_started_at,completion_verification_completed_at,
                        completion_source_hashes_json,created_at,analyzed_at,approved_at,started_at,
                        paused_at,finished_at,updated_at
                 FROM security_remediation_campaigns
                 ORDER BY created_at DESC LIMIT ?1",
            )?;
            let rows = statement.query_map([limit], map_campaign)?;
            values.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        Ok(values)
    }

    pub fn findings(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<SecurityRemediationCampaignFindingRecord>, SecurityRemediationCampaignError> {
        let mut statement = self.database.connection().prepare(
            "SELECT campaign_id,finding_id,ordinal,status,eligibility,severity,confidence,category,
                    endpoint_url,source_file_id,source_symbol_id,root_file_id,root_symbol_id,
                    shared_root_primary_finding_id,order_reason,depends_on_json,
                    expected_affected_json,retest_floor_rowid,active_attempt_id,skip_reason,
                    created_at,updated_at
             FROM security_remediation_campaign_findings
             WHERE campaign_id=?1 ORDER BY ordinal",
        )?;
        let rows = statement.query_map([campaign_id], map_campaign_finding)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn relationships(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<SecurityRemediationRelationshipRecord>, SecurityRemediationCampaignError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id,campaign_id,from_finding_id,to_finding_id,relationship,confidence,reason,created_at
             FROM security_remediation_campaign_relationships
             WHERE campaign_id=?1
             ORDER BY confidence DESC,relationship,from_finding_id,to_finding_id",
        )?;
        let rows = statement.query_map([campaign_id], |row| {
            Ok(SecurityRemediationRelationshipRecord {
                id: row.get(0)?,
                campaign_id: row.get(1)?,
                from_finding_id: row.get(2)?,
                to_finding_id: row.get(3)?,
                relationship: row.get(4)?,
                confidence: row.get(5)?,
                reason: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn events(
        &self,
        campaign_id: &str,
        limit: usize,
    ) -> Result<Vec<SecurityRemediationCampaignEventRecord>, SecurityRemediationCampaignError> {
        let mut statement = self.database.connection().prepare(
            "SELECT id,campaign_id,sequence,event_type,message,detail_json,created_at
             FROM security_remediation_campaign_events
             WHERE campaign_id=?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![campaign_id, to_i64(limit.clamp(1, MAX_EVENTS))],
            |row| {
                Ok(SecurityRemediationCampaignEventRecord {
                    id: row.get(0)?,
                    campaign_id: row.get(1)?,
                    sequence: to_usize(row.get(2)?),
                    event_type: row.get(3)?,
                    message: row.get(4)?,
                    detail_json: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn summary(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignSummary, SecurityRemediationCampaignError> {
        let findings = self.findings(campaign_id)?;
        let mut summary = SecurityRemediationCampaignSummary {
            selected_findings: findings.len(),
            ..Default::default()
        };
        for finding in findings {
            match finding.status.as_str() {
                "VERIFIED" => summary.verified_fixed += 1,
                "STILL_VULNERABLE" => summary.still_vulnerable += 1,
                "MANUAL_ACTION_REQUIRED" => summary.manual_action_required += 1,
                "UNABLE_TO_VERIFY" => summary.unable_to_verify += 1,
                "REGRESSION_DETECTED" => summary.regression_detected += 1,
                "BLOCKED" => summary.blocked += 1,
                "SKIPPED" => summary.skipped += 1,
                _ => summary.queued_or_in_progress += 1,
            }
        }
        Ok(summary)
    }

    pub fn before_after(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<SecurityRemediationBeforeAfterItem>, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        let baseline: serde_json::Value = serde_json::from_str(&campaign.baseline_json)?;
        let baseline_findings = baseline
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let baseline_map = baseline_findings
            .into_iter()
            .filter_map(|value| {
                let id = value.get("finding_id")?.as_str()?.to_string();
                Some((id, value))
            })
            .collect::<HashMap<_, _>>();
        let fix = SecurityFixService::new(self.database);

        let mut output = Vec::new();
        for finding in self.findings(campaign_id)? {
            let attempt = if let Some(attempt_id) = finding.active_attempt_id.as_deref() {
                fix.get_attempt(attempt_id)?
            } else {
                None
            };
            let baseline = baseline_map.get(&finding.finding_id);
            let title: String = self.database.connection().query_row(
                "SELECT title FROM web_security_findings WHERE id=?1",
                [&finding.finding_id],
                |row| row.get(0),
            )?;
            output.push(SecurityRemediationBeforeAfterItem {
                finding_id: finding.finding_id,
                title,
                endpoint_url: finding.endpoint_url,
                severity: finding.severity,
                confidence: finding.confidence,
                baseline_status: baseline
                    .and_then(|value| value.get("status"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("open")
                    .to_string(),
                comparison_status: comparison_status_for_campaign_state(&finding.status).into(),
                campaign_status: finding.status,
                selected: true,
                attempt_id: attempt.as_ref().map(|attempt| attempt.id.clone()),
                validation_state: attempt
                    .as_ref()
                    .map(|attempt| attempt.validation_state.clone()),
                retest_state: attempt.as_ref().map(|attempt| attempt.retest_state.clone()),
            });
        }

        if let Some(verification_started_at) =
            campaign.completion_verification_started_at.as_deref()
        {
            let verification_end = campaign
                .completion_verification_completed_at
                .as_deref()
                .unwrap_or("9999-12-31 23:59:59");
            let mut statement = self.database.connection().prepare(
                "SELECT wf.id,wf.title,wf.endpoint_url,wf.severity,wf.confidence,wf.status
                 FROM web_security_findings wf
                 JOIN web_security_scans ws ON ws.id=wf.scan_id
                 WHERE ws.project_id=?1
                   AND ws.target_url=?2
                   AND ws.scope_json=?3
                   AND ws.authorization_confirmed=1
                   AND ws.created_at>=?4
                   AND ws.created_at<=?5
                   AND wf.fingerprint NOT IN (
                     SELECT baseline.fingerprint
                     FROM web_security_findings baseline
                     WHERE baseline.scan_id=?6
                   )
                 ORDER BY wf.first_detected,wf.id
                 LIMIT ?7",
            )?;
            let rows = statement.query_map(
                params![
                    campaign.project_id,
                    campaign.target_url,
                    campaign.scope_json,
                    verification_started_at,
                    verification_end,
                    campaign.scan_id,
                    to_i64(MAX_CAMPAIGN_FINDINGS),
                ],
                |row| {
                    Ok(SecurityRemediationBeforeAfterItem {
                        finding_id: row.get(0)?,
                        title: row.get(1)?,
                        endpoint_url: row.get(2)?,
                        severity: row.get(3)?,
                        confidence: row.get(4)?,
                        baseline_status: "not_observed".into(),
                        campaign_status: row.get(5)?,
                        comparison_status: "NEWLY_OBSERVED_DURING_VERIFICATION".into(),
                        selected: false,
                        attempt_id: None,
                        validation_state: None,
                        retest_state: None,
                    })
                },
            )?;
            output.extend(rows.collect::<Result<Vec<_>, _>>()?);
        }
        Ok(output)
    }

    pub fn regression_tracking(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<SecurityRemediationRegressionTracking>, SecurityRemediationCampaignError> {
        let fix = SecurityFixService::new(self.database);
        self.findings(campaign_id)?
            .into_iter()
            .map(|finding| {
                let attempt = if let Some(attempt_id) = finding.active_attempt_id.as_deref() {
                    fix.get_attempt(attempt_id)?
                } else {
                    None
                };
                let Some(attempt) = attempt else {
                    return Ok(SecurityRemediationRegressionTracking {
                        finding_id: finding.finding_id,
                        attempt_id: None,
                        generation_status: "NOT_PREPARED".into(),
                        recommendation: String::new(),
                        execution_status: "NOT_EXECUTED".into(),
                    });
                };
                let validations = fix.validation_results(&attempt.id, MAX_LIST)?;
                let execution_status = if validations.iter().any(|item| item.status == "FAIL") {
                    "FAILED"
                } else if !validations.is_empty()
                    && validations.iter().all(|item| item.status == "PASS")
                {
                    "PASSED"
                } else {
                    "NOT_EXECUTED"
                };
                Ok(SecurityRemediationRegressionTracking {
                    finding_id: finding.finding_id,
                    attempt_id: Some(attempt.id),
                    generation_status: attempt.test_plan.regression_generation_status,
                    recommendation: attempt.test_plan.regression_test_proposal,
                    execution_status: execution_status.into(),
                })
            })
            .collect()
    }

    pub fn rollback_assessment(
        &self,
        campaign_id: &str,
        finding_id: &str,
    ) -> Result<SecurityRemediationRollbackAssessment, SecurityRemediationCampaignError> {
        let campaign = self.require_campaign(campaign_id)?;
        self.assert_scope_binding(&campaign)?;
        let finding = self.require_finding(campaign_id, finding_id)?;
        let Some(attempt_id) = finding.active_attempt_id.as_deref() else {
            return Ok(SecurityRemediationRollbackAssessment {
                finding_id: finding_id.into(),
                attempt_id: None,
                allowed: false,
                blocking_findings: Vec::new(),
                reason: "No campaign-linked applied Fix & Verify attempt is available to roll back.".into(),
            });
        };
        let fix = SecurityFixService::new(self.database);
        let Some(attempt) = fix.get_attempt(attempt_id)? else {
            return Ok(SecurityRemediationRollbackAssessment {
                finding_id: finding_id.into(),
                attempt_id: Some(attempt_id.into()),
                allowed: false,
                blocking_findings: Vec::new(),
                reason: "The campaign-linked Fix & Verify attempt no longer exists.".into(),
            });
        };
        if attempt.application_run_id.is_none() || attempt.status == "rolled_back" {
            return Ok(SecurityRemediationRollbackAssessment {
                finding_id: finding_id.into(),
                attempt_id: Some(attempt.id),
                allowed: false,
                blocking_findings: Vec::new(),
                reason: "The selected finding has no currently applied repair to roll back.".into(),
            });
        }

        let all = self.findings(campaign_id)?;
        let mut blocking = Vec::new();
        for dependent in all {
            if dependent.finding_id == finding_id || !dependent.depends_on.iter().any(|id| id == finding_id) {
                continue;
            }
            let dependent_applied = if let Some(dependent_attempt_id) = dependent.active_attempt_id.as_deref() {
                fix.get_attempt(dependent_attempt_id)?
                    .is_some_and(|value| value.application_run_id.is_some() && value.status != "rolled_back")
            } else {
                false
            };
            if dependent_applied
                || matches!(
                    dependent.status.as_str(),
                    "VERIFIED"
                        | "VALIDATING"
                        | "RETESTING"
                        | "STILL_VULNERABLE"
                        | "UNABLE_TO_VERIFY"
                        | "REGRESSION_DETECTED"
                )
            {
                blocking.push(dependent.finding_id);
            }
        }
        blocking.sort();
        blocking.dedup();

        if blocking.is_empty() {
            Ok(SecurityRemediationRollbackAssessment {
                finding_id: finding_id.into(),
                attempt_id: Some(attempt.id),
                allowed: true,
                blocking_findings: Vec::new(),
                reason: "No later campaign outcome currently depends on this applied fix. Rollback still uses the individual Fix & Verify / RepairApplicationService path and preserves history.".into(),
            })
        } else {
            Ok(SecurityRemediationRollbackAssessment {
                finding_id: finding_id.into(),
                attempt_id: Some(attempt.id),
                allowed: false,
                blocking_findings: blocking.clone(),
                reason: format!(
                    "Rollback is blocked because {} later campaign finding(s) depend on this fix. Roll back or re-plan dependent work first.",
                    blocking.len()
                ),
            })
        }
    }

    pub fn security_debt(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationDebtView, SecurityRemediationCampaignError> {
        let mut view = SecurityRemediationDebtView::default();
        let fix = SecurityFixService::new(self.database);
        for finding in self.findings(campaign_id)? {
            if finding.status == "VERIFIED" {
                continue;
            }
            view.unresolved_total += 1;
            increment(&mut view.by_severity, &finding.severity);
            increment(&mut view.by_eligibility, finding.eligibility.as_db());
            increment(&mut view.by_endpoint, &finding.endpoint_url);
            let reason = if finding.status == "STILL_VULNERABLE"
                && fix.standard_attempt_limit_reached(&finding.finding_id)?
            {
                "fix attempt limit reached"
            } else {
                unresolved_reason(&finding)
            };
            increment(&mut view.by_reason, reason);

            let module = finding
                .root_file_id
                .as_deref()
                .or(finding.source_file_id.as_deref())
                .and_then(|file_id| {
                    self.database
                        .connection()
                        .query_row(
                            "SELECT relative_path FROM files WHERE id=?1",
                            [file_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .ok()
                        .flatten()
                })
                .unwrap_or_else(|| "unmapped source".into());
            increment(&mut view.by_module, &module);
        }
        Ok(view)
    }

    pub fn append_event(
        &self,
        campaign_id: &str,
        event_type: &str,
        message: &str,
        detail: &serde_json::Value,
    ) -> Result<SecurityRemediationCampaignEventRecord, SecurityRemediationCampaignError> {
        self.require_campaign(campaign_id)?;
        if contains_sensitive_text(message) {
            return Err(SecurityRemediationCampaignError::State(
                "campaign events must not persist credentials or secret material".into(),
            ));
        }
        reject_sensitive_json(detail)?;
        let detail_json = serde_json::to_string(detail)?;
        let sequence: i64 = self.database.connection().query_row(
            "SELECT COALESCE(MAX(sequence),0)+1
             FROM security_remediation_campaign_events WHERE campaign_id=?1",
            [campaign_id],
            |row| row.get(0),
        )?;
        if sequence > MAX_EVENTS as i64 {
            return Err(SecurityRemediationCampaignError::State(
                "campaign event limit reached".into(),
            ));
        }
        let id = random_id(self.database.connection(), "seccampevent")?;
        self.database.connection().execute(
            "INSERT INTO security_remediation_campaign_events(
                id,campaign_id,sequence,event_type,message,detail_json
             ) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                id,
                campaign_id,
                sequence,
                bounded_text(event_type, 120),
                bounded_text(message, 4_000),
                detail_json,
            ],
        )?;
        self.database.connection().query_row(
            "SELECT id,campaign_id,sequence,event_type,message,detail_json,created_at
             FROM security_remediation_campaign_events WHERE id=?1",
            [&id],
            |row| {
                Ok(SecurityRemediationCampaignEventRecord {
                    id: row.get(0)?,
                    campaign_id: row.get(1)?,
                    sequence: to_usize(row.get(2)?),
                    event_type: row.get(3)?,
                    message: row.get(4)?,
                    detail_json: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        ).map_err(Into::into)
    }

    fn analysis_nodes(
        &self,
        campaign_id: &str,
    ) -> Result<Vec<AnalysisNode>, SecurityRemediationCampaignError> {
        let mut statement = self.database.connection().prepare(
            "SELECT cf.finding_id,cf.severity,cf.confidence,cf.category,cf.endpoint_url,
                    wf.remediation,cf.source_file_id,cf.source_symbol_id,cf.eligibility
             FROM security_remediation_campaign_findings cf
             JOIN web_security_findings wf ON wf.id=cf.finding_id
             WHERE cf.campaign_id=?1",
        )?;
        let rows = statement.query_map([campaign_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        let raw = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);

        let fix = SecurityFixService::new(self.database);
        raw.into_iter()
            .map(
                |(
                    finding_id,
                    severity,
                    confidence,
                    category,
                    endpoint_url,
                    remediation,
                    source_file_id,
                    source_symbol_id,
                    stored_eligibility,
                )| {
                    let assessment = fix.evaluate_eligibility(&finding_id)?;
                    let roots = fix.analyze_root_causes(&finding_id)?;
                    let root = roots.first();
                    let eligibility = assessment.result;
                    if FixEligibility::parse(&stored_eligibility)? != eligibility {
                        self.database.connection().execute(
                            "UPDATE security_remediation_campaign_findings
                             SET eligibility=?3,updated_at=CURRENT_TIMESTAMP
                             WHERE campaign_id=?1 AND finding_id=?2",
                            params![campaign_id, finding_id, eligibility.as_db()],
                        )?;
                    }
                    Ok(AnalysisNode {
                        finding_id,
                        severity,
                        confidence,
                        category,
                        endpoint_url,
                        remediation,
                        source_file_id,
                        source_symbol_id,
                        root_file_id: root.map(|root| root.file_id.clone()),
                        root_symbol_id: root.and_then(|root| root.symbol_id.clone()),
                        root_start_line: root.and_then(|root| root.source_start_line),
                        root_end_line: root.and_then(|root| root.source_end_line),
                        root_path: root.map(|root| root.relative_path.clone()),
                        eligibility,
                    })
                },
            )
            .collect()
    }

    fn completion_retest_missing(
        &self,
        campaign_id: &str,
        floor_rowid: i64,
    ) -> Result<Vec<String>, SecurityRemediationCampaignError> {
        let mut statement = self.database.connection().prepare(
            "SELECT cf.finding_id
             FROM security_remediation_campaign_findings cf
             WHERE cf.campaign_id=?1
               AND NOT EXISTS (
                 SELECT 1 FROM guided_security_retests gr
                 WHERE gr.finding_id=cf.finding_id AND gr.rowid>?2
               )
             ORDER BY cf.ordinal",
        )?;
        let rows = statement.query_map(params![campaign_id, floor_rowid], |row| row.get(0))?;
        rows.collect::<Result<Vec<String>, _>>().map_err(Into::into)
    }

    fn completion_source_snapshot(
        &self,
        campaign_id: &str,
    ) -> Result<BTreeMap<String, String>, SecurityRemediationCampaignError> {
        let mut statement = self.database.connection().prepare(
            "WITH referenced_paths(relative_path) AS (
                 SELECT f.relative_path
                 FROM security_remediation_campaign_findings cf
                 JOIN files f ON f.id=cf.root_file_id
                 WHERE cf.campaign_id=?1
                 UNION
                 SELECT f.relative_path
                 FROM security_remediation_campaign_findings cf
                 JOIN files f ON f.id=cf.source_file_id
                 WHERE cf.campaign_id=?1
             )
             SELECT rp.relative_path, COALESCE(active.content_hash,'<missing>')
             FROM referenced_paths rp
             JOIN security_remediation_campaigns c ON c.id=?1
             LEFT JOIN files active
               ON active.project_id=c.project_id
              AND active.relative_path=rp.relative_path
              AND active.is_active=1
             ORDER BY rp.relative_path",
        )?;
        let rows = statement.query_map([campaign_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut output = BTreeMap::new();
        for row in rows {
            let (path, hash) = row?;
            output.insert(path, hash);
        }
        Ok(output)
    }

    fn latest_campaign_retest(
        &self,
        finding_id: &str,
        retest_floor_rowid: i64,
    ) -> Result<Option<String>, SecurityRemediationCampaignError> {
        self.database
            .connection()
            .query_row(
                "SELECT status FROM guided_security_retests
                 WHERE finding_id=?1 AND rowid>?2
                 ORDER BY rowid DESC LIMIT 1",
                params![finding_id, retest_floor_rowid],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn assert_plan_integrity(
        &self,
        campaign: &SecurityRemediationCampaignRecord,
    ) -> Result<(), SecurityRemediationCampaignError> {
        let Some(stored_hash) = campaign.plan_hash.as_deref() else {
            return Err(SecurityRemediationCampaignError::State(
                "campaign has no generated plan hash".into(),
            ));
        };
        if sha256_hex(campaign.plan_json.as_bytes()) != stored_hash {
            return Err(SecurityRemediationCampaignError::State(
                "campaign plan payload changed since relationship analysis".into(),
            ));
        }
        let plan: SecurityRemediationCampaignPlan = serde_json::from_str(&campaign.plan_json)?;
        if plan.version != campaign.plan_revision
            || plan.project_id != campaign.project_id
            || plan.scan_id != campaign.scan_id
            || plan.target_url != campaign.target_url
            || plan.environment != campaign.environment
            || plan.scope_sha256 != sha256_hex(campaign.scope_json.as_bytes())
        {
            return Err(SecurityRemediationCampaignError::State(
                "campaign plan scope identity does not match the authorized campaign".into(),
            ));
        }

        let findings = self.findings(&campaign.id)?;
        if findings.len() != campaign.selected_count
            || plan.ordered_findings.len() != campaign.selected_count
            || plan.relationship_count != self.relationships(&campaign.id)?.len()
        {
            return Err(SecurityRemediationCampaignError::State(
                "campaign plan membership or relationship set changed since analysis".into(),
            ));
        }
        let expected = findings
            .iter()
            .map(|finding| SecurityRemediationPlanItem {
                finding_id: finding.finding_id.clone(),
                ordinal: finding.ordinal,
                eligibility: finding.eligibility,
                order_reason: finding.order_reason.clone(),
                depends_on: finding.depends_on.clone(),
                expected_affected: finding.expected_affected.clone(),
                shared_root_primary_finding_id: finding.shared_root_primary_finding_id.clone(),
            })
            .collect::<Vec<_>>();
        if plan.ordered_findings != expected {
            return Err(SecurityRemediationCampaignError::State(
                "campaign finding order or dependency plan changed since review".into(),
            ));
        }
        Ok(())
    }

    fn assert_scope_binding(
        &self,
        campaign: &SecurityRemediationCampaignRecord,
    ) -> Result<(), SecurityRemediationCampaignError> {
        let session: Option<(Option<String>, String, String, Option<String>, i64)> = self
            .database
            .connection()
            .query_row(
                "SELECT project_id,target_url,environment,scan_id,authorization_confirmed
                 FROM guided_security_sessions WHERE id=?1",
                [&campaign.session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let Some((session_project, session_target, session_environment, session_scan, session_authorized)) = session else {
            return Err(SecurityRemediationCampaignError::Scope(
                "campaign guided security session no longer exists".into(),
            ));
        };
        let scan: Option<(Option<String>, String, String, String, i64)> = self
            .database
            .connection()
            .query_row(
                "SELECT project_id,target_url,status,scope_json,authorization_confirmed
                 FROM web_security_scans WHERE id=?1",
                [&campaign.scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let Some((scan_project, scan_target, scan_status, scan_scope, scan_authorized)) = scan else {
            return Err(SecurityRemediationCampaignError::Scope(
                "campaign security scan no longer exists".into(),
            ));
        };
        if session_authorized != 1
            || scan_authorized != 1
            || scan_status != "completed"
            || session_project.as_deref() != Some(campaign.project_id.as_str())
            || scan_project.as_deref() != Some(campaign.project_id.as_str())
            || session_target != campaign.target_url
            || scan_target != campaign.target_url
            || session_environment != campaign.environment
            || session_scan.as_deref() != Some(campaign.scan_id.as_str())
            || scan_scope != campaign.scope_json
        {
            return Err(SecurityRemediationCampaignError::Scope(
                "campaign project, authorized target, environment, scan or scope binding changed".into(),
            ));
        }
        Ok(())
    }

    fn require_campaign(
        &self,
        campaign_id: &str,
    ) -> Result<SecurityRemediationCampaignRecord, SecurityRemediationCampaignError> {
        self.get(campaign_id)?
            .ok_or_else(|| SecurityRemediationCampaignError::CampaignNotFound(campaign_id.into()))
    }

    fn require_finding(
        &self,
        campaign_id: &str,
        finding_id: &str,
    ) -> Result<SecurityRemediationCampaignFindingRecord, SecurityRemediationCampaignError> {
        self.database
            .connection()
            .query_row(
                "SELECT campaign_id,finding_id,ordinal,status,eligibility,severity,confidence,category,
                        endpoint_url,source_file_id,source_symbol_id,root_file_id,root_symbol_id,
                        shared_root_primary_finding_id,order_reason,depends_on_json,
                        expected_affected_json,retest_floor_rowid,active_attempt_id,skip_reason,
                        created_at,updated_at
                 FROM security_remediation_campaign_findings
                 WHERE campaign_id=?1 AND finding_id=?2",
                params![campaign_id, finding_id],
                map_campaign_finding,
            )
            .optional()?
            .ok_or_else(|| {
                SecurityRemediationCampaignError::Scope(format!(
                    "finding {finding_id} is not a member of campaign {campaign_id}"
                ))
            })
    }

    fn set_finding_state(
        &self,
        campaign_id: &str,
        finding_id: &str,
        status: &str,
    ) -> Result<(), SecurityRemediationCampaignError> {
        let updated = self.database.connection().execute(
            "UPDATE security_remediation_campaign_findings
             SET status=?3,updated_at=CURRENT_TIMESTAMP
             WHERE campaign_id=?1 AND finding_id=?2 AND status<>?3",
            params![campaign_id, finding_id, status],
        )?;
        if updated > 0 {
            self.append_event(
                campaign_id,
                "finding_state_changed",
                "Campaign finding state synchronized from persisted remediation evidence.",
                &json!({"finding_id": finding_id, "status": status}),
            )?;
        }
        Ok(())
    }
}

fn target_state(
    finding: &SecurityRemediationCampaignFindingRecord,
    attempt: Option<&SecurityFixAttemptRecord>,
    latest_retest: Option<&str>,
) -> &'static str {
    if let Some(attempt) = attempt {
        return match attempt.status.as_str() {
            "prepared" => "PREPARING_FIX",
            "patch_proposed" | "rejected" | "approved" => "AWAITING_REVIEW",
            "applied" => "VALIDATING",
            "validation_failed" if attempt.retest_state == "REGRESSION_DETECTED" => {
                "REGRESSION_DETECTED"
            }
            "validation_failed" => "BLOCKED",
            "verification_pending" => "RETESTING",
            "fix_verified" => "VERIFIED",
            "still_vulnerable" => "STILL_VULNERABLE",
            "unable_to_verify" => "UNABLE_TO_VERIFY",
            "rolled_back" => "QUEUED",
            _ => "BLOCKED",
        };
    }
    if let Some(retest) = latest_retest {
        return match retest {
            "retest_passed" => "VERIFIED",
            "still_vulnerable" => "STILL_VULNERABLE",
            "unable_to_verify" => "UNABLE_TO_VERIFY",
            _ => "BLOCKED",
        };
    }
    match finding.eligibility {
        FixEligibility::AutoFixCandidate | FixEligibility::GuidedFixCandidate => "QUEUED",
        FixEligibility::ManualRemediation => "MANUAL_ACTION_REQUIRED",
        FixEligibility::InsufficientEvidence => "BLOCKED",
    }
}

fn map_campaign(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityRemediationCampaignRecord> {
    Ok(SecurityRemediationCampaignRecord {
        id: row.get(0)?,
        session_id: row.get(1)?,
        scan_id: row.get(2)?,
        project_id: row.get(3)?,
        target_url: row.get(4)?,
        environment: row.get(5)?,
        scope_json: row.get(6)?,
        status: row.get(7)?,
        selected_count: to_usize(row.get(8)?),
        plan_revision: to_usize(row.get(9)?),
        plan_json: row.get(10)?,
        plan_hash: row.get(11)?,
        approved_plan_hash: row.get(12)?,
        baseline_json: row.get(13)?,
        completion_json: row.get(14)?,
        completion_retest_floor_rowid: row.get(15)?,
        completion_verification_started_at: row.get(16)?,
        completion_verification_completed_at: row.get(17)?,
        completion_source_hashes_json: row.get(18)?,
        created_at: row.get(19)?,
        analyzed_at: row.get(20)?,
        approved_at: row.get(21)?,
        started_at: row.get(22)?,
        paused_at: row.get(23)?,
        finished_at: row.get(24)?,
        updated_at: row.get(25)?,
    })
}

fn map_campaign_finding(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecurityRemediationCampaignFindingRecord> {
    let eligibility_text: String = row.get(4)?;
    let eligibility = FixEligibility::parse(&eligibility_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let depends_on_json: String = row.get(15)?;
    let expected_json: String = row.get(16)?;
    let depends_on = serde_json::from_str(&depends_on_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            15,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let expected_affected = serde_json::from_str(&expected_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            16,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(SecurityRemediationCampaignFindingRecord {
        campaign_id: row.get(0)?,
        finding_id: row.get(1)?,
        ordinal: to_usize(row.get(2)?),
        status: row.get(3)?,
        eligibility,
        severity: row.get(5)?,
        confidence: row.get(6)?,
        category: row.get(7)?,
        endpoint_url: row.get(8)?,
        source_file_id: row.get(9)?,
        source_symbol_id: row.get(10)?,
        root_file_id: row.get(11)?,
        root_symbol_id: row.get(12)?,
        shared_root_primary_finding_id: row.get(13)?,
        order_reason: row.get(14)?,
        depends_on,
        expected_affected,
        retest_floor_rowid: row.get(17)?,
        active_attempt_id: row.get(18)?,
        skip_reason: row.get(19)?,
        created_at: row.get(20)?,
        updated_at: row.get(21)?,
    })
}

fn priority(node: &AnalysisNode) -> (usize, usize, usize, usize, String, String) {
    (
        actionability_priority(node.eligibility),
        category_priority(&node.category),
        eligibility_priority(node.eligibility),
        severity_priority(&node.severity),
        node.root_path.clone().unwrap_or_default(),
        node.finding_id.clone(),
    )
}

fn actionability_priority(eligibility: FixEligibility) -> usize {
    match eligibility {
        FixEligibility::AutoFixCandidate | FixEligibility::GuidedFixCandidate => 0,
        FixEligibility::ManualRemediation => 3,
        FixEligibility::InsufficientEvidence => 4,
    }
}

fn eligibility_priority(eligibility: FixEligibility) -> usize {
    match eligibility {
        FixEligibility::AutoFixCandidate => 0,
        FixEligibility::GuidedFixCandidate => 1,
        FixEligibility::ManualRemediation => 2,
        FixEligibility::InsufficientEvidence => 3,
    }
}

fn category_priority(category: &str) -> usize {
    match category {
        "access_control" | "authorization" | "idor" => 0,
        "security_headers" | "cors" | "csrf" | "api_input_validation" | "api_validation" => 1,
        "sql_injection" => 2,
        "xss" => 3,
        _ => 4,
    }
}

fn severity_priority(severity: &str) -> usize {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn is_validation_category(category: &str) -> bool {
    matches!(
        category,
        "access_control"
            | "authorization"
            | "idor"
            | "csrf"
            | "api_input_validation"
            | "api_validation"
            | "security_headers"
            | "cors"
    )
}

fn shared_root_key(node: &AnalysisNode) -> Option<String> {
    if let Some(symbol_id) = node
        .root_symbol_id
        .as_ref()
        .or(node.source_symbol_id.as_ref())
    {
        return Some(format!("symbol:{symbol_id}:{}", node.category));
    }
    let file_id = node.root_file_id.as_ref().or(node.source_file_id.as_ref())?;
    let remediation = node
        .remediation
        .split_whitespace()
        .map(|part| part.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!("file:{file_id}:{}:{remediation}", node.category))
}

fn same_source_overlap(left: &AnalysisNode, right: &AnalysisNode) -> bool {
    if left.root_file_id.is_none() || left.root_file_id != right.root_file_id {
        return false;
    }
    match (
        left.root_start_line,
        left.root_end_line,
        right.root_start_line,
        right.root_end_line,
    ) {
        (Some(left_start), Some(left_end), Some(right_start), Some(right_end)) => {
            left_start <= right_end && right_start <= left_end
        }
        _ => false,
    }
}

fn order_reason(node: &AnalysisNode, depends_on: &[String], expected: &[String]) -> String {
    if !expected.is_empty() {
        return format!(
            "Probable shared root cause representative. Review one bounded fix first, then retest {} affected finding(s) independently before generating duplicate patches.",
            expected.len()
        );
    }
    if !depends_on.is_empty() {
        return format!(
            "Ordered after {} dependency finding(s) because source or validation relationships can invalidate a previously prepared patch. Regenerate and review against the new source state.",
            depends_on.len()
        );
    }
    match node.category.as_str() {
        "access_control" | "authorization" | "idor" => {
            "Backend authorization boundary is foundational; validate server-side ownership/permission behavior before dependent frontend or endpoint-specific changes.".into()
        }
        "security_headers" | "cors" | "csrf" | "api_input_validation" | "api_validation" => {
            "Shared middleware/configuration/validation controls are ordered before narrower endpoint changes when no stronger dependency is known.".into()
        }
        _ => "No stronger dependency was established. The finding is ordered deterministically by eligibility, vulnerability family, severity and source identity.".into(),
    }
}

fn comparison_status_for_campaign_state(status: &str) -> &'static str {
    match status {
        "VERIFIED" => "VERIFIED_RESOLVED",
        "STILL_VULNERABLE" => "STILL_VULNERABLE",
        "UNABLE_TO_VERIFY" => "UNABLE_TO_VERIFY",
        "MANUAL_ACTION_REQUIRED" => "MANUAL_ACTION_REQUIRED",
        "REGRESSION_DETECTED" => "REGRESSION_DETECTED",
        "SKIPPED" => "SKIPPED",
        "BLOCKED" => "BLOCKED",
        _ => "IN_PROGRESS",
    }
}

fn unresolved_reason(finding: &SecurityRemediationCampaignFindingRecord) -> &'static str {
    match finding.status.as_str() {
        "MANUAL_ACTION_REQUIRED" => "manual remediation required",
        "STILL_VULNERABLE" => "still vulnerable after retest",
        "UNABLE_TO_VERIFY" => "runtime target unavailable or insufficient usable responses",
        "REGRESSION_DETECTED" => "validation regression detected",
        "SKIPPED" => "developer skipped",
        "BLOCKED" if finding.eligibility == FixEligibility::InsufficientEvidence => {
            "insufficient evidence"
        }
        "BLOCKED" => "dependency or stale source blocked",
        "PREPARING_FIX" | "AWAITING_REVIEW" | "APPLYING" | "VALIDATING" | "RETESTING" => {
            "remediation in progress"
        }
        _ => "not yet remediated",
    }
}

fn increment(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_default() += 1;
}

fn dedup_ids(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert((*value).to_string()))
        .map(ToOwned::to_owned)
        .collect()
}

fn bounded_text(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn sha256_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn random_id(
    connection: &rusqlite::Connection,
    prefix: &str,
) -> Result<String, SecurityRemediationCampaignError> {
    let random: String = connection.query_row(
        "SELECT lower(hex(randomblob(16)))",
        [],
        |row| row.get(0),
    )?;
    Ok(format!("{prefix}_{random}"))
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Database, String, String, String, String) {
        let database = Database::open_in_memory().expect("database");
        database
            .connection()
            .execute_batch(
                "INSERT INTO projects(id,root_path,display_name)
                 VALUES ('campaign-project','/tmp/codetwin-campaign','campaign');
                 INSERT INTO web_security_scans(
                    id,project_id,target_url,status,phase,authorization_confirmed,
                    scope_json,config_json,auth_metadata_json
                 ) VALUES (
                    'campaign-scan','campaign-project','http://127.0.0.1:33001',
                    'completed','completed',1,
                    '{\"allowed_hostnames\":[\"127.0.0.1\"]}','{}','{}'
                 );
                 INSERT INTO guided_security_sessions(
                    id,project_id,target_url,environment,testing_depth,auth_mode,status,
                    authorization_confirmed,config_json,scan_id
                 ) VALUES (
                    'campaign-session','campaign-project','http://127.0.0.1:33001',
                    'local','standard','none','completed',1,
                    '{\"scope\":{\"authorization_confirmed\":true}}','campaign-scan'
                 );
                 INSERT INTO web_security_findings(
                    id,scan_id,fingerprint,category,severity,confidence,target,
                    endpoint_url,method,title,description,reproduction_summary,
                    impact,remediation,references_json
                 ) VALUES
                 (
                    'campaign-finding-a','campaign-scan','campaign-fp-a','sql_injection',
                    'high','Likely','http://127.0.0.1:33001',
                    'http://127.0.0.1:33001/search?q=a','GET',
                    'SQL injection','fixture','fixture','fixture',
                    'Use parameter binding.','[]'
                 ),
                 (
                    'campaign-finding-b','campaign-scan','campaign-fp-b','xss',
                    'medium','Likely','http://127.0.0.1:33001',
                    'http://127.0.0.1:33001/render?q=a','GET',
                    'XSS','fixture','fixture','fixture',
                    'Use text context rendering.','[]'
                 );",
            )
            .expect("fixture");
        let web = crate::AuthorizedWebSecurityStore::new(&database);
        for finding_id in ["campaign-finding-a", "campaign-finding-b"] {
            web.record_evidence(
                finding_id,
                &crate::WebEvidenceInput {
                    summary: "campaign runtime evidence".into(),
                    request_metadata_json: "{}".into(),
                    response_metadata_json: "{}".into(),
                },
            )
            .expect("campaign evidence");
        }
        (
            database,
            "campaign-session".into(),
            "campaign-scan".into(),
            "campaign-finding-a".into(),
            "campaign-finding-b".into(),
        )
    }

    #[test]
    fn campaign_scope_binding_rejects_cross_scan_finding_injection() {
        let (database, session_id, _, finding_a, _) = fixture();
        database
            .connection()
            .execute_batch(
                "INSERT INTO web_security_scans(
                    id,project_id,target_url,status,phase,authorization_confirmed,
                    scope_json,config_json,auth_metadata_json
                 ) VALUES (
                    'other-scan','campaign-project','http://127.0.0.1:33001',
                    'completed','completed',1,'{}','{}','{}'
                 );
                 INSERT INTO web_security_findings(
                    id,scan_id,fingerprint,category,severity,confidence,target,
                    endpoint_url,method,title,description,reproduction_summary,
                    impact,remediation,references_json
                 ) VALUES (
                    'other-finding','other-scan','other-fp','xss','medium','Likely',
                    'http://127.0.0.1:33001','http://127.0.0.1:33001/other','GET',
                    'other','fixture','fixture','fixture','fixture','[]'
                 );",
            )
            .expect("other scan");
        let error = SecurityRemediationCampaignService::new(&database)
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a, "other-finding".into()],
            })
            .expect_err("cross-scan finding injection must fail");
        assert!(error.to_string().contains("does not belong"));
    }

    #[test]
    fn campaign_scope_binding_rejects_cross_project_and_cross_target_finding_reuse() {
        let (database, session_id, _, finding_a, _) = fixture();
        database
            .connection()
            .execute_batch(
                "INSERT INTO projects(id,root_path,display_name)
                 VALUES ('other-project','/tmp/codetwin-other-project','other project');
                 INSERT INTO web_security_scans(
                    id,project_id,target_url,status,phase,authorization_confirmed,
                    scope_json,config_json,auth_metadata_json
                 ) VALUES (
                    'other-project-scan','other-project','http://127.0.0.1:44001',
                    'completed','completed',1,
                    '{\"allowed_hostnames\":[\"127.0.0.1\"]}','{}','{}'
                 );
                 INSERT INTO web_security_findings(
                    id,scan_id,fingerprint,category,severity,confidence,target,
                    endpoint_url,method,title,description,reproduction_summary,
                    impact,remediation,references_json
                 ) VALUES (
                    'other-project-finding','other-project-scan','other-project-fp',
                    'xss','medium','Likely','http://127.0.0.1:44001',
                    'http://127.0.0.1:44001/render?q=a','GET',
                    'other project XSS','fixture','fixture','fixture','fixture','[]'
                 );",
            )
            .expect("cross-project fixture");

        let error = SecurityRemediationCampaignService::new(&database)
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a, "other-project-finding".into()],
            })
            .expect_err("cross-project/target finding reuse must fail");
        assert!(
            error.to_string().contains("does not belong"),
            "campaign membership must remain bound to the original authorized scan"
        );
    }

    #[test]
    fn campaign_plan_approval_is_hash_bound_and_does_not_approve_patches() {
        let (database, session_id, _, finding_a, finding_b) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a, finding_b],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        let hash = analyzed.plan_hash.clone().expect("plan hash");
        assert!(service.approve_plan(&campaign.id, "0").is_err());
        let approved = service
            .approve_plan(&campaign.id, &hash)
            .expect("approve exact campaign plan");
        assert_eq!(approved.status, "APPROVED");
        let fix_attempts: i64 = database
            .connection()
            .query_row("SELECT COUNT(*) FROM security_fix_attempts", [], |row| row.get(0))
            .expect("attempt count");
        assert_eq!(fix_attempts, 0, "campaign approval cannot pre-authorize code patches");
    }

    #[test]
    fn campaign_events_reject_secret_material() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a],
            })
            .expect("create");
        assert!(service
            .append_event(
                &campaign.id,
                "unsafe",
                "Authorization: Bearer secret-token",
                &json!({})
            )
            .is_err());
        assert!(service
            .append_event(
                &campaign.id,
                "unsafe",
                "safe message",
                &json!({"cookie": "session=secret"})
            )
            .is_err());
    }

    #[test]
    fn paused_campaign_persists_and_resumes_after_database_reopen() {
        let file = tempfile::NamedTempFile::new().expect("campaign database file");
        let campaign_id;
        {
            let database = Database::open(file.path()).expect("persistent campaign database");
            database
                .connection()
                .execute_batch(
                    "INSERT INTO projects(id,root_path,display_name)
                     VALUES ('persistent-project','/tmp/codetwin-persistent','persistent');
                     INSERT INTO web_security_scans(
                        id,project_id,target_url,status,phase,authorization_confirmed,
                        scope_json,config_json,auth_metadata_json
                     ) VALUES (
                        'persistent-scan','persistent-project','http://127.0.0.1:34001',
                        'completed','completed',1,'{}','{}','{}'
                     );
                     INSERT INTO guided_security_sessions(
                        id,project_id,target_url,environment,testing_depth,auth_mode,status,
                        authorization_confirmed,config_json,scan_id
                     ) VALUES (
                        'persistent-session','persistent-project','http://127.0.0.1:34001',
                        'local','standard','none','completed',1,'{}','persistent-scan'
                     );
                     INSERT INTO web_security_findings(
                        id,scan_id,fingerprint,category,severity,confidence,target,
                        endpoint_url,method,title,description,reproduction_summary,
                        impact,remediation,references_json
                     ) VALUES (
                        'persistent-finding','persistent-scan','persistent-fp','xss',
                        'medium','Likely','http://127.0.0.1:34001',
                        'http://127.0.0.1:34001/render?q=a','GET',
                        'Persistent XSS','fixture','fixture','fixture','use safe text rendering','[]'
                     );",
                )
                .expect("persistent fixture");
            crate::AuthorizedWebSecurityStore::new(&database)
                .record_evidence(
                    "persistent-finding",
                    &crate::WebEvidenceInput {
                        summary: "persistent runtime evidence".into(),
                        request_metadata_json: "{}".into(),
                        response_metadata_json: "{}".into(),
                    },
                )
                .expect("persistent evidence");

            let service = SecurityRemediationCampaignService::new(&database);
            let campaign = service
                .create(&SecurityRemediationCampaignCreate {
                    session_id: "persistent-session".into(),
                    finding_ids: vec!["persistent-finding".into()],
                })
                .expect("create persistent campaign");
            campaign_id = campaign.id.clone();
            let analyzed = service.analyze(&campaign.id).expect("analyze persistent campaign");
            service
                .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
                .expect("approve persistent campaign");
            service.start(&campaign.id).expect("start persistent campaign");
            let paused = service.pause(&campaign.id).expect("pause persistent campaign");
            assert_eq!(paused.status, "PAUSED");
        }

        let reopened = Database::open(file.path()).expect("reopen campaign database");
        let service = SecurityRemediationCampaignService::new(&reopened);
        let persisted = service
            .get(&campaign_id)
            .expect("read persisted campaign")
            .expect("campaign persists");
        assert_eq!(persisted.status, "PAUSED");
        let resumed = service.resume(&campaign_id).expect("resume after reopen");
        assert_eq!(resumed.status, "IN_PROGRESS");
        assert!(service
            .events(&campaign_id, 50)
            .expect("persistent events")
            .iter()
            .any(|event| event.event_type == "campaign_resumed"));
    }

    #[test]
    fn campaign_rejects_target_substitution_before_plan_analysis() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a],
            })
            .expect("create");
        database
            .connection()
            .execute(
                "UPDATE security_remediation_campaigns
                 SET target_url='http://127.0.0.1:39999' WHERE id=?1",
                [&campaign.id],
            )
            .expect("simulate preapproval target substitution");
        let error = service
            .analyze(&campaign.id)
            .expect_err("substituted target must not be analyzed");
        assert!(error.to_string().contains("scope binding changed"));
    }

    #[test]
    fn campaign_plan_approval_rejects_preapproval_payload_or_order_tampering() {
        let (database, session_id, _, finding_a, finding_b) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a.clone(), finding_b.clone()],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        let reviewed_hash = analyzed.plan_hash.clone().expect("reviewed hash");

        database
            .connection()
            .execute(
                "UPDATE security_remediation_campaigns
                 SET plan_json='{}' WHERE id=?1",
                [&campaign.id],
            )
            .expect("simulate preapproval plan payload tampering");
        let payload_error = service
            .approve_plan(&campaign.id, &reviewed_hash)
            .expect_err("tampered payload must fail approval");
        assert!(payload_error.to_string().contains("payload changed"));

        database
            .connection()
            .execute(
                "UPDATE security_remediation_campaigns
                 SET plan_json=?2 WHERE id=?1",
                params![campaign.id, analyzed.plan_json],
            )
            .expect("restore reviewed plan payload");
        database
            .connection()
            .execute(
                "UPDATE security_remediation_campaign_findings
                 SET ordinal=99 WHERE campaign_id=?1 AND finding_id=?2",
                params![campaign.id, finding_a],
            )
            .expect("simulate preapproval order tampering");
        let order_error = service
            .approve_plan(&campaign.id, &reviewed_hash)
            .expect_err("tampered persisted order must fail approval");
        assert!(order_error.to_string().contains("order or dependency"));
    }

    #[test]
    fn approved_campaign_plan_rejects_order_and_plan_identity_tampering() {
        let (database, session_id, _, finding_a, finding_b) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a.clone(), finding_b],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("plan hash"))
            .expect("approve");

        assert!(database
            .connection()
            .execute(
                "UPDATE security_remediation_campaign_findings
                 SET ordinal=99 WHERE campaign_id=?1 AND finding_id=?2",
                params![campaign.id, finding_a],
            )
            .is_err(), "approved finding order must be immutable");
        assert!(database
            .connection()
            .execute(
                "UPDATE security_remediation_campaigns
                 SET plan_json='{}' WHERE id=?1",
                [&campaign.id],
            )
            .is_err(), "approved plan payload must be immutable");
    }

    #[test]
    fn campaign_retest_floor_prevents_precreation_retest_from_forging_verified() {
        let (database, session_id, _, finding_a, _) = fixture();
        database
            .connection()
            .execute(
                "INSERT INTO guided_security_retests(
                    id,finding_id,session_id,status,original_confidence,
                    observed_confidence,requests_performed,detail_json
                 ) VALUES (
                    'pre-campaign-retest',?1,?2,'retest_passed','Likely','Likely',2,'{}'
                 )",
                params![finding_a, session_id],
            )
            .expect("pre-campaign retest");

        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id: session_id.clone(),
                finding_ids: vec![finding_a.clone()],
            })
            .expect("create");
        let member = service
            .findings(&campaign.id)
            .expect("members")
            .into_iter()
            .next()
            .expect("member");
        assert!(member.retest_floor_rowid > 0);

        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        service.start(&campaign.id).expect("start");
        service.sync(&campaign.id).expect("sync");
        let before_new_retest = service
            .findings(&campaign.id)
            .expect("members")
            .into_iter()
            .next()
            .expect("member");
        assert_ne!(
            before_new_retest.status, "VERIFIED",
            "a retest that predates campaign creation cannot verify campaign work"
        );

        database
            .connection()
            .execute(
                "INSERT INTO guided_security_retests(
                    id,finding_id,session_id,status,original_confidence,
                    observed_confidence,requests_performed,detail_json
                 ) VALUES (
                    'post-campaign-retest',?1,?2,'retest_passed','Likely','Likely',2,'{}'
                 )",
                params![finding_a, session_id],
            )
            .expect("post-campaign retest");
        service.sync(&campaign.id).expect("sync post-campaign retest");
        assert_eq!(
            service
                .findings(&campaign.id)
                .expect("members")
                .into_iter()
                .next()
                .expect("member")
                .status,
            "VERIFIED"
        );
    }

    #[test]
    fn persistence_rejects_forged_verified_invalid_lifecycle_and_duplicate_history() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a.clone()],
            })
            .expect("create");

        assert!(database
            .connection()
            .execute(
                "UPDATE security_remediation_campaigns SET status='COMPLETED' WHERE id=?1",
                [&campaign.id],
            )
            .is_err(), "draft campaign cannot jump directly to completed");
        assert!(database
            .connection()
            .execute(
                "UPDATE security_remediation_campaign_findings
                 SET status='VERIFIED' WHERE campaign_id=?1 AND finding_id=?2",
                params![campaign.id, finding_a],
            )
            .is_err(), "VERIFIED requires persisted post-campaign security evidence");

        let event = service
            .events(&campaign.id, 20)
            .expect("events")
            .into_iter()
            .next()
            .expect("created event");
        assert!(database
            .connection()
            .execute(
                "INSERT INTO security_remediation_campaign_events(
                    id,campaign_id,sequence,event_type,message,detail_json
                 ) VALUES ('duplicate-campaign-event',?1,?2,'duplicate','duplicate','{}')",
                params![campaign.id, to_i64(event.sequence)],
            )
            .is_err(), "event sequence must be unique");
        assert!(database
            .connection()
            .execute(
                "DELETE FROM security_remediation_campaign_events WHERE id=?1",
                [&event.id],
            )
            .is_err(), "campaign event history must be append-only");
    }

    #[test]
    fn campaign_preserves_still_vulnerable_and_unable_to_verify_outcomes() {
        let (database, session_id, _, finding_a, finding_b) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id: session_id.clone(),
                finding_ids: vec![finding_a.clone(), finding_b.clone()],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        service.start(&campaign.id).expect("start");

        let guided = crate::GuidedSecurityStore::new(&database);
        guided
            .record_retest(crate::GuidedRetestInput {
                finding_id: &finding_a,
                session_id: Some(&session_id),
                status: "still_vulnerable",
                original_confidence: "Likely",
                observed_confidence: Some("Likely"),
                requests_performed: 2,
                detail_json: r#"{"fixture":"campaign-still-vulnerable"}"#,
            })
            .expect("still vulnerable retest");
        guided
            .record_retest(crate::GuidedRetestInput {
                finding_id: &finding_b,
                session_id: Some(&session_id),
                status: "unable_to_verify",
                original_confidence: "Likely",
                observed_confidence: None,
                requests_performed: 2,
                detail_json: r#"{"fixture":"campaign-unable"}"#,
            })
            .expect("unable retest");

        service.sync(&campaign.id).expect("sync failure outcomes");
        let findings = service.findings(&campaign.id).expect("campaign findings");
        assert_eq!(
            findings
                .iter()
                .find(|finding| finding.finding_id == finding_a)
                .expect("A")
                .status,
            "STILL_VULNERABLE"
        );
        assert_eq!(
            findings
                .iter()
                .find(|finding| finding.finding_id == finding_b)
                .expect("B")
                .status,
            "UNABLE_TO_VERIFY"
        );

        let summary = service.summary(&campaign.id).expect("summary");
        assert_eq!(summary.verified_fixed, 0);
        assert_eq!(summary.still_vulnerable, 1);
        assert_eq!(summary.unable_to_verify, 1);
        assert_eq!(summary.queued_or_in_progress, 0);
        assert!(service.complete(&campaign.id).is_err());

        service
            .begin_completion_verification(&campaign.id)
            .expect("begin final verification");
        guided
            .record_retest(crate::GuidedRetestInput {
                finding_id: &finding_a,
                session_id: Some(&session_id),
                status: "still_vulnerable",
                original_confidence: "Likely",
                observed_confidence: Some("Likely"),
                requests_performed: 2,
                detail_json: r#"{"fixture":"campaign-final-still-vulnerable"}"#,
            })
            .expect("final still vulnerable retest");
        guided
            .record_retest(crate::GuidedRetestInput {
                finding_id: &finding_b,
                session_id: Some(&session_id),
                status: "unable_to_verify",
                original_confidence: "Likely",
                observed_confidence: None,
                requests_performed: 2,
                detail_json: r#"{"fixture":"campaign-final-unable"}"#,
            })
            .expect("final unable retest");
        service
            .finalize_completion_verification(&campaign.id)
            .expect("finalize final verification");
        let completed = service.complete(&campaign.id).expect("factual completion");
        assert_eq!(completed.status, "COMPLETED_WITH_UNRESOLVED_FINDINGS");
    }

    #[test]
    fn before_after_reports_only_new_fingerprints_observed_during_final_verification() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id: session_id.clone(),
                finding_ids: vec![finding_a.clone()],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        service.start(&campaign.id).expect("start");
        service
            .skip_finding(&campaign.id, &finding_a, "deferred for comparison test")
            .expect("skip selected finding");
        service
            .begin_completion_verification(&campaign.id)
            .expect("begin final verification");

        crate::GuidedSecurityStore::new(&database)
            .record_retest(crate::GuidedRetestInput {
                finding_id: &finding_a,
                session_id: Some(&session_id),
                status: "still_vulnerable",
                original_confidence: "Likely",
                observed_confidence: Some("Likely"),
                requests_performed: 2,
                detail_json: r#"{"fixture":"comparison-final-retest"}"#,
            })
            .expect("fresh selected finding retest");

        database
            .connection()
            .execute_batch(
                "INSERT INTO web_security_scans(
                    id,project_id,target_url,status,phase,authorization_confirmed,
                    scope_json,config_json,auth_metadata_json
                 ) VALUES (
                    'verification-window-scan','campaign-project','http://127.0.0.1:33001',
                    'completed','completed',1,
                    '{"allowed_hostnames":["127.0.0.1"]}','{}','{}'
                 );
                 INSERT INTO web_security_findings(
                    id,scan_id,fingerprint,category,severity,confidence,target,
                    endpoint_url,method,title,description,reproduction_summary,
                    impact,remediation,references_json
                 ) VALUES
                 (
                    'verification-new-finding','verification-window-scan','new-verification-fp',
                    'security_headers','medium','Likely','http://127.0.0.1:33001',
                    'http://127.0.0.1:33001/new','GET',
                    'New header observation','fixture','fixture','fixture','fixture','[]'
                 ),
                 (
                    'verification-reobserved-existing','verification-window-scan','campaign-fp-a',
                    'sql_injection','high','Likely','http://127.0.0.1:33001',
                    'http://127.0.0.1:33001/search?q=a','GET',
                    'Reobserved SQL injection','fixture','fixture','fixture','fixture','[]'
                 );",
            )
            .expect("verification window findings");

        service
            .finalize_completion_verification(&campaign.id)
            .expect("finalize verification");
        let comparison = service.before_after(&campaign.id).expect("before after");
        assert!(comparison.iter().any(|item| {
            item.finding_id == "verification-new-finding"
                && item.comparison_status == "NEWLY_OBSERVED_DURING_VERIFICATION"
                && !item.selected
        }));
        assert!(!comparison
            .iter()
            .any(|item| item.finding_id == "verification-reobserved-existing"));
        assert!(comparison
            .iter()
            .any(|item| item.finding_id == finding_a && item.selected));
    }

    #[test]
    fn duplicate_campaign_retests_do_not_inflate_summary_or_state_history() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id: session_id.clone(),
                finding_ids: vec![finding_a.clone()],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        service.start(&campaign.id).expect("start");

        let guided = crate::GuidedSecurityStore::new(&database);
        for suffix in ["one", "two"] {
            guided
                .record_retest(crate::GuidedRetestInput {
                    finding_id: &finding_a,
                    session_id: Some(&session_id),
                    status: "still_vulnerable",
                    original_confidence: "Likely",
                    observed_confidence: Some("Likely"),
                    requests_performed: 2,
                    detail_json: &format!(r#"{{"fixture":"duplicate-{suffix}"}}"#),
                })
                .expect("persist duplicate retest");
            service.sync(&campaign.id).expect("sync duplicate retest");
        }

        let summary = service.summary(&campaign.id).expect("summary");
        assert_eq!(summary.selected_findings, 1);
        assert_eq!(summary.still_vulnerable, 1);
        assert_eq!(summary.verified_fixed, 0);
        let state_events = service
            .events(&campaign.id, 100)
            .expect("events")
            .into_iter()
            .filter(|event| {
                event.event_type == "finding_state_changed"
                    && event.detail_json.contains("STILL_VULNERABLE")
            })
            .count();
        assert_eq!(
            state_events, 1,
            "repeating the same factual retest outcome must not duplicate campaign state transitions"
        );
    }

    #[test]
    fn campaign_security_debt_reports_standard_fix_attempt_limit() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a.clone()],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        service.start(&campaign.id).expect("start");

        for attempt_number in 1..=3 {
            database
                .connection()
                .execute(
                    "INSERT INTO security_fix_attempts(
                        id,finding_id,session_id,project_id,attempt_number,eligibility,
                        category,status,root_cause_json,strategy_json,test_plan_json,
                        retest_state
                     ) VALUES (
                        ?1,?2,'campaign-session','campaign-project',?3,
                        'MANUAL_REMEDIATION','sql_injection','still_vulnerable',
                        '[]','{}','{}','STILL_VULNERABLE'
                     )",
                    params![
                        format!("campaign-limit-attempt-{attempt_number}"),
                        finding_a,
                        attempt_number
                    ],
                )
                .expect("persist unresolved fix attempt");
        }

        service.sync(&campaign.id).expect("sync attempt-limit state");
        assert_eq!(
            service
                .findings(&campaign.id)
                .expect("findings")
                .into_iter()
                .next()
                .expect("campaign finding")
                .status,
            "STILL_VULNERABLE"
        );
        assert!(SecurityFixService::new(&database)
            .standard_attempt_limit_reached(&finding_a)
            .expect("attempt limit"));
        let debt = service.security_debt(&campaign.id).expect("security debt");
        assert_eq!(
            debt.by_reason.get("fix attempt limit reached"),
            Some(&1),
            "security debt must expose the existing Fix & Verify standard attempt limit factually"
        );
    }

    #[test]
    fn campaign_completion_requires_fresh_retest_for_every_selected_finding() {
        let (database, session_id, _, finding_a, finding_b) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id: session_id.clone(),
                finding_ids: vec![finding_a.clone(), finding_b.clone()],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        service.start(&campaign.id).expect("start");
        service
            .skip_finding(&campaign.id, &finding_a, "deferred A")
            .expect("skip A");
        service
            .skip_finding(&campaign.id, &finding_b, "deferred B")
            .expect("skip B");

        service
            .begin_completion_verification(&campaign.id)
            .expect("begin completion verification");
        crate::GuidedSecurityStore::new(&database)
            .record_retest(crate::GuidedRetestInput {
                finding_id: &finding_a,
                session_id: Some(&session_id),
                status: "still_vulnerable",
                original_confidence: "Likely",
                observed_confidence: Some("Likely"),
                requests_performed: 2,
                detail_json: r#"{"fixture":"only-one-final-retest"}"#,
            })
            .expect("one final retest");

        let error = service
            .finalize_completion_verification(&campaign.id)
            .expect_err("missing selected finding retest must block completion verification");
        assert!(error.to_string().contains(&finding_b));
        assert!(service.complete(&campaign.id).is_err());
    }

    #[test]
    fn campaign_completion_with_unresolved_findings_is_factual() {
        let (database, session_id, _, finding_a, _) = fixture();
        let service = SecurityRemediationCampaignService::new(&database);
        let campaign = service
            .create(&SecurityRemediationCampaignCreate {
                session_id,
                finding_ids: vec![finding_a],
            })
            .expect("create");
        let analyzed = service.analyze(&campaign.id).expect("analyze");
        let approved = service
            .approve_plan(&campaign.id, analyzed.plan_hash.as_deref().expect("hash"))
            .expect("approve");
        assert_eq!(approved.status, "APPROVED");
        service.start(&campaign.id).expect("start");
        service
            .skip_finding(&campaign.id, "campaign-finding-a", "Deferred for manual review.")
            .expect("skip");
        assert!(service.complete(&campaign.id).is_err());
        service
            .begin_completion_verification(&campaign.id)
            .expect("begin final verification");
        crate::GuidedSecurityStore::new(&database)
            .record_retest(crate::GuidedRetestInput {
                finding_id: "campaign-finding-a",
                session_id: Some("campaign-session"),
                status: "still_vulnerable",
                original_confidence: "Likely",
                observed_confidence: Some("Likely"),
                requests_performed: 2,
                detail_json: r#"{"fixture":"campaign-skipped-final-verification"}"#,
            })
            .expect("fresh skipped finding retest");
        service
            .finalize_completion_verification(&campaign.id)
            .expect("finalize final verification");
        let completed = service.complete(&campaign.id).expect("complete");
        assert_eq!(completed.status, "COMPLETED_WITH_UNRESOLVED_FINDINGS");
        let summary = service.summary(&campaign.id).expect("summary");
        assert_eq!(summary.selected_findings, 1);
        assert_eq!(summary.verified_fixed, 0);
        assert_eq!(summary.skipped, 1);
    }
}
