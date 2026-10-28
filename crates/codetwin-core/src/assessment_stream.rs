//! Unified, typed assessment stream for the terminal-first workspace.
//!
//! Merges the durable workflow event log (migration 47) with structured
//! finding cards built from persisted analyzer findings, their stored
//! evidence and operator review verdicts. Nothing here is simulated: every
//! item is derived from SQLite rows, and the stream is resumable through the
//! event `seq` cursor.
//!
//! Severity, verification status and execution state are independent:
//! * severity comes from the analyzer;
//! * verification is `potential` until an operator review or analyzer
//!   status says otherwise — static detection is never "confirmed";
//! * execution state comes from the workflow run/task state machines.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use task_orchestrator::store::{EventRecord, TaskRecord};
use task_orchestrator::{EvidenceClass, Store, TaskState};

use crate::{
    CodeSecurityService, Database, DependencyAuditService, SecretScanningService,
    SecurityReviewService, WorkspaceService,
};

const MAX_CARDS_PER_TASK: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct StreamEvent {
    pub key: String,
    pub seq: i64,
    pub ts_ms: i64,
    pub run_id: String,
    pub task_id: Option<String>,
    pub agent: Option<String>,
    pub tool: Option<String>,
    /// Display tag such as INIT, ORCHESTRATOR, AGENT, TOOL, OK, POTENTIAL, ERROR.
    pub stage: String,
    /// Execution status the event reports (e.g. running, completed, denied).
    pub status: String,
    pub target: Option<String>,
    pub message: String,
    pub duration_ms: Option<i64>,
    pub correlation_id: String,
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceItem {
    pub kind: String,
    pub location: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewState {
    pub verdict: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingCard {
    pub key: String,
    /// `seq` of the event after which the card appears in the stream.
    pub seq: i64,
    pub ts_ms: i64,
    pub run_id: String,
    pub task_id: String,
    pub agent: String,
    pub finding_id: String,
    /// `appsec`, `secret` or `dependency`.
    pub source: String,
    pub title: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    /// `potential`, `validating`, `confirmed`, `false_positive`, `resolved`.
    pub verification: String,
    pub rule_id: String,
    pub description: String,
    pub target: String,
    pub location: Option<String>,
    pub first_seen: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub cve: Vec<String>,
    pub cvss: Option<f64>,
    pub confidence: Option<f64>,
    pub evidence: Vec<EvidenceItem>,
    pub impact: String,
    pub remediation: Vec<String>,
    /// Where the remediation text comes from (analyzer, advisory or general CWE guidance).
    pub remediation_basis: String,
    pub limitations: Vec<String>,
    pub review: Option<ReviewState>,
    /// Bindings an operator review must quote back (stale-review protection).
    pub scan_run_id: Option<String>,
    pub file_sha256: Option<String>,
    pub reviewable: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamItem {
    Event(Box<StreamEvent>),
    Finding(Box<FindingCard>),
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamPage {
    pub items: Vec<StreamItem>,
    pub next_cursor: i64,
    pub has_more: bool,
    pub run_state: String,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AssessmentSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub potential: usize,
    pub validating: usize,
    pub confirmed: usize,
    pub false_positive: usize,
    pub resolved: usize,
    /// Checks that completed successfully with no open findings.
    pub passed: usize,
    pub checks_completed: usize,
    pub checks_total: usize,
}

pub fn normalize_severity(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" | "moderate" => "medium",
        "low" => "low",
        _ => "info",
    }
}

fn verification(status: &str, review: Option<&ReviewState>) -> &'static str {
    match (status, review.map(|r| r.verdict.as_str())) {
        ("resolved" | "fixed", _) => "resolved",
        (_, Some("confirmed")) => "confirmed",
        (_, Some("false_positive")) => "false_positive",
        (_, Some("needs_review")) => "validating",
        _ => "potential",
    }
}

/// General, CWE-keyed guidance. Always labelled as general guidance — it is
/// not generated from the affected code and is not evidence.
fn cwe_guidance(cwe: Option<&str>) -> (String, Vec<String>) {
    let id = cwe.unwrap_or("").to_ascii_uppercase();
    let (impact, steps): (&str, &[&str]) = match id.as_str() {
        "CWE-94" | "CWE-95" => (
            "Attacker-influenced input evaluated as code can lead to arbitrary code execution in the application context.",
            &["Remove dynamic evaluation (eval/Function/exec) of data.", "Use a parser or an explicit allowlist of operations instead.", "Add a regression test that passes hostile input and asserts it is rejected."],
        ),
        "CWE-798" | "CWE-259" => (
            "Anyone with access to the code or build artifacts can reuse the embedded credential.",
            &["Move the credential to environment configuration or a secret manager.", "Rotate the exposed credential; treat it as compromised.", "Remove it from version history and add a secret-scanning check."],
        ),
        "CWE-89" => (
            "Crafted input can change SQL query structure, exposing or modifying data.",
            &["Use parameterized queries or prepared statements.", "Never concatenate untrusted input into SQL.", "Add tests with SQL metacharacters in inputs."],
        ),
        "CWE-79" => (
            "Injected script can run in other users' browsers, stealing sessions or performing actions.",
            &["Apply context-aware output encoding.", "Avoid raw HTML sinks (innerHTML, dangerouslySetInnerHTML) for untrusted data.", "Add a Content-Security-Policy and an encoding regression test."],
        ),
        "CWE-78" | "CWE-77" => (
            "Crafted input can execute operating-system commands with the application's privileges.",
            &["Avoid shell invocation; pass arguments as an array to the process API.", "Validate inputs against an allowlist.", "Add tests with shell metacharacters."],
        ),
        "CWE-22" | "CWE-23" => (
            "Crafted paths can read or write files outside the intended directory.",
            &["Canonicalize paths and verify they stay under an allowed root.", "Reject absolute paths and `..` segments.", "Add traversal regression tests."],
        ),
        "CWE-918" => (
            "The server can be induced to request internal or cloud-metadata endpoints.",
            &["Allowlist destinations and resolve then validate IPs before connecting.", "Disable redirects or revalidate each hop.", "Add tests for private and metadata addresses."],
        ),
        "CWE-327" | "CWE-328" | "CWE-916" => (
            "Weak cryptography can let attackers recover or forge protected data.",
            &["Replace with current algorithms (AES-GCM, SHA-256+, Argon2/bcrypt for passwords).", "Plan key/hash migration for stored data.", "Add tests pinning the algorithm choice."],
        ),
        "CWE-502" => (
            "Deserializing untrusted data can lead to code execution or object injection.",
            &["Use data-only formats (JSON) with schema validation.", "Never deserialize untrusted input into arbitrary types.", "Add tests with malformed payloads."],
        ),
        "CWE-611" => (
            "External entities can read local files or trigger SSRF.",
            &["Disable DTDs and external entity resolution in the XML parser.", "Add a regression test with an external entity."],
        ),
        _ => (
            "Impact depends on how the affected code is reachable; review the rule description and data flow.",
            &["Review the affected location and the rule description.", "Apply the OWASP guidance for this weakness class.", "Add a regression test and re-run the analyzer to verify."],
        ),
    };
    (
        impact.to_owned(),
        steps.iter().map(|s| (*s).to_owned()).collect(),
    )
}

fn stage_for(event: &EventRecord) -> (&'static str, String) {
    let d = &event.detail;
    let s = |k: &str| d.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    match event.kind.as_str() {
        "run_created" => ("INIT", "running".into()),
        "run_state" => ("ORCHESTRATOR", s("to")),
        "approval_requested" | "approval_decided" | "approval_expired" => (
            "APPROVAL",
            event.kind.trim_start_matches("approval_").into(),
        ),
        "task_state" => match s("to").as_str() {
            "running" => ("AGENT", "running".into()),
            "completed" => ("OK", "completed".into()),
            "failed" => ("ERROR", "failed".into()),
            "blocked" => ("BLOCKED", "blocked".into()),
            "retry_wait" => ("RETRY", "retry_wait".into()),
            "cancelled" => ("CANCELLED", "cancelled".into()),
            "validating" => ("VALIDATOR", "validating".into()),
            other => ("ORCHESTRATOR", other.to_owned()),
        },
        "tool_started" => ("TOOL", "running".into()),
        "tool_finished" => {
            if d.get("ok").and_then(Value::as_bool) == Some(false) {
                ("ERROR", "failed".into())
            } else {
                ("TOOL", "completed".into())
            }
        }
        "tool_denied" => ("DENIED", "denied".into()),
        "validation_failed" => ("ERROR", "validation_failed".into()),
        "delegated" => ("ORCHESTRATOR", "delegated".into()),
        "delegation_denied" => ("DENIED", "denied".into()),
        "cancel_requested" | "pause_requested" | "resumed" => ("CONTROL", event.kind.clone()),
        "side_effect_resolved" => ("CONTROL", "resolved".into()),
        _ => ("INFO", event.kind.clone()),
    }
}

pub struct AssessmentStream<'a> {
    db: &'a Database,
}

struct Context {
    tasks: BTreeMap<String, TaskRecord>,
    target: String,
    project_id: String,
    tool_durations: BTreeMap<String, i64>,
}

impl<'a> AssessmentStream<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    fn context(
        &self,
        run_id: &str,
    ) -> Result<(task_orchestrator::store::RunRecord, Context), String> {
        let store = Store::new(self.db.connection());
        let run = store.get_run(run_id).map_err(|e| e.to_string())?;
        let tasks = store
            .list_tasks(run_id)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|t| (t.id.clone(), t))
            .collect();
        let tool_durations = store
            .tool_invocations(run_id)
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|t| t.finished_ms.map(|f| (t.id, f - t.started_ms)))
            .collect();
        let target = WorkspaceService::new(self.db)
            .get_project(&run.project_id)
            .map_err(|e| e.to_string())?
            .map_or_else(|| run.project_id.clone(), |p| p.display_name);
        let project_id = run.project_id.clone();
        Ok((
            run,
            Context {
                tasks,
                target,
                project_id,
                tool_durations,
            },
        ))
    }

    fn finding_ids(task: &TaskRecord) -> Vec<(String, String)> {
        let Some(output) = &task.output else {
            return Vec::new();
        };
        let data = output.get("data").cloned().unwrap_or(Value::Null);
        let mut ids = Vec::new();
        match task.role.as_str() {
            "security_reviewer" => {
                for (field, source) in [("security", "appsec"), ("secrets", "secret")] {
                    for f in data
                        .get(field)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(id) = f.get("id").and_then(Value::as_str) {
                            ids.push((id.to_owned(), source.to_owned()));
                        }
                    }
                }
            }
            "dependency_analyst" => {
                for f in data
                    .pointer("/inventory/findings")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = f.get("id").and_then(Value::as_str) {
                        ids.push((id.to_owned(), "dependency".to_owned()));
                    }
                }
            }
            _ => {}
        }
        ids.truncate(MAX_CARDS_PER_TASK);
        ids
    }

    fn review(&self, project_id: &str, finding_id: &str) -> Option<ReviewState> {
        SecurityReviewService::new(self.db)
            .list(project_id, Some(finding_id), 1)
            .ok()?
            .into_iter()
            .find(|r| r.is_current)
            .map(|r| ReviewState {
                verdict: r.verdict,
                note: r.note,
                created_at: r.created_at,
            })
    }

    /// Build cards for the given finding ids from the analyzers' own stores.
    fn cards(
        &self,
        ctx: &Context,
        task: &TaskRecord,
        seq: i64,
        ts_ms: i64,
        ids: &[(String, String)],
    ) -> Result<Vec<FindingCard>, String> {
        let wanted: BTreeSet<&str> = ids.iter().map(|(id, _)| id.as_str()).collect();
        let mut cards = Vec::new();
        let base = |finding_id: &str, source: &str| FindingCard {
            key: format!("f:{}:{finding_id}", task.id),
            seq,
            ts_ms,
            run_id: task.run_id.clone(),
            task_id: task.id.clone(),
            agent: task.role.clone(),
            finding_id: finding_id.to_owned(),
            source: source.to_owned(),
            title: String::new(),
            severity: "info".into(),
            verification: "potential".into(),
            rule_id: String::new(),
            description: String::new(),
            target: ctx.target.clone(),
            location: None,
            first_seen: String::new(),
            cwe: None,
            owasp: None,
            cve: Vec::new(),
            cvss: None,
            confidence: None,
            evidence: Vec::new(),
            impact: String::new(),
            remediation: Vec::new(),
            remediation_basis: String::new(),
            limitations: Vec::new(),
            review: None,
            scan_run_id: None,
            file_sha256: None,
            reviewable: false,
        };
        if ids.iter().any(|(_, s)| s == "appsec") {
            let security = CodeSecurityService::new(self.db);
            for f in security
                .list_findings(&ctx.project_id, None, 1_000)
                .map_err(|e| e.to_string())?
            {
                if !wanted.contains(f.id.as_str()) {
                    continue;
                }
                let file: Option<(String, String)> = f.file_id.as_deref().and_then(|id| {
                    self.db
                        .connection()
                        .query_row(
                            "SELECT relative_path, content_hash FROM files WHERE id=?1",
                            [id],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .ok()
                });
                let evidence = security
                    .finding_evidence(&f.id, 10)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|e| EvidenceItem {
                        kind: e.evidence_type,
                        location: e.uri.map(|u| match e.line_start {
                            Some(l) => format!("{u}:{l}"),
                            None => u,
                        }),
                        summary: e.summary.chars().take(500).collect(),
                    })
                    .collect();
                let (impact, remediation) = cwe_guidance(f.cwe.as_deref());
                let review = self.review(&ctx.project_id, &f.id);
                let mut card = base(&f.id, "appsec");
                card.verification = verification(&f.status, review.as_ref()).into();
                card.title = f.title;
                card.severity = normalize_severity(&f.severity).into();
                card.rule_id = f.rule_id;
                card.description = f.description;
                card.location = file.as_ref().map(|(p, _)| match f.source_start_line {
                    Some(l) => format!("{p}:{l}"),
                    None => p.clone(),
                });
                card.first_seen = f.first_seen;
                card.remediation_basis = format!(
                    "General guidance for {} (not generated from this code)",
                    f.cwe.as_deref().unwrap_or("this weakness")
                );
                card.cwe = f.cwe;
                card.owasp = f.owasp;
                card.confidence = f.confidence;
                card.evidence = evidence;
                card.impact = format!("Potential impact (general): {impact}");
                card.remediation = remediation;
                card.limitations = vec![
                    "Detected by static pattern analysis of indexed source; not exploited or dynamically confirmed.".into(),
                    "Reachability and data-flow from untrusted input were not proven.".into(),
                ];
                card.review = review;
                card.scan_run_id = Some(f.run_id);
                card.file_sha256 = file.map(|(_, h)| h);
                card.reviewable = f.status == "open";
                cards.push(card);
            }
        }
        if ids.iter().any(|(_, s)| s == "secret") {
            for f in SecretScanningService::new(self.db)
                .list_findings(&ctx.project_id, None, 1_000)
                .map_err(|e| e.to_string())?
            {
                if !wanted.contains(f.id.as_str()) {
                    continue;
                }
                let (impact, _) = cwe_guidance(Some("CWE-798"));
                let mut card = base(&f.id, "secret");
                card.verification = verification(&f.status, None).into();
                card.title = f.title;
                card.severity = normalize_severity(&f.severity).into();
                card.rule_id = f.rule_id;
                card.description = f.description;
                card.location = Some(match f.line {
                    Some(l) => format!("{}:{l}", f.relative_path),
                    None => f.relative_path.clone(),
                });
                card.first_seen = f.first_seen;
                card.cwe = Some("CWE-798".into());
                card.confidence = Some(f.confidence);
                // Only the analyzer's redacted preview is ever shown.
                card.evidence = vec![EvidenceItem {
                    kind: "redacted_match".into(),
                    location: card.location.clone(),
                    summary: f.redacted,
                }];
                card.impact = format!("Potential impact (general): {impact}");
                card.remediation = vec![f.remediation];
                card.remediation_basis = "Secret scanner remediation".into();
                card.limitations = vec![
                    "The secret value is never displayed; its validity was not tested.".into(),
                    if f.in_test_path {
                        "Located in a test path; confirm whether it is a real credential.".into()
                    } else {
                        "Located outside test paths.".into()
                    },
                ];
                cards.push(card);
            }
        }
        if ids.iter().any(|(_, s)| s == "dependency") {
            for f in DependencyAuditService::new(self.db)
                .list_findings(&ctx.project_id, None, 1_000)
                .map_err(|e| e.to_string())?
            {
                if !wanted.contains(f.id.as_str()) {
                    continue;
                }
                let mut card = base(&f.id, "dependency");
                card.verification = verification(&f.status, None).into();
                card.title = format!("{} — {}@{}", f.title, f.package, f.version);
                card.severity = normalize_severity(&f.severity).into();
                card.rule_id = f.display_id.clone();
                card.description = f.description.chars().take(2_000).collect();
                card.location = Some(match f.line {
                    Some(l) => format!("{}:{l}", f.manifest_path),
                    None => f.manifest_path.clone(),
                });
                card.first_seen = f.first_seen;
                card.cve = std::iter::once(f.display_id.clone())
                    .chain(f.aliases.iter().cloned())
                    .filter(|a| a.starts_with("CVE-"))
                    .collect();
                card.cvss = f.cvss_score;
                card.confidence = Some(f.confidence);
                card.evidence = vec![EvidenceItem {
                    kind: "advisory_match".into(),
                    location: card.location.clone(),
                    summary: format!(
                        "{} {}@{} matched advisory {} ({})",
                        f.ecosystem, f.package, f.version, f.advisory_id, f.match_basis
                    ),
                }];
                card.impact = "Potential impact: see the advisory description; exploitability depends on whether the vulnerable code path is used.".into();
                card.remediation = if f.fixed_versions.is_empty() {
                    vec!["No fixed version is listed; mitigate per the advisory or replace the package.".into()]
                } else {
                    vec![
                        format!(
                            "Upgrade {} to a fixed version: {}.",
                            f.package,
                            f.fixed_versions.join(", ")
                        ),
                        "Re-run the dependency audit to verify.".into(),
                    ]
                };
                card.remediation_basis = "OSV advisory".into();
                card.limitations = vec!["Version match against an OSV advisory; reachability of the vulnerable code was not analyzed.".into()];
                cards.push(card);
            }
        }
        // Stable order: severity, then title.
        let rank = |s: &str| {
            ["critical", "high", "medium", "low", "info"]
                .iter()
                .position(|x| *x == s)
                .unwrap_or(5)
        };
        cards.sort_by(|a, b| {
            rank(&a.severity)
                .cmp(&rank(&b.severity))
                .then(a.title.cmp(&b.title))
        });
        Ok(cards)
    }

    /// One page of the stream after `cursor` (exclusive), in `seq` order.
    pub fn page(&self, run_id: &str, cursor: i64, limit: usize) -> Result<StreamPage, String> {
        let store = Store::new(self.db.connection());
        let limit = limit.clamp(1, 500);
        let events = store
            .events_since(run_id, cursor.max(0), limit + 1)
            .map_err(|e| e.to_string())?;
        let has_more = events.len() > limit;
        let events = &events[..events.len().min(limit)];
        let (run, ctx) = self.context(run_id)?;
        let mut items = Vec::with_capacity(events.len());
        for e in events {
            let (stage, status) = stage_for(e);
            let task = e.task_id.as_ref().and_then(|id| ctx.tasks.get(id));
            let d = &e.detail;
            let tool = d.get("tool").and_then(Value::as_str).map(str::to_owned);
            let mut message = match e.kind.as_str() {
                "task_state" => format!(
                    "{}: {} → {}{}",
                    task.map_or("task", |t| t.title.as_str()),
                    d.get("from").and_then(Value::as_str).unwrap_or("?"),
                    d.get("to").and_then(Value::as_str).unwrap_or("?"),
                    d.get("reason")
                        .and_then(Value::as_str)
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default()
                ),
                "run_state" => format!(
                    "Run {} → {}{}",
                    d.get("from").and_then(Value::as_str).unwrap_or("?"),
                    d.get("to").and_then(Value::as_str).unwrap_or("?"),
                    d.get("outcome")
                        .and_then(Value::as_str)
                        .map(|o| format!(" · outcome {o}"))
                        .unwrap_or_default()
                ),
                "run_created" => format!(
                    "Assessment created: {}",
                    run.goal.chars().take(200).collect::<String>()
                ),
                "tool_started" => format!(
                    "{} started ({})",
                    tool.as_deref().unwrap_or("tool"),
                    d.get("capability").and_then(Value::as_str).unwrap_or("")
                ),
                "tool_finished" => format!(
                    "{} {}",
                    tool.as_deref().unwrap_or("tool"),
                    if d.get("ok").and_then(Value::as_bool) == Some(false) {
                        "failed"
                    } else {
                        "finished"
                    }
                ),
                "tool_denied" => format!(
                    "{} denied by policy: {}",
                    tool.as_deref().unwrap_or("tool"),
                    d.get("reason").and_then(Value::as_str).unwrap_or("")
                ),
                "approval_requested" => format!(
                    "Approval required ({})",
                    d.get("kind").and_then(Value::as_str).unwrap_or("")
                ),
                "approval_decided" => format!(
                    "Approval {} by {}",
                    if d.get("approve").and_then(Value::as_bool) == Some(true) {
                        "granted"
                    } else {
                        "rejected"
                    },
                    d.get("by").and_then(Value::as_str).unwrap_or("operator")
                ),
                _ => d
                    .get("detail")
                    .and_then(Value::as_str)
                    .map_or_else(|| e.kind.replace('_', " "), str::to_owned),
            };
            let completed = e.kind == "task_state" && status == "completed";
            if let (true, Some(t)) = (completed, task) {
                if let Some(summary) = &t.summary {
                    message = format!("{message} — {summary}");
                }
            }
            let duration_ms = match e.kind.as_str() {
                "task_state" if completed || status == "failed" => {
                    task.and_then(|t| Some(t.finished_ms? - t.started_ms?))
                }
                "tool_finished" => d
                    .get("invocation_id")
                    .and_then(Value::as_str)
                    .and_then(|id| ctx.tool_durations.get(id).copied()),
                _ => None,
            };
            let ids = match (completed, task) {
                (true, Some(t)) => Self::finding_ids(t),
                _ => Vec::new(),
            };
            items.push(StreamItem::Event(Box::new(StreamEvent {
                key: format!("e:{}", e.seq),
                seq: e.seq,
                ts_ms: e.created_ms,
                run_id: e.run_id.clone(),
                task_id: e.task_id.clone(),
                agent: task.map(|t| t.role.clone()),
                tool: tool.clone(),
                stage: if completed && !ids.is_empty() {
                    "POTENTIAL".into()
                } else {
                    stage.into()
                },
                status,
                target: Some(tool.unwrap_or_else(|| ctx.target.clone())),
                message,
                duration_ms,
                correlation_id: e.correlation_id.clone(),
                finding_ids: ids.iter().map(|(id, _)| id.clone()).collect(),
            })));
            if let (false, Some(t)) = (ids.is_empty(), task) {
                for card in self.cards(&ctx, t, e.seq, e.created_ms, &ids)? {
                    items.push(StreamItem::Finding(Box::new(card)));
                }
            }
        }
        Ok(StreamPage {
            next_cursor: events.last().map_or(cursor, |e| e.seq),
            has_more,
            run_state: run.state.as_str().into(),
            outcome: run.outcome.map(|o| o.as_str().into()),
            items,
        })
    }

    /// Counts over the whole run (not just the loaded page).
    pub fn summary(&self, run_id: &str) -> Result<AssessmentSummary, String> {
        let (_, ctx) = self.context(run_id)?;
        let mut summary = AssessmentSummary::default();
        let mut seen = BTreeSet::new();
        for task in ctx.tasks.values().filter(|t| !t.is_superseded()) {
            summary.checks_total += 1;
            if task.state != TaskState::Completed {
                continue;
            }
            summary.checks_completed += 1;
            let ids = Self::finding_ids(task);
            let producing = matches!(
                task.role.as_str(),
                "security_reviewer" | "dependency_analyst"
            );
            if (producing && ids.is_empty())
                || (task.role == "evidence_verifier"
                    && task.evidence_class == Some(EvidenceClass::ValidatedResult))
            {
                summary.passed += 1;
            }
            if ids.is_empty() {
                continue;
            }
            for card in self.cards(&ctx, task, 0, 0, &ids)? {
                if !seen.insert(card.finding_id.clone()) {
                    continue;
                }
                summary.total += 1;
                match card.severity.as_str() {
                    "critical" => summary.critical += 1,
                    "high" => summary.high += 1,
                    "medium" => summary.medium += 1,
                    "low" => summary.low += 1,
                    _ => summary.info += 1,
                }
                match card.verification.as_str() {
                    "confirmed" => summary.confirmed += 1,
                    "false_positive" => summary.false_positive += 1,
                    "validating" => summary.validating += 1,
                    "resolved" => summary.resolved += 1,
                    _ => summary.potential += 1,
                }
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_and_verification_are_independent() {
        assert_eq!(normalize_severity("CRITICAL"), "critical");
        assert_eq!(normalize_severity("moderate"), "medium");
        assert_eq!(normalize_severity("note"), "info");
        let review = |v: &str| ReviewState {
            verdict: v.into(),
            note: "n".into(),
            created_at: String::new(),
        };
        assert_eq!(
            verification("open", None),
            "potential",
            "static detection is never confirmed by default"
        );
        assert_eq!(
            verification("open", Some(&review("confirmed"))),
            "confirmed"
        );
        assert_eq!(
            verification("open", Some(&review("needs_review"))),
            "validating"
        );
        assert_eq!(
            verification("open", Some(&review("false_positive"))),
            "false_positive"
        );
        assert_eq!(
            verification("resolved", Some(&review("confirmed"))),
            "resolved"
        );
    }

    #[test]
    fn guidance_is_labelled_general() {
        let (impact, steps) = cwe_guidance(Some("cwe-95"));
        assert!(impact.contains("code execution"));
        assert!(!steps.is_empty());
        let (fallback, _) = cwe_guidance(None);
        assert!(fallback.contains("depends"));
    }
}
