//! Cross-analyzer security intelligence over the shared `findings` table.
//!
//! * **Normalisation** — every analyzer's severity vocabulary maps onto one
//!   scale; a missing confidence gets a conservative per-analyzer default.
//! * **Correlation** — open findings at the same path and nearby lines that
//!   share a CWE or category are clustered; independent analyzers that agree
//!   raise the cluster's combined (noisy-OR) confidence.
//! * **Suppression** — an expiring, audited overlay created only by a human
//!   approver. Analyzer-owned `findings` rows are never modified. A current
//!   `false_positive` review also hides a finding, citing the review.
//! * **Policy** — a deterministic gate over the unsuppressed clusters.
//!
//! Nothing here is model-driven; models cannot create suppressions because
//! automation principals can never hold approval authority.
use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::collaboration::{new_id, now_ms, sha256_hex, Action, Collaboration};
use crate::Database;

const MAX_FINDINGS: usize = 5000;
const LINE_WINDOW: i64 = 3;
const MAX_SUPPRESSION_DAYS: u32 = 365;
const SECURITY_CATEGORIES: &[&str] = &["security", "secrets", "dependency", "runtime", "database"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Normalise analyzer vocabularies (CVSS words, SARIF levels, ad-hoc).
    /// Unknown values map to `Medium` so nothing silently drops to "info".
    pub fn normalize(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" | "blocker" | "severe" => Self::Critical,
            "high" | "error" | "major" => Self::High,
            "medium" | "moderate" | "warning" | "warn" => Self::Medium,
            "low" | "minor" | "note" => Self::Low,
            "info" | "informational" | "none" | "hint" => Self::Info,
            _ => Self::Medium,
        }
    }

    fn weight(self) -> f64 {
        match self {
            Self::Critical => 10.0,
            Self::High => 7.5,
            Self::Medium => 5.0,
            Self::Low => 2.5,
            Self::Info => 0.5,
        }
    }
}

fn default_confidence(analyzer: &str) -> f64 {
    match analyzer {
        "dependency_audit" | "secret_scanning" | "secret_history" => 0.8,
        "appsec" => 0.6,
        _ => 0.5,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizedFinding {
    pub id: String,
    pub fingerprint: String,
    pub analyzer: String,
    pub category: String,
    pub rule: Option<String>,
    pub severity: Severity,
    pub confidence: f64,
    pub title: String,
    pub path: Option<String>,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub cwe: Option<String>,
    pub review_verdict: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingCluster {
    /// Stable id derived from the sorted member fingerprints.
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// Noisy-OR over the strongest finding of each distinct analyzer.
    pub confidence: f64,
    pub risk_score: f64,
    pub analyzers: Vec<String>,
    /// More than one independent analyzer reported it.
    pub corroborated: bool,
    /// An operator review confirmed at least one member.
    pub confirmed: bool,
    pub path: Option<String>,
    pub line: Option<i64>,
    pub cwe: Option<String>,
    pub members: Vec<NormalizedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuppressedFinding {
    pub finding_id: String,
    pub fingerprint: String,
    pub title: String,
    /// `suppression:<id>` or `review:false_positive`.
    pub cause: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityPolicy {
    pub max_critical: u32,
    pub max_high: Option<u32>,
    /// Clusters below this confidence do not count against the limits.
    pub min_confidence: f64,
    pub fail_on_secrets: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            max_critical: 0,
            max_high: None,
            min_confidence: 0.3,
            fail_on_secrets: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyOutcome {
    pub passed: bool,
    pub violations: Vec<String>,
    pub counted: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelationReport {
    pub project_id: String,
    pub generated_ms: i64,
    pub finding_count: usize,
    /// Findings beyond the load limit are omitted and reported here.
    pub truncated: bool,
    pub clusters: Vec<FindingCluster>,
    pub suppressed: Vec<SuppressedFinding>,
    pub policy: SecurityPolicy,
    pub outcome: PolicyOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionScope {
    Fingerprint,
    Rule,
    Path,
}

impl SuppressionScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint",
            Self::Rule => "rule",
            Self::Path => "path",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fingerprint" => Some(Self::Fingerprint),
            "rule" => Some(Self::Rule),
            "path" => Some(Self::Path),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Suppression {
    pub id: String,
    pub project_id: String,
    pub scope: SuppressionScope,
    pub matcher: String,
    pub reason: String,
    pub created_by: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub revoked_by: Option<String>,
    pub revoked_ms: Option<i64>,
}

impl Suppression {
    fn active(&self, now: i64) -> bool {
        self.revoked_ms.is_none() && self.expires_ms > now
    }

    fn matches(&self, f: &NormalizedFinding) -> bool {
        match self.scope {
            SuppressionScope::Fingerprint => f.fingerprint == self.matcher,
            SuppressionScope::Rule => f.rule.as_deref() == Some(self.matcher.as_str()),
            SuppressionScope::Path => f
                .path
                .as_deref()
                .is_some_and(|p| p.starts_with(self.matcher.as_str())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionEvent {
    pub suppression_id: String,
    pub action: String,
    pub actor: String,
    pub detail: String,
    pub created_ms: i64,
}

/// Cluster normalised findings. Pure and deterministic for a given input.
pub fn correlate(findings: &[NormalizedFinding]) -> Vec<FindingCluster> {
    let n = findings.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], mut i: usize) -> usize {
        while p[i] != i {
            p[i] = p[p[i]];
            i = p[i];
        }
        i
    }
    let mut by_path: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if let Some(path) = f.path.as_deref() {
            by_path.entry(path).or_default().push(i);
        }
    }
    for idxs in by_path.values() {
        for (a, &i) in idxs.iter().enumerate() {
            for &j in &idxs[a + 1..] {
                let (x, y) = (&findings[i], &findings[j]);
                let near = match (x.start_line, y.start_line) {
                    (Some(xs), Some(ys)) => {
                        let xe = x.end_line.unwrap_or(xs).max(xs);
                        let ye = y.end_line.unwrap_or(ys).max(ys);
                        xs <= ye + LINE_WINDOW && ys <= xe + LINE_WINDOW
                    }
                    _ => false,
                };
                let related = match (&x.cwe, &y.cwe) {
                    (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                    _ => x.category == y.category,
                };
                if near && related {
                    let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                    if ri != rj {
                        parent[ri.max(rj)] = ri.min(rj);
                    }
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }
    let mut clusters: Vec<FindingCluster> = groups
        .into_values()
        .map(|idxs| {
            let mut members: Vec<NormalizedFinding> =
                idxs.iter().map(|&i| findings[i].clone()).collect();
            members.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then(b.confidence.total_cmp(&a.confidence))
                    .then(a.fingerprint.cmp(&b.fingerprint))
            });
            let mut best_per_analyzer: BTreeMap<&str, f64> = BTreeMap::new();
            for m in &members {
                let c = if m.review_verdict.as_deref() == Some("confirmed") {
                    m.confidence.max(0.95)
                } else {
                    m.confidence
                };
                let e = best_per_analyzer.entry(m.analyzer.as_str()).or_insert(0.0);
                *e = e.max(c.clamp(0.0, 1.0));
            }
            let confidence = 1.0 - best_per_analyzer.values().map(|c| 1.0 - c).product::<f64>();
            let analyzers: Vec<String> =
                best_per_analyzer.keys().map(|s| (*s).to_owned()).collect();
            let lead = &members[0];
            let confirmed = members
                .iter()
                .any(|m| m.review_verdict.as_deref() == Some("confirmed"));
            let boost = 1.0 + 0.15 * (analyzers.len() as f64 - 1.0);
            let risk =
                (lead.severity.weight() * confidence * boost * if confirmed { 1.2 } else { 1.0 })
                    .min(10.0);
            let fingerprints: BTreeSet<&str> =
                members.iter().map(|m| m.fingerprint.as_str()).collect();
            let id_source = fingerprints.into_iter().collect::<Vec<_>>().join("\n");
            FindingCluster {
                id: format!("corr-{}", &sha256_hex(id_source.as_bytes())[..16]),
                title: lead.title.clone(),
                severity: lead.severity,
                confidence: (confidence * 1000.0).round() / 1000.0,
                risk_score: (risk * 100.0).round() / 100.0,
                corroborated: analyzers.len() > 1,
                analyzers,
                confirmed,
                path: lead.path.clone(),
                line: members.iter().filter_map(|m| m.start_line).min(),
                cwe: members.iter().find_map(|m| m.cwe.clone()),
                members,
            }
        })
        .collect();
    clusters.sort_by(|a, b| {
        b.risk_score
            .total_cmp(&a.risk_score)
            .then(b.severity.cmp(&a.severity))
            .then(a.id.cmp(&b.id))
    });
    clusters
}

/// Deterministic policy gate over unsuppressed clusters.
pub fn evaluate_policy(clusters: &[FindingCluster], policy: &SecurityPolicy) -> PolicyOutcome {
    let mut counted: BTreeMap<String, u32> = BTreeMap::new();
    let mut secrets = 0u32;
    for c in clusters
        .iter()
        .filter(|c| c.confidence >= policy.min_confidence)
    {
        let key = serde_json::to_value(c.severity)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        *counted.entry(key).or_default() += 1;
        if c.members.iter().any(|m| m.category == "secrets") {
            secrets += 1;
        }
    }
    let mut violations = Vec::new();
    let critical = counted.get("critical").copied().unwrap_or(0);
    if critical > policy.max_critical {
        violations.push(format!(
            "{critical} critical cluster(s) exceed the limit of {}",
            policy.max_critical
        ));
    }
    if let Some(max_high) = policy.max_high {
        let high = counted.get("high").copied().unwrap_or(0);
        if high > max_high {
            violations.push(format!(
                "{high} high cluster(s) exceed the limit of {max_high}"
            ));
        }
    }
    if policy.fail_on_secrets && secrets > 0 {
        violations.push(format!("{secrets} unsuppressed secret exposure cluster(s)"));
    }
    PolicyOutcome {
        passed: violations.is_empty(),
        violations,
        counted,
    }
}

pub struct SecurityIntelligence<'a> {
    db: &'a Database,
}

impl<'a> SecurityIntelligence<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    fn conn(&self) -> &rusqlite::Connection {
        self.db.connection()
    }

    /// Load open security findings with normalised severity/confidence and
    /// each finding's current review verdict.
    pub fn load_findings(
        &self,
        project_id: &str,
    ) -> Result<(Vec<NormalizedFinding>, bool), String> {
        let placeholders = SECURITY_CATEGORIES
            .iter()
            .map(|c| format!("'{c}'"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT f.id, f.fingerprint, COALESCE(f.analyzer_key, f.category), f.category, f.sub_category,
                    f.severity, f.confidence, f.title,
                    COALESCE(files.relative_path,
                             (SELECT e.uri FROM finding_evidence e WHERE e.finding_id=f.id AND e.uri IS NOT NULL ORDER BY e.id LIMIT 1)),
                    f.source_start_line, f.source_end_line, f.cwe,
                    (SELECT r.verdict FROM security_finding_reviews r
                      WHERE r.finding_id=f.id AND r.scan_run_id=COALESCE(f.last_run_id, f.run_id)
                        AND r.indexed_content_hash IS files.content_hash
                      ORDER BY r.id DESC LIMIT 1)
             FROM findings f LEFT JOIN files ON files.id=f.file_id
             WHERE f.project_id=?1 AND f.status='open' AND f.category IN ({placeholders})
             ORDER BY f.id LIMIT ?2"
        );
        let mut stmt = self.conn().prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![project_id, (MAX_FINDINGS + 1) as i64], |r| {
                let analyzer: String = r.get(2)?;
                let confidence: Option<f64> = r.get(6)?;
                let severity: String = r.get(5)?;
                Ok(NormalizedFinding {
                    id: r.get(0)?,
                    fingerprint: r.get(1)?,
                    confidence: confidence
                        .filter(|c| c.is_finite())
                        .unwrap_or_else(|| default_confidence(&analyzer))
                        .clamp(0.0, 1.0),
                    analyzer,
                    category: r.get(3)?,
                    rule: r.get(4)?,
                    severity: Severity::normalize(&severity),
                    title: r.get(7)?,
                    path: r.get(8)?,
                    start_line: r.get(9)?,
                    end_line: r.get(10)?,
                    cwe: r.get(11)?,
                    review_verdict: r.get(12)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let truncated = out.len() > MAX_FINDINGS;
        out.truncate(MAX_FINDINGS);
        Ok((out, truncated))
    }

    /// Correlate, apply suppressions and evaluate `policy`. Read-only.
    pub fn report(
        &self,
        project_id: &str,
        policy: &SecurityPolicy,
    ) -> Result<CorrelationReport, String> {
        let now = now_ms();
        let (findings, truncated) = self.load_findings(project_id)?;
        let suppressions: Vec<Suppression> = self
            .suppressions(project_id)?
            .into_iter()
            .filter(|s| s.active(now))
            .collect();
        let finding_count = findings.len();
        let mut kept = Vec::with_capacity(findings.len());
        let mut suppressed = Vec::new();
        for f in findings {
            let cause = suppressions
                .iter()
                .find(|s| s.matches(&f))
                .map(|s| format!("suppression:{}", s.id))
                .or_else(|| {
                    (f.review_verdict.as_deref() == Some("false_positive"))
                        .then(|| "review:false_positive".to_owned())
                });
            match cause {
                Some(cause) => suppressed.push(SuppressedFinding {
                    finding_id: f.id,
                    fingerprint: f.fingerprint,
                    title: f.title,
                    cause,
                }),
                None => kept.push(f),
            }
        }
        let clusters = correlate(&kept);
        let outcome = evaluate_policy(&clusters, policy);
        Ok(CorrelationReport {
            project_id: project_id.to_owned(),
            generated_ms: now,
            finding_count,
            truncated,
            clusters,
            suppressed,
            policy: policy.clone(),
            outcome,
        })
    }

    /// Persist a hashed snapshot of the report so reports can cite it.
    pub fn snapshot(
        &self,
        project_id: &str,
        policy: &SecurityPolicy,
    ) -> Result<(String, String, CorrelationReport), String> {
        let report = self.report(project_id, policy)?;
        let json = serde_json::to_string(&report).map_err(|e| e.to_string())?;
        let digest = sha256_hex(json.as_bytes());
        let id = new_id("corrsnap");
        self.conn()
            .execute(
                "INSERT INTO security_correlation_snapshots
                   (id,project_id,created_ms,finding_count,cluster_count,suppressed_count,policy_verdict,report_json,report_sha256)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    id,
                    project_id,
                    report.generated_ms,
                    report.finding_count as i64,
                    report.clusters.len() as i64,
                    report.suppressed.len() as i64,
                    if report.outcome.passed { "pass" } else { "fail" },
                    json,
                    digest
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok((id, digest, report))
    }

    /// Re-hash a stored snapshot; `false` means it was altered after capture.
    pub fn verify_snapshot(&self, snapshot_id: &str) -> Result<bool, String> {
        let row: Option<(String, String)> = self
            .conn()
            .query_row(
                "SELECT report_json, report_sha256 FROM security_correlation_snapshots WHERE id=?1",
                [snapshot_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let (json, digest) = row.ok_or("snapshot not found")?;
        Ok(sha256_hex(json.as_bytes()) == digest)
    }

    /// Create an expiring suppression. Requires human approval authority.
    pub fn suppress(
        &self,
        project_id: &str,
        actor: &str,
        scope: SuppressionScope,
        matcher: &str,
        reason: &str,
        ttl_days: u32,
    ) -> Result<Suppression, String> {
        let collab = Collaboration::new(self.db);
        collab.authorize(project_id, actor, Action::Approve)?;
        let matcher = matcher.trim();
        let reason = reason.trim();
        if matcher.is_empty() || matcher.len() > 512 || matcher.chars().any(char::is_control) {
            return Err("suppression matcher must be 1–512 printable characters".into());
        }
        if scope == SuppressionScope::Path && (matcher == "/" || matcher.contains("..")) {
            return Err("a path suppression must name a specific relative prefix".into());
        }
        if reason.chars().count() < 10 || reason.chars().count() > 2000 {
            return Err("a suppression needs a reason of 10–2000 characters".into());
        }
        if ttl_days == 0 || ttl_days > MAX_SUPPRESSION_DAYS {
            return Err(format!(
                "suppressions expire within 1–{MAX_SUPPRESSION_DAYS} days"
            ));
        }
        let now = now_ms();
        let id = new_id("supp");
        let expires = now + i64::from(ttl_days) * 86_400_000;
        let tx = self
            .conn()
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO security_suppressions(id,project_id,scope,matcher,reason,created_by,created_ms,expires_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, project_id, scope.as_str(), matcher, reason, actor, now, expires],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO security_suppression_events(suppression_id,project_id,action,actor,detail,created_ms)
             VALUES (?1,?2,'created',?3,?4,?5)",
            params![
                id,
                project_id,
                actor,
                json!({"scope": scope.as_str(), "matcher": matcher, "ttl_days": ttl_days, "reason": reason})
                    .to_string(),
                now
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        collab.audit(
            actor,
            "security_suppress",
            Some(project_id),
            Some(&id),
            "ok",
            json!({"scope": scope.as_str()}),
        );
        self.suppression(&id)?
            .ok_or_else(|| "suppression not found".into())
    }

    pub fn revoke(
        &self,
        project_id: &str,
        suppression_id: &str,
        actor: &str,
    ) -> Result<(), String> {
        let collab = Collaboration::new(self.db);
        collab.authorize(project_id, actor, Action::Approve)?;
        let now = now_ms();
        let tx = self
            .conn()
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        let changed = tx
            .execute(
                "UPDATE security_suppressions SET revoked_by=?3, revoked_ms=?4
                 WHERE id=?1 AND project_id=?2 AND revoked_ms IS NULL",
                params![suppression_id, project_id, actor, now],
            )
            .map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("suppression not found or already revoked".into());
        }
        tx.execute(
            "INSERT INTO security_suppression_events(suppression_id,project_id,action,actor,detail,created_ms)
             VALUES (?1,?2,'revoked',?3,'{}',?4)",
            params![suppression_id, project_id, actor, now],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        collab.audit(
            actor,
            "security_unsuppress",
            Some(project_id),
            Some(suppression_id),
            "ok",
            json!({}),
        );
        Ok(())
    }

    fn suppression(&self, id: &str) -> Result<Option<Suppression>, String> {
        self.conn()
            .query_row(&format!("{} WHERE id=?1", Self::select()), [id], Self::read)
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn suppressions(&self, project_id: &str) -> Result<Vec<Suppression>, String> {
        let mut stmt = self
            .conn()
            .prepare(&format!(
                "{} WHERE project_id=?1 ORDER BY created_ms DESC LIMIT 1000",
                Self::select()
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([project_id], Self::read)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn suppression_events(&self, project_id: &str) -> Result<Vec<SuppressionEvent>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT suppression_id, action, actor, detail, created_ms FROM security_suppression_events
                 WHERE project_id=?1 ORDER BY id DESC LIMIT 1000",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([project_id], |r| {
                Ok(SuppressionEvent {
                    suppression_id: r.get(0)?,
                    action: r.get(1)?,
                    actor: r.get(2)?,
                    detail: r.get(3)?,
                    created_ms: r.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    fn select() -> &'static str {
        "SELECT id, project_id, scope, matcher, reason, created_by, created_ms, expires_ms, revoked_by, revoked_ms
         FROM security_suppressions"
    }

    fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<Suppression> {
        let scope: String = r.get(2)?;
        Ok(Suppression {
            id: r.get(0)?,
            project_id: r.get(1)?,
            scope: SuppressionScope::parse(&scope).unwrap_or(SuppressionScope::Fingerprint),
            matcher: r.get(3)?,
            reason: r.get(4)?,
            created_by: r.get(5)?,
            created_ms: r.get(6)?,
            expires_ms: r.get(7)?,
            revoked_by: r.get(8)?,
            revoked_ms: r.get(9)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collaboration::PrincipalKind;

    fn nf(
        fp: &str,
        analyzer: &str,
        cat: &str,
        sev: &str,
        conf: f64,
        line: i64,
        cwe: Option<&str>,
    ) -> NormalizedFinding {
        NormalizedFinding {
            id: format!("f-{fp}"),
            fingerprint: fp.into(),
            analyzer: analyzer.into(),
            category: cat.into(),
            rule: Some(format!("{analyzer}.rule")),
            severity: Severity::normalize(sev),
            confidence: conf,
            title: format!("{analyzer} finding"),
            path: Some("src/app.py".into()),
            start_line: Some(line),
            end_line: Some(line),
            cwe: cwe.map(Into::into),
            review_verdict: None,
        }
    }

    #[test]
    fn severity_vocabularies_normalise_conservatively() {
        assert_eq!(Severity::normalize("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::normalize("error"), Severity::High);
        assert_eq!(Severity::normalize("warning"), Severity::Medium);
        assert_eq!(Severity::normalize("note"), Severity::Low);
        assert_eq!(Severity::normalize("weird"), Severity::Medium);
    }

    #[test]
    fn independent_analyzers_corroborate_and_raise_confidence() {
        let findings = vec![
            nf("a", "appsec", "security", "high", 0.6, 10, Some("CWE-89")),
            nf("b", "runtime", "runtime", "medium", 0.5, 12, Some("cwe-89")),
            // Same place, unrelated CWE: separate cluster.
            nf("c", "appsec", "security", "low", 0.9, 11, Some("CWE-79")),
            // Same CWE but far away: separate cluster.
            nf("d", "runtime", "runtime", "high", 0.5, 80, Some("CWE-89")),
        ];
        let clusters = correlate(&findings);
        assert_eq!(clusters.len(), 3);
        let sqli = clusters.iter().find(|c| c.members.len() == 2).unwrap();
        assert!(sqli.corroborated);
        assert_eq!(sqli.analyzers, vec!["appsec", "runtime"]);
        assert_eq!(sqli.severity, Severity::High);
        assert!(
            (sqli.confidence - 0.8).abs() < 1e-9,
            "noisy-OR of 0.6 and 0.5"
        );
        assert_eq!(clusters[0].id, sqli.id, "corroborated high ranks first");
        // Cluster ids are stable regardless of input order.
        let mut reversed = findings.clone();
        reversed.reverse();
        assert_eq!(correlate(&reversed)[0].id, sqli.id);
    }

    #[test]
    fn same_analyzer_duplicates_do_not_inflate_confidence() {
        let findings = vec![
            nf("a", "appsec", "security", "high", 0.6, 10, Some("CWE-89")),
            nf("b", "appsec", "security", "high", 0.6, 11, Some("CWE-89")),
        ];
        let c = &correlate(&findings)[0];
        assert_eq!(c.members.len(), 2);
        assert!(!c.corroborated);
        assert!((c.confidence - 0.6).abs() < 1e-9);
    }

    #[test]
    fn policy_gate_counts_confident_clusters_and_secrets() {
        let mut secret = nf(
            "s",
            "secret_scanning",
            "secrets",
            "high",
            0.8,
            1,
            Some("CWE-798"),
        );
        secret.path = Some("config.env".into());
        let clusters = correlate(&[
            nf(
                "a",
                "appsec",
                "security",
                "critical",
                0.9,
                10,
                Some("CWE-78"),
            ),
            nf(
                "weak",
                "appsec",
                "security",
                "critical",
                0.1,
                50,
                Some("CWE-22"),
            ),
            secret,
        ]);
        let outcome = evaluate_policy(&clusters, &SecurityPolicy::default());
        assert!(!outcome.passed);
        assert_eq!(
            outcome.counted.get("critical"),
            Some(&1),
            "low-confidence cluster ignored"
        );
        assert_eq!(outcome.violations.len(), 2);
        let lenient = SecurityPolicy {
            max_critical: 1,
            fail_on_secrets: false,
            ..SecurityPolicy::default()
        };
        assert!(evaluate_policy(&clusters, &lenient).passed);
    }

    fn seed(db: &Database) {
        db.connection()
            .execute_batch(
                "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES ('p1','/tmp/p1','p1','/tmp/p1');
                 INSERT INTO analysis_runs(id, project_id, status, analyzer_version) VALUES ('r1','p1','completed','t');
                 INSERT INTO files(id, project_id, relative_path, language, content_hash, byte_size, relative_path_identity, is_active)
                   VALUES ('file1','p1','src/db.py','python','h',10,'src/db.py',1),
                          ('file2','p1','vendor/lib.py','python','h2',10,'vendor/lib.py',1);
                 INSERT INTO findings(id,project_id,run_id,category,sub_category,severity,confidence,title,description,file_id,source_start_line,source_end_line,cwe,status,fingerprint,analyzer_key)
                   VALUES ('f1','p1','r1','security','sql.injection','high',0.7,'SQL injection','d','file1',20,20,'CWE-89','open','fp1','appsec'),
                          ('f2','p1','r1','runtime','runtime.sql','error',NULL,'Tainted query','d','file1',21,22,'CWE-89','open','fp2','runtime'),
                          ('f3','p1','r1','security','eval.use','critical',0.9,'eval of input','d','file2',5,5,'CWE-95','open','fp3','appsec'),
                          ('f4','p1','r1','quality','complexity','high',1.0,'Too complex','d','file1',1,1,NULL,'open','fp4','quality'),
                          ('f5','p1','r1','security','old','high',0.9,'Resolved','d','file1',1,1,NULL,'resolved','fp5','appsec');",
            )
            .unwrap();
    }

    #[test]
    fn end_to_end_correlation_suppression_audit_and_snapshot() {
        let db = Database::open_in_memory().unwrap();
        seed(&db);
        let intel = SecurityIntelligence::new(&db);
        let before = intel.report("p1", &SecurityPolicy::default()).unwrap();
        assert_eq!(
            before.finding_count, 3,
            "quality and resolved findings are excluded"
        );
        assert_eq!(before.clusters.len(), 2);
        assert!(
            !before.outcome.passed,
            "critical eval finding fails the gate"
        );
        let sqli = before.clusters.iter().find(|c| c.corroborated).unwrap();
        assert_eq!(sqli.members.len(), 2);
        assert!(
            (sqli.members[1].confidence - 0.5).abs() < 1e-9
                || (sqli.members[0].confidence - 0.5).abs() < 1e-9,
            "missing confidence takes the analyzer default"
        );

        // Automation principals can never suppress.
        let collab = Collaboration::new(&db);
        collab
            .ensure_principal("bot:planner", "Planner", PrincipalKind::Automation)
            .unwrap();
        assert!(intel
            .suppress(
                "p1",
                "bot:planner",
                SuppressionScope::Path,
                "vendor/",
                "third-party code we do not ship",
                30
            )
            .is_err());
        // Validation: unbounded suppressions and vague reasons are refused.
        assert!(intel
            .suppress(
                "p1",
                "alice",
                SuppressionScope::Path,
                "vendor/",
                "too short",
                30
            )
            .is_err());
        assert!(intel
            .suppress(
                "p1",
                "alice",
                SuppressionScope::Path,
                "vendor/",
                "third-party code we do not ship",
                0
            )
            .is_err());
        assert!(intel
            .suppress(
                "p1",
                "alice",
                SuppressionScope::Path,
                "../",
                "third-party code we do not ship",
                30
            )
            .is_err());

        let s = intel
            .suppress(
                "p1",
                "alice",
                SuppressionScope::Path,
                "vendor/",
                "third-party code we do not ship",
                30,
            )
            .unwrap();
        let after = intel.report("p1", &SecurityPolicy::default()).unwrap();
        assert_eq!(after.clusters.len(), 1);
        assert_eq!(after.suppressed.len(), 1);
        assert_eq!(after.suppressed[0].cause, format!("suppression:{}", s.id));
        assert!(after.outcome.passed);

        // Terms cannot be widened in place, and the audit trail is append-only.
        assert!(db
            .connection()
            .execute(
                "UPDATE security_suppressions SET expires_ms = expires_ms + 1 WHERE id=?1",
                [&s.id]
            )
            .is_err());
        assert!(db
            .connection()
            .execute("UPDATE security_suppression_events SET actor='x'", [])
            .is_err());
        assert!(db
            .connection()
            .execute("DELETE FROM security_suppression_events", [])
            .is_err());

        intel.revoke("p1", &s.id, "alice").unwrap();
        assert!(intel.revoke("p1", &s.id, "alice").is_err());
        let events = intel.suppression_events("p1").unwrap();
        assert_eq!(
            events.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
            vec!["revoked", "created"]
        );
        assert_eq!(
            intel
                .report("p1", &SecurityPolicy::default())
                .unwrap()
                .clusters
                .len(),
            2
        );

        // A current false-positive review hides a finding and says why.
        db.connection()
            .execute(
                "INSERT INTO security_finding_reviews(finding_id,project_id,scan_run_id,indexed_content_hash,verdict,note)
                 VALUES ('f3','p1','r1','h2','false_positive','sandboxed eval of constant')",
                [],
            )
            .unwrap();
        let reviewed = intel.report("p1", &SecurityPolicy::default()).unwrap();
        assert_eq!(reviewed.suppressed[0].cause, "review:false_positive");

        let (snap, digest, _) = intel.snapshot("p1", &SecurityPolicy::default()).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(intel.verify_snapshot(&snap).unwrap());
        db.connection()
            .execute(
                "UPDATE security_correlation_snapshots SET report_json = report_json || ' '",
                [],
            )
            .unwrap();
        assert!(
            !intel.verify_snapshot(&snap).unwrap(),
            "tampering is detected"
        );
    }
}
