//! Observability for the workflow platform and model gateway, computed from
//! the durable SQLite records (no extra telemetry store):
//!
//! * [`llm_analytics`] — calls, outcomes, latency percentiles, token usage
//!   (only where the provider reported it) and credits, by model, role and
//!   day.
//! * [`metrics_snapshot`] — queue depth, worker leases (live/stale), task
//!   latency per role, retries, tool denials, and derived operator alerts.
//! * [`export_diagnostics`] — a redacted JSON bundle for support: metadata,
//!   counts and digests only; never prompts, outputs, goals or secrets.
//!
//! Correlation: every workflow event carries the run id, every provider
//! call carries its `X-Request-Id`, and both are linked by `run_id`/`task_id`.
use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::Database;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

fn percentile(sorted: &[i64], p: f64) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UsageStats {
    pub calls: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub success_rate: f64,
    pub credits: u64,
    /// Calls whose provider reported token usage (streams do not).
    pub calls_with_token_usage: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub avg_latency_ms: i64,
    pub p50_latency_ms: i64,
    pub p95_latency_ms: i64,
    pub streamed_calls: u64,
    pub retried_calls: u64,
    pub redactions: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupUsage {
    pub key: String,
    pub stats: UsageStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmAnalytics {
    pub since_ms: i64,
    pub generated_ms: i64,
    pub totals: UsageStats,
    pub by_model: Vec<GroupUsage>,
    pub by_provider: Vec<GroupUsage>,
    pub by_role: Vec<GroupUsage>,
    pub by_day: Vec<GroupUsage>,
    pub outcomes: BTreeMap<String, u64>,
    /// Credits are the billable unit OpenMindAI documents (one per
    /// successful call). Token counts are never estimated.
    pub cost_basis: String,
}

#[derive(Default)]
struct Acc {
    latencies: Vec<i64>,
    stats: UsageStats,
}

impl Acc {
    fn add(&mut self, r: &Row) {
        let s = &mut self.stats;
        s.calls += 1;
        if r.outcome == "ok" {
            s.succeeded += 1;
        } else {
            s.failed += 1;
        }
        s.credits += r.credits;
        if r.prompt_tokens.is_some() || r.completion_tokens.is_some() {
            s.calls_with_token_usage += 1;
        }
        s.prompt_tokens += r.prompt_tokens.unwrap_or(0);
        s.completion_tokens += r.completion_tokens.unwrap_or(0);
        s.streamed_calls += u64::from(r.streamed);
        s.retried_calls += u64::from(r.attempts > 1);
        s.redactions += r.redactions;
        s.bytes_sent += r.bytes_sent;
        self.latencies.push(r.latency_ms);
    }

    fn finish(mut self) -> UsageStats {
        self.latencies.sort_unstable();
        let s = &mut self.stats;
        if s.calls > 0 {
            s.success_rate = s.succeeded as f64 / s.calls as f64;
            s.avg_latency_ms = self.latencies.iter().sum::<i64>() / s.calls as i64;
        }
        s.p50_latency_ms = percentile(&self.latencies, 50.0);
        s.p95_latency_ms = percentile(&self.latencies, 95.0);
        self.stats
    }
}

struct Row {
    provider: String,
    model: String,
    role: Option<String>,
    day: String,
    outcome: String,
    attempts: i64,
    latency_ms: i64,
    bytes_sent: u64,
    redactions: u64,
    credits: u64,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    streamed: bool,
}

fn groups(map: BTreeMap<String, Acc>) -> Vec<GroupUsage> {
    let mut out: Vec<GroupUsage> = map
        .into_iter()
        .map(|(key, acc)| GroupUsage {
            key,
            stats: acc.finish(),
        })
        .collect();
    out.sort_by(|a, b| b.stats.calls.cmp(&a.stats.calls).then(a.key.cmp(&b.key)));
    out
}

/// Model-call analytics since `since_ms`, optionally for one project.
pub fn llm_analytics(
    db: &Database,
    project_id: Option<&str>,
    since_ms: i64,
) -> Result<LlmAnalytics, String> {
    let mut stmt = db
        .connection()
        .prepare(
            "SELECT r.provider, r.model, t.role, strftime('%Y-%m-%d', r.created_ms/1000, 'unixepoch'),
                    r.outcome, r.attempts, r.latency_ms, r.bytes_sent, r.redactions, r.credits,
                    r.prompt_tokens, r.completion_tokens, r.streamed
             FROM provider_requests r LEFT JOIN workflow_tasks t ON t.id = r.task_id
             WHERE r.created_ms >= ?1 AND (?2 IS NULL OR r.project_id = ?2)
             ORDER BY r.created_ms DESC LIMIT 50000",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![since_ms, project_id], |r| {
            Ok(Row {
                provider: r.get(0)?,
                model: r.get(1)?,
                role: r.get(2)?,
                day: r.get(3)?,
                outcome: r.get(4)?,
                attempts: r.get(5)?,
                latency_ms: r.get(6)?,
                bytes_sent: r.get::<_, i64>(7)?.max(0) as u64,
                redactions: r.get::<_, i64>(8)?.max(0) as u64,
                credits: r.get::<_, i64>(9)?.max(0) as u64,
                prompt_tokens: r.get::<_, Option<i64>>(10)?.map(|v| v.max(0) as u64),
                completion_tokens: r.get::<_, Option<i64>>(11)?.map(|v| v.max(0) as u64),
                streamed: r.get::<_, i64>(12)? != 0,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut total = Acc::default();
    let (mut by_model, mut by_provider, mut by_role, mut by_day) = (
        BTreeMap::<String, Acc>::new(),
        BTreeMap::<String, Acc>::new(),
        BTreeMap::<String, Acc>::new(),
        BTreeMap::<String, Acc>::new(),
    );
    let mut outcomes = BTreeMap::new();
    for row in rows {
        let row = row.map_err(|e| e.to_string())?;
        total.add(&row);
        by_model.entry(row.model.clone()).or_default().add(&row);
        by_provider.entry(row.provider.clone()).or_default().add(&row);
        by_role
            .entry(row.role.clone().unwrap_or_else(|| "interactive".into()))
            .or_default()
            .add(&row);
        by_day.entry(row.day.clone()).or_default().add(&row);
        *outcomes.entry(row.outcome.clone()).or_insert(0) += 1;
    }
    let mut by_day = groups(by_day);
    by_day.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(LlmAnalytics {
        since_ms,
        generated_ms: now_ms(),
        totals: total.finish(),
        by_model: groups(by_model),
        by_provider: groups(by_provider),
        by_role: groups(by_role),
        by_day,
        outcomes,
        cost_basis: "provider credits (1 per successful OpenMindAI call); local models cost 0 credits; \
                     tokens are reported only when the provider returned usage"
            .into(),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleLatency {
    pub role: String,
    pub completed: u64,
    pub failed: u64,
    pub avg_ms: i64,
    pub p95_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub generated_ms: i64,
    pub runs_by_state: BTreeMap<String, u64>,
    pub tasks_by_state: BTreeMap<String, u64>,
    /// Tasks queued or waiting to retry (work not yet claimed).
    pub queue_depth: u64,
    pub live_leases: u64,
    pub stale_leases: u64,
    pub attempts_failed_24h: u64,
    pub retries_24h: u64,
    pub error_categories_24h: BTreeMap<String, u64>,
    pub tool_calls_24h: u64,
    pub tool_denials_24h: BTreeMap<String, u64>,
    pub uncertain_side_effects: u64,
    pub role_latency: Vec<RoleLatency>,
    pub provider_error_rate_24h: f64,
    pub alerts: Vec<Alert>,
}

fn count_by(db: &Database, sql: &str, p: &[&dyn rusqlite::ToSql]) -> Result<BTreeMap<String, u64>, String> {
    let mut stmt = db.connection().prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(p, |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|e| e.to_string())?;
    rows.map(|r| r.map(|(k, v)| (k, v.max(0) as u64)).map_err(|e| e.to_string()))
        .collect()
}

fn scalar(db: &Database, sql: &str, p: &[&dyn rusqlite::ToSql]) -> Result<u64, String> {
    db.connection()
        .query_row(sql, p, |r| r.get::<_, i64>(0))
        .map(|v| v.max(0) as u64)
        .map_err(|e| e.to_string())
}

/// Point-in-time operational metrics with derived alerts.
pub fn metrics_snapshot(db: &Database, project_id: Option<&str>) -> Result<MetricsSnapshot, String> {
    let now = now_ms();
    let day = now - 24 * 3_600_000;
    let runs_by_state = count_by(
        db,
        "SELECT state, COUNT(*) FROM workflow_runs WHERE (?1 IS NULL OR project_id=?1) GROUP BY state",
        &[&project_id],
    )?;
    let tasks_by_state = count_by(
        db,
        "SELECT t.state, COUNT(*) FROM workflow_tasks t JOIN workflow_runs r ON r.id=t.run_id
         WHERE (?1 IS NULL OR r.project_id=?1) GROUP BY t.state",
        &[&project_id],
    )?;
    let queue_depth = tasks_by_state.get("queued").copied().unwrap_or(0)
        + tasks_by_state.get("retry_wait").copied().unwrap_or(0);
    let live_leases = scalar(
        db,
        "SELECT COUNT(*) FROM workflow_worker_leases l JOIN workflow_runs r ON r.id=l.run_id
         WHERE l.expires_ms > ?1 AND (?2 IS NULL OR r.project_id=?2)",
        &[&now, &project_id],
    )?;
    let stale_leases = scalar(
        db,
        "SELECT COUNT(*) FROM workflow_worker_leases l JOIN workflow_runs r ON r.id=l.run_id
         WHERE l.expires_ms <= ?1 AND (?2 IS NULL OR r.project_id=?2)",
        &[&now, &project_id],
    )?;
    let error_categories_24h = count_by(
        db,
        "SELECT a.error_category, COUNT(*) FROM workflow_task_attempts a
         JOIN workflow_tasks t ON t.id=a.task_id JOIN workflow_runs r ON r.id=t.run_id
         WHERE a.error_category IS NOT NULL AND a.started_ms >= ?1 AND (?2 IS NULL OR r.project_id=?2)
         GROUP BY a.error_category",
        &[&day, &project_id],
    )?;
    let attempts_failed_24h = error_categories_24h.values().sum();
    let retries_24h = scalar(
        db,
        "SELECT COUNT(*) FROM workflow_task_attempts a
         JOIN workflow_tasks t ON t.id=a.task_id JOIN workflow_runs r ON r.id=t.run_id
         WHERE a.attempt_no > 1 AND a.started_ms >= ?1 AND (?2 IS NULL OR r.project_id=?2)",
        &[&day, &project_id],
    )?;
    let tool_calls_24h = scalar(
        db,
        "SELECT COUNT(*) FROM workflow_tool_invocations i JOIN workflow_runs r ON r.id=i.run_id
         WHERE i.started_ms >= ?1 AND (?2 IS NULL OR r.project_id=?2)",
        &[&day, &project_id],
    )?;
    let tool_denials_24h = count_by(
        db,
        "SELECT i.decision_reason, COUNT(*) FROM workflow_tool_invocations i JOIN workflow_runs r ON r.id=i.run_id
         WHERE i.status='denied' AND i.started_ms >= ?1 AND (?2 IS NULL OR r.project_id=?2)
         GROUP BY i.decision_reason",
        &[&day, &project_id],
    )?;
    let uncertain_side_effects = scalar(
        db,
        "SELECT COUNT(*) FROM workflow_tool_invocations i JOIN workflow_runs r ON r.id=i.run_id
         WHERE i.status='uncertain' AND (?1 IS NULL OR r.project_id=?1)",
        &[&project_id],
    )?;
    let mut role_latency = Vec::new();
    {
        let mut stmt = db
            .connection()
            .prepare(
                "SELECT t.role, t.state, t.finished_ms - t.started_ms FROM workflow_tasks t
                 JOIN workflow_runs r ON r.id=t.run_id
                 WHERE t.started_ms IS NOT NULL AND t.finished_ms IS NOT NULL
                   AND t.finished_ms >= ?1 AND (?2 IS NULL OR r.project_id=?2)
                 LIMIT 20000",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![now - 7 * 24 * 3_600_000, project_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })
            .map_err(|e| e.to_string())?;
        let mut by_role: BTreeMap<String, (u64, u64, Vec<i64>)> = BTreeMap::new();
        for row in rows {
            let (role, state, ms) = row.map_err(|e| e.to_string())?;
            let e = by_role.entry(role).or_default();
            if state == "completed" {
                e.0 += 1;
            } else if state == "failed" {
                e.1 += 1;
            }
            e.2.push(ms.max(0));
        }
        for (role, (completed, failed, mut ms)) in by_role {
            ms.sort_unstable();
            role_latency.push(RoleLatency {
                role,
                completed,
                failed,
                avg_ms: if ms.is_empty() {
                    0
                } else {
                    ms.iter().sum::<i64>() / ms.len() as i64
                },
                p95_ms: percentile(&ms, 95.0),
            });
        }
    }
    let provider_calls = scalar(
        db,
        "SELECT COUNT(*) FROM provider_requests WHERE created_ms >= ?1 AND (?2 IS NULL OR project_id=?2)",
        &[&day, &project_id],
    )?;
    let provider_errors = scalar(
        db,
        "SELECT COUNT(*) FROM provider_requests WHERE created_ms >= ?1 AND outcome <> 'ok'
         AND (?2 IS NULL OR project_id=?2)",
        &[&day, &project_id],
    )?;
    let provider_error_rate_24h = if provider_calls == 0 {
        0.0
    } else {
        provider_errors as f64 / provider_calls as f64
    };

    let mut alerts = Vec::new();
    let mut alert = |severity: &str, code: &str, message: String| {
        alerts.push(Alert {
            severity: severity.into(),
            code: code.into(),
            message,
        })
    };
    if uncertain_side_effects > 0 {
        alert(
            "critical",
            "uncertain_side_effects",
            format!("{uncertain_side_effects} tool side effect(s) need operator confirmation"),
        );
    }
    if stale_leases > 0 {
        alert(
            "warning",
            "stale_leases",
            format!("{stale_leases} expired worker lease(s); run recovery reconciles them"),
        );
    }
    let blocked = runs_by_state.get("blocked").copied().unwrap_or(0);
    if blocked > 0 {
        alert(
            "warning",
            "blocked_runs",
            format!("{blocked} run(s) blocked and awaiting operator action"),
        );
    }
    if provider_calls >= 5 && provider_error_rate_24h >= 0.25 {
        alert(
            "warning",
            "provider_errors",
            format!(
                "model provider error rate {:.0}% over {provider_calls} call(s) in 24 h",
                provider_error_rate_24h * 100.0
            ),
        );
    }
    let policy_denials = error_categories_24h.get("policy").copied().unwrap_or(0);
    if policy_denials > 0 {
        alert(
            "info",
            "policy_denials",
            format!("{policy_denials} task attempt(s) stopped by policy in 24 h"),
        );
    }
    if tool_denials_24h.contains_key("tool_call_loop_detected") {
        alert(
            "warning",
            "loop_detected",
            "a worker repeated an identical tool call and was stopped".into(),
        );
    }

    Ok(MetricsSnapshot {
        generated_ms: now,
        runs_by_state,
        tasks_by_state,
        queue_depth,
        live_leases,
        stale_leases,
        attempts_failed_24h,
        retries_24h,
        error_categories_24h,
        tool_calls_24h,
        tool_denials_24h,
        uncertain_side_effects,
        role_latency,
        provider_error_rate_24h,
        alerts,
    })
}

/// Write a redacted diagnostics bundle (JSON) to `path`. It holds versions,
/// schema state, metrics, analytics and recent event *kinds* — never goals,
/// prompts, model output, source text, URLs or credentials.
pub fn export_diagnostics(db: &Database, path: &Path) -> Result<Value, String> {
    let schema: i64 = db
        .connection()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let integrity: String = db
        .connection()
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let recent_events = count_by(
        db,
        "SELECT kind, COUNT(*) FROM workflow_events WHERE created_ms >= ?1 GROUP BY kind",
        &[&(now_ms() - 24 * 3_600_000)],
    )?;
    let bundle = json!({
        "format": "codetwin-diagnostics/1",
        "generated_ms": now_ms(),
        "app_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "schema_version": schema,
        "sqlite_quick_check": integrity,
        "metrics": metrics_snapshot(db, None)?,
        "llm_analytics_7d": llm_analytics(db, None, now_ms() - 7 * 24 * 3_600_000)?,
        "event_kinds_24h": recent_events,
        "redaction": "no goals, prompts, model output, source, URLs, tokens or keys are included",
    });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("o.sqlite3")).unwrap();
        db.connection()
            .execute(
                "INSERT INTO projects(id,root_path,display_name) VALUES ('p1','/tmp/o1','p1')",
                [],
            )
            .unwrap();
        (dir, db)
    }

    fn call(db: &Database, id: &str, model: &str, outcome: &str, latency: i64, tokens: Option<i64>) {
        db.connection()
            .execute(
                "INSERT INTO provider_requests(request_id,project_id,provider,model,operation,outcome,attempts,
                    latency_ms,bytes_sent,credits,prompt_tokens,completion_tokens,created_ms)
                 VALUES (?1,'p1','openmindai',?2,'chat.completions',?3,1,?4,100,?5,?6,?6,?7)",
                params![id, model, outcome, latency, i64::from(outcome == "ok"), tokens, now_ms()],
            )
            .unwrap();
    }

    #[test]
    fn analytics_aggregate_truthfully() {
        let (_d, db) = db();
        call(&db, "a", "lite", "ok", 100, Some(10));
        call(&db, "b", "lite", "ok", 300, None);
        call(&db, "c", "super", "timeout", 900, None);
        let a = llm_analytics(&db, Some("p1"), 0).unwrap();
        assert_eq!(a.totals.calls, 3);
        assert_eq!(a.totals.succeeded, 2);
        assert_eq!(a.totals.credits, 2);
        assert_eq!(a.totals.calls_with_token_usage, 1, "never estimated");
        assert_eq!(a.totals.prompt_tokens, 10);
        assert_eq!(a.by_model[0].key, "lite");
        assert_eq!(a.by_model[0].stats.p95_latency_ms, 300);
        assert_eq!(a.outcomes.get("timeout"), Some(&1));
        assert_eq!(a.by_role[0].key, "interactive");
        assert_eq!(a.by_day.len(), 1);
        let other = llm_analytics(&db, Some("nope"), 0).unwrap();
        assert_eq!(other.totals.calls, 0);
    }

    #[test]
    fn metrics_and_alerts_and_redacted_bundle() {
        let (dir, db) = db();
        for (i, outcome) in ["ok", "timeout", "unavailable", "ok", "timeout"].iter().enumerate() {
            call(&db, &format!("r{i}"), "lite", outcome, 50, None);
        }
        let m = metrics_snapshot(&db, Some("p1")).unwrap();
        assert!(m.provider_error_rate_24h > 0.5);
        assert!(m.alerts.iter().any(|a| a.code == "provider_errors"));
        let path = dir.path().join("diag/bundle.json");
        let bundle = export_diagnostics(&db, &path).unwrap();
        assert_eq!(bundle["sqlite_quick_check"], "ok");
        let text = std::fs::read_to_string(path).unwrap();
        assert!(!text.contains("/tmp/o1"), "no paths leak into diagnostics");
    }
}
