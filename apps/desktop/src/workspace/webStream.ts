/**
 * Adapts a guided web-security session (activity log + findings) into the same
 * StreamItem / AssessmentSummary model the local assessment terminal renders, so
 * web and local scans share one terminal view. Pure functions — no I/O.
 */
import type { AssessmentSummary, FindingCard, Severity, StreamEvent, StreamItem, Verification } from "./assessmentApi";
import type { GuidedActivityRecord, GuidedSecuritySessionRecord, WebFindingRecord } from "./types";

const FINDING_SEQ_BASE = 1_000_000;

function tsOf(value: string | null | undefined): number {
  if (!value) return Date.now();
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? Date.now() : ms;
}

/** Map a guided activity event_type to a terminal stage tag (drives row color). */
export function webStage(eventType: string): string {
  const t = eventType.toLowerCase();
  if (/(error|failed|failure)/.test(t)) return "ERROR";
  if (/(denied|blocked|reject)/.test(t)) return "BLOCKED";
  if (/(finding|vuln|anomaly|detected)/.test(t)) return "POTENTIAL";
  if (/(complete|completed|done|passed|verified|ok)/.test(t)) return "OK";
  if (/(warn|caution|skip)/.test(t)) return "WARN";
  return "INFO";
}

const SEVERITY_MAP: Record<WebFindingRecord["severity"], Severity> = {
  critical: "critical", high: "high", medium: "medium", low: "low", informational: "info",
};

const CONFIDENCE_MAP: Record<WebFindingRecord["confidence"], Verification> = {
  Potential: "potential", Likely: "validating", Confirmed: "confirmed",
};

const CONFIDENCE_SCORE: Record<WebFindingRecord["confidence"], number> = {
  Potential: 0.4, Likely: 0.7, Confirmed: 0.95,
};

export function webActivityToEvent(session: GuidedSecuritySessionRecord, a: GuidedActivityRecord): StreamEvent {
  return {
    type: "event",
    key: "wa-" + a.id,
    seq: a.sequence,
    ts_ms: tsOf(a.created_at),
    run_id: session.id,
    task_id: null,
    agent: a.phase || null,
    tool: null,
    stage: webStage(a.event_type),
    status: a.event_type,
    target: session.target_url,
    message: a.message,
    duration_ms: null,
    correlation_id: a.id,
    finding_ids: [],
  };
}

export function webFindingToCard(session: GuidedSecuritySessionRecord, f: WebFindingRecord, index: number): FindingCard {
  const location = [f.method, f.endpoint_url].filter(Boolean).join(" ") + (f.parameter_name ? ` (${f.parameter_name})` : "");
  return {
    type: "finding",
    key: "wf-" + f.id,
    seq: FINDING_SEQ_BASE + index,
    ts_ms: tsOf(f.first_detected),
    run_id: session.id,
    task_id: f.scan_id,
    agent: "web_scanner",
    finding_id: f.id,
    // Web findings are not local-source reviewable; `reviewable: false` keeps them
    // out of the appsec review/retest actions in the shared finding card.
    source: "appsec",
    title: f.title,
    severity: SEVERITY_MAP[f.severity] ?? "info",
    verification: CONFIDENCE_MAP[f.confidence] ?? "potential",
    rule_id: f.category,
    description: f.description,
    target: f.target || f.endpoint_url,
    location: location || f.endpoint_url,
    first_seen: f.first_detected,
    cwe: null,
    owasp: null,
    cve: [],
    cvss: null,
    confidence: CONFIDENCE_SCORE[f.confidence] ?? null,
    evidence: f.reproduction_summary ? [{ kind: "reproduction", location: f.endpoint_url, summary: f.reproduction_summary }] : [],
    impact: f.impact,
    remediation: f.remediation ? [f.remediation] : [],
    remediation_basis: "Authorized web assessment",
    limitations: ["Web finding: verify manually within the authorized scope before acting."],
    review: null,
    scan_run_id: f.scan_id,
    file_sha256: null,
    reviewable: false,
  };
}

/** Combined, ordered stream for a web session: activity events first, findings after. */
export function webSessionStream(
  session: GuidedSecuritySessionRecord,
  activities: GuidedActivityRecord[],
  findings: WebFindingRecord[],
): StreamItem[] {
  const events = activities.map((a) => webActivityToEvent(session, a));
  const cards = findings.map((f, i) => webFindingToCard(session, f, i));
  return [...events, ...cards];
}

export function webSessionSummary(findings: WebFindingRecord[]): AssessmentSummary {
  const summary: AssessmentSummary = {
    total: findings.length,
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
    potential: 0, validating: 0, confirmed: 0, false_positive: 0, resolved: 0,
    passed: 0, checks_completed: 0, checks_total: 0,
  };
  for (const f of findings) {
    summary[SEVERITY_MAP[f.severity] ?? "info"] += 1;
    if (f.status === "false_positive") summary.false_positive += 1;
    else if (f.status === "resolved") summary.resolved += 1;
    else summary[CONFIDENCE_MAP[f.confidence] ?? "potential"] += 1;
  }
  return summary;
}

/** Web session states that mean the scan is still producing output. */
export const WEB_ACTIVE_STATES: GuidedSecuritySessionRecord["status"][] = ["preparing", "awaiting_approval", "approved", "running"];
