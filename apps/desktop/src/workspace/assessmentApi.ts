import { invoke } from "@tauri-apps/api/core";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verification = "potential" | "validating" | "confirmed" | "false_positive" | "resolved";

export interface StreamEvent {
  type: "event";
  key: string;
  seq: number;
  ts_ms: number;
  run_id: string;
  task_id: string | null;
  agent: string | null;
  tool: string | null;
  stage: string;
  status: string;
  target: string | null;
  message: string;
  duration_ms: number | null;
  correlation_id: string;
  finding_ids: string[];
}

export interface FindingCard {
  type: "finding";
  key: string;
  seq: number;
  ts_ms: number;
  run_id: string;
  task_id: string;
  agent: string;
  finding_id: string;
  source: "appsec" | "secret" | "dependency";
  title: string;
  severity: Severity;
  verification: Verification;
  rule_id: string;
  description: string;
  target: string;
  location: string | null;
  first_seen: string;
  cwe: string | null;
  owasp: string | null;
  cve: string[];
  cvss: number | null;
  confidence: number | null;
  evidence: Array<{ kind: string; location: string | null; summary: string }>;
  impact: string;
  remediation: string[];
  remediation_basis: string;
  limitations: string[];
  review: { verdict: string; note: string; created_at: string } | null;
  scan_run_id: string | null;
  file_sha256: string | null;
  reviewable: boolean;
}

export type StreamItem = StreamEvent | FindingCard;

export interface StreamPage {
  items: StreamItem[];
  next_cursor: number;
  has_more: boolean;
  run_state: string;
  outcome: string | null;
}

export interface AssessmentSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  potential: number;
  validating: number;
  confirmed: number;
  false_positive: number;
  resolved: number;
  passed: number;
  checks_completed: number;
  checks_total: number;
}

export type ReviewVerdict = "confirmed" | "false_positive" | "needs_review";

export const assessmentApi = {
  page: (runId: string, cursor: number, limit = 250) => invoke<StreamPage>("assessment_stream_page", { runId, cursor, limit }),
  summary: (runId: string) => invoke<AssessmentSummary>("assessment_summary", { runId }),
  review: (card: FindingCard, verdict: ReviewVerdict, note: string, projectId: string) =>
    invoke("review_assessment_finding", {
      projectId, findingId: card.finding_id, scanRunId: card.scan_run_id, fileSha256: card.file_sha256, verdict, note,
    }),
  retestAppSec: (projectId: string) => invoke("run_security_analysis", { projectId }),
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const VERIFICATION_LABEL: Record<Verification, string> = {
  potential: "Potential",
  validating: "Validating",
  confirmed: "Confirmed",
  false_positive: "False positive",
  resolved: "Resolved",
};

/** Sort key: events by seq; cards after the event that produced them. */
function order(a: StreamItem, b: StreamItem): number {
  if (a.seq !== b.seq) return a.seq - b.seq;
  if (a.type !== b.type) return a.type === "event" ? -1 : 1;
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

/**
 * Merge incoming items (push or replay) into the current list. Items are
 * deduplicated by key; a re-delivered finding card replaces the old one so
 * review/verification updates show without duplicating it. Returns the same
 * array instance when nothing changed (stable identity for React).
 */
export function mergeItems(current: StreamItem[], incoming: StreamItem[], cap = 20_000): StreamItem[] {
  if (!incoming.length) return current;
  const index = new Map(current.map((item, i) => [item.key, i]));
  let next: StreamItem[] | null = null;
  const appended: StreamItem[] = [];
  for (const item of incoming) {
    const at = index.get(item.key);
    if (at === undefined) {
      appended.push(item);
      index.set(item.key, -1);
    } else if (at >= 0 && item.type === "finding" && JSON.stringify(item) !== JSON.stringify(current[at])) {
      next ??= current.slice();
      next[at] = item;
    }
  }
  if (!appended.length && !next) return current;
  const base = next ?? current;
  const lastSeq = base.length ? base[base.length - 1].seq : -Infinity;
  const merged = appended.every((i) => i.seq >= lastSeq) ? base.concat(appended.sort(order)) : base.concat(appended).sort(order);
  return merged.length > cap ? merged.slice(merged.length - cap) : merged;
}

export function maxSeq(items: StreamItem[]): number {
  return items.reduce((m, i) => (i.type === "event" && i.seq > m ? i.seq : m), 0);
}

export interface StreamFilter {
  query: string;
  kinds: "all" | "findings" | "errors" | "tools" | "agents";
  agent: string | null;
  severity: Severity | null;
  verification: Verification | "passed" | null;
}

export const EMPTY_FILTER: StreamFilter = { query: "", kinds: "all", agent: null, severity: null, verification: null };

export function matches(item: StreamItem, filter: StreamFilter): boolean {
  if (filter.agent && item.agent !== filter.agent) return false;
  if (filter.severity || (filter.verification && filter.verification !== "passed")) {
    if (item.type !== "finding") return false;
    if (filter.severity && item.severity !== filter.severity) return false;
    if (filter.verification && filter.verification !== "passed" && item.verification !== filter.verification) return false;
  }
  if (filter.verification === "passed" && !(item.type === "event" && item.stage === "OK" && item.finding_ids.length === 0)) return false;
  switch (filter.kinds) {
    case "findings": if (item.type !== "finding" && !(item.type === "event" && item.stage === "POTENTIAL")) return false; break;
    case "errors": if (!(item.type === "event" && ["ERROR", "DENIED", "BLOCKED", "RETRY"].includes(item.stage))) return false; break;
    case "tools": if (!(item.type === "event" && item.tool)) return false; break;
    case "agents": if (!(item.type === "event" && item.agent)) return false; break;
  }
  const q = filter.query.trim().toLowerCase();
  if (!q) return true;
  const hay = item.type === "event"
    ? `${item.stage} ${item.agent ?? ""} ${item.tool ?? ""} ${item.message} ${item.correlation_id}`
    : `${item.title} ${item.finding_id} ${item.rule_id} ${item.location ?? ""} ${item.cwe ?? ""} ${item.description}`;
  return hay.toLowerCase().includes(q);
}

export function formatClock(ms: number): string {
  const d = new Date(ms);
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms == null || ms < 0) return "";
  if (ms < 1000) return `${ms} ms`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

/** Plain-text log line used for copy and download. */
export function toLogLine(item: StreamItem): string {
  if (item.type === "event") {
    const parts = [`[${formatClock(item.ts_ms)}]`, `[${item.stage}]`];
    if (item.agent) parts.push(`[${item.agent}]`);
    parts.push(item.message);
    if (item.duration_ms != null) parts.push(`(${formatDuration(item.duration_ms)})`);
    return parts.join(" ");
  }
  return `[${formatClock(item.ts_ms)}] [FINDING] [${item.severity.toUpperCase()}/${VERIFICATION_LABEL[item.verification]}] ${item.title} @ ${item.location ?? item.target} (${item.finding_id})`;
}
