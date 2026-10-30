import { invoke } from "@tauri-apps/api/core";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface NormalizedFinding {
  id: string;
  fingerprint: string;
  analyzer: string;
  category: string;
  rule: string | null;
  severity: Severity;
  confidence: number;
  title: string;
  path: string | null;
  start_line: number | null;
  end_line: number | null;
  cwe: string | null;
  review_verdict: string | null;
}
export interface FindingCluster {
  id: string;
  title: string;
  severity: Severity;
  confidence: number;
  risk_score: number;
  analyzers: string[];
  corroborated: boolean;
  confirmed: boolean;
  path: string | null;
  line: number | null;
  cwe: string | null;
  members: NormalizedFinding[];
}
export interface SuppressedFinding { finding_id: string; fingerprint: string; title: string; cause: string }
export interface SecurityPolicy { max_critical: number; max_high: number | null; min_confidence: number; fail_on_secrets: boolean }
export const DEFAULT_POLICY: SecurityPolicy = { max_critical: 0, max_high: null, min_confidence: 0.3, fail_on_secrets: true };
export interface PolicyOutcome { passed: boolean; violations: string[]; counted: Record<string, number> }
export interface CorrelationReport {
  project_id: string;
  generated_ms: number;
  finding_count: number;
  truncated: boolean;
  clusters: FindingCluster[];
  suppressed: SuppressedFinding[];
  policy: SecurityPolicy;
  outcome: PolicyOutcome;
}
export type SuppressionScope = "fingerprint" | "rule" | "path";
export interface Suppression {
  id: string;
  project_id: string;
  scope: SuppressionScope;
  matcher: string;
  reason: string;
  created_by: string;
  created_ms: number;
  expires_ms: number;
  revoked_by: string | null;
  revoked_ms: number | null;
}
export interface SuppressionEvent { suppression_id: string; action: "created" | "revoked"; actor: string; detail: string; created_ms: number }
export interface SnapshotReceipt { id: string; sha256: string; report: CorrelationReport }

export interface MemoryVersion {
  version: number;
  title: string;
  body: string;
  confidence: number;
  verified: boolean;
  source_ref: string;
  change_kind: "revised" | "superseded";
  changed_by: string;
  created_ms: number;
}
export interface KnowledgeConflict {
  id: string;
  project_id: string;
  kind: "memory" | "edge";
  existing_ref: string;
  proposed: Record<string, unknown>;
  reason: string;
  created_ms: number;
  resolved_ms: number | null;
  resolved_by: string | null;
  resolution: "accepted" | "rejected" | null;
}
export interface EmbedReceipt { model: string; embedded: number }
export interface TaskDiff {
  key: string;
  role: string;
  left_state: string | null;
  right_state: string | null;
  output_changed: boolean;
  left_attempts: number;
  right_attempts: number;
  duration_delta_ms: number | null;
}
export interface RunComparison {
  left_run: string;
  right_run: string;
  same_goal: boolean;
  left_outcome: string | null;
  right_outcome: string | null;
  duration_delta_ms: number | null;
  credits_delta: number;
  only_left: string[];
  only_right: string[];
  changed: TaskDiff[];
  unchanged: number;
}
export interface StallReport { run_id: string; stuck: string[]; root_causes: string[] }

export const intelligenceApi = {
  correlation: (projectId: string, policy?: SecurityPolicy) =>
    invoke<CorrelationReport>("security_correlation_report", { projectId, policy: policy ?? null }),
  snapshot: (projectId: string, policy?: SecurityPolicy) =>
    invoke<SnapshotReceipt>("security_correlation_snapshot", { projectId, policy: policy ?? null }),
  verifySnapshot: (snapshotId: string) => invoke<boolean>("verify_security_snapshot", { snapshotId }),
  suppressions: (projectId: string) =>
    invoke<{ suppressions: Suppression[]; events: SuppressionEvent[] }>("list_security_suppressions", { projectId }),
  suppress: (projectId: string, scope: SuppressionScope, matcher: string, reason: string, ttlDays: number) =>
    invoke<Suppression>("create_security_suppression", { projectId, scope, matcher, reason, ttlDays }),
  revokeSuppression: (projectId: string, suppressionId: string) =>
    invoke<boolean>("revoke_security_suppression", { projectId, suppressionId }),
  memoryHistory: (projectId: string, itemId: string) => invoke<MemoryVersion[]>("memory_item_history", { projectId, itemId }),
  conflicts: (projectId: string, openOnly: boolean) => invoke<KnowledgeConflict[]>("knowledge_conflicts", { projectId, openOnly }),
  resolveConflict: (projectId: string, conflictId: string, accept: boolean) =>
    invoke<boolean>("resolve_knowledge_conflict", { projectId, conflictId, accept }),
  embedMemory: (projectId: string, endpoint: string, model: string) =>
    invoke<EmbedReceipt>("embed_project_memory", { projectId, endpoint, model, limit: null }),
  compareRuns: (leftRunId: string, rightRunId: string) => invoke<RunComparison>("compare_workflow_runs", { leftRunId, rightRunId }),
  diagnoseStall: (runId: string) => invoke<StallReport | null>("diagnose_workflow_stall", { runId }),
};

/** Signed millisecond delta as "+1.2 s" / "−300 ms"; "—" when unknown. */
export function formatDelta(ms: number | null): string {
  if (ms === null) return "—";
  const sign = ms > 0 ? "+" : ms < 0 ? "−" : "±";
  const abs = Math.abs(ms);
  return `${sign}${abs >= 1000 ? `${(abs / 1000).toFixed(1)} s` : `${abs} ms`}`;
}

/** Human-readable reason a finding is hidden from the prioritised view. */
export function describeCause(cause: string): string {
  if (cause === "review:false_positive") return "Reviewed as a false positive";
  if (cause.startsWith("suppression:")) return `Suppressed (${cause.slice("suppression:".length)})`;
  return cause;
}

export type SuppressionState = "active" | "expired" | "revoked";
export function suppressionState(s: Suppression, now: number = Date.now()): SuppressionState {
  if (s.revoked_ms !== null) return "revoked";
  return s.expires_ms > now ? "active" : "expired";
}

/** Mirrors the backend rules so the form can explain a refusal before sending. */
export function validateSuppression(form: { scope: SuppressionScope; matcher: string; reason: string; ttlDays: number }): string | null {
  const matcher = form.matcher.trim();
  if (!matcher || matcher.length > 512) return "Enter what to suppress (1–512 characters).";
  if (form.scope === "path" && (matcher === "/" || matcher.includes(".."))) return "A path suppression must name a specific relative prefix.";
  const reason = form.reason.trim().length;
  if (reason < 10 || reason > 2000) return "Explain why in 10–2000 characters; the reason is kept in the audit trail.";
  if (!Number.isInteger(form.ttlDays) || form.ttlDays < 1 || form.ttlDays > 365) return "Suppressions must expire within 1–365 days.";
  return null;
}

export const isLoopbackEndpoint = (raw: string): boolean => {
  try {
    const url = new URL(raw);
    return ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) && url.pathname.endsWith("/embeddings");
  } catch {
    return false;
  }
};
