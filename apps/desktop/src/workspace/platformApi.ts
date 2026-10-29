import { invoke } from "@tauri-apps/api/core";

import type { ProviderSettings } from "./workflowApi";

export interface UsageStats {
  calls: number;
  succeeded: number;
  failed: number;
  success_rate: number;
  credits: number;
  calls_with_token_usage: number;
  prompt_tokens: number;
  completion_tokens: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  streamed_calls: number;
  retried_calls: number;
  redactions: number;
  bytes_sent: number;
}
export interface GroupUsage { key: string; stats: UsageStats }
export interface LlmAnalytics {
  since_ms: number;
  generated_ms: number;
  totals: UsageStats;
  by_model: GroupUsage[];
  by_provider: GroupUsage[];
  by_role: GroupUsage[];
  by_day: GroupUsage[];
  outcomes: Record<string, number>;
  cost_basis: string;
}
export interface RoleLatency { role: string; completed: number; failed: number; avg_ms: number; p95_ms: number }
export interface PlatformAlert { severity: "critical" | "warning" | "info"; code: string; message: string }
export interface MetricsSnapshot {
  generated_ms: number;
  runs_by_state: Record<string, number>;
  tasks_by_state: Record<string, number>;
  queue_depth: number;
  live_leases: number;
  stale_leases: number;
  attempts_failed_24h: number;
  retries_24h: number;
  error_categories_24h: Record<string, number>;
  tool_calls_24h: number;
  tool_denials_24h: Record<string, number>;
  uncertain_side_effects: number;
  role_latency: RoleLatency[];
  provider_error_rate_24h: number;
  alerts: PlatformAlert[];
}
export interface RetentionReport { runs_deleted: number; provider_requests_deleted: number; audit_records_deleted: number }
export interface Citation {
  id: string;
  claim: string;
  quote: string | null;
  support: "supported" | "unsupported" | "contradicted";
  url: string | null;
  title: string | null;
  sha256: string | null;
  fetched_ms: number;
}
export interface PdfExport { path: string; base64: string; bytes: number }

export type SearchProviderKind = "brave" | "searxng";
export interface SearchProviderRecord {
  config: { kind: SearchProviderKind; base_url: string; max_results: number };
  enabled: boolean;
  updated_ms: number;
}

export type Role = "viewer" | "analyst" | "approver" | "administrator";
export const ROLES: Role[] = ["viewer", "analyst", "approver", "administrator"];
export interface AccessPolicy { enforce_rbac: boolean; separation_of_duties: boolean }
export interface Membership {
  project_id: string;
  principal_id: string;
  display_name: string;
  role: Role;
  granted_by: string;
  granted_ms: number;
  revision: number;
}
export interface Invitation {
  id: string;
  project_id: string;
  role: Role;
  invited_by: string;
  created_ms: number;
  expires_ms: number;
  accepted_by: string | null;
  revoked_ms: number | null;
}
export interface AccessOverview {
  policy: AccessPolicy;
  me: string;
  my_role: Role | null;
  members: Membership[];
  invitations: Invitation[];
}
export interface Comment {
  id: string;
  project_id: string;
  target_kind: string;
  target_id: string;
  parent_id: string | null;
  author: string;
  body: string;
  revision: number;
  created_ms: number;
  edited_ms: number | null;
  deleted: boolean;
}
export interface AuditRecord {
  seq: number;
  actor: string;
  action: string;
  project_id: string | null;
  target: string | null;
  outcome: "allowed" | "denied" | "error";
  detail: unknown;
  created_ms: number;
}
export const API_SCOPES = ["runs:read", "runs:write", "reports:read", "analytics:read"] as const;
export interface ApiToken {
  id: string;
  principal_id: string;
  label: string;
  scopes: string[];
  project_id: string;
  created_by: string;
  created_ms: number;
  expires_ms: number;
  last_used_ms: number | null;
  revoked: boolean;
}
export interface ApiStatus { running: boolean; address: string | null }

export const platformApi = {
  localModelStatus: () => invoke<{ settings: ProviderSettings | null }>("local_model_status"),
  saveLocalModel: (baseUrl: string, enabled: boolean, defaultModel: string | null, localByRole: Record<string, string> | null) =>
    invoke<ProviderSettings>("save_local_model_settings", { baseUrl, enabled, defaultModel, localByRole }),
  saveCloudRoleModels: (baseUrl: string, enabled: boolean, defaultModel: string | null, cloudByRole: Record<string, string>) =>
    invoke<ProviderSettings>("save_cloud_provider_settings", { baseUrl, enabled, defaultModel, cloudByRole }),
  searchStatus: () => invoke<{ settings: SearchProviderRecord | null; key_stored: boolean }>("search_provider_status"),
  saveSearch: (kind: SearchProviderKind, baseUrl: string, enabled: boolean, maxResults: number) =>
    invoke<SearchProviderRecord>("save_search_provider_settings", { kind, baseUrl, enabled, maxResults }),
  setSearchKey: (key: string) => invoke<boolean>("set_search_provider_key", { key }),
  clearSearchKey: () => invoke<boolean>("clear_search_provider_key"),

  analytics: (projectId: string | null, days: number) => invoke<LlmAnalytics>("llm_usage_analytics", { projectId, days }),
  metrics: (projectId: string | null) => invoke<MetricsSnapshot>("workflow_metrics", { projectId }),
  exportDiagnostics: () => invoke<string>("export_platform_diagnostics"),
  prune: (olderThanDays: number, keepLatest: number) => invoke<RetentionReport>("prune_workflow_history", { olderThanDays, keepLatest }),
  citations: (runId: string) => invoke<Citation[]>("research_citations", { runId }),
  reportPdf: (runId: string) => invoke<PdfExport>("workflow_report_pdf", { runId }),

  access: (projectId: string) => invoke<AccessOverview>("project_access", { projectId }),
  setPolicy: (projectId: string, enforceRbac: boolean, separationOfDuties: boolean) =>
    invoke<AccessPolicy>("set_project_access_policy", { projectId, enforceRbac, separationOfDuties }),
  registerPrincipal: (principalId: string, displayName: string) =>
    invoke<{ id: string }>("register_principal", { principalId, displayName }),
  grantRole: (projectId: string, principalId: string, role: Role, expectedRevision: number | null) =>
    invoke<Membership>("grant_project_role", { projectId, principalId, role, expectedRevision }),
  revokeRole: (projectId: string, principalId: string) => invoke<boolean>("revoke_project_role", { projectId, principalId }),
  invite: (projectId: string, role: Role, ttlHours: number) =>
    invoke<{ invitation: Invitation; code: string }>("create_project_invitation", { projectId, role, ttlHours }),
  acceptInvitation: (code: string) => invoke<Membership>("accept_project_invitation", { code, principalId: null }),
  revokeInvitation: (invitationId: string) => invoke<boolean>("revoke_project_invitation", { invitationId }),
  comments: (projectId: string, targetKind: string, targetId: string) =>
    invoke<Comment[]>("list_comments", { projectId, targetKind, targetId }),
  addComment: (projectId: string, targetKind: string, targetId: string, parentId: string | null, body: string) =>
    invoke<Comment>("add_comment", { projectId, targetKind, targetId, parentId, body }),
  editComment: (commentId: string, body: string, expectedRevision: number) =>
    invoke<Comment>("edit_comment", { commentId, body, expectedRevision }),
  deleteComment: (commentId: string) => invoke<boolean>("delete_comment", { commentId }),
  auditLog: (projectId: string | null) => invoke<AuditRecord[]>("audit_log", { projectId, limit: 200 }),

  apiStatus: () => invoke<ApiStatus>("automation_api_status"),
  startApi: (port: number) => invoke<ApiStatus>("start_automation_api", { port }),
  stopApi: () => invoke<ApiStatus>("stop_automation_api"),
  createToken: (projectId: string, label: string, scopes: string[], ttlDays: number) =>
    invoke<{ token: ApiToken; plaintext: string }>("create_api_token", { projectId, label, scopes, ttlDays }),
  listTokens: (projectId: string) => invoke<ApiToken[]>("list_api_tokens", { projectId }),
  revokeToken: (tokenId: string) => invoke<boolean>("revoke_api_token", { tokenId }),
};

/** Trigger a browser download of a base64 PDF (works in the WebView and web builds). */
export function downloadPdf(base64: string, filename: string): void {
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const formatPercent = (ratio: number) => `${(ratio * 100).toFixed(ratio > 0 && ratio < 0.01 ? 2 : 0)}%`;
export const formatMs = (ms: number) => (ms >= 10_000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`);

/** Agent conversation: each finished task as a message from its role, in completion order. */
export interface AgentMessage { taskId: string; role: string; title: string; text: string; evidenceClass: string | null; inReplyTo: string[]; at: number }
export function agentConversation(tasks: Array<{
  id: string; key: string; role: string; title: string; summary: string | null; evidence_class: string | null;
  depends_on?: string[]; started_ms: number | null; finished_ms: number | null; reason_code: string | null;
}>): AgentMessage[] {
  return tasks
    .filter((t) => t.summary && t.reason_code !== "superseded_by_replan")
    .map((t) => ({
      taskId: t.id,
      role: t.role,
      title: t.title,
      text: t.summary ?? "",
      evidenceClass: t.evidence_class,
      inReplyTo: t.depends_on ?? [],
      at: t.finished_ms ?? t.started_ms ?? 0,
    }))
    .sort((a, b) => a.at - b.at);
}
