import { invoke } from "@tauri-apps/api/core";

export type RunState =
  | "draft" | "planned" | "awaiting_approval" | "queued" | "running" | "paused"
  | "validating" | "completed" | "failed" | "cancelled" | "blocked";
export type TaskState =
  | "draft" | "planned" | "awaiting_approval" | "queued" | "running" | "validating"
  | "retry_wait" | "completed" | "failed" | "cancelled" | "blocked";
export type Outcome = "verified" | "unverified" | "blocked" | "failed" | "cancelled";
export type EvidenceClass = "observation" | "hypothesis" | "recommendation" | "applied_change" | "validated_result";

export interface RunBudgets {
  max_replans: number;
  max_parallel: number;
  max_runtime_ms: number;
  max_attempts_per_task: number;
  max_tasks: number;
  max_credits: number;
}

export interface WorkflowRun {
  id: string;
  project_id: string;
  goal: string;
  owner: string;
  state: RunState;
  outcome: Outcome | null;
  reason_code: string | null;
  plan_revision: number;
  approved_revision: number | null;
  approved_capabilities: string[];
  replan_count: number;
  budgets: RunBudgets;
  credits_used: number;
  cancel_requested: boolean;
  pause_requested: boolean;
  cloud_consented: boolean;
  created_ms: number;
  updated_ms: number;
  started_ms: number | null;
  finished_ms: number | null;
}

export interface EvidenceRef { kind: string; id: string; sha256: string | null }

export interface WorkflowTask {
  id: string;
  run_id: string;
  plan_revision: number;
  key: string;
  parent_task_id: string | null;
  delegation_depth: number;
  role: string;
  title: string;
  side_effect: "read_only" | "local_mutation" | "external";
  capabilities: string[];
  scope_digest: string;
  state: TaskState;
  reason_code: string | null;
  attempt_count: number;
  max_attempts: number;
  output: { data?: unknown; evidence_refs?: EvidenceRef[]; delegations?: unknown[] } | null;
  output_sha256: string | null;
  summary: string | null;
  evidence_class: EvidenceClass | null;
  depends_on: string[];
  started_ms: number | null;
  finished_ms: number | null;
}

export interface ApprovalRequest {
  id: string;
  run_id: string;
  task_id: string | null;
  kind: "plan" | "task_capability";
  capabilities: string[];
  scope_digest: string;
  plan_revision: number;
  summary: string;
  status: "pending" | "approved" | "rejected" | "expired" | "superseded";
  requested_ms: number;
  expires_ms: number;
  decided_by: string | null;
}

export interface AttemptRecord {
  task_id: string;
  attempt_no: number;
  worker_id: string;
  status: string;
  error_category: string | null;
  error_detail: string | null;
  started_ms: number;
  finished_ms: number | null;
}

export interface ToolInvocation {
  id: string;
  task_id: string;
  attempt_no: number;
  tool_id: string;
  capability: string;
  side_effect: string;
  args_sha256: string;
  status: "denied" | "started" | "succeeded" | "failed" | "uncertain";
  decision_reason: string;
  output_sha256: string | null;
  started_ms: number;
  finished_ms: number | null;
}

export interface RunDetail {
  run: WorkflowRun;
  tasks: WorkflowTask[];
  approvals: ApprovalRequest[];
  attempts: AttemptRecord[];
  tool_invocations: ToolInvocation[];
}

export interface WorkflowEvent {
  seq: number;
  run_id: string;
  task_id: string | null;
  kind: string;
  detail: Record<string, unknown>;
  correlation_id: string;
  created_ms: number;
}

export interface WorkerRole {
  role: string;
  display_name: string;
  description: string;
  capabilities: string[];
  output_class: EvidenceClass;
}

export interface CapabilityStatus {
  capability: string;
  side_effect: string;
  enabled: boolean;
  tools: string[];
  reason: string;
}

export type MemoryLayer = "working" | "episodic" | "project_fact" | "approved_knowledge" | "evidence_ref";

export interface MemoryItem {
  id: string;
  project_id: string;
  layer: MemoryLayer;
  title: string;
  body: string;
  source_kind: string;
  source_ref: string;
  source_sha256: string | null;
  confidence: number;
  verified: boolean;
  approved_by: string | null;
  updated_ms: number;
  expires_ms: number | null;
}

export interface RetrievalResult {
  items: Array<{ item: MemoryItem; keyword_score: number; vector_score: number; score: number }>;
  candidates: number;
  omitted: number;
  omitted_chars: number;
  vector_model: string;
}

export interface EvidenceGraph {
  nodes: Array<{ id: string; kind: string; ref_id: string; label: string }>;
  edges: Array<{ id: string; from_node: string; to_node: string; relation: string; source_ref: string; confidence: number; provenance: "verified" | "inferred" }>;
  truncated: boolean;
}

export interface ProviderSettings {
  provider: string;
  kind: string;
  base_url: string;
  enabled: boolean;
  role_models: { default_cloud: string | null; default_local: string | null; cloud_by_role: Record<string, string> };
  updated_ms: number;
}

export interface CloudProviderStatus {
  settings: ProviderSettings;
  token_stored: boolean;
  credential_backend: string;
}

export interface Diagnostics {
  provider: string;
  base_url: string;
  reachable: boolean;
  authenticated: boolean;
  models: Array<{ id: string; available: boolean; active: boolean; operation: string | null; description: string | null }>;
  latency_ms: number;
  error: string | null;
  credential_fingerprint: string | null;
}

export interface ConsentRecord {
  consent: {
    project_id: string;
    allow_cloud: boolean;
    allow_source_excerpts: boolean;
    allow_local_fallback: boolean;
    max_payload_bytes: number;
    granted_by: string;
    granted_ms: number;
  };
  allow_web_research: boolean;
  revoked_ms: number | null;
}

export interface EgressPreview {
  provider: string;
  model: string;
  request: { model: string; messages: Array<{ role: string; content?: string }> };
  bytes: number;
  redactions: number;
  contains_source: boolean;
  sha256: string;
}

export interface ProviderRequestRecord {
  request_id: string;
  project_id: string | null;
  run_id: string | null;
  provider: string;
  model: string;
  outcome: string;
  http_status: number | null;
  attempts: number;
  latency_ms: number;
  bytes_sent: number;
  credits: number;
  streamed: boolean;
  created_ms: number;
}

export type OverrideResolution = "requeue" | "cancel" | "side_effect_applied" | "side_effect_not_applied";

export const TERMINAL_RUN_STATES: RunState[] = ["completed", "failed", "cancelled"];

export const workflowApi = {
  roles: () => invoke<WorkerRole[]>("workflow_roles"),
  capabilities: (projectId: string) => invoke<CapabilityStatus[]>("workflow_capability_matrix", { projectId }),
  createInvestigation: (projectId: string, goal: string, researchUrls: string[], cloudReview: boolean, maxParallel: number) =>
    invoke<{ run: WorkflowRun; approvals: ApprovalRequest[] }>("create_workflow_investigation", { projectId, goal, researchUrls, cloudReview, maxParallel }),
  listRuns: (projectId: string | null) => invoke<WorkflowRun[]>("list_workflow_runs", { projectId }),
  detail: (runId: string) => invoke<RunDetail>("workflow_run_detail", { runId }),
  events: (runId: string, cursor: number) => invoke<WorkflowEvent[]>("workflow_events", { runId, cursor }),
  pendingApprovals: () => invoke<ApprovalRequest[]>("pending_workflow_approvals"),
  decide: (approvalId: string, approve: boolean, scopeDigest: string, note: string | null) =>
    invoke<ApprovalRequest>("decide_workflow_approval", { approvalId, approve, scopeDigest, note }),
  start: (runId: string) => invoke<void>("start_workflow_run", { runId }),
  cancel: (runId: string) => invoke<WorkflowRun>("cancel_workflow_run", { runId }),
  pause: (runId: string) => invoke<WorkflowRun>("pause_workflow_run", { runId }),
  resume: (runId: string) => invoke<WorkflowRun>("resume_workflow_run", { runId }),
  overrideTask: (taskId: string, resolution: OverrideResolution) => invoke<WorkflowTask>("override_workflow_task", { taskId, resolution }),
  report: (runId: string, format: "markdown" | "json") => invoke<string>("workflow_report", { runId, format }),
  memorySearch: (projectId: string, query: string) => invoke<RetrievalResult>("memory_search", { projectId, query, maxItems: 20 }),
  memoryList: (projectId: string, layer: MemoryLayer | null) => invoke<MemoryItem[]>("memory_list", { projectId, layer }),
  memoryApprove: (itemId: string) => invoke<MemoryItem>("memory_approve", { itemId }),
  memoryDelete: (projectId: string, itemId: string) => invoke<boolean>("memory_delete", { projectId, itemId }),
  memoryClear: (projectId: string, layer: MemoryLayer | null) => invoke<number>("memory_clear", { projectId, layer }),
  memoryRunGraph: (projectId: string, runId: string) => invoke<EvidenceGraph>("memory_run_graph", { projectId, runId }),
  cloudStatus: () => invoke<CloudProviderStatus>("cloud_provider_status"),
  saveCloudSettings: (baseUrl: string, enabled: boolean, defaultModel: string | null) =>
    invoke<ProviderSettings>("save_cloud_provider_settings", { baseUrl, enabled, defaultModel }),
  setCloudToken: (token: string) => invoke<boolean>("set_cloud_provider_token", { token }),
  clearCloudToken: () => invoke<boolean>("clear_cloud_provider_token"),
  cloudDiagnostics: () => invoke<Diagnostics>("cloud_provider_diagnostics"),
  consent: (projectId: string) => invoke<ConsentRecord | null>("project_cloud_consent", { projectId }),
  grantConsent: (projectId: string, allowCloud: boolean, allowSourceExcerpts: boolean, allowLocalFallback: boolean, allowWebResearch: boolean, maxPayloadBytes: number) =>
    invoke<ConsentRecord>("grant_project_cloud_consent", { projectId, allowCloud, allowSourceExcerpts, allowLocalFallback, allowWebResearch, maxPayloadBytes }),
  revokeConsent: (projectId: string) => invoke<boolean>("revoke_project_cloud_consent", { projectId }),
  requestLog: (projectId: string | null) => invoke<ProviderRequestRecord[]>("cloud_request_log", { projectId }),
  previewQuestion: (projectId: string, prompt: string) => invoke<EgressPreview>("preview_cloud_question", { projectId, prompt }),
  sendQuestion: (projectId: string, prompt: string, confirmedSha256: string) =>
    invoke<string>("send_cloud_question", { projectId, prompt, confirmedSha256 }),
};

/** Human label that keeps planned / running / applied / tested / verified distinct. */
export function evidenceLabel(task: Pick<WorkflowTask, "state" | "evidence_class">): string {
  if (task.state !== "completed") return task.state.replaceAll("_", " ");
  switch (task.evidence_class) {
    case "validated_result": return "verified";
    case "applied_change": return "applied";
    case "observation": return "observed";
    case "hypothesis": return "hypothesis (unverified)";
    case "recommendation": return "recommendation";
    default: return "completed";
  }
}

/** Group tasks into dependency levels for the DAG view. */
export function dagLevels(tasks: WorkflowTask[]): WorkflowTask[][] {
  const byId = new Map(tasks.map((t) => [t.id, t]));
  const depth = new Map<string, number>();
  const visit = (task: WorkflowTask, stack: Set<string>): number => {
    const known = depth.get(task.id);
    if (known !== undefined) return known;
    if (stack.has(task.id)) return 0;
    stack.add(task.id);
    const d = task.depends_on.reduce((max, dep) => {
      const parent = byId.get(dep);
      return parent ? Math.max(max, visit(parent, stack) + 1) : max;
    }, 0);
    stack.delete(task.id);
    depth.set(task.id, d);
    return d;
  };
  const levels: WorkflowTask[][] = [];
  for (const task of tasks) {
    const d = visit(task, new Set());
    (levels[d] ??= []).push(task);
  }
  return levels.filter(Boolean);
}
