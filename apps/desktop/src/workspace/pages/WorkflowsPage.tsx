import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { EmptyState, LoadingState, PageHeader, Panel, ProjectSelect, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import {
  dagLevels, evidenceLabel, TERMINAL_RUN_STATES, workflowApi,
  type ApprovalRequest, type CapabilityStatus, type CloudProviderStatus, type ConsentRecord, type Diagnostics,
  type EgressPreview, type EvidenceGraph, type MemoryItem, type MemoryLayer, type ProviderRequestRecord,
  type RetrievalResult, type RunDetail, type WorkerRole, type WorkflowEvent, type WorkflowRun,
} from "../workflowApi";
import "../workflows.css";

type Tab = "runs" | "approvals" | "memory" | "cloud" | "capabilities";
const TABS: Array<{ id: Tab; label: string }> = [
  { id: "runs", label: "Runs" },
  { id: "approvals", label: "Approval inbox" },
  { id: "memory", label: "Memory" },
  { id: "cloud", label: "Cloud & consent" },
  { id: "capabilities", label: "Capabilities" },
];

const time = (ms: number | null | undefined) => (ms ? new Date(ms).toLocaleString() : "—");
const short = (digest: string | null | undefined, n = 12) => (digest ? digest.slice(0, n) : "—");

function useErrorToast() {
  const { setToast } = useWorkspace();
  return useCallback((error: unknown) => setToast({ tone: "error", message: String(error) }), [setToast]);
}

export function WorkflowsPage() {
  const { projects, activeProjectId } = useWorkspace();
  const [projectId, setProjectId] = useState<string | null>(activeProjectId);
  const [tab, setTab] = useState<Tab>("runs");
  useEffect(() => { if (!projectId && activeProjectId) setProjectId(activeProjectId); }, [activeProjectId, projectId]);

  return (
    <section className="ws-page ws-workflows">
      <PageHeader
        eyebrow="Durable orchestration"
        title="Workflows"
        description="Plan, approve and run bounded specialist workflows. Nothing executes until you approve the exact scope; model output is never treated as evidence."
        actions={<ProjectSelect projects={projects} value={projectId} onChange={setProjectId}/>}
      />
      <div className="wf-tabs" role="tablist" aria-label="Workflow sections">
        {TABS.map((t) => (
          <button key={t.id} role="tab" type="button" aria-selected={tab === t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {!projectId && tab !== "approvals" ? (
        <EmptyState icon="projects" title="Select an indexed project" description="Workflows are scoped to one indexed project."/>
      ) : (
        <div role="tabpanel">
          {tab === "runs" && projectId && <RunsTab projectId={projectId}/>}
          {tab === "approvals" && <ApprovalsTab/>}
          {tab === "memory" && projectId && <MemoryTab projectId={projectId}/>}
          {tab === "cloud" && projectId && <CloudTab projectId={projectId}/>}
          {tab === "capabilities" && projectId && <CapabilitiesTab projectId={projectId}/>}
        </div>
      )}
    </section>
  );
}

function RunsTab({ projectId }: { projectId: string }) {
  const onError = useErrorToast();
  const [runs, setRuns] = useState<WorkflowRun[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const refresh = useCallback(() => workflowApi.listRuns(projectId).then(setRuns).catch(onError), [projectId, onError]);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const off = listen<{ run_id: string }>("workflow://settled", () => { void refresh(); });
    return () => { void off.then((fn) => fn()); };
  }, [refresh]);

  return (
    <div className="wf-grid">
      <div className="wf-col">
        <GoalComposer projectId={projectId} onCreated={(run) => { setSelected(run.id); void refresh(); }}/>
        <Panel title="Run history">
          {!runs ? <LoadingState/> : runs.length === 0 ? <p className="ws-form-help">No workflow runs yet.</p> : (
            <ul className="wf-run-list">
              {runs.map((run) => (
                <li key={run.id}>
                  <button type="button" className={selected === run.id ? "active" : ""} onClick={() => setSelected(run.id)}>
                    <strong>{run.goal}</strong>
                    <span><StatusBadge status={run.state}/> {run.outcome && <StatusBadge status={run.outcome}/>} <small>{time(run.created_ms)}</small></span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <div className="wf-col wf-col-wide">
        {selected ? <RunView projectId={projectId} runId={selected} onChanged={refresh}/> :
          <EmptyState icon="agents" title="No run selected" description="Compose a goal or pick a run to see its plan, live timeline and evidence."/>}
      </div>
    </div>
  );
}

function GoalComposer({ projectId, onCreated }: { projectId: string; onCreated: (run: WorkflowRun) => void }) {
  const onError = useErrorToast();
  const [goal, setGoal] = useState("");
  const [urls, setUrls] = useState("");
  const [cloud, setCloud] = useState(false);
  const [parallel, setParallel] = useState(3);
  const [busy, setBusy] = useState(false);
  async function submit() {
    setBusy(true);
    try {
      const researchUrls = urls.split(/\s+/).map((u) => u.trim()).filter(Boolean);
      const { run } = await workflowApi.createInvestigation(projectId, goal, researchUrls, cloud, parallel);
      setGoal("");
      onCreated(run);
    } catch (error) {
      onError(error);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Panel title="Goal composer">
      <div className="ws-form-stack">
        <label className="ws-field"><span>Engineering goal</span>
          <textarea rows={3} maxLength={4000} value={goal} onChange={(e) => setGoal(e.target.value)} placeholder="e.g. Review how authentication tokens are validated"/>
        </label>
        <label className="ws-field"><span>Research sources (optional, one HTTPS URL per line, max 5)</span>
          <textarea rows={2} value={urls} onChange={(e) => setUrls(e.target.value)} placeholder="https://docs.example.org/security"/>
        </label>
        <label className="ws-check-field"><input type="checkbox" checked={cloud} onChange={(e) => setCloud(e.target.checked)}/> Add OpenMindAI Cloud review of redacted summaries (needs project consent)</label>
        <label className="ws-field"><span>Parallel read-only workers</span>
          <select value={parallel} onChange={(e) => setParallel(Number(e.target.value))}>{[1, 2, 3, 4].map((n) => <option key={n} value={n}>{n}</option>)}</select>
        </label>
        <p className="ws-form-help">Creating a plan executes nothing. You approve the exact scope next.</p>
        <div className="ws-button-row"><button type="button" className="ws-button ws-button-primary" disabled={busy || !goal.trim()} onClick={() => void submit()}>{busy ? "Planning…" : "Create plan"}</button></div>
      </div>
    </Panel>
  );
}

function RunView({ projectId, runId, onChanged }: { projectId: string; runId: string; onChanged: () => void }) {
  const onError = useErrorToast();
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [events, setEvents] = useState<WorkflowEvent[]>([]);
  const [report, setReport] = useState<string | null>(null);
  const [graph, setGraph] = useState<EvidenceGraph | null>(null);
  const cursor = useRef(0);

  const load = useCallback(async () => {
    try {
      setDetail(await workflowApi.detail(runId));
      const fresh = await workflowApi.events(runId, cursor.current);
      if (fresh.length) {
        cursor.current = fresh[fresh.length - 1].seq;
        setEvents((prev) => [...prev, ...fresh].slice(-400));
      }
    } catch (error) {
      onError(error);
    }
  }, [runId, onError]);

  useEffect(() => { cursor.current = 0; setEvents([]); setReport(null); setGraph(null); void load(); }, [runId, load]);
  const live = detail && !TERMINAL_RUN_STATES.includes(detail.run.state) && detail.run.state !== "awaiting_approval";
  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => { void load(); }, 1000);
    return () => window.clearInterval(timer);
  }, [live, load]);

  async function act(fn: () => Promise<unknown>) {
    try { await fn(); await load(); onChanged(); } catch (error) { onError(error); }
  }

  if (!detail) return <LoadingState/>;
  const { run, tasks, approvals, tool_invocations: tools, attempts } = detail;
  const current = tasks.filter((t) => t.reason_code !== "superseded_by_replan");
  const pending = approvals.filter((a) => a.status === "pending");
  return (
    <div className="wf-run">
      <Panel title="Run" action={<span className="wf-badges"><StatusBadge status={run.state}/>{run.outcome && <StatusBadge status={run.outcome}/>}</span>}>
        <p className="wf-goal">{run.goal}</p>
        <dl className="wf-meta">
          <div><dt>Reason</dt><dd>{run.reason_code ?? "—"}</dd></div>
          <div><dt>Plan revision</dt><dd>{run.plan_revision} {run.approved_revision === run.plan_revision ? "(approved)" : "(not approved)"}</dd></div>
          <div><dt>Parallel</dt><dd>{run.budgets.max_parallel}</dd></div>
          <div><dt>Credits</dt><dd>{run.credits_used} / {run.budgets.max_credits}</dd></div>
          <div><dt>Runtime budget</dt><dd>{Math.round(run.budgets.max_runtime_ms / 60000)} min</dd></div>
          <div><dt>Cloud</dt><dd>{run.cloud_consented ? "consented" : "offline only"}</dd></div>
        </dl>
        <div className="ws-button-row">
          {run.state === "queued" && <button type="button" className="ws-button ws-button-primary" onClick={() => void act(() => workflowApi.start(run.id))}>Run approved plan</button>}
          {(run.state === "running" || run.state === "queued") && <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.pause(run.id))}>Pause</button>}
          {(run.state === "paused" || run.state === "blocked") && <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.resume(run.id))}>Resume</button>}
          {!TERMINAL_RUN_STATES.includes(run.state) && <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.cancel(run.id))}>Cancel</button>}
          {TERMINAL_RUN_STATES.includes(run.state) && <>
            <button type="button" className="ws-button ws-button-secondary" onClick={() => void workflowApi.report(run.id, "markdown").then(setReport).catch(onError)}>View report</button>
            <button type="button" className="ws-button ws-button-secondary" onClick={() => void workflowApi.memoryRunGraph(projectId, run.id).then(setGraph).catch(onError)}>Evidence graph</button>
          </>}
        </div>
      </Panel>
      {pending.length > 0 && <Panel title="Approvals required for this run"><ApprovalList approvals={pending} onDecided={load}/></Panel>}
      <Panel title="Task DAG">
        <div className="wf-dag" role="list" aria-label="Task dependency levels">
          {dagLevels(current).map((level, i) => (
            <div key={i} className="wf-dag-level" role="listitem">
              <span className="wf-level-label">Stage {i + 1}</span>
              {level.map((task) => (
                <article key={task.id} className={"wf-task wf-task-" + task.state}>
                  <header><strong>{task.title}</strong><StatusBadge status={evidenceLabel(task)}/></header>
                  <p className="wf-role">{task.role} · {task.side_effect.replace("_", " ")} · attempt {task.attempt_count}/{task.max_attempts}</p>
                  {task.summary && <p>{task.summary}</p>}
                  {task.reason_code && task.state !== "completed" && <p className="wf-reason">{task.reason_code}</p>}
                  {(task.output?.evidence_refs?.length ?? 0) > 0 && <p className="wf-role">{task.output!.evidence_refs!.length} evidence reference(s){task.output_sha256 && <> · output {short(task.output_sha256)}</>}</p>}
                  {task.state === "blocked" && <div className="ws-button-row">
                    <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.overrideTask(task.id, "requeue"))}>Retry</button>
                    <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.overrideTask(task.id, "cancel"))}>Cancel task</button>
                    {task.reason_code === "uncertain_side_effect" && <>
                      <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.overrideTask(task.id, "side_effect_applied"))}>Confirm applied</button>
                      <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.overrideTask(task.id, "side_effect_not_applied"))}>Confirm not applied</button>
                    </>}
                  </div>}
                </article>
              ))}
            </div>
          ))}
        </div>
      </Panel>
      <div className="wf-grid">
        <Panel title="Live timeline" className="wf-col">
          <ol className="wf-timeline" aria-live="polite">
            {events.slice().reverse().map((e) => (
              <li key={e.seq}><small>#{e.seq} {new Date(e.created_ms).toLocaleTimeString()}</small> <strong>{e.kind.replaceAll("_", " ")}</strong> <span>{summarizeEvent(e, tasks)}</span></li>
            ))}
          </ol>
        </Panel>
        <Panel title="Tool invocations" className="wf-col">
          {tools.length === 0 ? <p className="ws-form-help">No tool calls yet.</p> : (
            <ul className="wf-tools">{tools.map((t) => (
              <li key={t.id}><StatusBadge status={t.status}/> <code>{t.tool_id}</code> <small>{t.capability} · {t.decision_reason} · args {short(t.args_sha256, 8)}{t.output_sha256 && <> · out {short(t.output_sha256, 8)}</>}</small></li>
            ))}</ul>
          )}
          {attempts.some((a) => a.error_category) && <>
            <h3 className="wf-subhead">Retries and errors</h3>
            <ul className="wf-tools">{attempts.filter((a) => a.error_category).map((a) => (
              <li key={a.task_id + a.attempt_no}><StatusBadge status={a.status}/> attempt {a.attempt_no} <small>{a.error_category}: {a.error_detail}</small></li>
            ))}</ul>
          </>}
        </Panel>
      </div>
      {graph && <Panel title={`Evidence graph (${graph.nodes.length} nodes${graph.truncated ? ", truncated" : ""})`}>
        <ul className="wf-tools">{graph.edges.map((e) => {
          const label = (id: string) => graph.nodes.find((n) => n.id === id);
          const from = label(e.from_node); const to = label(e.to_node);
          return <li key={e.id}><StatusBadge status={e.provenance}/> {from?.kind}:{from?.label} → <em>{e.relation}</em> → {to?.kind}:{to?.label} <small>confidence {e.confidence.toFixed(2)} · {e.source_ref}</small></li>;
        })}</ul>
      </Panel>}
      {report && <Panel title="Report (Markdown)" action={<button type="button" className="ws-button ws-button-secondary" onClick={() => void navigator.clipboard.writeText(report)}>Copy</button>}>
        <pre className="wf-report">{report}</pre>
      </Panel>}
    </div>
  );
}

function summarizeEvent(e: WorkflowEvent, tasks: RunDetail["tasks"]): string {
  const title = e.task_id ? tasks.find((t) => t.id === e.task_id)?.title ?? "" : "";
  const d = e.detail as Record<string, string | boolean | undefined>;
  if (e.kind === "task_state" || e.kind === "run_state") return `${title} ${d.from} → ${d.to}${d.reason ? ` (${d.reason})` : ""}`;
  if (e.kind.startsWith("tool_")) return `${title} ${d.tool ?? ""} ${d.reason ?? (d.ok === false ? "failed" : "")}`;
  return title;
}

function ApprovalList({ approvals, onDecided }: { approvals: ApprovalRequest[]; onDecided: () => void }) {
  const onError = useErrorToast();
  async function decide(a: ApprovalRequest, approve: boolean) {
    try { await workflowApi.decide(a.id, approve, a.scope_digest, null); onDecided(); } catch (error) { onError(error); }
  }
  return (
    <ul className="wf-approvals">
      {approvals.map((a) => (
        <li key={a.id}>
          <div>
            <strong>{a.kind === "plan" ? "Approve plan" : "Approve task capability"}</strong> <StatusBadge status={a.status}/>
            <p>{a.summary}</p>
            <small>Capabilities: {a.capabilities.join(", ") || "none"} · scope <code title={a.scope_digest}>{short(a.scope_digest, 16)}</code> · revision {a.plan_revision} · expires {time(a.expires_ms)}</small>
          </div>
          {a.status === "pending" && <div className="ws-button-row">
            <button type="button" className="ws-button ws-button-primary" onClick={() => void decide(a, true)}>Approve exact scope</button>
            <button type="button" className="ws-button ws-button-secondary" onClick={() => void decide(a, false)}>Reject</button>
          </div>}
        </li>
      ))}
    </ul>
  );
}

function ApprovalsTab() {
  const onError = useErrorToast();
  const [items, setItems] = useState<ApprovalRequest[] | null>(null);
  const load = useCallback(() => workflowApi.pendingApprovals().then(setItems).catch(onError), [onError]);
  useEffect(() => { void load(); }, [load]);
  if (!items) return <LoadingState/>;
  return items.length === 0
    ? <EmptyState icon="security" title="Nothing awaiting approval" description="Plan and capability approvals appear here with their exact scope and expiry."/>
    : <Panel title={`Pending approvals (${items.length})`}><ApprovalList approvals={items} onDecided={load}/></Panel>;
}

const LAYERS: MemoryLayer[] = ["episodic", "project_fact", "approved_knowledge", "working", "evidence_ref"];

function MemoryTab({ projectId }: { projectId: string }) {
  const onError = useErrorToast();
  const [layer, setLayer] = useState<MemoryLayer | "">("");
  const [items, setItems] = useState<MemoryItem[]>([]);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<RetrievalResult | null>(null);
  const load = useCallback(() => workflowApi.memoryList(projectId, layer || null).then(setItems).catch(onError), [projectId, layer, onError]);
  useEffect(() => { void load(); }, [load]);
  const act = async (fn: () => Promise<unknown>) => { try { await fn(); await load(); } catch (e) { onError(e); } };
  const shown = result ? result.items.map((r) => r.item) : items;
  return (
    <Panel title="Memory explorer">
      <div className="wf-toolbar">
        <label className="ws-field"><span>Search (hybrid keyword + local vectors)</span>
          <input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void workflowApi.memorySearch(projectId, query).then(setResult).catch(onError); }}/>
        </label>
        <label className="ws-field"><span>Layer</span>
          <select value={layer} onChange={(e) => { setResult(null); setLayer(e.target.value as MemoryLayer | ""); }}>
            <option value="">All</option>{LAYERS.map((l) => <option key={l} value={l}>{l.replace("_", " ")}</option>)}
          </select>
        </label>
        <button type="button" className="ws-button ws-button-secondary" onClick={() => void workflowApi.memorySearch(projectId, query).then(setResult).catch(onError)}>Search</button>
        {result && <button type="button" className="ws-button ws-button-secondary" onClick={() => setResult(null)}>Clear search</button>}
        <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.memoryClear(projectId, layer || null))}>Delete {layer || "all"} memory</button>
      </div>
      {result && <p className="ws-form-help">{result.candidates} candidate(s); {result.omitted} omitted by the retrieval budget. Vectors: {result.vector_model} (lexical, not neural).</p>}
      {shown.length === 0 ? <p className="ws-form-help">No memory items.</p> : (
        <ul className="wf-memory">{shown.map((m) => (
          <li key={m.id}>
            <header><strong>{m.title}</strong> <StatusBadge status={m.layer}/> {m.verified && <StatusBadge status="verified"/>}</header>
            <p>{m.body.slice(0, 400)}</p>
            <small>source {m.source_kind}:{m.source_ref} · confidence {m.confidence.toFixed(2)} · {time(m.updated_ms)}{m.approved_by && ` · approved by ${m.approved_by}`}</small>
            <div className="ws-button-row">
              {m.layer !== "approved_knowledge" && <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.memoryApprove(m.id))}>Promote to approved knowledge</button>}
              <button type="button" className="ws-button ws-button-secondary" onClick={() => void act(() => workflowApi.memoryDelete(projectId, m.id))}>Delete</button>
            </div>
          </li>
        ))}</ul>
      )}
    </Panel>
  );
}

function CloudTab({ projectId }: { projectId: string }) {
  const onError = useErrorToast();
  const { setToast } = useWorkspace();
  const [status, setStatus] = useState<CloudProviderStatus | null>(null);
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [token, setToken] = useState("");
  const [diag, setDiag] = useState<Diagnostics | null>(null);
  const [consent, setConsent] = useState<ConsentRecord | null>(null);
  const [draft, setDraft] = useState({ cloud: false, source: false, fallback: false, research: false, bytes: 24576 });
  const [log, setLog] = useState<ProviderRequestRecord[]>([]);
  const [prompt, setPrompt] = useState("");
  const [preview, setPreview] = useState<EgressPreview | null>(null);
  const [answer, setAnswer] = useState("");
  const [sending, setSending] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await workflowApi.cloudStatus();
      setStatus(s); setBaseUrl(s.settings.base_url); setEnabled(s.settings.enabled); setModel(s.settings.role_models.default_cloud ?? "");
      const c = await workflowApi.consent(projectId);
      setConsent(c);
      if (c) setDraft({ cloud: c.consent.allow_cloud, source: c.consent.allow_source_excerpts, fallback: c.consent.allow_local_fallback, research: c.allow_web_research, bytes: c.consent.max_payload_bytes });
      setLog(await workflowApi.requestLog(projectId));
    } catch (e) { onError(e); }
  }, [projectId, onError]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const off = listen<{ text: string }>("cloud://delta", (e) => setAnswer((a) => a + e.payload.text));
    return () => { void off.then((fn) => fn()); };
  }, []);

  const modelOptions = useMemo(() => diag?.models.map((m) => m.id) ?? [], [diag]);
  if (!status) return <LoadingState/>;
  return (
    <div className="wf-grid">
      <Panel title="OpenMindAI Cloud provider" className="wf-col">
        <div className="ws-form-stack">
          <label className="ws-field"><span>Base URL</span><input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)}/></label>
          <label className="ws-field"><span>Default model</span>
            <input list="wf-models" value={model} onChange={(e) => setModel(e.target.value)} placeholder="openmindai-lite"/>
            <datalist id="wf-models">{modelOptions.map((m) => <option key={m} value={m}/>)}</datalist>
          </label>
          <label className="ws-check-field"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)}/> Enable cloud provider</label>
          <div className="ws-button-row"><button type="button" className="ws-button ws-button-primary" onClick={() => void workflowApi.saveCloudSettings(baseUrl, enabled, model || null).then(load).catch(onError)}>Save settings</button></div>
          <label className="ws-field"><span>Developer key ({status.token_stored ? "stored" : "not stored"} · {status.credential_backend})</span>
            <input type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} placeholder="Stored only in the OS credential store"/>
          </label>
          <div className="ws-button-row">
            <button type="button" className="ws-button ws-button-secondary" disabled={!token} onClick={() => void workflowApi.setCloudToken(token).then(() => { setToken(""); setToast({ tone: "success", message: "Key stored in the OS credential store" }); return load(); }).catch(onError)}>Store key</button>
            <button type="button" className="ws-button ws-button-secondary" disabled={!status.token_stored} onClick={() => void workflowApi.clearCloudToken().then(load).catch(onError)}>Remove key</button>
            <button type="button" className="ws-button ws-button-secondary" disabled={!status.token_stored} onClick={() => void workflowApi.cloudDiagnostics().then(setDiag).catch(onError)}>Test connection</button>
          </div>
          {diag && <p className="ws-form-help" role="status">
            {diag.authenticated ? `Connected in ${diag.latency_ms} ms · ${diag.models.length} model(s): ${diag.models.map((m) => `${m.id}${m.available ? "" : " (unavailable)"}`).join(", ")}` : `Not connected: ${diag.error}`}
            {diag.credential_fingerprint && ` · key fingerprint ${diag.credential_fingerprint}`}
          </p>}
        </div>
      </Panel>
      <Panel title="Project data-disclosure consent" className="wf-col">
        <div className="ws-form-stack">
          <p className="ws-form-help">{consent?.revoked_ms ? `Revoked ${time(consent.revoked_ms)}.` : consent ? `Granted by ${consent.consent.granted_by} on ${time(consent.consent.granted_ms)}.` : "No consent recorded: this project is offline-only."}</p>
          <label className="ws-check-field"><input type="checkbox" checked={draft.cloud} onChange={(e) => setDraft({ ...draft, cloud: e.target.checked })}/> Allow redacted summaries to be sent to OpenMindAI Cloud</label>
          <label className="ws-check-field"><input type="checkbox" checked={draft.source} disabled={!draft.cloud} onChange={(e) => setDraft({ ...draft, source: e.target.checked })}/> Also allow redacted source excerpts</label>
          <label className="ws-check-field"><input type="checkbox" checked={draft.fallback} onChange={(e) => setDraft({ ...draft, fallback: e.target.checked })}/> Allow fallback to the local model if the cloud fails</label>
          <label className="ws-check-field"><input type="checkbox" checked={draft.research} onChange={(e) => setDraft({ ...draft, research: e.target.checked })}/> Allow bounded public web research</label>
          <label className="ws-field"><span>Max payload bytes</span><input type="number" min={1024} max={262144} value={draft.bytes} onChange={(e) => setDraft({ ...draft, bytes: Number(e.target.value) })}/></label>
          <div className="ws-button-row">
            <button type="button" className="ws-button ws-button-primary" onClick={() => void workflowApi.grantConsent(projectId, draft.cloud, draft.source, draft.fallback, draft.research, draft.bytes).then(load).catch(onError)}>Save consent</button>
            <button type="button" className="ws-button ws-button-secondary" disabled={!consent || !!consent.revoked_ms} onClick={() => void workflowApi.revokeConsent(projectId).then(load).catch(onError)}>Revoke now</button>
          </div>
        </div>
      </Panel>
      <Panel title="Ask OpenMindAI (preview before sending)" className="wf-col-wide">
        <div className="ws-form-stack">
          <textarea rows={3} value={prompt} maxLength={8000} onChange={(e) => { setPrompt(e.target.value); setPreview(null); }} aria-label="Question"/>
          <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" disabled={!prompt.trim()} onClick={() => void workflowApi.previewQuestion(projectId, prompt).then(setPreview).catch(onError)}>Preview data to be sent</button></div>
          {preview && <div className="ws-warning-box">
            <p><strong>{preview.bytes} bytes</strong> to {preview.provider} / {preview.model}; {preview.redactions} secret(s) redacted; digest <code>{short(preview.sha256, 16)}</code></p>
            <pre className="wf-report">{preview.request.messages.map((m) => `[${m.role}] ${m.content ?? ""}`).join("\n\n")}</pre>
            <div className="ws-button-row"><button type="button" className="ws-button ws-button-primary" disabled={sending} onClick={() => {
              setSending(true); setAnswer("");
              void workflowApi.sendQuestion(projectId, prompt, preview.sha256).then((final) => setAnswer(final)).catch(onError).finally(() => { setSending(false); void load(); });
            }}>{sending ? "Streaming…" : "Send exactly this"}</button></div>
          </div>}
          {answer && <><p className="ws-form-help">Model output is an unverified suggestion, not evidence.</p><pre className="wf-report" aria-live="polite">{answer}</pre></>}
        </div>
      </Panel>
      <Panel title="Cloud request audit (metadata only)" className="wf-col-wide">
        {log.length === 0 ? <p className="ws-form-help">No cloud requests for this project.</p> : (
          <ul className="wf-tools">{log.map((r) => (
            <li key={r.request_id}><StatusBadge status={r.outcome}/> <code>{r.model}</code> <small>{time(r.created_ms)} · HTTP {r.http_status ?? "—"} · {r.attempts} attempt(s) · {r.latency_ms} ms · {r.bytes_sent} B sent · {r.credits} credit(s){r.streamed ? " · streamed" : ""}</small></li>
          ))}</ul>
        )}
      </Panel>
    </div>
  );
}

function CapabilitiesTab({ projectId }: { projectId: string }) {
  const onError = useErrorToast();
  const [matrix, setMatrix] = useState<CapabilityStatus[] | null>(null);
  const [roles, setRoles] = useState<WorkerRole[]>([]);
  useEffect(() => {
    workflowApi.capabilities(projectId).then(setMatrix).catch(onError);
    workflowApi.roles().then(setRoles).catch(onError);
  }, [projectId, onError]);
  if (!matrix) return <LoadingState/>;
  return (
    <div className="wf-grid">
      <Panel title="Capability matrix (this platform)" className="wf-col">
        <table className="wf-table"><thead><tr><th>Capability</th><th>Effect</th><th>Status</th><th>Tools / reason</th></tr></thead>
          <tbody>{matrix.map((c) => (
            <tr key={c.capability}><td><code>{c.capability}</code></td><td>{c.side_effect.replace("_", " ")}</td><td><StatusBadge status={c.enabled ? "active" : "disabled"}/></td><td><small>{c.tools.join(", ") || "—"} · {c.reason}</small></td></tr>
          ))}</tbody>
        </table>
      </Panel>
      <Panel title="Specialist roster" className="wf-col">
        <ul className="wf-memory">{roles.map((r) => (
          <li key={r.role}><header><strong>{r.display_name}</strong> <StatusBadge status={r.output_class}/></header><p>{r.description}</p><small>{r.capabilities.join(", ")}</small></li>
        ))}</ul>
      </Panel>
    </div>
  );
}
