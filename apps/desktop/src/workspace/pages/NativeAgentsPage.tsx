import { useCallback, useEffect, useState } from "react";

import { workspaceApi } from "../api";
import { useWorkspace } from "../WorkspaceContext";
import { PageHeader, Panel, ProjectSelect, StatusBadge } from "../ui";

export type NativeAgentStep = {
  position: number;
  role: string;
  tool: string;
  status: string;
  result: string | null;
};
export type NativeAgentRun = {
  id: string;
  project_id: string;
  objective: string;
  status: string;
  message: string | null;
  max_files: number;
  budget_seconds: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  steps: NativeAgentStep[];
};

export function NativeAgentsPage() {
  const { projects, activeProjectId, setActiveProjectId } = useWorkspace();
  const [runs, setRuns] = useState<NativeAgentRun[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [objective, setObjective] = useState("Review the selected project's security, code quality and reliability. Report confirmed evidence and unresolved issues.");
  const [maxFiles, setMaxFiles] = useState(500);
  const [budget, setBudget] = useState(600);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [modelStatus, setModelStatus] = useState<{ configured: boolean; detail: string } | null>(null);
  const [insight, setInsight] = useState<{ content: string; created_at: string } | null>(null);
  const [modelConsent, setModelConsent] = useState(false);

  useEffect(() => {
    void workspaceApi.nativeModelReadiness().then(setModelStatus)
      .catch(reason => setError(String(reason)));
  }, []);

  const refresh = useCallback(async () => {
    if (!activeProjectId) {
      setRuns([]);
      return;
    }
    const next = await workspaceApi.listNativeAgentReviews(activeProjectId);
    setRuns(next);
  }, [activeProjectId]);

  useEffect(() => {
    void refresh().catch(reason => setError(String(reason)));
    const timer = window.setInterval(() => {
      void refresh().catch(reason => setError(String(reason)));
    }, 3500);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    const id = selectedId || runs[0]?.id;
    if (!id) { setInsight(null); return; }
    let active = true;
    void workspaceApi.nativeAgentInsight(id)
      .then(value => { if (active) setInsight(value); })
      .catch(reason => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [selectedId, runs]);

  async function interpret(id: string) {
    if (!modelConsent) return;
    setBusy("reason"); setError("");
    try {
      const value = await workspaceApi.interpretNativeAgentReview(id, true);
      setInsight(value);
      setModelConsent(false);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  async function createPlan() {
    if (!activeProjectId) return;
    setError(""); setBusy("plan");
    try {
      const run = await workspaceApi.createNativeAgentReview(activeProjectId, objective, maxFiles, budget);
      setSelectedId(run.id);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  async function approve(id: string) {
    if (!window.confirm("Approve the six listed passive analyzers for this indexed project? No external commands or active network probes will run.")) return;
    setBusy("approve"); setError("");
    try {
      await workspaceApi.approveNativeAgentReview(id);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  function execute(id: string) {
    setBusy("run"); setError("");
    void workspaceApi.runNativeAgentReview(id)
      .then(() => refresh())
      .catch(reason => setError(String(reason)))
      .finally(() => setBusy(""));
  }

  async function cancel(id: string) {
    setError("");
    try {
      await workspaceApi.cancelNativeAgentReview(id);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function copyReport(id: string) {
    try {
      const text = await workspaceApi.nativeAgentReport(id);
      await navigator.clipboard.writeText(text);
    } catch (reason) {
      setError("Could not copy report: " + String(reason));
    }
  }

  const selected = runs.find(run => run.id === selectedId) ?? runs[0];
  return <div>
    <PageHeader
      eyebrow="LOCAL SECURITY AUTOMATION"
      title="CodeTwin Agents"
      description="Rust-native supervised review of your indexed source, application security, QA evidence and runtime configuration. Runs are persisted locally."
      actions={<button className="ws-button ws-button-secondary" onClick={() => void refresh().catch(reason => setError(String(reason)))}>Refresh</button>}
    />
    <Panel title="Create a supervised review">
      <div className="ws-form-stack">
        <ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/>
        <label className="ws-field"><span>Review objective</span>
          <textarea value={objective} maxLength={2000} rows={3} onChange={event => setObjective(event.target.value)}/>
        </label>
        <label className="ws-field"><span>Maximum indexed files (1–2000)</span>
          <input type="number" min={1} max={2000} value={maxFiles} onChange={event => setMaxFiles(Number(event.target.value))}/>
        </label>
        <label className="ws-field"><span>Review time budget in seconds (1–3600)</span>
          <input type="number" min={1} max={3600} value={budget} onChange={event => setBudget(Number(event.target.value))}/>
        </label>
        <p className="ws-form-help">
          The planner uses the existing CodeTwin passive analyzers. It checks source hashes before the source-audit step, requires explicit approval and never runs generated shell commands or unapproved website attacks.
        </p>
        <button className="ws-button ws-button-primary" disabled={!activeProjectId || Boolean(busy) || !objective.trim()} onClick={() => void createPlan()}>
          {busy === "plan" ? "Preparing…" : "Prepare review"}
        </button>
        {error && <p className="ws-warning-box" role="alert">{error}</p>}
      </div>
    </Panel>

    <Panel title="Saved reviews">
      {!runs.length && <p className="ws-inline-empty">Choose an indexed project to create your first local review.</p>}
      <div className="ws-history-list">{runs.map(run =>
        <button className="ws-button ws-button-secondary" key={run.id} aria-pressed={selected?.id === run.id}
          onClick={() => setSelectedId(run.id)}>
          {run.objective.slice(0, 60)} · {run.status}
        </button>
      )}</div>
    </Panel>

    {selected && <Panel title="Review execution">
      <p><StatusBadge status={selected.status}/> <strong>{selected.objective}</strong></p>
      <p className="ws-form-help">Bounded to {selected.max_files} indexed files and {selected.budget_seconds} seconds at analyzer boundaries. Agents never bypass CodeTwin's existing security approval rules.</p>
      <div className="ws-history-list">
        {selected.steps.map(step => <details key={step.position}>
          <summary><strong>{step.role}</strong> · {step.status}</summary>
          <p className="ws-form-help">{step.tool}</p>
          <pre className="ws-diagnostics">{step.result ?? "No execution evidence yet"}</pre>
        </details>)}
      </div>
      {selected.message && <p className="ws-warning-box">{selected.message}</p>}
      <div className="ws-form-stack">
        <h3>Optional model interpretation</h3>
        <p className="ws-form-help">{modelStatus?.detail ?? "Checking model configuration…"}. This does not create validated findings or control tools.</p>
        {insight ? <div><p><strong>Unverified AI interpretation</strong> · {insight.created_at}</p><pre className="ws-diagnostics">{insight.content}</pre></div>
        : <>
          <label className="ws-field"><span><input type="checkbox" checked={modelConsent} onChange={event => setModelConsent(event.target.checked)}/>
          I approve sending up to 9,000 characters of this local review report to my configured model endpoint for interpretation.</span></label>
          <button className="ws-button ws-button-secondary" disabled={!modelStatus?.configured || !modelConsent || Boolean(busy) ||
            !["completed","failed","cancelled","interrupted"].includes(selected.status)}
            onClick={() => void interpret(selected.id)}>{busy === "reason" ? "Analyzing…" : "Generate AI interpretation"}</button>
        </>}
      </div>
      <div className="ws-top-actions">
        {selected.status === "planned" && <button className="ws-button ws-button-primary" disabled={Boolean(busy)} onClick={() => void approve(selected.id)}>Approve plan</button>}
        {selected.status === "approved" && <button className="ws-button ws-button-primary" disabled={Boolean(busy)} onClick={() => execute(selected.id)}>Run approved review</button>}
        {["planned", "approved", "running"].includes(selected.status) && <button className="ws-button ws-button-secondary" onClick={() => void cancel(selected.id)}>Cancel</button>}
        <button className="ws-button ws-button-secondary" onClick={() => void copyReport(selected.id)}>Copy evidence report</button>
      </div>
    </Panel>}
  </div>;
}
