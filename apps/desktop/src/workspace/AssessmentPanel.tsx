import { useEffect, useRef, useState } from "react";
import { workspaceApi } from "./api";
import type { AssessmentJob } from "./types";
import { Disclosure, Panel, StatusBadge, formatDate } from "./ui";

const names: Record<string, string> = { "code.sast": "Source security", "code.quality": "Code quality" };
export function AssessmentPanel({ projectId, projectName }: { projectId: string; projectName: string }) {
  const [jobs, setJobs] = useState<AssessmentJob[]>([]);
  const [tools, setTools] = useState(["code.sast", "code.quality"]);
  const [maxFiles, setMaxFiles] = useState(2000);
  const [seconds, setSeconds] = useState(120);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const records = await workspaceApi.assessmentJobs(projectId);
        if (cancelled) return;
        setJobs(records); setHistoryError(null);
      } catch (error) { if (!cancelled) setHistoryError(String(error)); }
      if (!cancelled) { setLoading(false); timer = setTimeout(() => { void load(); }, 2000); }
    }
    void load();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [projectId, refresh]);

  async function perform(action: () => Promise<unknown>, id: string) {
    setBusy(id); setActionError(null);
    try { await action(); }
    catch (error) { if (mounted.current) setActionError(String(error)); }
    finally { if (mounted.current) { setBusy(null); setRefresh(value => value + 1); } }
  }
  async function cancel(id: string) {
    setCancelling(id); setActionError(null);
    try { await workspaceApi.cancelAssessment(id); }
    catch (error) { if (mounted.current) setActionError(String(error)); }
    finally { if (mounted.current) { setCancelling(null); setRefresh(value => value + 1); } }
  }
  const running = jobs.some(job => job.status === "running");
  const latestRevision = Math.max(0, ...jobs.map(job => job.scope_revision));
  const valid = tools.length > 0 && Number.isInteger(maxFiles) && maxFiles >= 1 && maxFiles <= 2000 && Number.isInteger(seconds) && seconds >= 1 && seconds <= 3600;
  return <Panel title="Passive assessment" className="ws-tool-run-panel">
    <p className="ws-form-help">Selected project: <strong>{projectName}</strong></p>
    <p>Save a plan for this project’s indexed files, review its scope, then start it. Source security and code quality run locally without executing project code.</p>
    <p className="ws-form-help">Each new plan creates a scope revision and supersedes older unstarted plans. Changed source or indexing requires a fresh plan. Cancel and time limits are checked between analyzers; the current analyzer can finish first.</p>
    <fieldset disabled={Boolean(busy) || running} className="ws-assessment-options">
      <legend>Plan tools and limits</legend>
      {Object.entries(names).map(([id, name]) => <label key={id}><input type="checkbox" checked={tools.includes(id)} onChange={event => setTools(previous => event.target.checked ? [...previous, id] : previous.filter(value => value !== id))}/>{name}</label>)}
      <label className="ws-field"><span>Maximum indexed files</span><input aria-label="Maximum indexed files" type="number" min={1} max={2000} value={maxFiles} onChange={event => setMaxFiles(Number(event.target.value))}/></label>
      <label className="ws-field"><span>Time budget (seconds)</span><input aria-label="Time budget (seconds)" type="number" min={1} max={3600} value={seconds} onChange={event => setSeconds(Number(event.target.value))}/></label>
      <button className="ws-button" disabled={!valid || loading || Boolean(historyError)} onClick={() => { void perform(() => workspaceApi.createAssessmentPlan(projectId, tools, maxFiles, seconds), "plan"); }}>{busy === "plan" ? "Saving plan…" : "Save assessment plan"}</button>
    </fieldset>
    {actionError && <p role="alert" className="ws-warning-box">Assessment action failed: {actionError}</p>}
    {historyError && <p role="alert" className="ws-warning-box">Assessment history unavailable: {historyError}. Displayed records may be stale.</p>}
    <button className="ws-button ws-button-secondary" onClick={() => setRefresh(value => value + 1)}>Refresh assessments</button>
    {loading && <p role="status">Loading saved assessments…</p>}
    {!loading && !historyError && !jobs.length && <p className="ws-inline-empty">No saved assessments for this project.</p>}
    {jobs.map(job => <article className="ws-assessment-job" key={job.id} aria-label={`Assessment revision ${job.scope_revision}`}>
      <div className="ws-tool-title"><h3>Scope revision {job.scope_revision}</h3><StatusBadge status={job.status}/></div>
      <p>{job.file_count} indexed files · limit {job.max_files} · {job.budget_seconds}s at analyzer boundaries</p>
      <progress aria-label={`Assessment revision ${job.scope_revision} progress`} max={job.steps.length} value={job.steps.filter(step => step.status === "completed").length}/>
      <ol>{job.steps.map(step => <li key={step.position}>{names[step.tool_id] ?? step.tool_id}: {step.status}{step.coverage_complete === false ? " · Partial source coverage" : ""}</li>)}</ol>
      {job.message && <p className="ws-warning-box">{job.message}</p>}
      {job.cancel_requested && job.status === "running" && <p role="status">Cancellation requested. Waiting for the current analyzer to finish.</p>}
      <Disclosure title="Saved scope and evidence"><p className="ws-form-help">{job.root_path}</p><p className="ws-form-help">Input fingerprint: {job.input_hash}</p><p className="ws-form-help">Assessment definition {job.definition_version} · {formatDate(job.finished_at ?? job.started_at ?? job.created_at)}</p>{job.steps.map(step => <p className="ws-form-help" key={step.position}>{names[step.tool_id]} run: {step.run_id ?? "No persisted analyzer run"}</p>)}</Disclosure>
      {job.status === "planned" && <button className="ws-button" disabled={Boolean(busy) || running || Boolean(historyError) || job.scope_revision !== latestRevision} onClick={() => { void perform(() => workspaceApi.runAssessment(job.id), job.id); }}>Start assessment</button>}
      {(job.status === "planned" || job.status === "running") && <button className="ws-button ws-button-secondary" disabled={Boolean(cancelling) || job.cancel_requested || Boolean(historyError)} onClick={() => { void cancel(job.id); }}>{job.cancel_requested ? "Cancellation requested" : "Cancel assessment"}</button>}
    </article>)}
    <p className="ws-form-help">Completion describes execution, not a security pass. Scope covers indexed files only; active network scans and QA execution retain their separate authorization workflows. Interrupted jobs are never resumed automatically.</p>
  </Panel>;
}
