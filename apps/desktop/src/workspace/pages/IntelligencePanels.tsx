import { useCallback, useEffect, useState } from "react";

import { LoadingState, Panel, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import { workflowApi, type WorkflowRun } from "../workflowApi";
import {
  DEFAULT_POLICY, describeCause, formatDelta, intelligenceApi, isLoopbackEndpoint, suppressionState, validateSuppression,
  type CorrelationReport, type FindingCluster, type KnowledgeConflict, type RunComparison, type SecurityPolicy,
  type StallReport, type Suppression, type SuppressionEvent, type SuppressionScope,
} from "../intelligenceApi";

const time = (ms: number | null | undefined) => (ms ? new Date(ms).toLocaleString() : "—");

function useNotify() {
  const { setToast } = useWorkspace();
  const onError = useCallback((error: unknown) => setToast({ tone: "error", message: String(error) }), [setToast]);
  const ok = useCallback((message: string) => setToast({ tone: "success", message }), [setToast]);
  return { onError, ok };
}

function ClusterRow({ cluster, onSuppress }: { cluster: FindingCluster; onSuppress: (fingerprint: string) => void }) {
  const [open, setOpen] = useState(false);
  const where = cluster.path ? `${cluster.path}${cluster.line ? `:${cluster.line}` : ""}` : "—";
  return (
    <>
      <tr>
        <th scope="row">
          <button type="button" className="ws-link-button" aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? "▾" : "▸"} <strong>{cluster.title}</strong>
          </button>
          <br/><small><code>{where}</code>{cluster.cwe && ` · ${cluster.cwe}`}</small>
        </th>
        <td><StatusBadge status={cluster.severity}/></td>
        <td>{cluster.risk_score.toFixed(2)}</td>
        <td>{(cluster.confidence * 100).toFixed(0)}%</td>
        <td>
          {cluster.analyzers.join(", ")}
          {cluster.corroborated && <> <StatusBadge status="corroborated"/></>}
          {cluster.confirmed && <> <StatusBadge status="confirmed"/></>}
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5}>
            <ul className="wf-memory">{cluster.members.map((m) => (
              <li key={m.id}>
                <header><strong>{m.title}</strong> <StatusBadge status={m.severity}/> <small>{m.analyzer}{m.rule && ` · ${m.rule}`}</small></header>
                <small>confidence {m.confidence.toFixed(2)} · lines {m.start_line ?? "?"}–{m.end_line ?? m.start_line ?? "?"}{m.review_verdict && ` · review: ${m.review_verdict}`} · <code>{m.fingerprint.slice(0, 16)}</code></small>
                <div className="ws-button-row">
                  <button type="button" className="ws-button ws-button-secondary" onClick={() => onSuppress(m.fingerprint)}>Suppress this finding…</button>
                </div>
              </li>
            ))}</ul>
          </td>
        </tr>
      )}
    </>
  );
}

export function SecurityIntelTab({ projectId }: { projectId: string }) {
  const { onError, ok } = useNotify();
  const [policy, setPolicy] = useState<SecurityPolicy>(DEFAULT_POLICY);
  const [report, setReport] = useState<CorrelationReport | null>(null);
  const [suppressions, setSuppressions] = useState<Suppression[]>([]);
  const [events, setEvents] = useState<SuppressionEvent[]>([]);
  const [form, setForm] = useState({ scope: "path" as SuppressionScope, matcher: "", reason: "", ttlDays: 30 });
  const [snapshot, setSnapshot] = useState<{ id: string; sha256: string; verified: boolean | null } | null>(null);
  const load = useCallback(() => {
    intelligenceApi.correlation(projectId, policy).then(setReport).catch(onError);
    intelligenceApi.suppressions(projectId).then((r) => { setSuppressions(r.suppressions); setEvents(r.events); }).catch(onError);
  }, [projectId, policy, onError]);
  useEffect(load, [load]);
  if (!report) return <LoadingState/>;
  const formError = validateSuppression(form);
  const submit = () => {
    if (formError) return onError(formError);
    intelligenceApi.suppress(projectId, form.scope, form.matcher, form.reason, form.ttlDays)
      .then(() => { ok("Suppression created and audited"); setForm({ ...form, matcher: "", reason: "" }); load(); })
      .catch(onError);
  };
  return (
    <div className="wf-run">
      <Panel title="Policy gate" action={<StatusBadge status={report.outcome.passed ? "passed" : "failed"}/>}>
        <p className="ws-form-help">
          {report.finding_count} open security finding(s) from all analyzers form {report.clusters.length} correlated cluster(s);
          {" "}{report.suppressed.length} hidden by suppressions or false-positive reviews. Findings themselves are never modified.
          {report.truncated && " Only the first 5,000 findings were evaluated."}
        </p>
        {report.outcome.violations.length > 0 && <ul>{report.outcome.violations.map((v) => <li key={v}>{v}</li>)}</ul>}
        <div className="wf-toolbar">
          <label className="ws-field"><span>Max critical</span>
            <input type="number" min={0} value={policy.max_critical} onChange={(e) => setPolicy({ ...policy, max_critical: Math.max(0, Number(e.target.value) || 0) })}/>
          </label>
          <label className="ws-field"><span>Max high (blank = no limit)</span>
            <input type="number" min={0} value={policy.max_high ?? ""} onChange={(e) => setPolicy({ ...policy, max_high: e.target.value === "" ? null : Math.max(0, Number(e.target.value) || 0) })}/>
          </label>
          <label className="ws-field"><span>Min confidence</span>
            <input type="number" min={0} max={1} step={0.05} value={policy.min_confidence} onChange={(e) => setPolicy({ ...policy, min_confidence: Math.min(1, Math.max(0, Number(e.target.value) || 0)) })}/>
          </label>
          <label className="ws-check-field"><input type="checkbox" checked={policy.fail_on_secrets} onChange={(e) => setPolicy({ ...policy, fail_on_secrets: e.target.checked })}/> Fail on secret exposure</label>
          <button type="button" className="ws-button ws-button-secondary" onClick={() => void intelligenceApi.snapshot(projectId, policy)
            .then((r) => { setSnapshot({ id: r.id, sha256: r.sha256, verified: null }); setReport(r.report); ok("Snapshot recorded"); })
            .catch(onError)}>Record hashed snapshot</button>
        </div>
        {snapshot && (
          <p className="ws-form-help">
            Snapshot <code>{snapshot.id}</code>, SHA-256 <code>{snapshot.sha256.slice(0, 16)}…</code>{" "}
            <button type="button" className="ws-button ws-button-secondary" onClick={() => void intelligenceApi.verifySnapshot(snapshot.id)
              .then((verified) => setSnapshot({ ...snapshot, verified })).catch(onError)}>Re-verify</button>
            {snapshot.verified === true && " Content matches its hash."}
            {snapshot.verified === false && " Content no longer matches its hash."}
            {" "}A content hash detects later edits; it is not a signature.
          </p>
        )}
      </Panel>
      <Panel title="Correlated findings (highest risk first)">
        {report.clusters.length === 0 ? <p className="ws-form-help">No open security findings. Run an analysis to populate this view.</p> : (
          <div className="wf-table-wrap"><table className="wf-table">
            <thead><tr><th scope="col">Finding</th><th scope="col">Severity</th><th scope="col">Risk</th><th scope="col">Confidence</th><th scope="col">Analyzers</th></tr></thead>
            <tbody>{report.clusters.map((c) => (
              <ClusterRow key={c.id} cluster={c} onSuppress={(fingerprint) => setForm({ ...form, scope: "fingerprint", matcher: fingerprint })}/>
            ))}</tbody>
          </table></div>
        )}
      </Panel>
      <Panel title="Suppressions">
        <p className="ws-form-help">Suppressions need approval authority, always expire, and every change is kept in an append-only audit trail. Automated agents cannot create them.</p>
        <div className="ws-form-stack">
          <div className="wf-toolbar">
            <label className="ws-field"><span>Scope</span>
              <select value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value as SuppressionScope })}>
                <option value="fingerprint">One finding (fingerprint)</option>
                <option value="rule">Analyzer rule</option>
                <option value="path">Path prefix</option>
              </select>
            </label>
            <label className="ws-field"><span>Matcher</span><input value={form.matcher} onChange={(e) => setForm({ ...form, matcher: e.target.value })}/></label>
            <label className="ws-field"><span>Expires in (days)</span>
              <input type="number" min={1} max={365} value={form.ttlDays} onChange={(e) => setForm({ ...form, ttlDays: Number(e.target.value) })}/>
            </label>
          </div>
          <label className="ws-field"><span>Reason (kept in the audit trail)</span>
            <textarea rows={2} value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })}/>
          </label>
          {formError && (form.matcher || form.reason) && <p className="ws-form-help" role="alert">{formError}</p>}
          <div className="ws-button-row"><button type="button" className="ws-button" disabled={formError !== null} onClick={submit}>Create suppression</button></div>
        </div>
        {suppressions.length > 0 && (
          <div className="wf-table-wrap"><table className="wf-table">
            <thead><tr><th scope="col">Matcher</th><th scope="col">State</th><th scope="col">Reason</th><th scope="col">Created</th><th scope="col">Actions</th></tr></thead>
            <tbody>{suppressions.map((s) => {
              const state = suppressionState(s);
              return (
                <tr key={s.id}>
                  <th scope="row"><small>{s.scope}</small><br/><code>{s.matcher}</code></th>
                  <td><StatusBadge status={state}/><br/><small>until {time(s.expires_ms)}</small></td>
                  <td>{s.reason}</td>
                  <td><small>{s.created_by} · {time(s.created_ms)}</small></td>
                  <td>{state === "active" && <button type="button" className="ws-button ws-button-secondary" onClick={() => void intelligenceApi.revokeSuppression(projectId, s.id).then(() => { ok("Suppression revoked"); load(); }).catch(onError)}>Revoke</button>}</td>
                </tr>
              );
            })}</tbody>
          </table></div>
        )}
        {report.suppressed.length > 0 && (
          <>
            <h3 className="wf-subhead">Hidden findings</h3>
            <ul>{report.suppressed.map((f) => <li key={f.finding_id}>{f.title} — <small>{describeCause(f.cause)}</small></li>)}</ul>
          </>
        )}
        {events.length > 0 && (
          <>
            <h3 className="wf-subhead">Audit trail</h3>
            <ul>{events.slice(0, 50).map((e, i) => <li key={`${e.suppression_id}-${e.action}-${i}`}><small>{time(e.created_ms)}</small> {e.actor} {e.action} <code>{e.suppression_id}</code></li>)}</ul>
          </>
        )}
      </Panel>
    </div>
  );
}

export function KnowledgeTab({ projectId }: { projectId: string }) {
  const { onError, ok } = useNotify();
  const [openOnly, setOpenOnly] = useState(true);
  const [conflicts, setConflicts] = useState<KnowledgeConflict[] | null>(null);
  const [embed, setEmbed] = useState({ endpoint: "http://127.0.0.1:11434/v1/embeddings", model: "nomic-embed-text" });
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { intelligenceApi.conflicts(projectId, openOnly).then(setConflicts).catch(onError); }, [projectId, openOnly, onError]);
  useEffect(load, [load]);
  if (!conflicts) return <LoadingState/>;
  const resolve = (id: string, accept: boolean) => void intelligenceApi.resolveConflict(projectId, id, accept)
    .then(() => { ok(accept ? "Change accepted and applied" : "Change rejected"); load(); }).catch(onError);
  const endpointOk = isLoopbackEndpoint(embed.endpoint) && embed.model.trim() !== "";
  return (
    <div className="wf-run">
      <Panel title="Knowledge conflicts" action={<label className="ws-check-field"><input type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)}/> Open only</label>}>
        <p className="ws-form-help">An unverified observation is never allowed to overwrite verified memory or replace a verified fact. It waits here for a person to accept or reject it. Accepted changes keep the previous version in history.</p>
        {conflicts.length === 0 ? <p className="ws-form-help">No {openOnly ? "open " : ""}conflicts.</p> : (
          <ul className="wf-memory">{conflicts.map((c) => (
            <li key={c.id}>
              <header><strong>{c.reason}</strong> <StatusBadge status={c.resolution ?? "open"}/> <small>{c.kind} · {time(c.created_ms)}</small></header>
              <small>Existing: <code>{c.existing_ref}</code></small>
              <pre className="wf-pre">{JSON.stringify(c.proposed, null, 2).slice(0, 1200)}</pre>
              {c.resolution ? <small>{c.resolution} by {c.resolved_by} · {time(c.resolved_ms)}</small> : (
                <div className="ws-button-row">
                  <button type="button" className="ws-button" onClick={() => resolve(c.id, true)}>Accept change</button>
                  <button type="button" className="ws-button ws-button-secondary" onClick={() => resolve(c.id, false)}>Reject</button>
                </div>
              )}
            </li>
          ))}</ul>
        )}
      </Panel>
      <Panel title="Neural embeddings (local model)">
        <p className="ws-form-help">
          Embed project memory with an OpenAI-compatible embedding model running on this machine (for example Ollama or a llama.cpp server).
          Nothing leaves the computer. Searches report which vector model ranked the results; without this step they use lexical hashed vectors.
        </p>
        <div className="wf-toolbar">
          <label className="ws-field"><span>Endpoint (loopback, ends in /embeddings)</span><input value={embed.endpoint} onChange={(e) => setEmbed({ ...embed, endpoint: e.target.value })}/></label>
          <label className="ws-field"><span>Model</span><input value={embed.model} onChange={(e) => setEmbed({ ...embed, model: e.target.value })}/></label>
          <button type="button" className="ws-button" disabled={!endpointOk || busy} onClick={() => {
            setBusy(true);
            intelligenceApi.embedMemory(projectId, embed.endpoint, embed.model)
              .then((r) => ok(`Embedded ${r.embedded} item(s) with ${r.model}`))
              .catch(onError)
              .finally(() => setBusy(false));
          }}>{busy ? "Embedding…" : "Embed memory"}</button>
        </div>
        {!isLoopbackEndpoint(embed.endpoint) && <p className="ws-form-help" role="alert">Only 127.0.0.1, ::1 or localhost endpoints ending in /embeddings are accepted here.</p>}
      </Panel>
    </div>
  );
}

export function RunAnalysisTab({ projectId }: { projectId: string }) {
  const { onError } = useNotify();
  const [runs, setRuns] = useState<WorkflowRun[] | null>(null);
  const [pair, setPair] = useState({ left: "", right: "" });
  const [comparison, setComparison] = useState<RunComparison | null>(null);
  const [stall, setStall] = useState<{ runId: string; report: StallReport | null } | null>(null);
  useEffect(() => { workflowApi.listRuns(projectId).then(setRuns).catch(onError); }, [projectId, onError]);
  if (!runs) return <LoadingState/>;
  const label = (r: WorkflowRun) => `${r.goal.slice(0, 60)} · ${r.state} · ${new Date(r.created_ms).toLocaleString()}`;
  const runPicker = (side: "left" | "right") => (
    <label className="ws-field"><span>{side === "left" ? "Baseline run" : "Compared run"}</span>
      <select value={pair[side]} onChange={(e) => setPair({ ...pair, [side]: e.target.value })}>
        <option value="">Choose a run…</option>
        {runs.map((r) => <option key={r.id} value={r.id}>{label(r)}</option>)}
      </select>
    </label>
  );
  return (
    <div className="wf-run">
      <Panel title="Compare runs">
        <p className="ws-form-help">Tasks are matched by their plan key. Output changes are detected by content hash, so a changed result is visible even when its state is the same.</p>
        <div className="wf-toolbar">
          {runPicker("left")}
          {runPicker("right")}
          <button type="button" className="ws-button" disabled={!pair.left || !pair.right || pair.left === pair.right}
            onClick={() => void intelligenceApi.compareRuns(pair.left, pair.right).then(setComparison).catch(onError)}>Compare</button>
        </div>
        {comparison && (
          <>
            <p className="ws-form-help">
              Outcome {comparison.left_outcome ?? "—"} → {comparison.right_outcome ?? "—"} · duration {formatDelta(comparison.duration_delta_ms)} ·
              {" "}credits {comparison.credits_delta >= 0 ? "+" : ""}{comparison.credits_delta} · {comparison.unchanged} unchanged task(s)
              {!comparison.same_goal && " · the goals differ, so differences may be expected"}
            </p>
            {comparison.changed.length > 0 && (
              <div className="wf-table-wrap"><table className="wf-table">
                <thead><tr><th scope="col">Task</th><th scope="col">State</th><th scope="col">Output</th><th scope="col">Attempts</th><th scope="col">Duration</th></tr></thead>
                <tbody>{comparison.changed.map((d) => (
                  <tr key={d.key}>
                    <th scope="row">{d.key}<br/><small>{d.role}</small></th>
                    <td>{d.left_state ?? "—"} → {d.right_state ?? "—"}</td>
                    <td>{d.output_changed ? "changed" : "same"}</td>
                    <td>{d.left_attempts} → {d.right_attempts}</td>
                    <td>{formatDelta(d.duration_delta_ms)}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
            {(comparison.only_left.length > 0 || comparison.only_right.length > 0) && (
              <p className="ws-form-help">Only in baseline: {comparison.only_left.join(", ") || "none"} · Only in compared run: {comparison.only_right.join(", ") || "none"}</p>
            )}
          </>
        )}
      </Panel>
      <Panel title="Stall diagnosis">
        <p className="ws-form-help">Finds runs that are not finished and not waiting for a person, but can never progress because the tasks they need failed, were cancelled or are blocked.</p>
        <ul className="wf-memory">{runs.filter((r) => !["completed", "failed", "cancelled"].includes(r.state)).map((r) => (
          <li key={r.id}>
            <header><strong>{r.goal.slice(0, 80)}</strong> <StatusBadge status={r.state}/></header>
            <div className="ws-button-row">
              <button type="button" className="ws-button ws-button-secondary" onClick={() => void intelligenceApi.diagnoseStall(r.id).then((report) => setStall({ runId: r.id, report })).catch(onError)}>Diagnose</button>
            </div>
            {stall?.runId === r.id && (stall.report
              ? <p role="alert">Stalled: {stall.report.stuck.join(", ")} wait on {stall.report.root_causes.join(", ")}. Retry or override the root task, or cancel the run.</p>
              : <p className="ws-form-help">Not stalled: the run can still progress or is waiting for a person.</p>)}
          </li>
        ))}</ul>
      </Panel>
    </div>
  );
}
