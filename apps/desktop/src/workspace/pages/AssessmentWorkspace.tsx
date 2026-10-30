import { listen } from "@tauri-apps/api/event";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { workspaceApi } from "../api";
import { Icon, type IconName } from "../Icon";
import { navigate } from "../routes";
import type { GuidedSecuritySessionRecord } from "../types";
import { useWorkspace } from "../WorkspaceContext";
import {
  assessmentApi, EMPTY_FILTER, formatClock, formatDuration, matches, maxSeq, mergeItems, SEVERITIES, toLogLine,
  VERIFICATION_LABEL, type AssessmentSummary, type FindingCard, type ReviewVerdict, type Severity, type StreamEvent,
  type StreamFilter, type StreamItem, type StreamPage, type Verification,
} from "../assessmentApi";
import { TERMINAL_RUN_STATES, workflowApi, type RunDetail, type WorkflowRun } from "../workflowApi";
import { WEB_ACTIVE_STATES, webSessionStream, webSessionSummary } from "../webStream";
import "../assessment.css";

/** Terminal header metadata shared by local workflow runs and web guided sessions. */
type StreamMeta = { id: string; state: string; goal: string; outcome: string | null; live: boolean };
const SOURCE_KEY = "codetwin.workspace.sourceWeb";
const EMPTY_WEB_FILTER = { severity: null, category: null, confidence: null, endpoint: null, status: null };

const RENDER_STEP = 600;
const PANEL_KEY = "codetwin.workspace.contextPanel";

function readPref(key: string, fallback: boolean): boolean {
  try {
    const v = window.localStorage.getItem(key);
    return v === null ? fallback : v === "1";
  } catch {
    return fallback;
  }
}

function writePref(key: string, value: boolean) {
  try { window.localStorage.setItem(key, value ? "1" : "0"); } catch { /* storage unavailable */ }
}

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const ACTIVE = new Set(["running", "validating", "queued", "awaiting_approval", "paused", "planned"]);

export function AssessmentWorkspace() {
  const { projects, activeProjectId, setActiveProjectId, setToast, scanNow } = useWorkspace();
  const projectId = activeProjectId ?? projects[0]?.id ?? null;
  const project = projects.find((p) => p.id === projectId) ?? null;
  const onError = useCallback((e: unknown) => setToast({ tone: "error", message: String(e) }), [setToast]);

  // Both targets — a local codebase (workflow runs) and a web target (guided
  // sessions) — render in this one terminal; `source` switches between them.
  const [source, setSource] = useState<"local" | "web">(() => (readPref(SOURCE_KEY, false) ? "web" : "local"));
  const setSourceMode = (next: "local" | "web") => { setSource(next); writePref(SOURCE_KEY, next === "web"); };

  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [webSessions, setWebSessions] = useState<GuidedSecuritySessionRecord[]>([]);
  const [webSessionId, setWebSessionId] = useState<string | null>(null);
  const [webSession, setWebSession] = useState<GuidedSecuritySessionRecord | null>(null);
  const [items, setItems] = useState<StreamItem[]>([]);
  const [summary, setSummary] = useState<AssessmentSummary | null>(null);
  const [filter, setFilter] = useState<StreamFilter>(EMPTY_FILTER);
  const [composing, setComposing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [model, setModel] = useState<string>("Local analyzers");
  const [panelOpen, setPanelOpen] = useState(() => readPref(PANEL_KEY, true));
  const [now, setNow] = useState(() => Date.now());
  const cursor = useRef(0);

  const loadRuns = useCallback(async () => {
    if (!projectId) return;
    try {
      const list = await workflowApi.listRuns(projectId);
      setRuns(list);
      setRunId((current) => (current && list.some((r) => r.id === current) ? current : list[0]?.id ?? null));
    } catch (e) { onError(e); }
  }, [projectId, onError]);

  const loadWebSessions = useCallback(async () => {
    try {
      const list = await workspaceApi.listGuidedSecuritySessions(null, 100);
      setWebSessions(list);
      setWebSessionId((current) => (current && list.some((s) => s.id === current) ? current : list[0]?.id ?? null));
    } catch (e) { onError(e); }
  }, [onError]);

  useEffect(() => { if (source === "local") void loadRuns(); else void loadWebSessions(); }, [source, loadRuns, loadWebSessions]);
  useEffect(() => {
    workflowApi.cloudStatus()
      .then((s) => setModel(s.settings.enabled && s.token_stored ? `OpenMindAI · ${s.settings.role_models.default_cloud ?? "openmindai-lite"}` : "Local analyzers · cloud off"))
      .catch(() => setModel("Local analyzers"));
  }, []);

  /** Replay from the durable cursor until caught up (initial load and reconnect). */
  const catchUp = useCallback(async (id: string, from: number) => {
    let next = from;
    for (let guard = 0; guard < 200; guard++) {
      const page: StreamPage = await assessmentApi.page(id, next, 250);
      setItems((cur) => mergeItems(cur, page.items));
      next = Math.max(next, page.next_cursor);
      if (!page.has_more) break;
    }
    cursor.current = Math.max(cursor.current, next);
  }, []);

  const refresh = useCallback(async (id: string) => {
    try {
      const [d, s] = await Promise.all([workflowApi.detail(id), assessmentApi.summary(id)]);
      setDetail(d);
      setSummary(s);
      await catchUp(id, cursor.current);
    } catch (e) { onError(e); }
  }, [catchUp, onError]);

  // Web session has no durable cursor stream; re-read the whole activity+findings
  // set each tick and adapt it into the shared terminal model.
  const refreshWeb = useCallback(async (id: string) => {
    try {
      const s = await workspaceApi.getGuidedSecuritySession(id);
      setWebSession(s);
      if (!s) { setItems([]); setSummary(null); return; }
      const activities = await workspaceApi.listGuidedSecurityActivity(id, 1000);
      const findings = s.scan_id ? await workspaceApi.listWebSecurityFindings(s.scan_id, EMPTY_WEB_FILTER, 500) : [];
      setItems(webSessionStream(s, activities, findings));
      setSummary(webSessionSummary(findings));
    } catch (e) { onError(e); }
  }, [onError]);

  useEffect(() => {
    if (source !== "local") return;
    cursor.current = 0;
    setItems([]);
    setDetail(null);
    setSummary(null);
    if (runId) void refresh(runId);
  }, [source, runId, refresh]);

  useEffect(() => {
    if (source !== "web") return;
    setItems([]);
    setWebSession(null);
    setSummary(null);
    if (webSessionId) void refreshWeb(webSessionId);
  }, [source, webSessionId, refreshWeb]);

  // Push channel from the backend watcher (local only); dedup handles replay overlap.
  useEffect(() => {
    if (source !== "local") return;
    const off = listen<{ run_id: string; page: StreamPage }>("assessment://items", (e) => {
      if (e.payload.run_id !== runId) return;
      setItems((cur) => mergeItems(cur, e.payload.page.items));
      cursor.current = Math.max(cursor.current, e.payload.page.next_cursor);
    });
    const settled = listen<{ run_id: string }>("workflow://settled", (e) => {
      if (e.payload.run_id === runId) { void refresh(e.payload.run_id); void loadRuns(); }
    });
    return () => { void off.then((f) => f()); void settled.then((f) => f()); };
  }, [source, runId, refresh, loadRuns]);

  const localLive = source === "local" && !!detail && ACTIVE.has(detail.run.state);
  const webLive = source === "web" && !!webSession && WEB_ACTIVE_STATES.includes(webSession.status);
  const live = localLive || webLive;
  // Fallback poll recovers anything missed (local push gaps, web with no push channel).
  useEffect(() => {
    if (source === "local") {
      if (!runId || !localLive) return;
      const t = window.setInterval(() => { void refresh(runId); }, 2000);
      return () => window.clearInterval(t);
    }
    if (!webSessionId || !webLive) return;
    const t = window.setInterval(() => { void refreshWeb(webSessionId); }, 2000);
    return () => window.clearInterval(t);
  }, [source, runId, webSessionId, localLive, webLive, refresh, refreshWeb]);
  useEffect(() => {
    if (!live) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [live]);

  async function control(fn: () => Promise<unknown>) {
    try { await fn(); if (runId) await refresh(runId); await loadRuns(); } catch (e) { onError(e); }
  }

  async function runScanNow() {
    if (!projectId) return;
    setScanning(true);
    try { const r = await scanNow(projectId); await loadRuns(); setRunId(r.id); setComposing(false); }
    catch { /* toast already shown */ } finally { setScanning(false); }
  }

  const run = detail?.run ?? null;
  const elapsed = run?.started_ms ? (run.finished_ms ?? now) - run.started_ms : null;
  const pendingApprovals = detail?.approvals.filter((a) => a.status === "pending") ?? [];

  const meta: StreamMeta | null = source === "local"
    ? (run ? { id: run.id, state: run.state, goal: run.goal, outcome: run.outcome, live: localLive } : null)
    : (webSession ? { id: webSession.id, state: webSession.status, goal: "Authorized web assessment · " + webSession.target_url, outcome: ["completed", "failed", "cancelled"].includes(webSession.status) ? webSession.status : null, live: webLive } : null);
  const target = source === "local" ? (project?.display_name ?? "project") : (webSession ? webSession.target_url.replace(/^https?:\/\//, "") : "web target");

  const sourceToggle = (
    <div className="aw-seg aw-source-seg" role="group" aria-label="Scan source">
      {(["local", "web"] as const).map((s) => (
        <button key={s} type="button" aria-pressed={source === s} className={source === s ? "active" : ""} onClick={() => setSourceMode(s)}>{s === "local" ? "Local" : "Web"}</button>
      ))}
    </div>
  );

  if (source === "local" && !projectId) {
    return (
      <div className="aw aw-empty">
        <h1>Workspace</h1>
        {sourceToggle}
        <p>Index a project first, or switch to <strong>Web</strong> to assess a URL. Assessments run against an authorized scope.</p>
        <button type="button" className="aw-btn aw-btn-primary" onClick={() => navigate("launch")}>Choose a target</button>
      </div>
    );
  }

  return (
    <div className={"aw" + (panelOpen ? " aw-with-panel" : "")}>
      <header className="aw-header">
        <div className="aw-heading">
          <div className="aw-selectors">
            {sourceToggle}
            {source === "local" ? <>
              <label className="aw-select-field"><span>Target</span>
                <select aria-label="Project" value={projectId ?? ""} onChange={(e) => setActiveProjectId(e.target.value)}>
                  {projects.map((p) => <option key={p.id} value={p.id}>{p.display_name}</option>)}
                </select>
              </label>
              <label className="aw-select-field aw-select-wide"><span>Assessment</span>
                <select aria-label="Assessment" value={runId ?? ""} onChange={(e) => { setRunId(e.target.value || null); setComposing(false); }}>
                  {!runs.length && <option value="">No assessments yet</option>}
                  {runs.map((r) => <option key={r.id} value={r.id}>{r.goal.slice(0, 80)}</option>)}
                </select>
              </label>
            </> : (
              <label className="aw-select-field aw-select-wide"><span>Web scan</span>
                <select aria-label="Web scan" value={webSessionId ?? ""} onChange={(e) => setWebSessionId(e.target.value || null)}>
                  {!webSessions.length && <option value="">No web scans yet</option>}
                  {webSessions.map((s) => <option key={s.id} value={s.id}>{s.target_url.replace(/^https?:\/\//, "")} · {s.status}</option>)}
                </select>
              </label>
            )}
          </div>
          <div className="aw-meta">
            {meta && <span className={"aw-state aw-state-" + meta.state} role="status"><i aria-hidden="true"/>{meta.state.replaceAll("_", " ")}</span>}
            {source === "local" && elapsed != null && <span className="aw-mono aw-timer" aria-label="Elapsed time">{formatDuration(elapsed)}</span>}
            {meta?.outcome && <span className={"aw-outcome aw-outcome-" + meta.outcome}>outcome: {meta.outcome}</span>}
            <span className="aw-model" title="Model / provider used by cloud-enabled tasks">{model}</span>
          </div>
        </div>
        <div className="aw-run-controls">
          {source === "local" && <>
            <button type="button" className="aw-btn aw-btn-primary" disabled={scanning || !projectId} onClick={() => void runScanNow()}>{scanning ? "Starting…" : "Scan now"}</button>
            {run?.state === "queued" && <button type="button" className="aw-btn" onClick={() => void control(() => workflowApi.start(run.id))}>Start</button>}
            {(run?.state === "running" || run?.state === "queued") && <button type="button" className="aw-btn" onClick={() => void control(() => workflowApi.pause(run.id))}>Pause</button>}
            {(run?.state === "paused" || run?.state === "blocked") && <button type="button" className="aw-btn" onClick={() => void control(() => workflowApi.resume(run.id))}>Resume</button>}
            {run && !TERMINAL_RUN_STATES.includes(run.state) && <button type="button" className="aw-btn aw-btn-danger" onClick={() => void control(() => workflowApi.cancel(run.id))}>Stop</button>}
            <button type="button" className={"aw-btn" + (composing ? "" : "")} onClick={() => setComposing((c) => !c)}>{composing ? "Cancel" : "+ New"}</button>
          </>}
          {source === "web" && <>
            <button type="button" className="aw-btn aw-btn-primary" onClick={() => navigate("launch")}>+ New web scan</button>
            <button type="button" className="aw-btn" disabled={!webSessionId} onClick={() => { if (webSessionId) void refreshWeb(webSessionId); }}>Refresh</button>
          </>}
          <button type="button" className="aw-btn aw-icon" aria-pressed={panelOpen} aria-label={panelOpen ? "Hide context panel" : "Show context panel"} title={panelOpen ? "Hide context panel" : "Show context panel"} onClick={() => { setPanelOpen(!panelOpen); writePref(PANEL_KEY, !panelOpen); }}>{panelOpen ? "⇥" : "⇤"}</button>
        </div>
      </header>

      {source === "local" && composing && <Composer projectId={projectId!} onCreated={(r) => { setComposing(false); void loadRuns().then(() => setRunId(r.id)); }} onError={onError}/>}

      {summary && <SummaryBar summary={summary} filter={filter} setFilter={setFilter}/>}

      <div className="aw-body">
        <section className="aw-stream-col" aria-label="Live execution stream">
          {meta ? (
            <LiveStream items={items} filter={filter} setFilter={setFilter} meta={meta} projectId={source === "local" ? (projectId ?? "") : (webSession?.project_id ?? "")} target={target}
              onChanged={() => { if (source === "local" && runId) { cursor.current = 0; void refresh(runId); } else if (webSessionId) void refreshWeb(webSessionId); }} onError={onError}/>
          ) : (
            <div className="aw-placeholder">{source === "local" ? <>No assessment selected. Press <strong>Scan now</strong> to start the full read-only scan.</> : <>No web scan selected. Press <strong>+ New web scan</strong> to start one.</>}</div>
          )}
        </section>
        {source === "local" && panelOpen && detail && (
          <ContextPanel detail={detail} summary={summary} items={items} target={project?.display_name ?? ""}
            approvals={pendingApprovals} onDecide={(id, digest, ok) => void control(() => workflowApi.decide(id, ok, digest, null))}
            onAgent={(agent) => setFilter({ ...filter, agent: filter.agent === agent ? null : agent })} activeAgent={filter.agent}/>
        )}
        {source === "web" && panelOpen && webSession && (
          <WebContextPanel session={webSession} summary={summary} items={items}
            elapsed={webSession.started_at ? (webSession.finished_at ? Date.parse(webSession.finished_at) : now) - Date.parse(webSession.started_at) : null}/>
        )}
      </div>
    </div>
  );
}

function Composer({ projectId, onCreated, onError }: { projectId: string; onCreated: (r: WorkflowRun) => void; onError: (e: unknown) => void }) {
  const [goal, setGoal] = useState("");
  const [cloud, setCloud] = useState(false);
  const [busy, setBusy] = useState(false);
  return (
    <form className="aw-composer" onSubmit={(e) => {
      e.preventDefault();
      setBusy(true);
      workflowApi.createInvestigation(projectId, goal, [], cloud, 3).then(({ run }) => onCreated(run)).catch(onError).finally(() => setBusy(false));
    }}>
      <label htmlFor="aw-goal">Assessment goal</label>
      <textarea id="aw-goal" rows={2} maxLength={4000} value={goal} onChange={(e) => setGoal(e.target.value)} placeholder="e.g. Review authentication and secret handling in the API layer"/>
      <div className="aw-composer-row">
        <label><input type="checkbox" checked={cloud} onChange={(e) => setCloud(e.target.checked)}/> Include OpenMindAI review of redacted summaries (requires project consent)</label>
        <button type="submit" className="aw-btn aw-btn-primary" disabled={busy || !goal.trim()}>{busy ? "Planning…" : "Create plan"}</button>
      </div>
      <p className="aw-hint">Creating a plan executes nothing. Scope approval appears in the context panel; passive analyzers only — no active scanning without the separate authorized web-security workflow.</p>
    </form>
  );
}

const STAT_CARDS: Array<{ key: keyof AssessmentSummary; label: string; tone: string; icon: IconName; severity?: Severity }> = [
  { key: "total", label: "All Findings", tone: "total", icon: "scan" },
  { key: "critical", label: "Critical", tone: "critical", icon: "security", severity: "critical" },
  { key: "high", label: "High", tone: "high", icon: "activity", severity: "high" },
  { key: "medium", label: "Medium", tone: "medium", icon: "activity", severity: "medium" },
  { key: "low", label: "Low", tone: "low", icon: "activity", severity: "low" },
  { key: "info", label: "Informational", tone: "info", icon: "folder", severity: "info" },
  { key: "passed", label: "Passed", tone: "passed", icon: "check" },
];

// One row of stat cards (All Findings / severity breakdown / Passed) shared by the
// local and web terminals; clicking a card filters the stream by that severity.
function SummaryBar({ summary, filter, setFilter }: { summary: AssessmentSummary; filter: StreamFilter; setFilter: (f: StreamFilter) => void }) {
  return (
    <div className="aw-stats" role="group" aria-label="Finding summary">
      {STAT_CARDS.map((c) => {
        const active = (c.severity && filter.severity === c.severity)
          || (c.key === "total" && filter.kinds === "findings" && !filter.severity && !filter.verification);
        return (
          <button key={c.key} type="button" aria-pressed={!!active} className={"aw-stat aw-stat-" + c.tone + (active ? " active" : "")}
            onClick={() => {
              if (c.key === "passed") return;
              if (active) return setFilter({ ...filter, severity: null, verification: null, kinds: "all" });
              if (c.severity) setFilter({ ...filter, severity: c.severity, verification: null, kinds: "all" });
              else setFilter({ ...filter, kinds: "findings", severity: null, verification: null });
            }}>
            <span className="aw-stat-ico" aria-hidden="true"><Icon name={c.icon} size={16}/></span>
            <span className="aw-stat-label">{c.label}</span>
            <strong className="aw-mono aw-stat-num">{summary[c.key]}</strong>
          </button>
        );
      })}
    </div>
  );
}

const REPLAY_SPEEDS = [0.5, 1, 2, 4, 8];
// Base per-line delay in ms; divided by the chosen speed. At 1x each line
// appears about every quarter second so it reads like live `ping` output.
const REPLAY_BASE_MS = 260;

function LiveStream({ items, filter, setFilter, meta, projectId, target, onChanged, onError }: {
  items: StreamItem[]; filter: StreamFilter; setFilter: (f: StreamFilter) => void; meta: StreamMeta | null;
  projectId: string; target: string; onChanged: () => void; onError: (e: unknown) => void;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  const [frozen, setFrozen] = useState<StreamItem[] | null>(null);
  const [limit, setLimit] = useState(RENDER_STEP);
  // Replay re-plays the real recorded items one by one; it never invents output.
  const [replay, setReplay] = useState<number | null>(null);
  const [speed, setSpeed] = useState(1);
  const live = meta?.live ?? false;
  useEffect(() => {
    if (replay === null || replay >= items.length) return;
    const t = window.setTimeout(() => setReplay((r) => (r === null ? r : r + 1)), Math.max(30, REPLAY_BASE_MS / speed));
    return () => window.clearTimeout(t);
  }, [replay, speed, items.length]);
  // Rows newer than what was on screen at load animate in like terminal output.
  const baseline = useRef<number | null>(null);
  useEffect(() => {
    if (baseline.current !== null || !items.length) return;
    const t = window.setTimeout(() => { baseline.current = maxSeq(items); }, 1200);
    return () => window.clearTimeout(t);
  }, [items]);
  const isFresh = (seq: number) => replay !== null || (baseline.current !== null && seq > baseline.current);
  const source = replay !== null ? items.slice(0, replay) : frozen ?? items;
  const filtered = useMemo(() => source.filter((i) => matches(i, filter)), [source, filter]);
  const shown = filtered.length > limit ? filtered.slice(filtered.length - limit) : filtered;
  const agents = useMemo(() => [...new Set(items.map((i) => i.agent).filter(Boolean) as string[])].sort(), [items]);
  const newSinceFreeze = frozen ? Math.max(0, maxSeq(items) - maxSeq(frozen)) : 0;
  const filtering = filter.query !== "" || filter.kinds !== "all" || !!filter.agent || !!filter.severity || !!filter.verification;

  const programmatic = useRef(false);
  useEffect(() => {
    const el = scroller.current;
    if (!el || !follow) return;
    // Lazily rendered rows can change scrollHeight after layout; pin twice.
    const pin = () => { programmatic.current = true; el.scrollTop = el.scrollHeight; };
    pin();
    const frame = requestAnimationFrame(() => { pin(); requestAnimationFrame(pin); });
    return () => cancelAnimationFrame(frame);
  }, [shown, follow]);

  return (
    <>
      <div className="aw-filters">
        <input
          className="aw-search"
          type="search"
          placeholder="Search events, agents, tools, findings, CWE, files…"
          aria-label="Search execution stream"
          value={filter.query}
          onChange={(e) => setFilter({ ...filter, query: e.target.value })}
        />
        <div className="aw-seg" role="group" aria-label="Event kinds">
          {(["all", "findings", "errors", "tools", "agents"] as const).map((k) => (
            <button key={k} type="button" aria-pressed={filter.kinds === k} className={filter.kinds === k ? "active" : ""} onClick={() => setFilter({ ...filter, kinds: k })}>{k}</button>
          ))}
        </div>
        <select className="aw-agent-select" aria-label="Filter by agent" value={filter.agent ?? ""} onChange={(e) => setFilter({ ...filter, agent: e.target.value || null })}>
          <option value="">All agents</option>
          {agents.map((a) => <option key={a} value={a}>{a.replaceAll("_", " ")}</option>)}
        </select>
        {filtering && <button type="button" className="aw-btn aw-btn-ghost" onClick={() => setFilter(EMPTY_FILTER)}>Clear</button>}
        <span className="aw-spacer"/>
        <button type="button" className="aw-btn aw-btn-ghost" aria-pressed={!!frozen} onClick={() => setFrozen(frozen ? null : items)}>
          {frozen ? `Resume view${newSinceFreeze ? ` (+${newSinceFreeze})` : ""}` : "Freeze view"}
        </button>
        <details className="aw-menu">
          <summary className="aw-btn aw-btn-ghost">Export</summary>
          <div className="aw-menu-list">
            <button type="button" onClick={() => void navigator.clipboard.writeText(filtered.map(toLogLine).join("\n"))}>Copy visible lines</button>
            <button type="button" onClick={() => download(`assessment-${meta?.id ?? "log"}.log`, source.map(toLogLine).join("\n"), "text/plain")}>Download .log</button>
            <button type="button" onClick={() => download(`assessment-${meta?.id ?? "log"}.json`, JSON.stringify(source, null, 2), "application/json")}>Download JSON</button>
          </div>
        </details>
      </div>
      <div className="aw-term">
      <div className="aw-term-bar">
        <span className="aw-dots" aria-hidden="true"><i/><i/><i/></span>
        <span className="aw-term-title">codetwin@{target}: ~/assessments/{meta?.id.slice(4, 12) ?? ""}</span>
        <span className="aw-spacer"/>
        {replay !== null
          ? <span className="aw-term-badge aw-term-replay">REPLAY {Math.min(replay, items.length)}/{items.length}</span>
          : live ? <span className="aw-term-badge aw-term-live"><i aria-hidden="true"/>LIVE</span>
          : <span className="aw-term-badge">{meta?.state === "awaiting_approval" ? "WAITING" : "DONE"}</span>}
        <span className="aw-term-count">{items.length} events</span>
        {replay === null ? (
          <button type="button" className="aw-term-btn" disabled={!items.length || live} title={live ? "Replay is available after the run settles" : "Replay the recorded events line by line"}
            onClick={() => { setFrozen(null); setFollow(true); setReplay(0); }}>Replay</button>
        ) : (
          <>
            <select className="aw-term-speed" aria-label="Replay speed" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              {REPLAY_SPEEDS.map((x) => <option key={x} value={x}>{x}x</option>)}
            </select>
            <button type="button" className="aw-term-btn" onClick={() => setReplay(null)}>Stop replay</button>
          </>
        )}
      </div>
      <div className="aw-stream" ref={scroller} role="log" aria-live="polite" aria-relevant="additions"
        onScroll={(e) => {
          if (programmatic.current) { programmatic.current = false; return; }
          const el = e.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
        }}>
        {filtered.length > shown.length && (
          <button type="button" className="aw-earlier" onClick={() => setLimit((l) => l + RENDER_STEP)}>Show {Math.min(RENDER_STEP, filtered.length - shown.length)} earlier of {filtered.length - shown.length} hidden</button>
        )}
        <div className="aw-prompt"><span className="aw-ps1">$</span> codetwin assess --target "{target}" --goal "{meta?.goal.slice(0, 120) ?? ""}"</div>
        {shown.length === 0 && <div className="aw-placeholder">{items.length ? "No events match the current filters." : "Waiting for events. Approve the plan and start the assessment."}</div>}
        {shown.map((item) => item.type === "event"
          ? <EventRow key={item.key} event={item} fresh={isFresh(item.seq)}/>
          : <FindingCardView key={item.key} card={item} projectId={projectId} onChanged={onChanged} onError={onError}/>)}
        {(live || (replay !== null && replay < items.length)) && (
          <div className="aw-cursor-line"><span className="aw-ps1">&gt;</span> {replay !== null ? "replaying recorded events" : "agents working"}<span className="aw-blink" aria-hidden="true">_</span></div>
        )}
        {!live && meta?.outcome && (replay === null || replay >= items.length) && (
          <div className="aw-exit">[process exited] state={meta.state} outcome={meta.outcome} events={items.length}</div>
        )}
      </div>
      </div>
      {!follow && <button type="button" className="aw-jump" onClick={() => setFollow(true)}>Jump to latest ↓</button>}
    </>
  );
}

const EventRow = memo(function EventRow({ event, fresh }: { event: StreamEvent; fresh: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={"aw-line aw-stage-" + event.stage.toLowerCase() + (fresh ? " aw-fresh" : "")}>
      <button type="button" className="aw-line-main" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="aw-line-meta">
          <span className="aw-ts">{formatClock(event.ts_ms)}</span>
          <span className="aw-tag">{event.stage}</span>
          {event.agent && <span className="aw-agent">{event.agent.replaceAll("_", " ")}</span>}
        </span>
        <span className="aw-msg">{event.message}</span>
        {event.duration_ms != null && <span className="aw-dur">{formatDuration(event.duration_ms)}</span>}
      </button>
      {open && (
        <dl className="aw-line-detail">
          <div><dt>seq</dt><dd>{event.seq}</dd></div>
          <div><dt>assessment</dt><dd>{event.run_id}</dd></div>
          {event.task_id && <div><dt>task</dt><dd>{event.task_id}</dd></div>}
          {event.tool && <div><dt>tool</dt><dd>{event.tool}</dd></div>}
          <div><dt>status</dt><dd>{event.status}</dd></div>
          {event.target && <div><dt>target</dt><dd>{event.target}</dd></div>}
          <div><dt>correlation</dt><dd>{event.correlation_id}</dd></div>
          {event.finding_ids.length > 0 && <div><dt>findings</dt><dd>{event.finding_ids.join(", ")}</dd></div>}
        </dl>
      )}
    </div>
  );
});

const FindingCardView = memo(function FindingCardView({ card, projectId, onChanged, onError }: {
  card: FindingCard; projectId: string; onChanged: () => void; onError: (e: unknown) => void;
}) {
  const [open, setOpen] = useState(card.severity === "critical");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  async function review(verdict: ReviewVerdict) {
    if (!note.trim()) return onError("Add a short review note explaining the evidence for this decision.");
    setBusy(true);
    try { await assessmentApi.review(card, verdict, note.trim(), projectId); setNote(""); onChanged(); } catch (e) { onError(e); } finally { setBusy(false); }
  }
  async function retest() {
    setBusy(true);
    try { await assessmentApi.retestAppSec(projectId); onChanged(); } catch (e) { onError(e); } finally { setBusy(false); }
  }
  const markdown = [
    `### ${card.title} (${card.finding_id})`, `Severity: ${card.severity} · Verification: ${VERIFICATION_LABEL[card.verification]}`,
    `Location: ${card.location ?? card.target}`, card.cwe ? `Weakness: ${card.cwe}` : "", "", card.description, "", `Impact: ${card.impact}`,
    "", "Remediation:", ...card.remediation.map((r) => `- ${r}`), "", "Limitations:", ...card.limitations.map((l) => `- ${l}`),
  ].join("\n");
  return (
    <article className={`aw-finding aw-sev-${card.severity}`} aria-label={`${card.severity} finding: ${card.title}`}>
      <button type="button" className="aw-finding-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="aw-ts">{formatClock(card.ts_ms)}</span>
        <span className={"aw-badge aw-badge-sev-" + card.severity}>{card.severity}</span>
        <span className={"aw-badge aw-badge-ver-" + card.verification}>{VERIFICATION_LABEL[card.verification]}</span>
        <strong className="aw-finding-title">{card.title}</strong>
        <span className="aw-loc aw-mono">{card.location ?? card.target}</span>
        <span className="aw-caret" aria-hidden="true">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="aw-finding-body">
          <dl className="aw-facts">
            <div><dt>Finding ID</dt><dd className="aw-mono">{card.finding_id}</dd></div>
            <div><dt>Source</dt><dd>{card.source} · {card.agent.replaceAll("_", " ")}</dd></div>
            <div><dt>Rule</dt><dd className="aw-mono">{card.rule_id}</dd></div>
            <div><dt>Target</dt><dd>{card.target}</dd></div>
            {card.cwe && <div><dt>CWE</dt><dd>{card.cwe}{card.owasp ? ` · ${card.owasp}` : ""}</dd></div>}
            {card.cve.length > 0 && <div><dt>CVE</dt><dd>{card.cve.join(", ")}</dd></div>}
            {card.cvss != null && <div><dt>CVSS</dt><dd>{card.cvss.toFixed(1)}</dd></div>}
            {card.confidence != null && <div><dt>Confidence</dt><dd>{Math.round(card.confidence * 100)}%</dd></div>}
            {card.first_seen && <div><dt>First detected</dt><dd>{card.first_seen}</dd></div>}
          </dl>
          {card.description && <section><h4>Description</h4><p>{card.description}</p></section>}
          <section><h4>Evidence</h4>
            {card.evidence.length ? <ul className="aw-evidence">{card.evidence.map((e, i) => <li key={i}><span className="aw-mono">{e.kind}{e.location ? ` · ${e.location}` : ""}</span><pre>{e.summary}</pre></li>)}</ul>
              : <p className="aw-hint">No stored evidence excerpt for this finding.</p>}
          </section>
          <section><h4>Impact</h4><p>{card.impact}</p></section>
          <section><h4>Remediation</h4><ol>{card.remediation.map((r, i) => <li key={i}>{r}</li>)}</ol><p className="aw-hint">Basis: {card.remediation_basis}</p></section>
          <section><h4>Verification limits</h4><ul>{card.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul></section>
          {card.review && <p className="aw-review">Last review: <strong>{card.review.verdict.replace("_", " ")}</strong> — {card.review.note} <span className="aw-hint">({card.review.created_at})</span></p>}
          <div className="aw-actions">
            {card.reviewable && <>
              <input aria-label="Review note" placeholder="Review note (required for a verdict)" value={note} onChange={(e) => setNote(e.target.value)} maxLength={1900}/>
              <button type="button" className="aw-btn" disabled={busy} onClick={() => void review("confirmed")}>Confirm (evidence reviewed)</button>
              <button type="button" className="aw-btn" disabled={busy} onClick={() => void review("needs_review")}>Needs validation</button>
              <button type="button" className="aw-btn" disabled={busy} onClick={() => void review("false_positive")}>False positive</button>
            </>}
            {card.reviewable && card.source === "appsec" && <button type="button" className="aw-btn" disabled={busy} onClick={() => void retest()}>Retest (re-run AppSec)</button>}
            <button type="button" className="aw-btn" onClick={() => navigate("security")}>Create fix task</button>
            <button type="button" className="aw-btn" onClick={() => void navigator.clipboard.writeText(markdown)}>Copy finding</button>
            <button type="button" className="aw-btn" onClick={() => download(`finding-${card.finding_id}.json`, JSON.stringify(card, null, 2), "application/json")}>Export evidence</button>
            <button type="button" className="aw-btn" disabled title="Risk acceptance is not supported by the local finding store yet">Accept risk</button>
            <button type="button" className="aw-btn" disabled title="Assignment requires multi-user collaboration, which is not implemented">Assign</button>
          </div>
        </div>
      )}
    </article>
  );
});

const WEB_STATUS_PCT: Record<string, number> = { preparing: 10, awaiting_approval: 25, approved: 40, running: 70, completed: 100, failed: 100, cancelled: 100 };
const WEB_PHASES = ["init", "preflight", "mapping", "testing", "reporting"];

// Right-hand context for a web session — the same panel the local run shows, filled
// from the guided session + its streamed activity (Target / Progress / Recent Findings).
function WebContextPanel({ session, summary, items, elapsed }: {
  session: GuidedSecuritySessionRecord; summary: AssessmentSummary | null; items: StreamItem[]; elapsed: number | null;
}) {
  const findings = items.filter((i): i is FindingCard => i.type === "finding");
  const recent = [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)).slice(0, 6);
  const seen = new Set(items.filter((i): i is StreamEvent => i.type === "event").map((e) => e.agent).filter(Boolean) as string[]);
  const pct = WEB_STATUS_PCT[session.status] ?? 0;
  const host = session.target_url.replace(/^https?:\/\//, "").replace(/\/$/, "");
  return (
    <aside className="aw-context" aria-label="Assessment context">
      <section>
        <h3>Target</h3>
        <dl className="aw-target">
          <div><dt>URL</dt><dd className="aw-mono">{session.target_url}</dd></div>
          <div><dt>Scope</dt><dd>{host}</dd></div>
          <div><dt>Type</dt><dd>Web Application</dd></div>
          <div><dt>Environment</dt><dd>{session.environment.replaceAll("_", " ")}</dd></div>
          {session.started_at && <div><dt>Start Time</dt><dd>{new Date(session.started_at).toLocaleString()}</dd></div>}
          {elapsed != null && <div><dt>Duration</dt><dd className="aw-mono">{formatDuration(elapsed)}</dd></div>}
          <div><dt>Status</dt><dd><span className={"aw-state aw-state-" + session.status}><i aria-hidden="true"/>{session.status.replaceAll("_", " ")}</span></dd></div>
        </dl>
      </section>
      <section>
        <h3>Assessment Progress</h3>
        <div className="aw-progress" role="progressbar" aria-label="Assessment progress" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: pct + "%" }}/></div>
        <p className="aw-hint">{pct}% · {session.mapping_requests} mapping request{session.mapping_requests === 1 ? "" : "s"}{summary ? ` · ${summary.total} finding${summary.total === 1 ? "" : "s"}` : ""}</p>
        <ul className="aw-phases">
          {WEB_PHASES.map((p) => (
            <li key={p} className={seen.has(p) ? "done" : ""}>
              <span className={"aw-dot aw-dot-" + (seen.has(p) ? "completed" : "pending")} aria-hidden="true"/>
              <span className="aw-phase-name">{p}</span>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3>Recent Findings</h3>
        {recent.length ? <ul className="aw-recent">{recent.map((f) => (
          <li key={f.key}><span className={"aw-badge aw-badge-sev-" + f.severity}>{f.severity}</span> <span>{f.title}</span></li>
        ))}</ul> : <p className="aw-hint">No findings in the loaded stream yet.</p>}
      </section>
    </aside>
  );
}

function ContextPanel({ detail, summary, items, target, approvals, onDecide, onAgent, activeAgent }: {
  detail: RunDetail; summary: AssessmentSummary | null; items: StreamItem[]; target: string;
  approvals: RunDetail["approvals"]; onDecide: (id: string, digest: string, approve: boolean) => void;
  onAgent: (agent: string) => void; activeAgent: string | null;
}) {
  const { run, tasks, tool_invocations: tools, attempts } = detail;
  const current = tasks.filter((t) => t.reason_code !== "superseded_by_replan");
  const done = current.filter((t) => ["completed", "failed", "cancelled", "blocked"].includes(t.state)).length;
  const pct = current.length ? Math.round((done / current.length) * 100) : 0;
  const runningTool = (taskId: string) => tools.filter((t) => t.task_id === taskId && t.status === "started").at(-1)?.tool_id;
  const findings = items.filter((i): i is FindingCard => i.type === "finding");
  const recent = [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)).slice(0, 5);
  const errors = attempts.filter((a) => a.error_category).length;
  return (
    <aside className="aw-context" aria-label="Assessment context">
      <section>
        <h3>Target</h3>
        <p><strong>{target}</strong></p>
        <p className="aw-hint">Approved capabilities: {run.approved_capabilities.length ? run.approved_capabilities.join(", ") : "none yet"}</p>
        <p className="aw-hint">{run.cloud_consented ? "Cloud disclosure consented (redacted summaries only)" : "Offline only"}</p>
      </section>
      {approvals.length > 0 && (
        <section className="aw-approvals">
          <h3>Waiting for approval</h3>
          {approvals.map((a) => (
            <div key={a.id} className="aw-approval">
              <p>{a.summary}</p>
              <p className="aw-hint aw-mono">scope {a.scope_digest.slice(0, 16)} · expires {new Date(a.expires_ms).toLocaleString()}</p>
              <div className="aw-actions">
                <button type="button" className="aw-btn aw-btn-primary" onClick={() => onDecide(a.id, a.scope_digest, true)}>Approve exact scope</button>
                <button type="button" className="aw-btn" onClick={() => onDecide(a.id, a.scope_digest, false)}>Reject</button>
              </div>
            </div>
          ))}
        </section>
      )}
      <section>
        <h3>Assessment Progress</h3>
        <div className="aw-progress" role="progressbar" aria-label="Tasks settled" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${pct}%` }}/></div>
        <p className="aw-hint">{done}/{current.length} tasks settled · run {run.state.replaceAll("_", " ")}{run.outcome ? ` · outcome ${run.outcome}` : ""}</p>
        {summary && <p className="aw-hint">{summary.passed} check(s) passed · {errors} attempt error(s) · {run.credits_used}/{run.budgets.max_credits} credits</p>}
      </section>
      <section>
        <h3>Active Agents</h3>
        <ul className="aw-agents">
          {current.map((t) => (
            <li key={t.id}>
              <button type="button" aria-pressed={activeAgent === t.role} className={activeAgent === t.role ? "active" : ""} onClick={() => onAgent(t.role)} title="Filter the stream to this agent">
                <span className={"aw-dot aw-dot-" + t.state}/>
                <span className="aw-agent-name">{t.role.replaceAll("_", " ")}</span>
                <span className="aw-hint">{t.state.replaceAll("_", " ")}{t.attempt_count > 1 ? ` · try ${t.attempt_count}` : ""}</span>
                {runningTool(t.id) && <span className="aw-mono aw-hint">⚙ {runningTool(t.id)}</span>}
                {t.started_ms && t.finished_ms && <span className="aw-mono aw-hint">{formatDuration(t.finished_ms - t.started_ms)}</span>}
              </button>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h3>Recent Findings</h3>
        {recent.length ? <ul className="aw-recent">{recent.map((f) => (
          <li key={f.key}><span className={"aw-badge aw-badge-sev-" + f.severity}>{f.severity}</span> <span>{f.title}</span></li>
        ))}</ul> : <p className="aw-hint">No findings in the loaded stream.</p>}
      </section>
      <section>
        <h3>Resources</h3>
        <p className="aw-hint">Parallel workers: {run.budgets.max_parallel} · runtime budget {Math.round(run.budgets.max_runtime_ms / 60000)} min. CPU/memory usage is not measured by the orchestrator.</p>
      </section>
    </aside>
  );
}
