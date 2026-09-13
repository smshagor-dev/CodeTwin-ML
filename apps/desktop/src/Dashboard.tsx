import { useMemo, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";

export type DashboardDestination = "engineering" | "security" | "database" | "runtime" | "qa" | "ml" | "repair" | "repair-apply";
type Status = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type Profile = Record<"languages" | "frameworks" | "package_managers" | "build_systems" | "test_frameworks" | "databases" | "ci_providers" | "project_kinds", string[]>;
type IndexSummary = { project_id: string; status: Status; duration_ms: number; delta: { files_scanned: number; parse_errors: number } };
type Graph = { node_count: number; edge_count: number };
type Finding = { id: string; severity: string; title: string; last_seen: string };
type QaFramework = { framework: string; artifacts: number; test_files: number; config_files: number };
type QaArtifact = { id: string };
type Run = { id?: string; status: Status; started_at: string | null; duration_ms: number | null };
type EvidenceKey = "twin" | "quality" | "security" | "database" | "runtime" | "qa" | "history";
type Data = { profile: Profile; graph: Graph; quality: Finding[]; security: Finding[]; database: Finding[]; runtime: Finding[]; qa: QaArtifact[]; qaFrameworks: QaFramework[]; history: Run[]; unavailable: EvidenceKey[] };

type Props = { onNavigate: (destination: DashboardDestination) => void };
const emptyProfile: Profile = { languages: [], frameworks: [], package_managers: [], build_systems: [], test_frameworks: [], databases: [], ci_providers: [], project_kinds: [] };
const severityRanks: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const sevRank = (v: string) => severityRanks[v.toLowerCase()] ?? 0;
const sevCount = (rows: Finding[], v: string) => rows.filter((row) => row.severity.toLowerCase() === v).length;
const projectName = (path: string) => path.trim().replace(/[\\/]+$/, "").split(/[\\/]/).filter(Boolean).at(-1) ?? "Local project";
const fmtTime = (value: string | null) => value ? new Date(value).toLocaleString() : "time unavailable";

function Card({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return <section className="ct-card"><div className="ct-card-head"><h2>{title}</h2>{action}</div>{children}</section>;
}

function Metric({ icon, title, value, note, tone, onClick }: { icon: string; title: string; value: number | string; note: string; tone: string; onClick: () => void }) {
  return <button className="ct-metric" data-tone={tone} onClick={onClick} type="button"><span className="ct-metric-icon">{icon}</span><span><small>{title}</small><strong>{value}</strong><em>{note}</em></span><b>›</b></button>;
}

export function Dashboard({ onNavigate }: Props) {
  const [path, setPath] = useState("");
  const [summary, setSummary] = useState<IndexSummary | null>(null);
  const [data, setData] = useState<Data | null>(null);
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function refresh(projectId: string, profile: Profile = data?.profile ?? emptyProfile) {
    const keys: EvidenceKey[] = ["twin", "quality", "security", "database", "runtime", "qa", "qa", "history"];
    const results = await Promise.allSettled([
      invoke<Graph>("get_graph_summary", { projectId }),
      invoke<Finding[]>("list_quality_findings", { projectId, status: "open", limit: 500 }),
      invoke<Finding[]>("list_security_findings", { projectId, status: "open", limit: 500 }),
      invoke<Finding[]>("list_database_findings", { projectId, status: "open", limit: 500 }),
      invoke<Finding[]>("list_runtime_findings", { projectId, status: "open", limit: 500 }),
      invoke<QaArtifact[]>("list_qa_artifacts", { projectId, activeOnly: true, framework: null, limit: 500 }),
      invoke<QaFramework[]>("list_qa_frameworks", { projectId }),
      invoke<Run[]>("index_history", { projectId, limit: 6 }),
    ]);
    const unavailable = [...new Set(results.flatMap((result, index) => result.status === "rejected" ? [keys[index]] : []))];
    const take = <T,>(index: number, fallback: T): T => results[index].status === "fulfilled" ? results[index].value as T : fallback;
    setData({
      profile,
      graph: take<Graph>(0, { node_count: 0, edge_count: 0 }),
      quality: take<Finding[]>(1, []),
      security: take<Finding[]>(2, []),
      database: take<Finding[]>(3, []),
      runtime: take<Finding[]>(4, []),
      qa: take<QaArtifact[]>(5, []),
      qaFrameworks: take<QaFramework[]>(6, []),
      history: take<Run[]>(7, []),
      unavailable,
    });
    if (unavailable.length) setError(`Evidence unavailable: ${unavailable.join(", ")}. These areas are not being reported as zero.`);
  }

  async function openProject() {
    if (!path.trim()) return;
    setBusy(true); setError(null);
    try {
      const profile = await invoke<Profile>("discover_project", { path: path.trim() });
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setSummary(index);
      await refresh(index.project_id, profile);
    } catch (value) { setError(String(value)); }
    finally { setBusy(false); }
  }

  async function runDeterministicAnalysis() {
    if (!summary) return;
    setRunning(true); setError(null);
    const projectId = summary.project_id;
    const results = await Promise.allSettled([
      invoke("run_code_quality", { projectId }), invoke("run_security_analysis", { projectId }),
      invoke("run_database_analysis", { projectId }), invoke("run_runtime_analysis", { projectId }),
      invoke("run_qa_discovery", { projectId }),
    ]);
    await refresh(projectId);
    const failed = results.filter((item) => item.status === "rejected").length;
    if (failed) setError(`${failed} deterministic analysis task${failed === 1 ? "" : "s"} failed. Failed analyzers remain explicitly unavailable/incomplete.`);
    setRunning(false);
  }

  const unavailable = (key: EvidenceKey) => data?.unavailable.includes(key) ?? false;
  const findings = useMemo(() => data ? [
    ...data.security.map((x) => ({ ...x, area: "Security" as const, target: "security" as const })),
    ...data.quality.map((x) => ({ ...x, area: "Quality" as const, target: "engineering" as const })),
    ...data.database.map((x) => ({ ...x, area: "Database" as const, target: "database" as const })),
    ...data.runtime.map((x) => ({ ...x, area: "Runtime" as const, target: "runtime" as const })),
  ].sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.last_seen.localeCompare(a.last_seen)) : [], [data]);
  const severity = useMemo(() => ({ critical: sevCount(findings, "critical"), high: sevCount(findings, "high"), medium: sevCount(findings, "medium"), low: sevCount(findings, "low") }), [findings]);
  const stack = data ? [...data.profile.languages, ...data.profile.frameworks, ...data.profile.databases].filter((v, i, a) => a.indexOf(v) === i).slice(0, 7) : [];
  const maxFindings = data ? Math.max(1, data.quality.length, data.security.length, data.database.length, data.runtime.length) : 1;
  const total = severity.critical + severity.high + severity.medium + severity.low;
  const c1 = total ? severity.critical / total * 360 : 0;
  const c2 = total ? c1 + severity.high / total * 360 : 0;
  const c3 = total ? c2 + severity.medium / total * 360 : 0;
  const donut = { background: total ? `conic-gradient(#ef4444 0 ${c1}deg,#f97316 ${c1}deg ${c2}deg,#f4b63e ${c2}deg ${c3}deg,#4f8cff ${c3}deg 360deg)` : "#e6edf6" };

  return <main className="ct-dashboard">
    <aside className="ct-side">
      <div className="ct-brand"><img src="/app-icon.png" alt=""/><div><strong>CodeTwin-ML</strong><span>Your Code. Its Digital Twin.</span></div></div>
      <nav>
        <button className="active">⌂ <span>Dashboard</span></button>
        <button onClick={() => onNavigate("engineering")}>◇ <span>Engineering</span></button>
        <button onClick={() => onNavigate("security")}>⬡ <span>Security</span></button>
        <button onClick={() => onNavigate("database")}>▣ <span>Database</span></button>
        <button onClick={() => onNavigate("runtime")}>⬢ <span>Runtime</span></button>
        <button onClick={() => onNavigate("qa")}>△ <span>QA & Testing</span></button>
        <button onClick={() => onNavigate("ml")}>AI <span>ML</span></button>
        <button onClick={() => onNavigate("repair")}>⌁ <span>Repair Lab</span></button>
        <button onClick={() => onNavigate("repair-apply")}>↺ <span>Apply & Rollback</span></button>
      </nav>
      <div className="ct-side-note"><b>AI</b><strong>Local-first engineering intelligence</strong><p>Evidence-backed analysis from the persisted Software Digital Twin.</p></div>
      <footer><i/> Analysis workstation ready</footer>
    </aside>

    <section className="ct-page">
      <div className="ct-top">
        <div className="ct-path"><span>⌕</span><input value={path} onChange={(e) => setPath(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void openProject()} placeholder="Enter a local repository path…"/></div>
        <button className="ct-project" onClick={() => void openProject()} disabled={busy || !path.trim()}>▰ {busy ? "Opening…" : summary ? projectName(path) : "Open project"}</button>
        <button className="ct-run" onClick={() => void runDeterministicAnalysis()} disabled={!summary || running}>▷ {running ? "Analyzing…" : "Run deterministic analysis"}</button>
      </div>

      <div className="ct-content">
        <header className="ct-heading"><div><p>LOCAL SOFTWARE DIGITAL TWIN</p><h1>Dashboard</h1><span>{summary ? `Current project: ${projectName(path)}` : "Open a repository to build and inspect its persisted engineering evidence."}</span></div>{summary && <div className="ct-status"><b>{summary.status}</b><small>{summary.delta.files_scanned} files indexed · {summary.duration_ms} ms</small></div>}</header>
        {error && <div className="ct-alert">{error}</div>}

        {!summary || !data ? <section className="ct-empty"><div>◇</div><h2>Build the project Digital Twin</h2><p>Enter a local repository path. CodeTwin discovers the stack, updates the persistent Tree-sitter index, and loads existing deterministic evidence without executing repository commands.</p><div><input value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\\work\\project or /home/user/project"/><button onClick={() => void openProject()} disabled={busy || !path.trim()}>{busy ? "Indexing…" : "Open & index project"}</button></div></section> : <>
          <section className="ct-metrics">
            <Metric icon="◇" title="Digital Twin" value={unavailable("twin") ? "—" : data.graph.node_count.toLocaleString()} note={unavailable("twin") ? "Evidence unavailable" : `${data.graph.edge_count.toLocaleString()} relationships`} tone="twin" onClick={() => onNavigate("engineering")}/>
            <Metric icon="</>" title="Code Quality" value={unavailable("quality") ? "—" : data.quality.length} note={unavailable("quality") ? "Evidence unavailable" : `${sevCount(data.quality,"critical") + sevCount(data.quality,"high")} high / critical`} tone="quality" onClick={() => onNavigate("engineering")}/>
            <Metric icon="⬡" title="Security" value={unavailable("security") ? "—" : data.security.length} note={unavailable("security") ? "Evidence unavailable" : `${sevCount(data.security,"critical")} critical · ${sevCount(data.security,"high")} high`} tone="security" onClick={() => onNavigate("security")}/>
            <Metric icon="▣" title="Database" value={unavailable("database") ? "—" : data.database.length} note={unavailable("database") ? "Evidence unavailable" : `${sevCount(data.database,"critical") + sevCount(data.database,"high")} high-risk`} tone="database" onClick={() => onNavigate("database")}/>
            <Metric icon="⬢" title="Runtime" value={unavailable("runtime") ? "—" : data.runtime.length} note={unavailable("runtime") ? "Evidence unavailable" : `${sevCount(data.runtime,"critical") + sevCount(data.runtime,"high")} high-priority`} tone="runtime" onClick={() => onNavigate("runtime")}/>
            <Metric icon="△" title="QA Evidence" value={unavailable("qa") ? "—" : data.qa.length} note={unavailable("qa") ? "Evidence unavailable" : `${data.qaFrameworks.length} framework${data.qaFrameworks.length === 1 ? "" : "s"} detected`} tone="qa" onClick={() => onNavigate("qa")}/>
          </section>

          <section className="ct-grid-a">
            <Card title="Open findings overview"><div className="ct-bars">{[["Quality",data.quality.length,"quality"],["Security",data.security.length,"security"],["Database",data.database.length,"database"],["Runtime",data.runtime.length,"runtime"]].map(([label,value,tone]) => <div key={String(label)}><span>{label}</span><b><i data-tone={tone} style={{width:`${Math.max(4, Number(value) / maxFindings * 100)}%`}}/></b><strong>{data.unavailable.includes(String(label).toLowerCase() as EvidenceKey) ? "—" : value}</strong></div>)}</div><p className="ct-truth">Counts come from durable open findings. Failed evidence reads are marked unavailable rather than converted to zero.</p></Card>
            <Card title="Findings by severity"><div className="ct-severity"><div className="ct-donut" style={donut}><span><strong>{total}</strong><small>Loaded open</small></span></div><div>{[["Critical",severity.critical,"critical"],["High",severity.high,"high"],["Medium",severity.medium,"medium"],["Low",severity.low,"low"]].map(([label,value,tone]) => <p key={String(label)}><i className={String(tone)}/><span>{label}</span><b>{value}</b></p>)}</div></div>{data.unavailable.some((key) => ["quality","security","database","runtime"].includes(key)) && <p className="ct-truth">Severity totals cover successfully loaded analyzers only.</p>}</Card>
            <Card title="Tech stack"><div className="ct-stack">{stack.length ? stack.map((item,index) => <p key={item}><span>{String(index+1).padStart(2,"0")}</span><b>{item}</b></p>) : <em>No stack metadata detected.</em>}</div></Card>
          </section>

          <section className="ct-grid-b">
            <div className="ct-column">
              <Card title="Digital Twin overview" action={<button className="ct-link" onClick={() => onNavigate("engineering")}>Explore twin ›</button>}><div className="ct-twin"><div><b>{summary.delta.files_scanned}</b><span>Files scanned</span></div><div><b>{unavailable("twin") ? "—" : data.graph.node_count}</b><span>Graph nodes</span></div><div><b>{unavailable("twin") ? "—" : data.graph.edge_count}</b><span>Graph edges</span></div><div><b>{summary.delta.parse_errors}</b><span>Parse errors</span></div></div></Card>
              <Card title="Quick actions"><div className="ct-actions"><button className="primary" onClick={() => void runDeterministicAnalysis()}>▷ Run deterministic analysis</button><button onClick={() => onNavigate("engineering")}>◇ View Digital Twin</button><button onClick={() => onNavigate("security")}>⬡ Review Security</button><button onClick={() => onNavigate("database")}>▣ Analyze Database</button><button onClick={() => onNavigate("runtime")}>⬢ Runtime Reliability</button><button onClick={() => onNavigate("qa")}>△ QA Evidence</button><button onClick={() => onNavigate("ml")}>AI ML Workspace</button><button onClick={() => onNavigate("repair")}>⌁ Repair Lab</button></div></Card>
            </div>
            <Card title="Analysis activity"><div className="ct-activity">{unavailable("history") ? <em>History unavailable.</em> : data.history.length ? data.history.map((run,index) => <div key={`${run.id ?? index}-${run.started_at}`}><i className={run.status === "completed" ? "ok" : "warn"}/><span><b>Digital Twin update</b><small>{run.status} · {run.duration_ms ?? 0} ms</small></span><time>{fmtTime(run.started_at)}</time></div>) : <em>No persisted analysis history yet.</em>}</div></Card>
            <Card title="Recent findings"><div className="ct-findings">{findings.slice(0,7).map((f) => <button key={`${f.area}-${f.id}`} onClick={() => onNavigate(f.target)}><span className={f.severity.toLowerCase()}>{f.area[0]}</span><div><b>{f.title}</b><small>{f.area} · {f.severity}</small></div><em>›</em></button>)}{!findings.length && <em>{data.unavailable.some((key) => ["quality","security","database","runtime"].includes(key)) ? "Some finding sources are unavailable." : "No open findings are currently persisted."}</em>}</div></Card>
          </section>

          <section className="ct-summary"><b>CT</b><div><strong>CodeTwin-ML evidence summary</strong><p>{stack.length ? `Detected stack: ${stack.slice(0,4).join(", ")}. ` : ""}{findings.length ? `${findings.length} loaded open findings are available across deterministic analyzers.` : "No open deterministic findings are currently persisted in the successfully loaded analyzers."} Semantic enrichment and ML inference remain explicit trusted workflows.</p></div><button onClick={() => onNavigate("engineering")}>Open Engineering</button></section>
        </>}
      </div>
    </section>
  </main>;
}
