import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

type IndexSummary = {
  project_id: string;
  status: AnalysisStatus;
};

type SecurityRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  files_considered: number;
  files_analyzed: number;
  files_stale: number;
  files_skipped: number;
  observations: number;
  findings_opened: number;
  findings_refreshed: number;
  findings_resolved: number;
  hardcoded_credentials: number;
  dynamic_execution: number;
  weak_crypto: number;
  unsafe_c_apis: number;
  duration_ms: number;
};

type SecurityRunRecord = Omit<SecurityRunSummary, "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type SecurityFindingRecord = {
  id: string;
  project_id: string;
  run_id: string;
  rule_id: string;
  severity: string;
  confidence: number | null;
  title: string;
  description: string;
  file_id: string | null;
  symbol_id: string | null;
  source_start_line: number | null;
  source_end_line: number | null;
  cwe: string | null;
  owasp: string | null;
  status: string;
  fingerprint: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
};

type FindingEvidenceRecord = {
  id: string;
  finding_id: string;
  evidence_type: string;
  uri: string | null;
  line_start: number | null;
  line_end: number | null;
  summary: string;
  metadata_json: string;
};

type ScopeFilter = "web" | "all";
type StatusFilter = "open" | "resolved" | "all";

export function WebSecurityWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<SecurityRunSummary | null>(null);
  const [findings, setFindings] = useState<SecurityFindingRecord[]>([]);
  const [history, setHistory] = useState<SecurityRunRecord[]>([]);
  const [scope, setScope] = useState<ScopeFilter>("web");
  const [status, setStatus] = useState<StatusFilter>("open");
  const [selectedFinding, setSelectedFinding] = useState<SecurityFindingRecord | null>(null);
  const [evidence, setEvidence] = useState<FindingEvidenceRecord[]>([]);

  const visibleFindings = useMemo(
    () => scope === "web" ? findings.filter((item) => item.rule_id.startsWith("web.")) : findings,
    [findings, scope],
  );

  const webFindingCount = findings.filter((item) => item.rule_id.startsWith("web.")).length;
  const criticalCount = visibleFindings.filter((item) => item.severity === "critical").length;
  const highCount = visibleFindings.filter((item) => item.severity === "high").length;

  async function loadWorkspace(id: string, nextStatus: StatusFilter = status) {
    const statusArg = nextStatus === "all" ? null : nextStatus;
    const [nextFindings, nextHistory] = await Promise.all([
      invoke<SecurityFindingRecord[]>("list_security_findings", {
        projectId: id,
        status: statusArg,
        limit: 500,
      }),
      invoke<SecurityRunRecord[]>("security_history", { projectId: id, limit: 30 }),
    ]);
    setFindings(nextFindings);
    setHistory(nextHistory);
    setSelectedFinding(null);
    setEvidence([]);
  }

  async function openProject() {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setProjectId(index.project_id);
      setSummary(null);
      setStatus("open");
      setScope("web");
      await loadWorkspace(index.project_id, "open");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function runReview() {
    if (!projectId) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<SecurityRunSummary>("run_security_analysis", { projectId });
      setSummary(result);
      await loadWorkspace(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function changeStatus(nextStatus: StatusFilter) {
    setStatus(nextStatus);
    if (!projectId) return;
    setError(null);
    try {
      await loadWorkspace(projectId, nextStatus);
    } catch (value) {
      setError(String(value));
    }
  }

  async function selectFinding(finding: SecurityFindingRecord) {
    setSelectedFinding(finding);
    setError(null);
    try {
      const nextEvidence = await invoke<FindingEvidenceRecord[]>("list_security_evidence", {
        findingId: finding.id,
        limit: 20,
      });
      setEvidence(nextEvidence);
    } catch (value) {
      setError(String(value));
    }
  }

  return (
    <main className="standalone-workspace">
      <header>
        <div>
          <p className="eyebrow">PERSISTED WEB / APP SECURITY</p>
          <h1>Web Security</h1>
          <p>
            Review source-backed SQL injection, header injection, SSRF, command-injection and AppSec evidence with durable finding lifecycle. The review is static and does not attack, crawl, or execute the target application.
          </p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Project</h2>
        <p>Index the repository first. Findings are persisted against the same Software Digital Twin project and source hashes used by the other deterministic analyzers.</p>
        <div className="row">
          <input
            aria-label="Repository path"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="C:\\work\\project or /home/user/project"
          />
          <button onClick={() => void openProject()} disabled={busy || !path.trim()}>
            {busy && !projectId ? "Opening…" : "Open & index"}
          </button>
        </div>
        {projectId && <p className="mono workspace-project-id">Project {projectId}</p>}
      </section>

      {projectId && (
        <>
          <section className="panel">
            <div className="section-heading">
              <div>
                <h2>Static security review</h2>
                <p>Reads only current hash-verified indexed source. It does not execute repository commands, send HTTP requests, connect to project databases, submit payloads, or claim exploitability.</p>
              </div>
              <button onClick={() => void runReview()} disabled={busy}>
                {busy ? "Reviewing…" : "Run security review"}
              </button>
            </div>
            {summary && (
              <div className="grid runtime-metrics">
                <Metric label="coverage" value={summary.coverage_complete ? "complete" : "incomplete"} />
                <Metric label="files" value={`${summary.files_analyzed}/${summary.files_considered}`} />
                <Metric label="observations" value={summary.observations} />
                <Metric label="opened" value={summary.findings_opened} />
                <Metric label="refreshed" value={summary.findings_refreshed} />
                <Metric label="resolved" value={summary.findings_resolved} />
                <Metric label="web open" value={webFindingCount} />
                <Metric label="duration" value={`${summary.duration_ms} ms`} />
              </div>
            )}
            <p className="warning banner">
              The desktop review persists the deterministic indexed-source rules. The Python web-security CLI remains the broader static layer for selected non-indexed configuration and SQL artifacts; neither layer performs live exploitation.
            </p>
          </section>

          <section className="runtime-layout">
            <div className="twin-column">
              <section className="panel compact">
                <h2>Filters</h2>
                <label>
                  Scope
                  <select value={scope} onChange={(event) => setScope(event.target.value as ScopeFilter)}>
                    <option value="web">Web injection / request flow</option>
                    <option value="all">All persisted AppSec</option>
                  </select>
                </label>
                <label>
                  Lifecycle
                  <select value={status} onChange={(event) => void changeStatus(event.target.value as StatusFilter)}>
                    <option value="open">Open</option>
                    <option value="resolved">Resolved</option>
                    <option value="all">Open + resolved</option>
                  </select>
                </label>
                <div className="grid runtime-metrics">
                  <Metric label="visible" value={visibleFindings.length} />
                  <Metric label="critical" value={criticalCount} />
                  <Metric label="high" value={highCount} />
                </div>
              </section>

              <section className="panel compact">
                <h2>Run history</h2>
                <div className="history-list runtime-scroll-list">
                  {history.map((run) => (
                    <div className="history-item" key={run.run_id}>
                      <div><strong>{run.status}</strong><span>{run.started_at ?? "time unavailable"}</span></div>
                      <span>{run.observations} observations · {run.findings_opened} opened</span>
                      <small>{run.coverage_complete ? "complete coverage" : "incomplete coverage"} · {run.duration_ms ?? 0} ms</small>
                    </div>
                  ))}
                  {!history.length && <p className="empty">No persisted security review run exists for this project.</p>}
                </div>
              </section>
            </div>

            <div className="twin-column wide">
              <section className="panel compact">
                <div className="section-heading">
                  <div>
                    <h2>Persisted findings</h2>
                    <p>{visibleFindings.length} finding{visibleFindings.length === 1 ? "" : "s"}</p>
                  </div>
                </div>
                <div className="result-list runtime-scroll-list">
                  {visibleFindings.map((finding) => (
                    <button
                      className="relationship-item"
                      key={finding.id}
                      onClick={() => void selectFinding(finding)}
                    >
                      <strong>{finding.severity.toUpperCase()} · {finding.title}</strong>
                      <span>{finding.rule_id} · {finding.cwe ?? "CWE unavailable"}</span>
                      <small>
                        {finding.status} · confidence {finding.confidence == null ? "n/a" : finding.confidence.toFixed(2)}
                        {finding.source_start_line ? ` · line ${finding.source_start_line}` : ""}
                      </small>
                    </button>
                  ))}
                  {!visibleFindings.length && <p className="empty">No finding matches the current scope and lifecycle filter.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Selected evidence</h2>
                {!selectedFinding && <p className="empty">Select a finding to inspect its persisted source evidence and remediation context.</p>}
                {selectedFinding && (
                  <>
                    <p><strong>{selectedFinding.title}</strong></p>
                    <p>{selectedFinding.description}</p>
                    <p className="mono">{selectedFinding.rule_id} · {selectedFinding.cwe ?? "no CWE"} · {selectedFinding.owasp ?? "no OWASP mapping"}</p>
                    <div className="relationship-list runtime-scroll-list">
                      {evidence.map((item) => (
                        <div className="relationship-item" key={item.id}>
                          <strong>{item.uri ?? "source"}{item.line_start ? `:${item.line_start}` : ""}</strong>
                          <span>{item.summary}</span>
                          <small>{item.evidence_type}</small>
                        </div>
                      ))}
                      {!evidence.length && <p className="empty">No persisted evidence record is available.</p>}
                    </div>
                  </>
                )}
              </section>
            </div>
          </section>
        </>
      )}
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <article className="card"><h3>{label}</h3><p>{value}</p></article>;
}
