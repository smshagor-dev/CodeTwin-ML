import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type FindingFilter = "open" | "resolved" | "all";

type IndexSummary = {
  project_id: string;
  status: AnalysisStatus;
};

type DatabaseRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  artifacts_considered: number;
  artifacts_analyzed: number;
  artifacts_skipped: number;
  sql_files: number;
  prisma_schemas: number;
  observations: number;
  findings_opened: number;
  findings_refreshed: number;
  findings_resolved: number;
  destructive_statements: number;
  unscoped_writes: number;
  foreign_keys_disabled: number;
  literal_datasource_urls: number;
  duration_ms: number;
};

type DatabaseRunRecord = Omit<DatabaseRunSummary, "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type DatabaseArtifactRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  artifact_kind: string;
  framework: string | null;
  content_hash: string;
  byte_size: number;
  last_run_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  is_active: boolean;
};

type DatabaseFindingRecord = {
  id: string;
  project_id: string;
  run_id: string;
  rule_id: string;
  severity: string;
  confidence: number | null;
  title: string;
  description: string;
  source_start_line: number | null;
  source_end_line: number | null;
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

type DatabaseRuleRecord = {
  id: string;
  title: string;
  description: string;
  confidence: number;
};

export function DatabaseWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<DatabaseRunSummary | null>(null);
  const [artifacts, setArtifacts] = useState<DatabaseArtifactRecord[]>([]);
  const [findings, setFindings] = useState<DatabaseFindingRecord[]>([]);
  const [history, setHistory] = useState<DatabaseRunRecord[]>([]);
  const [rules, setRules] = useState<DatabaseRuleRecord[]>([]);
  const [filter, setFilter] = useState<FindingFilter>("open");
  const [selectedFinding, setSelectedFinding] = useState<DatabaseFindingRecord | null>(null);
  const [evidence, setEvidence] = useState<FindingEvidenceRecord[]>([]);

  async function loadWorkspace(id: string, nextFilter: FindingFilter = filter) {
    const status = nextFilter === "all" ? null : nextFilter;
    const [nextArtifacts, nextFindings, nextHistory, nextRules] = await Promise.all([
      invoke<DatabaseArtifactRecord[]>("list_database_artifacts", { projectId: id, activeOnly: false, limit: 300 }),
      invoke<DatabaseFindingRecord[]>("list_database_findings", { projectId: id, status, limit: 300 }),
      invoke<DatabaseRunRecord[]>("database_history", { projectId: id, limit: 30 }),
      invoke<DatabaseRuleRecord[]>("list_database_rules"),
    ]);
    setArtifacts(nextArtifacts);
    setFindings(nextFindings);
    setHistory(nextHistory);
    setRules(nextRules);
    if (selectedFinding && !nextFindings.some((item) => item.id === selectedFinding.id)) {
      setSelectedFinding(null);
      setEvidence([]);
    }
  }

  async function openProject() {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setProjectId(index.project_id);
      setSummary(null);
      setSelectedFinding(null);
      setEvidence([]);
      await loadWorkspace(index.project_id);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function runAnalysis() {
    if (!projectId) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<DatabaseRunSummary>("run_database_analysis", { projectId });
      setSummary(result);
      await loadWorkspace(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function changeFilter(next: FindingFilter) {
    setFilter(next);
    setSelectedFinding(null);
    setEvidence([]);
    if (!projectId) return;
    setError(null);
    try {
      await loadWorkspace(projectId, next);
    } catch (value) {
      setError(String(value));
    }
  }

  async function selectFinding(finding: DatabaseFindingRecord) {
    setSelectedFinding(finding);
    setError(null);
    try {
      const records = await invoke<FindingEvidenceRecord[]>("list_database_evidence", {
        findingId: finding.id,
        limit: 100,
      });
      setEvidence(records);
    } catch (value) {
      setEvidence([]);
      setError(String(value));
    }
  }

  return (
    <main className="standalone-workspace">
      <header>
        <div>
          <p className="eyebrow">PASSIVE DATABASE REVIEW</p>
          <h1>Database Analysis</h1>
          <p>SQL and Prisma artifact inventory with evidence-backed review findings. No database connection or migration execution.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Project</h2>
        <p>Index the repository first so this workspace uses the same persistent project identity as the Software Digital Twin.</p>
        <div className="row">
          <input aria-label="Repository path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="C:\\work\\project or /home/user/project" />
          <button onClick={() => void openProject()} disabled={busy || !path.trim()}>{busy && !projectId ? "Opening…" : "Open & index"}</button>
        </div>
        {projectId && <p className="mono workspace-project-id">Project {projectId}</p>}
      </section>

      {projectId && (
        <>
          <section className="panel">
            <div className="section-heading">
              <div>
                <h2>Database review</h2>
                <p>Scans bounded SQL/Prisma artifacts as untrusted text. Findings are review signals, not proof of live database state or data loss.</p>
              </div>
              <button onClick={() => void runAnalysis()} disabled={busy}>{busy ? "Analyzing…" : "Run database analysis"}</button>
            </div>
            {summary && (
              <div className="grid database-metrics">
                <Metric label="coverage" value={summary.coverage_complete ? "complete" : "incomplete"} />
                <Metric label="artifacts" value={summary.artifacts_analyzed} />
                <Metric label="skipped" value={summary.artifacts_skipped} />
                <Metric label="observations" value={summary.observations} />
                <Metric label="opened" value={summary.findings_opened} />
                <Metric label="refreshed" value={summary.findings_refreshed} />
                <Metric label="resolved" value={summary.findings_resolved} />
                <Metric label="destructive DDL" value={summary.destructive_statements} />
                <Metric label="unscoped writes" value={summary.unscoped_writes} />
                <Metric label="FK disabled" value={summary.foreign_keys_disabled} />
                <Metric label="literal URLs" value={summary.literal_datasource_urls} />
                <Metric label="duration" value={`${summary.duration_ms} ms`} />
              </div>
            )}
            {summary && !summary.coverage_complete && (
              <p className="warning banner">Coverage is incomplete. Existing findings are intentionally not auto-resolved from skipped or unreadable artifacts.</p>
            )}
          </section>

          <section className="database-layout">
            <div className="twin-column">
              <section className="panel compact">
                <div className="section-heading">
                  <div><h2>Findings</h2><p>{findings.length} bounded result{findings.length === 1 ? "" : "s"}</p></div>
                  <select aria-label="Database finding status" value={filter} onChange={(event) => void changeFilter(event.target.value as FindingFilter)}>
                    <option value="open">Open</option>
                    <option value="resolved">Resolved</option>
                    <option value="all">All</option>
                  </select>
                </div>
                <div className="result-list database-scroll-list">
                  {findings.map((finding) => (
                    <button key={finding.id} className={`result-item finding-item ${selectedFinding?.id === finding.id ? "selected" : ""}`} onClick={() => void selectFinding(finding)}>
                      <strong>{finding.title}</strong>
                      <span>{finding.rule_id} · {finding.status}</span>
                      <small>{finding.source_start_line ? `line ${finding.source_start_line}` : "artifact-level evidence"}</small>
                    </button>
                  ))}
                  {!findings.length && <p className="empty">No findings match this status filter.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Artifacts</h2>
                <div className="result-list database-scroll-list">
                  {artifacts.map((artifact) => (
                    <div className="relationship-item" key={artifact.id}>
                      <strong>{artifact.relative_path}</strong>
                      <span>{artifact.artifact_kind}{artifact.framework ? ` · ${artifact.framework}` : ""} · {artifact.byte_size} bytes</span>
                      <small>{artifact.is_active ? "active" : "inactive"} · hash {artifact.content_hash.slice(0, 16)}…</small>
                    </div>
                  ))}
                  {!artifacts.length && <p className="empty">No database artifacts have been inventoried for this project.</p>}
                </div>
              </section>
            </div>

            <div className="twin-column wide">
              <section className="panel compact detail-panel">
                <h2>Finding evidence</h2>
                {selectedFinding ? (
                  <>
                    <div className="finding-title-row">
                      <span className={`severity severity-${selectedFinding.severity}`}>{selectedFinding.severity}</span>
                      <strong>{selectedFinding.title}</strong>
                    </div>
                    <p>{selectedFinding.description}</p>
                    <dl className="metadata-grid">
                      <dt>Rule</dt><dd>{selectedFinding.rule_id}</dd>
                      <dt>Status</dt><dd>{selectedFinding.status}</dd>
                      <dt>Confidence</dt><dd>{selectedFinding.confidence ?? "Unavailable"}</dd>
                      <dt>Range</dt><dd>{selectedFinding.source_start_line ?? "—"}–{selectedFinding.source_end_line ?? "—"}</dd>
                      <dt>Fingerprint</dt><dd className="mono">{selectedFinding.fingerprint}</dd>
                    </dl>
                    <div className="relationship-list">
                      {evidence.map((item) => (
                        <div className="relationship-item" key={item.id}>
                          <strong>{item.evidence_type}</strong>
                          <span>{item.uri ?? "No artifact URI"}{item.line_start ? ` · lines ${item.line_start}–${item.line_end ?? item.line_start}` : ""}</span>
                          <small>{item.summary}</small>
                        </div>
                      ))}
                      {!evidence.length && <p className="empty">No bounded evidence records are stored for this finding.</p>}
                    </div>
                  </>
                ) : <p className="empty">Select a finding to inspect persisted evidence.</p>}
              </section>

              <section className="panel compact">
                <h2>Rules</h2>
                <div className="relationship-list">
                  {rules.map((rule) => (
                    <div className="relationship-item" key={rule.id}>
                      <strong>{rule.title}</strong>
                      <span>{rule.id} · confidence {rule.confidence}</span>
                      <small>{rule.description}</small>
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel compact">
                <h2>Run history</h2>
                <div className="history-list">
                  {history.map((run) => (
                    <div className="history-item" key={run.run_id}>
                      <div><strong>{run.status}</strong><span>{run.started_at ?? "time unavailable"}</span></div>
                      <span>{run.observations} observations · {run.duration_ms ?? 0} ms</span>
                      <small>{run.coverage_complete ? "complete coverage" : "incomplete coverage"} · {run.findings_opened} opened · {run.findings_resolved} resolved</small>
                    </div>
                  ))}
                  {!history.length && <p className="empty">No database analysis run has been persisted for this project.</p>}
                </div>
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
