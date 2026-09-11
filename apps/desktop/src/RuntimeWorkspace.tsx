import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type FindingFilter = "open" | "resolved" | "all";

type IndexSummary = {
  project_id: string;
  status: AnalysisStatus;
};

type RuntimeRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  artifacts_considered: number;
  artifacts_analyzed: number;
  artifacts_skipped: number;
  dockerfiles: number;
  compose_files: number;
  observations: number;
  findings_opened: number;
  findings_refreshed: number;
  findings_resolved: number;
  mutable_images: number;
  healthchecks_disabled: number;
  healthchecks_missing: number;
  restarts_disabled: number;
  duration_ms: number;
};

type RuntimeRunRecord = Omit<RuntimeRunSummary, "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type RuntimeArtifactRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  artifact_kind: string;
  content_hash: string;
  byte_size: number;
  last_run_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  is_active: boolean;
};

type RuntimeFindingRecord = {
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

type RuntimeRuleRecord = {
  id: string;
  title: string;
  description: string;
  confidence: number;
};

export function RuntimeWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<RuntimeRunSummary | null>(null);
  const [artifacts, setArtifacts] = useState<RuntimeArtifactRecord[]>([]);
  const [findings, setFindings] = useState<RuntimeFindingRecord[]>([]);
  const [history, setHistory] = useState<RuntimeRunRecord[]>([]);
  const [rules, setRules] = useState<RuntimeRuleRecord[]>([]);
  const [filter, setFilter] = useState<FindingFilter>("open");
  const [selectedFinding, setSelectedFinding] = useState<RuntimeFindingRecord | null>(null);
  const [evidence, setEvidence] = useState<FindingEvidenceRecord[]>([]);

  async function loadWorkspace(id: string, nextFilter: FindingFilter = filter) {
    const status = nextFilter === "all" ? null : nextFilter;
    const [nextArtifacts, nextFindings, nextHistory, nextRules] = await Promise.all([
      invoke<RuntimeArtifactRecord[]>("list_runtime_artifacts", { projectId: id, activeOnly: false, limit: 300 }),
      invoke<RuntimeFindingRecord[]>("list_runtime_findings", { projectId: id, status, limit: 300 }),
      invoke<RuntimeRunRecord[]>("runtime_history", { projectId: id, limit: 30 }),
      invoke<RuntimeRuleRecord[]>("list_runtime_rules"),
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
      const result = await invoke<RuntimeRunSummary>("run_runtime_analysis", { projectId });
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

  async function selectFinding(finding: RuntimeFindingRecord) {
    setSelectedFinding(finding);
    setError(null);
    try {
      const records = await invoke<FindingEvidenceRecord[]>("list_runtime_evidence", {
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
          <p className="eyebrow">PASSIVE RUNTIME RELIABILITY REVIEW</p>
          <h1>Runtime Reliability</h1>
          <p>Dockerfile and Compose configuration evidence. No containers, services, health probes, or repository commands are executed.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Project</h2>
        <p>Index the repository first so Runtime Reliability shares the persistent Software Digital Twin project identity.</p>
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
                <h2>Reliability review</h2>
                <p>Reviews bounded Dockerfile/Compose artifacts as untrusted text. Findings are configuration review signals, not live availability or outage evidence.</p>
              </div>
              <button onClick={() => void runAnalysis()} disabled={busy}>{busy ? "Analyzing…" : "Run runtime analysis"}</button>
            </div>
            {summary && (
              <div className="grid runtime-metrics">
                <Metric label="coverage" value={summary.coverage_complete ? "complete" : "incomplete"} />
                <Metric label="artifacts" value={summary.artifacts_analyzed} />
                <Metric label="Dockerfiles" value={summary.dockerfiles} />
                <Metric label="Compose files" value={summary.compose_files} />
                <Metric label="skipped" value={summary.artifacts_skipped} />
                <Metric label="observations" value={summary.observations} />
                <Metric label="opened" value={summary.findings_opened} />
                <Metric label="resolved" value={summary.findings_resolved} />
                <Metric label="mutable images" value={summary.mutable_images} />
                <Metric label="health disabled" value={summary.healthchecks_disabled} />
                <Metric label="health missing" value={summary.healthchecks_missing} />
                <Metric label="restart disabled" value={summary.restarts_disabled} />
                <Metric label="duration" value={`${summary.duration_ms} ms`} />
              </div>
            )}
            {summary && !summary.coverage_complete && (
              <p className="warning banner">Coverage is incomplete. Existing findings are intentionally not auto-resolved from skipped or unreadable runtime artifacts.</p>
            )}
          </section>

          <section className="runtime-layout">
            <div className="twin-column">
              <section className="panel compact">
                <div className="section-heading">
                  <div><h2>Findings</h2><p>{findings.length} bounded result{findings.length === 1 ? "" : "s"}</p></div>
                  <select aria-label="Runtime finding status" value={filter} onChange={(event) => void changeFilter(event.target.value as FindingFilter)}>
                    <option value="open">Open</option>
                    <option value="resolved">Resolved</option>
                    <option value="all">All</option>
                  </select>
                </div>
                <div className="result-list runtime-scroll-list">
                  {findings.map((finding) => (
                    <button key={finding.id} className={`result-item finding-item ${selectedFinding?.id === finding.id ? "selected" : ""}`} onClick={() => void selectFinding(finding)}>
                      <strong>{finding.title}</strong>
                      <span>{finding.rule_id} · {finding.status}</span>
                      <small>{finding.source_start_line ? `line ${finding.source_start_line}` : "artifact-level evidence"}</small>
                    </button>
                  ))}
                  {!findings.length && <p className="empty">No runtime findings match this status filter.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Runtime artifacts</h2>
                <div className="result-list runtime-scroll-list">
                  {artifacts.map((artifact) => (
                    <div className="relationship-item" key={artifact.id}>
                      <strong>{artifact.relative_path}</strong>
                      <span>{artifact.artifact_kind} · {artifact.byte_size} bytes</span>
                      <small>{artifact.is_active ? "active" : "inactive"} · hash {artifact.content_hash.slice(0, 16)}…</small>
                    </div>
                  ))}
                  {!artifacts.length && <p className="empty">No Dockerfile or Compose artifacts have been inventoried for this project.</p>}
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
                ) : <p className="empty">Select a finding to inspect persisted runtime evidence.</p>}
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
                  {!history.length && <p className="empty">No runtime reliability analysis run has been persisted for this project.</p>}
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
