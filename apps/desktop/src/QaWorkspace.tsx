import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

type IndexSummary = {
  project_id: string;
  status: AnalysisStatus;
};

type QaDiscoveryRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  candidate_files: number;
  artifacts_discovered: number;
  artifacts_skipped: number;
  test_files: number;
  config_files: number;
  framework_count: number;
  frameworks: string[];
  duration_ms: number;
};

type QaDiscoveryRunRecord = Omit<QaDiscoveryRunSummary, "frameworks" | "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type QaArtifactRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  artifact_kind: string;
  framework: string;
  evidence_kind: string;
  content_hash: string;
  byte_size: number;
  last_run_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  is_active: boolean;
};

type QaFrameworkSummary = {
  framework: string;
  artifacts: number;
  test_files: number;
  config_files: number;
};

export function QaWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<QaDiscoveryRunSummary | null>(null);
  const [artifacts, setArtifacts] = useState<QaArtifactRecord[]>([]);
  const [frameworks, setFrameworks] = useState<QaFrameworkSummary[]>([]);
  const [history, setHistory] = useState<QaDiscoveryRunRecord[]>([]);
  const [frameworkFilter, setFrameworkFilter] = useState("all");

  async function loadWorkspace(id: string, nextFramework = frameworkFilter) {
    const framework = nextFramework === "all" ? null : nextFramework;
    const [nextArtifacts, nextFrameworks, nextHistory] = await Promise.all([
      invoke<QaArtifactRecord[]>("list_qa_artifacts", {
        projectId: id,
        activeOnly: false,
        framework,
        limit: 500,
      }),
      invoke<QaFrameworkSummary[]>("list_qa_frameworks", { projectId: id }),
      invoke<QaDiscoveryRunRecord[]>("qa_discovery_history", { projectId: id, limit: 30 }),
    ]);
    setArtifacts(nextArtifacts);
    setFrameworks(nextFrameworks);
    setHistory(nextHistory);
  }

  async function openProject() {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setProjectId(index.project_id);
      setSummary(null);
      setFrameworkFilter("all");
      await loadWorkspace(index.project_id, "all");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function runDiscovery() {
    if (!projectId) return;
    setBusy(true);
    setError(null);
    try {
      const result = await invoke<QaDiscoveryRunSummary>("run_qa_discovery", { projectId });
      setSummary(result);
      await loadWorkspace(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function changeFramework(nextFramework: string) {
    setFrameworkFilter(nextFramework);
    if (!projectId) return;
    setError(null);
    try {
      await loadWorkspace(projectId, nextFramework);
    } catch (value) {
      setError(String(value));
    }
  }

  return (
    <main className="standalone-workspace">
      <header>
        <div>
          <p className="eyebrow">PASSIVE QA / TEST INVENTORY</p>
          <h1>QA Discovery</h1>
          <p>Inventory test files and framework configuration as static repository evidence. Discovery never means tests ran, passed, failed, or produced coverage.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Project</h2>
        <p>Index the repository first so QA evidence is tied to the same persistent Software Digital Twin identity.</p>
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
                <h2>Discovery scan</h2>
                <p>Reads bounded conventional test/config candidates only. No package scripts, test runners, browsers, compilers, interpreters, hooks, or repository executables are started.</p>
              </div>
              <button onClick={() => void runDiscovery()} disabled={busy}>
                {busy ? "Discovering…" : "Run QA discovery"}
              </button>
            </div>
            {summary && (
              <div className="grid runtime-metrics">
                <Metric label="coverage" value={summary.coverage_complete ? "complete" : "incomplete"} />
                <Metric label="candidates" value={summary.candidate_files} />
                <Metric label="evidence" value={summary.artifacts_discovered} />
                <Metric label="test files" value={summary.test_files} />
                <Metric label="config evidence" value={summary.config_files} />
                <Metric label="frameworks" value={summary.framework_count} />
                <Metric label="skipped" value={summary.artifacts_skipped} />
                <Metric label="duration" value={`${summary.duration_ms} ms`} />
              </div>
            )}
            <p className="warning banner">QA discovery is evidence inventory only. No test result or coverage claim is produced by this workspace.</p>
            {summary && !summary.coverage_complete && (
              <p className="warning banner">Coverage is incomplete because at least one candidate could not be safely inspected. Existing artifacts are not deactivated from an incomplete scan.</p>
            )}
          </section>

          <section className="runtime-layout">
            <div className="twin-column">
              <section className="panel compact">
                <h2>Framework evidence</h2>
                <div className="relationship-list runtime-scroll-list">
                  {frameworks.map((framework) => (
                    <div className="relationship-item" key={framework.framework}>
                      <strong>{framework.framework}</strong>
                      <span>{framework.test_files} test · {framework.config_files} config</span>
                      <small>{framework.artifacts} active evidence record{framework.artifacts === 1 ? "" : "s"}</small>
                    </div>
                  ))}
                  {!frameworks.length && <p className="empty">No active framework evidence has been discovered yet.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Run history</h2>
                <div className="history-list runtime-scroll-list">
                  {history.map((run) => (
                    <div className="history-item" key={run.run_id}>
                      <div><strong>{run.status}</strong><span>{run.started_at ?? "time unavailable"}</span></div>
                      <span>{run.artifacts_discovered} evidence · {run.framework_count} frameworks</span>
                      <small>{run.coverage_complete ? "complete coverage" : "incomplete coverage"} · {run.duration_ms ?? 0} ms</small>
                    </div>
                  ))}
                  {!history.length && <p className="empty">No QA discovery run has been persisted for this project.</p>}
                </div>
              </section>
            </div>

            <div className="twin-column wide">
              <section className="panel compact">
                <div className="section-heading">
                  <div>
                    <h2>Test & config evidence</h2>
                    <p>{artifacts.length} bounded result{artifacts.length === 1 ? "" : "s"}</p>
                  </div>
                  <select
                    aria-label="QA framework filter"
                    value={frameworkFilter}
                    onChange={(event) => void changeFramework(event.target.value)}
                  >
                    <option value="all">All frameworks</option>
                    {frameworks.map((framework) => (
                      <option value={framework.framework} key={framework.framework}>{framework.framework}</option>
                    ))}
                  </select>
                </div>
                <div className="result-list qa-artifact-list">
                  {artifacts.map((artifact) => (
                    <div className="relationship-item" key={artifact.id}>
                      <strong>{artifact.relative_path}</strong>
                      <span>{artifact.framework} · {artifact.artifact_kind} · {artifact.evidence_kind}</span>
                      <small>{artifact.is_active ? "active" : "inactive"} · {artifact.byte_size} bytes · SHA-256 {artifact.content_hash.slice(0, 16)}…</small>
                    </div>
                  ))}
                  {!artifacts.length && <p className="empty">No QA evidence matches this framework filter.</p>}
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
