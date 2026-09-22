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

type TestRunnerKind = "pytest" | "rust_cargo_test" | "go_test" | "vitest" | "jest" | "php_unit";

type QaExecutionAvailability = {
  execution_enabled: boolean;
  backend_kind: string;
  enforced_capabilities: Record<string, boolean>;
  reason: string;
};

type QaExecutionPlanRecord = {
  id: string;
  project_id: string;
  status: "blocked" | "planned" | "approved";
  blocking_reasons: string[];
  provenance: Record<string, unknown>;
  approved_at: string | null;
};

type QaExecutionRunRecord = {
  id: string;
  plan_id: string;
  project_id: string;
  status: "queued" | "running" | "completed" | "failed" | "timed_out" | "cancelled" | "infrastructure_error";
  duration_ms: number | null;
  exit_code: number | null;
  parser_completed: boolean;
  tests_passed: boolean | null;
  stdout_excerpt: string;
  stderr_excerpt: string;
  created_at: string;
};

const strictQaPolicy = {
  timeout_ms: 120_000,
  cpu_time_seconds: 60,
  memory_bytes: 2 * 1024 * 1024 * 1024,
  max_output_bytes: 512 * 1024,
  max_targets: 32,
  require_process_isolation: true,
  require_filesystem_isolation: true,
  require_network_isolation: true,
  require_cpu_limit: true,
  require_memory_limit: true,
  require_cancellation: true,
  inherit_host_environment: false,
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
  const [dockerExecutable, setDockerExecutable] = useState("");
  const [dockerImage, setDockerImage] = useState("");
  const [runner, setRunner] = useState<TestRunnerKind>("pytest");
  const [targetText, setTargetText] = useState("");
  const [dockerAvailability, setDockerAvailability] = useState<QaExecutionAvailability | null>(null);
  const [executionPlans, setExecutionPlans] = useState<QaExecutionPlanRecord[]>([]);
  const [executionRuns, setExecutionRuns] = useState<QaExecutionRunRecord[]>([]);
  const [selectedPlanId, setSelectedPlanId] = useState("");
  const [executionBusy, setExecutionBusy] = useState(false);

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
    const [nextPlans, nextRuns] = await Promise.all([
      invoke<QaExecutionPlanRecord[]>("list_qa_execution_plans", { projectId: id, limit: 50 }),
      invoke<QaExecutionRunRecord[]>("qa_execution_history", { projectId: id, limit: 50 }),
    ]);
    setExecutionPlans(nextPlans);
    setExecutionRuns(nextRuns);
    setSelectedPlanId((current) =>
      current && nextPlans.some((plan) => plan.id === current) ? current : nextPlans[0]?.id ?? "",
    );
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


  async function checkDocker() {
    if (!dockerExecutable.trim() || !dockerImage.trim()) return;
    setExecutionBusy(true);
    setError(null);
    try {
      const availability = await invoke<QaExecutionAvailability>("qa_docker_availability", {
        dockerExecutable: dockerExecutable.trim(),
        image: dockerImage.trim(),
      });
      setDockerAvailability(availability);
    } catch (value) {
      setDockerAvailability(null);
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function createExecutionPlan() {
    if (!projectId) return;
    const targets = [...new Set(
      targetText.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean),
    )];
    if (!targets.length) {
      setError("Enter at least one explicit test target.");
      return;
    }
    setExecutionBusy(true);
    setError(null);
    try {
      const plan = await invoke<QaExecutionPlanRecord>("create_qa_docker_plan", {
        request: {
          project_id: projectId,
          discovery_run_id: summary?.run_id ?? history.find((run) => run.status === "completed")?.run_id ?? null,
          runner,
          targets,
          docker_executable: dockerExecutable.trim(),
          image: dockerImage.trim(),
          policy: strictQaPolicy,
        },
      });
      setSelectedPlanId(plan.id);
      await loadWorkspace(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function approveExecutionPlan() {
    if (!projectId || !selectedPlanId) return;
    setExecutionBusy(true);
    setError(null);
    try {
      await invoke<QaExecutionPlanRecord>("approve_qa_execution_plan", { planId: selectedPlanId });
      await loadWorkspace(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function runExecutionPlan() {
    if (!projectId || !selectedPlanId) return;
    setExecutionBusy(true);
    setError(null);
    try {
      await invoke<QaExecutionRunRecord>("run_qa_docker_plan", { planId: selectedPlanId });
      await loadWorkspace(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function cancelExecutionPlan() {
    if (!selectedPlanId) return;
    try {
      await invoke<boolean>("cancel_qa_execution", { planId: selectedPlanId });
    } catch (value) {
      setError(String(value));
    }
  }

  const selectedPlan = executionPlans.find((plan) => plan.id === selectedPlanId) ?? null;

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

          <section className="panel">
            <div className="section-heading">
              <div>
                <h2>Safe QA execution</h2>
                <p>Run only explicitly selected tests inside a digest-pinned Docker sandbox. Source is read-only, network is disabled, Linux capabilities are dropped, output/time/memory/PID budgets are enforced, and every run requires an immutable approved plan.</p>
              </div>
              <button onClick={() => void checkDocker()} disabled={executionBusy || !dockerExecutable.trim() || !dockerImage.trim()}>
                Check Docker sandbox
              </button>
            </div>
            <div className="ml-config-grid">
              <label>
                <span>Docker executable</span>
                <input value={dockerExecutable} onChange={(event) => setDockerExecutable(event.target.value)} placeholder="C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe or /usr/bin/docker" />
              </label>
              <label>
                <span>Digest-pinned test image</span>
                <input value={dockerImage} onChange={(event) => setDockerImage(event.target.value)} placeholder="registry/image@sha256:..." />
              </label>
              <label>
                <span>Runner</span>
                <select value={runner} onChange={(event) => setRunner(event.target.value as TestRunnerKind)}>
                  <option value="pytest">pytest</option>
                  <option value="rust_cargo_test">cargo test</option>
                  <option value="go_test">go test</option>
                  <option value="vitest">Vitest</option>
                  <option value="jest">Jest</option>
                  <option value="php_unit">PHPUnit</option>
                </select>
              </label>
              <label>
                <span>Explicit test targets</span>
                <textarea value={targetText} onChange={(event) => setTargetText(event.target.value)} placeholder={"tests/test_api.py\ntests/test_auth.py"} />
              </label>
            </div>
            {dockerAvailability && (
              <p className={dockerAvailability.execution_enabled ? "status-good" : "warning banner"}>
                {dockerAvailability.backend_kind}: {dockerAvailability.reason}
              </p>
            )}
            <div className="row">
              <button
                onClick={() => void createExecutionPlan()}
                disabled={executionBusy || !dockerAvailability?.execution_enabled || !targetText.trim()}
              >
                Create immutable plan
              </button>
              <select
                aria-label="QA execution plan"
                value={selectedPlanId}
                onChange={(event) => setSelectedPlanId(event.target.value)}
              >
                <option value="">Select plan</option>
                {executionPlans.map((plan) => (
                  <option key={plan.id} value={plan.id}>{plan.status} · {plan.id.slice(0, 18)}…</option>
                ))}
              </select>
              <button onClick={() => void approveExecutionPlan()} disabled={executionBusy || selectedPlan?.status !== "planned"}>
                Approve exact plan
              </button>
              <button onClick={() => void runExecutionPlan()} disabled={executionBusy || selectedPlan?.status !== "approved"}>
                {executionBusy ? "Running…" : "Run approved tests"}
              </button>
              <button onClick={() => void cancelExecutionPlan()} disabled={!executionBusy || !selectedPlanId}>
                Cancel
              </button>
            </div>
            {selectedPlan?.blocking_reasons?.length ? (
              <p className="warning banner">{selectedPlan.blocking_reasons.join(" · ")}</p>
            ) : null}
            <p className="warning banner">Floating image tags are rejected. The image must already exist locally and be referenced as <code>repository@sha256:...</code>; CodeTwin runs Docker with <code>--pull=never</code> and <code>--network none</code>.</p>
            <div className="history-list runtime-scroll-list">
              {executionRuns.map((run) => (
                <div className="history-item" key={run.id}>
                  <div><strong>{run.status}</strong><span>{run.created_at}</span></div>
                  <span>exit {run.exit_code ?? "n/a"} · {run.tests_passed === null ? "verdict unavailable" : run.tests_passed ? "tests passed" : "tests failed"}</span>
                  <small>{run.duration_ms ?? 0} ms · stdout {run.stdout_excerpt.slice(0, 180)}{run.stderr_excerpt ? " · stderr " + run.stderr_excerpt.slice(0, 180) : ""}</small>
                </div>
              ))}
              {!executionRuns.length && <p className="empty">No approved QA execution has run for this project.</p>}
            </div>
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
