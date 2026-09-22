import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type QaTestRunnerKind = "pytest" | "rust_cargo_test" | "go_test" | "vitest" | "jest" | "php_unit";
type QaExecutionPlanStatus = "blocked" | "planned" | "approved";
type QaExecutionRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "infrastructure_error";

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

type QaSandboxCapabilities = {
  process_isolation: boolean;
  filesystem_isolation: boolean;
  network_isolation: boolean;
  cpu_limit: boolean;
  memory_limit: boolean;
  cancellation: boolean;
};

type QaExecutionAvailability = {
  execution_enabled: boolean;
  backend_kind: string;
  enforced_capabilities: QaSandboxCapabilities;
  reason: string;
};

type QaExecutionPlanRecord = {
  id: string;
  project_id: string;
  discovery_run_id: string | null;
  runner: QaTestRunnerKind;
  status: QaExecutionPlanStatus;
  blocking_reasons: string[];
  command: { program: string; args: string[]; uses_shell: boolean };
  approved_project_manifest: { sha256: string } | null;
  approved_external_read_surface: { sha256: string } | null;
  created_at: string;
  approved_at: string | null;
};

type QaExecutionRunRecord = {
  id: string;
  plan_id: string;
  project_id: string;
  status: QaExecutionRunStatus;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  exit_code: number | null;
  parser_completed: boolean;
  tests_passed: boolean | null;
  stdout_excerpt: string;
  stderr_excerpt: string;
  stdout_original_bytes: number;
  stderr_original_bytes: number;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
  result: unknown;
  created_at: string;
};

const RUNNER_OPTIONS: Array<[QaTestRunnerKind, string]> = [
  ["pytest", "Pytest"],
  ["vitest", "Vitest"],
  ["jest", "Jest"],
  ["rust_cargo_test", "Rust cargo test"],
  ["go_test", "Go test"],
  ["php_unit", "PHPUnit"],
];

function defaultPolicy(targetCount: number) {
  return {
    timeout_ms: 120_000,
    cpu_time_seconds: 60,
    memory_bytes: 2 * 1024 * 1024 * 1024,
    max_output_bytes: 512 * 1024,
    max_targets: Math.max(1, Math.min(32, targetCount || 1)),
    require_process_isolation: true,
    require_filesystem_isolation: true,
    require_network_isolation: true,
    require_cpu_limit: true,
    require_memory_limit: true,
    require_cancellation: true,
    inherit_host_environment: false,
  };
}

function uniqueLines(value: string): string[] {
  return [...new Set(value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))];
}

function executableParent(value: string): string {
  const trimmed = value.trim().replace(/[\\/]+$/, "");
  const slash = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  return slash > 0 ? trimmed.slice(0, slash) : "";
}

function frameworkRunner(framework: string | undefined): QaTestRunnerKind {
  switch ((framework ?? "").toLowerCase()) {
    case "pytest":
      return "pytest";
    case "vitest":
      return "vitest";
    case "jest":
      return "jest";
    case "cargo":
    case "rust":
      return "rust_cargo_test";
    case "go":
      return "go_test";
    case "phpunit":
      return "php_unit";
    default:
      return "pytest";
  }
}

export function QaWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [executionBusy, setExecutionBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<QaDiscoveryRunSummary | null>(null);
  const [artifacts, setArtifacts] = useState<QaArtifactRecord[]>([]);
  const [frameworks, setFrameworks] = useState<QaFrameworkSummary[]>([]);
  const [history, setHistory] = useState<QaDiscoveryRunRecord[]>([]);
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [availability, setAvailability] = useState<QaExecutionAvailability | null>(null);
  const [plans, setPlans] = useState<QaExecutionPlanRecord[]>([]);
  const [runs, setRuns] = useState<QaExecutionRunRecord[]>([]);
  const [runner, setRunner] = useState<QaTestRunnerKind>("pytest");
  const [targetsText, setTargetsText] = useState("");
  const [toolchainPath, setToolchainPath] = useState("");
  const [toolchainVersion, setToolchainVersion] = useState("");
  const [externalRootsText, setExternalRootsText] = useState("");

  const activeTestArtifacts = useMemo(
    () => artifacts.filter((artifact) => artifact.is_active && artifact.artifact_kind === "test_file"),
    [artifacts],
  );

  async function loadExecution(id: string) {
    const [nextAvailability, nextPlans, nextRuns] = await Promise.all([
      invoke<QaExecutionAvailability>("qa_execution_availability"),
      invoke<QaExecutionPlanRecord[]>("list_qa_execution_plans", { projectId: id, limit: 30 }),
      invoke<QaExecutionRunRecord[]>("list_qa_execution_runs", { projectId: id, limit: 30 }),
    ]);
    setAvailability(nextAvailability);
    setPlans(nextPlans);
    setRuns(nextRuns);
  }

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
    if (!targetsText.trim()) {
      const candidates = nextArtifacts
        .filter((artifact) => artifact.is_active && artifact.artifact_kind === "test_file")
        .slice(0, 16);
      setTargetsText(candidates.map((artifact) => artifact.relative_path).join("\n"));
      if (candidates[0]) setRunner(frameworkRunner(candidates[0].framework));
    }
    await loadExecution(id);
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
      setTargetsText("");
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

  function addDetectedTests() {
    setTargetsText(activeTestArtifacts.slice(0, 32).map((artifact) => artifact.relative_path).join("\n"));
    if (activeTestArtifacts[0]) setRunner(frameworkRunner(activeTestArtifacts[0].framework));
  }

  async function createExecutionPlan() {
    if (!projectId) return;
    const targets = uniqueLines(targetsText);
    const executable = toolchainPath.trim();
    const version = toolchainVersion.trim();
    if (!targets.length) {
      setError("Select at least one explicit discovered test target.");
      return;
    }
    if (!executable || !version) {
      setError("Trusted runner executable path and version are required.");
      return;
    }
    let roots = uniqueLines(externalRootsText);
    const runnerParent = executableParent(executable);
    if (runnerParent && !roots.includes(runnerParent)) roots = [runnerParent, ...roots];
    if (!roots.length) {
      setError("At least the trusted runner/runtime root must be declared.");
      return;
    }

    setExecutionBusy(true);
    setError(null);
    try {
      await invoke<QaExecutionPlanRecord>("create_qa_execution_plan", {
        projectId,
        request: {
          runner,
          targets,
          discovery_run_id: summary?.run_id ?? history[0]?.run_id ?? null,
        },
        toolchain: {
          runner,
          executable_path: executable,
          version,
          sha256: null,
          trusted_by_user: true,
          declared_external_read_roots: roots.map((root, index) => ({
            kind: index === 0 ? "runtime_root" : "toolchain_support",
            path: root,
          })),
        },
        policy: defaultPolicy(targets.length),
      });
      await loadExecution(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function approvePlan(planId: string) {
    if (!projectId) return;
    setExecutionBusy(true);
    setError(null);
    try {
      await invoke<QaExecutionPlanRecord>("approve_qa_execution_plan", { planId });
      await loadExecution(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function executePlan(planId: string) {
    if (!projectId) return;
    setExecutionBusy(true);
    setError(null);
    try {
      await invoke<QaExecutionRunRecord>("run_qa_execution_plan", { planId });
      await loadExecution(projectId);
    } catch (value) {
      setError(String(value));
    } finally {
      setExecutionBusy(false);
    }
  }

  async function cancelExecution() {
    try {
      await invoke<boolean>("cancel_qa_execution");
    } catch (value) {
      setError(String(value));
    }
  }

  return (
    <main className="standalone-workspace">
      <header>
        <div>
          <p className="eyebrow">QA DISCOVERY + SANDBOXED EXECUTION</p>
          <h1>QA / Test Engine</h1>
          <p>Discover test evidence passively, then optionally run explicit approved targets inside the strict local sandbox. Discovery and execution remain separate evidence states.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}

      <section className="panel">
        <h2>Project</h2>
        <p>Index the repository first so QA evidence and any later execution are bound to the same Software Digital Twin identity.</p>
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
                <h2>1. Discovery scan</h2>
                <p>Reads bounded conventional test/config candidates only. It does not execute package scripts, tests, interpreters, compilers, browsers, hooks, or repository commands.</p>
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
            <p className="warning banner">Discovery alone never creates a pass/fail or coverage claim.</p>
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
                <h2>Discovery history</h2>
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

          <section className="panel">
            <div className="section-heading">
              <div>
                <h2>2. Strict sandboxed execution</h2>
                <p>Only explicit targets can run. The plan is immutable after creation, approval binds project/runtime hashes, and execution has no unsandboxed fallback.</p>
              </div>
              <strong>{availability?.execution_enabled ? "available" : "blocked on this platform"}</strong>
            </div>
            {availability && (
              <>
                <p>{availability.reason}</p>
                <div className="grid runtime-metrics">
                  <Metric label="backend" value={availability.backend_kind} />
                  <Metric label="process" value={availability.enforced_capabilities.process_isolation ? "isolated" : "blocked"} />
                  <Metric label="filesystem" value={availability.enforced_capabilities.filesystem_isolation ? "isolated" : "blocked"} />
                  <Metric label="network" value={availability.enforced_capabilities.network_isolation ? "denied" : "not enforced"} />
                  <Metric label="CPU / memory" value={availability.enforced_capabilities.cpu_limit && availability.enforced_capabilities.memory_limit ? "bounded" : "incomplete"} />
                  <Metric label="cancel" value={availability.enforced_capabilities.cancellation ? "enforced" : "unavailable"} />
                </div>
              </>
            )}

            <div className="ws-webscan-two">
              <label className="ws-field">
                <span>Runner</span>
                <select value={runner} onChange={(event) => setRunner(event.target.value as QaTestRunnerKind)}>
                  {RUNNER_OPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
              </label>
              <label className="ws-field">
                <span>Runner version</span>
                <input value={toolchainVersion} onChange={(event) => setToolchainVersion(event.target.value)} placeholder="e.g. Python 3.12 / Cargo 1.82" />
              </label>
            </div>
            <label className="ws-field">
              <span>Trusted runner executable</span>
              <input value={toolchainPath} onChange={(event) => setToolchainPath(event.target.value)} placeholder="Absolute path to pytest/python, cargo, go, vitest/jest runner, or phpunit" />
              <small>CodeTwin SHA-256 pins the executable during plan creation.</small>
            </label>
            <label className="ws-field">
              <span>Explicit test targets</span>
              <textarea rows={6} value={targetsText} onChange={(event) => setTargetsText(event.target.value)} placeholder="One project-relative test path per line" />
            </label>
            <button className="ws-button ws-button-secondary" onClick={addDetectedTests} disabled={!activeTestArtifacts.length || executionBusy}>
              Use discovered test files
            </button>
            <label className="ws-field">
              <span>Approved runtime/toolchain roots</span>
              <textarea rows={4} value={externalRootsText} onChange={(event) => setExternalRootsText(event.target.value)} placeholder="One absolute runtime/toolchain root per line" />
              <small>The runner parent is automatically included. Approval hashes the complete declared read surface before execution.</small>
            </label>
            <div className="row">
              <button onClick={() => void createExecutionPlan()} disabled={!availability?.execution_enabled || executionBusy}>
                {executionBusy ? "Working…" : "Create immutable execution plan"}
              </button>
              <button onClick={() => void cancelExecution()} disabled={!executionBusy}>Cancel active execution</button>
            </div>
          </section>

          <section className="runtime-layout">
            <div className="twin-column">
              <section className="panel compact">
                <h2>Execution plans</h2>
                <div className="history-list runtime-scroll-list">
                  {plans.map((plan) => (
                    <div className="history-item" key={plan.id}>
                      <div><strong>{plan.status}</strong><span>{plan.runner}</span></div>
                      <span>{plan.command.args.join(" ")}</span>
                      <small>{plan.blocking_reasons.length ? plan.blocking_reasons.join(" · ") : "strict capability floor satisfied"}</small>
                      {plan.status === "planned" && (
                        <button onClick={() => void approvePlan(plan.id)} disabled={executionBusy}>Approve exact hashes</button>
                      )}
                      {plan.status === "approved" && (
                        <button onClick={() => void executePlan(plan.id)} disabled={executionBusy}>Run in strict sandbox</button>
                      )}
                    </div>
                  ))}
                  {!plans.length && <p className="empty">No execution plans yet.</p>}
                </div>
              </section>
            </div>

            <div className="twin-column wide">
              <section className="panel compact">
                <h2>Execution evidence</h2>
                <div className="history-list runtime-scroll-list">
                  {runs.map((run) => (
                    <div className="history-item" key={run.id}>
                      <div>
                        <strong>{run.status}</strong>
                        <span>{run.tests_passed === true ? "tests passed" : run.tests_passed === false ? "tests failed" : "no test verdict"}</span>
                      </div>
                      <span>exit {run.exit_code ?? "n/a"} · parser {run.parser_completed ? "recognized" : "not proven"} · {run.duration_ms ?? 0} ms</span>
                      {run.stdout_excerpt && <pre>{run.stdout_excerpt}</pre>}
                      {run.stderr_excerpt && <pre>{run.stderr_excerpt}</pre>}
                      <small>
                        stdout {run.stdout_original_bytes} B{run.stdout_truncated ? " (truncated)" : ""} · stderr {run.stderr_original_bytes} B{run.stderr_truncated ? " (truncated)" : ""}
                      </small>
                    </div>
                  ))}
                  {!runs.length && <p className="empty">No sandboxed QA execution evidence exists for this project.</p>}
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
