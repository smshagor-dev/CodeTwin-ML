import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type {
  QaArtifactRecord,
  QaDiscoveryRunRecord,
  QaExecutionAvailability,
  QaExecutionPlanRecord,
  QaExecutionRunRecord,
  QaFrameworkSummary,
  QaSandboxPolicy,
  QaTestRunnerKind,
} from "../types";
import { EmptyState, PageHeader, Panel, ProjectSelect, StatusBadge, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

const strictPolicy: QaSandboxPolicy = {
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

function runnerForFramework(framework: string): QaTestRunnerKind {
  switch (framework.toLowerCase()) {
    case "pytest": return "pytest";
    case "cargo":
    case "rust":
    case "rust_cargo_test": return "rust_cargo_test";
    case "go":
    case "go_test": return "go_test";
    case "vitest": return "vitest";
    case "jest": return "jest";
    case "phpunit":
    case "php_unit": return "php_unit";
    default: return "pytest";
  }
}

export function TestingPage() {
  const { projects, activeProjectId, setActiveProjectId, operation, runQaDiscovery, setToast } = useWorkspace();
  const [artifacts, setArtifacts] = useState<QaArtifactRecord[]>([]);
  const [frameworks, setFrameworks] = useState<QaFrameworkSummary[]>([]);
  const [history, setHistory] = useState<QaDiscoveryRunRecord[]>([]);
  const [framework, setFramework] = useState("all");
  const [availability, setAvailability] = useState<QaExecutionAvailability | null>(null);
  const [plans, setPlans] = useState<QaExecutionPlanRecord[]>([]);
  const [runs, setRuns] = useState<QaExecutionRunRecord[]>([]);
  const [target, setTarget] = useState("");
  const [runner, setRunner] = useState<QaTestRunnerKind>("pytest");
  const [toolchainPath, setToolchainPath] = useState("");
  const [toolchainVersion, setToolchainVersion] = useState("");
  const [toolchainHash, setToolchainHash] = useState("");
  const [externalRoots, setExternalRoots] = useState("");
  const [qaBusy, setQaBusy] = useState<string | null>(null);

  async function load(projectId: string) {
    try {
      const [nextArtifacts, nextFrameworks, nextHistory, nextAvailability, nextPlans, nextRuns] = await Promise.all([
        workspaceApi.qaArtifacts(projectId, 500),
        workspaceApi.qaFrameworks(projectId),
        workspaceApi.qaHistory(projectId, 50),
        workspaceApi.qaExecutionAvailability(),
        workspaceApi.qaExecutionPlans(projectId, 50),
        workspaceApi.qaExecutionRuns(projectId, 50),
      ]);
      setArtifacts(nextArtifacts);
      setFrameworks(nextFrameworks);
      setHistory(nextHistory);
      setAvailability(nextAvailability);
      setPlans(nextPlans);
      setRuns(nextRuns);
      const firstTest = nextArtifacts.find((item) => item.artifact_kind === "test_file" && item.is_active);
      if (firstTest && !target) {
        setTarget(firstTest.relative_path);
        setRunner(runnerForFramework(firstTest.framework));
      }
    } catch (error) {
      setToast({ tone: "error", message: "Could not load QA evidence: " + String(error) });
    }
  }

  useEffect(() => {
    if (!activeProjectId) {
      setArtifacts([]);
      setFrameworks([]);
      setHistory([]);
      setPlans([]);
      setRuns([]);
      setAvailability(null);
      return;
    }
    void load(activeProjectId);
  }, [activeProjectId]);

  const visible = useMemo(
    () => framework === "all" ? artifacts : artifacts.filter((artifact) => artifact.framework === framework),
    [artifacts, framework],
  );

  const testArtifacts = useMemo(
    () => artifacts.filter((item) => item.artifact_kind === "test_file" && item.is_active),
    [artifacts],
  );

  async function pinToolchain() {
    if (!toolchainPath.trim()) return;
    setQaBusy("hash");
    try {
      setToolchainHash(await workspaceApi.qaToolchainSha256(toolchainPath.trim()));
    } catch (error) {
      setToast({ tone: "error", message: "Could not pin QA toolchain: " + String(error) });
    } finally {
      setQaBusy(null);
    }
  }

  async function createPlan() {
    if (!activeProjectId || !target || !toolchainPath.trim() || !toolchainVersion.trim() || !toolchainHash) {
      setToast({ tone: "error", message: "Choose a test target and provide a versioned, SHA-256-pinned trusted toolchain." });
      return;
    }
    setQaBusy("plan");
    try {
      const discoveryRunId = history.find((item) => item.status === "completed")?.run_id ?? null;
      await workspaceApi.createQaExecutionPlan(
        activeProjectId,
        { runner, targets: [target], discovery_run_id: discoveryRunId },
        {
          runner,
          executable_path: toolchainPath.trim(),
          version: toolchainVersion.trim(),
          sha256: toolchainHash,
          trusted_by_user: true,
          declared_external_read_roots: externalRoots
            .split("\n")
            .map((value) => value.trim())
            .filter(Boolean)
            .map((path) => ({ kind: "runtime_root" as const, path })),
        },
        strictPolicy,
      );
      await load(activeProjectId);
      setToast({ tone: "success", message: "QA execution plan created. Review and approve it before execution." });
    } catch (error) {
      setToast({ tone: "error", message: "Could not create QA execution plan: " + String(error) });
    } finally {
      setQaBusy(null);
    }
  }

  async function approvePlan(planId: string) {
    if (!activeProjectId) return;
    setQaBusy("approve:" + planId);
    try {
      await workspaceApi.approveQaExecutionPlan(planId);
      await load(activeProjectId);
      setToast({ tone: "success", message: "QA plan approved and bound to the current project/toolchain provenance." });
    } catch (error) {
      setToast({ tone: "error", message: "Could not approve QA plan: " + String(error) });
    } finally {
      setQaBusy(null);
    }
  }

  async function executePlan(planId: string) {
    if (!activeProjectId) return;
    setQaBusy("run:" + planId);
    try {
      await workspaceApi.runQaExecutionPlan(planId);
      await load(activeProjectId);
      setToast({ tone: "success", message: "Sandboxed QA execution finished. Review the persisted run evidence below." });
    } catch (error) {
      setToast({ tone: "error", message: "QA execution did not complete: " + String(error) });
      await load(activeProjectId);
    } finally {
      setQaBusy(null);
    }
  }

  if (!projects.length) {
    return <><PageHeader eyebrow="QA EVIDENCE" title="Testing" description="Discover test evidence and run explicitly approved tests only inside the strict sandbox."/><EmptyState icon="testing" title="No project selected" description="Add an indexed project before discovering QA evidence."/></>;
  }

  return (
    <div>
      <PageHeader
        eyebrow="QA / SANDBOX"
        title="Testing"
        description="Discover tests passively, then create an immutable execution plan. Test code runs only when the strict sandbox capability floor is available and the exact plan is explicitly approved."
        actions={<div className="ws-header-tools"><ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/><button className="ws-button ws-button-primary" onClick={() => void runQaDiscovery().then(() => activeProjectId && load(activeProjectId))} disabled={!activeProjectId || operation !== null}><Icon name="testing"/>{operation?.kind === "testing" ? "Discovering…" : "Discover Tests"}</button></div>}
      />

      <div className="ws-limitation-banner">
        <Icon name={availability?.execution_enabled ? "testing" : "warning"}/>
        <div>
          <strong>{availability?.execution_enabled ? "Strict QA sandbox available" : "QA execution blocked on this platform/backend"}</strong>
          <p>{availability?.reason ?? "Checking sandbox capability evidence…"}</p>
        </div>
      </div>

      <section className="ws-analysis-metrics">
        <div><span><Icon name="testing"/></span><strong>{testArtifacts.length}</strong><small>Test files</small></div>
        <div><span><Icon name="settings"/></span><strong>{artifacts.filter((item) => item.artifact_kind === "config_file").length}</strong><small>Config evidence</small></div>
        <div><span><Icon name="integrations"/></span><strong>{frameworks.length}</strong><small>Frameworks</small></div>
        <div><span><Icon name="activity"/></span><strong>{runs.length}</strong><small>Execution runs</small></div>
      </section>

      {activeProjectId && (
        <Panel title="Sandboxed test execution">
          <p className="ws-form-help">Execution is never inferred from discovery. Select one discovered test target, pin the exact trusted runner executable, create a plan, then approve that immutable plan. Network access and ambient host environment remain denied by the strict policy.</p>
          <div className="ws-webscan-two">
            <label className="ws-field">
              <span>Discovered test target</span>
              <select value={target} onChange={(event) => {
                const value = event.target.value;
                setTarget(value);
                const artifact = testArtifacts.find((item) => item.relative_path === value);
                if (artifact) setRunner(runnerForFramework(artifact.framework));
              }}>
                <option value="">Choose test</option>
                {testArtifacts.map((item) => <option key={item.id} value={item.relative_path}>{item.relative_path} — {item.framework}</option>)}
              </select>
            </label>
            <label className="ws-field">
              <span>Runner</span>
              <select value={runner} onChange={(event) => setRunner(event.target.value as QaTestRunnerKind)}>
                <option value="pytest">pytest</option>
                <option value="vitest">vitest</option>
                <option value="jest">jest</option>
                <option value="rust_cargo_test">cargo test</option>
                <option value="go_test">go test</option>
                <option value="php_unit">PHPUnit</option>
              </select>
            </label>
            <label className="ws-field">
              <span>Trusted runner executable</span>
              <input value={toolchainPath} onChange={(event) => { setToolchainPath(event.target.value); setToolchainHash(""); }} placeholder="Absolute path to pytest.exe / cargo.exe / go.exe / …"/>
            </label>
            <label className="ws-field">
              <span>Runner version</span>
              <input value={toolchainVersion} onChange={(event) => setToolchainVersion(event.target.value)} placeholder="e.g. 8.4.2"/>
            </label>
          </div>
          <label className="ws-field">
            <span>Approved external runtime read roots <small>optional, one absolute path per line</small></span>
            <textarea rows={3} value={externalRoots} onChange={(event) => setExternalRoots(event.target.value)} placeholder="Python stdlib/runtime or other required immutable runtime roots"/>
          </label>
          <div className="ws-header-tools">
            <button className="ws-button ws-button-secondary" onClick={() => void pinToolchain()} disabled={!toolchainPath.trim() || qaBusy !== null}>
              {qaBusy === "hash" ? "Hashing…" : "Pin SHA-256"}
            </button>
            <button className="ws-button ws-button-primary" onClick={() => void createPlan()} disabled={!availability?.execution_enabled || qaBusy !== null || !target || !toolchainHash}>
              {qaBusy === "plan" ? "Creating…" : "Create strict plan"}
            </button>
          </div>
          {toolchainHash && <p className="mono">Runner SHA-256: {toolchainHash}</p>}

          <div className="ws-history-list">
            {plans.map((plan) => (
              <div key={plan.id}>
                <StatusBadge status={plan.status}/>
                <p>
                  <strong>{plan.runner} · {plan.request.targets.join(", ")}</strong>
                  <small>{plan.blocking_reasons.length ? plan.blocking_reasons.join(" · ") : "Strict capability floor satisfied"}</small>
                </p>
                <div className="ws-header-tools">
                  {plan.status === "planned" && <button className="ws-button ws-button-secondary" onClick={() => void approvePlan(plan.id)} disabled={qaBusy !== null}>Approve exact plan</button>}
                  {plan.status === "approved" && <button className="ws-button ws-button-primary" onClick={() => void executePlan(plan.id)} disabled={qaBusy !== null || !availability?.execution_enabled}>Run in sandbox</button>}
                </div>
              </div>
            ))}
            {!plans.length && <p className="ws-inline-empty">No QA execution plan has been created for this project.</p>}
          </div>
        </Panel>
      )}

      <div className="ws-security-layout">
        <Panel title="Discovered QA evidence" action={<select aria-label="Filter QA framework" value={framework} onChange={(event) => setFramework(event.target.value)}><option value="all">All frameworks</option>{frameworks.map((item) => <option key={item.framework} value={item.framework}>{item.framework}</option>)}</select>}>
          <div className="ws-artifact-list">
            {visible.map((artifact) => <div key={artifact.id}><Icon name={artifact.artifact_kind === "test_file" ? "testing" : "settings"} size={18}/><p><strong>{artifact.relative_path}</strong><small>{artifact.framework} · {artifact.evidence_kind}</small></p><StatusBadge status={artifact.is_active ? "active" : "inactive"}/></div>)}
            {!visible.length && <p className="ws-inline-empty">No QA artifacts have been discovered for this filter.</p>}
          </div>
        </Panel>
        <Panel title="Execution history">
          <div className="ws-history-list">
            {runs.map((run) => <div key={run.id}><StatusBadge status={run.status}/><p><strong>{run.tests_passed === true ? "Tests passed" : run.tests_passed === false ? "Tests failed" : "No parsed test verdict"}</strong><small>exit {run.exit_code ?? "n/a"} · {run.duration_ms ?? 0} ms · {run.parser_completed ? "parser complete" : "raw execution evidence only"}</small></p><time>{formatDate(run.finished_at ?? run.started_at)}</time></div>)}
            {!runs.length && <p className="ws-inline-empty">No sandboxed QA execution run yet.</p>}
          </div>
        </Panel>
      </div>

      <Panel title="Discovery history">
        <div className="ws-history-list">
          {history.map((run) => <div key={run.run_id}><StatusBadge status={run.status}/><p><strong>{run.artifacts_discovered} artifacts discovered</strong><small>{run.test_files} tests · {run.config_files} configs · {run.framework_count} frameworks</small></p><time>{formatDate(run.finished_at ?? run.started_at)}</time></div>)}
          {!history.length && <p className="ws-inline-empty">No QA discovery runs yet.</p>}
        </div>
      </Panel>
    </div>
  );
}
