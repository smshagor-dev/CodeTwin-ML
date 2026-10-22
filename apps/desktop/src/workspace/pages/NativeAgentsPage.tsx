import { useCallback, useEffect, useState } from "react";

import { workspaceApi } from "../api";
import { useWorkspace } from "../WorkspaceContext";
import { PageHeader, Panel, ProjectSelect, StatusBadge } from "../ui";

const roleChoices = [
  { id: "scout", name: "Project Recon", mandatory: true },
  { id: "source", name: "Source Auditor", mandatory: true },
  { id: "secrets", name: "Secrets Auditor", mandatory: false },
  { id: "qa", name: "Test Researcher", mandatory: false },
  { id: "database", name: "Database Reviewer", mandatory: false },
  { id: "runtime", name: "Runtime Reviewer", mandatory: false },
] as const;

export type NativeTaskProposal = {
  tasks: { role: string; objective: string; depends_on: string[] }[];
  rationale: string;
};

export type NativeAgentStep = {
  position: number;
  role: string;
  tool: string;
  status: string;
  result: string | null;
};
export type NativeAgentRun = {
  id: string;
  project_id: string;
  objective: string;
  status: string;
  message: string | null;
  max_files: number;
  budget_seconds: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  steps: NativeAgentStep[];
};

export type NativeAgentMemory = {
  project_id: string;
  run_id: string;
  position: number;
  role: string;
  tool: string;
  status: string;
  created_at: string;
};

export type AgentHandoff = {
  run_id: string;
  from_position: number;
  to_position: number;
  from_role: string;
  to_role: string;
  evidence_sha256: string;
  created_at: string;
};

export type AgentVerification = {
  run_id: string;
  verified: boolean;
  checked_roles: number;
  checked_handoffs: number;
  issues: string[];
};

export type DelegationGraph = {
  run_id: string;
  tasks: { position: number; role: string; tool: string; status: string; requires: number[] }[];
};
export type KnowledgeNode = {
  run_id: string; position: number; role: string; tool: string; status: string; score: number;
};
export type KnowledgeGraph = {
  project_id: string;
  nodes: KnowledgeNode[];
  edges: { run_id: string; from_position: number; to_position: number; relation: string }[];
};
export type WorkerAuditRecord = {
  id: number; run_id: string; status: string; image_digest: string | null;
  report_sha256: string | null; vulnerability_count: number | null;
  misconfiguration_count: number | null; error_code: string | null;
  started_at: string; finished_at: string | null;
};
export type NeuralMatch = { run_id: string; position: number; role: string; status: string; score: number };
export type GraphInference = {
  run_id: string; selected_position: number; ancestors: number[];
  downstream_dependents: number[]; shortest_paths: number[][];
  reachable_nodes: number; orphaned_nodes: number[]; cycles_detected: boolean;
};

export type IsolatedScanReceipt = {
  run_id: string; image_digest: string; report_sha256: string;
  vulnerability_count: number; misconfiguration_count: number;
  runtime_seconds: number; warnings: string[];
};

export function NativeAgentsPage() {
  const { projects, activeProjectId, setActiveProjectId } = useWorkspace();
  const [runs, setRuns] = useState<NativeAgentRun[]>([]);
  const [memory, setMemory] = useState<NativeAgentMemory[]>([]);
  const [memoryQuery, setMemoryQuery] = useState("");
  const [knowledgeQuery, setKnowledgeQuery] = useState("");
  const [knowledgeMatches, setKnowledgeMatches] = useState<KnowledgeNode[]>([]);
  const [knowledgeGraph, setKnowledgeGraph] = useState<KnowledgeGraph | null>(null);
  const [delegation, setDelegation] = useState<DelegationGraph | null>(null);
  const [workerStatus, setWorkerStatus] = useState<{ configured: boolean; detail: string } | null>(null);
  const [workerConsent, setWorkerConsent] = useState(false);
  const [workerReceipt, setWorkerReceipt] = useState<IsolatedScanReceipt | null>(null);
  const [workerHistory, setWorkerHistory] = useState<WorkerAuditRecord[]>([]);
  const [neuralReady, setNeuralReady] = useState<{ configured: boolean; detail: string } | null>(null);
  const [neuralConsent, setNeuralConsent] = useState(false);
  const [neuralHits, setNeuralHits] = useState<NeuralMatch[]>([]);
  const [neuralQuery, setNeuralQuery] = useState("");
  const [graphInference, setGraphInference] = useState<GraphInference | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [handoffs, setHandoffs] = useState<AgentHandoff[]>([]);
  const [verification, setVerification] = useState<AgentVerification | null>(null);
  const [objective, setObjective] = useState("Review the selected project's security, code quality and reliability. Report confirmed evidence and unresolved issues.");
  const [maxFiles, setMaxFiles] = useState(500);
  const [budget, setBudget] = useState(600);
  const [selectedRoles, setSelectedRoles] = useState<string[]>(roleChoices.map(role => role.id));
  const [taskProposal, setTaskProposal] = useState<{
    proposal: NativeTaskProposal; objective: string; projectId: string;
  } | null>(null);
  const [taskSchedule, setTaskSchedule] = useState<{ batches: string[][]; max_parallel: number } | null>(null);
  const [acceptedTaskPlan, setAcceptedTaskPlan] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [modelStatus, setModelStatus] = useState<{ configured: boolean; detail: string } | null>(null);
  const [insight, setInsight] = useState<{ content: string; created_at: string } | null>(null);
  const [modelConsent, setModelConsent] = useState(false);
  const [planConsent, setPlanConsent] = useState(false);
  const [suggestion, setSuggestion] = useState<{
    roles: string[];
    rationale: string;
    objective: string;
    projectId: string;
  } | null>(null);

  useEffect(() => {
    void workspaceApi.nativeModelReadiness().then(setModelStatus)
      .catch(reason => setError(String(reason)));
    void workspaceApi.nativeIsolatedScanReadiness().then(setWorkerStatus)
      .catch(reason => setError(String(reason)));
    void workspaceApi.nativeNeuralReadiness().then(setNeuralReady)
      .catch(reason => setError(String(reason)));
  }, []);

  const refresh = useCallback(async () => {
    if (!activeProjectId) {
      setRuns([]);
      setMemory([]);
      return;
    }
    const [reviews, remembered] = await Promise.all([
      workspaceApi.listNativeAgentReviews(activeProjectId),
      workspaceApi.listNativeAgentMemory(activeProjectId, memoryQuery, 50),
    ]);
    setRuns(reviews);
    setMemory(remembered);
  }, [activeProjectId, memoryQuery]);

  useEffect(() => {
    void refresh().catch(reason => setError(String(reason)));
    const timer = window.setInterval(() => {
      void refresh().catch(reason => setError(String(reason)));
    }, 3500);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    const id = selectedId || runs[0]?.id;
    if (!id) { setInsight(null); return; }
    let active = true;
    void workspaceApi.nativeAgentInsight(id)
      .then(value => { if (active) setInsight(value); })
      .catch(reason => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [selectedId, runs]);

  useEffect(() => {
    const id = selectedId || runs[0]?.id;
    if (!id) { setHandoffs([]); setVerification(null); return; }
    let active = true;
    void Promise.all([workspaceApi.nativeAgentHandoffs(id), workspaceApi.verifyNativeAgentRun(id)])
      .then(([edges, result]) => {
        if (active) {
          setHandoffs(edges);
          setVerification(result);
        }
      })
      .catch(reason => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [selectedId, runs]);

  useEffect(() => {
    const id = selectedId || runs[0]?.id;
    if (!activeProjectId || !id) {
      setKnowledgeGraph(null);
      setDelegation(null);
      return;
    }
    let active = true;
    void Promise.all([
      workspaceApi.nativeDelegationGraph(id),
      workspaceApi.nativeKnowledgeGraph(activeProjectId, id),
      workspaceApi.nativeTaskSchedule(id),
      workspaceApi.nativeWorkerAudit(id),
    ]).then(([tasks, graph, schedule, history]) => {
      if (active) {
        setDelegation(tasks);
        setKnowledgeGraph(graph);
        setTaskSchedule(schedule);
        setWorkerHistory(history);
      }
    }).catch(reason => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [activeProjectId, selectedId, runs]);

  async function searchKnowledge() {
    if (!activeProjectId) return;
    setError("");
    try {
      setKnowledgeMatches(await workspaceApi.searchNativeKnowledge(activeProjectId, knowledgeQuery, 12));
    } catch (reason) { setError(String(reason)); }
  }

  async function clearKnowledge() {
    if (!activeProjectId || !window.confirm("Delete the derived vector and graph memory for this project? Review evidence will remain.")) return;
    setBusy("knowledge"); setError("");
    try {
      await workspaceApi.clearNativeKnowledge(activeProjectId);
      setKnowledgeMatches([]);
      setKnowledgeGraph(null);
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function indexNeural(id: string) {
    if (!neuralConsent) return;
    setBusy("embedding"); setError("");
    try {
      const count = await workspaceApi.indexNativeNeuralMemory(id, true);
      setNeuralConsent(false);
      setError("Indexed " + count + " privacy-reduced specialist vectors.");
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function searchNeural() {
    if (!activeProjectId || !neuralConsent) return;
    setBusy("neural-search"); setError("");
    try {
      setNeuralHits(await workspaceApi.searchNativeNeuralMemory(activeProjectId, neuralQuery, 12, true));
      setNeuralConsent(false);
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function reasonGraph(id: string, position: number) {
    if (!activeProjectId) return;
    setError("");
    try { setGraphInference(await workspaceApi.reasonNativeKnowledgeGraph(activeProjectId, id, position)); }
    catch (reason) { setError(String(reason)); }
  }

  async function runWorker(id: string) {
    if (!workerConsent || !window.confirm("Run an offline, read-only Docker security scan of this approved local project?")) return;
    setBusy("worker"); setError("");
    setWorkerReceipt(null);
    try {
      const receipt = await workspaceApi.runNativeIsolatedScan(id, true);
      setWorkerReceipt(receipt);
      setWorkerHistory(await workspaceApi.nativeWorkerAudit(id));
      setWorkerConsent(false);
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function interpret(id: string) {
    if (!modelConsent) return;
    setBusy("reason"); setError("");
    try {
      const value = await workspaceApi.interpretNativeAgentReview(id, true);
      setInsight(value);
      setModelConsent(false);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  async function suggestRoles() {
    if (!activeProjectId || !planConsent || !objective.trim()) return;
    setBusy("suggest"); setError("");
    setSuggestion(null);
    const requestedProjectId = activeProjectId;
    const requestedObjective = objective;
    try {
      const result = await workspaceApi.suggestNativeAgentRoles(requestedProjectId, requestedObjective, true);
      setSuggestion({
        roles: result.roles,
        rationale: result.rationale,
        objective: requestedObjective,
        projectId: requestedProjectId,
      });
      setPlanConsent(false);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  async function suggestDecomposition() {
    if (!activeProjectId || !planConsent || !objective.trim()) return;
    setBusy("decompose"); setError("");
    const requestedProjectId = activeProjectId;
    const requestedObjective = objective;
    setTaskProposal(null);
    setAcceptedTaskPlan(false);
    try {
      const proposal = await workspaceApi.suggestNativeTaskPlan(requestedProjectId, requestedObjective, true);
      setTaskProposal({proposal, projectId: requestedProjectId, objective: requestedObjective});
      setPlanConsent(false);
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function createPlan() {
    if (!activeProjectId) return;
    setError(""); setBusy("plan");
    try {
      const selectedPlan = acceptedTaskPlan && taskProposal?.objective === objective && taskProposal?.projectId === activeProjectId
        ? taskProposal.proposal : null;
      const run = selectedPlan
        ? await workspaceApi.createNativeTaskReview(activeProjectId, objective, maxFiles, budget, selectedPlan)
        : await workspaceApi.createNativeAgentReview(activeProjectId, objective, maxFiles, budget, selectedRoles);
      setTaskProposal(null);
      setAcceptedTaskPlan(false);
      setSelectedId(run.id);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  async function approve(id: string) {
    if (!window.confirm("Approve the selected passive analyzers for this indexed project? No external commands or active network probes will run.")) return;
    setBusy("approve"); setError("");
    try {
      await workspaceApi.approveNativeAgentReview(id);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  function execute(id: string) {
    setBusy("run"); setError("");
    void workspaceApi.runNativeAgentReview(id)
      .then(() => refresh())
      .catch(reason => setError(String(reason)))
      .finally(() => setBusy(""));
  }

  async function cancel(id: string) {
    setError("");
    try {
      await workspaceApi.cancelNativeAgentReview(id);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function clearMemory() {
    if (!activeProjectId) return;
    if (!window.confirm("Forget the saved agent-role summaries for this project? Original review history will remain.")) return;
    setBusy("memory"); setError("");
    try {
      await workspaceApi.clearNativeAgentMemory(activeProjectId);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy("");
    }
  }

  async function copyReport(id: string) {
    try {
      const text = await workspaceApi.nativeAgentReport(id);
      await navigator.clipboard.writeText(text);
    } catch (reason) {
      setError("Could not copy report: " + String(reason));
    }
  }

  const selected = runs.find(run => run.id === selectedId) ?? runs[0];
  return <div>
    <PageHeader
      eyebrow="LOCAL SECURITY AUTOMATION"
      title="CodeTwin Agents"
      description="Rust-native supervised review of your indexed source, application security, QA evidence and runtime configuration. Runs are persisted locally."
      actions={<button className="ws-button ws-button-secondary" onClick={() => void refresh().catch(reason => setError(String(reason)))}>Refresh</button>}
    />
    <Panel title="Create a supervised review">
      <div className="ws-form-stack">
        <ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/>
        <label className="ws-field"><span>Review objective</span>
          <textarea value={objective} maxLength={2000} rows={3} onChange={event => setObjective(event.target.value)}/>
        </label>
        <label className="ws-field"><span>Maximum indexed files (1–2000)</span>
          <input type="number" min={1} max={2000} value={maxFiles} onChange={event => setMaxFiles(Number(event.target.value))}/>
        </label>
        <label className="ws-field"><span>Review time budget in seconds (1–3600)</span>
          <input type="number" min={1} max={3600} value={budget} onChange={event => setBudget(Number(event.target.value))}/>
        </label>
        <fieldset className="ws-form-stack">
          <legend>AI-suggested review roles</legend>
          <p className="ws-form-help">
            The configured model receives your objective, aggregate index counts and at most 12 prior specialist role/status pairs; never source files, project paths, report contents or verified findings. Suggestions cannot run tools or approve plans.
          </p>
          <label className="ws-field"><span>
            <input type="checkbox" checked={planConsent} disabled={!modelStatus?.configured || Boolean(busy)}
              onChange={event => setPlanConsent(event.target.checked)}/>
            I consent to up to two model requests using this objective, aggregate index counts and up to 12 earlier role/status pairs (a second request is only used to correct invalid JSON).
          </span></label>
          <button className="ws-button ws-button-secondary"
            disabled={!modelStatus?.configured || !activeProjectId || !planConsent || !objective.trim() || Boolean(busy)}
            onClick={() => void suggestRoles()}>
            {busy === "suggest" ? "Generating suggestion…" : "Suggest specialist roles"}
          </button>
          <button className="ws-button ws-button-secondary"
            disabled={!modelStatus?.configured || !activeProjectId || !planConsent || !objective.trim() || Boolean(busy)}
            onClick={() => void suggestDecomposition()}>
            {busy === "decompose" ? "Decomposing…" : "Propose multi-step task graph"}
          </button>
          {taskProposal && taskProposal.objective === objective && taskProposal.projectId === activeProjectId && <div>
            <p><strong>Model-proposed task DAG (not approved)</strong></p>
            {taskProposal.proposal.tasks.map(task => <p key={task.role}>
              <strong>{task.role}</strong> · {task.objective} · depends on {task.depends_on.join(", ") || "none"}
            </p>)}
            <p>{taskProposal.proposal.rationale}</p>
            <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
              onClick={() => {
                setSelectedRoles(taskProposal.proposal.tasks.map(task => task.role));
                setAcceptedTaskPlan(true);
              }}>
              Use this reviewed task plan
            </button>
          </div>}
          {suggestion && suggestion.objective === objective && suggestion.projectId === activeProjectId && <div>
            <p><strong>Proposed roles:</strong> {suggestion.roles.map(role =>
              roleChoices.find(choice => choice.id === role)?.name ?? role).join(", ")}</p>
            <p>{suggestion.rationale}</p>
            <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
              onClick={() => { setSelectedRoles(suggestion.roles); setSuggestion(null); }}>
              Use suggested roles (review before approval)
            </button>
          </div>}
        </fieldset>
        <fieldset className="ws-form-stack">
          <legend>Approved specialist roles</legend>
          {roleChoices.map(role => <label className="ws-field" key={role.id}>
            <span><input type="checkbox" checked={selectedRoles.includes(role.id)}
              disabled={role.mandatory || Boolean(busy)}
              onChange={event => setSelectedRoles(current =>
                event.target.checked ? [...current, role.id] : current.filter(id => id !== role.id))}/>
              {role.name}{role.mandatory ? " (required)" : ""}
            </span>
          </label>)}
        </fieldset>
        <p className="ws-form-help">
          The planner uses the existing CodeTwin passive analyzers. It checks source hashes before the source-audit step, requires explicit approval and never runs generated shell commands or unapproved website attacks.
        </p>
        <button className="ws-button ws-button-primary" disabled={!activeProjectId || Boolean(busy) || !objective.trim()} onClick={() => void createPlan()}>
          {busy === "plan" ? "Preparing…" : "Prepare review"}
        </button>
        {error && <p className="ws-warning-box" role="alert">{error}</p>}
      </div>
    </Panel>

    <Panel title="Project review memory">
      <p className="ws-form-help">Previous completed or failed specialist-role states, indexed by project and original review. Source text, secrets, tool output and AI responses are not copied into this memory.</p>
      <div className="ws-tool-filters">
        <label className="ws-field"><span>Search past roles or statuses</span>
          <input value={memoryQuery} maxLength={120} placeholder="Recon, source, completed…" onChange={event => setMemoryQuery(event.target.value)}/>
        </label>
        <button className="ws-button ws-button-secondary" disabled={!activeProjectId || Boolean(busy)} onClick={() => void clearMemory()}>Clear project memory</button>
      </div>
      {!memory.length && <p className="ws-inline-empty">No remembered role outcomes in this project.</p>}
      <div className="ws-history-list">{memory.map(item =>
        <button key={item.run_id + ":" + item.position} className="ws-button ws-button-secondary" title={"Original review: " + item.run_id}
          onClick={() => setSelectedId(item.run_id)}>
          {item.role} · {item.status} · {item.created_at}
        </button>
      )}</div>
    </Panel>

    <Panel title="Local vector and knowledge-graph memory">
      <p className="ws-form-help">Local lexical vectors, not neural embeddings. Only role, tool and status provenance is indexed; source code and scan output are never copied here.</p>
      <label className="ws-field"><span>Search prior specialist outcomes</span>
        <input value={knowledgeQuery} maxLength={120} onChange={event => setKnowledgeQuery(event.target.value)}
          placeholder="source secrets database runtime"/>
      </label>
      <div className="ws-top-actions">
        <button className="ws-button ws-button-secondary" disabled={!activeProjectId || Boolean(busy)}
          onClick={() => void searchKnowledge()}>Search local vectors</button>
        <button className="ws-button ws-button-secondary" disabled={!activeProjectId || Boolean(busy)}
          onClick={() => void clearKnowledge()}>Clear derived knowledge</button>
      </div>
      {knowledgeMatches.map(node => <button key={node.run_id + ":" + node.position}
        className="ws-button ws-button-secondary" onClick={() => setSelectedId(node.run_id)}>
        {node.role} · {node.status} · similarity {node.score.toFixed(2)}
      </button>)}
    </Panel>

    <Panel title="Neural embedding memory (optional)">
      <p className="ws-form-help">
        {neuralReady?.detail ?? "Checking model connection…"}.
        Genuine model embeddings require an explicitly configured provider and user consent.
        Only role, tool and status are embedded, never local files or scanner results.
      </p>
      <label className="ws-field"><span>Neural similarity query</span>
        <input value={neuralQuery} maxLength={150} placeholder="Find past source review activity"
          onChange={event => setNeuralQuery(event.target.value)}/>
      </label>
      <label className="ws-field"><span>
        <input type="checkbox" checked={neuralConsent} onChange={event => setNeuralConsent(event.target.checked)}/>
        I consent to sending short specialist provenance or this query to my configured embedding provider.
      </span></label>
      <button className="ws-button ws-button-secondary"
        disabled={!neuralReady?.configured || !neuralConsent || !neuralQuery.trim() || !activeProjectId || Boolean(busy)}
        onClick={() => void searchNeural()}>Search neural memory</button>
      {neuralHits.map(hit => <button className="ws-button ws-button-secondary" key={hit.run_id + ":" + hit.position}
        onClick={() => setSelectedId(hit.run_id)}>{hit.role} · cosine similarity {hit.score.toFixed(2)}</button>)}
    </Panel>

    <Panel title="Saved reviews">
      {!runs.length && <p className="ws-inline-empty">Choose an indexed project to create your first local review.</p>}
      <div className="ws-history-list">{runs.map(run =>
        <button className="ws-button ws-button-secondary" key={run.id} aria-pressed={selected?.id === run.id}
          onClick={() => setSelectedId(run.id)}>
          {run.objective.slice(0, 60)} · {run.status}
        </button>
      )}</div>
    </Panel>

    {selected && <Panel title="Review execution">
      <p><StatusBadge status={selected.status}/> <strong>{selected.objective}</strong></p>
      <p className="ws-form-help">Bounded to {selected.max_files} indexed files and {selected.budget_seconds} seconds at analyzer boundaries. Agents never bypass CodeTwin's existing security approval rules.</p>
      <div className="ws-history-list">
        {selected.steps.map(step => <details key={step.position}>
          <summary><strong>{step.role}</strong> · {step.status}</summary>
          <p className="ws-form-help">{step.tool}</p>
          <pre className="ws-diagnostics">{step.result ?? "No execution evidence yet"}</pre>
        </details>)}
      </div>
      {selected.message && <p className="ws-warning-box">{selected.message}</p>}
      <section>
        <h3>Approved delegation tasks</h3>
        <p className="ws-form-help">Dependencies are verified in Rust before each registered specialist runs.</p>
        {delegation?.tasks.map(task => <p key={task.position}>
          <strong>{task.role}</strong> · {task.status}
          {task.requires.length ? " · requires " + task.requires.join(", ") : " · initial task"}
        </p>)}
        <h3>Dependency-ready scheduling batches</h3>
        <p className="ws-form-help">These are parallel-ready groups for planning. Existing analyzer execution is still serialized for database safety.</p>
        {taskSchedule?.batches.map((batch, index) => <p key={index}>
          Group {index + 1}: {batch.join(", ")}
        </p>)}
        <h3>Stored knowledge graph</h3>
        {knowledgeGraph?.nodes.map(node => <button key={node.run_id + ":" + node.position}
          className="ws-button ws-button-secondary"
          onClick={() => void reasonGraph(selected.id, node.position)}>
          Explain {node.role} dependencies
        </button>)}
        {graphInference && graphInference.run_id === selected.id && <p className="ws-form-help">
          Role {graphInference.selected_position}: {graphInference.ancestors.length} ancestors,
          {" "}{graphInference.downstream_dependents.length} downstream roles,
          {" "}{graphInference.reachable_nodes} reachable nodes.
          {graphInference.cycles_detected ? " A graph cycle was detected." : ""}
        </p>}
        <p className="ws-form-help">
          {knowledgeGraph?.nodes.length ?? 0} local evidence nodes · {knowledgeGraph?.edges.length ?? 0} verified handoff relations.
        </p>
      </section>
      <section>
        <h3>Specialist handoffs and verification</h3>
        <p className="ws-form-help">
          Each specialist passes only a SHA-256 evidence fingerprint and approved role identity to the next specialist.
          The supervisor stops when a predecessor or its evidence does not validate.
        </p>
        {verification && <p role="status">
          <strong>{verification.verified ? "Evidence chain verified" : "Evidence chain not yet verified"}</strong>
          {" · "}{verification.checked_roles} specialists, {verification.checked_handoffs} verified handoffs.
        </p>}
        {verification?.issues.map((issue, index) =>
          <p className="ws-warning-box" key={index}>{issue}</p>)}
        <div className="ws-history-list">{handoffs.map(edge =>
          <details key={edge.from_position + ":" + edge.to_position}>
            <summary>{edge.from_role} → {edge.to_role}</summary>
            <p className="ws-form-help">SHA-256: <code>{edge.evidence_sha256}</code></p>
            <p className="ws-form-help">Recorded: {edge.created_at}</p>
          </details>
        )}</div>
      </section>
      <div className="ws-form-stack">
        <h3>Optional model interpretation</h3>
        <p className="ws-form-help">{modelStatus?.detail ?? "Checking model configuration…"}. This does not create validated findings or control tools.</p>
        {insight ? <div><p><strong>Unverified AI interpretation</strong> · {insight.created_at}</p><pre className="ws-diagnostics">{insight.content}</pre></div>
        : <>
          <label className="ws-field"><span><input type="checkbox" checked={modelConsent} onChange={event => setModelConsent(event.target.checked)}/>
          I approve sending up to 9,000 characters of this local review report to my configured model endpoint for interpretation.</span></label>
          <button className="ws-button ws-button-secondary" disabled={!modelStatus?.configured || !modelConsent || Boolean(busy) ||
            !["completed","failed","cancelled","interrupted"].includes(selected.status)}
            onClick={() => void interpret(selected.id)}>{busy === "reason" ? "Analyzing…" : "Generate AI interpretation"}</button>
        </>}
      </div>
      <section className="ws-form-stack">
        <h3>Opt-in neural indexing</h3>
        <p className="ws-form-help">No embedding call is automatic. Index only trusted role/status summaries from this finished review.</p>
        <button className="ws-button ws-button-secondary"
          disabled={!neuralReady?.configured || !neuralConsent || Boolean(busy) ||
            !["completed","failed","cancelled","interrupted"].includes(selected.status)}
          onClick={() => void indexNeural(selected.id)}>Index this review with neural embeddings</button>
      </section>
      <section className="ws-form-stack">
        <h3>Optional isolated security worker</h3>
        <p className="ws-form-help">{workerStatus?.detail ?? "Checking Docker worker configuration…"}</p>
        <p className="ws-form-help">Pinned Trivy image only · local Docker · no network · read-only source mount · fixed arguments · resource/time ceilings. Never launches arbitrary commands.</p>
        <label className="ws-field"><span>
          <input type="checkbox" checked={workerConsent} onChange={event => setWorkerConsent(event.target.checked)}/>
          I explicitly authorize an offline security scan of the selected project in Docker.
        </span></label>
        <button className="ws-button ws-button-secondary"
          disabled={!workerConsent || !workerStatus?.configured || selected.status !== "approved" || Boolean(busy)}
          onClick={() => void runWorker(selected.id)}>
          {busy === "worker" ? "Running isolated scan…" : "Run approved offline scanner"}
        </button>
        <h3>Persistent worker audit</h3>
        {!workerHistory.length && <p className="ws-form-help">No recorded worker attempts for this review.</p>}
        {workerHistory.map(event => <p className="ws-form-help" key={event.id}>
          Attempt {event.id} · {event.status} · {event.started_at}
          {event.report_sha256 ? " · evidence " + event.report_sha256.slice(0, 12) : ""}
        </p>)}
        {workerReceipt && <p role="status">
          Offline scan finished · {workerReceipt.vulnerability_count} vulnerability records,
          {" "}{workerReceipt.misconfiguration_count} misconfiguration records.
          Evidence SHA-256: <code>{workerReceipt.report_sha256}</code>
        </p>}
      </section>
      <div className="ws-top-actions">
        {selected.status === "planned" && <button className="ws-button ws-button-primary" disabled={Boolean(busy)} onClick={() => void approve(selected.id)}>Approve plan</button>}
        {selected.status === "approved" && <button className="ws-button ws-button-primary" disabled={Boolean(busy)} onClick={() => execute(selected.id)}>Run approved review</button>}
        {["planned", "approved", "running"].includes(selected.status) && <button className="ws-button ws-button-secondary" onClick={() => void cancel(selected.id)}>Cancel</button>}
        <button className="ws-button ws-button-secondary" onClick={() => void copyReport(selected.id)}>Copy evidence report</button>
      </div>
    </Panel>}
  </div>;
}
