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

export type AutomatedSecurityFlow = {
  review_id: string;
  project_id: string;
  objective: string;
  mode: string;
  status: string;
  created_at: string;
  approved_at: string | null;
  completed_subtasks: number;
  total_subtasks: number;
  tasks: {
    title: string;
    subtasks: {
      position: number;
      role: string;
      status: string;
      requires: number[];
      actions: {
        position: number;
        role: string;
        status: string;
        result_sha256: string | null;
        started_at: string;
        finished_at: string | null;
      }[];
    }[];
  }[];
};

export type ApprovedFlowQueueItem = {
  id: number;
  review_id: string;
  project_id: string;
  status: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  detail: string;
  completed_steps: number;
  total_steps: number;
  active_role: string | null;
  active_roles: string[];
  review_status: string;
  issue_role: string | null;
  issue_status: string | null;
};

export type AdaptiveFlowFollowup = {
  review_id: string;
  proposal: NativeTaskProposal;
  created_at: string;
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

export type HistoricalEvidenceAudit = {
  project_id: string;
  total_completed: number;
  checked: number;
  verified: number;
  invalid: { review_id: string; issues: string[] }[];
  next_before_rowid: string | null;
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
  const [cleanupHolds, setCleanupHolds] = useState<number | null>(null);
  const [neuralReady, setNeuralReady] = useState<{ configured: boolean; detail: string } | null>(null);
  const [neuralProbe, setNeuralProbe] = useState<{ model: string; dimensions: number; latency_ms: number; normalized: boolean } | null>(null);
  const [neuralConsent, setNeuralConsent] = useState(false);
  const [neuralHits, setNeuralHits] = useState<NeuralMatch[]>([]);
  const [neuralQuery, setNeuralQuery] = useState("");
  const [graphInference, setGraphInference] = useState<GraphInference | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [automatedFlow, setAutomatedFlow] = useState<AutomatedSecurityFlow | null>(null);
  const [flowQueue, setFlowQueue] = useState<ApprovedFlowQueueItem[]>([]);
  const [adaptiveFollowup, setAdaptiveFollowup] = useState<AdaptiveFlowFollowup | null>(null);
  const [handoffs, setHandoffs] = useState<AgentHandoff[]>([]);
  const [verification, setVerification] = useState<AgentVerification | null>(null);
  const [historyAudit, setHistoryAudit] = useState<HistoricalEvidenceAudit | null>(null);
  const [objective, setObjective] = useState("Review the selected project's security, code quality and reliability. Report confirmed evidence and unresolved issues.");
  const [maxFiles, setMaxFiles] = useState(500);
  const [budget, setBudget] = useState(600);
  const [selectedRoles, setSelectedRoles] = useState<string[]>(roleChoices.map(role => role.id));
  const [taskProposal, setTaskProposal] = useState<{
    proposal: NativeTaskProposal; objective: string; projectId: string;
  } | null>(null);
  const [taskSchedule, setTaskSchedule] = useState<{ batches: string[][]; max_parallel: number } | null>(null);
  const [acceptedTaskPlan, setAcceptedTaskPlan] = useState(false);
  const [refineRole, setRefineRole] = useState("qa");
  const [refineObjective, setRefineObjective] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [actionReceipts, setActionReceipts] = useState<{
    reviewId: string;
    records: { position: number; role: string; status: string;
      result_sha256: string | null; started_at: string; finished_at: string | null }[];
  } | null>(null);
  const [goDispatchAudit, setGoDispatchAudit] = useState<{
    reviewId: string;
    records: { id: number; position: number; role: string; verdict: string;
      ready: string[]; reason: string; created_at: string }[];
  } | null>(null);
  const [goDispatch, setGoDispatch] = useState<{
    id: string;
    advice: { ready: string[]; waiting: string[]; running: string[]; terminal: boolean; reason: string };
  } | null>(null);
  const [goStatus, setGoStatus] = useState<{ configured: boolean; detail: string } | null>(null);
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
    void workspaceApi.goSecurityReadiness().then(setGoStatus)
      .catch(reason => setError(String(reason)));
    void workspaceApi.nativeModelReadiness().then(setModelStatus)
      .catch(reason => setError(String(reason)));
    void workspaceApi.nativeIsolatedScanReadiness().then(setWorkerStatus)
      .catch(reason => setError(String(reason)));
    void workspaceApi.workerCleanupHoldCount().then(setCleanupHolds)
      .catch(reason => setError(String(reason)));
    void workspaceApi.nativeNeuralReadiness().then(setNeuralReady)
      .catch(reason => setError(String(reason)));
  }, []);

  useEffect(() => {
    void workspaceApi.listApprovedFlowQueue()
      .then(setFlowQueue)
      .catch(reason => setError(String(reason)));
    const timer = window.setInterval(() => {
      void workspaceApi.listApprovedFlowQueue()
        .then(setFlowQueue)
        .catch(() => undefined);
    }, 3500);
    return () => window.clearInterval(timer);
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

  useEffect(() => {
    const id = selectedId || runs[0]?.id;
    if (!id) { setAutomatedFlow(null); return; }
    let active = true;
    void workspaceApi.getAutomatedSecurityFlow(id)
      .then(result => { if (active) setAutomatedFlow(result); })
      .catch(reason => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [selectedId, runs]);

  useEffect(() => {
    const id = selectedId || runs[0]?.id;
    if (!id) { setAdaptiveFollowup(null); return; }
    let active = true;
    void workspaceApi.getAutomatedFlowFollowup(id)
      .then(result => { if (active) setAdaptiveFollowup(result); })
      .catch(reason => { if (active) setError(String(reason)); });
    return () => { active = false; };
  }, [selectedId, runs]);

  useEffect(() => {
    if (busy !== "auto-flow") return;
    const id = selectedId || runs[0]?.id;
    if (!id) return;
    const poll = window.setInterval(() => {
      void workspaceApi.getAutomatedSecurityFlow(id)
        .then(result => setAutomatedFlow(result))
        .catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(poll);
  }, [busy, selectedId, runs]);

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

  async function testNeuralProvider() {
    setBusy("probe"); setError(""); setNeuralProbe(null);
    try {
      setNeuralProbe(await workspaceApi.probeNativeNeuralProvider());
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
    finally {
      void workspaceApi.workerCleanupHoldCount().then(setCleanupHolds).catch(() => undefined);
      setBusy("");
    }
  }

  async function verifyCleanup() {
    if (!window.confirm(
      "Check the current Docker daemon for remaining CodeTwin scanner containers? This read-only check will release blocked scans only if none remain."
    )) return;
    setBusy("worker-cleanup"); setError("");
    try {
      await workspaceApi.verifyWorkerCleanup(true);
      setCleanupHolds(await workspaceApi.workerCleanupHoldCount());
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

  async function readActionReceipts(id: string) {
    setBusy("action-ledger"); setError("");
    try {
      const records = await workspaceApi.listNativeActionReceipts(id);
      setActionReceipts({ reviewId: id, records });
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function readGoDispatchAudit(id: string) {
    setBusy("go-audit"); setError("");
    try {
      const records = await workspaceApi.listGoDispatchAudit(id);
      setGoDispatchAudit({ reviewId: id, records });
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function inspectGoScheduling(id: string) {
    if (!goStatus?.configured) return;
    setBusy("go-dispatch"); setError("");
    setGoDispatch(null);
    try {
      const advice = await workspaceApi.goSecurityDispatchPreview(id);
      setGoDispatch({ id, advice });
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function refineGoDecomposition(op: "add" | "remove" | "modify") {
    if (!goStatus?.configured || !activeProjectId || !taskProposal ||
        taskProposal.projectId !== activeProjectId || taskProposal.objective !== objective) return;
    setBusy("go-refine"); setError("");
    const current = taskProposal.proposal;
    const operation = op === "remove"
      ? { op, role: refineRole }
      : { op, role: refineRole, objective: refineObjective };
    try {
      const proposal = await workspaceApi.refineGoSecurityTaskPlan(
        activeProjectId, current, [operation]
      );
      setTaskProposal({ proposal, projectId: activeProjectId, objective });
      setAcceptedTaskPlan(false);
      setRefineObjective("");
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function suggestGoDecomposition() {
    if (!activeProjectId || !objective.trim()) return;
    setBusy("go-decompose"); setError("");
    const requestedProjectId = activeProjectId;
    const requestedObjective = objective;
    setTaskProposal(null);
    setAcceptedTaskPlan(false);
    try {
      const proposal = await workspaceApi.suggestGoSecurityTaskPlan(requestedProjectId, requestedObjective);
      setTaskProposal({ proposal, projectId: requestedProjectId, objective: requestedObjective });
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
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

  async function requestAdaptiveFollowup(id: string) {
    setBusy("flow-followup"); setError("");
    try {
      const proposed = await workspaceApi.suggestAutomatedFlowFollowup(id);
      setAdaptiveFollowup(proposed);
      if (!proposed) setError("No incomplete specialist requires a follow-up.");
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  function reviewAdaptiveFollowup(followup: AdaptiveFlowFollowup, run: NativeAgentRun) {
    setActiveProjectId(run.project_id);
    setObjective(run.objective);
    setSelectedRoles(followup.proposal.tasks.map(task => task.role));
    setTaskProposal({
      proposal: followup.proposal,
      projectId: run.project_id,
      objective: run.objective,
    });
    // The proposed DAG remains unapproved until explicitly reviewed and used.
    setAcceptedTaskPlan(false);
  }

  async function queueApprovedFlow(id: string) {
    setBusy("queue-add"); setError("");
    try {
      await workspaceApi.enqueueApprovedSecurityFlow(id);
      setFlowQueue(await workspaceApi.listApprovedFlowQueue());
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function removeQueuedFlow(id: string) {
    setBusy("queue-remove"); setError("");
    try { setFlowQueue(await workspaceApi.removeQueuedSecurityFlow(id)); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function runApprovedFlowQueue() {
    if (!window.confirm(
      "Run the queued, separately approved passive reviews in FIFO order? The batch stops at the first failed or interrupted review."
    )) return;
    setBusy("flow-queue"); setError("");
    try {
      setFlowQueue(await workspaceApi.runApprovedSecurityFlowQueue());
      await refresh();
    } catch (reason) { setError(String(reason)); await refresh(); }
    finally { setBusy(""); }
  }

  async function prepareAutomatedFlow(id: string) {
    if (!goStatus?.configured) return;
    setBusy("auto-prepare"); setError("");
    try {
      setAutomatedFlow(await workspaceApi.prepareAutomatedSecurityFlow(id));
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function runApprovedAutomatedFlow(id: string) {
    setBusy("auto-flow"); setError("");
    try {
      setAutomatedFlow(await workspaceApi.runAutomatedSecurityFlow(id));
      setAdaptiveFollowup(await workspaceApi.getAutomatedFlowFollowup(id));
      await refresh();
    } catch (reason) { setError(String(reason)); await refresh(); }
    finally { setBusy(""); }
  }

  async function approveAndQueueAutomatedFlow(id: string) {
    if (!goStatus?.configured || !window.confirm(
      "Approve this exact passive specialist plan and add it to the SQLite queue? It will not run until you start the approved flow queue."
    )) return;
    setBusy("auto-queue"); setError("");
    try {
      setAutomatedFlow(await workspaceApi.approveAutomatedSecurityFlow(id));
      await workspaceApi.enqueueApprovedSecurityFlow(id);
      setFlowQueue(await workspaceApi.listApprovedFlowQueue());
      await refresh();
    } catch (reason) { setError(String(reason)); await refresh(); }
    finally { setBusy(""); }
  }

  async function approveAndRunAutomatedFlow(id: string) {
    if (!goStatus?.configured || !window.confirm(
      "Approve the displayed passive specialist DAG and automatically run every dependency-ready task? Rust retains tool permissions and SQLite evidence; any failure or cancellation stops the flow."
    )) return;
    setBusy("auto-flow"); setError("");
    try {
      setAutomatedFlow(await workspaceApi.approveAutomatedSecurityFlow(id));
      setAutomatedFlow(await workspaceApi.runAutomatedSecurityFlow(id));
      setAdaptiveFollowup(await workspaceApi.getAutomatedFlowFollowup(id));
      await refresh();
    } catch (reason) { setError(String(reason)); await refresh(); }
    finally { setBusy(""); }
  }

  function executeWithGo(id: string) {
    if (!goStatus?.configured || !window.confirm(
      "Run the already-approved passive review with local Go verifying each specialist dependency? Rust keeps control of execution and SQLite evidence."
    )) return;
    setBusy("go-run"); setError("");
    void workspaceApi.runNativeGoReview(id)
      .then(() => refresh())
      .catch(reason => setError(String(reason)))
      .finally(() => setBusy(""));
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

  async function auditEvidenceHistory(loadOlder = false) {
    if (!activeProjectId || busy) return;
    const projectId = activeProjectId;
    const previous = loadOlder && historyAudit?.project_id === projectId ? historyAudit : null;
    if (loadOlder && !previous?.next_before_rowid) return;
    setBusy("evidence-history");
    setError("");
    if (!loadOlder) setHistoryAudit(null);
    try {
      const audit = await workspaceApi.auditNativeEvidenceHistory(
        projectId, 100, previous?.next_before_rowid ?? null,
      );
      if (previous) {
        setHistoryAudit({
          ...audit,
          checked: previous.checked + audit.checked,
          verified: previous.verified + audit.verified,
          invalid: [...previous.invalid, ...audit.invalid],
        });
      } else {
        setHistoryAudit(audit);
      }
    } catch (reason) {
      setError("Historical evidence audit failed: " + String(reason));
    } finally {
      setBusy("");
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
    <Panel title="Approved security flow queue">
      <p className="ws-form-help">
        Queue up to eight individually approved local passive reviews. One batch run
        executes them in order using Go scheduling checks and SQLite action receipts.
        Failed or interrupted work stops the batch; no automatic restart or retry.
      </p>
      <div className="ws-button-row">
        <button className="ws-button ws-button-primary"
          disabled={!goStatus?.configured || Boolean(busy) || !flowQueue.some(item => item.status === "queued")}
          onClick={() => void runApprovedFlowQueue()}>
          {busy === "flow-queue" ? "Running approved flows…" : "Run approved flow queue"}
        </button>
        <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
          onClick={() => void workspaceApi.listApprovedFlowQueue().then(setFlowQueue).catch(reason => setError(String(reason)))}>
          Refresh queue
        </button>
      </div>
      {flowQueue.length === 0
        ? <p className="ws-form-help">No flows have been added to the queue.</p>
        : flowQueue.map(item => <div key={item.id} className="ws-form-stack">
            <div className="ws-button-row">
              <span className="ws-form-help">
                Review {item.review_id.slice(0, 12)} · {item.status}
                {" · "}{item.completed_steps}/{item.total_steps} specialists completed
                {item.active_roles.length > 0
                  ? " · Running (" + item.active_roles.length + "): " + item.active_roles.join(", ")
                  : ""}
                {item.issue_role && item.issue_status
                  ? " · " + item.issue_role + ": " + item.issue_status : ""}
                {item.detail ? " · " + item.detail : ""}
              </span>
              {item.status === "queued" && <button className="ws-button ws-button-secondary"
                disabled={Boolean(busy)} onClick={() => void removeQueuedFlow(item.review_id)}>
                Remove waiting flow
              </button>}
            </div>
            <progress
              value={item.completed_steps}
              max={Math.max(1, item.total_steps)}
              aria-label={`Review ${item.review_id.slice(0, 12)} completed specialists`}
              aria-valuetext={`${item.completed_steps} of ${item.total_steps} specialists completed`}
            />
            {item.review_status !== item.status && item.status !== "queued" &&
              <span className="ws-form-help">Review state: {item.review_status}</span>}
          </div>)}
    </Panel>
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
            disabled={!goStatus?.configured || !activeProjectId || !objective.trim() || Boolean(busy)}
            onClick={() => void suggestGoDecomposition()}>
            {busy === "go-decompose" ? "Preparing local plan…" : "Propose with local Go (offline)"}
          </button>
          <p className="ws-form-help">{goStatus?.detail ?? "Checking local Go security engine…"}</p>
          <button className="ws-button ws-button-secondary"
            disabled={!modelStatus?.configured || !activeProjectId || !planConsent || !objective.trim() || Boolean(busy)}
            onClick={() => void suggestDecomposition()}>
            {busy === "decompose" ? "Decomposing…" : "Propose multi-step task graph"}
          </button>
          {taskProposal && taskProposal.objective === objective && taskProposal.projectId === activeProjectId && <div>
            <p><strong>Proposed specialist task DAG (not approved)</strong></p>
            {taskProposal.proposal.tasks.map(task => <p key={task.role}>
              <strong>{task.role}</strong> · {task.objective} · depends on {task.depends_on.join(", ") || "none"}
            </p>)}
            <p>{taskProposal.proposal.rationale}</p>
            {goStatus?.configured && <div className="ws-form-stack">
              <p className="ws-form-help">Refine this unapproved task plan locally. Only registered passive specialists are allowed; no tools run until you create and approve the review.</p>
              <label className="ws-field">
                <span>Specialist to refine</span>
                <select value={refineRole} disabled={Boolean(busy)}
                  onChange={event => setRefineRole(event.target.value)}>
                  {roleChoices.filter(role => !role.mandatory).map(role =>
                    <option key={role.id} value={role.id}>{role.name}</option>)}
                </select>
              </label>
              <label className="ws-field">
                <span>Updated review objective (required for add or update)</span>
                <input type="text" value={refineObjective} maxLength={300}
                  placeholder="Describe the passive evidence to review"
                  disabled={Boolean(busy)}
                  onChange={event => setRefineObjective(event.target.value)} />
              </label>
              <div className="ws-button-row">
                <button className="ws-button ws-button-secondary" disabled={Boolean(busy) ||
                  taskProposal.proposal.tasks.some(task => task.role === refineRole) ||
                  !refineObjective.trim()} onClick={() => void refineGoDecomposition("add")}>
                  Add specialist
                </button>
                <button className="ws-button ws-button-secondary" disabled={Boolean(busy) ||
                  !taskProposal.proposal.tasks.some(task => task.role === refineRole) ||
                  !refineObjective.trim()} onClick={() => void refineGoDecomposition("modify")}>
                  Update objective
                </button>
                <button className="ws-button ws-button-secondary" disabled={Boolean(busy) ||
                  !taskProposal.proposal.tasks.some(task => task.role === refineRole)}
                  onClick={() => void refineGoDecomposition("remove")}>
                  Remove specialist
                </button>
              </div>
            </div>}
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
              onChange={event => {
                setAcceptedTaskPlan(false);
                setSelectedRoles(current =>
                  event.target.checked ? [...current, role.id] : current.filter(id => id !== role.id));
              }}/>
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
      <div className="ws-top-actions">
        <button className="ws-button ws-button-secondary"
          disabled={!neuralReady?.configured || Boolean(busy)}
          onClick={() => void testNeuralProvider()}>
          {busy === "probe" ? "Testing provider…" : "Test embedding connection"}
        </button>
        {neuralProbe && <p role="status">
          Provider verified · {neuralProbe.model} · {neuralProbe.dimensions} dimensions
          · {neuralProbe.latency_ms} ms · normalized: {neuralProbe.normalized ? "yes" : "no"}
        </p>}
      </div>
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
      {automatedFlow?.review_id === selected.id &&
        ["failed", "interrupted"].includes(automatedFlow.status) && <section>
          <h3>Adaptive follow-up proposal</h3>
          <p className="ws-form-help">
            A failed or interrupted flow can propose a new, narrower passive review.
            It never repeats work or grants a new approval automatically.
          </p>
          {adaptiveFollowup?.review_id === selected.id
            ? <>
                <p>{adaptiveFollowup.proposal.rationale}</p>
                <p className="ws-form-help">
                  Suggested specialists: {adaptiveFollowup.proposal.tasks.map(task => task.role).join(" → ")}
                </p>
                <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
                  onClick={() => reviewAdaptiveFollowup(adaptiveFollowup, selected)}>
                  Review follow-up task plan
                </button>
              </>
            : <button className="ws-button ws-button-secondary" disabled={Boolean(busy) || !goStatus?.configured}
                onClick={() => void requestAdaptiveFollowup(selected.id)}>
                {busy === "flow-followup" ? "Preparing scoped follow-up…" : "Suggest scoped follow-up"}
              </button>}
        </section>}
      {automatedFlow?.review_id === selected.id && <section>
        <h3>Automated security flow</h3>
        <p className="ws-form-help" role="status">
          Flow {automatedFlow.status} · {automatedFlow.completed_subtasks} of {automatedFlow.total_subtasks} subtasks complete.
          After one approval, the Go scheduler checks dependencies while Rust runs the approved passive specialists automatically.
        </p>
        {automatedFlow.tasks.map(task => <details key={task.title} open>
          <summary><strong>{task.title}</strong></summary>
          {task.subtasks.map(subtask => <p className="ws-form-help" key={subtask.position}>
            {subtask.role} · {subtask.status}
            {" · "}depends on: {subtask.requires.join(", ") || "none"}
            {" · "}actions: {subtask.actions.map(action => action.status).join(", ") || "not started"}
          </p>)}
        </details>)}
      </section>}
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
        <h3>Local Go scheduler</h3>
        <p className="ws-form-help">
          Reads the persisted SQLite review lifecycle and approved role DAG.
          This is a read-only scheduling preview; it does not approve, execute or retry tasks.
        </p>
        <button className="ws-button ws-button-secondary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => void inspectGoScheduling(selected.id)}>
          {busy === "go-dispatch" ? "Checking schedule…" : "Inspect dependency-ready Go schedule"}
        </button>
        {goDispatch?.id === selected.id && <p role="status">
          {goDispatch.advice.terminal ? "Terminal review" : "Schedule preview"}
          {" · "}ready: {goDispatch.advice.ready.join(", ") || "none"}
          {" · "}running: {goDispatch.advice.running.join(", ") || "none"}
          {" · "}waiting: {goDispatch.advice.waiting.join(", ") || "none"}
        </p>}
        <h3>SQLite specialist action receipts</h3>
        <p className="ws-form-help">
          Every started passive specialist has a durable receipt. The receipt records
          its final status and a SHA-256 evidence digest without copying source or secrets.
        </p>
        <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
          onClick={() => void readActionReceipts(selected.id)}>
          {busy === "action-ledger" ? "Reading receipts…" : "View action receipts"}
        </button>
        {actionReceipts?.reviewId === selected.id && (
          actionReceipts.records.length === 0
            ? <p className="ws-form-help">No specialist actions have started for this review.</p>
            : actionReceipts.records.map(item => <p className="ws-form-help" key={item.position}>
                {item.role} · {item.status} · started {item.started_at}
                {item.result_sha256 ? " · SHA-256: " + item.result_sha256 : ""}
              </p>)
        )}
        <h3>Persisted Go dispatch decisions</h3>
        <p className="ws-form-help">Rust records every Go-verified role decision in SQLite. Failed verification blocks execution and records a denied decision.</p>
        <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
          onClick={() => void readGoDispatchAudit(selected.id)}>
          {busy === "go-audit" ? "Reading audit…" : "View Go dispatch audit"}
        </button>
        {goDispatchAudit?.reviewId === selected.id && (
          goDispatchAudit.records.length === 0
            ? <p className="ws-form-help">No Go scheduling decisions recorded for this review.</p>
            : goDispatchAudit.records.map(item => <p className="ws-form-help" key={item.id}>
                {item.role} · {item.verdict} · ready: {item.ready.join(", ") || "none"} · {item.created_at}
              </p>)
        )}
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
        <div className="ws-form-stack">
          <button className="ws-button ws-button-secondary" disabled={!activeProjectId || Boolean(busy)}
            onClick={() => void auditEvidenceHistory()}>
            {busy === "evidence-history" ? "Checking saved reviews…" : "Audit completed review history"}
          </button>
          {historyAudit && historyAudit.project_id === activeProjectId && <div role="status">
            <p className="ws-form-help">
              Verified {historyAudit.verified} of {historyAudit.checked} checked completed reviews
              {" · "}{historyAudit.total_completed} total completed.
              {historyAudit.next_before_rowid
                ? " Older completed reviews remain unaudited."
                : historyAudit.checked < historyAudit.total_completed
                  ? " No older pages remain; restart the audit to include reviews created during pagination."
                  : " All completed reviews in this audit were checked."}
            </p>
            {historyAudit.next_before_rowid && <button
              className="ws-button ws-button-secondary"
              disabled={Boolean(busy)}
              onClick={() => void auditEvidenceHistory(true)}>
              {busy === "evidence-history" ? "Checking older reviews…" : "Audit next 100 older reviews"}
            </button>}
            {historyAudit.invalid.map(item => <div className="ws-warning-box" key={item.review_id}>
              <strong>Unverified review <code>{item.review_id}</code></strong>
              {item.issues.map((issue, index) => <p key={index}>{issue}</p>)}
            </div>)}
          </div>}
        </div>
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
        {cleanupHolds === null && <p className="ws-form-help">Checking saved worker cleanup state…</p>}
        {cleanupHolds !== null && cleanupHolds > 0 && <div role="alert" className="ws-form-stack">
          <p className="ws-form-help">
            {cleanupHolds} previous worker cleanup {cleanupHolds === 1 ? "attempt needs" : "attempts need"}
            {" "}verification. New isolated scans are blocked until the configured Docker daemon confirms no CodeTwin scanner containers remain.
          </p>
          <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
            onClick={() => void verifyCleanup()}>
            {busy === "worker-cleanup" ? "Checking local Docker…": "Verify scanner cleanup in Docker"}
          </button>
        </div>}
        <label className="ws-field"><span>
          <input type="checkbox" checked={workerConsent} onChange={event => setWorkerConsent(event.target.checked)}/>
          I explicitly authorize an offline security scan of the selected project in Docker.
        </span></label>
        <button className="ws-button ws-button-secondary"
          disabled={!workerConsent || !workerStatus?.configured || cleanupHolds !== 0 || selected.status !== "approved" || Boolean(busy)}
          onClick={() => void runWorker(selected.id)}>
          {busy === "worker" ? "Running isolated scan…" : "Run approved offline scanner"}
        </button>
        <h3>Persistent worker audit</h3>
        {!workerHistory.length && <p className="ws-form-help">No recorded worker attempts for this review.</p>}
        {workerHistory.map(event => <p className="ws-form-help" key={event.id}>
          Attempt {event.id} · {event.status} · {event.started_at}
          {event.report_sha256 ? " · evidence " + event.report_sha256.slice(0, 12) : ""}
          {event.error_code ? " · " + event.error_code : ""}
        </p>)}
        {workerReceipt && <p role="status">
          Offline scan finished · {workerReceipt.vulnerability_count} vulnerability records,
          {" "}{workerReceipt.misconfiguration_count} misconfiguration records.
          Evidence SHA-256: <code>{workerReceipt.report_sha256}</code>
        </p>}
      </section>
      <div className="ws-top-actions">
        {selected.status === "planned" && automatedFlow?.review_id !== selected.id && <button className="ws-button ws-button-primary" disabled={Boolean(busy)} onClick={() => void approve(selected.id)}>Approve plan</button>}
        {selected.status === "planned" && automatedFlow?.review_id !== selected.id && <button className="ws-button ws-button-secondary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => void prepareAutomatedFlow(selected.id)}>Prepare automated flow</button>}
        {selected.status === "planned" && automatedFlow?.review_id === selected.id && <button className="ws-button ws-button-secondary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => void approveAndQueueAutomatedFlow(selected.id)}>
          {busy === "auto-queue" ? "Approving and queuing…" : "Approve and queue flow"}
        </button>}
        {selected.status === "planned" && automatedFlow?.review_id === selected.id && <button className="ws-button ws-button-primary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => void approveAndRunAutomatedFlow(selected.id)}>
          {busy === "auto-flow" ? "Running approved flow…" : "Approve and run complete flow"}
        </button>}
        {selected.status === "approved" && automatedFlow?.review_id === selected.id && automatedFlow.approved_at &&
          !flowQueue.some(item => item.review_id === selected.id) && <button className="ws-button ws-button-secondary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => void queueApprovedFlow(selected.id)}>Queue approved flow</button>}
        {selected.status === "approved" && automatedFlow?.review_id === selected.id && automatedFlow.approved_at &&
          !flowQueue.some(item => item.review_id === selected.id) && <button className="ws-button ws-button-primary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => void runApprovedAutomatedFlow(selected.id)}>Run approved automated flow</button>}
        {selected.status === "approved" && automatedFlow?.review_id !== selected.id && <button className="ws-button ws-button-primary" disabled={Boolean(busy)} onClick={() => execute(selected.id)}>Run approved review</button>}
        {selected.status === "approved" && automatedFlow?.review_id !== selected.id && <button className="ws-button ws-button-secondary"
          disabled={!goStatus?.configured || Boolean(busy)}
          onClick={() => executeWithGo(selected.id)}>
          {busy === "go-run" ? "Running Go-verified review…" : "Run with Go scheduling checks"}
        </button>}
        {["planned", "approved", "running"].includes(selected.status) && <button className="ws-button ws-button-secondary" onClick={() => void cancel(selected.id)}>Cancel</button>}
        <button className="ws-button ws-button-secondary" onClick={() => void copyReport(selected.id)}>Copy evidence report</button>
      </div>
    </Panel>}
  </div>;
}
