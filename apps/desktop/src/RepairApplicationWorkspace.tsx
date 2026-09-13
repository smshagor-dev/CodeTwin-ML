import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type IndexSummary = {
  project_id: string;
};

type RepairPlanRecord = {
  id: string;
  project_id: string;
  finding_id: string | null;
  title: string;
  rationale: string;
  status: string;
  created_at: string;
  updated_at: string;
  approved_at: string | null;
  verified_at: string | null;
};

type RepairApplicationRunRecord = {
  id: string;
  repair_id: string;
  project_id: string;
  status: string;
  changes_total: number;
  changes_applied: number;
  rollback_performed: boolean;
  backup_dir_name: string;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
};

type RepairApplicationItemRecord = {
  run_id: string;
  change_id: string;
  relative_path: string;
  base_content_hash: string;
  proposed_content_hash: string;
  backup_content_hash: string;
  backup_file_name: string;
  state: string;
};

export function RepairApplicationWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [plans, setPlans] = useState<RepairPlanRecord[]>([]);
  const [selectedPlan, setSelectedPlan] = useState<RepairPlanRecord | null>(null);
  const [history, setHistory] = useState<RepairApplicationRunRecord[]>([]);
  const [selectedRun, setSelectedRun] = useState<RepairApplicationRunRecord | null>(null);
  const [items, setItems] = useState<RepairApplicationItemRecord[]>([]);
  const [confirmApply, setConfirmApply] = useState(false);
  const [confirmRollback, setConfirmRollback] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function loadPlans(id: string, keepPlanId?: string) {
    const nextPlans = await invoke<RepairPlanRecord[]>("list_repair_plans", {
      projectId: id,
      status: null,
      limit: 200,
    });
    setPlans(nextPlans);
    if (keepPlanId) {
      const refreshed = nextPlans.find((plan) => plan.id === keepPlanId) ?? null;
      setSelectedPlan(refreshed);
      if (refreshed) {
        await loadHistory(refreshed.id);
      } else {
        setHistory([]);
        setSelectedRun(null);
        setItems([]);
      }
    }
  }

  async function openProject() {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setProjectId(index.project_id);
      setSelectedPlan(null);
      setSelectedRun(null);
      setItems([]);
      setHistory([]);
      setConfirmApply(false);
      setConfirmRollback(false);
      await loadPlans(index.project_id);
      setNotice("Repository indexed. Application still requires an approved repair plan and explicit confirmation.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function reindexProject() {
    if (!path.trim() || !projectId) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      setProjectId(index.project_id);
      await loadPlans(index.project_id, selectedPlan?.id);
      setNotice("Repository re-indexed. Verification should use this refreshed indexed state.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function loadHistory(repairId: string) {
    const runs = await invoke<RepairApplicationRunRecord[]>("repair_application_history", {
      repairId,
      limit: 100,
    });
    setHistory(runs);
    if (selectedRun && !runs.some((run) => run.id === selectedRun.id)) {
      setSelectedRun(null);
      setItems([]);
    }
  }

  async function selectPlan(plan: RepairPlanRecord) {
    setSelectedPlan(plan);
    setSelectedRun(null);
    setItems([]);
    setConfirmApply(false);
    setConfirmRollback(false);
    setError(null);
    try {
      await loadHistory(plan.id);
    } catch (value) {
      setHistory([]);
      setError(String(value));
    }
  }

  async function selectRun(run: RepairApplicationRunRecord) {
    setSelectedRun(run);
    setConfirmRollback(false);
    setError(null);
    try {
      const nextItems = await invoke<RepairApplicationItemRecord[]>("list_repair_application_items", {
        runId: run.id,
        limit: 500,
      });
      setItems(nextItems);
    } catch (value) {
      setItems([]);
      setError(String(value));
    }
  }

  async function applySelectedPlan() {
    if (!selectedPlan || selectedPlan.status !== "approved" || !confirmApply || !projectId) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const run = await invoke<RepairApplicationRunRecord>("apply_repair_plan", {
        repairId: selectedPlan.id,
      });
      setSelectedRun(run);
      setItems(await invoke<RepairApplicationItemRecord[]>("list_repair_application_items", {
        runId: run.id,
        limit: 500,
      }));
      setConfirmApply(false);
      await loadPlans(projectId, selectedPlan.id);
      if (run.status === "applied") {
        setNotice("Proposed bytes were applied. Re-index the repository before hash verification; linked findings still require their analyzer to resolve them.");
      } else {
        setNotice(`Application recorded status: ${run.status}. No success claim is made for a failed or rollback-failed run.`);
      }
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function rollbackSelectedRun() {
    if (!selectedRun || selectedRun.status !== "applied" || !confirmRollback || !projectId) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const run = await invoke<RepairApplicationRunRecord>("rollback_repair_application", {
        runId: selectedRun.id,
      });
      setSelectedRun(run);
      setItems(await invoke<RepairApplicationItemRecord[]>("list_repair_application_items", {
        runId: run.id,
        limit: 500,
      }));
      setConfirmRollback(false);
      await loadPlans(projectId, selectedPlan?.id);
      setNotice("Rollback restored the hash-pinned backups. The plan returned to draft; re-index and approve again before any future application.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  const canApply = selectedPlan?.status === "approved";
  const canRollback = selectedRun?.status === "applied" && selectedPlan?.status === "applied";

  return (
    <main className="standalone-workspace repair-application-workspace">
      <header>
        <div>
          <p className="eyebrow">EXPLICIT FILE MUTATION BOUNDARY</p>
          <h1>Repair Apply & Rollback</h1>
          <p>
            This workspace can write approved replacement bytes to repository files. It never runs repository commands, tests,
            compilers, package managers, hooks, or language servers.
          </p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}
      {notice && <p className="success banner" role="status">{notice}</p>}

      <section className="panel danger-panel">
        <h2>Mutation safety</h2>
        <p>
          Application is refused unless every current repository file is a regular non-symlink file inside the project root and
          still matches the proposal's approved base SHA-256. All replacement files and app-data backups are staged before swaps.
          A failed multi-file application attempts reverse rollback. A rollback refuses to overwrite post-apply manual edits.
        </p>
        <p>
          This is not a crash-proof filesystem transaction: a process or machine crash during a rename window may require manual
          recovery from the persisted app-data backup evidence.
        </p>
      </section>

      <section className="panel">
        <div className="section-heading">
          <div>
            <h2>Project</h2>
            <p>Open the same repository used by Repair Lab. Re-index after application or rollback before verification.</p>
          </div>
          {projectId && <button onClick={() => void reindexProject()} disabled={busy}>Re-index repository</button>}
        </div>
        <div className="row">
          <input aria-label="Repository path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="C:\\work\\project or /home/user/project" />
          <button onClick={() => void openProject()} disabled={busy || !path.trim()}>{busy && !projectId ? "Opening…" : "Open & index"}</button>
        </div>
        {projectId && <p className="mono workspace-project-id">Project {projectId}</p>}
      </section>

      {projectId && (
        <section className="repair-application-layout">
          <div className="twin-column">
            <section className="panel compact">
              <div className="section-heading">
                <div><h2>Repair plans</h2><p>Only approved plans can be applied.</p></div>
              </div>
              <div className="result-list repair-apply-scroll">
                {plans.map((plan) => (
                  <button key={plan.id} className={`result-item ${selectedPlan?.id === plan.id ? "selected" : ""}`} onClick={() => void selectPlan(plan)}>
                    <strong>{plan.title}</strong>
                    <span>{plan.status}{plan.finding_id ? " · finding-linked" : ""}</span>
                    <small>{plan.updated_at}</small>
                  </button>
                ))}
                {!plans.length && <p className="empty">No repair plans are persisted for this project.</p>}
              </div>
            </section>

            {selectedPlan && (
              <section className="panel compact danger-panel">
                <h2>Apply approved proposal</h2>
                <p><strong>{selectedPlan.title}</strong></p>
                <p>Status: <span className="mono">{selectedPlan.status}</span></p>
                <p>{selectedPlan.rationale}</p>
                {canApply ? (
                  <>
                    <label className="repair-confirmation">
                      <input type="checkbox" checked={confirmApply} onChange={(event) => setConfirmApply(event.target.checked)} />
                      I understand this action will replace repository file bytes after live SHA-256 precondition checks.
                    </label>
                    <button className="danger-action" onClick={() => void applySelectedPlan()} disabled={busy || !confirmApply}>
                      {busy ? "Applying…" : "Apply approved files"}
                    </button>
                  </>
                ) : (
                  <p className="empty">Return to Repair Lab and approve a draft plan before application.</p>
                )}
              </section>
            )}
          </div>

          <div className="twin-column">
            <section className="panel compact">
              <h2>Application history</h2>
              <div className="result-list repair-apply-scroll">
                {history.map((run) => (
                  <button key={run.id} className={`result-item ${selectedRun?.id === run.id ? "selected" : ""}`} onClick={() => void selectRun(run)}>
                    <strong>{run.status}</strong>
                    <span>{run.changes_applied}/{run.changes_total} currently applied · rollback {run.rollback_performed ? "attempted" : "not attempted"}</span>
                    <small>{run.completed_at ?? run.created_at}</small>
                  </button>
                ))}
                {!history.length && <p className="empty">No application attempts for the selected repair plan.</p>}
              </div>
            </section>

            {selectedRun && (
              <section className="panel compact">
                <div className="section-heading">
                  <div>
                    <h2>Application evidence</h2>
                    <p>{selectedRun.status} · backup set {selectedRun.backup_dir_name}</p>
                  </div>
                </div>
                {selectedRun.error_message && <p className="warning banner">{selectedRun.error_message}</p>}
                <div className="result-list repair-apply-scroll">
                  {items.map((item) => (
                    <div key={item.change_id} className="result-item static-item">
                      <strong>{item.relative_path}</strong>
                      <span>{item.state} · backup {item.backup_file_name}</span>
                      <small className="mono">base {shortHash(item.base_content_hash)} → proposed {shortHash(item.proposed_content_hash)}</small>
                      <small className="mono">backup {shortHash(item.backup_content_hash)}</small>
                    </div>
                  ))}
                </div>
                {canRollback && (
                  <div className="repair-rollback-box">
                    <label className="repair-confirmation">
                      <input type="checkbox" checked={confirmRollback} onChange={(event) => setConfirmRollback(event.target.checked)} />
                      Restore the recorded base backups only if every current file still matches the applied proposal hash.
                    </label>
                    <button className="danger-action" onClick={() => void rollbackSelectedRun()} disabled={busy || !confirmRollback}>
                      {busy ? "Rolling back…" : "Rollback applied files"}
                    </button>
                  </div>
                )}
              </section>
            )}
          </div>
        </section>
      )}
    </main>
  );
}

function shortHash(value: string) {
  return value.length > 16 ? `${value.slice(0, 16)}…` : value;
}
