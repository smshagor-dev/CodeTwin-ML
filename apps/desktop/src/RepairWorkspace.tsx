import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type PlanFilter = "all" | "draft" | "approved" | "applied" | "verified" | "rejected" | "superseded";

type IndexSummary = {
  project_id: string;
  status: AnalysisStatus;
};

type SourceFileRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  language: string | null;
  content_hash: string;
  byte_size: number;
  parse_state: string | null;
  is_active: boolean;
};

type RepairSourceSnapshot = {
  file_id: string;
  project_id: string;
  relative_path: string;
  language: string | null;
  content_hash: string;
  byte_size: number;
  content: string;
};

type RepairFindingRecord = {
  id: string;
  project_id: string;
  analyzer_key: string | null;
  category: string;
  severity: string;
  title: string;
  status: string;
  file_id: string | null;
  source_start_line: number | null;
  source_end_line: number | null;
  last_seen: string;
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

type RepairChangeRecord = {
  id: string;
  repair_id: string;
  file_id: string | null;
  relative_path: string;
  base_content_hash: string;
  proposed_content_hash: string;
  proposed_content: string;
  proposed_byte_size: number;
  created_at: string;
};

type RepairVerificationRunRecord = {
  id: string;
  repair_id: string;
  project_id: string;
  status: string;
  finding_status: string | null;
  matched_changes: number;
  mismatched_changes: number;
  missing_changes: number;
  created_at: string;
};

type RepairVerificationItemRecord = {
  run_id: string;
  change_id: string;
  state: string;
  expected_hash: string;
  observed_hash: string | null;
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

const MAX_PROPOSED_BYTES = 1_048_576;

function buildPatchPreview(before: string, after: string, maxOutputLines = 320): string {
  const beforeLines = before.split("\n");
  const afterLines = after.split("\n");
  const output: string[] = [];
  const max = Math.max(beforeLines.length, afterLines.length);

  for (let index = 0; index < max && output.length < maxOutputLines; index += 1) {
    const previous = beforeLines[index];
    const next = afterLines[index];
    if (previous === next) {
      if (output.length && output[output.length - 1] !== " … unchanged lines omitted …") {
        output.push(" … unchanged lines omitted …");
      }
      continue;
    }
    if (previous !== undefined) output.push("- " + previous);
    if (next !== undefined && output.length < maxOutputLines) output.push("+ " + next);
  }

  if (output.length >= maxOutputLines) {
    output.push("… patch preview truncated; full proposed file remains visible above …");
  }
  return output.join("\n");
}

export function RepairWorkspace() {
  const [path, setPath] = useState("");
  const [projectId, setProjectId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [files, setFiles] = useState<SourceFileRecord[]>([]);
  const [findings, setFindings] = useState<RepairFindingRecord[]>([]);
  const [plans, setPlans] = useState<RepairPlanRecord[]>([]);
  const [planFilter, setPlanFilter] = useState<PlanFilter>("all");

  const [selectedPlan, setSelectedPlan] = useState<RepairPlanRecord | null>(null);
  const [changes, setChanges] = useState<RepairChangeRecord[]>([]);
  const [verificationHistory, setVerificationHistory] = useState<RepairVerificationRunRecord[]>([]);
  const [selectedVerification, setSelectedVerification] = useState<RepairVerificationRunRecord | null>(null);
  const [verificationItems, setVerificationItems] = useState<RepairVerificationItemRecord[]>([]);

  const [applicationHistory, setApplicationHistory] = useState<RepairApplicationRunRecord[]>([]);

  const [title, setTitle] = useState("");
  const [rationale, setRationale] = useState("");
  const [findingId, setFindingId] = useState("");
  const [fileId, setFileId] = useState("");
  const [source, setSource] = useState<RepairSourceSnapshot | null>(null);
  const [proposedContent, setProposedContent] = useState("");

  async function loadProjectData(id: string, nextFilter: PlanFilter = planFilter) {
    const status = nextFilter === "all" ? null : nextFilter;
    const [nextFiles, nextFindings, nextPlans] = await Promise.all([
      invoke<SourceFileRecord[]>("list_project_files", { projectId: id, search: null, limit: 500 }),
      invoke<RepairFindingRecord[]>("list_repair_candidate_findings", { projectId: id, status: "open", limit: 200 }),
      invoke<RepairPlanRecord[]>("list_repair_plans", { projectId: id, status, limit: 200 }),
    ]);
    setFiles(nextFiles);
    setFindings(nextFindings);
    setPlans(nextPlans);

    if (selectedPlan) {
      const refreshed = nextPlans.find((plan) => plan.id === selectedPlan.id);
      if (refreshed) {
        setSelectedPlan(refreshed);
        await loadPlanDetails(refreshed.id);
      } else if (nextFilter !== "all") {
        setSelectedPlan(null);
        setChanges([]);
        setVerificationHistory([]);
        setSelectedVerification(null);
        setVerificationItems([]);
        setApplicationHistory([]);
      }
    }
  }

  async function loadPlanDetails(repairId: string) {
    const [nextChanges, nextHistory, nextApplications] = await Promise.all([
      invoke<RepairChangeRecord[]>("list_repair_changes", { repairId, limit: 500 }),
      invoke<RepairVerificationRunRecord[]>("repair_verification_history", { repairId, limit: 100 }),
      invoke<RepairApplicationRunRecord[]>("repair_application_history", { repairId, limit: 100 }),
    ]);
    setChanges(nextChanges);
    setVerificationHistory(nextHistory);
    setApplicationHistory(nextApplications);
    if (selectedVerification) {
      const refreshed = nextHistory.find((run) => run.id === selectedVerification.id);
      if (!refreshed) {
        setSelectedVerification(null);
        setVerificationItems([]);
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
      setChanges([]);
      setVerificationHistory([]);
      setSelectedVerification(null);
      setVerificationItems([]);
      setApplicationHistory([]);
      setSource(null);
      setProposedContent("");
      await loadProjectData(index.project_id);
      setNotice("Project indexed. Repair proposals will be pinned to this indexed state.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function reindexProject() {
    if (!projectId || !path.trim()) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const index = await invoke<IndexSummary>("index_project", { path: path.trim() });
      if (index.project_id !== projectId) {
        throw new Error("Re-index resolved to a different project identity.");
      }
      await loadProjectData(projectId);
      setSource(null);
      setProposedContent("");
      setNotice("Project re-indexed. Verification can now compare the persisted state with approved proposal hashes.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function createPlan() {
    if (!projectId || !title.trim() || !rationale.trim()) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const plan = await invoke<RepairPlanRecord>("create_repair_plan", {
        projectId,
        findingId: findingId || null,
        title: title.trim(),
        rationale: rationale.trim(),
      });
      setSelectedPlan(plan);
      setTitle("");
      setRationale("");
      setChanges([]);
      setVerificationHistory([]);
      setSelectedVerification(null);
      setVerificationItems([]);
      setApplicationHistory([]);
      await loadProjectData(projectId);
      setSelectedPlan(plan);
      setNotice("Draft repair plan created. Add at least one full-file replacement before approval.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function selectPlan(plan: RepairPlanRecord) {
    setSelectedPlan(plan);
    setSource(null);
    setProposedContent("");
    setSelectedVerification(null);
    setVerificationItems([]);
    setError(null);
    try {
      await loadPlanDetails(plan.id);
    } catch (value) {
      setError(String(value));
    }
  }

  async function loadSource() {
    if (!fileId) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const snapshot = await invoke<RepairSourceSnapshot>("read_repair_source", { fileId });
      if (projectId && snapshot.project_id !== projectId) {
        throw new Error("Selected file does not belong to the current project.");
      }
      setSource(snapshot);
      setProposedContent(snapshot.content);
      setNotice("Hash-verified source loaded. Edit the full file below; unchanged content cannot be saved as a repair change.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function saveReplacement() {
    if (!selectedPlan || !fileId || !source) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await invoke<RepairChangeRecord>("add_repair_file_replacement", {
        repairId: selectedPlan.id,
        fileId,
        proposedContent,
      });
      await loadPlanDetails(selectedPlan.id);
      setNotice("Replacement proposal persisted. The repository itself was not modified.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function approvePlan() {
    if (!selectedPlan) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const plan = await invoke<RepairPlanRecord>("approve_repair_plan", { repairId: selectedPlan.id });
      setSelectedPlan(plan);
      if (projectId) await loadProjectData(projectId);
      setSelectedPlan(plan);
      await loadPlanDetails(plan.id);
      setNotice("Plan approved after base-hash recheck. Use Apply approved repair to perform the hash-verified in-product application, then re-index before verification.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function rejectPlan() {
    if (!selectedPlan) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const plan = await invoke<RepairPlanRecord>("reject_repair_plan", { repairId: selectedPlan.id });
      setSelectedPlan(plan);
      if (projectId) await loadProjectData(projectId);
      setSelectedPlan(plan);
      await loadPlanDetails(plan.id);
      setNotice("Repair plan rejected. No repository bytes were changed by CodeTwin.");
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function applyPlan() {
    if (!selectedPlan || selectedPlan.status !== "approved") return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const run = await invoke<RepairApplicationRunRecord>("apply_repair_plan", { repairId: selectedPlan.id });
      if (projectId) await loadProjectData(projectId);
      await loadPlanDetails(selectedPlan.id);
      if (run.status === "applied") {
        setNotice("Approved repair applied with hash-verified backups. Re-index the repository before verification.");
      } else {
        setError(run.error_message ?? `Repair application ended with status ${run.status}.`);
      }
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function rollbackApplication(runId: string) {
    if (!selectedPlan) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const run = await invoke<RepairApplicationRunRecord>("rollback_repair_application", { runId });
      if (projectId) await loadProjectData(projectId);
      await loadPlanDetails(selectedPlan.id);
      if (run.status === "rolled_back") {
        setNotice("Repair rollback restored the verified backup bytes. Re-index before approving or verifying another repair state.");
      } else {
        setError(run.error_message ?? `Repair rollback ended with status ${run.status}.`);
      }
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function verifyPlan() {
    if (!selectedPlan) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const run = await invoke<RepairVerificationRunRecord>("verify_repair_plan", { repairId: selectedPlan.id });
      setSelectedVerification(run);
      const items = await invoke<RepairVerificationItemRecord[]>("list_repair_verification_items", { runId: run.id, limit: 500 });
      setVerificationItems(items);
      if (projectId) {
        const nextPlans = await invoke<RepairPlanRecord[]>("list_repair_plans", { projectId, status: null, limit: 200 });
        setPlans(nextPlans);
        const refreshed = nextPlans.find((plan) => plan.id === selectedPlan.id);
        if (refreshed) setSelectedPlan(refreshed);
      }
      await loadPlanDetails(selectedPlan.id);
      setSelectedVerification(run);
      setVerificationItems(items);
      setNotice(`Verification recorded: ${run.status}. Verification compares the re-indexed repository with the approved proposal hashes.`);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function selectVerification(run: RepairVerificationRunRecord) {
    setSelectedVerification(run);
    setError(null);
    try {
      setVerificationItems(await invoke<RepairVerificationItemRecord[]>("list_repair_verification_items", { runId: run.id, limit: 500 }));
    } catch (value) {
      setVerificationItems([]);
      setError(String(value));
    }
  }

  async function changePlanFilter(next: PlanFilter) {
    setPlanFilter(next);
    if (!projectId) return;
    setError(null);
    try {
      await loadProjectData(projectId, next);
    } catch (value) {
      setError(String(value));
    }
  }

  function changeFinding(nextFindingId: string) {
    setFindingId(nextFindingId);
    const finding = findings.find((item) => item.id === nextFindingId);
    if (finding?.file_id && files.some((file) => file.id === finding.file_id)) {
      setFileId(finding.file_id);
      setSource(null);
      setProposedContent("");
    }
  }

  const proposedBytes = new TextEncoder().encode(proposedContent).length;
  const patchPreview = source && proposedContent !== source.content
    ? buildPatchPreview(source.content, proposedContent)
    : "";
  const editable = selectedPlan?.status === "draft";
  const verifiable = selectedPlan?.status === "approved" || selectedPlan?.status === "applied";

  return (
    <main className="standalone-workspace repair-workspace">
      <header>
        <div>
          <p className="eyebrow">HASH-VERIFIED REPAIR LAB</p>
          <h1>Verified Repair</h1>
          <p>Create reviewable full-file replacement proposals pinned to indexed hashes, apply them through the hash-verified Apply & Rollback lifecycle, and verify the re-indexed result. Repair application never executes project commands.</p>
        </div>
      </header>

      {error && <p className="error banner" role="alert">{error}</p>}
      {notice && <p className="success banner" role="status">{notice}</p>}

      <section className="panel">
        <div className="section-heading">
          <div>
            <h2>Project state</h2>
            <p>Indexing establishes the source hashes used as repair preconditions and later verification evidence.</p>
          </div>
          {projectId && <button onClick={() => void reindexProject()} disabled={busy}>Re-index repository state</button>}
        </div>
        <div className="row">
          <input aria-label="Repository path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="C:\\work\\project or /home/user/project" />
          <button onClick={() => void openProject()} disabled={busy || !path.trim()}>{busy && !projectId ? "Opening…" : "Open & index"}</button>
        </div>
        {projectId && <p className="mono workspace-project-id">Project {projectId}</p>}
      </section>

      {projectId && (
        <>
          <section className="repair-layout">
            <div className="twin-column">
              <section className="panel compact">
                <div className="section-heading">
                  <div><h2>Repair plans</h2><p>{plans.length} bounded result{plans.length === 1 ? "" : "s"}</p></div>
                  <select aria-label="Repair plan status" value={planFilter} onChange={(event) => void changePlanFilter(event.target.value as PlanFilter)}>
                    <option value="all">All</option>
                    <option value="draft">Draft</option>
                    <option value="approved">Approved</option>
                    <option value="applied">Applied / finding open</option>
                    <option value="verified">Verified</option>
                    <option value="rejected">Rejected</option>
                    <option value="superseded">Superseded</option>
                  </select>
                </div>
                <div className="result-list repair-scroll-list">
                  {plans.map((plan) => (
                    <button key={plan.id} className={`result-item ${selectedPlan?.id === plan.id ? "selected" : ""}`} onClick={() => void selectPlan(plan)}>
                      <strong>{plan.title}</strong>
                      <span>{plan.status}{plan.finding_id ? " · finding-linked" : ""}</span>
                      <small>{plan.updated_at}</small>
                    </button>
                  ))}
                  {!plans.length && <p className="empty">No repair plans match this filter.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>New draft</h2>
                <label>
                  Optional open finding
                  <select value={findingId} onChange={(event) => changeFinding(event.target.value)}>
                    <option value="">No finding link</option>
                    {findings.map((finding) => (
                      <option key={finding.id} value={finding.id}>{finding.severity} · {finding.title}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Title
                  <input value={title} maxLength={512} onChange={(event) => setTitle(event.target.value)} placeholder="Replace unsafe configuration path" />
                </label>
                <label>
                  Rationale
                  <textarea value={rationale} maxLength={16384} onChange={(event) => setRationale(event.target.value)} rows={5} placeholder="Why this replacement addresses the observed evidence and what remains to verify." />
                </label>
                <button onClick={() => void createPlan()} disabled={busy || !title.trim() || !rationale.trim()}>Create draft plan</button>
              </section>
            </div>

            <div className="twin-column">
              <section className="panel compact repair-detail-panel">
                <div className="section-heading">
                  <div>
                    <h2>{selectedPlan ? selectedPlan.title : "Plan detail"}</h2>
                    <p>{selectedPlan ? `${selectedPlan.status} · ${selectedPlan.id}` : "Select or create a plan."}</p>
                  </div>
                  {selectedPlan && <span className={`status-pill status-${selectedPlan.status}`}>{selectedPlan.status}</span>}
                </div>

                {selectedPlan ? (
                  <>
                    <p>{selectedPlan.rationale}</p>
                    {selectedPlan.finding_id && <p className="mono">Finding {selectedPlan.finding_id}</p>}
                    <div className="repair-actions">
                      <button onClick={() => void approvePlan()} disabled={busy || !editable || changes.length === 0}>Approve with base-hash check</button>
                      {selectedPlan.status === "approved" && <button onClick={() => void applyPlan()} disabled={busy}>Apply approved repair</button>}
                      <button className="secondary" onClick={() => void rejectPlan()} disabled={busy || !["draft", "approved", "applied"].includes(selectedPlan.status)}>Reject</button>
                      <button onClick={() => void verifyPlan()} disabled={busy || !verifiable}>Verify re-indexed state</button>
                    </div>
                    {selectedPlan.status === "approved" && <p className="warning banner">Apply performs a base-hash recheck, writes verified backups, and swaps only the approved full-file replacements. Re-index after application before verification.</p>}
                    {selectedPlan.status === "applied" && <p className="warning banner">Repository bytes were applied by CodeTwin. Re-index before verification; use the application history below to roll back to verified backups if needed.</p>}
                  </>
                ) : <p className="empty">No plan selected.</p>}
              </section>

              {selectedPlan && editable && (
                <section className="panel compact">
                  <h2>Full-file replacement</h2>
                  <p>Loading source is read-only and requires the current bytes to match the persisted index hash.</p>
                  <label>
                    Indexed file
                    <select value={fileId} onChange={(event) => { setFileId(event.target.value); setSource(null); setProposedContent(""); }}>
                      <option value="">Select a file</option>
                      {files.map((file) => <option key={file.id} value={file.id}>{file.relative_path}</option>)}
                    </select>
                  </label>
                  <button className="secondary" onClick={() => void loadSource()} disabled={busy || !fileId}>Load hash-verified source</button>
                  {source && (
                    <>
                      <div className="repair-source-meta">
                        <span>{source.relative_path}</span>
                        <span>{source.language ?? "unknown language"}</span>
                        <span>{source.byte_size} bytes</span>
                        <span className="mono" title={source.content_hash}>{source.content_hash.slice(0, 16)}…</span>
                      </div>
                      <label>
                        Proposed full file
                        <textarea className="repair-editor" value={proposedContent} onChange={(event) => setProposedContent(event.target.value)} spellCheck={false} />
                      </label>
                      <p className={proposedBytes > MAX_PROPOSED_BYTES ? "error" : "muted"}>{proposedBytes.toLocaleString()} / {MAX_PROPOSED_BYTES.toLocaleString()} UTF-8 bytes</p>
                      {patchPreview && (
                        <details className="repair-patch-preview" open>
                          <summary>Review patch before approval</summary>
                          <p>Plain-text preview only. The base SHA-256 is still rechecked before approval and again before application.</p>
                          <pre>{patchPreview}</pre>
                        </details>
                      )}
                      <button onClick={() => void saveReplacement()} disabled={busy || proposedBytes > MAX_PROPOSED_BYTES || proposedContent === source.content}>Save replacement proposal</button>
                    </>
                  )}
                </section>
              )}
            </div>
          </section>

          {selectedPlan && (
            <section className="repair-layout lower">
              <section className="panel compact">
                <h2>Proposed changes</h2>
                <div className="result-list repair-scroll-list">
                  {changes.map((change) => (
                    <article key={change.id} className="result-item static-item">
                      <strong>{change.relative_path}</strong>
                      <span>{change.proposed_byte_size.toLocaleString()} bytes</span>
                      <small className="mono">base {change.base_content_hash.slice(0, 16)}… → proposed {change.proposed_content_hash.slice(0, 16)}…</small>
                    </article>
                  ))}
                  {!changes.length && <p className="empty">No replacements have been proposed.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Apply & rollback history</h2>
                <div className="result-list repair-scroll-list">
                  {applicationHistory.map((run) => (
                    <article key={run.id} className="result-item static-item">
                      <strong>{run.status}</strong>
                      <span>{run.changes_applied} / {run.changes_total} applied{run.rollback_performed ? " · rollback performed" : ""}</span>
                      <small>{run.created_at}{run.completed_at ? ` → ${run.completed_at}` : ""}</small>
                      {run.error_message && <small>{run.error_message}</small>}
                      {run.status === "applied" && <button className="secondary" onClick={() => void rollbackApplication(run.id)} disabled={busy}>Rollback verified backup</button>}
                    </article>
                  ))}
                  {!applicationHistory.length && <p className="empty">No application runs yet.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Verification history</h2>
                <div className="result-list repair-scroll-list">
                  {verificationHistory.map((run) => (
                    <button key={run.id} className={`result-item ${selectedVerification?.id === run.id ? "selected" : ""}`} onClick={() => void selectVerification(run)}>
                      <strong>{run.status}</strong>
                      <span>{run.matched_changes} matched · {run.mismatched_changes} mismatch · {run.missing_changes} missing</span>
                      <small>{run.created_at}{run.finding_status ? ` · finding ${run.finding_status}` : ""}</small>
                    </button>
                  ))}
                  {!verificationHistory.length && <p className="empty">No verification runs yet.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Verification evidence</h2>
                {selectedVerification ? (
                  <div className="result-list repair-scroll-list">
                    {verificationItems.map((item) => (
                      <article key={item.change_id} className="result-item static-item">
                        <strong>{item.state}</strong>
                        <span className="mono">expected {item.expected_hash.slice(0, 20)}…</span>
                        <small className="mono">observed {item.observed_hash ? `${item.observed_hash.slice(0, 20)}…` : "missing"}</small>
                      </article>
                    ))}
                    {!verificationItems.length && <p className="empty">No per-change verification evidence returned.</p>}
                  </div>
                ) : <p className="empty">Select a verification run.</p>}
              </section>
            </section>
          )}
        </>
      )}
    </main>
  );
}
