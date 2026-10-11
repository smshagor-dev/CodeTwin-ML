import { useEffect, useRef, useState } from "react";
import { workspaceApi } from "./api";
import type { GitReviewStatus } from "./types";

export function GitBranchPanel({ projectId, status }: { projectId: string; status: GitReviewStatus }) {
  const [branch, setBranch] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<{ branch: string; head: string } | null>(null);
  const mounted = useRef(true);
  const running = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  async function create() {
    if (!status.head || !status.branch || running.current) return;
    running.current = true;
    setBusy(true); setError(null); setReceipt(null);
    try {
      const result = await workspaceApi.gitCreateBranch(projectId, branch, status.head);
      if (mounted.current) { setReceipt(result); setBranch(""); }
    } catch (cause: unknown) {
      if (mounted.current) setError(String(cause));
    } finally {
      running.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  return <details className="ws-git-branch">
    <summary>Create branch</summary>
    <p className="ws-form-help">Create a local branch at the reviewed HEAD. Your current branch and staged files stay in place. Switch branches with Git when ready.</p>
    {!status.head || !status.branch ? <p className="ws-form-help">Load an initialized, named branch to create a new branch.</p> : <form onSubmit={(event) => { event.preventDefault(); void create(); }}>
      <label>New branch name<input className="ws-input" value={branch} maxLength={120} required disabled={busy} autoComplete="off" spellCheck={false} onChange={(event) => { setBranch(event.target.value); setError(null); setReceipt(null); }} placeholder="feature/security-review" /></label>
      <button className="ws-button ws-button-secondary" disabled={busy || !branch || !/^[A-Za-z0-9/._-]{1,120}$/.test(branch)} type="submit">{busy ? "Creating branch…" : "Create at reviewed HEAD"}</button>
    </form>}
    {error && <p className="ws-warning-box" role="alert">Branch creation failed: {error}. Refresh Git changes before retrying.</p>}
    {receipt && <p role="status">Created {receipt.branch} at <span className="ws-mono">{receipt.head}</span>.</p>}
  </details>;
}
