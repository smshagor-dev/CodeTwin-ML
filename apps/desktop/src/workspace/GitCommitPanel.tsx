import { useEffect, useRef, useState } from "react";
import { workspaceApi } from "./api";
import type { GitCommitPreview, GitCommitReceipt, GitReviewStatus } from "./types";

export function GitCommitPanel({ projectId, status }: { projectId: string; status: GitReviewStatus }) {
  const [paths, setPaths] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [preview, setPreview] = useState<GitCommitPreview | null>(null);
  const [receipt, setReceipt] = useState<GitCommitReceipt | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const running = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const staged = status.changes.filter((change) => change.staged !== " " && change.staged !== "?");
  const ready = !!status.head && !!status.branch && paths.length > 0 && name.trim() && email.trim() && message.trim();
  function invalidate() { setPreview(null); setError(null); }
  async function action(commit: boolean) {
    if (running.current || receipt || !ready || !status.head || !status.branch) return;
    if (commit && !preview) return;
    running.current = true; setBusy(true); setError(null);
    try {
      if (commit && preview) {
        const result = await workspaceApi.gitApplyCommit(projectId, preview.request, preview.digest);
        if (mounted.current) { setReceipt(result); setPreview(null); }
      } else {
        const result = await workspaceApi.gitPrepareCommit(projectId, { branch: status.branch, head: status.head, paths, name, email, message });
        if (mounted.current) setPreview(result);
      }
    } catch (cause: unknown) {
      if (mounted.current) { setError(String(cause)); setPreview(null); }
    } finally {
      running.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  return <details className="ws-git-commit">
    <summary>Commit selected staged files</summary>
    <p className="ws-form-help">Stage files with Git first. Select paths and review the exact staged snapshot before committing. Unstaged edits and other staged files are preserved. Commits are unsigned; the entered author is not authenticated.</p>
    {!status.head || !status.branch ? <p className="ws-form-help">An initialized, named branch is required.</p> : <>
      <fieldset disabled={busy || !!receipt}>
        <legend>Staged paths</legend>
        {!staged.length && <p className="ws-inline-empty">No staged changes. Stage files externally, then refresh Git changes.</p>}
        {staged.map((change) => <label className="ws-git-commit-path" key={change.path}><input type="checkbox" checked={paths.includes(change.path)} onChange={(event) => { const checked = event.target.checked; setPaths((current) => checked ? [...current, change.path] : current.filter((path) => path !== change.path)); invalidate(); }} /><span>{change.path}{change.original_path && <small> · {change.staged === "R" ? "includes original path" : "source path"} {change.original_path}</small>}</span></label>)}
        <div className="ws-git-commit-fields">
          <label>Commit author name<input className="ws-input" value={name} maxLength={100} onChange={(event) => { setName(event.target.value); invalidate(); }} /></label>
          <label>Commit author email<input className="ws-input" type="email" value={email} maxLength={254} onChange={(event) => { setEmail(event.target.value); invalidate(); }} /></label>
          <label>Commit message<textarea className="ws-input" value={message} maxLength={4096} rows={3} onChange={(event) => { setMessage(event.target.value); invalidate(); }} /></label>
        </div>
      </fieldset>
      <button className="ws-button ws-button-secondary" disabled={busy || !ready || !!receipt} onClick={() => void action(false)}>{busy ? "Checking commit…" : "Prepare selected commit review"}</button>
      {preview && <div aria-label="Selected commit preview">
        <p className="ws-form-help">Branch {preview.request.branch} · author {preview.request.name} &lt;{preview.request.email}&gt;</p>
        <p className="ws-mono">Parent {preview.request.head}</p>
        <p>{preview.request.message}</p>
        <ul>{preview.paths.map((path) => <li key={path}>{path}</li>)}</ul>
        <pre className="ws-git-diff">{preview.patch}</pre>
        <button className="ws-button" disabled={busy} onClick={() => void action(true)}>Commit reviewed staged snapshot</button>
      </div>}
    </>}
    {error && <p className="ws-warning-box" role="alert">Commit action failed: {error}. Refresh Git changes and prepare a new review before retrying.</p>}
    {receipt && <p role="status">Committed <span className="ws-mono">{receipt.commit}</span> to {receipt.branch}. Refresh Git changes to see the current state.</p>}
  </details>;
}
