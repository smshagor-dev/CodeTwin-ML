import { useEffect, useState } from "react";
import { GitPublishPanel } from "./GitPublishPanel";
import { GitCommitPanel } from "./GitCommitPanel";
import { GitBranchPanel } from "./GitBranchPanel";
import { workspaceApi } from "./api";
import type { GitFileReview, GitReviewStatus } from "./types";

function changeLabel(code: string) {
  return ({ " ": "unchanged", "?": "untracked", M: "modified", A: "added", D: "deleted", R: "renamed", C: "copied", U: "conflicted", T: "type changed" } as Record<string, string>)[code] ?? code;
}

export function GitReviewPanel({ projectId }: { projectId: string }) {
  const [enabled, setEnabled] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [status, setStatus] = useState<GitReviewStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [path, setPath] = useState<string | null>(null);
  const [review, setReview] = useState<GitFileReview | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setLoading(true); setError(null); setStatus(null); setPath(null);
    void workspaceApi.gitStatus(projectId).then((next) => {
      if (!cancelled) setStatus(next);
    }).catch((cause: unknown) => {
      if (!cancelled) setError(String(cause));
    }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [projectId, enabled, refresh]);

  useEffect(() => {
    let cancelled = false;
    setReview(null); setReviewError(null);
    if (!path) { setReviewLoading(false); return; }
    setReviewLoading(true);
    void workspaceApi.gitFile(projectId, path).then((next) => {
      if (!cancelled) setReview(next);
    }).catch((cause: unknown) => {
      if (!cancelled) setReviewError(String(cause));
    }).finally(() => { if (!cancelled) setReviewLoading(false); });
    return () => { cancelled = true; };
  }, [projectId, path, refresh]);

  return <section className="ws-detail-section ws-git-review" aria-label="Git change review">
    <h3>Git changes</h3>
    <p className="ws-form-help">Review local staged and working-tree changes. Refresh to read current files. Review is read-only. Use the separate actions below to create a branch or commit selected staged files.</p>
    <button className="ws-button ws-button-secondary" disabled={loading} onClick={() => { setEnabled(true); setRefresh((value) => value + 1); }}>{loading ? "Reading Git changes…" : enabled ? "Refresh Git changes" : "Load Git changes"}</button>
    {error && <p role="alert" className="ws-warning-box">Git review unavailable: {error}</p>}
    {status && <>
      <dl className="ws-detail-grid"><dt>Branch</dt><dd>{status.branch ?? (status.head ? "Detached HEAD" : "Unborn branch")}</dd><dt>HEAD</dt><dd className="ws-mono">{status.head ?? "No commits yet"}</dd></dl>
      <GitPublishPanel key={"publish:" + projectId + ":" + refresh} projectId={projectId} status={status} />
      <GitCommitPanel key={"commit:" + projectId + ":" + refresh} projectId={projectId} status={status} />
      <GitBranchPanel key={projectId + ":" + refresh} projectId={projectId} status={status} />
      {!status.changes.length && <p className="ws-inline-empty">Working tree is clean.</p>}
      <div className="ws-list-stack">{status.changes.map((change) => <button key={change.path} className={"ws-project-row " + (path === change.path ? "selected" : "")} aria-pressed={path === change.path} onClick={() => setPath(change.path)}>
        <span className="ws-list-main"><strong>{change.path}</strong>{change.original_path && <small>From {change.original_path}</small>}<small>{change.staged === "?" ? "Untracked file" : "Staged: " + changeLabel(change.staged) + " · Working tree: " + changeLabel(change.unstaged)}</small></span>
      </button>)}</div>
    </>}
    {reviewLoading && <p role="status">Loading file review…</p>}
    {reviewError && <p role="alert" className="ws-warning-box">File review unavailable: {reviewError}. Refresh Git changes to retry.</p>}
    {review && <div aria-label="Selected file review">
      <h4>{review.path}</h4>
      {review.notice && <p className="ws-warning-box">{review.notice}</p>}
      {review.staged_diff && <details open><summary>Staged diff</summary><pre className="ws-git-diff">{review.staged_diff}</pre></details>}
      {review.unstaged_diff && <details open><summary>Working-tree diff</summary><pre className="ws-git-diff">{review.unstaged_diff}</pre></details>}
      {review.untracked_content !== null && <details open><summary>Untracked file content</summary><pre className="ws-git-diff">{review.untracked_content || "Empty file"}</pre></details>}
    </div>}
  </section>;
}
