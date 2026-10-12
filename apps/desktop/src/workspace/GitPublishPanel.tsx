import { useEffect, useRef, useState } from "react";
import { workspaceApi } from "./api";
import type { GitPublishReceipt, GitReviewStatus } from "./types";

export function GitPublishPanel({ projectId, status }: { projectId: string; status: GitReviewStatus }) {
  const [repository, setRepository] = useState("");
  const [token, setToken] = useState("");
  const [base, setBase] = useState("main");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [receipt, setReceipt] = useState<GitPublishReceipt | null>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const running = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const valid = !!status.branch && !!status.head && /^[a-f0-9]{40}$/.test(status.head) && /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repository) && token.length >= 10;
  const published = receipt?.repository === repository && receipt.branch === status.branch && receipt.commit === status.head;
  async function action(pr: boolean) {
    if (running.current || !valid || !status.branch || !status.head || (pr && (!published || !title.trim() || !base || base === status.branch))) return;
    running.current = true; setBusy(true); setError(null);
    const target = { repository, branch: status.branch, commit: status.head };
    try {
      if (pr) {
        const url = await workspaceApi.gitOpenDraftPr(projectId, target, base, title, body, token);
        if (mounted.current) { setPrUrl(url); setToken(""); }
      } else {
        const next = await workspaceApi.gitPublishCommit(projectId, target, token);
        if (mounted.current) { setReceipt(next); setPrUrl(null); }
      }
    } catch (cause: unknown) {
      if (mounted.current) { setError(String(cause)); if (!pr) setReceipt(null); }
    } finally {
      running.current = false; if (mounted.current) setBusy(false);
    }
  }
  return <details className="ws-git-commit">
    <summary>Publish commit and open draft PR</summary>
    <p className="ws-form-help">Publish the displayed HEAD to GitHub, then explicitly open a draft PR. One unsigned commit, with its parent already on GitHub, is supported. Default branches and force updates are blocked. Refresh after a local commit.</p>
    <p className="ws-form-help">Token permissions: repository Contents write and Pull requests write; workflow changes may also need Workflows write. The token is held in memory for this panel and is cleared after PR success or when you refresh or switch projects.</p>
    <p className="ws-mono">{status.branch ?? "No named branch"} · {status.head ?? "No commit"}</p>
    <fieldset disabled={busy} className="ws-git-commit-fields">
      <legend>GitHub destination</legend>
      <label>GitHub repository<input className="ws-input" placeholder="owner/repository" value={repository} onChange={(event) => { setRepository(event.target.value); setReceipt(null); setPrUrl(null); setError(null); }} /></label>
      <label>GitHub token<input className="ws-input" type="password" autoComplete="off" spellCheck={false} value={token} maxLength={1024} onChange={(event) => { setToken(event.target.value); setError(null); }} /></label>
      <button className="ws-button ws-button-secondary" disabled={!token} onClick={() => setToken("")}>Clear GitHub token</button>
    </fieldset>
    <button className="ws-button ws-button-secondary" disabled={busy || !valid} onClick={() => void action(false)}>Publish displayed commit</button>
    {published && <p role="status">Verified published commit <span className="ws-mono">{receipt.commit}</span> on {receipt.repository}/{receipt.branch}.</p>}
    <fieldset disabled={busy} className="ws-git-commit-fields">
      <legend>Draft pull request</legend>
      <label>PR base branch<input className="ws-input" value={base} maxLength={120} onChange={(event) => { setBase(event.target.value); setPrUrl(null); }} /></label>
      <label>PR title<input className="ws-input" value={title} maxLength={200} onChange={(event) => { setTitle(event.target.value); setPrUrl(null); }} /></label>
      <label>PR description<textarea className="ws-input" value={body} maxLength={20000} rows={3} onChange={(event) => { setBody(event.target.value); setPrUrl(null); }} /></label>
    </fieldset>
    <button className="ws-button" disabled={busy || !valid || !published || !title.trim() || !base || base === status.branch} onClick={() => void action(true)}>Open draft PR</button>
    {error && <p role="alert" className="ws-warning-box">GitHub action failed: {error}. A remote action may have completed; verify GitHub before retrying.</p>}
    {prUrl && /^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/pull\/\d+$/.test(prUrl) && <a href={prUrl} target="_blank" rel="noopener noreferrer">View draft PR</a>}
  </details>;
}
