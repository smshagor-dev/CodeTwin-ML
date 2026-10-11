import { useEffect, useMemo, useRef, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type { RepairSourceSnapshot, SourceFileRecord, SecurityFindingRecord, SecurityRunRecord } from "../types";
import { Disclosure, EmptyState, Panel, ProjectSelect, StatusBadge, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function StaticSecurityPanel() {
  const { projects, activeProjectId, setActiveProjectId, operation, runSecurity, setToast } = useWorkspace();
  const [findings, setFindings] = useState<SecurityFindingRecord[]>([]);
  const [history, setHistory] = useState<SecurityRunRecord[]>([]);
  const requestId = useRef(0);
  const [files, setFiles] = useState<SourceFileRecord[]>([]);
  const [source, setSource] = useState<RepairSourceSnapshot | null>(null);
  const [sourceError, setSourceError] = useState<string | null>(null);
  const [sourceBusy, setSourceBusy] = useState(false);
  const sourceRequest = useRef(0);
  const [status, setStatus] = useState("open");
  const [query, setQuery] = useState("");

  async function load(projectId: string, nextStatus = status) {
    const request = ++requestId.current;
    try {
      const [nextFindings, nextHistory, nextFiles] = await Promise.all([
        workspaceApi.securityFindings(projectId, nextStatus === "all" ? null : nextStatus, 500),
        workspaceApi.securityHistory(projectId, 50),
        workspaceApi.listFiles(projectId),
      ]);
      if (request !== requestId.current) return;
      setFiles(nextFiles);
      setFindings(nextFindings);
      setHistory(nextHistory);
    } catch (error) {
      if (request !== requestId.current) return;
      setToast({ tone: "error", message: "Could not load static security evidence: " + String(error) });
    }
  }

  useEffect(() => {
    sourceRequest.current++;
    setSource(null);
    setSourceError(null);
    setSourceBusy(false);
    setFindings([]);
    setHistory([]);
    setFiles([]);
    if (!activeProjectId) {
      setFindings([]);
      setHistory([]);
      return;
    }
    void load(activeProjectId);
    return () => { requestId.current++; sourceRequest.current++; };
  }, [activeProjectId, status]);

  async function readEvidence(fileId: string) {
    const request = ++sourceRequest.current;
    setSource(null);
    setSourceError(null);
    setSourceBusy(true);
    try {
      const snapshot = await workspaceApi.readRepairSource(fileId);
      if (request === sourceRequest.current) setSource(snapshot);
    } catch (error) {
      if (request === sourceRequest.current) setSourceError(String(error));
    } finally {
      if (request === sourceRequest.current) setSourceBusy(false);
    }
  }

  const sourcePaths = useMemo(() => new Map(files.map((file) => [file.id, file.relative_path])), [files]);

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return findings;
    return findings.filter((finding) =>
      [finding.title, finding.description, finding.rule_id, finding.cwe ?? "", finding.owasp ?? ""]
        .some((value) => value.toLowerCase().includes(normalized)),
    );
  }, [findings, query]);

  const severityCount = (severity: string) =>
    findings.filter((finding) => finding.severity.toLowerCase() === severity).length;

  if (!projects.length) {
    return (
      <EmptyState
        icon="security"
        title="No indexed project"
        description="Static source security analysis uses CodeTwin's existing persistent source index. Import a project first, or use Authorized Web Testing for a separately authorized web target."
      />
    );
  }

  return (
    <div className="ws-security-tab-content">
      <div className="ws-security-toolbar">
        <ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/>
        <button
          className="ws-button ws-button-primary"
          onClick={() => void runSecurity().then(() => (activeProjectId ? load(activeProjectId) : undefined))}
          disabled={!activeProjectId || operation !== null}
        >
          <Icon name="scan"/>
          {operation?.kind === "security" ? "Scanning…" : "Run Static Scan"}
        </button>
      </div>

      <section className="ws-analysis-metrics">
        <div><span className="ws-critical"><Icon name="warning"/></span><strong>{severityCount("critical")}</strong><small>Critical</small></div>
        <div><span className="ws-high"><Icon name="security"/></span><strong>{severityCount("high")}</strong><small>High</small></div>
        <div><span><Icon name="security"/></span><strong>{severityCount("medium")}</strong><small>Medium</small></div>
        <div><span><Icon name="activity"/></span><strong>{history.length}</strong><small>Recent runs</small></div>
      </section>

      {sourceError && <p role="alert">Source evidence unavailable: {sourceError}</p>}
      {source && <Panel title={"Source evidence · " + source.relative_path}>
        <p className="ws-form-help">Current bytes verified against the indexed SHA-256. A rule match requires review; it does not prove exploitability.</p>
        <p className="mono" style={{ overflowWrap: "anywhere" }}>SHA-256: {source.content_hash}</p>
        <pre style={{ overflow: "auto", maxHeight: 360 }}><code>{source.content.split("\n").map((line, index) => `${index + 1}: ${line}`).join("\n")}</code></pre>
        <button className="ws-button ws-button-secondary" onClick={() => setSource(null)}>Close evidence</button>
      </Panel>}
      <div className="ws-static-layout">
        <Panel
          title="Static source findings"
          action={
            <select aria-label="Static finding status" value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="all">All</option>
            </select>
          }
        >
          <label className="ws-search-field">
            <Icon name="search" size={18}/>
            <input
              aria-label="Search static security findings"
              placeholder="Search rule, title, CWE, OWASP…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <div className="ws-finding-list">
            {visible.map((finding) => (
              <article key={finding.id}>
                <StatusBadge status={finding.severity}/>
                <div>
                  <strong>{finding.title}</strong>
                  <p>{finding.description}</p>
                  <small>{sourcePaths.get(finding.file_id ?? "") ?? "Source path unavailable"}{finding.source_start_line ? ":" + finding.source_start_line : ""} · {finding.status}</small>
                  <div className="ws-header-tools">
                    {finding.file_id && <button className="ws-button ws-button-secondary" disabled={sourceBusy} onClick={() => void readEvidence(finding.file_id!)}>View source evidence</button>}
                    {finding.status === "open" && finding.file_id && <a className="ws-button ws-button-secondary" href={"#/repair?project=" + encodeURIComponent(finding.project_id) + "&finding=" + encodeURIComponent(finding.id)}>Create repair proposal</a>}
                  </div>
                  <small>{finding.rule_id}{finding.cwe ? " · " + finding.cwe : ""}{finding.owasp ? " · " + finding.owasp : ""}</small>
                </div>
                <time>{formatDate(finding.last_seen)}</time>
              </article>
            ))}
            {!visible.length && <p className="ws-inline-empty">No persisted static findings match this view.</p>}
          </div>
        </Panel>

        <Disclosure title="Static scan history">
          <Panel title="Static scan history">
          <div className="ws-history-list">
            {history.map((run) => (
              <div key={run.run_id}>
                <StatusBadge status={run.status}/>
                <p>
                  <strong>{run.files_analyzed} files analyzed</strong>
                  <small>{run.findings_opened} opened · {run.findings_refreshed} refreshed · {run.findings_resolved} resolved</small>
                </p>
                <time>{formatDate(run.finished_at ?? run.started_at)}</time>
              </div>
            ))}
            {!history.length && <p className="ws-inline-empty">No static security scan history for this project yet.</p>}
          </div>
        </Panel>
        </Disclosure>
      </div>
    </div>
  );
}
