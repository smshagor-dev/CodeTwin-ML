import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type { SecurityFindingRecord, SecurityRunRecord } from "../types";
import { EmptyState, PageHeader, Panel, ProjectSelect, StatusBadge, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function SecurityPage() {
  const { projects, activeProjectId, setActiveProjectId, operation, runSecurity, setToast } = useWorkspace();
  const [findings, setFindings] = useState<SecurityFindingRecord[]>([]);
  const [history, setHistory] = useState<SecurityRunRecord[]>([]);
  const [status, setStatus] = useState("open");
  const [query, setQuery] = useState("");

  async function load(projectId: string, nextStatus = status) {
    try {
      const [nextFindings, nextHistory] = await Promise.all([
        workspaceApi.securityFindings(projectId, nextStatus === "all" ? null : nextStatus, 500),
        workspaceApi.securityHistory(projectId, 50),
      ]);
      setFindings(nextFindings);
      setHistory(nextHistory);
    } catch (error) {
      setToast({ tone: "error", message: "Could not load security evidence: " + String(error) });
    }
  }

  useEffect(() => {
    if (!activeProjectId) {
      setFindings([]);
      setHistory([]);
      return;
    }
    void load(activeProjectId);
  }, [activeProjectId, status]);

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return findings;
    return findings.filter((finding) => [finding.title, finding.description, finding.rule_id, finding.cwe ?? "", finding.owasp ?? ""].some((value) => value.toLowerCase().includes(normalized)));
  }, [findings, query]);

  const severityCount = (severity: string) => findings.filter((finding) => finding.severity.toLowerCase() === severity).length;

  if (!projects.length) {
    return <><PageHeader eyebrow="STATIC APPLICATION SECURITY" title="Security" description="Run existing source-backed CodeTwin security rules on indexed projects."/><EmptyState icon="security" title="No project selected" description="Add and index a project before running static security analysis."/></>;
  }

  return (
    <div>
      <PageHeader
        eyebrow="STATIC APPLICATION SECURITY"
        title="Security"
        description="Security scans run the existing deterministic source analyzer against an indexed project. Registered website URLs are never probed for vulnerabilities from this page."
        actions={<div className="ws-header-tools"><ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/><button className="ws-button ws-button-primary" onClick={() => void runSecurity().then(() => activeProjectId && load(activeProjectId))} disabled={!activeProjectId || operation !== null}><Icon name="scan"/>{operation?.kind === "security" ? "Scanning…" : "Run Scan"}</button></div>}
      />

      <section className="ws-analysis-metrics">
        <div><span className="ws-critical"><Icon name="warning"/></span><strong>{severityCount("critical")}</strong><small>Critical</small></div>
        <div><span className="ws-high"><Icon name="security"/></span><strong>{severityCount("high")}</strong><small>High</small></div>
        <div><span><Icon name="security"/></span><strong>{severityCount("medium")}</strong><small>Medium</small></div>
        <div><span><Icon name="activity"/></span><strong>{history.length}</strong><small>Recent scan records</small></div>
      </section>

      <div className="ws-security-layout">
        <Panel title="Security findings" action={<div className="ws-inline-controls"><select aria-label="Finding status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="open">Open</option><option value="resolved">Resolved</option><option value="all">All</option></select></div>}>
          <label className="ws-search-field"><Icon name="search" size={18}/><input aria-label="Search security findings" placeholder="Search rule, title, CWE, OWASP…" value={query} onChange={(event) => setQuery(event.target.value)}/></label>
          <div className="ws-finding-list">
            {visible.map((finding) => (
              <article key={finding.id}>
                <StatusBadge status={finding.severity}/>
                <div><strong>{finding.title}</strong><p>{finding.description}</p><small>{finding.rule_id}{finding.cwe ? " · " + finding.cwe : ""}{finding.owasp ? " · " + finding.owasp : ""}</small></div>
                <time>{formatDate(finding.last_seen)}</time>
              </article>
            ))}
            {!visible.length && <p className="ws-inline-empty">No persisted findings match this view. CodeTwin does not invent vulnerability results.</p>}
          </div>
        </Panel>

        <Panel title="Scan history">
          <div className="ws-history-list">
            {history.map((run) => (
              <div key={run.run_id}><StatusBadge status={run.status}/><p><strong>{run.files_analyzed} files analyzed</strong><small>{run.findings_opened} opened · {run.findings_refreshed} refreshed · {run.findings_resolved} resolved</small></p><time>{formatDate(run.finished_at ?? run.started_at)}</time></div>
            ))}
            {!history.length && <p className="ws-inline-empty">No security scan history for this project yet.</p>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
