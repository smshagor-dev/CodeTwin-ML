import { useEffect, useState } from "react";
import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import { navigate } from "../routes";
import type { QaDiscoveryRunRecord, SecurityFindingRecord, SecurityRunRecord, SourceFileRecord } from "../types";
import { PageHeader, Panel, ProjectSelect, StatusBadge, displayPath, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

type Evidence = {
  projectId: string;
  findings: SecurityFindingRecord[];
  securityRuns: SecurityRunRecord[];
  testRuns: QaDiscoveryRunRecord[];
  files: SourceFileRecord[];
  errors: string[];
};

function openSourceSecurity() {
  window.location.hash = "#/security?mode=source";
}

export function DashboardPage() {
  const { projects, activeProjectId, activeProject, setActiveProjectId, operation,
    systemStatus, pickAndImportProject, runSecurity, runQaDiscovery } = useWorkspace();
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [retry, setRetry] = useState(0);
  const busy = operation !== null;

  useEffect(() => {
    if (!activeProjectId || busy) return;
    let cancelled = false;
    setEvidence(null);
    void Promise.allSettled([
      workspaceApi.securityFindings(activeProjectId, "open", 500),
      workspaceApi.securityHistory(activeProjectId, 8),
      workspaceApi.qaHistory(activeProjectId, 8),
      workspaceApi.listFiles(activeProjectId, null, 500),
    ]).then(([findings, securityRuns, testRuns, files]) => {
      if (cancelled) return;
      const results = [findings, securityRuns, testRuns, files];
      const labels = ["Findings", "Security history", "Test discovery history", "Source paths"];
      setEvidence({
        projectId: activeProjectId,
        findings: findings.status === "fulfilled" ? findings.value : [],
        securityRuns: securityRuns.status === "fulfilled" ? securityRuns.value : [],
        testRuns: testRuns.status === "fulfilled" ? testRuns.value : [],
        files: files.status === "fulfilled" ? files.value : [],
        errors: results.flatMap((result, index) => result.status === "rejected" ? [labels[index] + " unavailable: " + String(result.reason)] : []),
      });
    });
    return () => { cancelled = true; };
  }, [activeProjectId, busy, retry]);

  const current = evidence?.projectId === activeProjectId ? evidence : null;
  const findings = [...(current?.findings ?? [])].sort((a, b) => b.last_seen.localeCompare(a.last_seen)).slice(0, 5);
  const paths = new Map(current?.files.map(file => [file.id, file.relative_path]) ?? []);
  const runs = [
    ...(current?.securityRuns ?? []).map(run => ({ id: run.run_id, label: "Static analysis", status: run.status,
      duration: run.duration_ms, date: run.finished_at ?? run.started_at, incomplete: !run.coverage_complete, route: "security" as const })),
    ...(current?.testRuns ?? []).map(run => ({ id: run.run_id, label: "Test discovery", status: run.status,
      duration: run.duration_ms, date: run.finished_at ?? run.started_at, incomplete: !run.coverage_complete, route: "testing" as const })),
    ...(activeProject?.last_index_status ? [{ id: "latest-index", label: "Project indexing", status: activeProject.last_index_status,
      duration: activeProject.last_index_duration_ms, date: activeProject.last_indexed_at, incomplete: false, route: "code-analysis" as const }] : []),
  ].sort((a, b) => (b.date ?? "").localeCompare(a.date ?? "")).slice(0, 5);

  return (
    <div className="ws-overview">
      <PageHeader title="Workspace Overview" description="Index, inspect and validate your code."
        actions={<div className="ws-overview-project-tools">
          <ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId} label="Active project"/>
          <button className="ws-button ws-button-secondary" disabled={busy} onClick={() => void pickAndImportProject()}><Icon name="plus"/>Add project</button>
        </div>}/>
      <section className="ws-overview-project" aria-label="Project summary">
        {activeProject ? <>
          <div className="ws-overview-project-heading">
            <div><h2>{activeProject.display_name}</h2><p className="ws-mono" title={displayPath(activeProject.root_path)}>{displayPath(activeProject.root_path)}</p></div>
            <span>Indexed {formatDate(activeProject.last_indexed_at)}</span>
          </div>
          <dl className="ws-overview-metrics">
            <div><dt>Files</dt><dd>{activeProject.file_count.toLocaleString()}</dd></div>
            <div><dt>Symbols</dt><dd>{activeProject.symbol_count.toLocaleString()}</dd></div>
            <div><dt>Index</dt><dd><StatusBadge status={activeProject.last_index_status ?? "not_indexed"}/></dd></div>
            <div><dt>Languages</dt><dd>{activeProject.language_count.toLocaleString()}</dd></div>
          </dl>
        </> : <div className="ws-overview-empty-project"><Icon name="folder" size={24}/><div><h2>Add your first project</h2><p>Choose a local folder to index its files and symbols.</p></div></div>}
      </section>
      <div className="ws-overview-actions" aria-label="Analysis actions">
        <button className="ws-button ws-button-secondary" disabled={!activeProject} onClick={() => navigate("code-analysis")}><Icon name="code"/>Code Analysis</button>
        <button className="ws-button ws-button-primary" disabled={!activeProject || busy} title="Run static source analysis on the selected local project" onClick={() => void runSecurity()}><Icon name="security"/>{operation?.kind === "security" ? "Scanning…" : "Run Security Scan"}</button>
        <button className="ws-button ws-button-secondary" disabled={!activeProject || busy} onClick={() => void runQaDiscovery()}><Icon name="testing"/>{operation?.kind === "testing" ? "Discovering…" : "Discover Tests"}</button>
        {activeProject && <button className="ws-text-button ws-overview-view-project" onClick={() => { window.location.hash = "#/projects?project=" + encodeURIComponent(activeProject.id); }}>View project →</button>}
      </div>
      {current && current.errors.length > 0 && <div className="ws-overview-error" role="alert"><div><strong>Evidence unavailable</strong>{current.errors.map(error => <p key={error}>{error}</p>)}</div><button className="ws-button ws-button-secondary" disabled={busy} onClick={() => setRetry(value => value + 1)}>Retry</button></div>}
      <Panel title="Latest findings" action={<button className="ws-text-button" onClick={openSourceSecurity}>View all →</button>}>
        {!activeProject ? <p className="ws-inline-empty">Select an indexed project to view source findings.</p> : !current ? <p className="ws-inline-empty" role="status">Loading project evidence…</p> : findings.length ? <>
          <div className="ws-table-wrap"><table className="ws-table ws-overview-table"><thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>Status</th></tr></thead><tbody>
            {findings.map(finding => <tr key={finding.id}>
              <td><StatusBadge status={finding.severity}/></td><td><button className="ws-overview-finding-link" onClick={openSourceSecurity}>{finding.title}</button></td>
              <td className="ws-mono">{finding.file_id ? (paths.get(finding.file_id) ?? "Source path unavailable") : "Project"}{finding.source_start_line !== null ? ":" + finding.source_start_line : ""}</td>
              <td><StatusBadge status={finding.status}/></td>
            </tr>)}
          </tbody></table></div>
          <p className="ws-overview-table-note">Showing {findings.length} latest open source findings. Review scope and coverage in Security.</p>
        </> : <p className="ws-inline-empty">{current.errors.some(error => error.startsWith("Findings")) ? "Findings could not be loaded. Retry the evidence read." : current.securityRuns.length ? "No persisted open source findings for this project. Review scan coverage in Security." : "No source analysis yet. Run a security scan to collect findings."}</p>}
      </Panel>
      <Panel title="Recent runs" action={<button className="ws-text-button" onClick={() => navigate("testing")}>View tests →</button>}>
        {!activeProject ? <p className="ws-inline-empty">Index a project to start collecting run history.</p> : !current ? <p className="ws-inline-empty" role="status">Loading run history…</p> : runs.length ? <div className="ws-table-wrap"><table className="ws-table ws-overview-table"><thead><tr><th>Run</th><th>Project</th><th>Status</th><th>Duration</th><th>Finished / started</th></tr></thead><tbody>
          {runs.map(run => <tr key={run.label + run.id}><td><button className="ws-overview-finding-link" onClick={() => run.route === "security" ? openSourceSecurity() : navigate(run.route)}>{run.label}</button></td><td>{activeProject.display_name}</td><td><StatusBadge status={run.status}/>{run.incomplete && <small>Coverage incomplete</small>}</td><td>{run.duration === null ? "—" : (run.duration / 1000).toLocaleString(undefined, { maximumFractionDigits: 2 }) + "s"}</td><td>{formatDate(run.date)}</td></tr>)}
        </tbody></table></div> : <p className="ws-inline-empty">No persisted analysis runs yet.</p>}
      </Panel>
      <footer className="ws-overview-status" aria-label="Local system status">
        {systemStatus.filter(entry => ["backend", "database", "indexer"].includes(entry.key)).map(entry => <span key={entry.key} title={entry.detail}><i className={"ws-system-dot ws-system-" + entry.state}/>{entry.label} · {entry.state}</span>)}
        {!systemStatus.length && <span>System status unavailable</span>}
        <button className="ws-text-button" onClick={() => navigate("support")}>Diagnostics →</button>
      </footer>
    </div>
  );
}
