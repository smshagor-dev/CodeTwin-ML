import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type { QaArtifactRecord, QaDiscoveryRunRecord, QaFrameworkSummary } from "../types";
import { EmptyState, PageHeader, Panel, ProjectSelect, StatusBadge, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function TestingPage() {
  const { projects, activeProjectId, setActiveProjectId, operation, runQaDiscovery, setToast } = useWorkspace();
  const [artifacts, setArtifacts] = useState<QaArtifactRecord[]>([]);
  const [frameworks, setFrameworks] = useState<QaFrameworkSummary[]>([]);
  const [history, setHistory] = useState<QaDiscoveryRunRecord[]>([]);
  const [framework, setFramework] = useState("all");

  async function load(projectId: string) {
    try {
      const [nextArtifacts, nextFrameworks, nextHistory] = await Promise.all([
        workspaceApi.qaArtifacts(projectId, 500),
        workspaceApi.qaFrameworks(projectId),
        workspaceApi.qaHistory(projectId, 50),
      ]);
      setArtifacts(nextArtifacts);
      setFrameworks(nextFrameworks);
      setHistory(nextHistory);
    } catch (error) {
      setToast({ tone: "error", message: "Could not load QA evidence: " + String(error) });
    }
  }

  useEffect(() => {
    if (!activeProjectId) {
      setArtifacts([]);
      setFrameworks([]);
      setHistory([]);
      return;
    }
    void load(activeProjectId);
  }, [activeProjectId]);

  const visible = useMemo(() => framework === "all" ? artifacts : artifacts.filter((artifact) => artifact.framework === framework), [artifacts, framework]);

  if (!projects.length) {
    return <><PageHeader eyebrow="QA EVIDENCE" title="Testing" description="Discover test files and framework configuration without executing untrusted repository code."/><EmptyState icon="testing" title="No project selected" description="Add an indexed project before discovering QA evidence."/></>;
  }

  return (
    <div>
      <PageHeader
        eyebrow="QA EVIDENCE"
        title="Testing"
        description="CodeTwin currently supports passive test discovery. Public test execution is intentionally disabled until the sandbox enforces every required isolation capability."
        actions={<div className="ws-header-tools"><ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/><button className="ws-button ws-button-primary" onClick={() => void runQaDiscovery().then(() => activeProjectId && load(activeProjectId))} disabled={!activeProjectId || operation !== null}><Icon name="testing"/>{operation?.kind === "testing" ? "Discovering…" : "Discover Tests"}</button></div>}
      />

      <div className="ws-limitation-banner"><Icon name="warning"/><div><strong>Test execution unavailable</strong><p>No pass/fail or coverage result is fabricated. This workspace inventories test evidence only because the current QA execution service reports execution disabled.</p></div></div>

      <section className="ws-analysis-metrics">
        <div><span><Icon name="testing"/></span><strong>{artifacts.filter((item) => item.artifact_kind === "test_file").length}</strong><small>Test files</small></div>
        <div><span><Icon name="settings"/></span><strong>{artifacts.filter((item) => item.artifact_kind === "config_file").length}</strong><small>Config evidence</small></div>
        <div><span><Icon name="integrations"/></span><strong>{frameworks.length}</strong><small>Frameworks</small></div>
        <div><span><Icon name="activity"/></span><strong>{history.length}</strong><small>Discovery runs</small></div>
      </section>

      <div className="ws-security-layout">
        <Panel title="Discovered QA evidence" action={<select aria-label="Filter QA framework" value={framework} onChange={(event) => setFramework(event.target.value)}><option value="all">All frameworks</option>{frameworks.map((item) => <option key={item.framework} value={item.framework}>{item.framework}</option>)}</select>}>
          <div className="ws-artifact-list">
            {visible.map((artifact) => <div key={artifact.id}><Icon name={artifact.artifact_kind === "test_file" ? "testing" : "settings"} size={18}/><p><strong>{artifact.relative_path}</strong><small>{artifact.framework} · {artifact.evidence_kind}</small></p><StatusBadge status={artifact.is_active ? "active" : "inactive"}/></div>)}
            {!visible.length && <p className="ws-inline-empty">No QA artifacts have been discovered for this filter.</p>}
          </div>
        </Panel>
        <Panel title="Discovery history">
          <div className="ws-history-list">
            {history.map((run) => <div key={run.run_id}><StatusBadge status={run.status}/><p><strong>{run.artifacts_discovered} artifacts discovered</strong><small>{run.test_files} tests · {run.config_files} configs · {run.framework_count} frameworks</small></p><time>{formatDate(run.finished_at ?? run.started_at)}</time></div>)}
            {!history.length && <p className="ws-inline-empty">No QA discovery runs yet.</p>}
          </div>
        </Panel>
      </div>
    </div>
  );
}
