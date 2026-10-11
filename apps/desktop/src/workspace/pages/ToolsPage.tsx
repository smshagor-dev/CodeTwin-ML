import { useEffect, useMemo, useState } from "react";
import { workspaceApi } from "../api";
import { navigate, routeHref } from "../routes";
import { availabilityLabels, filterTools, toolAction } from "../toolCatalog";
import type { CatalogRunSummary, CatalogTool } from "../types";
import { Disclosure, LoadingState, PageHeader, Panel, ProjectSelect, StatusBadge, formatDate } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

import { AssessmentPanel } from "../AssessmentPanel";

export function ToolsPage() {
  const { projects, activeProjectId, setActiveProjectId } = useWorkspace();
  const [tools, setTools] = useState<CatalogTool[]>([]);
  const [runs, setRuns] = useState<CatalogRunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [availability, setAvailability] = useState("");
  const [operation, setOperation] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError(null); setRunError(null); setTools([]); setRuns([]);
    void Promise.allSettled([workspaceApi.securityTools(activeProjectId), workspaceApi.securityToolRuns(activeProjectId)]).then(([catalog, history]) => {
      if (cancelled) return;
      if (catalog.status === "fulfilled") setTools(catalog.value); else setError(String(catalog.reason));
      if (history.status === "fulfilled") setRuns(history.value); else setRunError(String(history.reason));
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [activeProjectId, refresh]);

  const categories = useMemo(() => [...new Set(tools.map(tool => tool.category))].sort(), [tools]);
  const operations = useMemo(() => [...new Set(tools.map(tool => tool.operation_kind))].sort(), [tools]);
  const visible = useMemo(() => filterTools(tools, query, category, availability, operation), [tools, query, category, availability, operation]);

  return <div>
    <PageHeader eyebrow="CYBERSECURITY WORKFLOWS" title="Tool Library" description="Find supported workflows, inspect their prerequisites and see what is still planned. Opening a workflow does not start a scan." actions={<button className="ws-button ws-button-secondary" disabled={loading} onClick={() => setRefresh(value => value + 1)}>Refresh availability</button>}/>
    {activeProjectId && <AssessmentPanel key={activeProjectId} projectId={activeProjectId} projectName={projects.find(project => project.id === activeProjectId)?.display_name ?? activeProjectId}/>}
    <div className="ws-tool-filters">
      <ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/>
      <label className="ws-field"><span>Search tools</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Name, ID or coverage…"/></label>
      <label className="ws-field"><span>Category</span><select aria-label="Category" value={category} onChange={event => setCategory(event.target.value)}><option value="">All categories</option>{categories.map(value => <option key={value}>{value}</option>)}</select></label>
      <label className="ws-field"><span>Availability</span><select aria-label="Availability" value={availability} onChange={event => setAvailability(event.target.value)}><option value="">All availability</option>{Object.entries(availabilityLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      <label className="ws-field"><span>Operation</span><select aria-label="Operation" value={operation} onChange={event => setOperation(event.target.value)}><option value="">All operations</option>{operations.map(value => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
    </div>
    <p className="ws-form-help">Availability describes access to an existing workflow. Its target, toolchain, input hashes and approvals are checked before execution. Planned tools have no registered workflow.</p>
    {loading && <LoadingState label="Checking tool availability…"/>}
    {error && <p role="alert" className="ws-warning-box">Tool catalog unavailable: {error}. Refresh availability to retry.</p>}
    {!loading && !error && <><p className="ws-form-help">{visible.length} of {tools.length} tools shown</p>
      {!visible.length && <p className="ws-inline-empty">No tools match these filters.</p>}
      <div className="ws-tool-grid">{visible.map(tool => {
        const action = toolAction(tool);
        return <article key={tool.id} className="ws-tool-card" aria-label={tool.name}>
          <div className="ws-tool-title"><h2>{tool.name}</h2><span className={"ws-status ws-status-" + tool.availability}>{availabilityLabels[tool.availability]}</span></div>
          <p>{tool.description}</p><p className="ws-form-help">{tool.category} · {tool.operation_kind.replaceAll("_", " ")}</p>
          <p>{tool.reason}</p>
          <Disclosure title="Coverage and prerequisites"><p>{tool.coverage}</p>{tool.prerequisites.length > 0 && <ul>{tool.prerequisites.map(item => <li key={item}>{item}</li>)}</ul>}<p className="ws-form-help">{tool.platforms.join(" · ") || "Platform support not implemented"}</p><p className="ws-form-help">{tool.id} · catalog definition {tool.definition_version} · {tool.roadmap}</p></Disclosure>
          <button className="ws-button ws-button-secondary" disabled={!action} onClick={() => { if (action) { if (action.mode) window.location.hash = routeHref(action.route) + "?mode=" + action.mode; else navigate(action.route); } }}>{action?.label ?? "Unavailable"}</button>
        </article>;
      })}</div>
    </>}
    <Panel title="Recent persisted runs" className="ws-tool-run-panel">
      <p className="ws-form-help">Latest 20 analysis, web and QA execution records in this project scope. Completed scans do not imply passing tests or complete security coverage.</p>
      {runError && <p role="alert">Run history unavailable: {runError}. Refresh availability to retry.</p>}
      {!loading && !runError && !runs.length && <p className="ws-inline-empty">No persisted runs in this scope.</p>}
      <div className="ws-history-list">{runs.map(run => <div key={run.source + ":" + run.id}><StatusBadge status={run.status}/><p><strong>{run.kind.replaceAll("_", " ")}</strong><small>{run.source} · {run.duration_ms ?? "n/a"} ms{run.tests_passed === null ? " · No test verdict" : run.tests_passed ? " · Tests passed" : " · Tests failed"}</small></p><time>{formatDate(run.finished_at ?? run.started_at)}</time></div>)}</div>
    </Panel>
  </div>;
}
