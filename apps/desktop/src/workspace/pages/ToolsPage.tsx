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
  const [networkTarget, setNetworkTarget] = useState("127.0.0.1");
  const [networkPorts, setNetworkPorts] = useState("80,443,3000");
  const [networkAuthorized, setNetworkAuthorized] = useState(false);
  const [networkBusy, setNetworkBusy] = useState(false);
  const [networkError, setNetworkError] = useState("");
  const [networkHistory, setNetworkHistory] = useState<Awaited<ReturnType<typeof workspaceApi.networkInspectionHistory>>>([]);
  const [networkHistoryError, setNetworkHistoryError] = useState("");
  const [dnsHost, setDnsHost] = useState("localhost");
  const [dnsAllowAddresses, setDnsAllowAddresses] = useState("127.0.0.1,::1");
  const [dnsAuthorized, setDnsAuthorized] = useState(false);
  const [dnsBusy, setDnsBusy] = useState(false);
  const [dnsError, setDnsError] = useState("");
  const [dnsResult, setDnsResult] = useState<{ hostname: string; addresses: string[]; note: string } | null>(null);

  useEffect(() => {
    let valid = true;
    void workspaceApi.networkInspectionHistory()
      .then(rows => { if (valid) setNetworkHistory(rows); })
      .catch(reason => { if (valid) setNetworkHistoryError(String(reason)); });
    return () => { valid = false; };
  }, []);
  const [networkResult, setNetworkResult] = useState<{
    target: string;
    observations: { port: number; state: string; elapsed_ms: number }[];
    tested_ports: number;
    note: string;
  } | null>(null);

  async function inspectDns() {
    setDnsResult(null); setDnsError("");
    if (!dnsAuthorized) { setDnsError("Confirm authorization first."); return; }
    setDnsBusy(true);
    try {
      setDnsResult(await workspaceApi.inspectAuthorizedDns({
        authorized: true,
        hostname: dnsHost.trim(),
        allowed_hostnames: [dnsHost.trim()],
        allowed_addresses: dnsAllowAddresses.split(",").map(value => value.trim()).filter(Boolean),
      }));
    } catch (reason) { setDnsError(String(reason)); }
    finally { setDnsBusy(false); }
  }

  async function inspectNetwork() {
    setNetworkError(""); setNetworkResult(null);
    if (!networkAuthorized) { setNetworkError("Confirm authorization first."); return; }
    const ports = networkPorts.split(",").map(part => Number(part.trim()));
    if (!ports.length || ports.length > 32 || ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) {
      setNetworkError("Provide 1-32 comma-separated TCP ports."); return;
    }
    setNetworkBusy(true);
    try {
      const result = await workspaceApi.inspectAuthorizedNetworkServices({
        authorized: true,
        target: networkTarget.trim(),
        allowed_addresses: [networkTarget.trim()],
        ports,
        timeout_ms: 750,
      });
      setNetworkResult(result);
      try {
        setNetworkHistory(await workspaceApi.networkInspectionHistory());
        setNetworkHistoryError("");
      } catch (reason) { setNetworkHistoryError(String(reason)); }
    } catch (reason) { setNetworkError(String(reason)); }
    finally { setNetworkBusy(false); }
  }


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
    <Panel title="Authorized private-network TCP inspection">
      <p className="ws-form-help">TCP connection reachability only. Supports explicitly approved private/loopback IP addresses, up to 32 ports and four concurrent connections. No public networks, DNS discovery, exploitation or command execution. Results are local to this screen.</p>
      <label className="ws-field"><span>Authorized private or loopback IP address</span>
        <input value={networkTarget} onChange={event => { setNetworkTarget(event.target.value); setNetworkResult(null); setNetworkAuthorized(false); }} placeholder="127.0.0.1"/></label>
      <label className="ws-field"><span>TCP ports (comma-separated)</span>
        <input value={networkPorts} onChange={event => setNetworkPorts(event.target.value)} placeholder="80,443,3000"/></label>
      <label className="ws-field"><span><input type="checkbox" checked={networkAuthorized} onChange={event => setNetworkAuthorized(event.target.checked)}/> I own or am explicitly authorized to inspect this target.</span></label>
      <button className="ws-button ws-button-secondary" disabled={!networkAuthorized || networkBusy} onClick={() => void inspectNetwork()}>{networkBusy ? "Inspecting…" : "Inspect TCP services"}</button>
      {networkError && <p role="alert">{networkError}</p>}
      {networkResult && <div role="status"><p>{networkResult.tested_ports} ports checked on {networkResult.target}</p><ul>{networkResult.observations.map(item => <li key={item.port}>{item.port}/tcp · {item.state} · {item.elapsed_ms} ms</li>)}</ul><p className="ws-form-help">{networkResult.note}</p></div>}
      <Disclosure title="Local network inspection history">
        <p className="ws-form-help">Recent explicit local inspections are retained in SQLite with SHA-256 result-integrity checks. An open port is not a vulnerability finding.</p>
        {networkHistoryError && <p role="alert">{networkHistoryError}</p>}
        {!networkHistory.length && <p>No recorded network inspections.</p>}
        <ul>{networkHistory.map(record => <li key={record.id}>
          {record.target_ip} · {record.status} · {record.ports_tested}/{record.ports_requested} ports · {record.started_at}
          {record.inspection && <span> · {record.inspection.observations.filter(item => item.state === "open").length} reachable</span>}
        </li>)}</ul>
      </Disclosure>
    </Panel>
    <Panel title="Authorized DNS address verification">
      <p className="ws-form-help">Exact-name, explicit IP allowlist, private/loopback addresses only. Fails closed if DNS returns any unauthorized address. No subdomain discovery or DNSSEC assertion.</p>
      <label className="ws-field"><span>Approved hostname</span><input value={dnsHost} onChange={event => { setDnsHost(event.target.value); setDnsAuthorized(false); setDnsResult(null); }}/></label>
      <label className="ws-field"><span>Allowed resolved private IP addresses</span><input value={dnsAllowAddresses} onChange={event => { setDnsAllowAddresses(event.target.value); setDnsResult(null); }} placeholder="127.0.0.1,::1"/></label>
      <label className="ws-field"><span><input type="checkbox" checked={dnsAuthorized} onChange={event => setDnsAuthorized(event.target.checked)}/> I am authorized to resolve this exact hostname and allowed IPs.</span></label>
      <button className="ws-button ws-button-secondary" disabled={!dnsAuthorized || dnsBusy} onClick={() => void inspectDns()}>{dnsBusy ? "Resolving…" : "Verify DNS addresses"}</button>
      {dnsError && <p role="alert">{dnsError}</p>}
      {dnsResult && <div role="status"><p>{dnsResult.hostname}: {dnsResult.addresses.join(", ")}</p><p className="ws-form-help">{dnsResult.note}</p></div>}
    </Panel>
    <Panel title="Recent persisted runs" className="ws-tool-run-panel">
      <p className="ws-form-help">Latest 20 analysis, web and QA execution records in this project scope. Completed scans do not imply passing tests or complete security coverage.</p>
      {runError && <p role="alert">Run history unavailable: {runError}. Refresh availability to retry.</p>}
      {!loading && !runError && !runs.length && <p className="ws-inline-empty">No persisted runs in this scope.</p>}
      <div className="ws-history-list">{runs.map(run => <div key={run.source + ":" + run.id}><StatusBadge status={run.status}/><p><strong>{run.kind.replaceAll("_", " ")}</strong><small>{run.source} · {run.duration_ms ?? "n/a"} ms{run.tests_passed === null ? " · No test verdict" : run.tests_passed ? " · Tests passed" : " · Tests failed"}</small></p><time>{formatDate(run.finished_at ?? run.started_at)}</time></div>)}</div>
    </Panel>
  </div>;
}
