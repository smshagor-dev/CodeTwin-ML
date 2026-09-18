import { Icon } from "../Icon";
import { navigate } from "../routes";
import { EmptyState, PageHeader, Panel, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function AgentsPage() {
  return (
    <div>
      <PageHeader eyebrow="AUTOMATION" title="Agents" description="Agent state is shown only when backed by a real CodeTwin runtime."/>
      <EmptyState
        icon="agents"
        title="No autonomous agent runtime is available"
        description="CodeTwin currently has ML inference, deterministic analyzers, and verified repair workflows, but it does not expose a background autonomous-agent runtime. No running agents or task history are fabricated."
        action={<button className="ws-button ws-button-secondary" onClick={() => navigate("ml")}><Icon name="code"/>Open ML Workspace</button>}
      />
    </div>
  );
}

export function DeploymentsPage() {
  return (
    <div>
      <PageHeader eyebrow="RELEASE WORKFLOWS" title="Deployments" description="Deployment history appears here only when CodeTwin has a deployment execution service."/>
      <EmptyState
        icon="deploy"
        title="Deployment execution is not implemented"
        description="There is no CodeTwin deployment backend to safely run or record deployments yet. The dashboard Deploy action is intentionally disabled rather than simulating a successful release."
        action={<button className="ws-button ws-button-secondary" onClick={() => navigate("documentation")}><Icon name="docs"/>Read Capability Boundaries</button>}
      />
    </div>
  );
}

export function DocumentationPage() {
  return (
    <div>
      <PageHeader eyebrow="PRODUCT DOCUMENTATION" title="Documentation" description="A concise guide to the capabilities currently exposed by this desktop build."/>
      <div className="ws-doc-grid">
        <Panel title="Projects & Digital Twin"><p>Importing a local folder uses project discovery and the existing persistent Tree-sitter indexing service. Files, symbols, imports, graph evidence, index runs, and project identity are stored in SQLite.</p><button className="ws-text-button" onClick={() => navigate("code-analysis")}>Open Code Analysis →</button></Panel>
        <Panel title="Security"><p>Security scans are explicit deterministic source analysis. Registering a website does not crawl, attack, fuzz, or otherwise security-test that URL.</p><button className="ws-text-button" onClick={() => navigate("security")}>Open Security →</button></Panel>
        <Panel title="Testing"><p>QA discovery inventories test files and framework evidence. Repository test execution remains disabled until CodeTwin's sandbox can truthfully enforce all required isolation controls.</p><button className="ws-text-button" onClick={() => navigate("testing")}>Open Testing →</button></Panel>
        <Panel title="Semantic integrations"><p>TypeScript/JavaScript, Pyright, and Rust Analyzer executable paths can be configured explicitly. Semantic enrichment remains a separate explicit engineering action.</p><button className="ws-text-button" onClick={() => navigate("integrations")}>Open Integrations →</button></Panel>
        <Panel title="Advanced workspaces"><p>The existing Database, Runtime, ML, Repair Lab, and Apply/Rollback workspaces remain available from Dashboard → More. They are preserved rather than duplicated inside the new shell.</p></Panel>
        <Panel title="Local-first data"><p>Project metadata, analysis evidence, websites, and effective settings are kept in the application-managed SQLite database. Source projects are read and indexed; removing a project from CodeTwin does not delete its files.</p></Panel>
      </div>
    </div>
  );
}

export function SupportPage() {
  const { projects, websites, systemStatus, setToast } = useWorkspace();

  const diagnostics = [
    "CodeTwin desktop diagnostics",
    "Projects: " + projects.length,
    "Websites: " + websites.length,
    ...systemStatus.map((entry) => entry.label + ": " + entry.state + " — " + entry.detail),
  ].join("\n");

  return (
    <div>
      <PageHeader eyebrow="LOCAL DIAGNOSTICS" title="Support" description="Inspect capability health and copy a non-secret diagnostic summary for troubleshooting."/>
      <div className="ws-security-layout">
        <Panel title="System capabilities">
          <div className="ws-system-list ws-system-list-large">
            {systemStatus.map((entry) => <div key={entry.key} title={entry.detail}><span className={"ws-system-dot ws-system-" + entry.state}/><span><strong>{entry.label}</strong><small>{entry.detail}</small></span><StatusBadge status={entry.state}/></div>)}
          </div>
        </Panel>
        <Panel title="Diagnostic summary">
          <p>Copy a short status summary containing only subsystem state and workspace counts. It does not include project source, file contents, secrets, or website credentials.</p>
          <pre className="ws-diagnostics">{diagnostics}</pre>
          <button className="ws-button ws-button-secondary" onClick={() => void navigator.clipboard.writeText(diagnostics).then(() => setToast({ tone: "success", message: "Diagnostic summary copied." })).catch((error) => setToast({ tone: "error", message: "Copy failed: " + String(error) }))}>Copy Diagnostics</button>
        </Panel>
      </div>
    </div>
  );
}
