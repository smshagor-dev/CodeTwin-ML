import { Icon } from "../Icon";
import { navigate } from "../routes";
import { Disclosure, EmptyState, PageHeader, Panel, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import { NativeAgentsPage } from "./NativeAgentsPage";

export function AgentsPage() {
  return <NativeAgentsPage/>;
}

export function DeploymentsPage() {
  return (
    <div>
      <PageHeader eyebrow="RELEASE WORKFLOWS" title="Deployments" description="Review release capabilities."/>
      <EmptyState
        icon="deploy"
        title="Deployments are unavailable"
        description="This build does not execute or record deployments."
        action={<button className="ws-button ws-button-secondary" onClick={() => navigate("documentation")}><Icon name="docs"/>Read Capability Boundaries</button>}
      />
    </div>
  );
}

export function DocumentationPage() {
  return (
    <div>
      <PageHeader eyebrow="PRODUCT DOCUMENTATION" title="Documentation" description="A concise guide to the capabilities currently exposed by this desktop build."/>
      <Panel title="Workspace guide" className="ws-guide-panel">
        <article><div><h3>Tool Library</h3><p>Search tools, inspect availability and prerequisites, and open registered workflows. Planned and blocked tools cannot run.</p></div><button className="ws-text-button" onClick={() => navigate("tools")}>Open Tool Library →</button></article>
        <article><div><h3>Projects &amp; code analysis</h3><p>Import a local folder to index its files and symbols. Removing it from CodeTwin keeps the original files.</p></div><button className="ws-text-button" onClick={() => navigate("code-analysis")}>Open Code Analysis →</button></article>
        <article><div><h3>Security</h3><p>Run source, secret and dependency checks. Web testing needs explicit authorization and a bounded scope; registering a URL does not start a scan.</p></div><button className="ws-text-button" onClick={() => navigate("security")}>Open Security →</button></article>
        <article><div><h3>Testing</h3><p>Discovery inventories test files. Execution needs an approved plan and an available strict sandbox.</p></div><button className="ws-text-button" onClick={() => navigate("testing")}>Open Testing →</button></article>
        <article><div><h3>Language servers</h3><p>Configure TypeScript, Pyright or Rust Analyzer for explicitly requested semantic enrichment.</p></div><button className="ws-text-button" onClick={() => navigate("integrations")}>Open Integrations →</button></article>
        <article><div><h3>Advanced tools</h3><p>Open Advanced tools in the sidebar for engineering, database, runtime, local ML and repair workflows. Repairs require review and approval.</p></div></article>
        <article><div><h3>Local data</h3><p>Projects, evidence and preferences are stored in the application SQLite database.</p></div></article>
      </Panel>
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
      <PageHeader eyebrow="LOCAL DIAGNOSTICS" title="Support" description="Check subsystem health and copy a diagnostic summary."/>
      <div className="ws-security-layout">
        <Panel title="System capabilities">
          <div className="ws-system-list ws-system-list-large">
            {systemStatus.map((entry) => <div key={entry.key} title={entry.detail}><span className={"ws-system-dot ws-system-" + entry.state}/><span><strong>{entry.label}</strong><small>{entry.detail}</small></span><StatusBadge status={entry.state}/></div>)}
          </div>
        </Panel>
        <Panel title="Diagnostic summary">
          <p>Includes subsystem state and workspace counts. Source files and credentials are excluded.</p>
          <Disclosure title="View diagnostic details"><pre className="ws-diagnostics">{diagnostics}</pre></Disclosure>
          <button className="ws-button ws-button-secondary" onClick={() => void navigator.clipboard.writeText(diagnostics).then(() => setToast({ tone: "success", message: "Diagnostic summary copied." })).catch((error) => setToast({ tone: "error", message: "Copy failed: " + String(error) }))}>Copy Diagnostics</button>
        </Panel>
      </div>
    </div>
  );
}
