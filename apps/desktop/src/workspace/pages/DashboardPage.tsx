import { Icon } from "../Icon";
import { navigate } from "../routes";
import { Panel, StatusBadge, formatDate, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

function SummaryCard({
  icon,
  label,
  value,
  route,
  tone,
}: {
  icon: Parameters<typeof Icon>[0]["name"];
  label: string;
  value: number;
  route: "projects" | "websites" | "agents" | "security";
  tone: string;
}) {
  return (
    <button className="ws-summary-card" data-tone={tone} onClick={() => navigate(route)}>
      <span className="ws-summary-icon"><Icon name={icon} size={25}/></span>
      <span><strong>{value.toLocaleString()}</strong><small>{label}</small></span>
      <Icon name="chevron" size={18}/>
    </button>
  );
}

export function DashboardPage() {
  const {
    projects,
    websites,
    summary,
    activity,
    systemStatus,
    activeProject,
    operation,
    setWebsiteComposerOpen,
    pickAndImportProject,
    runSecurity,
    runQaDiscovery,
  } = useWorkspace();

  const recentProjects = projects.slice(0, 5);
  const recentWebsites = websites.slice(0, 5);
  const busy = operation !== null;

  return (
    <div className="ws-dashboard-page">
      <section className="ws-welcome">
        <div>
          <p className="ws-eyebrow">CODETWIN WORKSPACE</p>
          <h1>Welcome to CodeTwin</h1>
          <p>Manage projects, inspect persisted engineering evidence, and run explicit analysis workflows.</p>
        </div>
        <blockquote>“Index. Analyze. Secure. Verify. All from one local workspace.”</blockquote>
      </section>

      <section className="ws-summary-grid" aria-label="Workspace summary">
        <SummaryCard icon="projects" label="Projects" value={summary.project_count} route="projects" tone="blue"/>
        <SummaryCard icon="websites" label="Websites" value={summary.website_count} route="websites" tone="cyan"/>
        <SummaryCard icon="agents" label="Active Agents" value={summary.active_agents} route="agents" tone="purple"/>
        <SummaryCard icon="security" label="Security Scans" value={summary.security_scan_count} route="security" tone="green"/>
      </section>

      <section className="ws-primary-actions" aria-label="Primary actions">
        <button className="ws-action-button ws-action-blue" onClick={() => setWebsiteComposerOpen(true)}>
          <Icon name="plus"/><Icon name="websites"/> Add Website Link
        </button>
        <button className="ws-action-button ws-action-green" onClick={() => void pickAndImportProject()} disabled={busy}>
          <Icon name="folder"/>{operation?.kind === "project-import" ? operation.stage : "Add Project Folder"}
        </button>
        <button className="ws-action-button" disabled title="Project scaffolding is not implemented. Import an existing project folder instead.">
          <Icon name="file"/> New Project
        </button>
        <button className="ws-action-button" onClick={() => void runSecurity()} disabled={!activeProject || busy}>
          <Icon name="scan"/> Run Scan
        </button>
        <button className="ws-action-button" disabled title="Deployment execution is not implemented in CodeTwin yet.">
          <Icon name="deploy"/> Deploy
        </button>
        <details className="ws-more-menu">
          <summary className="ws-action-button"><Icon name="more"/> More</summary>
          <div>
            <button onClick={() => navigate("database")}>Database Analysis</button>
            <button onClick={() => navigate("runtime")}>Runtime Reliability</button>
            <button onClick={() => navigate("ml")}>ML Workspace</button>
            <button onClick={() => navigate("repair")}>Repair Lab</button>
          </div>
        </details>
      </section>

      <section className="ws-dashboard-tables">
        <Panel title="Recent Websites" action={<button className="ws-text-button" onClick={() => navigate("websites")}>View All →</button>}>
          {recentWebsites.length ? (
            <div className="ws-table-wrap">
              <table className="ws-table">
                <thead><tr><th>#</th><th>Website</th><th>Status</th><th>Last Checked</th><th>Actions</th></tr></thead>
                <tbody>
                  {recentWebsites.map((website, index) => (
                    <tr key={website.id}>
                      <td>{index + 1}</td>
                      <td><strong>{website.display_name}</strong><small title={website.url}>{shortPath(website.url, 46)}</small></td>
                      <td><StatusBadge status={website.status}/></td>
                      <td>{formatDate(website.last_checked_at)}</td>
                      <td><button className="ws-icon-button" aria-label={"View " + website.display_name} onClick={() => navigate("websites")}><Icon name="chevron"/></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="ws-inline-empty">No websites registered yet.</p>}
        </Panel>

        <Panel title="Recent Projects" action={<button className="ws-text-button" onClick={() => navigate("projects")}>View All →</button>}>
          {recentProjects.length ? (
            <div className="ws-table-wrap">
              <table className="ws-table">
                <thead><tr><th>#</th><th>Project</th><th>Path</th><th>Last Indexed</th><th>Actions</th></tr></thead>
                <tbody>
                  {recentProjects.map((project, index) => (
                    <tr key={project.id}>
                      <td>{index + 1}</td>
                      <td><strong>{project.display_name}</strong><small>{project.file_count} files · {project.symbol_count} symbols</small></td>
                      <td className="ws-mono" title={project.root_path}>{shortPath(project.root_path, 42)}</td>
                      <td>{formatDate(project.last_indexed_at)}</td>
                      <td><button className="ws-icon-button" aria-label={"Open " + project.display_name} onClick={() => navigate("projects")}><Icon name="chevron"/></button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="ws-inline-empty">No projects have been indexed yet.</p>}
        </Panel>
      </section>

      <section className="ws-dashboard-lower">
        <Panel title="Quick Actions" className="ws-quick-panel">
          <div className="ws-quick-grid">
            <button onClick={() => setWebsiteComposerOpen(true)}><span><Icon name="websites"/></span><b>Add Website Link</b><small>Register a URL without scanning it</small></button>
            <button onClick={() => void pickAndImportProject()} disabled={busy}><span><Icon name="folder"/></span><b>Add Project Folder</b><small>Discover and persist a local project</small></button>
            <button onClick={() => navigate("code-analysis")} disabled={!activeProject}><span><Icon name="code"/></span><b>Code Analysis</b><small>Inspect files and symbols</small></button>
            <button onClick={() => void runSecurity()} disabled={!activeProject || busy}><span><Icon name="security"/></span><b>Run Security Scan</b><small>Run existing static source rules</small></button>
            <button onClick={() => void runQaDiscovery()} disabled={!activeProject || busy}><span><Icon name="testing"/></span><b>Discover Tests</b><small>Inventory QA evidence safely</small></button>
            <button onClick={() => navigate("documentation")}><span><Icon name="docs"/></span><b>Documentation</b><small>Review current capability boundaries</small></button>
          </div>
        </Panel>

        <Panel title="Recent Activity" action={<button className="ws-text-button" onClick={() => navigate("projects")}>Explore →</button>}>
          <div className="ws-activity-list">
            {activity.slice(0, 6).map((item) => (
              <div key={item.id}>
                <span className={"ws-activity-dot ws-activity-" + item.kind}/>
                <p><strong>{item.title}</strong><small>{item.detail}</small></p>
                <time>{formatDate(item.occurred_at)}</time>
              </div>
            ))}
            {!activity.length && <p className="ws-inline-empty">No persisted workspace activity yet.</p>}
          </div>
        </Panel>

        <Panel title="System Status">
          <div className="ws-system-list">
            {systemStatus.map((entry) => (
              <div key={entry.key} title={entry.detail}>
                <span className={"ws-system-dot ws-system-" + entry.state}/>
                <span>{entry.label}</span>
                <StatusBadge status={entry.state}/>
              </div>
            ))}
          </div>
          <div className="ws-status-note">
            <Icon name={systemStatus.every((entry) => entry.state === "operational") ? "check" : "warning"}/>
            <div>
              <strong>Capability truth</strong>
              <small>Unavailable and limited subsystems are shown explicitly rather than reported as operational.</small>
            </div>
          </div>
        </Panel>
      </section>
    </div>
  );
}
