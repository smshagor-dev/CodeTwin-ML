import { useEffect, useMemo, useRef, useState } from "react";

import { validateWebsiteUrl, workspaceApi } from "./api";
import { Icon, type IconName } from "./Icon";
import { navigate, routeHref, type WorkspaceRoute } from "./routes";
import type { WorkspaceSearchResult } from "./types";
import { LoadingState, Modal, StatusBadge, formatDate } from "./ui";
import { useWorkspace } from "./WorkspaceContext";
import { DashboardPage } from "./pages/DashboardPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { WebsitesPage } from "./pages/WebsitesPage";
import { CodeAnalysisPage } from "./pages/CodeAnalysisPage";
import { SecurityPage } from "./pages/SecurityPage";
import { TestingPage } from "./pages/TestingPage";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { AgentsPage, DeploymentsPage, DocumentationPage, SupportPage } from "./pages/InfoPages";

const navigation: Array<{ route: WorkspaceRoute; label: string; icon: IconName }> = [
  { route: "dashboard", label: "Dashboard", icon: "dashboard" },
  { route: "projects", label: "Projects", icon: "projects" },
  { route: "websites", label: "Websites", icon: "websites" },
  { route: "agents", label: "Agents", icon: "agents" },
  { route: "code-analysis", label: "Code Analysis", icon: "code" },
  { route: "security", label: "Security", icon: "security" },
  { route: "testing", label: "Testing", icon: "testing" },
  { route: "deployments", label: "Deployments", icon: "deploy" },
  { route: "integrations", label: "Integrations", icon: "integrations" },
  { route: "settings", label: "Settings", icon: "settings" },
  { route: "documentation", label: "Documentation", icon: "docs" },
  { route: "support", label: "Support", icon: "support" },
];

function routePage(route: WorkspaceRoute) {
  switch (route) {
    case "dashboard": return <DashboardPage/>;
    case "projects": return <ProjectsPage/>;
    case "websites": return <WebsitesPage/>;
    case "agents": return <AgentsPage/>;
    case "code-analysis": return <CodeAnalysisPage/>;
    case "security": return <SecurityPage/>;
    case "testing": return <TestingPage/>;
    case "deployments": return <DeploymentsPage/>;
    case "integrations": return <IntegrationsPage/>;
    case "settings": return <SettingsPage/>;
    case "documentation": return <DocumentationPage/>;
    case "support": return <SupportPage/>;
  }
}

function WebsiteComposer() {
  const { websiteComposerOpen, setWebsiteComposerOpen, projects, activeProjectId, addWebsite, setToast } = useWorkspace();
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [projectId, setProjectId] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!websiteComposerOpen) return;
    setUrl("");
    setName("");
    setProjectId(activeProjectId ?? "");
    setError(null);
  }, [activeProjectId, websiteComposerOpen]);

  async function submit() {
    const validation = validateWebsiteUrl(url);
    if (validation) {
      setError(validation);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await addWebsite(url, name, projectId || null);
      setWebsiteComposerOpen(false);
      navigate("websites");
    } catch (value) {
      const message = String(value);
      setError(message.includes("already registered") ? "That website is already registered in CodeTwin." : message);
      setToast(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={websiteComposerOpen}
      onClose={() => !busy && setWebsiteComposerOpen(false)}
      title="Add Website Link"
      description="Register a URL for workspace tracking. This does not start a security scan."
      footer={<>
        <button className="ws-button ws-button-secondary" onClick={() => setWebsiteComposerOpen(false)} disabled={busy}>Cancel</button>
        <button className="ws-button ws-button-primary" onClick={() => void submit()} disabled={busy}><Icon name="plus"/>{busy ? "Adding…" : "Add Website"}</button>
      </>}
    >
      <div className="ws-form-stack">
        <label className="ws-field"><span>Website URL</span><input autoFocus value={url} onChange={(event) => setUrl(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void submit()} placeholder="https://example.com" inputMode="url"/></label>
        <label className="ws-field"><span>Display name <small>optional</small></span><input value={name} onChange={(event) => setName(event.target.value)} maxLength={120} placeholder="My product site"/></label>
        <label className="ws-field"><span>Associated project <small>optional</small></span><select value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="">No associated project</option>{projects.map((project) => <option key={project.id} value={project.id}>{project.display_name}</option>)}</select></label>
        {error && <p className="ws-form-error" role="alert">{error}</p>}
        <div className="ws-safe-note"><Icon name="security"/><p><strong>No implicit security testing</strong><span>Adding a URL only persists it. Availability checks and project security scans stay separate explicit actions.</span></p></div>
      </div>
    </Modal>
  );
}

function GlobalSearch() {
  const { setActiveProjectId, setToast } = useWorkspace();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<WorkspaceSearchResult[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        inputRef.current?.focus();
        setOpen(true);
      }
    }
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, []);

  useEffect(() => {
    const value = query.trim();
    if (!value) {
      setResults([]);
      setBusy(false);
      return;
    }
    let cancelled = false;
    setBusy(true);
    const timer = window.setTimeout(() => {
      void workspaceApi.search(value, 24)
        .then((next) => { if (!cancelled) setResults(next); })
        .catch((error) => { if (!cancelled) setToast({ tone: "error", message: "Search failed: " + String(error) }); })
        .finally(() => { if (!cancelled) setBusy(false); });
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query, setToast]);

  function choose(result: WorkspaceSearchResult) {
    if (result.project_id) setActiveProjectId(result.project_id);
    setOpen(false);
    setQuery("");
    if (result.kind === "website") {
      window.location.hash = "#/websites?website=" + encodeURIComponent(result.id);
    } else if (result.kind === "file" || result.kind === "symbol") {
      window.location.hash = "#/code-analysis?q=" + encodeURIComponent(result.title);
    } else {
      window.location.hash = "#/projects?project=" + encodeURIComponent(result.project_id ?? result.id);
    }
  }

  return (
    <div className="ws-global-search">
      <Icon name="search" size={19}/>
      <input
        ref={inputRef}
        aria-label="Global search"
        aria-expanded={open && Boolean(query.trim())}
        placeholder="Search projects, websites, files, symbols…"
        value={query}
        onFocus={() => setOpen(true)}
        onChange={(event) => { setQuery(event.target.value); setOpen(true); }}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false);
          if (event.key === "Enter" && results[0]) choose(results[0]);
        }}
      />
      <kbd>Ctrl K</kbd>
      {open && query.trim() && (
        <div className="ws-search-results">
          {busy && <p>Searching persistent workspace…</p>}
          {!busy && results.map((result) => (
            <button key={result.kind + ":" + result.id} onClick={() => choose(result)}>
              <span className={"ws-search-kind ws-search-" + result.kind}>{result.kind.slice(0, 1).toUpperCase()}</span>
              <span><strong>{result.title}</strong><small>{result.subtitle}</small></span>
              <Icon name="chevron" size={16}/>
            </button>
          ))}
          {!busy && !results.length && <p>No matching persisted data.</p>}
        </div>
      )}
    </div>
  );
}

export function WorkspaceShell({ route }: { route: WorkspaceRoute }) {
  const { preferences, savePreferences, activity, operation, toast, setToast, setActiveProjectId, loading } = useWorkspace();
  const alertCount = useMemo(() => activity.filter((item) => ["failed", "offline", "degraded"].includes(item.status)).length, [activity]);
  const initials = preferences.display_name.trim().split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "U";

  async function toggleTheme() {
    const current = preferences.theme === "system"
      ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
      : preferences.theme;
    await savePreferences({ ...preferences, theme: current === "dark" ? "light" : "dark" });
  }

  return (
    <div className="ws-app">
      <aside className="ws-sidebar">
        <a href={routeHref("dashboard")} className="ws-brand" aria-label="CodeTwin dashboard">
          <img src="/app-icon.png" alt=""/>
          <span><strong>CodeTwin</strong><small>Engineering Intelligence</small></span>
        </a>
        <nav aria-label="Main navigation">
          {navigation.map((item, index) => (
            <a key={item.route} href={routeHref(item.route)} className={route === item.route ? "active" : ""} data-section={index === 10 ? "secondary" : undefined}>
              <Icon name={item.icon}/><span>{item.label}</span>
            </a>
          ))}
        </nav>
        <div className="ws-sidebar-profile">
          <span className="ws-avatar">{initials}</span>
          <span><strong>{preferences.display_name}</strong><small>Local workspace</small></span>
          <Icon name="chevron" size={16}/>
        </div>
      </aside>

      <section className="ws-main">
        <header className="ws-topbar">
          <GlobalSearch/>
          <div className="ws-top-actions">
            <details className="ws-top-menu">
              <summary className="ws-icon-button" aria-label="Notifications"><Icon name="bell"/>{alertCount > 0 && <b>{Math.min(alertCount, 99)}</b>}</summary>
              <div className="ws-popover ws-notifications">
                <h3>Recent activity</h3>
                {activity.slice(0, 6).map((item) => <button key={item.id} onClick={() => {
                  if (item.project_id) setActiveProjectId(item.project_id);
                  navigate(item.kind === "website" ? "websites" : "projects");
                }}><span className={"ws-activity-dot ws-activity-" + item.kind}/><span><strong>{item.title}</strong><small>{item.detail} · {formatDate(item.occurred_at)}</small></span></button>)}
                {!activity.length && <p>No activity yet.</p>}
              </div>
            </details>
            <button className="ws-icon-button" aria-label="Toggle light or dark theme" onClick={() => void toggleTheme()}><Icon name={preferences.theme === "dark" ? "sun" : "moon"}/></button>
            <details className="ws-top-menu ws-user-menu">
              <summary><span className="ws-avatar ws-avatar-small">{initials}</span><span>{preferences.display_name}</span><Icon name="chevron" size={15}/></summary>
              <div className="ws-popover">
                <button onClick={() => navigate("settings")}><Icon name="settings" size={17}/>Settings</button>
                <button onClick={() => navigate("support")}><Icon name="support" size={17}/>Support</button>
              </div>
            </details>
          </div>
        </header>

        {operation && <div className="ws-operation-banner" role="status"><span className="ws-spinner"/>{operation.stage}</div>}
        {toast && <div className={"ws-toast ws-toast-" + toast.tone} role={toast.tone === "error" ? "alert" : "status"}><span>{toast.message}</span><button aria-label="Dismiss notification" onClick={() => setToast(null)}><Icon name="close" size={16}/></button></div>}
        <main className="ws-content">{loading ? <LoadingState label="Loading CodeTwin workspace…"/> : routePage(route)}</main>
      </section>

      <WebsiteComposer/>
    </div>
  );
}
