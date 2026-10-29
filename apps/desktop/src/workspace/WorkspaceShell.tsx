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
import { ToolsPage } from "./pages/ToolsPage";
import { SecurityPage } from "./pages/SecurityPage";
import { TestingPage } from "./pages/TestingPage";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { AgentsPage, DeploymentsPage, DocumentationPage, SupportPage } from "./pages/InfoPages";
import { WorkflowsPage } from "./pages/WorkflowsPage";
import { AssessmentWorkspace } from "./pages/AssessmentWorkspace";
import { LaunchPage } from "./pages/LaunchPage";
import "./shell.css";

type NavItem = { route: WorkspaceRoute; label: string; icon: IconName; tab?: string; disabled?: string };

/** Primary navigation: the terminal-first workspace and its supporting areas. */
const primaryNav: NavItem[] = [
  { route: "launch", label: "Start", icon: "activity" },
  { route: "workspace", label: "Workspace", icon: "activity" },
  { route: "workflows", label: "Reports", icon: "docs", tab: "runs" },
  { route: "projects", label: "Targets", icon: "projects" },
  { route: "agents", label: "Agents", icon: "agents" },
  { route: "workflows", label: "Knowledge", icon: "file", tab: "memory" },
  { route: "tools", label: "Tools", icon: "integrations" },
  { route: "workflows", label: "Project Settings", icon: "settings", tab: "cloud" },
];

const secondaryNav: NavItem[] = [
  { route: "workflows", label: "Usage", icon: "activity", tab: "capabilities" },
  { route: "settings", label: "Organization", icon: "user", disabled: "Single local operator — organizations are not implemented" },
  { route: "settings", label: "Settings", icon: "settings" },
  { route: "documentation", label: "Help Center", icon: "support" },
];

/** Existing areas stay reachable; nothing was removed by the redesign. */
const moreNav: NavItem[] = [
  { route: "dashboard", label: "Overview", icon: "dashboard" },
  { route: "websites", label: "Websites", icon: "websites" },
  { route: "code-analysis", label: "Code Analysis", icon: "code" },
  { route: "security", label: "Security", icon: "security" },
  { route: "testing", label: "Testing", icon: "testing" },
  { route: "integrations", label: "Integrations", icon: "integrations" },
  { route: "deployments", label: "Deployments", icon: "deploy" },
  { route: "workflows", label: "Workflows", icon: "agents", tab: "approvals" },
  { route: "support", label: "Support", icon: "support" },
];

const navigation = [...primaryNav, ...secondaryNav, ...moreNav];
const SIDEBAR_KEY = "codetwin.shell.sidebarCollapsed";
const SIDEBAR_WIDTH_KEY = "codetwin.shell.sidebarWidth";
const SIDEBAR_DEFAULT = 244;
const clampSidebar = (px: number) => Math.round(Math.min(380, Math.max(180, px)));

function navHref(item: NavItem): string {
  return routeHref(item.route) + (item.tab ? `?tab=${item.tab}` : "");
}

function isActive(item: NavItem, route: WorkspaceRoute): boolean {
  if (item.route !== route || item.disabled) return false;
  if (!item.tab) return true;
  const tab = new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("tab") ?? "runs";
  return tab === item.tab;
}

function routeLabel(route: WorkspaceRoute): string {
  return navigation.find((item) => isActive(item, route))?.label
    ?? navigation.find((item) => item.route === route)?.label ?? route;
}

function NavLinks({ items, route }: { items: NavItem[]; route: WorkspaceRoute }) {
  return (
    <>
      {items.map((item) => item.disabled ? (
        <span key={item.label} className="ws-nav-item ws-nav-disabled" aria-disabled="true" title={item.disabled}>
          <Icon name={item.icon}/><span>{item.label}</span>
        </span>
      ) : (
        <div key={item.label} className="ws-nav-item">
          <a href={navHref(item)} aria-label={item.label} title={item.label} aria-current={isActive(item, route) ? "page" : undefined} className={isActive(item, route) ? "active" : ""}>
            <Icon name={item.icon}/><span>{item.label}</span>
          </a>
        </div>
      ))}
    </>
  );
}

export function workspaceRoutePage(route: WorkspaceRoute) {
  switch (route) {
    case "launch": return <LaunchPage/>;
    case "workspace": return <AssessmentWorkspace/>;
    case "dashboard": return <DashboardPage/>;
    case "projects": return <ProjectsPage/>;
    case "websites": return <WebsitesPage/>;
    case "agents": return <AgentsPage/>;
    case "code-analysis": return <CodeAnalysisPage/>;
    case "security": return <SecurityPage/>;
    case "tools": return <ToolsPage/>;
    case "testing": return <TestingPage/>;
    case "deployments": return <DeploymentsPage/>;
    case "integrations": return <IntegrationsPage/>;
    case "settings": return <SettingsPage/>;
    case "documentation": return <DocumentationPage/>;
    case "support": return <SupportPage/>;
    case "workflows": return <WorkflowsPage/>;
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
        onChange={(event) => {
          const value = event.target.value;
          setQuery(value);
          // Results belong to the previous query until the new search completes.
          setResults([]);
          setBusy(Boolean(value.trim()));
          setOpen(true);
        }}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false);
          if (event.key === "Enter" && !busy && results[0]) choose(results[0]);
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
  const [collapsed, setCollapsedState] = useState(() => {
    try { return window.localStorage.getItem(SIDEBAR_KEY) === "1"; } catch { return false; }
  });
  const setCollapsed = (value: boolean) => {
    setCollapsedState(value);
    try { window.localStorage.setItem(SIDEBAR_KEY, value ? "1" : "0"); } catch { /* storage unavailable */ }
  };
  // Operator-resizable sidebar width (drag the right edge), persisted.
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    try { return clampSidebar(Number(window.localStorage.getItem(SIDEBAR_WIDTH_KEY)) || SIDEBAR_DEFAULT); } catch { return SIDEBAR_DEFAULT; }
  });
  const dragging = useRef(false);
  function startResize(event: React.PointerEvent) {
    if (collapsed) return;
    event.preventDefault();
    dragging.current = true;
    const move = (e: PointerEvent) => {
      if (!dragging.current) return;
      setSidebarWidth(clampSidebar(e.clientX));
    };
    const up = () => {
      dragging.current = false;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      setSidebarWidth((w) => { try { window.localStorage.setItem(SIDEBAR_WIDTH_KEY, String(w)); } catch { /* storage unavailable */ } return w; });
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }
  // Re-render when only the `?tab=` part of the hash changes so nav state stays accurate.
  const [, setHashVersion] = useState(0);
  const activeMore = moreNav.find((item) => isActive(item, route));
  useEffect(() => {
    const onHash = () => setHashVersion((v) => v + 1);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  async function toggleTheme() {
    const current = preferences.theme === "system"
      ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
      : preferences.theme;
    await savePreferences({ ...preferences, theme: current === "dark" ? "light" : "dark" });
  }

  return (
    <div className={"ws-app" + (collapsed ? " ws-collapsed" : "")} style={{ ["--ws-sidebar-w" as string]: `${sidebarWidth}px` }}>
      <aside className="ws-sidebar">
        <a href={routeHref("dashboard")} className="ws-brand" aria-label="CodeTwin dashboard">
          <Icon name="code" size={27}/>
          <span><strong>CodeTwin</strong></span>
        </a>
        <button type="button" className="ws-collapse" aria-pressed={collapsed} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} title={collapsed ? "Expand sidebar" : "Collapse sidebar"} onClick={() => setCollapsed(!collapsed)}>
          <Icon name="chevron" size={14}/>
        </button>
        {!collapsed && <div className="ws-sidebar-resize" role="separator" aria-label="Resize sidebar" title="Drag to resize" onPointerDown={startResize}/>}
        <nav aria-label="Main navigation">
          <NavLinks items={primaryNav} route={route}/>
          <p className="ws-nav-label">Account</p>
          <NavLinks items={secondaryNav} route={route}/>
          <details className="ws-sidebar-more">
            <summary aria-label="More areas" title="More areas" className={activeMore ? "active" : ""}><Icon name="more"/><span>{activeMore ? `More · ${activeMore.label}` : "More"}</span><Icon name="chevron" size={14}/></summary>
            <NavLinks items={moreNav} route={route}/>
          </details>
          <details className="ws-sidebar-tools">
            <summary aria-label="Advanced tools" title="Advanced tools"><Icon name="code"/><span>Advanced tools</span><Icon name="chevron" size={14}/></summary>
            <a href={routeHref("engineering")}>Engineering</a>
            <a href={routeHref("web-security")}>Source security</a>
            <a href={routeHref("database")}>Database</a>
            <a href={routeHref("runtime")}>Runtime</a>
            <a href={routeHref("qa")}>QA</a>
            <a href={routeHref("ml")}>Local ML</a>
            <a href={routeHref("repair")}>Repair</a>
            <a href={routeHref("repair-apply")}>Apply & rollback</a>
          </details>
        </nav>
        <div className="ws-sidebar-profile">
          <span className="ws-avatar">{initials}</span>
          <span><strong>{preferences.display_name}</strong><small>Local workspace</small></span>
          <Icon name="chevron" size={16}/>
        </div>
      </aside>

      <section className="ws-main">
        <header className="ws-topbar">
          <div className="ws-breadcrumb"><span>Workspace</span><span>/</span><strong>{routeLabel(route)}</strong></div>
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
        <main className="ws-content">{loading ? <LoadingState label="Loading CodeTwin workspace…"/> : workspaceRoutePage(route)}</main>
      </section>

      <WebsiteComposer/>
    </div>
  );
}
