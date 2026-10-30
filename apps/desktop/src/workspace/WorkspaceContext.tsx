import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  chooseProjectFolder,
  importProjectPath,
  workspaceApi,
  type ImportStage,
} from "./api";
import { workflowApi, type WorkflowRun } from "./workflowApi";
import { buildGuidedRequests, guidedConfigFor } from "./security/guidedSecurityModel";
import type {
  AppPreferences,
  GuidedSecuritySessionRecord,
  ProjectOverview,
  SystemStatusEntry,
  WebsiteRecord,
  WorkspaceActivity,
  WorkspaceSummary,
} from "./types";

type Operation = { kind: "project-import" | "security" | "testing"; stage: string } | null;
type Toast = { tone: "success" | "error" | "info"; message: string } | null;

type WorkspaceContextValue = {
  projects: ProjectOverview[];
  websites: WebsiteRecord[];
  summary: WorkspaceSummary;
  activity: WorkspaceActivity[];
  systemStatus: SystemStatusEntry[];
  preferences: AppPreferences;
  activeProjectId: string | null;
  activeProject: ProjectOverview | null;
  loading: boolean;
  operation: Operation;
  toast: Toast;
  websiteComposerOpen: boolean;
  setWebsiteComposerOpen: (open: boolean) => void;
  setActiveProjectId: (id: string) => void;
  setToast: (toast: Toast) => void;
  refreshWorkspace: () => Promise<void>;
  pickAndImportProject: () => Promise<void>;
  reindexProject: (project: ProjectOverview, fullRebuild?: boolean) => Promise<void>;
  removeProject: (project: ProjectOverview) => Promise<void>;
  addWebsite: (url: string, name: string, projectId: string | null) => Promise<WebsiteRecord>;
  checkWebsite: (website: WebsiteRecord) => Promise<void>;
  removeWebsite: (website: WebsiteRecord) => Promise<void>;
  runSecurity: (projectId?: string | null) => Promise<void>;
  runQaDiscovery: (projectId?: string | null) => Promise<void>;
  scanNow: (projectId?: string | null) => Promise<WorkflowRun>;
  scanWebNow: (website: WebsiteRecord) => Promise<GuidedSecuritySessionRecord>;
  savePreferences: (preferences: AppPreferences) => Promise<void>;
};

const defaults: WorkspaceSummary = { project_count: 0, website_count: 0, active_agents: 0, security_scan_count: 0 };
const defaultPreferences: AppPreferences = {
  display_name: "Local User",
  theme: "system",
  auto_run_security_on_import: false,
  auto_discover_tests_on_import: false,
};

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

function stageLabel(stage: ImportStage): string {
  switch (stage) {
    case "selecting": return "Selecting project folder…";
    case "discovering": return "Validating and discovering project…";
    case "indexing": return "Building persistent source index…";
    case "security": return "Running configured static security analysis…";
    case "testing": return "Discovering test evidence…";
  }
}

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [projects, setProjects] = useState<ProjectOverview[]>([]);
  const [websites, setWebsites] = useState<WebsiteRecord[]>([]);
  const [summary, setSummary] = useState<WorkspaceSummary>(defaults);
  const [activity, setActivity] = useState<WorkspaceActivity[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatusEntry[]>([]);
  const [preferences, setPreferences] = useState<AppPreferences>(defaultPreferences);
  const [activeProjectId, setActiveProjectIdState] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [operation, setOperation] = useState<Operation>(null);
  const [toast, setToast] = useState<Toast>(null);
  const [websiteComposerOpen, setWebsiteComposerOpen] = useState(false);

  const refreshWorkspace = useCallback(async () => {
    const [nextProjects, nextWebsites, nextSummary, nextActivity, nextSystem, nextPreferences] = await Promise.all([
      workspaceApi.listProjects(),
      workspaceApi.listWebsites(),
      workspaceApi.summary(),
      workspaceApi.recentActivity(30),
      workspaceApi.systemStatus(),
      workspaceApi.preferences(),
    ]);
    setProjects(nextProjects);
    setWebsites(nextWebsites);
    setSummary(nextSummary);
    setActivity(nextActivity);
    setSystemStatus(nextSystem);
    setPreferences(nextPreferences);
    setActiveProjectIdState((current) => {
      if (current && nextProjects.some((project) => project.id === current)) return current;
      return nextProjects[0]?.id ?? null;
    });
  }, []);

  useEffect(() => {
    void refreshWorkspace()
      .catch((error) => setToast({ tone: "error", message: String(error) }))
      .finally(() => setLoading(false));
  }, [refreshWorkspace]);

  useEffect(() => {
    document.documentElement.dataset.theme = preferences.theme;
  }, [preferences.theme]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4600);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const activeProject = useMemo(
    () => projects.find((project) => project.id === activeProjectId) ?? null,
    [activeProjectId, projects],
  );

  const setActiveProjectId = useCallback((id: string) => {
    if (projects.some((project) => project.id === id)) setActiveProjectIdState(id);
  }, [projects]);

  const pickAndImportProject = useCallback(async () => {
    setOperation({ kind: "project-import", stage: stageLabel("selecting") });
    try {
      const path = await chooseProjectFolder();
      if (!path) return;
      const result = await importProjectPath(path, preferences, (stage) => {
        setOperation({ kind: "project-import", stage: stageLabel(stage) });
      });
      await refreshWorkspace();
      setActiveProjectIdState(result.index.project_id);
      setToast(result.postImportErrors.length
        ? {
            tone: "error",
            message: "Project indexed, but configured post-import work did not complete: " + result.postImportErrors.join("; "),
          }
        : {
            tone: "success",
            message: "Project indexed successfully: " + result.index.delta.files_scanned + " files scanned.",
          });
    } catch (error) {
      setToast({ tone: "error", message: "Project import failed: " + String(error) });
    } finally {
      setOperation(null);
    }
  }, [preferences, refreshWorkspace]);

  const reindexProject = useCallback(async (project: ProjectOverview, fullRebuild = false) => {
    setOperation({ kind: "project-import", stage: (fullRebuild ? "Rebuilding " : "Re-indexing ") + project.display_name + "…" });
    try {
      const result = await workspaceApi.indexProject(project.root_path, fullRebuild);
      await refreshWorkspace();
      setToast({ tone: "success", message: `${fullRebuild ? "Full rebuild" : "Incremental index"} completed: ${result.delta.files_added} added, ${result.delta.files_modified} modified, ${result.delta.files_unchanged} unchanged, ${result.delta.files_deleted} deleted. ${result.delta.skipped_files} skipped; ${result.delta.parse_errors} parse errors.` });
    } catch (error) {
      setToast({ tone: "error", message: "Re-index failed: " + String(error) });
    } finally {
      setOperation(null);
    }
  }, [refreshWorkspace]);

  const removeProject = useCallback(async (project: ProjectOverview) => {
    await workspaceApi.removeProject(project.id);
    await refreshWorkspace();
    setToast({ tone: "success", message: "Removed " + project.display_name + " from CodeTwin." });
  }, [refreshWorkspace]);

  const addWebsite = useCallback(async (url: string, name: string, projectId: string | null) => {
    const website = await workspaceApi.addWebsite(url, name, projectId);
    await refreshWorkspace();
    setToast({ tone: "success", message: "Website added. Availability checks remain explicit." });
    return website;
  }, [refreshWorkspace]);

  const checkWebsite = useCallback(async (website: WebsiteRecord) => {
    try {
      await workspaceApi.checkWebsite(website.id);
      await refreshWorkspace();
      setToast({ tone: "success", message: "Availability refreshed for " + website.display_name + "." });
    } catch (error) {
      setToast({ tone: "error", message: "Website check failed: " + String(error) });
      throw error;
    }
  }, [refreshWorkspace]);

  const removeWebsite = useCallback(async (website: WebsiteRecord) => {
    await workspaceApi.removeWebsite(website.id);
    await refreshWorkspace();
    setToast({ tone: "success", message: "Website removed from CodeTwin." });
  }, [refreshWorkspace]);

  const runSecurity = useCallback(async (projectId?: string | null) => {
    const id = projectId ?? activeProjectId;
    if (!id) throw new Error("Choose a project before running a security scan.");
    setOperation({ kind: "security", stage: "Running static security analysis…" });
    try {
      await workspaceApi.runSecurity(id);
      await refreshWorkspace();
      setToast({ tone: "success", message: "Static security analysis completed." });
    } catch (error) {
      setToast({ tone: "error", message: "Security analysis failed: " + String(error) });
    } finally {
      setOperation(null);
    }
  }, [activeProjectId, refreshWorkspace]);

  const runQaDiscovery = useCallback(async (projectId?: string | null) => {
    const id = projectId ?? activeProjectId;
    if (!id) throw new Error("Choose a project before discovering test evidence.");
    setOperation({ kind: "testing", stage: "Discovering test evidence…" });
    try {
      await workspaceApi.runQaDiscovery(id);
      await refreshWorkspace();
      setToast({ tone: "success", message: "QA evidence discovery completed." });
    } catch (error) {
      setToast({ tone: "error", message: "QA discovery failed: " + String(error) });
    } finally {
      setOperation(null);
    }
  }, [activeProjectId, refreshWorkspace]);

  // One-click local scan: plan the full read-only assessment, auto-approve only
  // read-only scope, and start it. Anything non-read-only is never auto-approved —
  // it stays a pending decision the operator sees in the terminal.
  const scanNow = useCallback(async (projectId?: string | null) => {
    const id = projectId ?? activeProjectId;
    if (!id) throw new Error("Add or select a project before scanning.");
    setOperation({ kind: "security", stage: "Planning full assessment…" });
    try {
      let readOnly = new Set<string>();
      try {
        const caps = await workflowApi.capabilities(id);
        readOnly = new Set(caps.filter((c) => c.side_effect === "read_only").map((c) => c.capability));
      } catch { /* matrix unavailable: leave approvals manual rather than auto-approving blindly */ }
      const goal = "Full read-only security assessment: source security, secrets, dependency and test-evidence review across the authorized project scope.";
      const { run, approvals } = await workflowApi.createInvestigation(id, goal, [], false, 3);
      setOperation({ kind: "security", stage: "Approving read-only scope…" });
      for (const approval of approvals) {
        const safe = approval.status === "pending" && approval.kind === "plan"
          && approval.capabilities.length > 0 && approval.capabilities.every((c) => readOnly.has(c));
        if (safe) await workflowApi.decide(approval.id, true, approval.scope_digest, "Auto-approved: read-only scan");
      }
      // Start now if the scope was fully approved; otherwise the run waits for the
      // operator's decision in the terminal (the backend enforces the gate regardless).
      try { await workflowApi.start(run.id); } catch { /* awaiting approval — shown in the terminal */ }
      setActiveProjectIdState(id);
      await refreshWorkspace();
      setToast({ tone: "success", message: "Scan started. Live progress is in the terminal." });
      return run;
    } catch (error) {
      setToast({ tone: "error", message: "Could not start scan: " + String(error) });
      throw error;
    } finally {
      setOperation(null);
    }
  }, [activeProjectId, refreshWorkspace]);

  // One-click web scan: build a conservative authorized-production plan, prepare the
  // guided session, and approve it. Authorization is confirmed by the caller's popup.
  const scanWebNow = useCallback(async (website: WebsiteRecord) => {
    setOperation({ kind: "security", stage: "Preparing authorized web assessment…" });
    try {
      const config = guidedConfigFor(website.url, "authorized_production", "standard");
      config.scope.authorization_confirmed = true;
      const { prepare, execution } = buildGuidedRequests({
        websiteId: website.id,
        projectId: website.project_id,
        environment: "authorized_production",
        testingDepth: "standard",
        authMode: "none",
        config,
        primaryCookie: "", primaryBearer: "", primaryHeaders: "",
        secondaryCookie: "", secondaryBearer: "", secondaryHeaders: "",
      });
      let session = await workspaceApi.prepareGuidedSecurityTest(prepare);
      if (session.status === "awaiting_approval") {
        setOperation({ kind: "security", stage: "Approving authorized scope…" });
        session = await workspaceApi.approveGuidedSecurityPlan(session.id);
      }
      // Execute the approved plan. This creates the scan, links it to the guided session
      // (approved → running) and runs the checks in the background; activity events and
      // critical findings then stream into the unified workspace terminal. The backend's
      // assert_execution_allowed gate still enforces the approved, authorized scope.
      if (session.status === "approved") {
        setOperation({ kind: "security", stage: "Running authorized web checks…" });
        execution.guided_session_id = session.id;
        await workspaceApi.startWebSecurityScan(execution);
        session = (await workspaceApi.getGuidedSecuritySession(session.id)) ?? session;
      }
      await refreshWorkspace();
      setToast({ tone: "success", message: "Web assessment running — live progress streams in the workspace terminal." });
      return session;
    } catch (error) {
      setToast({ tone: "error", message: "Could not start web scan: " + String(error) });
      throw error;
    } finally {
      setOperation(null);
    }
  }, [refreshWorkspace]);

  const savePreferences = useCallback(async (next: AppPreferences) => {
    try {
      const saved = await workspaceApi.savePreferences(next);
      setPreferences(saved);
      setToast({ tone: "success", message: "Settings saved." });
    } catch (error) {
      setToast({ tone: "error", message: "Could not save settings: " + String(error) });
    }
  }, []);

  const value = useMemo<WorkspaceContextValue>(() => ({
    projects,
    websites,
    summary,
    activity,
    systemStatus,
    preferences,
    activeProjectId,
    activeProject,
    loading,
    operation,
    toast,
    websiteComposerOpen,
    setWebsiteComposerOpen,
    setActiveProjectId,
    setToast,
    refreshWorkspace,
    pickAndImportProject,
    reindexProject,
    removeProject,
    addWebsite,
    checkWebsite,
    removeWebsite,
    runSecurity,
    runQaDiscovery,
    scanNow,
    scanWebNow,
    savePreferences,
  }), [
    projects, websites, summary, activity, systemStatus, preferences, activeProjectId, activeProject,
    loading, operation, toast, websiteComposerOpen, setActiveProjectId, refreshWorkspace,
    pickAndImportProject, reindexProject, removeProject, addWebsite, checkWebsite, removeWebsite,
    runSecurity, runQaDiscovery, scanNow, scanWebNow, savePreferences,
  ]);

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("useWorkspace must be used within WorkspaceProvider");
  return value;
}
