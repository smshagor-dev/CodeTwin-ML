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
import type {
  AppPreferences,
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
  reindexProject: (project: ProjectOverview) => Promise<void>;
  removeProject: (project: ProjectOverview) => Promise<void>;
  addWebsite: (url: string, name: string, projectId: string | null) => Promise<WebsiteRecord>;
  checkWebsite: (website: WebsiteRecord) => Promise<void>;
  removeWebsite: (website: WebsiteRecord) => Promise<void>;
  runSecurity: (projectId?: string | null) => Promise<void>;
  runQaDiscovery: (projectId?: string | null) => Promise<void>;
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

  const reindexProject = useCallback(async (project: ProjectOverview) => {
    setOperation({ kind: "project-import", stage: "Re-indexing " + project.display_name + "…" });
    try {
      const result = await workspaceApi.indexProject(project.root_path);
      await refreshWorkspace();
      setActiveProjectIdState(result.project_id);
      setToast({ tone: "success", message: "Index refreshed for " + project.display_name + "." });
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
    savePreferences,
  }), [
    projects, websites, summary, activity, systemStatus, preferences, activeProjectId, activeProject,
    loading, operation, toast, websiteComposerOpen, setActiveProjectId, refreshWorkspace,
    pickAndImportProject, reindexProject, removeProject, addWebsite, checkWebsite, removeWebsite,
    runSecurity, runQaDiscovery, savePreferences,
  ]);

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("useWorkspace must be used within WorkspaceProvider");
  return value;
}
