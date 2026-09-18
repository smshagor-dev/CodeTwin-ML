import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

import type {
  AppPreferences,
  IndexSummary,
  LanguageServerConfig,
  LanguageServerKind,
  ProjectOverview,
  ProjectProfile,
  QaArtifactRecord,
  QaDiscoveryRunRecord,
  QaFrameworkSummary,
  SecurityFindingRecord,
  SecurityRunRecord,
  SourceFileRecord,
  SymbolRecord,
  SystemStatusEntry,
  WebsiteRecord,
  WorkspaceActivity,
  WorkspaceSearchResult,
  WorkspaceSummary,
} from "./types";

export type ImportStage = "selecting" | "discovering" | "indexing" | "security" | "testing";

export const workspaceApi = {
  listProjects(search: string | null = null, limit = 250) {
    return invoke<ProjectOverview[]>("list_projects", { search, limit });
  },
  removeProject(projectId: string) {
    return invoke<boolean>("remove_project", { projectId });
  },
  listWebsites(search: string | null = null, limit = 250) {
    return invoke<WebsiteRecord[]>("list_websites", { search, limit });
  },
  addWebsite(url: string, displayName: string, projectId: string | null) {
    return invoke<WebsiteRecord>("add_website", {
      input: {
        url,
        display_name: displayName.trim() || null,
        project_id: projectId,
      },
    });
  },
  checkWebsite(websiteId: string) {
    return invoke<WebsiteRecord>("check_website", { websiteId });
  },
  removeWebsite(websiteId: string) {
    return invoke<boolean>("remove_website", { websiteId });
  },
  summary() {
    return invoke<WorkspaceSummary>("workspace_summary");
  },
  recentActivity(limit = 20) {
    return invoke<WorkspaceActivity[]>("recent_activity", { limit });
  },
  systemStatus() {
    return invoke<SystemStatusEntry[]>("system_status");
  },
  search(query: string, limit = 24) {
    return invoke<WorkspaceSearchResult[]>("search_workspace", { query, limit });
  },
  preferences() {
    return invoke<AppPreferences>("get_app_preferences");
  },
  savePreferences(preferences: AppPreferences) {
    return invoke<AppPreferences>("save_app_preferences", { preferences });
  },
  discoverProject(path: string) {
    return invoke<ProjectProfile>("discover_project", { path });
  },
  indexProject(path: string) {
    return invoke<IndexSummary>("index_project", { path });
  },
  listFiles(projectId: string, search: string | null = null, limit = 500) {
    return invoke<SourceFileRecord[]>("list_project_files", { projectId, search, limit });
  },
  searchSymbols(projectId: string, query: string, kind: string | null = null, limit = 500) {
    return invoke<SymbolRecord[]>("search_symbols", {
      projectId,
      search: {
        query,
        mode: "substring",
        kind,
        language: null,
        file: null,
        qualified_only: false,
        limit,
      },
    });
  },
  runSecurity(projectId: string) {
    return invoke("run_security_analysis", { projectId });
  },
  securityFindings(projectId: string, status: string | null = null, limit = 500) {
    return invoke<SecurityFindingRecord[]>("list_security_findings", { projectId, status, limit });
  },
  securityHistory(projectId: string, limit = 50) {
    return invoke<SecurityRunRecord[]>("security_history", { projectId, limit });
  },
  runQaDiscovery(projectId: string) {
    return invoke("run_qa_discovery", { projectId });
  },
  qaArtifacts(projectId: string, limit = 500) {
    return invoke<QaArtifactRecord[]>("list_qa_artifacts", {
      projectId,
      activeOnly: false,
      framework: null,
      limit,
    });
  },
  qaFrameworks(projectId: string) {
    return invoke<QaFrameworkSummary[]>("list_qa_frameworks", { projectId });
  },
  qaHistory(projectId: string, limit = 50) {
    return invoke<QaDiscoveryRunRecord[]>("qa_discovery_history", { projectId, limit });
  },
  languageServers() {
    return invoke<LanguageServerConfig[]>("list_language_server_configs");
  },
  saveLanguageServer(config: LanguageServerConfig) {
    return invoke("set_language_server_config", { config });
  },
  removeLanguageServer(kind: LanguageServerKind) {
    return invoke<boolean>("remove_language_server_config", { kind });
  },
};

export function validateWebsiteUrl(value: string): string | null {
  const raw = value.trim();
  if (!raw) return "Enter a website URL.";
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return "Enter a valid absolute URL, including https:// or http://.";
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return "Only http:// and https:// URLs are supported.";
  }
  if (!parsed.hostname) return "The URL must contain a host.";
  if (parsed.username || parsed.password) return "URLs containing credentials are not accepted.";
  return null;
}

export async function chooseProjectFolder(): Promise<string | null> {
  const selected = await open({
    directory: true,
    multiple: false,
    title: "Add CodeTwin Project Folder",
  });
  return typeof selected === "string" ? selected : null;
}

export async function importProjectPath(
  path: string,
  preferences: AppPreferences,
  onStage?: (stage: ImportStage) => void,
): Promise<{ profile: ProjectProfile; index: IndexSummary }> {
  const normalizedPath = path.trim();
  if (!normalizedPath) throw new Error("Choose a project folder first.");

  onStage?.("discovering");
  const profile = await workspaceApi.discoverProject(normalizedPath);
  onStage?.("indexing");
  const index = await workspaceApi.indexProject(normalizedPath);

  if (preferences.auto_run_security_on_import) {
    onStage?.("security");
    await workspaceApi.runSecurity(index.project_id);
  }
  if (preferences.auto_discover_tests_on_import) {
    onStage?.("testing");
    await workspaceApi.runQaDiscovery(index.project_id);
  }
  return { profile, index };
}
