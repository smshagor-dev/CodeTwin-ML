import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

import type {
  AppPreferences,
  GuidedActivityRecord,
  GuidedFixPreparation,
  GuidedPlanItemRecord,
  GuidedRetestRecord,
  GuidedRiskGraph,
  GuidedScanComparison,
  GuidedSecurityPrepareRequest,
  GuidedSecurityScorecard,
  GuidedSecuritySessionRecord,
  GuidedSourceCandidate,
  FixEligibilityAssessment,
  IndexSummary,
  MultiFindingOverlap,
  PatchReview,
  RepairSourceSnapshot,
  LanguageServerConfig,
  LanguageServerKind,
  ProjectOverview,
  ProjectProfile,
  QaArtifactRecord,
  QaDiscoveryRunRecord,
  QaFrameworkSummary,
  SecurityFindingRecord,
  SecurityFixApplicationResult,
  SecurityFixAttemptRecord,
  SecurityFixEventRecord,
  SecurityFixPreparation,
  SecurityFixValidationRecord,
  SecurityFixValidationRun,
  SecurityRunRecord,
  SourceFileRecord,
  SymbolRecord,
  SystemStatusEntry,
  WebsiteRecord,
  WorkspaceActivity,
  WorkspaceSearchResult,
  WorkspaceSummary,
  WebEndpointRecord,
  WebEvidenceRecord,
  WebFindingFilter,
  WebFindingRecord,
  WebScanRecord,
  WebScanStartRequest,
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
  prepareGuidedSecurityTest(request: GuidedSecurityPrepareRequest) {
    return invoke<GuidedSecuritySessionRecord>("prepare_guided_security_test", { request });
  },
  approveGuidedSecurityPlan(sessionId: string) {
    return invoke<GuidedSecuritySessionRecord>("approve_guided_security_plan", { sessionId });
  },
  getGuidedSecuritySession(sessionId: string) {
    return invoke<GuidedSecuritySessionRecord | null>("get_guided_security_session", { sessionId });
  },
  listGuidedSecuritySessions(projectId: string | null = null, limit = 100) {
    return invoke<GuidedSecuritySessionRecord[]>("list_guided_security_sessions", { projectId, limit });
  },
  listGuidedSecurityPlanItems(sessionId: string, limit = 1000) {
    return invoke<GuidedPlanItemRecord[]>("list_guided_security_plan_items", { sessionId, limit });
  },
  listGuidedSecurityActivity(sessionId: string, limit = 500) {
    return invoke<GuidedActivityRecord[]>("list_guided_security_activity", { sessionId, limit });
  },
  correlateGuidedSecuritySources(findingId: string, limit = 5) {
    return invoke<GuidedSourceCandidate[]>("correlate_guided_security_sources", { findingId, limit });
  },
  guidedSecurityScorecard(sessionId: string) {
    return invoke<GuidedSecurityScorecard>("guided_security_scorecard", { sessionId });
  },
  guidedSecurityRiskGraph(sessionId: string) {
    return invoke<GuidedRiskGraph>("guided_security_risk_graph", { sessionId });
  },
  compareGuidedSecurityScans(sessionId: string | null, previousScanId: string, currentScanId: string) {
    return invoke<GuidedScanComparison>("compare_guided_security_scans", {
      sessionId,
      previousScanId,
      currentScanId,
    });
  },
  prepareGuidedSecurityFix(findingId: string) {
    return invoke<GuidedFixPreparation>("prepare_guided_security_fix", { findingId });
  },
  retestGuidedSecurityFinding(findingId: string, primaryAuth: import("./types").WebAuthContext, secondaryAuth: import("./types").WebAuthContext | null) {
    return invoke<GuidedRetestRecord>("retest_guided_security_finding", {
      request: {
        finding_id: findingId,
        primary_auth: primaryAuth,
        secondary_auth: secondaryAuth,
      },
    });
  },
  listGuidedSecurityRetestCandidates(sessionId: string, limit = 500) {
    return invoke<string[]>("list_guided_security_retest_candidates", { sessionId, limit });
  },
  listGuidedSecurityRetests(findingId: string, limit = 50) {
    return invoke<GuidedRetestRecord[]>("list_guided_security_retests", { findingId, limit });
  },
  evaluateSecurityFixEligibility(findingId: string) {
    return invoke<FixEligibilityAssessment>("evaluate_security_fix_eligibility", { findingId });
  },
  prepareSecurityFix(findingId: string, allowAdditionalAttempt = false) {
    return invoke<SecurityFixPreparation>("prepare_security_fix", {
      findingId,
      allowAdditionalAttempt,
    });
  },
  generateSecurityFixPatch(attemptId: string) {
    return invoke<PatchReview>("generate_security_fix_patch", { attemptId });
  },
  proposeSecurityFixReplacement(attemptId: string, fileId: string, proposedContent: string) {
    return invoke<PatchReview>("propose_security_fix_replacement", {
      attemptId,
      fileId,
      proposedContent,
    });
  },
  reviewSecurityFix(attemptId: string) {
    return invoke<PatchReview>("review_security_fix", { attemptId });
  },
  approveSecurityFix(attemptId: string, acceptCaution: boolean) {
    return invoke<SecurityFixAttemptRecord>("approve_security_fix", {
      attemptId,
      acceptCaution,
    });
  },
  getSecurityFixAttempt(attemptId: string) {
    return invoke<SecurityFixAttemptRecord | null>("get_security_fix_attempt", { attemptId });
  },
  listSecurityFixAttempts(findingId: string, limit = 20) {
    return invoke<SecurityFixAttemptRecord[]>("list_security_fix_attempts", { findingId, limit });
  },
  listSecurityFixValidation(attemptId: string, limit = 200) {
    return invoke<SecurityFixValidationRecord[]>("list_security_fix_validation", { attemptId, limit });
  },
  listSecurityFixEvents(attemptId: string, limit = 200) {
    return invoke<SecurityFixEventRecord[]>("list_security_fix_events", { attemptId, limit });
  },
  analyzeSecurityFixOverlap(findingIds: string[]) {
    return invoke<MultiFindingOverlap>("analyze_security_fix_overlap", { findingIds });
  },
  applySecurityFix(attemptId: string) {
    return invoke<SecurityFixApplicationResult>("apply_security_fix", { attemptId });
  },
  rollbackSecurityFix(attemptId: string) {
    return invoke<SecurityFixApplicationResult>("rollback_security_fix", { attemptId });
  },
  runSecurityFixValidation(attemptId: string) {
    return invoke<SecurityFixValidationRun>("run_security_fix_validation", { attemptId });
  },
  readRepairSource(fileId: string) {
    return invoke<RepairSourceSnapshot>("read_repair_source", { fileId });
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
  startWebSecurityScan(request: WebScanStartRequest) {
    return invoke<WebScanRecord>("start_web_security_scan", { request });
  },
  cancelWebSecurityScan(scanId: string) {
    return invoke<boolean>("cancel_web_security_scan", { scanId });
  },
  getWebSecurityScan(scanId: string) {
    return invoke<WebScanRecord | null>("get_web_security_scan", { scanId });
  },
  listWebSecurityScans(websiteId: string | null = null, projectId: string | null = null, limit = 100) {
    return invoke<WebScanRecord[]>("list_web_security_scans", { websiteId, projectId, limit });
  },
  listWebSecurityEndpoints(scanId: string, limit = 500) {
    return invoke<WebEndpointRecord[]>("list_web_security_endpoints", { scanId, limit });
  },
  listWebSecurityFindings(scanId: string, filter: WebFindingFilter, limit = 500) {
    return invoke<WebFindingRecord[]>("list_web_security_findings", { scanId, filter, limit });
  },
  listWebSecurityEvidence(findingId: string, limit = 50) {
    return invoke<WebEvidenceRecord[]>("list_web_security_evidence", { findingId, limit });
  },
  updateWebSecurityFindingStatus(findingId: string, status: string) {
    return invoke<boolean>("update_web_security_finding_status", { findingId, status });
  },
  generateWebSecurityReport(scanId: string, format: "markdown" | "json") {
    return invoke<string>("generate_web_security_report", { scanId, format });
  },
  exportWebSecurityReport(scanId: string, format: "markdown" | "json", path: string) {
    return invoke<string>("export_web_security_report", { scanId, format, path });
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
): Promise<{ profile: ProjectProfile; index: IndexSummary; postImportErrors: string[] }> {
  const normalizedPath = path.trim();
  if (!normalizedPath) throw new Error("Choose a project folder first.");

  onStage?.("discovering");
  const profile = await workspaceApi.discoverProject(normalizedPath);
  onStage?.("indexing");
  const index = await workspaceApi.indexProject(normalizedPath);

  const postImportErrors: string[] = [];
  if (preferences.auto_run_security_on_import) {
    onStage?.("security");
    try {
      await workspaceApi.runSecurity(index.project_id);
    } catch (error) {
      postImportErrors.push("security analysis: " + String(error));
    }
  }
  if (preferences.auto_discover_tests_on_import) {
    onStage?.("testing");
    try {
      await workspaceApi.runQaDiscovery(index.project_id);
    } catch (error) {
      postImportErrors.push("QA discovery: " + String(error));
    }
  }
  return { profile, index, postImportErrors };
}


export async function chooseWebSecurityReportPath(
  format: "markdown" | "json",
): Promise<string | null> {
  const extension = format === "json" ? "json" : "md";
  const selected = await save({
    title: "Export CodeTwin Security Report",
    defaultPath: "codetwin-security-report." + extension,
    filters: [{
      name: format === "json" ? "JSON report" : "Markdown report",
      extensions: [extension],
    }],
  });
  return typeof selected === "string" ? selected : null;
}
