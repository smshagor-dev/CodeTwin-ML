export type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

export type ProjectProfile = {
  languages: string[];
  frameworks: string[];
  package_managers: string[];
  build_systems: string[];
  test_frameworks: string[];
  databases: string[];
  ci_providers: string[];
  project_kinds: string[];
};

export type ProjectOverview = {
  id: string;
  display_name: string;
  root_path: string;
  path_identity: string;
  git_remote: string | null;
  last_opened_at: string | null;
  last_indexed_at: string | null;
  file_count: number;
  symbol_count: number;
  language_count: number;
  last_index_status: AnalysisStatus | null;
  last_index_duration_ms: number | null;
};

export type WebsiteRecord = {
  id: string;
  url: string;
  normalized_url: string;
  display_name: string;
  project_id: string | null;
  project_name: string | null;
  status: "not_checked" | "online" | "degraded" | "offline";
  http_status: number | null;
  last_checked_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

export type WorkspaceSummary = {
  project_count: number;
  website_count: number;
  active_agents: number;
  security_scan_count: number;
};

export type WorkspaceActivity = {
  id: string;
  kind: "project" | "website" | "analysis" | string;
  title: string;
  detail: string;
  status: string;
  occurred_at: string;
  project_id: string | null;
};

export type WorkspaceSearchResult = {
  kind: "project" | "website" | "file" | "symbol" | string;
  id: string;
  title: string;
  subtitle: string;
  project_id: string | null;
  file_id: string | null;
};

export type AppPreferences = {
  display_name: string;
  theme: "system" | "light" | "dark";
  auto_run_security_on_import: boolean;
  auto_discover_tests_on_import: boolean;
};

export type SystemStatusEntry = {
  key: string;
  label: string;
  state: "operational" | "limited" | "unavailable" | string;
  detail: string;
};

export type IndexSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  delta: {
    files_scanned: number;
    files_added: number;
    files_modified: number;
    files_unchanged: number;
    files_deleted: number;
    symbols_added: number;
    symbols_updated: number;
    symbols_removed: number;
    parse_errors: number;
    skipped_files: number;
  };
  graph_node_count: number;
  graph_edge_count: number;
  duration_ms: number;
};

export type SourceFileRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  relative_path_identity: string;
  language: string | null;
  content_hash: string;
  byte_size: number;
  ast_root_kind: string | null;
  parse_state: string | null;
  is_active: boolean;
};

export type SymbolRecord = {
  id: string;
  project_id: string;
  file_id: string;
  kind: string;
  name: string;
  qualified_name: string | null;
  parent_symbol_id: string | null;
  fingerprint: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

export type SecurityFindingRecord = {
  id: string;
  project_id: string;
  run_id: string;
  rule_id: string;
  severity: string;
  title: string;
  description: string;
  file_id: string | null;
  source_start_line: number | null;
  source_end_line: number | null;
  status: string;
  first_seen: string;
  last_seen: string;
  cwe: string | null;
  owasp: string | null;
};

export type SecurityRunRecord = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  files_considered: number;
  files_analyzed: number;
  findings_opened: number;
  findings_refreshed: number;
  findings_resolved: number;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

export type QaArtifactRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  artifact_kind: string;
  framework: string;
  evidence_kind: string;
  last_seen_at: string;
  is_active: boolean;
};

export type QaFrameworkSummary = {
  framework: string;
  artifacts: number;
  test_files: number;
  config_files: number;
};

export type QaDiscoveryRunRecord = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  candidate_files: number;
  artifacts_discovered: number;
  artifacts_skipped: number;
  test_files: number;
  config_files: number;
  framework_count: number;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

export type LanguageServerKind = "typescript" | "pyright" | "rust_analyzer";
export type LanguageServerConfig = {
  kind: LanguageServerKind;
  executable_path: string;
  arguments: string[];
  initialization_options: unknown | null;
  enabled: boolean;
};

export type WebScopeConfig = {
  target_url: string;
  allowed_hostnames: string[];
  allowed_subdomains: string[];
  allowed_paths: string[];
  excluded_paths: string[];
  max_crawl_depth: number;
  max_requests: number;
  concurrency: number;
  timeout_ms: number;
  response_limit_bytes: number;
  redirect_limit: number;
  retry_limit: number;
  active_testing: boolean;
  allow_non_idempotent_methods: boolean;
  allow_private_networks: boolean;
  enable_timing_probes: boolean;
  authorization_confirmed: boolean;
};

export type WebCheckConfig = {
  sql_injection: boolean;
  xss: boolean;
  csrf: boolean;
  open_redirect: boolean;
  path_traversal: boolean;
  ssrf_indicators: boolean;
  template_command_indicators: boolean;
  method_misconfiguration: boolean;
  cors: boolean;
  session: boolean;
  access_control: boolean;
  api_validation: boolean;
};

export type WebScanConfig = {
  scope: WebScopeConfig;
  checks: WebCheckConfig;
};

export type WebAuthContext = {
  cookie_header: string | null;
  bearer_token: string | null;
  custom_headers: Array<[string, string]>;
};

export type WebScanStartRequest = {
  website_id: string | null;
  project_id: string | null;
  config: WebScanConfig;
  primary_auth: WebAuthContext;
  secondary_auth: WebAuthContext | null;
};

export type WebScanRecord = {
  id: string;
  website_id: string | null;
  project_id: string | null;
  target_url: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  phase: "queued" | "discovering" | "crawling" | "passive_analysis" | "active_testing" | "correlating" | "completed" | "failed" | "cancelled";
  authorization_confirmed: boolean;
  scope_json: string;
  config_json: string;
  auth_metadata_json: string;
  endpoints_discovered: number;
  requests_performed: number;
  findings_count: number;
  last_error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  cancelled_at: string | null;
};

export type WebEndpointRecord = {
  id: string;
  scan_id: string;
  url: string;
  method: string;
  depth: number;
  source: string;
  parameter_names: string[];
  parameter_locations: Record<string, string>;
  response_header_names: string[];
  cookie_names: string[];
  content_type: string | null;
  status_code: number | null;
  redirect_to: string | null;
  created_at: string;
};

export type WebFindingRecord = {
  id: string;
  scan_id: string;
  fingerprint: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence: "Potential" | "Likely" | "Confirmed";
  target: string;
  endpoint_url: string;
  method: string;
  parameter_name: string | null;
  title: string;
  description: string;
  reproduction_summary: string;
  impact: string;
  remediation: string;
  references: string[];
  source_file_id: string | null;
  source_relative_path: string | null;
  source_symbol_id: string | null;
  source_symbol_name: string | null;
  source_confidence: number | null;
  status: "open" | "resolved" | "accepted_risk" | "false_positive";
  first_detected: string;
  last_detected: string;
};

export type WebEvidenceRecord = {
  id: string;
  finding_id: string;
  summary: string;
  request_metadata_json: string;
  response_metadata_json: string;
  created_at: string;
};

export type WebFindingFilter = {
  severity: string | null;
  category: string | null;
  confidence: string | null;
  endpoint: string | null;
  status: string | null;
};
