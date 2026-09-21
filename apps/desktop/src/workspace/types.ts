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
  guided_session_id?: string | null;
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


export type GuidedEnvironment = "local" | "development" | "staging" | "authorized_production";
export type GuidedTestingDepth = "quick" | "standard" | "deep" | "custom";
export type GuidedAuthMode = "none" | "existing_session" | "test_account_a" | "test_accounts_a_b";
export type GuidedRisk = "SAFE" | "CAUTION" | "RESTRICTED";

export type GuidedSecurityPrepareRequest = {
  website_id: string | null;
  project_id: string | null;
  environment: GuidedEnvironment;
  testing_depth: GuidedTestingDepth;
  auth_mode: GuidedAuthMode;
  config: WebScanConfig;
  primary_auth: WebAuthContext;
  secondary_auth: WebAuthContext | null;
};

export type GuidedSecuritySessionRecord = {
  id: string;
  website_id: string | null;
  project_id: string | null;
  target_url: string;
  environment: GuidedEnvironment;
  testing_depth: GuidedTestingDepth;
  auth_mode: GuidedAuthMode;
  status: "preparing" | "awaiting_approval" | "approved" | "running" | "completed" | "failed" | "cancelled";
  authorization_confirmed: boolean;
  config_json: string;
  preflight_json: string;
  application_map_json: string;
  plan_json: string;
  mapping_requests: number;
  scan_id: string | null;
  last_error: string | null;
  created_at: string;
  prepared_at: string | null;
  approved_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string;
};

export type GuidedPreflight = {
  authorized_target: string;
  resolved_address: string;
  ip_classification: string;
  allowed_hostnames: string[];
  allowed_subdomains: string[];
  allowed_paths: string[];
  excluded_paths: string[];
  port: number;
  https_behavior: string;
  redirect_limit: number;
  max_requests: number;
  concurrency: number;
  timeout_ms: number;
  authentication_available: boolean;
  destructive_actions: boolean;
  state_changing_testing: boolean;
  timing_probes: boolean;
};

export type GuidedApplicationRoute = {
  url: string;
  method: string;
  source: string;
  parameters: string[];
  parameter_locations: Record<string, string>;
  content_type: string | null;
  status_code: number | null;
  cookies: string[];
  authentication_boundary: boolean;
  source_hints: Array<{
    relative_path: string;
    symbol_name: string | null;
    confidence: number;
  }>;
};

export type GuidedApplicationMap = {
  groups: Array<{ label: string; routes: GuidedApplicationRoute[] }>;
  endpoint_count: number;
  page_count: number;
  form_count: number;
  api_endpoint_count: number;
  parameter_count: number;
  authenticated_endpoint_count: number;
};

export type GuidedPlanItemRecord = {
  id: string;
  session_id: string;
  operation_key: string;
  endpoint_url: string;
  method: string;
  parameter_name: string | null;
  category: string;
  risk: GuidedRisk;
  selected: boolean;
  reason: string;
  skip_reason: string | null;
  created_at: string;
};

export type GuidedTestPlan = {
  endpoint_count: number;
  form_count: number;
  parameter_count: number;
  selected_count: number;
  skipped_count: number;
  counts_by_category: Record<string, number>;
  counts_by_risk: Record<string, number>;
  operations: Array<{
    operation_key: string;
    endpoint_url: string;
    method: string;
    parameter_name: string | null;
    category: string;
    risk: GuidedRisk;
    selected: boolean;
    reason: string;
    skip_reason: string | null;
  }>;
};

export type GuidedActivityRecord = {
  id: string;
  session_id: string;
  sequence: number;
  event_type: string;
  phase: string;
  message: string;
  detail_json: string;
  created_at: string;
};

export type GuidedSourceCandidate = {
  id: string;
  finding_id: string;
  rank: number;
  file_id: string;
  relative_path: string;
  symbol_id: string | null;
  symbol_name: string | null;
  confidence: number;
  rationale: string;
  created_at: string;
};

export type GuidedSecurityScorecard = {
  endpoints_mapped: number;
  endpoints_tested: number;
  coverage_percent: number;
  confirmed_findings: number;
  likely_findings: number;
  potential_findings: number;
  rejected_anomalies: number;
  by_severity: Record<string, number>;
  authentication_context_supplied: boolean;
  authenticated_endpoints_mapped: number;
  planned_authorization_checks: number;
  authorization_plan_coverage_percent: number;
  planned_api_validation_checks: number;
  api_validation_plan_coverage_percent: number;
  planned_input_checks: number;
  input_plan_coverage_percent: number;
};

export type GuidedRiskGraph = {
  nodes: Array<{ id: string; kind: string; label: string }>;
  edges: Array<{ from: string; to: string; relationship: string }>;
};

export type GuidedRetestRecord = {
  id: string;
  finding_id: string;
  session_id: string | null;
  status: "retest_passed" | "still_vulnerable" | "unable_to_verify";
  original_confidence: string;
  observed_confidence: string | null;
  requests_performed: number;
  detail_json: string;
  created_at: string;
};

export type GuidedScanComparison = {
  id: string;
  session_id: string | null;
  previous_scan_id: string;
  current_scan_id: string;
  comparison_json: string;
  created_at: string;
};

export type GuidedFixPreparation = {
  finding_id: string;
  project_id: string;
  repair: {
    id: string;
    project_id: string;
    finding_id: string | null;
    title: string;
    rationale: string;
    status: string;
    created_at: string;
    updated_at: string;
    approved_at?: string | null;
  };
  source_candidates: GuidedSourceCandidate[];
  remediation: string;
};


export type FixEligibility =
  | "AUTO_FIX_CANDIDATE"
  | "GUIDED_FIX_CANDIDATE"
  | "MANUAL_REMEDIATION"
  | "INSUFFICIENT_EVIDENCE";

export type PatchSafetyClass = "SAFE_TO_REVIEW" | "CAUTION" | "REJECTED";

export type SecurityRemediationCampaignStatus =
  | "DRAFT"
  | "ANALYZING"
  | "READY_FOR_REVIEW"
  | "APPROVED"
  | "IN_PROGRESS"
  | "PAUSED"
  | "BLOCKED"
  | "COMPLETED"
  | "COMPLETED_WITH_UNRESOLVED_FINDINGS"
  | "CANCELLED";

export type SecurityRemediationFindingStatus =
  | "QUEUED"
  | "PREPARING_FIX"
  | "AWAITING_REVIEW"
  | "APPLYING"
  | "VALIDATING"
  | "RETESTING"
  | "VERIFIED"
  | "STILL_VULNERABLE"
  | "MANUAL_ACTION_REQUIRED"
  | "UNABLE_TO_VERIFY"
  | "REGRESSION_DETECTED"
  | "BLOCKED"
  | "SKIPPED";

export type SecurityRemediationRelationship =
  | "INDEPENDENT"
  | "SHARED_ROOT_CAUSE"
  | "SOURCE_OVERLAP"
  | "VALIDATION_DEPENDENCY"
  | "RETEST_DEPENDENCY"
  | "POTENTIAL_CONFLICT";

export type SecurityRemediationCampaignCreate = {
  session_id: string;
  finding_ids: string[];
};

export type SecurityRemediationCampaignRecord = {
  id: string;
  session_id: string;
  scan_id: string;
  project_id: string;
  target_url: string;
  environment: GuidedEnvironment;
  scope_json: string;
  status: SecurityRemediationCampaignStatus;
  selected_count: number;
  plan_revision: number;
  plan_json: string;
  plan_hash: string | null;
  approved_plan_hash: string | null;
  baseline_json: string;
  completion_json: string;
  completion_retest_floor_rowid: number;
  completion_verification_started_at: string | null;
  completion_verification_completed_at: string | null;
  completion_source_hashes_json: string;
  created_at: string;
  analyzed_at: string | null;
  approved_at: string | null;
  started_at: string | null;
  paused_at: string | null;
  finished_at: string | null;
  updated_at: string;
};

export type SecurityRemediationCampaignFindingRecord = {
  campaign_id: string;
  finding_id: string;
  ordinal: number;
  status: SecurityRemediationFindingStatus;
  eligibility: FixEligibility;
  severity: WebFindingRecord["severity"];
  confidence: WebFindingRecord["confidence"];
  category: string;
  endpoint_url: string;
  source_file_id: string | null;
  source_symbol_id: string | null;
  root_file_id: string | null;
  root_symbol_id: string | null;
  shared_root_primary_finding_id: string | null;
  order_reason: string;
  depends_on: string[];
  expected_affected: string[];
  retest_floor_rowid: number;
  active_attempt_id: string | null;
  skip_reason: string | null;
  created_at: string;
  updated_at: string;
};

export type SecurityRemediationRelationshipRecord = {
  id: string;
  campaign_id: string;
  from_finding_id: string;
  to_finding_id: string;
  relationship: SecurityRemediationRelationship;
  confidence: number;
  reason: string;
  created_at: string;
};

export type SecurityRemediationCampaignEventRecord = {
  id: string;
  campaign_id: string;
  sequence: number;
  event_type: string;
  message: string;
  detail_json: string;
  created_at: string;
};

export type SecurityRemediationPlanItem = {
  finding_id: string;
  ordinal: number;
  eligibility: FixEligibility;
  order_reason: string;
  depends_on: string[];
  expected_affected: string[];
  shared_root_primary_finding_id: string | null;
};

export type SecurityRemediationCampaignPlan = {
  version: number;
  project_id: string;
  scan_id: string;
  target_url: string;
  environment: GuidedEnvironment;
  scope_sha256: string;
  ordered_findings: SecurityRemediationPlanItem[];
  relationship_count: number;
  mutation_strategy: string;
};

export type SecurityRemediationCampaignSummary = {
  selected_findings: number;
  verified_fixed: number;
  still_vulnerable: number;
  manual_action_required: number;
  unable_to_verify: number;
  regression_detected: number;
  blocked: number;
  skipped: number;
  queued_or_in_progress: number;
};

export type SecurityRemediationBeforeAfterItem = {
  finding_id: string;
  severity: string;
  confidence: string;
  baseline_status: string;
  campaign_status: SecurityRemediationFindingStatus;
  attempt_id: string | null;
  validation_state: string | null;
  retest_state: string | null;
};

export type SecurityRemediationRegressionTracking = {
  finding_id: string;
  attempt_id: string | null;
  generation_status: string;
  recommendation: string;
  execution_status: "PASSED" | "FAILED" | "NOT_EXECUTED";
};

export type SecurityRemediationRollbackAssessment = {
  finding_id: string;
  attempt_id: string | null;
  allowed: boolean;
  blocking_findings: string[];
  reason: string;
};

export type SecurityRemediationDebtView = {
  unresolved_total: number;
  by_severity: Record<string, number>;
  by_eligibility: Record<string, number>;
  by_module: Record<string, number>;
  by_endpoint: Record<string, number>;
  by_reason: Record<string, number>;
};


export type FixEligibilityAssessment = {
  finding_id: string;
  result: FixEligibility;
  reasons: string[];
  evidence_count: number;
  source_candidate_count: number;
  best_source_confidence: number | null;
  supported_language: string | null;
  bounded_patch_available: boolean;
};

export type RootCauseCandidate = {
  file_id: string;
  relative_path: string;
  symbol_id: string | null;
  symbol_name: string | null;
  source_start_line: number | null;
  source_end_line: number | null;
  confidence: number;
  reasoning: string[];
};

export type FixStrategy = {
  category: string;
  change_summary: string;
  rationale: string;
  likely_files: string[];
  expected_behavior: string;
  compatibility_risks: string[];
  prohibited_shortcuts: string[];
  regression_test_suggestion: string;
};

export type PatchSafetyReport = {
  classification: PatchSafetyClass;
  patch_hash: string;
  files_changed: number;
  changed_lines: number;
  risk_notes: string[];
  rejected_reasons: string[];
};

export type SelectedValidation = {
  label: string;
  runner_kind: string;
  targets: string[];
  reason: string;
  repository_command_execution_required: boolean;
};

export type SecurityFixTestPlan = {
  targeted: SelectedValidation[];
  full_suite_optional: boolean;
  qa_execution_available: boolean;
  qa_execution_reason: string;
  security_retest: string;
  regression_test_proposal: string;
  regression_generation_status: "EXISTING_TEST_SELECTED" | "RECOMMENDATION_ONLY";
  regression_generation_reason: string;
};

export type SecurityFixAttemptRecord = {
  id: string;
  finding_id: string;
  session_id: string | null;
  project_id: string;
  repair_id: string | null;
  attempt_number: number;
  eligibility: FixEligibility;
  category: string;
  status:
    | "prepared"
    | "patch_proposed"
    | "rejected"
    | "approved"
    | "applied"
    | "validation_failed"
    | "verification_pending"
    | "fix_verified"
    | "still_vulnerable"
    | "unable_to_verify"
    | "rolled_back";
  root_causes: RootCauseCandidate[];
  strategy: FixStrategy;
  test_plan: SecurityFixTestPlan;
  patch_hash: string | null;
  safety_class: PatchSafetyClass | null;
  safety: PatchSafetyReport | null;
  approved_patch_hash: string | null;
  approved_files_json: string | null;
  approved_safety_class: PatchSafetyClass | null;
  caution_acknowledged: boolean;
  approved_at: string | null;
  application_run_id: string | null;
  retest_floor_rowid: number;
  validation_state: "not_executed" | "passed" | "failed" | "partial";
  retest_state:
    | "not_executed"
    | "FIX_VERIFIED"
    | "STILL_VULNERABLE"
    | "UNABLE_TO_VERIFY"
    | "REGRESSION_DETECTED";
  static_before_json: string;
  static_after_json: string;
  created_at: string;
  updated_at: string;
};

export type SecurityFixPreparation = {
  attempt: SecurityFixAttemptRecord;
  eligibility: FixEligibilityAssessment;
  root_causes: RootCauseCandidate[];
  strategy: FixStrategy;
  test_plan: SecurityFixTestPlan;
  repair: {
    id: string;
    project_id: string;
    finding_id: string | null;
    title: string;
    rationale: string;
    status: string;
    created_at: string;
    updated_at: string;
    approved_at: string | null;
    verified_at: string | null;
  } | null;
};

export type PatchReview = {
  attempt_id: string;
  repair_id: string;
  unified_diff: string;
  safety: PatchSafetyReport;
  affected_files: string[];
  expected_behavior: string;
  tests_to_run: string[];
  security_retest: string;
};

export type SecurityFixValidationRecord = {
  id: string;
  attempt_id: string;
  sequence: number;
  command_label: string;
  runner_kind: string;
  targets: string[];
  status: "PASS" | "FAIL" | "NOT_EXECUTED";
  exit_code: number | null;
  duration_ms: number | null;
  classification:
    | "NONE"
    | "PRE_EXISTING_FAILURE"
    | "PATCH_INTRODUCED_FAILURE"
    | "INFRASTRUCTURE_FAILURE"
    | "UNKNOWN";
  stdout_summary: string;
  stderr_summary: string;
  created_at: string;
};

export type SecurityFixEventRecord = {
  id: string;
  attempt_id: string;
  sequence: number;
  event_type: string;
  message: string;
  detail_json: string;
  created_at: string;
};

export type SecurityFixApplicationResult = {
  attempt: SecurityFixAttemptRecord;
  application: {
    id: string;
    repair_id: string;
    project_id: string;
    status: string;
    changes_total: number;
    changes_applied: number;
    rollback_performed: boolean;
    backup_dir_name: string;
    error_message: string | null;
    created_at: string;
    completed_at: string | null;
  };
};

export type SecurityFixValidationRun = {
  attempt: SecurityFixAttemptRecord;
  results: SecurityFixValidationRecord[];
};

export type MultiFindingOverlap = {
  finding_ids: string[];
  overlapping_files: string[];
  requires_combined_review: boolean;
  message: string;
};

export type RepairSourceSnapshot = {
  file_id: string;
  project_id: string;
  relative_path: string;
  language: string | null;
  content_hash: string;
  byte_size: number;
  content: string;
};
