export type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "confirmed" | "false_positive" | "accepted_risk" | "fixed" | "regression";

export interface ProjectProfile {
  languages: string[];
  frameworks: string[];
  package_managers: string[];
  build_systems: string[];
  test_frameworks: string[];
  databases: string[];
  ci_providers: string[];
  project_kinds: string[];
}
