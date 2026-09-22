import type {
  FixEligibilityAssessment,
  SecurityRemediationCampaignFindingRecord,
  SecurityRemediationCampaignSummary,
  WebFindingRecord,
} from "../types";

export type CampaignFindingFilters = {
  severity: string;
  confidence: string;
  category: string;
  source: string;
  eligibility: string;
};

export function campaignFindingMatches(
  finding: WebFindingRecord,
  assessment: FixEligibilityAssessment | undefined,
  filters: CampaignFindingFilters,
): boolean {
  if (filters.severity && finding.severity !== filters.severity) return false;
  if (filters.confidence && finding.confidence !== filters.confidence) return false;
  if (filters.category && finding.category !== filters.category) return false;
  if (
    filters.source
    && !(finding.source_relative_path ?? "").toLowerCase().includes(filters.source.toLowerCase())
  ) return false;
  if (filters.eligibility && assessment?.result !== filters.eligibility) return false;
  return true;
}

export function eligibleForCampaignSelection(
  assessment: FixEligibilityAssessment | undefined,
): boolean {
  return Boolean(assessment && assessment.result !== "INSUFFICIENT_EVIDENCE");
}

export function currentCampaignFinding(
  findings: SecurityRemediationCampaignFindingRecord[],
): SecurityRemediationCampaignFindingRecord | null {
  const inFlightStatuses = new Set([
    "PREPARING_FIX",
    "AWAITING_REVIEW",
    "APPLYING",
    "VALIDATING",
    "RETESTING",
  ]);
  return findings.find((finding) => inFlightStatuses.has(finding.status))
    ?? findings.find((finding) => finding.status === "QUEUED")
    ?? findings.find((finding) => finding.status === "STILL_VULNERABLE")
    ?? findings.find((finding) => finding.status === "UNABLE_TO_VERIFY")
    ?? findings.find((finding) => finding.status === "REGRESSION_DETECTED")
    ?? findings.find((finding) => finding.status === "BLOCKED")
    ?? findings.find((finding) => finding.status === "MANUAL_ACTION_REQUIRED")
    ?? null;
}

export function campaignProgressPercent(summary: SecurityRemediationCampaignSummary | null): number {
  if (!summary?.selected_findings) return 0;
  const settled = summary.verified_fixed
    + summary.still_vulnerable
    + summary.manual_action_required
    + summary.unable_to_verify
    + summary.regression_detected
    + summary.blocked
    + summary.skipped;
  return Math.round((settled / summary.selected_findings) * 100);
}

export function factualCampaignOutcome(summary: SecurityRemediationCampaignSummary): string {
  return [
    `${summary.verified_fixed} of ${summary.selected_findings} selected findings were verified fixed within the tested scope.`,
    summary.still_vulnerable ? `${summary.still_vulnerable} still vulnerable.` : "",
    summary.manual_action_required ? `${summary.manual_action_required} require manual action.` : "",
    summary.unable_to_verify ? `${summary.unable_to_verify} could not be verified.` : "",
    summary.regression_detected ? `${summary.regression_detected} detected a regression.` : "",
    summary.blocked ? `${summary.blocked} remain blocked.` : "",
    summary.skipped ? `${summary.skipped} were skipped by the developer.` : "",
  ].filter(Boolean).join(" ");
}
