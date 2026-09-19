import { describe, expect, it } from "vitest";

import type {
  FixEligibilityAssessment,
  SecurityRemediationCampaignFindingRecord,
  SecurityRemediationCampaignSummary,
  WebFindingRecord,
} from "../types";
import {
  campaignFindingMatches,
  campaignProgressPercent,
  currentCampaignFinding,
  eligibleForCampaignSelection,
  factualCampaignOutcome,
} from "./securityCampaignModel";

const finding = (overrides: Partial<WebFindingRecord> = {}): WebFindingRecord => ({
  id: "f-1",
  scan_id: "scan-1",
  fingerprint: "fp",
  category: "sql_injection",
  severity: "high",
  confidence: "Likely",
  target: "http://127.0.0.1",
  endpoint_url: "http://127.0.0.1/search?q=a",
  method: "GET",
  parameter_name: "q",
  title: "SQL injection",
  description: "",
  reproduction_summary: "",
  impact: "",
  remediation: "",
  references: [],
  source_file_id: "file-1",
  source_relative_path: "src/api/search.ts",
  source_symbol_id: "symbol-1",
  source_symbol_name: "search",
  source_confidence: 0.9,
  status: "open",
  first_detected: "",
  last_detected: "",
  ...overrides,
});

const assessment = (result: FixEligibilityAssessment["result"]): FixEligibilityAssessment => ({
  finding_id: "f-1",
  result,
  reasons: [],
  evidence_count: 2,
  source_candidate_count: 1,
  best_source_confidence: 0.9,
  supported_language: "typescript",
  bounded_patch_available: result === "AUTO_FIX_CANDIDATE",
});

const campaignFinding = (
  status: SecurityRemediationCampaignFindingRecord["status"],
  ordinal: number,
): SecurityRemediationCampaignFindingRecord => ({
  campaign_id: "campaign-1",
  finding_id: `f-${ordinal}`,
  ordinal,
  status,
  eligibility: "AUTO_FIX_CANDIDATE",
  severity: "high",
  confidence: "Likely",
  category: "sql_injection",
  endpoint_url: "http://127.0.0.1/search",
  source_file_id: null,
  source_symbol_id: null,
  root_file_id: null,
  root_symbol_id: null,
  shared_root_primary_finding_id: null,
  order_reason: "",
  depends_on: [],
  expected_affected: [],
  retest_floor_rowid: 0,
  active_attempt_id: null,
  skip_reason: null,
  created_at: "",
  updated_at: "",
});

describe("security remediation campaign frontend model", () => {
  it("filters by persisted finding fields and Fix & Verify eligibility without upgrading it", () => {
    expect(campaignFindingMatches(finding(), assessment("AUTO_FIX_CANDIDATE"), {
      severity: "high",
      confidence: "Likely",
      category: "sql_injection",
      source: "search.ts",
      eligibility: "AUTO_FIX_CANDIDATE",
    })).toBe(true);
    expect(eligibleForCampaignSelection(assessment("INSUFFICIENT_EVIDENCE"))).toBe(false);
    expect(eligibleForCampaignSelection(assessment("MANUAL_REMEDIATION"))).toBe(true);
  });

  it("keeps the ordered unresolved finding as the current campaign work item", () => {
    const current = currentCampaignFinding([
      campaignFinding("VERIFIED", 1),
      campaignFinding("AWAITING_REVIEW", 2),
      campaignFinding("QUEUED", 3),
    ]);
    expect(current?.finding_id).toBe("f-2");
  });

  it("reports only factual settled progress and never a security score", () => {
    const summary: SecurityRemediationCampaignSummary = {
      selected_findings: 10,
      verified_fixed: 5,
      still_vulnerable: 1,
      manual_action_required: 1,
      unable_to_verify: 1,
      regression_detected: 0,
      blocked: 0,
      skipped: 1,
      queued_or_in_progress: 1,
    };
    expect(campaignProgressPercent(summary)).toBe(90);
    expect(factualCampaignOutcome(summary)).toContain("5 of 10 selected findings were verified fixed");
    expect(factualCampaignOutcome(summary)).not.toContain("secure");
  });
});
