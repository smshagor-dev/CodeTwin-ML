import { describe, expect, it } from "vitest";

import type {
  PatchReview,
  SecurityFixAttemptRecord,
} from "../types";
import {
  canApproveAndApplySecurityFix,
  isAttemptLimitError,
  isStaleApprovalError,
  securityFixActions,
  securityFixDisplayStatus,
  securityFixRetestExplanation,
  securityFixStage,
} from "./securityFixModel";

function attempt(
  status: SecurityFixAttemptRecord["status"],
  retestState: SecurityFixAttemptRecord["retest_state"] = "not_executed",
  overrides: Partial<SecurityFixAttemptRecord> = {},
): SecurityFixAttemptRecord {
  return {
    id: "attempt-1",
    finding_id: "finding-1",
    session_id: "session-1",
    project_id: "project-1",
    repair_id: "repair-1",
    attempt_number: 1,
    eligibility: "AUTO_FIX_CANDIDATE",
    category: "sql_injection",
    status,
    root_causes: [{
      file_id: "file-1",
      relative_path: "src/search.ts",
      symbol_id: "symbol-1",
      symbol_name: "search",
      source_start_line: 1,
      source_end_line: 5,
      confidence: 0.91,
      reasoning: ["runtime route correlation"],
    }],
    strategy: {
      category: "sql_injection",
      change_summary: "Use parameter binding.",
      rationale: "Treat input as data.",
      likely_files: ["src/search.ts"],
      expected_behavior: "SQL-shaped input remains data.",
      compatibility_risks: [],
      prohibited_shortcuts: ["No manual quote escaping."],
      regression_test_suggestion: "Search remains functional.",
    },
    test_plan: {
      targeted: [],
      full_suite_optional: true,
      qa_execution_available: false,
      qa_execution_reason: "sandbox unavailable",
      security_retest: "targeted SQLi retest",
      regression_test_proposal: "normal and SQL-shaped search input",
      regression_generation_status: "RECOMMENDATION_ONLY",
      regression_generation_reason: "test location not safely inferred",
    },
    patch_hash: "a".repeat(64),
    safety_class: "SAFE_TO_REVIEW",
    safety: null,
    approved_patch_hash: null,
    approved_files_json: null,
    approved_safety_class: null,
    caution_acknowledged: false,
    approved_at: null,
    application_run_id: null,
    validation_state: "not_executed",
    retest_state: retestState,
    static_before_json: "{}",
    static_after_json: "{}",
    created_at: "2026-09-19T00:00:00Z",
    updated_at: "2026-09-19T00:00:00Z",
    ...overrides,
  };
}

function review(classification: PatchReview["safety"]["classification"]): PatchReview {
  return {
    attempt_id: "attempt-1",
    repair_id: "repair-1",
    unified_diff: "--- a/src/search.ts\n+++ b/src/search.ts",
    safety: {
      classification,
      patch_hash: "a".repeat(64),
      files_changed: 1,
      changed_lines: 1,
      risk_notes: classification === "CAUTION" ? ["review exception handling"] : [],
      rejected_reasons: classification === "REJECTED" ? ["unsafe change"] : [],
    },
    affected_files: ["src/search.ts"],
    expected_behavior: "input remains data",
    tests_to_run: ["targeted test"],
    security_retest: "targeted SQLi retest",
  };
}

describe("Guided Security Fix & Verify frontend lifecycle", () => {
  it("maps persisted backend states through the complete developer workflow", () => {
    expect(securityFixStage(null)).toBe("prepare");
    expect(securityFixStage(attempt("prepared"))).toBe("diagnosis");
    expect(securityFixStage(attempt("patch_proposed"))).toBe("patch_review");
    expect(securityFixStage(attempt("rejected"))).toBe("rejected");
    expect(securityFixStage(attempt("approved"))).toBe("approved");
    expect(securityFixStage(attempt("applied"))).toBe("applied");
    expect(securityFixStage(attempt("validation_failed"))).toBe("validation_failed");
    expect(securityFixStage(attempt("verification_pending"))).toBe("verification_pending");
    expect(securityFixStage(attempt("fix_verified", "FIX_VERIFIED"))).toBe("fix_verified");
    expect(securityFixStage(attempt("still_vulnerable", "STILL_VULNERABLE"))).toBe("still_vulnerable");
    expect(securityFixStage(attempt("unable_to_verify", "UNABLE_TO_VERIFY"))).toBe("unable_to_verify");
    expect(securityFixStage(attempt("rolled_back", "FIX_VERIFIED"))).toBe("rolled_back");
  });

  it("never renders fake success from an applied/static/test-only or inconsistent state", () => {
    expect(securityFixDisplayStatus(attempt("applied"))).toBe("Applied — Verification Pending");
    expect(securityFixDisplayStatus(
      attempt("verification_pending", "not_executed", { validation_state: "passed" }),
    )).toBe("Applied — Verification Pending");
    expect(securityFixDisplayStatus(
      attempt("fix_verified", "not_executed"),
    )).toBe("Verification State Invalid");
    expect(securityFixRetestExplanation(
      attempt("fix_verified", "not_executed"),
    )).toMatch(/never labeled fixed/i);
    expect(securityFixDisplayStatus(
      attempt("fix_verified", "FIX_VERIFIED"),
    )).toBe("Fix Verified");
  });

  it("shows still-vulnerable, unable-to-verify and regression states from backend truth", () => {
    expect(securityFixDisplayStatus(
      attempt("still_vulnerable", "STILL_VULNERABLE"),
    )).toBe("Still Vulnerable");
    expect(securityFixDisplayStatus(
      attempt("unable_to_verify", "UNABLE_TO_VERIFY"),
    )).toBe("Applied — Verification Pending");
    expect(securityFixDisplayStatus(
      attempt("validation_failed", "REGRESSION_DETECTED"),
    )).toBe("Regression Detected");

    expect(securityFixActions(
      attempt("still_vulnerable", "STILL_VULNERABLE", {
        application_run_id: "run-1",
      }),
    )).toMatchObject({ retest: true, rollback: true, revise: true });
    expect(securityFixActions(
      attempt("validation_failed", "REGRESSION_DETECTED", {
        application_run_id: "run-1",
      }),
    ).rollback).toBe(true);
  });

  it("requires explicit CAUTION acknowledgement and refuses REJECTED or stale review identity", () => {
    const proposed = attempt("patch_proposed");
    expect(canApproveAndApplySecurityFix(proposed, review("SAFE_TO_REVIEW"), false, false)).toBe(true);
    expect(canApproveAndApplySecurityFix(proposed, review("CAUTION"), false, false)).toBe(false);
    expect(canApproveAndApplySecurityFix(proposed, review("CAUTION"), true, false)).toBe(true);
    expect(canApproveAndApplySecurityFix(proposed, review("REJECTED"), true, false)).toBe(false);
    expect(canApproveAndApplySecurityFix(proposed, {
      ...review("SAFE_TO_REVIEW"),
      attempt_id: "other-attempt",
    }, false, false)).toBe(false);
    expect(canApproveAndApplySecurityFix(proposed, review("SAFE_TO_REVIEW"), false, true)).toBe(false);
  });

  it("exposes rollback/retest only for backend states that support them", () => {
    expect(securityFixActions(attempt("prepared"))).toMatchObject({
      review: true,
      retest: false,
      rollback: false,
    });
    expect(securityFixActions(
      attempt("applied", "not_executed", { application_run_id: "run-1" }),
    )).toMatchObject({ retest: true, rollback: false });
    expect(securityFixActions(
      attempt("unable_to_verify", "UNABLE_TO_VERIFY", { application_run_id: "run-1" }),
    ).retest).toBe(true);
    expect(securityFixActions(
      attempt("rolled_back", "FIX_VERIFIED", { application_run_id: "run-1" }),
    )).toMatchObject({ retest: false, rollback: false, revise: false });
  });

  it("recognizes attempt-limit and exact stale-source backend errors without inventing success", () => {
    expect(isAttemptLimitError("security fix attempt limit reached; explicit additional investigation is required")).toBe(true);
    expect(isStaleApprovalError("Source changed since approval. Regenerate/review the fix.")).toBe(true);
    expect(isStaleApprovalError("something else")).toBe(false);
  });
});
