import type { PatchReview, SecurityFixAttemptRecord } from "../types";

export type SecurityFixUiStage =
  | "prepare"
  | "diagnosis"
  | "patch_review"
  | "approved"
  | "applied"
  | "validation_failed"
  | "verification_pending"
  | "fix_verified"
  | "still_vulnerable"
  | "unable_to_verify"
  | "rolled_back"
  | "rejected";

export function securityFixStage(
  attempt: SecurityFixAttemptRecord | null,
): SecurityFixUiStage {
  if (!attempt) return "prepare";
  switch (attempt.status) {
    case "prepared":
      return "diagnosis";
    case "patch_proposed":
      return "patch_review";
    case "approved":
      return "approved";
    case "applied":
      return "applied";
    case "validation_failed":
      return "validation_failed";
    case "verification_pending":
      return "verification_pending";
    case "fix_verified":
      return "fix_verified";
    case "still_vulnerable":
      return "still_vulnerable";
    case "unable_to_verify":
      return "unable_to_verify";
    case "rolled_back":
      return "rolled_back";
    case "rejected":
      return "rejected";
  }
}

export function securityFixDisplayStatus(attempt: SecurityFixAttemptRecord): string {
  if (attempt.status === "fix_verified") {
    return attempt.retest_state === "FIX_VERIFIED"
      ? "Fix Verified"
      : "Verification State Invalid";
  }
  if (attempt.retest_state === "STILL_VULNERABLE") return "Still Vulnerable";
  if (attempt.retest_state === "UNABLE_TO_VERIFY") {
    return "Applied — Verification Pending";
  }
  if (attempt.retest_state === "REGRESSION_DETECTED") return "Regression Detected";
  if (attempt.status === "verification_pending" || attempt.status === "applied") {
    return "Applied — Verification Pending";
  }
  return titleCase(attempt.status);
}

export function securityFixRetestExplanation(
  attempt: SecurityFixAttemptRecord,
): string {
  if (attempt.retest_state === "FIX_VERIFIED" && attempt.status === "fix_verified") {
    return "The original targeted runtime behavior no longer reproduced.";
  }
  if (attempt.retest_state === "STILL_VULNERABLE") {
    return "The original targeted runtime behavior still reproduced.";
  }
  if (attempt.retest_state === "UNABLE_TO_VERIFY") {
    return "The targeted runtime retest could not complete safely.";
  }
  if (attempt.retest_state === "REGRESSION_DETECTED") {
    return "Runtime behavior improved, but repository validation indicates a possible regression.";
  }
  return "A patch is never labeled fixed until the targeted runtime retest passes.";
}

export function canApproveAndApplySecurityFix(
  attempt: SecurityFixAttemptRecord | null,
  review: PatchReview | null,
  acceptCaution: boolean,
  busy: boolean,
): boolean {
  if (busy || !attempt || !review) return false;
  if (attempt.status !== "patch_proposed") return false;
  if (review.attempt_id !== attempt.id) return false;
  if (!attempt.patch_hash || attempt.patch_hash !== review.safety.patch_hash) return false;
  if (review.safety.classification === "REJECTED") return false;
  if (review.safety.classification === "CAUTION" && !acceptCaution) return false;
  return true;
}

export function securityFixActions(attempt: SecurityFixAttemptRecord | null) {
  const status = attempt?.status;
  return {
    prepare: attempt === null,
    review:
      status === "prepared"
      || status === "patch_proposed"
      || status === "rejected",
    retest: Boolean(
      attempt
      && ["applied", "verification_pending", "validation_failed", "still_vulnerable", "unable_to_verify"]
        .includes(attempt.status),
    ),
    rollback: Boolean(
      attempt?.application_run_id
      && (
        status === "validation_failed"
        || status === "still_vulnerable"
        || attempt.retest_state === "REGRESSION_DETECTED"
      ),
    ),
    revise: status === "still_vulnerable",
  };
}

export function isAttemptLimitError(message: string): boolean {
  return message.toLowerCase().includes("attempt limit reached");
}

export function isStaleApprovalError(message: string): boolean {
  return message.includes("Source changed since approval. Regenerate/review the fix.");
}

export function titleCase(value: string): string {
  return value
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
