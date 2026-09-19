import { useCallback, useEffect, useState } from "react";

import { workspaceApi } from "../api";
import type {
  PatchReview,
  RepairSourceSnapshot,
  SecurityFixAttemptRecord,
  SecurityFixEventRecord,
  SecurityFixPreparation,
  SecurityFixValidationRecord,
  WebFindingRecord,
} from "../types";
import { StatusBadge, formatDate } from "../ui";
import {
  canApproveAndApplySecurityFix,
  isAttemptLimitError,
  securityFixActions,
  securityFixDisplayStatus,
  securityFixRetestExplanation,
} from "./securityFixModel";

type SecurityFixWorkflowProps = {
  finding: WebFindingRecord;
  onRetest: () => Promise<void>;
};

export function SecurityFixWorkflow({
  finding,
  onRetest,
}: SecurityFixWorkflowProps) {
  const [preparation, setPreparation] = useState<SecurityFixPreparation | null>(null);
  const [attempt, setAttempt] = useState<SecurityFixAttemptRecord | null>(null);
  const [review, setReview] = useState<PatchReview | null>(null);
  const [history, setHistory] = useState<SecurityFixAttemptRecord[]>([]);
  const [validations, setValidations] = useState<SecurityFixValidationRecord[]>([]);
  const [events, setEvents] = useState<SecurityFixEventRecord[]>([]);
  const [source, setSource] = useState<RepairSourceSnapshot | null>(null);
  const [proposedContent, setProposedContent] = useState("");
  const [editing, setEditing] = useState(false);
  const [acceptCaution, setAcceptCaution] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limitReached, setLimitReached] = useState(false);

  const refreshAttempt = useCallback(async (attemptId: string) => {
    const current = await workspaceApi.getSecurityFixAttempt(attemptId);
    if (!current) return;
    setAttempt(current);
    const [nextValidation, nextEvents, nextHistory] = await Promise.all([
      workspaceApi.listSecurityFixValidation(attemptId, 200),
      workspaceApi.listSecurityFixEvents(attemptId, 200),
      workspaceApi.listSecurityFixAttempts(finding.id, 20),
    ]);
    setValidations(nextValidation);
    setEvents(nextEvents);
    setHistory(nextHistory);
  }, [finding.id]);

  useEffect(() => {
    let cancelled = false;
    setPreparation(null);
    setAttempt(null);
    setReview(null);
    setValidations([]);
    setEvents([]);
    setSource(null);
    setProposedContent("");
    setEditing(false);
    setError(null);
    setLimitReached(false);

    void workspaceApi.listSecurityFixAttempts(finding.id, 20)
      .then((items) => {
        if (cancelled) return;
        setHistory(items);
        if (items[0]) {
          setAttempt(items[0]);
          void Promise.all([
            workspaceApi.listSecurityFixValidation(items[0].id, 200),
            workspaceApi.listSecurityFixEvents(items[0].id, 200),
          ]).then(([nextValidation, nextEvents]) => {
            if (cancelled) return;
            setValidations(nextValidation);
            setEvents(nextEvents);
          });
        }
      })
      .catch((value) => {
        if (!cancelled) setError(String(value));
      });
    return () => {
      cancelled = true;
    };
  }, [finding.id]);

  async function prepare(allowAdditionalAttempt = false) {
    setBusy("Analyzing source");
    setError(null);
    try {
      const value = await workspaceApi.prepareSecurityFix(
        finding.id,
        allowAdditionalAttempt,
      );
      setPreparation(value);
      setAttempt(value.attempt);
      setReview(null);
      setValidations([]);
      setEvents(await workspaceApi.listSecurityFixEvents(value.attempt.id, 200));
      setHistory(await workspaceApi.listSecurityFixAttempts(finding.id, 20));
      setSource(null);
      setProposedContent("");
      setEditing(false);
      setLimitReached(false);
    } catch (value) {
      const message = String(value);
      setError(message);
      if (isAttemptLimitError(message)) {
        setLimitReached(true);
      }
    } finally {
      setBusy(null);
    }
  }

  async function generatePatch() {
    if (!attempt) return;
    setBusy("Generating bounded patch");
    setError(null);
    try {
      const next = await workspaceApi.generateSecurityFixPatch(attempt.id);
      setReview(next);
      await refreshAttempt(attempt.id);
    } catch (value) {
      setError(
        String(value)
        + " Use Edit Plan for a developer-guided replacement when automatic generation is not safe.",
      );
    } finally {
      setBusy(null);
    }
  }

  async function openEditor() {
    if (!attempt?.root_causes[0]) return;
    setBusy("Loading hash-verified source");
    setError(null);
    try {
      const snapshot = await workspaceApi.readRepairSource(
        attempt.root_causes[0].file_id,
      );
      setSource(snapshot);
      setProposedContent(snapshot.content);
      setEditing(true);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function reviewEditedPlan() {
    if (!attempt || !source || proposedContent === source.content) return;
    setBusy("Analyzing patch safety");
    setError(null);
    try {
      const next = await workspaceApi.proposeSecurityFixReplacement(
        attempt.id,
        source.file_id,
        proposedContent,
      );
      setReview(next);
      setEditing(false);
      await refreshAttempt(attempt.id);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function approveAndApply() {
    if (!attempt || !review || review.safety.classification === "REJECTED") return;
    setBusy("Approving exact patch");
    setError(null);
    try {
      const approved = await workspaceApi.approveSecurityFix(
        attempt.id,
        acceptCaution,
      );
      setAttempt(approved);
      setBusy("Applying approved patch");
      const applied = await workspaceApi.applySecurityFix(attempt.id);
      setAttempt(applied.attempt);
      if (applied.application.status !== "applied") {
        setError(
          "Patch application did not complete successfully: "
          + applied.application.status
          + (applied.application.error_message
            ? " — " + applied.application.error_message
            : ""),
        );
        await refreshAttempt(attempt.id);
        return;
      }

      setBusy("Running selected repository validation");
      const validation = await workspaceApi.runSecurityFixValidation(attempt.id);
      setAttempt(validation.attempt);
      setValidations(validation.results);
      setEvents(await workspaceApi.listSecurityFixEvents(attempt.id, 200));
      setHistory(await workspaceApi.listSecurityFixAttempts(finding.id, 20));
    } catch (value) {
      setError(String(value));
      await refreshAttempt(attempt.id).catch(() => undefined);
    } finally {
      setBusy(null);
    }
  }

  async function retest() {
    if (!attempt) return;
    setBusy("Running targeted security retest");
    setError(null);
    try {
      await onRetest();
      await refreshAttempt(attempt.id);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function rollback() {
    if (!attempt?.application_run_id) return;
    setBusy("Rolling back approved fix");
    setError(null);
    try {
      const result = await workspaceApi.rollbackSecurityFix(attempt.id);
      setAttempt(result.attempt);
      setEvents(await workspaceApi.listSecurityFixEvents(attempt.id, 200));
      setHistory(await workspaceApi.listSecurityFixAttempts(finding.id, 20));
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  function closeReview() {
    setPreparation(null);
    setReview(null);
    setSource(null);
    setEditing(false);
    setProposedContent("");
    setError(null);
  }

  const currentPreparation = preparation?.attempt.id === attempt?.id
    ? preparation
    : null;
  const strategy = attempt?.strategy ?? currentPreparation?.strategy;
  const roots = attempt?.root_causes ?? currentPreparation?.root_causes ?? [];
  const testPlan = attempt?.test_plan ?? currentPreparation?.test_plan;
  const manualOnly =
    attempt?.eligibility === "MANUAL_REMEDIATION"
    || attempt?.eligibility === "INSUFFICIENT_EVIDENCE";
  const canPatch = Boolean(attempt?.repair_id) && !manualOnly;
  const actions = securityFixActions(attempt);
  const canRetest = actions.retest;
  const shouldOfferRollback = actions.rollback;

  return (
    <section className="ws-security-fix">
      <div className="ws-security-fix-heading">
        <div>
          <h4>Guided Security Fix & Verify</h4>
          <p>
            Source diagnosis, patch review, application, repository validation and the
            original targeted security retest share one auditable workflow.
          </p>
        </div>
        {attempt && <FixStateBadge attempt={attempt}/>}
      </div>

      {!attempt && (
        <div className="ws-security-fix-start">
          <p>
            CodeTwin will first decide whether this finding has enough runtime evidence and
            source confidence for a bounded remediation proposal. No source is modified by
            this step.
          </p>
          <button
            className="ws-button ws-button-primary"
            disabled={Boolean(busy)}
            onClick={() => void prepare(false)}
          >
            {busy ?? "Prepare Fix"}
          </button>
        </div>
      )}

      {attempt && (
        <>
          <div className="ws-security-fix-grid">
            <article>
              <span>Eligibility</span>
              <strong>{label(attempt.eligibility)}</strong>
              {currentPreparation?.eligibility.reasons.map((reason) => (
                <small key={reason}>{reason}</small>
              ))}
            </article>
            <article>
              <span>Attempt</span>
              <strong>#{attempt.attempt_number}</strong>
              <small>Automatic guided attempts are conservatively bounded.</small>
            </article>
            <article>
              <span>Runtime status</span>
              <strong>{securityFixDisplayStatus(attempt)}</strong>
              <small>{securityFixRetestExplanation(attempt)}</small>
            </article>
          </div>

          <section className="ws-security-fix-section">
            <h5>Root Cause Candidate</h5>
            {roots.map((root, index) => (
              <article className="ws-root-cause" key={root.file_id + String(index)}>
                <div>
                  <strong>
                    {root.relative_path}
                    {root.symbol_name ? " → " + root.symbol_name : ""}
                  </strong>
                  <StatusBadge status={Math.round(root.confidence * 100) + "% confidence"}/>
                </div>
                {(root.source_start_line || root.source_end_line) && (
                  <small>
                    source lines {root.source_start_line ?? "?"}–{root.source_end_line ?? "?"}
                  </small>
                )}
                <ul>
                  {root.reasoning.map((reason) => <li key={reason}>{reason}</li>)}
                </ul>
              </article>
            ))}
            {!roots.length && (
              <p className="ws-inline-empty">
                No bounded source candidate is strong enough. Runtime evidence is retained,
                but CodeTwin will not invent a patch target.
              </p>
            )}
          </section>

          {strategy && (
            <section className="ws-security-fix-section">
              <h5>Fix Strategy</h5>
              <p><strong>{strategy.change_summary}</strong></p>
              <p>{strategy.rationale}</p>
              <dl className="ws-detail-grid">
                <dt>Expected behavior</dt><dd>{strategy.expected_behavior}</dd>
                <dt>Likely files</dt><dd>{strategy.likely_files.join(", ") || "No bounded edit target"}</dd>
                <dt>Compatibility risk</dt><dd>{strategy.compatibility_risks.join(" ") || "No specific risk identified."}</dd>
              </dl>
              {!!strategy.prohibited_shortcuts.length && (
                <div className="ws-security-fix-danger">
                  <strong>Unsafe shortcuts rejected</strong>
                  <ul>{strategy.prohibited_shortcuts.map((item) => <li key={item}>{item}</li>)}</ul>
                </div>
              )}
            </section>
          )}

          {testPlan && (
            <section className="ws-security-fix-section">
              <h5>Validation & Regression Plan</h5>
              <div className="ws-security-fix-tests">
                {testPlan.targeted.map((item) => (
                  <div key={item.label + item.runner_kind}>
                    <strong>{item.label}</strong>
                    <span>{item.reason}</span>
                    <small>
                      {item.repository_command_execution_required
                        ? "Repository command — executes only through trusted QA execution when available."
                        : "CodeTwin internal validation."}
                    </small>
                  </div>
                ))}
              </div>
              <p><strong>Security regression:</strong> {testPlan.regression_test_proposal}</p>
              <p>
                <strong>Regression test generation:</strong>{" "}
                {testPlan.regression_generation_status.replaceAll("_", " ")}
              </p>
              <p className="ws-form-help">{testPlan.regression_generation_reason}</p>
              <p><strong>Targeted retest:</strong> {testPlan.security_retest}</p>
              {!testPlan.qa_execution_available && (
                <p className="ws-security-fix-warning">
                  Repository test execution is unavailable in the current sandbox:
                  {" " + testPlan.qa_execution_reason}
                  {" "}These checks will be recorded as NOT EXECUTED, never PASS.
                </p>
              )}
            </section>
          )}

          {canPatch && !["approved", "applied", "verification_pending", "validation_failed", "fix_verified", "still_vulnerable", "unable_to_verify", "rolled_back"]
            .includes(attempt.status) && (
            <div className="ws-button-row">
              {attempt.eligibility === "AUTO_FIX_CANDIDATE" && (
                <button
                  className="ws-button ws-button-primary"
                  disabled={Boolean(busy)}
                  onClick={() => void generatePatch()}
                >
                  {busy === "Generating bounded patch" ? busy + "…" : "Review Fix"}
                </button>
              )}
              <button
                className="ws-button ws-button-secondary"
                disabled={Boolean(busy) || !roots.length}
                onClick={() => void openEditor()}
              >
                Edit Plan
              </button>
              <button className="ws-button ws-button-secondary" onClick={closeReview}>
                Cancel
              </button>
            </div>
          )}

          {manualOnly && (
            <p className="ws-security-fix-warning">
              CodeTwin will not create a speculative patch for this finding. Follow the
              remediation strategy manually or improve source/evidence correlation first.
            </p>
          )}

          {editing && source && (
            <section className="ws-security-fix-section">
              <h5>Developer-Guided Patch</h5>
              <p>
                Editing a proposal does not modify the repository. The replacement is hash-pinned
                and safety-analyzed before it can be approved.
              </p>
              <div className="ws-security-fix-file-meta">
                <strong>{source.relative_path}</strong>
                <span>{source.language ?? "unknown language"} · {source.byte_size} bytes</span>
              </div>
              <textarea
                className="ws-security-fix-editor"
                spellCheck={false}
                value={proposedContent}
                onChange={(event) => setProposedContent(event.target.value)}
              />
              <div className="ws-button-row">
                <button
                  className="ws-button ws-button-primary"
                  disabled={Boolean(busy) || proposedContent === source.content}
                  onClick={() => void reviewEditedPlan()}
                >
                  Analyze Patch Safety
                </button>
                <button className="ws-button ws-button-secondary" onClick={() => setEditing(false)}>
                  Cancel Edit
                </button>
              </div>
            </section>
          )}

          {review && (
            <section className="ws-security-fix-section">
              <div className="ws-security-fix-review-head">
                <h5>Patch Safety Review</h5>
                <StatusBadge status={review.safety.classification}/>
              </div>
              <dl className="ws-detail-grid">
                <dt>Affected files</dt><dd>{review.affected_files.join(", ")}</dd>
                <dt>Changed lines</dt><dd>{review.safety.changed_lines}</dd>
                <dt>Patch SHA-256</dt><dd className="ws-mono">{review.safety.patch_hash}</dd>
                <dt>Expected behavior</dt><dd>{review.expected_behavior}</dd>
              </dl>
              {!!review.safety.risk_notes.length && (
                <div className="ws-security-fix-warning">
                  <strong>Review notes</strong>
                  <ul>{review.safety.risk_notes.map((item) => <li key={item}>{item}</li>)}</ul>
                </div>
              )}
              {!!review.safety.rejected_reasons.length && (
                <div className="ws-security-fix-danger">
                  <strong>Rejected</strong>
                  <ul>{review.safety.rejected_reasons.map((item) => <li key={item}>{item}</li>)}</ul>
                  <p>Generate or edit a new safe proposal. This patch cannot become applicable.</p>
                </div>
              )}
              <details open className="ws-security-fix-diff">
                <summary>Unified diff</summary>
                <pre>{review.unified_diff}</pre>
              </details>
              <p><strong>Tests after apply:</strong> {review.tests_to_run.join(", ") || "No repository tests discovered."}</p>
              <p><strong>Security retest:</strong> {review.security_retest}</p>

              {review.safety.classification === "CAUTION" && (
                <label className="ws-check-field">
                  <input
                    type="checkbox"
                    checked={acceptCaution}
                    onChange={(event) => setAcceptCaution(event.target.checked)}
                  />
                  <span>
                    I reviewed the caution notes and approve this exact patch identity.
                  </span>
                </label>
              )}

              <div className="ws-button-row">
                <button
                  className="ws-button ws-button-primary"
                  disabled={!canApproveAndApplySecurityFix(
                    attempt,
                    review,
                    acceptCaution,
                    Boolean(busy),
                  )}
                  onClick={() => void approveAndApply()}
                >
                  {busy ?? "Approve & Apply"}
                </button>
                <button
                  className="ws-button ws-button-secondary"
                  disabled={Boolean(busy)}
                  onClick={() => void prepare(false)}
                >
                  Regenerate Fix
                </button>
                <button
                  className="ws-button ws-button-secondary"
                  disabled={Boolean(busy)}
                  onClick={() => void openEditor()}
                >
                  Edit Plan
                </button>
                <button className="ws-button ws-button-secondary" onClick={closeReview}>
                  Cancel
                </button>
              </div>
            </section>
          )}

          {!!validations.length && (
            <section className="ws-security-fix-section">
              <h5>Repository Validation</h5>
              <div className="ws-security-fix-validation">
                {validations.map((item) => (
                  <div key={item.id}>
                    <StatusBadge status={item.status}/>
                    <p>
                      <strong>{item.command_label}</strong>
                      <span>{item.runner_kind} · {item.classification.replaceAll("_", " ")}</span>
                    </p>
                    <small>
                      exit {item.exit_code ?? "n/a"} · {item.duration_ms ?? 0} ms
                      {item.stderr_summary ? " · " + item.stderr_summary : ""}
                    </small>
                  </div>
                ))}
              </div>
            </section>
          )}

          {attempt.application_run_id && (
            <section className="ws-security-fix-section">
              <h5>Security Retest</h5>
              <p>{testPlan?.security_retest}</p>
              <p className="ws-security-fix-warning">
                A successful apply, build, static scan or unit test does not mean Fixed.
                Fix Verified requires the original targeted runtime behavior to stop reproducing.
              </p>
              {canRetest && (
                <button
                  className="ws-button ws-button-primary"
                  disabled={Boolean(busy)}
                  onClick={() => void retest()}
                >
                  {busy === "Running targeted security retest"
                    ? "Retesting…"
                    : "Run Targeted Security Retest"}
                </button>
              )}
            </section>
          )}

          {attempt.status === "still_vulnerable" && (
            <section className="ws-security-fix-section">
              <h5>Still Vulnerable</h5>
              <p>
                The first remediation was insufficient. CodeTwin will preserve the previous patch
                and runtime evidence, re-rank remaining candidates, and require a new reviewed
                proposal rather than repeating the same patch blindly.
              </p>
              <button
                className="ws-button ws-button-primary"
                disabled={Boolean(busy)}
                onClick={() => void prepare(false)}
              >
                Revise Fix
              </button>
            </section>
          )}

          {limitReached && (
            <section className="ws-security-fix-section">
              <h5>Guided attempt limit reached</h5>
              <p>
                Three guided attempts are the default safety limit. Continue only if you explicitly
                want further investigation of this finding.
              </p>
              <button
                className="ws-button ws-button-secondary"
                disabled={Boolean(busy)}
                onClick={() => void prepare(true)}
              >
                Investigate Further
              </button>
            </section>
          )}

          {shouldOfferRollback && (
            <div className="ws-security-fix-danger">
              <strong>Rollback recommended for review</strong>
              <p>
                Repository validation or the targeted security result indicates the applied patch
                may be insufficient or regressive. Rollback restores the hash-pinned backup and
                keeps the audit history.
              </p>
              <button
                className="ws-button ws-button-danger-ghost"
                disabled={Boolean(busy)}
                onClick={() => void rollback()}
              >
                Rollback Fix
              </button>
            </div>
          )}

          {!!events.length && (
            <details className="ws-security-fix-section">
              <summary>Fix history timeline</summary>
              <div className="ws-security-fix-events">
                {events.map((item) => (
                  <div key={item.id}>
                    <b>{item.sequence}</b>
                    <p>
                      <strong>{item.message}</strong>
                      <small>{item.event_type.replaceAll("_", " ")} · {formatDate(item.created_at)}</small>
                    </p>
                  </div>
                ))}
              </div>
            </details>
          )}

          {!!history.length && (
            <details className="ws-security-fix-section">
              <summary>Previous attempts</summary>
              <div className="ws-security-fix-attempts">
                {history.map((item) => (
                  <button key={item.id} onClick={() => void refreshAttempt(item.id)}>
                    <strong>Attempt #{item.attempt_number}</strong>
                    <span>{securityFixDisplayStatus(item)}</span>
                    <small>{formatDate(item.updated_at)}</small>
                  </button>
                ))}
              </div>
            </details>
          )}
        </>
      )}

      {error && <p className="ws-form-error" role="alert">{error}</p>}
      {busy && <p className="ws-form-help" role="status">{busy}…</p>}
    </section>
  );
}

function FixStateBadge({ attempt }: { attempt: SecurityFixAttemptRecord }) {
  return <StatusBadge status={securityFixDisplayStatus(attempt)}/>;
}

function label(value: string): string {
  return value
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
