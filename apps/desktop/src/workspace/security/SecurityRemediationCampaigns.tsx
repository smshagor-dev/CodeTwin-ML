import { useCallback, useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import type {
  FixEligibilityAssessment,
  SecurityRemediationBeforeAfterItem,
  SecurityRemediationCampaignEventRecord,
  SecurityRemediationCampaignFindingRecord,
  SecurityRemediationCampaignPlan,
  SecurityRemediationCampaignRecord,
  SecurityRemediationCampaignSummary,
  SecurityRemediationDebtView,
  SecurityRemediationRegressionTracking,
  SecurityRemediationRelationshipRecord,
  SecurityRemediationRollbackAssessment,
  GuidedSecuritySessionRecord,
  WebFindingRecord,
} from "../types";
import { Panel, StatusBadge, formatDate, shortPath } from "../ui";
import { SecurityFixWorkflow } from "./SecurityFixWorkflow";
import {
  campaignFindingMatches,
  campaignProgressPercent,
  currentCampaignFinding,
  eligibleForCampaignSelection,
  factualCampaignOutcome,
  type CampaignFindingFilters,
} from "./securityCampaignModel";

type Props = {
  session: GuidedSecuritySessionRecord;
  findings: WebFindingRecord[];
  onRetest: (finding: WebFindingRecord) => Promise<void>;
};

const EMPTY_SUMMARY: SecurityRemediationCampaignSummary = {
  selected_findings: 0,
  verified_fixed: 0,
  still_vulnerable: 0,
  manual_action_required: 0,
  unable_to_verify: 0,
  regression_detected: 0,
  blocked: 0,
  skipped: 0,
  queued_or_in_progress: 0,
};

const EMPTY_DEBT: SecurityRemediationDebtView = {
  unresolved_total: 0,
  by_severity: {},
  by_eligibility: {},
  by_module: {},
  by_endpoint: {},
  by_reason: {},
};

const EMPTY_FILTERS: CampaignFindingFilters = {
  severity: "",
  confidence: "",
  category: "",
  source: "",
  eligibility: "",
};

export function SecurityRemediationCampaigns({ session, findings, onRetest }: Props) {
  const [campaigns, setCampaigns] = useState<SecurityRemediationCampaignRecord[]>([]);
  const [campaign, setCampaign] = useState<SecurityRemediationCampaignRecord | null>(null);
  const [campaignFindings, setCampaignFindings] = useState<SecurityRemediationCampaignFindingRecord[]>([]);
  const [relationships, setRelationships] = useState<SecurityRemediationRelationshipRecord[]>([]);
  const [events, setEvents] = useState<SecurityRemediationCampaignEventRecord[]>([]);
  const [summary, setSummary] = useState<SecurityRemediationCampaignSummary | null>(null);
  const [beforeAfter, setBeforeAfter] = useState<SecurityRemediationBeforeAfterItem[]>([]);
  const [regressions, setRegressions] = useState<SecurityRemediationRegressionTracking[]>([]);
  const [debt, setDebt] = useState<SecurityRemediationDebtView>(EMPTY_DEBT);
  const [rollbackAssessments, setRollbackAssessments] = useState<Record<string, SecurityRemediationRollbackAssessment | null>>({});
  const [assessments, setAssessments] = useState<Record<string, FixEligibilityAssessment>>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filters, setFilters] = useState<CampaignFindingFilters>(EMPTY_FILTERS);
  const [expertView, setExpertView] = useState(false);
  const [skipReason, setSkipReason] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshCampaign = useCallback(async (campaignId: string, synchronize = false) => {
    if (synchronize) {
      await workspaceApi.syncSecurityRemediationCampaign(campaignId);
    }
    const [
      nextCampaign,
      nextFindings,
      nextRelationships,
      nextEvents,
      nextSummary,
      nextBeforeAfter,
      nextRegressions,
      nextDebt,
    ] = await Promise.all([
      workspaceApi.getSecurityRemediationCampaign(campaignId),
      workspaceApi.listSecurityRemediationCampaignFindings(campaignId),
      workspaceApi.listSecurityRemediationCampaignRelationships(campaignId),
      workspaceApi.listSecurityRemediationCampaignEvents(campaignId, 500),
      workspaceApi.securityRemediationCampaignSummary(campaignId),
      workspaceApi.securityRemediationCampaignBeforeAfter(campaignId),
      workspaceApi.securityRemediationCampaignRegressionTracking(campaignId),
      workspaceApi.securityRemediationCampaignDebt(campaignId),
    ]);
    setCampaign(nextCampaign);
    setCampaignFindings(nextFindings);
    setRelationships(nextRelationships);
    setEvents(nextEvents);
    setSummary(nextSummary);
    setBeforeAfter(nextBeforeAfter);
    setRegressions(nextRegressions);
    setDebt(nextDebt);
    const rollbackEntries = await Promise.all(
      nextFindings
        .filter((item) => item.active_attempt_id)
        .map(async (item) => {
          try {
            return [
              item.finding_id,
              await workspaceApi.assessSecurityRemediationCampaignRollback(campaignId, item.finding_id),
            ] as const;
          } catch {
            return [item.finding_id, null] as const;
          }
        }),
    );
    setRollbackAssessments(Object.fromEntries(rollbackEntries));
    return nextCampaign;
  }, []);

  useEffect(() => {
    let cancelled = false;
    void workspaceApi.listSecurityRemediationCampaigns(session.project_id, 100)
      .then((values) => {
        if (cancelled) return;
        const matching = values.filter((item) => item.session_id === session.id);
        setCampaigns(matching);
        if (!campaign && matching[0]) {
          void refreshCampaign(matching[0].id).catch((value) => {
            if (!cancelled) setError(String(value));
          });
        }
      })
      .catch((value) => {
        if (!cancelled) setError(String(value));
      });
    return () => {
      cancelled = true;
    };
  }, [session.id, session.project_id, refreshCampaign]);

  useEffect(() => {
    let cancelled = false;
    void Promise.all(findings.map(async (finding) => [
      finding.id,
      await workspaceApi.evaluateSecurityFixEligibility(finding.id),
    ] as const))
      .then((values) => {
        if (cancelled) return;
        setAssessments(Object.fromEntries(values));
      })
      .catch((value) => {
        if (!cancelled) setError(String(value));
      });
    return () => {
      cancelled = true;
    };
  }, [findings]);

  useEffect(() => {
    if (!campaign || !["IN_PROGRESS", "BLOCKED"].includes(campaign.status)) return;
    const timer = window.setInterval(() => {
      void refreshCampaign(campaign.id, true).catch((value) => setError(String(value)));
    }, 2_000);
    return () => window.clearInterval(timer);
  }, [campaign?.id, campaign?.status, refreshCampaign]);

  const visibleFindings = useMemo(
    () => findings.filter((finding) =>
      campaignFindingMatches(finding, assessments[finding.id], filters)
    ),
    [findings, assessments, filters],
  );

  const selectedFindings = useMemo(
    () => findings.filter((finding) => selected.has(finding.id)),
    [findings, selected],
  );

  const selectionStats = useMemo(() => {
    const severity: Record<string, number> = {};
    const eligibility: Record<string, number> = {};
    const sourceCounts: Record<string, number> = {};
    for (const finding of selectedFindings) {
      severity[finding.severity] = (severity[finding.severity] ?? 0) + 1;
      const eligibilityKey = assessments[finding.id]?.result ?? "EVALUATING";
      eligibility[eligibilityKey] = (eligibility[eligibilityKey] ?? 0) + 1;
      const source = finding.source_relative_path ?? "unmapped";
      sourceCounts[source] = (sourceCounts[source] ?? 0) + 1;
    }
    return {
      severity,
      eligibility,
      overlappingSources: Object.values(sourceCounts).filter((count) => count > 1).length,
    };
  }, [selectedFindings, assessments]);

  const plan = useMemo(() => {
    if (!campaign?.plan_json) return null;
    try {
      return JSON.parse(campaign.plan_json) as SecurityRemediationCampaignPlan;
    } catch {
      return null;
    }
  }, [campaign?.plan_json]);

  const current = useMemo(
    () => currentCampaignFinding(campaignFindings),
    [campaignFindings],
  );
  const currentWebFinding = current
    ? findings.find((finding) => finding.id === current.finding_id) ?? null
    : null;
  const currentRollback = current ? rollbackAssessments[current.finding_id] ?? null : null;

  function toggleFinding(findingId: string) {
    setSelected((currentSelection) => {
      const next = new Set(currentSelection);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  }

  function selectAllEligible() {
    setSelected(new Set(
      visibleFindings
        .filter((finding) => eligibleForCampaignSelection(assessments[finding.id]))
        .map((finding) => finding.id),
    ));
  }

  async function runAction(label: string, action: () => Promise<SecurityRemediationCampaignRecord>) {
    if (busy) return;
    setBusy(label);
    setError(null);
    try {
      const next = await action();
      await refreshCampaign(next.id);
      setCampaigns(await workspaceApi.listSecurityRemediationCampaigns(session.project_id, 100)
        .then((items) => items.filter((item) => item.session_id === session.id)));
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function createCampaign() {
    if (!selected.size) {
      setError("Select at least one finding.");
      return;
    }
    setBusy("Creating campaign");
    setError(null);
    try {
      const created = await workspaceApi.createSecurityRemediationCampaign({
        session_id: session.id,
        finding_ids: [...selected],
      });
      const analyzed = await workspaceApi.analyzeSecurityRemediationCampaign(created.id);
      setSelected(new Set());
      setCampaigns(await workspaceApi.listSecurityRemediationCampaigns(session.project_id, 100)
        .then((items) => items.filter((item) => item.session_id === session.id)));
      await refreshCampaign(analyzed.id);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function skipCurrent() {
    if (!campaign || !current || !skipReason.trim() || busy) return;
    setBusy("Skipping finding");
    setError(null);
    try {
      await workspaceApi.skipSecurityRemediationCampaignFinding(
        campaign.id,
        current.finding_id,
        skipReason.trim(),
      );
      setSkipReason("");
      await refreshCampaign(campaign.id, true);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function rollbackSelected(finding: SecurityRemediationCampaignFindingRecord) {
    if (!campaign || busy) return;
    const assessment = rollbackAssessments[finding.finding_id];
    if (!assessment?.allowed || !assessment.attempt_id) {
      setError(assessment?.reason ?? "Rollback safety has not been established for this campaign finding.");
      return;
    }
    setBusy("Rolling back selected Fix & Verify application");
    setError(null);
    try {
      await workspaceApi.rollbackSecurityFix(assessment.attempt_id);
      await refreshCampaign(campaign.id, true);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  async function boundedVerification() {
    if (!campaign || busy) return;
    const candidates = campaignFindings
      .map((item) => findings.find((finding) => finding.id === item.finding_id))
      .filter((finding): finding is WebFindingRecord => Boolean(finding));
    if (candidates.length !== campaignFindings.length) {
      setError("Final verification cannot start because one or more selected findings are missing from the loaded authorized scan.");
      return;
    }
    setBusy("Running bounded selected-finding verification");
    setError(null);
    try {
      await workspaceApi.beginSecurityRemediationCampaignCompletionVerification(campaign.id);
      for (const finding of candidates) {
        await onRetest(finding);
      }
      await workspaceApi.finalizeSecurityRemediationCampaignCompletionVerification(campaign.id);
      await refreshCampaign(campaign.id, true);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(null);
    }
  }

  if (!campaign) {
    return (
      <Panel title="Remediation Campaigns" className="ws-security-campaign">
        <div className="ws-security-campaign-intro">
          <div>
            <h3>Fix multiple findings without weakening individual review</h3>
            <p>
              Build a deterministic remediation plan from this authorized scan. Campaign approval
              approves only the order and dependencies; every actual code patch still goes through
              Guided Security Fix & Verify with its exact diff, hash and validation.
            </p>
          </div>
          {!!campaigns.length && (
            <div className="ws-security-campaign-history">
              <strong>Previous campaigns</strong>
              {campaigns.map((item) => (
                <button key={item.id} onClick={() => void refreshCampaign(item.id)}>
                  <span>{formatDate(item.created_at)}</span>
                  <StatusBadge status={item.status}/>
                  <small>{item.selected_count} selected</small>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="ws-security-campaign-filters">
          <select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}>
            <option value="">All severities</option>
            {["critical", "high", "medium", "low", "informational"].map((value) => <option key={value}>{value}</option>)}
          </select>
          <select value={filters.confidence} onChange={(event) => setFilters({ ...filters, confidence: event.target.value })}>
            <option value="">All confidence</option>
            {["Confirmed", "Likely", "Potential"].map((value) => <option key={value}>{value}</option>)}
          </select>
          <select value={filters.category} onChange={(event) => setFilters({ ...filters, category: event.target.value })}>
            <option value="">All vulnerability families</option>
            {[...new Set(findings.map((finding) => finding.category))].sort().map((value) => <option key={value} value={value}>{label(value)}</option>)}
          </select>
          <select value={filters.eligibility} onChange={(event) => setFilters({ ...filters, eligibility: event.target.value })}>
            <option value="">All eligibility</option>
            {["AUTO_FIX_CANDIDATE", "GUIDED_FIX_CANDIDATE", "MANUAL_REMEDIATION", "INSUFFICIENT_EVIDENCE"].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
          <input
            value={filters.source}
            placeholder="Filter source file/module"
            onChange={(event) => setFilters({ ...filters, source: event.target.value })}
          />
        </div>

        <div className="ws-security-campaign-selection-bar">
          <div>
            <strong>{selected.size} selected</strong>
            <span>{visibleFindings.length} visible from this scan</span>
          </div>
          <div className="ws-button-row">
            <button className="ws-button ws-button-secondary" onClick={selectAllEligible}>Select all eligible</button>
            <button className="ws-button ws-button-secondary" onClick={() => setSelected(new Set())}>Clear</button>
          </div>
        </div>

        <div className="ws-security-campaign-selection">
          {visibleFindings.map((finding) => {
            const assessment = assessments[finding.id];
            return (
              <label key={finding.id}>
                <input
                  type="checkbox"
                  checked={selected.has(finding.id)}
                  onChange={() => toggleFinding(finding.id)}
                />
                <StatusBadge status={finding.severity}/>
                <span>
                  <strong>{finding.title}</strong>
                  <small>{finding.method} {shortPath(finding.endpoint_url, 64)}</small>
                  <em>{finding.source_relative_path ?? "No correlated source file yet"}</em>
                </span>
                <StatusBadge status={finding.confidence}/>
                <StatusBadge status={assessment?.result ?? "EVALUATING"}/>
              </label>
            );
          })}
        </div>

        <div className="ws-security-campaign-selection-summary">
          <Stat label="Selected" value={selected.size}/>
          <Stat label="High/Critical" value={(selectionStats.severity.high ?? 0) + (selectionStats.severity.critical ?? 0)}/>
          <Stat label="Auto candidates" value={selectionStats.eligibility.AUTO_FIX_CANDIDATE ?? 0}/>
          <Stat label="Guided candidates" value={selectionStats.eligibility.GUIDED_FIX_CANDIDATE ?? 0}/>
          <Stat label="Manual" value={selectionStats.eligibility.MANUAL_REMEDIATION ?? 0}/>
          <Stat label="Insufficient evidence" value={selectionStats.eligibility.INSUFFICIENT_EVIDENCE ?? 0}/>
          <Stat label="Shared source groups" value={selectionStats.overlappingSources}/>
          <Stat label="Targeted retests" value={selected.size}/>
        </div>
        <p className="ws-form-help">
          Validation/retest work is shown as finding counts, not a time estimate. Shared root-cause
          analysis may reduce duplicate patch candidates, but affected findings are still verified independently.
        </p>
        <button
          className="ws-button ws-button-primary"
          disabled={!selected.size || Boolean(busy)}
          onClick={() => void createCampaign()}
        >
          {busy ?? "Create & Analyze Campaign"}
        </button>
        {error && <p className="ws-form-error">{error}</p>}
      </Panel>
    );
  }

  const terminal = ["COMPLETED", "COMPLETED_WITH_UNRESOLVED_FINDINGS", "CANCELLED"].includes(campaign.status);
  const progress = campaignProgressPercent(summary);

  return (
    <Panel
      title="Remediation Campaigns"
      className="ws-security-campaign"
      action={<StatusBadge status={campaign.status}/>}
    >
      <div className="ws-security-campaign-toolbar">
        <div>
          <strong>{campaign.selected_count} selected findings</strong>
          <span>{shortPath(campaign.target_url, 72)} · {campaign.environment}</span>
        </div>
        <div className="ws-button-row">
          {campaigns.map((item) => item.id !== campaign.id && (
            <button key={item.id} className="ws-button ws-button-secondary" onClick={() => void refreshCampaign(item.id)}>
              Open {formatDate(item.created_at)}
            </button>
          ))}
          <button className="ws-button ws-button-secondary" onClick={() => setCampaign(null)}>New Campaign</button>
        </div>
      </div>

      {campaign.status === "READY_FOR_REVIEW" && plan && (
        <section className="ws-security-campaign-plan">
          <div className="ws-security-campaign-plan-head">
            <div>
              <h4>Review remediation order</h4>
              <p>
                This approval covers only the campaign plan. It does not approve any current or
                future code patch.
              </p>
            </div>
            <code>{campaign.plan_hash}</code>
          </div>
          <div className="ws-security-campaign-order">
            {plan.ordered_findings.map((item) => {
              const source = findings.find((finding) => finding.id === item.finding_id);
              return (
                <article key={item.finding_id}>
                  <b>{item.ordinal}</b>
                  <div>
                    <strong>{source?.title ?? item.finding_id}</strong>
                    <small>{source ? shortPath(source.endpoint_url, 68) : item.finding_id}</small>
                    <p><b>Why this fix first:</b> {item.order_reason}</p>
                    {!!item.depends_on.length && <p><b>Depends on:</b> {item.depends_on.join(", ")}</p>}
                    {!!item.expected_affected.length && (
                      <p><b>Expected affected findings:</b> {item.expected_affected.join(", ")}. Each remains independently retested.</p>
                    )}
                  </div>
                  <StatusBadge status={item.eligibility}/>
                </article>
              );
            })}
          </div>
          <p className="ws-form-help">{plan.mutation_strategy}</p>
          <div className="ws-button-row">
            <button
              className="ws-button ws-button-primary"
              disabled={Boolean(busy) || !campaign.plan_hash}
              onClick={() => campaign.plan_hash && void runAction(
                "Approving campaign plan",
                () => workspaceApi.approveSecurityRemediationCampaignPlan(campaign.id, campaign.plan_hash!),
              )}
            >
              {busy ?? "Approve Campaign Plan"}
            </button>
          </div>
        </section>
      )}

      {campaign.status === "APPROVED" && (
        <section className="ws-security-campaign-callout">
          <strong>Campaign plan approved</strong>
          <p>
            Start to work through findings sequentially. Exact code mutation remains unapproved
            until you review the current Fix & Verify patch.
          </p>
          <button
            className="ws-button ws-button-primary"
            disabled={Boolean(busy)}
            onClick={() => void runAction(
              "Starting campaign",
              () => workspaceApi.startSecurityRemediationCampaign(campaign.id),
            )}
          >
            {busy ?? "Start Campaign"}
          </button>
        </section>
      )}

      {["DRAFT", "ANALYZING"].includes(campaign.status) && (
        <section className="ws-security-campaign-callout">
          <strong>Campaign analysis is incomplete</strong>
          <p>No source mutation is allowed from campaign state alone.</p>
          {campaign.status === "DRAFT" && (
            <button
              className="ws-button ws-button-primary"
              disabled={Boolean(busy)}
              onClick={() => void runAction(
                "Analyzing campaign",
                () => workspaceApi.analyzeSecurityRemediationCampaign(campaign.id),
              )}
            >
              Analyze Relationships
            </button>
          )}
        </section>
      )}

      {summary && campaign.status !== "READY_FOR_REVIEW" && campaign.status !== "APPROVED" && (
        <>
          <div className="ws-security-campaign-progress-head">
            <strong>{progress}% settled outcomes</strong>
            <span>{summary.verified_fixed} verified · {summary.blocked} blocked · {summary.manual_action_required} manual</span>
          </div>
          <div className="ws-security-campaign-progress"><span style={{ width: `${progress}%` }}/></div>
          <div className="ws-security-campaign-selection-summary">
            <Stat label="Selected" value={summary.selected_findings}/>
            <Stat label="Verified fixed" value={summary.verified_fixed}/>
            <Stat label="Still vulnerable" value={summary.still_vulnerable}/>
            <Stat label="Unable to verify" value={summary.unable_to_verify}/>
            <Stat label="Regression" value={summary.regression_detected}/>
            <Stat label="Manual" value={summary.manual_action_required}/>
            <Stat label="Blocked" value={summary.blocked}/>
            <Stat label="Skipped" value={summary.skipped}/>
          </div>
        </>
      )}

      {!terminal && ["IN_PROGRESS", "PAUSED", "BLOCKED"].includes(campaign.status) && (
        <div className="ws-security-campaign-actions">
          {campaign.status === "IN_PROGRESS" && (
            <button
              className="ws-button ws-button-secondary"
              disabled={Boolean(busy)}
              onClick={() => void runAction("Pausing campaign", () => workspaceApi.pauseSecurityRemediationCampaign(campaign.id))}
            >
              Pause
            </button>
          )}
          {["PAUSED", "BLOCKED"].includes(campaign.status) && (
            <button
              className="ws-button ws-button-primary"
              disabled={Boolean(busy)}
              onClick={() => void runAction("Revalidating source & resuming", () => workspaceApi.resumeSecurityRemediationCampaign(campaign.id))}
            >
              Revalidate & Resume
            </button>
          )}
          <button
            className="ws-button ws-button-secondary"
            disabled={Boolean(busy)}
            onClick={() => void refreshCampaign(campaign.id, true)}
          >
            Refresh Evidence
          </button>
          {campaign.status !== "PAUSED" && (
            <button
              className="ws-button ws-button-secondary"
              disabled={Boolean(busy)}
              onClick={() => void boundedVerification()}
            >
              Verify Selected Findings
            </button>
          )}
          <button
            className="ws-button ws-button-danger-ghost"
            disabled={Boolean(busy)}
            onClick={() => void runAction("Cancelling campaign", () => workspaceApi.cancelSecurityRemediationCampaign(campaign.id))}
          >
            Cancel Campaign
          </button>
        </div>
      )}

      {!terminal && current && (
        <section className="ws-security-campaign-current">
          <header>
            <div>
              <span>Current finding #{current.ordinal}</span>
              <h4>{currentWebFinding?.title ?? current.finding_id}</h4>
              <p>{current.order_reason}</p>
            </div>
            <div>
              <StatusBadge status={current.status}/>
              <StatusBadge status={current.eligibility}/>
            </div>
          </header>
          {!!current.depends_on.length && (
            <p className="ws-security-fix-warning">
              Dependency: {current.depends_on.join(", ")}. Dependent source mutation remains blocked
              when a prerequisite regression or stale approval is detected.
            </p>
          )}
          {!!current.expected_affected.length && (
            <p className="ws-form-help">
              Probable shared root cause: this remediation may affect {current.expected_affected.length} other selected finding(s).
              CodeTwin will not mark those findings fixed until their own targeted evidence verifies them.
            </p>
          )}

          {campaign.status === "PAUSED" ? (
            <div className="ws-security-campaign-callout">
              <strong>Campaign paused</strong>
              <p>
                New remediation and retest actions are paused. Any atomic Fix & Verify operation
                that already started may finish; refresh or resume to reconcile its persisted evidence.
              </p>
            </div>
          ) : current.eligibility === "INSUFFICIENT_EVIDENCE" ? (
            <div className="ws-security-campaign-callout">
              <strong>Insufficient evidence</strong>
              <p>Campaign membership does not upgrade remediation eligibility. Gather stronger runtime/source evidence before preparing a fix.</p>
            </div>
          ) : current.shared_root_primary_finding_id
            && ["QUEUED", "BLOCKED"].includes(current.status)
            && currentWebFinding ? (
            <div className="ws-security-campaign-callout">
              <strong>Retest shared-root finding before proposing another patch</strong>
              <p>
                Finding {current.shared_root_primary_finding_id} was selected as the probable shared-root representative.
                Retest this finding against the changed runtime first. A new patch is only appropriate if its own vulnerability still reproduces.
              </p>
              <button
                className="ws-button ws-button-primary"
                disabled={Boolean(busy)}
                onClick={() => void onRetest(currentWebFinding)
                  .then(() => refreshCampaign(campaign.id, true))
                  .catch((value) => setError(String(value)))}
              >
                Retest Before New Patch
              </button>
            </div>
          ) : currentWebFinding ? (
            <SecurityFixWorkflow
              finding={currentWebFinding}
              onRetest={() => onRetest(currentWebFinding)}
              rollbackAllowed={currentRollback?.allowed ?? true}
              rollbackBlockedReason={currentRollback?.allowed === false ? currentRollback.reason : null}
            />
          ) : (
            <p className="ws-form-error">The campaign finding is no longer present in the loaded scan result.</p>
          )}

          {campaign.status !== "PAUSED" && current.status !== "VERIFIED" && (
            <div className="ws-security-campaign-skip">
              <input
                value={skipReason}
                placeholder="Reason required to skip this finding"
                onChange={(event) => setSkipReason(event.target.value)}
              />
              <button
                className="ws-button ws-button-secondary"
                disabled={!skipReason.trim() || Boolean(busy)}
                onClick={() => void skipCurrent()}
              >
                Skip Finding
              </button>
            </div>
          )}
        </section>
      )}

      {!terminal && campaign.status !== "PAUSED" && summary && summary.queued_or_in_progress === 0 && (
        <section className="ws-security-campaign-callout">
          <strong>Selected finding work has factual outcomes</strong>
          <p>
            Campaign completion is backend-gated on a fresh bounded retest for every selected finding.
            Any source change after that pass requires verification again.
          </p>
          <div className="ws-button-row">
            <button className="ws-button ws-button-secondary" disabled={Boolean(busy)} onClick={() => void boundedVerification()}>
              {campaign.completion_verification_completed_at ? "Re-run Final Verification" : "Run Final Verification"}
            </button>
            <button
              className="ws-button ws-button-primary"
              disabled={Boolean(busy) || !campaign.completion_verification_completed_at}
              onClick={() => void runAction("Recording campaign completion", () => workspaceApi.completeSecurityRemediationCampaign(campaign.id))}
            >
              Record Factual Completion
            </button>
          </div>
          {campaign.completion_verification_completed_at && (
            <p className="ws-form-help">
              Final selected-finding verification completed {formatDate(campaign.completion_verification_completed_at)}.
            </p>
          )}
        </section>
      )}

      {terminal && summary && (
        <section className="ws-security-campaign-final">
          <h4>Before / after security state</h4>
          <p>{factualCampaignOutcome(summary)}</p>
          <div className="ws-security-campaign-before-after">
            {beforeAfter.map((item) => (
              <div key={item.finding_id}>
                <span>{item.title}</span>
                <small>
                  {item.severity} · {item.confidence} · {item.selected ? "selected" : "new observation"}
                </small>
                <em>
                  {item.baseline_status.replaceAll("_", " ")} → {item.comparison_status.replaceAll("_", " ")}
                </em>
                <StatusBadge status={item.comparison_status}/>
              </div>
            ))}
          </div>
        </section>
      )}

      {!terminal && campaignFindings.some((item) => item.active_attempt_id) && (
        <details className="ws-security-campaign-rollback-list">
          <summary>Rollback selected applied fix</summary>
          <p>
            Rollback always uses the individual Fix & Verify / RepairApplicationService path.
            Campaign dependencies can block an earlier rollback when later verified/applied work depends on it.
          </p>
          <div>
            {campaignFindings.filter((item) => item.active_attempt_id).map((item) => {
              const assessment = rollbackAssessments[item.finding_id];
              const source = findings.find((finding) => finding.id === item.finding_id);
              return (
                <article key={item.finding_id}>
                  <span>
                    <strong>{source?.title ?? item.finding_id}</strong>
                    <small>{assessment?.reason ?? "Assessing rollback dependencies…"}</small>
                  </span>
                  <button
                    className="ws-button ws-button-danger-ghost"
                    disabled={Boolean(busy) || !assessment?.allowed}
                    onClick={() => void rollbackSelected(item)}
                  >
                    Rollback Selected Fix
                  </button>
                </article>
              );
            })}
          </div>
        </details>
      )}

      <div className="ws-guided-view-toggle">
        <button className={!expertView ? "active" : ""} onClick={() => setExpertView(false)}>Developer View</button>
        <button className={expertView ? "active" : ""} onClick={() => setExpertView(true)}>Expert View</button>
      </div>

      <div className="ws-guided-two-column">
        <Panel title="Unresolved security debt">
          <strong>{debt.unresolved_total} unresolved selected finding(s)</strong>
          <DebtGroups debt={debt}/>
        </Panel>
        <Panel title="Regression test tracking">
          <div className="ws-security-campaign-regressions">
            {regressions.map((item) => (
              <div key={item.finding_id}>
                <StatusBadge status={item.execution_status}/>
                <p>
                  <strong>{findings.find((finding) => finding.id === item.finding_id)?.title ?? item.finding_id}</strong>
                  <small>{item.generation_status.replaceAll("_", " ")}</small>
                  {item.recommendation && <em>{item.recommendation}</em>}
                </p>
              </div>
            ))}
            {!regressions.length && <p className="ws-inline-empty">Regression-test plans appear after Fix & Verify preparation.</p>}
          </div>
        </Panel>
      </div>

      {expertView && (
        <div className="ws-guided-two-column">
          <Panel title="Relationship evidence">
            <div className="ws-security-campaign-relationships">
              {relationships.map((item) => (
                <div key={item.id}>
                  <strong>{item.relationship.replaceAll("_", " ")}</strong>
                  <span>{Math.round(item.confidence * 100)}% relationship confidence</span>
                  <small>{item.from_finding_id} → {item.to_finding_id}</small>
                  <p>{item.reason}</p>
                </div>
              ))}
              {!relationships.length && <p className="ws-inline-empty">No stronger relationship than deterministic independence was established.</p>}
            </div>
          </Panel>
          <Panel title="Campaign activity timeline">
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
          </Panel>
        </div>
      )}

      {error && <p className="ws-form-error">{error}</p>}
      {busy && <p className="ws-form-help">{busy}…</p>}
    </Panel>
  );
}

function Stat({ label: statLabel, value }: { label: string; value: number }) {
  return <div><strong>{value}</strong><span>{statLabel}</span></div>;
}

function DebtGroups({ debt }: { debt: SecurityRemediationDebtView }) {
  const groups = [
    ["Reason", debt.by_reason],
    ["Severity", debt.by_severity],
    ["Eligibility", debt.by_eligibility],
    ["Module", debt.by_module],
  ] as const;
  return (
    <div className="ws-security-campaign-debt">
      {groups.map(([groupLabel, values]) => (
        <details key={groupLabel} open={groupLabel === "Reason"}>
          <summary>{groupLabel}</summary>
          {Object.entries(values).map(([key, value]) => (
            <p key={key}><span>{key.replaceAll("_", " ")}</span><strong>{value}</strong></p>
          ))}
          {!Object.keys(values).length && <p><span>None</span><strong>0</strong></p>}
        </details>
      ))}
    </div>
  );
}

function label(value: string): string {
  return value
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
