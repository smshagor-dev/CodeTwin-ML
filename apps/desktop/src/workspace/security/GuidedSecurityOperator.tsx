import { useCallback, useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type {
  GuidedActivityRecord,
  GuidedApplicationMap,
  GuidedAuthMode,
  GuidedEnvironment,
  GuidedPlanItemRecord,
  GuidedPreflight,
  GuidedRetestRecord,
  GuidedRiskGraph,
  GuidedScanComparison,
  GuidedSecurityScorecard,
  GuidedSecuritySessionRecord,
  GuidedSourceCandidate,
  GuidedTestingDepth,
  GuidedTestPlan,
  WebEvidenceRecord,
  WebFindingRecord,
  WebScanConfig,
  WebScanRecord,
  WebScanStartRequest,
} from "../types";
import { Panel, StatusBadge, formatDate, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import { SecurityFixWorkflow } from "./SecurityFixWorkflow";
import { SecurityRemediationCampaigns } from "./SecurityRemediationCampaigns";
import {
  GUIDED_AUTHORIZATION_STATEMENT,
  buildGuidedRequests,
  developerFindingExplanation,
  guidedConfigFor,
  parseStoredJson,
  validateGuidedConfig,
} from "./guidedSecurityModel";

const EMPTY_MAP: GuidedApplicationMap = {
  groups: [],
  endpoint_count: 0,
  page_count: 0,
  form_count: 0,
  api_endpoint_count: 0,
  parameter_count: 0,
  authenticated_endpoint_count: 0,
};

const EMPTY_PLAN: GuidedTestPlan = {
  endpoint_count: 0,
  form_count: 0,
  parameter_count: 0,
  selected_count: 0,
  skipped_count: 0,
  counts_by_category: {},
  counts_by_risk: {},
  operations: [],
};

const EMPTY_PREFLIGHT: GuidedPreflight = {
  authorized_target: "",
  resolved_address: "",
  ip_classification: "",
  allowed_hostnames: [],
  allowed_subdomains: [],
  allowed_paths: [],
  excluded_paths: [],
  port: 0,
  https_behavior: "",
  redirect_limit: 0,
  max_requests: 0,
  concurrency: 0,
  timeout_ms: 0,
  authentication_available: false,
  destructive_actions: false,
  state_changing_testing: false,
  timing_probes: false,
};

export function GuidedSecurityOperator() {
  const { projects, websites, activeProjectId, setToast } = useWorkspace();
  const preferredWebsite = websites.find((website) => website.project_id === activeProjectId) ?? websites[0];
  const [websiteId, setWebsiteId] = useState(preferredWebsite?.id ?? "");
  const [projectId, setProjectId] = useState(preferredWebsite?.project_id ?? activeProjectId ?? "");
  const [target, setTarget] = useState(preferredWebsite?.url ?? "");
  const [environment, setEnvironment] = useState<GuidedEnvironment>("staging");
  const [depth, setDepth] = useState<GuidedTestingDepth>("standard");
  const [authMode, setAuthMode] = useState<GuidedAuthMode>("none");
  const [config, setConfig] = useState<WebScanConfig>(() =>
    guidedConfigFor(preferredWebsite?.url ?? "", "staging", "standard"),
  );
  const [primaryCookie, setPrimaryCookie] = useState("");
  const [primaryBearer, setPrimaryBearer] = useState("");
  const [primaryHeaders, setPrimaryHeaders] = useState("");
  const [secondaryCookie, setSecondaryCookie] = useState("");
  const [secondaryBearer, setSecondaryBearer] = useState("");
  const [secondaryHeaders, setSecondaryHeaders] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [preparing, setPreparing] = useState(false);
  const [starting, setStarting] = useState(false);
  const [session, setSession] = useState<GuidedSecuritySessionRecord | null>(null);
  const [planItems, setPlanItems] = useState<GuidedPlanItemRecord[]>([]);
  const [activity, setActivity] = useState<GuidedActivityRecord[]>([]);
  const [executionRequest, setExecutionRequest] = useState<WebScanStartRequest | null>(null);
  const [scan, setScan] = useState<WebScanRecord | null>(null);
  const [findings, setFindings] = useState<WebFindingRecord[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<WebEvidenceRecord[]>([]);
  const [sourceCandidates, setSourceCandidates] = useState<GuidedSourceCandidate[]>([]);
  const [retests, setRetests] = useState<GuidedRetestRecord[]>([]);
  const [scorecard, setScorecard] = useState<GuidedSecurityScorecard | null>(null);
  const [riskGraph, setRiskGraph] = useState<GuidedRiskGraph | null>(null);
  const [expertView, setExpertView] = useState(false);
  const [retesting, setRetesting] = useState(false);
  const [compareScanId, setCompareScanId] = useState("");
  const [availableScans, setAvailableScans] = useState<WebScanRecord[]>([]);
  const [comparison, setComparison] = useState<GuidedScanComparison | null>(null);
  const [error, setError] = useState<string | null>(null);

  const preflight = useMemo(
    () => session ? parseStoredJson<GuidedPreflight>(session.preflight_json, EMPTY_PREFLIGHT) : EMPTY_PREFLIGHT,
    [session],
  );
  const applicationMap = useMemo(
    () => session ? parseStoredJson<GuidedApplicationMap>(session.application_map_json, EMPTY_MAP) : EMPTY_MAP,
    [session],
  );
  const plan = useMemo(
    () => session ? parseStoredJson<GuidedTestPlan>(session.plan_json, EMPTY_PLAN) : EMPTY_PLAN,
    [session],
  );
  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null;
  const mappedStatuses = useMemo(
    () => applicationMap.groups.flatMap((group) => group.routes.map((route) => route.status_code)),
    [applicationMap],
  );
  const hasRateLimit = mappedStatuses.some((status) => status === 429);
  const hasAuthFailure = preflight.authentication_available
    && mappedStatuses.some((status) => status === 401 || status === 403);
  const budgetReached = Boolean(
    scan
      && preflight.max_requests > 0
      && scan.requests_performed >= preflight.max_requests,
  );

  const refreshSession = useCallback(async (sessionId: string) => {
    const [nextSession, nextPlan, nextActivity] = await Promise.all([
      workspaceApi.getGuidedSecuritySession(sessionId),
      workspaceApi.listGuidedSecurityPlanItems(sessionId, 1500),
      workspaceApi.listGuidedSecurityActivity(sessionId, 500),
    ]);
    if (!nextSession) return null;
    setSession(nextSession);
    setPlanItems(nextPlan);
    setActivity(nextActivity);
    if (nextSession.scan_id) {
      const [nextScan, nextFindings, nextScorecard, nextRisk] = await Promise.all([
        workspaceApi.getWebSecurityScan(nextSession.scan_id),
        workspaceApi.listWebSecurityFindings(nextSession.scan_id, {
          severity: null,
          category: null,
          confidence: null,
          endpoint: null,
          status: null,
        }, 500),
        workspaceApi.guidedSecurityScorecard(sessionId),
        workspaceApi.guidedSecurityRiskGraph(sessionId),
      ]);
      setScan(nextScan);
      setFindings(nextFindings);
      setScorecard(nextScorecard);
      setRiskGraph(nextRisk);
      setSelectedFindingId((current) =>
        current && nextFindings.some((finding) => finding.id === current)
          ? current
          : nextFindings[0]?.id ?? null,
      );
    }
    return nextSession;
  }, []);

  useEffect(() => {
    if (!session || session.status !== "running") return;
    const timer = window.setInterval(() => {
      void refreshSession(session.id).catch((value) => setError(String(value)));
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [session?.id, session?.status, refreshSession]);

  useEffect(() => {
    if (!selectedFindingId) {
      setEvidence([]);
      setSourceCandidates([]);
      setRetests([]);
      return;
    }
    void Promise.all([
      workspaceApi.listWebSecurityEvidence(selectedFindingId, 50),
      workspaceApi.correlateGuidedSecuritySources(selectedFindingId, 5),
      workspaceApi.listGuidedSecurityRetests(selectedFindingId, 20),
    ]).then(([nextEvidence, nextSources, nextRetests]) => {
      setEvidence(nextEvidence);
      setSourceCandidates(nextSources);
      setRetests(nextRetests);
    }).catch((value) => setError(String(value)));
  }, [selectedFindingId]);

  useEffect(() => {
    if (!session?.scan_id) return;
    void workspaceApi.listWebSecurityScans(null, session.project_id, 100)
      .then((values) => {
        setAvailableScans(values.filter((item) => item.id !== session.scan_id));
        setCompareScanId((current) =>
          current && values.some((item) => item.id === current)
            ? current
            : values.find((item) => item.id !== session.scan_id)?.id ?? "",
        );
      })
      .catch((value) => setError(String(value)));
  }, [session?.scan_id, session?.project_id]);

  function resetForTarget(nextTarget: string, nextEnvironment = environment, nextDepth = depth) {
    const next = guidedConfigFor(nextTarget, nextEnvironment, nextDepth);
    setConfig((current) => ({
      ...next,
      checks: current.checks,
      scope: {
        ...next.scope,
        authorization_confirmed: current.scope.authorization_confirmed,
      },
    }));
  }

  function chooseWebsite(value: string) {
    setWebsiteId(value);
    const website = websites.find((item) => item.id === value);
    if (!website) return;
    setTarget(website.url);
    setProjectId(website.project_id ?? activeProjectId ?? "");
    resetForTarget(website.url);
  }

  function changeTarget(value: string) {
    setTarget(value);
    if (websites.find((website) => website.id === websiteId)?.url !== value) setWebsiteId("");
    if (depth !== "custom") resetForTarget(value);
    else setConfig((current) => ({ ...current, scope: { ...current.scope, target_url: value } }));
  }

  function changeEnvironment(value: GuidedEnvironment) {
    setEnvironment(value);
    if (depth !== "custom") resetForTarget(target, value, depth);
    else if (value === "authorized_production") {
      setConfig((current) => ({
        ...current,
        scope: {
          ...current.scope,
          max_crawl_depth: Math.min(current.scope.max_crawl_depth, 2),
          max_requests: Math.min(current.scope.max_requests, 350),
          concurrency: Math.min(current.scope.concurrency, 2),
          timeout_ms: Math.min(current.scope.timeout_ms, 5_000),
          response_limit_bytes: Math.min(current.scope.response_limit_bytes, 512_000),
          redirect_limit: Math.min(current.scope.redirect_limit, 3),
          retry_limit: 0,
          allow_private_networks: false,
          allow_non_idempotent_methods: false,
          enable_timing_probes: false,
        },
      }));
    }
  }

  function changeDepth(value: GuidedTestingDepth) {
    setDepth(value);
    if (value !== "custom") resetForTarget(target, environment, value);
  }

  function patchScope(next: Partial<WebScanConfig["scope"]>) {
    setConfig((current) => ({ ...current, scope: { ...current.scope, ...next } }));
  }

  async function prepare() {
    const validation = validateGuidedConfig(config, environment);
    if (validation) {
      setError(validation);
      return;
    }
    setPreparing(true);
    try {
      const requests = buildGuidedRequests({
        websiteId: websiteId || null,
        projectId: projectId || null,
        environment,
        testingDepth: depth,
        authMode,
        config,
        primaryCookie,
        primaryBearer,
        primaryHeaders,
        secondaryCookie,
        secondaryBearer,
        secondaryHeaders,
      });
      setExecutionRequest(requests.execution);
      const prepared = await workspaceApi.prepareGuidedSecurityTest(requests.prepare);
      setSession(prepared);
      const [nextPlan, nextActivity] = await Promise.all([
        workspaceApi.listGuidedSecurityPlanItems(prepared.id, 1500),
        workspaceApi.listGuidedSecurityActivity(prepared.id, 500),
      ]);
      setPlanItems(nextPlan);
      setActivity(nextActivity);
      setError(null);
      setToast({ tone: "success", message: "Application mapped and a bounded security plan is ready for review." });
    } catch (value) {
      setError(String(value));
      setToast({ tone: "error", message: "Could not prepare the guided security test: " + String(value) });
    } finally {
      setPreparing(false);
    }
  }

  async function approveAndStart() {
    if (!session || !executionRequest) return;
    setStarting(true);
    try {
      const approved = await workspaceApi.approveGuidedSecurityPlan(session.id);
      const request = { ...executionRequest, guided_session_id: approved.id };
      const started = await workspaceApi.startWebSecurityScan(request);
      setScan(started);
      setSession({ ...approved, status: "running", scan_id: started.id });
      setToast({ tone: "success", message: "Approved security test started within the reviewed scope." });
      await refreshSession(approved.id);
    } catch (value) {
      setError(String(value));
      setToast({ tone: "error", message: "Could not start approved security execution: " + String(value) });
    } finally {
      setStarting(false);
    }
  }

  async function cancel() {
    if (!scan || !session) return;
    try {
      await workspaceApi.cancelWebSecurityScan(scan.id);
      await refreshSession(session.id);
      setToast({ tone: "info", message: "Security test cancellation requested." });
    } catch (value) {
      setError(String(value));
    }
  }

  async function retestFinding(finding: WebFindingRecord) {
    if (!executionRequest) {
      setToast({ tone: "error", message: "Retest credentials are not retained after leaving this guided session. Re-enter the authorized test session first." });
      return;
    }
    setRetesting(true);
    try {
      const result = await workspaceApi.retestGuidedSecurityFinding(
        finding.id,
        executionRequest.primary_auth,
        executionRequest.secondary_auth,
      );
      setRetests((current) => [result, ...current.filter((item) => item.id !== result.id)]);
      if (session) await refreshSession(session.id);
      setToast({
        tone: result.status === "retest_passed" ? "success" : "info",
        message: result.status === "retest_passed"
          ? "Targeted retest no longer reproduced the finding."
          : result.status === "still_vulnerable"
            ? "Targeted retest still observed the finding."
            : "CodeTwin could not verify this finding safely.",
      });
    } catch (value) {
      setToast({ tone: "error", message: "Retest failed: " + String(value) });
    } finally {
      setRetesting(false);
    }
  }

  async function retestFixedFindings() {
    if (!session) return;
    try {
      const candidateIds = await workspaceApi.listGuidedSecurityRetestCandidates(session.id, 500);
      const candidates = candidateIds
        .map((id) => findings.find((finding) => finding.id === id))
        .filter((finding): finding is WebFindingRecord => Boolean(finding));
      if (!candidates.length) {
        setToast({ tone: "info", message: "No applied guided fixes are waiting for targeted retest." });
        return;
      }
      for (const finding of candidates) {
        await retestFinding(finding);
      }
    } catch (value) {
      setToast({ tone: "error", message: "Could not load applied-fix retest candidates: " + String(value) });
    }
  }

  async function compareScans() {
    if (!session?.scan_id || !compareScanId) return;
    try {
      const value = await workspaceApi.compareGuidedSecurityScans(
        session.id,
        compareScanId,
        session.scan_id,
      );
      setComparison(value);
    } catch (value) {
      setToast({ tone: "error", message: "Could not compare scans: " + String(value) });
    }
  }

  function startOver() {
    setSession(null);
    setPlanItems([]);
    setActivity([]);
    setExecutionRequest(null);
    setScan(null);
    setFindings([]);
    setSelectedFindingId(null);
    setEvidence([]);
    setSourceCandidates([]);
    setRetests([]);
    setScorecard(null);
    setRiskGraph(null);
    setComparison(null);
    setError(null);
  }

  if (!session) {
    return (
      <div className="ws-guided-security">
        <Panel title="Developer Security Test" className="ws-guided-setup">
          <div className="ws-guided-intro">
            <span><Icon name="security" size={26}/></span>
            <div>
              <h2>Deep security testing without manual pentest setup</h2>
              <p>Choose the application and intent. CodeTwin handles bounded mapping, risk-aware planning, controlled checks, evidence and developer-focused remediation.</p>
            </div>
          </div>

          <div className="ws-guided-grid">
            <label className="ws-field">
              <span>Registered website <small>optional</small></span>
              <select value={websiteId} onChange={(event) => chooseWebsite(event.target.value)}>
                <option value="">Custom target</option>
                {websites.map((website) => <option key={website.id} value={website.id}>{website.display_name} — {website.url}</option>)}
              </select>
            </label>
            <label className="ws-field">
              <span>Target website/application</span>
              <input value={target} onChange={(event) => changeTarget(event.target.value)} placeholder="https://staging.example.test"/>
            </label>
            <label className="ws-field">
              <span>Associated CodeTwin project <small>recommended for source correlation</small></span>
              <select value={projectId} onChange={(event) => setProjectId(event.target.value)}>
                <option value="">No associated project</option>
                {projects.map((project) => <option key={project.id} value={project.id}>{project.display_name}</option>)}
              </select>
            </label>
            <label className="ws-field">
              <span>Environment</span>
              <select value={environment} onChange={(event) => changeEnvironment(event.target.value as GuidedEnvironment)}>
                <option value="local">Local</option>
                <option value="development">Development</option>
                <option value="staging">Staging</option>
                <option value="authorized_production">Authorized production</option>
              </select>
            </label>
            <label className="ws-field">
              <span>Testing depth</span>
              <select value={depth} onChange={(event) => changeDepth(event.target.value as GuidedTestingDepth)}>
                <option value="quick">Quick</option>
                <option value="standard">Standard</option>
                <option value="deep">Deep</option>
                <option value="custom">Custom</option>
              </select>
            </label>
            <label className="ws-field">
              <span>Authentication</span>
              <select value={authMode} onChange={(event) => setAuthMode(event.target.value as GuidedAuthMode)}>
                <option value="none">None</option>
                <option value="existing_session">Existing session</option>
                <option value="test_account_a">Test account A</option>
                <option value="test_accounts_a_b">Test accounts A + B for authorization comparison</option>
              </select>
            </label>
          </div>

          {authMode !== "none" && (
            <section className="ws-guided-auth">
              <h3>{authMode === "test_accounts_a_b" ? "Test identity A" : "Authorized test session"}</h3>
              <div className="ws-guided-grid">
                <label className="ws-field"><span>Session cookie <small>optional</small></span><input type="password" autoComplete="off" value={primaryCookie} onChange={(event) => setPrimaryCookie(event.target.value)}/></label>
                <label className="ws-field"><span>Bearer token <small>optional</small></span><input type="password" autoComplete="off" value={primaryBearer} onChange={(event) => setPrimaryBearer(event.target.value)}/></label>
              </div>
              <label className="ws-field"><span>Custom headers <small>one Name: value per line</small></span><textarea rows={3} value={primaryHeaders} onChange={(event) => setPrimaryHeaders(event.target.value)}/></label>
              {authMode === "test_accounts_a_b" && (
                <>
                  <h3>Test identity B</h3>
                  <div className="ws-guided-grid">
                    <label className="ws-field"><span>Session cookie</span><input type="password" autoComplete="off" value={secondaryCookie} onChange={(event) => setSecondaryCookie(event.target.value)}/></label>
                    <label className="ws-field"><span>Bearer token</span><input type="password" autoComplete="off" value={secondaryBearer} onChange={(event) => setSecondaryBearer(event.target.value)}/></label>
                  </div>
                  <label className="ws-field"><span>Custom headers</span><textarea rows={3} value={secondaryHeaders} onChange={(event) => setSecondaryHeaders(event.target.value)}/></label>
                </>
              )}
              <p className="ws-form-help">Credential values are used only for this running workflow and are not stored in guided session history, reports or activity logs.</p>
            </section>
          )}

          <details className="ws-guided-advanced" open={advancedOpen} onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}>
            <summary>Advanced configuration</summary>
            <div className="ws-guided-limits">
              <label className="ws-field"><span>Max requests</span><input type="number" min={1} max={2000} value={config.scope.max_requests} onChange={(event) => patchScope({ max_requests: Number(event.target.value) })}/></label>
              <label className="ws-field"><span>Crawl depth</span><input type="number" min={0} max={8} value={config.scope.max_crawl_depth} onChange={(event) => patchScope({ max_crawl_depth: Number(event.target.value) })}/></label>
              <label className="ws-field"><span>Concurrency</span><input type="number" min={1} max={8} value={config.scope.concurrency} onChange={(event) => patchScope({ concurrency: Number(event.target.value) })}/></label>
              <label className="ws-field"><span>Timeout ms</span><input type="number" min={500} max={30000} value={config.scope.timeout_ms} onChange={(event) => patchScope({ timeout_ms: Number(event.target.value) })}/></label>
            </div>
            <div className="ws-guided-grid">
              <label className="ws-field"><span>Allowed paths</span><textarea rows={3} value={config.scope.allowed_paths.join("\n")} onChange={(event) => patchScope({ allowed_paths: lines(event.target.value) })}/></label>
              <label className="ws-field"><span>Excluded paths</span><textarea rows={3} value={config.scope.excluded_paths.join("\n")} onChange={(event) => patchScope({ excluded_paths: lines(event.target.value) })}/></label>
            </div>
            <label className="ws-check-field">
              <input
                type="checkbox"
                checked={config.scope.allow_non_idempotent_methods}
                disabled={environment === "authorized_production"}
                onChange={(event) => patchScope({ allow_non_idempotent_methods: event.target.checked })}
              />
              <span>Allow bounded POST/PUT/PATCH testing <small>Only enable for a local/staging system where state changes are acceptable. DELETE remains restricted.</small></span>
            </label>
            <label className="ws-check-field">
              <input
                type="checkbox"
                checked={config.scope.enable_timing_probes}
                disabled={environment === "authorized_production"}
                onChange={(event) => patchScope({ enable_timing_probes: event.target.checked })}
              />
              <span>Allow bounded one-second timing indicators <small>Classified as CAUTION and never treated as confirmation by timing alone.</small></span>
            </label>
          </details>

          <label className="ws-check-field ws-guided-authorization">
            <input
              type="checkbox"
              checked={config.scope.authorization_confirmed}
              onChange={(event) => patchScope({ authorization_confirmed: event.target.checked })}
            />
            <span><strong>{GUIDED_AUTHORIZATION_STATEMENT}</strong><small>CodeTwin records this confirmation and the exact bounded configuration.</small></span>
          </label>

          {error && <p className="ws-form-error" role="alert">{error}</p>}
          <div className="ws-guided-actions">
            <button className="ws-button ws-button-primary" disabled={preparing} onClick={() => void prepare()}>
              {preparing ? "Mapping & planning…" : "Review Security Plan"}
            </button>
          </div>
        </Panel>
      </div>
    );
  }

  if (session.status === "awaiting_approval" || session.status === "approved") {
    return (
      <div className="ws-guided-security">
        <div className="ws-security-toolbar">
          <div className="ws-safe-note">
            <Icon name="security"/>
            <p><strong>Plan approval required</strong><span>Review the resolved target, scope, application map and planned operations. Restricted operations will not execute.</span></p>
          </div>
          <button className="ws-button ws-button-secondary" onClick={startOver}>Start over</button>
        </div>

        <section className="ws-guided-summary-cards">
          <div><strong>{applicationMap.endpoint_count}</strong><small>Endpoints mapped</small></div>
          <div><strong>{applicationMap.form_count}</strong><small>Forms</small></div>
          <div><strong>{applicationMap.parameter_count}</strong><small>Inputs</small></div>
          <div><strong>{plan.selected_count}</strong><small>Planned checks</small></div>
          <div><strong>{plan.skipped_count}</strong><small>Skipped by policy</small></div>
        </section>

        <Panel title="Pre-flight safety review">
          <div className="ws-guided-preflight">
            <dl className="ws-detail-grid">
              <dt>Authorized target</dt><dd>{preflight.authorized_target}</dd>
              <dt>Resolved address</dt><dd>{preflight.resolved_address} · {preflight.ip_classification}</dd>
              <dt>Allowed hosts</dt><dd>{preflight.allowed_hostnames.join(", ") || "none"}</dd>
              <dt>Allowed paths</dt><dd>{preflight.allowed_paths.join(", ") || "/"}</dd>
              <dt>Excluded paths</dt><dd>{preflight.excluded_paths.join(", ") || "none"}</dd>
              <dt>Port</dt><dd>{preflight.port}</dd>
              <dt>Maximum requests</dt><dd>{preflight.max_requests}</dd>
              <dt>Concurrency</dt><dd>{preflight.concurrency}</dd>
              <dt>Timeout</dt><dd>{preflight.timeout_ms} ms</dd>
              <dt>Authentication</dt><dd>{preflight.authentication_available ? "Supplied for this session" : "None"}</dd>
              <dt>State-changing tests</dt><dd>{preflight.state_changing_testing ? "Explicitly enabled with policy limits" : "Disabled"}</dd>
              <dt>Destructive actions</dt><dd>Disabled</dd>
            </dl>
            <p className="ws-form-help">{preflight.https_behavior}</p>
          </div>
        </Panel>

        {(hasRateLimit || hasAuthFailure) && (
          <div className="ws-guided-runtime-warning" role="status">
            {hasRateLimit && <p><strong>Rate limiting observed.</strong> One or more mapped requests returned HTTP 429. The approved request budget will not be increased automatically.</p>}
            {hasAuthFailure && <p><strong>Authentication may be expired or insufficient.</strong> The supplied session encountered HTTP 401/403 responses; review the map before approving active checks.</p>}
          </div>
        )}

        <div className="ws-guided-two-column">
          <Panel title="Application map">
            <div className="ws-guided-map">
              {applicationMap.groups.map((group) => (
                <details key={group.label} open={applicationMap.groups.length <= 6}>
                  <summary>{group.label} <span>{group.routes.length}</span></summary>
                  {group.routes.map((route) => (
                    <div className="ws-guided-route" key={route.method + route.url}>
                      <b>{route.method}</b>
                      <p><strong>{shortPath(route.url, 72)}</strong><small>{route.source}{route.authentication_boundary ? " · auth boundary" : ""}</small>
                        {!!route.parameters.length && <em>{route.parameters.join(", ")}</em>}
                        {!!route.source_hints.length && (
                          <em>Source: {route.source_hints.map((hint) =>
                            hint.relative_path
                            + (hint.symbol_name ? " → " + hint.symbol_name : "")
                            + " (" + Math.round(hint.confidence * 100) + "% heuristic)"
                          ).join(", ")}</em>
                        )}
                      </p>
                    </div>
                  ))}
                </details>
              ))}
              {!applicationMap.groups.length && <p className="ws-inline-empty">No in-scope endpoints were mapped.</p>}
            </div>
          </Panel>

          <Panel title="Risk-aware test plan">
            <div className="ws-guided-plan-counts">
              {Object.entries(plan.counts_by_category).map(([key, value]) => (
                <span key={key}><b>{value}</b>{labelCategory(key)}</span>
              ))}
            </div>
            <div className="ws-guided-plan-list">
              {planItems.slice(0, 160).map((item) => (
                <div key={item.id} data-selected={item.selected}>
                  <StatusBadge status={item.risk}/>
                  <p><strong>{labelCategory(item.category)}</strong><small>{item.method} {shortPath(item.endpoint_url, 58)}{item.parameter_name ? " · " + item.parameter_name : ""}</small><em>{item.selected ? item.reason : item.skip_reason ?? item.reason}</em></p>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {error && <p className="ws-form-error">{error}</p>}
        <div className="ws-guided-approval-bar">
          <div>
            <strong>Ready for controlled execution</strong>
            <span>{plan.selected_count} planned operations · {plan.skipped_count} skipped · request cap {preflight.max_requests}</span>
          </div>
          <button className="ws-button ws-button-primary" disabled={starting || !plan.selected_count} onClick={() => void approveAndStart()}>
            {starting ? "Starting…" : "Approve Plan & Start Security Test"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="ws-guided-security">
      <div className="ws-security-toolbar">
        <div className="ws-safe-note">
          <Icon name="activity"/>
          <p>
            <strong>{sessionTitle(session.status)}</strong>
            <span>{scan ? scan.phase.replaceAll("_", " ") + " · " + scan.requests_performed + " / " + preflight.max_requests + " requests" : session.status === "running" ? "Initializing approved scan…" : "No active scan."}</span>
          </p>
        </div>
        <div className="ws-button-row">
          {scan && ["queued", "running"].includes(scan.status) && <button className="ws-button ws-button-danger-ghost" onClick={() => void cancel()}>Cancel</button>}
          <button className="ws-button ws-button-secondary" onClick={startOver}>New Test</button>
        </div>
      </div>

      <section className="ws-guided-summary-cards">
        <div><strong>{scan?.endpoints_discovered ?? applicationMap.endpoint_count}</strong><small>Endpoints mapped</small></div>
        <div><strong>{scan?.requests_performed ?? 0}</strong><small>Requests used</small></div>
        <div><strong>{findings.filter((item) => item.confidence === "Confirmed").length}</strong><small>Confirmed</small></div>
        <div><strong>{findings.filter((item) => item.confidence === "Likely").length}</strong><small>Likely</small></div>
        <div><strong>{findings.filter((item) => item.confidence === "Potential").length}</strong><small>Potential</small></div>
      </section>

      <Panel title="Execution progress" action={<StatusBadge status={session.status}/>}>
        <div className="ws-guided-progress">
          {["discovering", "crawling", "passive_analysis", "active_testing", "correlating", "completed"].map((phase) => (
            <span key={phase} data-state={phaseState(scan?.phase, scan?.status, phase)}>{phaseLabel(phase)}</span>
          ))}
        </div>
        <div className="ws-guided-runtime">
          <span><b>Requests</b>{scan?.requests_performed ?? 0} / {preflight.max_requests}</span>
          <span><b>Concurrency cap</b>{preflight.concurrency}</span>
          <span><b>Elapsed</b>{elapsed(scan?.started_at, scan?.finished_at)}</span>
          <span><b>Findings so far</b>{scan?.findings_count ?? findings.length}</span>
        </div>
        {budgetReached && (
          <p className="ws-guided-runtime-warning">
            <strong>Request budget reached.</strong> CodeTwin stopped at the approved cap; coverage may be partial and no automatic escalation occurred.
          </p>
        )}
        {hasRateLimit && (
          <p className="ws-guided-runtime-warning">
            <strong>Rate limiting observed.</strong> HTTP 429 responses were seen during mapping; CodeTwin did not raise concurrency or request limits.
          </p>
        )}
        {hasAuthFailure && (
          <p className="ws-guided-runtime-warning">
            <strong>Authentication may be expired or insufficient.</strong> HTTP 401/403 responses were observed for the supplied test context.
          </p>
        )}
        {session.status === "cancelled" && <p className="ws-guided-runtime-warning">The test was cancelled. Persisted observations remain available; no success claim is made.</p>}
        {session.status === "failed" && <p className="ws-form-error">The guided test failed safely. Review the stored error and activity timeline before retrying.</p>}
        {scan?.last_error && <p className="ws-form-error">{scan.last_error}</p>}
      </Panel>

      {scorecard && (
        <Panel title="Developer security scorecard">
          <div className="ws-guided-scorecard">
            <div><strong>{scorecard.endpoints_mapped}</strong><span>Endpoints mapped</span></div>
            <div><strong>{scorecard.endpoints_tested}</strong><span>Endpoints reached</span></div>
            <div><strong>{scorecard.coverage_percent.toFixed(1)}%</strong><span>Mapped endpoint reach</span></div>
            <div><strong>{scorecard.confirmed_findings}</strong><span>Confirmed</span></div>
            <div><strong>{scorecard.likely_findings}</strong><span>Likely</span></div>
            <div><strong>{scorecard.rejected_anomalies}</strong><span>Rejected/retest-passed</span></div>
            <div><strong>{scorecard.authentication_context_supplied ? "Yes" : "No"}</strong><span>Authentication context supplied</span></div>
            <div><strong>{scorecard.authenticated_endpoints_mapped}</strong><span>Authenticated boundaries mapped</span></div>
            <div><strong>{scorecard.authorization_plan_coverage_percent.toFixed(1)}%</strong><span>Authorization plan coverage</span></div>
            <div><strong>{scorecard.api_validation_plan_coverage_percent.toFixed(1)}%</strong><span>API validation plan coverage</span></div>
            <div><strong>{scorecard.input_plan_coverage_percent.toFixed(1)}%</strong><span>Input-check plan coverage</span></div>
          </div>
          {session.status === "completed" && !scorecard.confirmed_findings && (
            <p className="ws-safe-note-text">No confirmed findings were detected within the tested scope. This does not mean the application is vulnerability-free.</p>
          )}
        </Panel>
      )}

      <div className="ws-guided-view-toggle">
        <button className={!expertView ? "active" : ""} onClick={() => setExpertView(false)}>Developer View</button>
        <button className={expertView ? "active" : ""} onClick={() => setExpertView(true)}>Expert View</button>
      </div>

      <div className="ws-guided-results-grid">
        <Panel title="Findings" action={<div className="ws-button-row"><span className="ws-count">{findings.length}</span><button className="ws-button ws-button-secondary" disabled={retesting} onClick={() => void retestFixedFindings()}>Retest Fixed Findings</button></div>}>
          <div className="ws-guided-finding-list">
            {findings.map((finding) => (
              <button key={finding.id} className={finding.id === selectedFindingId ? "selected" : ""} onClick={() => setSelectedFindingId(finding.id)}>
                <StatusBadge status={finding.severity}/>
                <span><strong>{friendlyTitle(finding)}</strong><small>{finding.method} {shortPath(finding.endpoint_url, 52)}{finding.parameter_name ? " · " + finding.parameter_name : ""}</small></span>
                <StatusBadge status={finding.confidence}/>
              </button>
            ))}
            {!findings.length && <p className="ws-inline-empty">{session.status === "completed" ? "No findings were observed by the executed checks." : "Findings will appear only when the scanner observes evidence."}</p>}
          </div>
        </Panel>

        {selectedFinding ? (
          <Panel title={friendlyTitle(selectedFinding)} action={<StatusBadge status={selectedFinding.confidence}/>}>
            <FindingDetail
              finding={selectedFinding}
              expert={expertView}
              evidence={evidence}
              sourceCandidates={sourceCandidates}
              retests={retests}
              retesting={retesting}
              onRetest={() => retestFinding(selectedFinding)}
            />
          </Panel>
        ) : (
          <Panel title="Finding details"><p className="ws-inline-empty">Select a finding to see developer guidance and correlated source candidates.</p></Panel>
        )}
      </div>

      {session.status === "completed" && session.scan_id && findings.length > 0 && (
        <SecurityRemediationCampaigns
          session={session}
          findings={findings}
          onRetest={retestFinding}
        />
      )}

      <div className="ws-guided-two-column">
        <Panel title="Defensive risk graph">
          <RiskGraph graph={riskGraph}/>
        </Panel>
        <Panel title="Operator activity log">
          <div className="ws-guided-activity">
            {activity.map((item) => (
              <div key={item.id}><b>{item.sequence}</b><p><strong>{item.message}</strong><small>{item.phase.replaceAll("_", " ")} · {formatDate(item.created_at)}</small></p></div>
            ))}
            {!activity.length && <p className="ws-inline-empty">No operator activity recorded yet.</p>}
          </div>
        </Panel>
      </div>

      {session.scan_id && (
        <Panel title="Compare scan">
          <div className="ws-guided-compare-controls">
            <select value={compareScanId} onChange={(event) => setCompareScanId(event.target.value)}>
              <option value="">Choose previous scan</option>
              {availableScans.map((item) => <option value={item.id} key={item.id}>{formatDate(item.created_at)} · {item.target_url} · {item.findings_count} findings</option>)}
            </select>
            <button className="ws-button ws-button-secondary" disabled={!compareScanId} onClick={() => void compareScans()}>Compare Scan</button>
          </div>
          {comparison && <ScanComparison comparison={comparison}/>}
        </Panel>
      )}

      {error && <p className="ws-form-error">{error}</p>}
    </div>
  );
}

function FindingDetail({
  finding,
  expert,
  evidence,
  sourceCandidates,
  retests,
  retesting,
  onRetest,
}: {
  finding: WebFindingRecord;
  expert: boolean;
  evidence: WebEvidenceRecord[];
  sourceCandidates: GuidedSourceCandidate[];
  retests: GuidedRetestRecord[];
  retesting: boolean;
  onRetest: () => Promise<void>;
}) {
  const explanation = developerFindingExplanation(finding.category);
  return (
    <div className="ws-guided-finding-detail">
      <dl className="ws-detail-grid">
        <dt>Severity</dt><dd><StatusBadge status={finding.severity}/></dd>
        <dt>Confidence</dt><dd><StatusBadge status={finding.confidence}/></dd>
        <dt>Where</dt><dd className="ws-mono">{finding.method} {finding.endpoint_url}</dd>
        <dt>Parameter</dt><dd>{finding.parameter_name ?? "n/a"}</dd>
      </dl>
      <h4>What happened?</h4><p>{explanation.what}</p>
      <h4>Why does it matter?</h4><p>{finding.impact}</p>
      <h4>What code may be responsible?</h4>
      {sourceCandidates.length ? (
        <ol className="ws-guided-source-list">
          {sourceCandidates.map((candidate) => (
            <li key={candidate.id}>
              <strong>{candidate.relative_path}{candidate.symbol_name ? " → " + candidate.symbol_name : ""}</strong>
              <span>{Math.round(candidate.confidence * 100)}% heuristic confidence</span>
              <small>{candidate.rationale}</small>
            </li>
          ))}
        </ol>
      ) : <p>No source candidate is strong enough yet. Runtime evidence remains valid without source attribution.</p>}
      <h4>How should I fix it?</h4><p>{finding.remediation || explanation.fix}</p>
      <h4>How do I verify the fix?</h4><p>{explanation.verify}</p>
      <div className="ws-button-row">
        <button className="ws-button ws-button-secondary" disabled={retesting} onClick={() => void onRetest()}>{retesting ? "Retesting…" : "Retest Finding"}</button>
      </div>
      <SecurityFixWorkflow finding={finding} onRetest={onRetest}/>
      {!!retests.length && (
        <div className="ws-guided-retests">
          <h4>Retest history</h4>
          {retests.map((item) => <p key={item.id}><StatusBadge status={item.status}/> {formatDate(item.created_at)} · {item.requests_performed} requests{item.observed_confidence ? " · " + item.observed_confidence : ""}</p>)}
        </div>
      )}
      {expert && (
        <details className="ws-guided-expert" open>
          <summary>Redacted technical evidence</summary>
          <p><strong>Detector category:</strong> {finding.category}</p>
          <p><strong>Reproduction summary:</strong> {finding.reproduction_summary}</p>
          {evidence.map((item) => (
            <details key={item.id}>
              <summary>{item.summary}</summary>
              <pre>{prettyJson(item.request_metadata_json)}</pre>
              <pre>{prettyJson(item.response_metadata_json)}</pre>
            </details>
          ))}
          {!evidence.length && <p>No persisted evidence metadata is available.</p>}
        </details>
      )}
    </div>
  );
}

function RiskGraph({ graph }: { graph: GuidedRiskGraph | null }) {
  if (!graph?.nodes.length) return <p className="ws-inline-empty">The defensive risk graph is built only from observed findings.</p>;
  const labels = new Map(graph.nodes.map((node) => [node.id, node.label]));
  return (
    <div className="ws-guided-risk-graph">
      {graph.edges.map((edge, index) => (
        <div key={edge.from + edge.to + index}>
          <strong>{labels.get(edge.from) ?? edge.from}</strong>
          <span>→ {edge.relationship} →</span>
          <strong>{labels.get(edge.to) ?? edge.to}</strong>
        </div>
      ))}
    </div>
  );
}

function ScanComparison({ comparison }: { comparison: GuidedScanComparison }) {
  const value = parseStoredJson<{
    new_findings?: string[];
    resolved_findings?: string[];
    persistent_findings?: string[];
    changed_confidence?: Array<{ fingerprint: string; before: string; after: string }>;
    coverage?: { endpoint_delta?: number; request_delta?: number };
  }>(comparison.comparison_json, {});
  return (
    <div className="ws-guided-comparison">
      <span><strong>{value.new_findings?.length ?? 0}</strong>New findings</span>
      <span><strong>{value.resolved_findings?.length ?? 0}</strong>Resolved findings</span>
      <span><strong>{value.persistent_findings?.length ?? 0}</strong>Persistent findings</span>
      <span><strong>{value.changed_confidence?.length ?? 0}</strong>Confidence changes</span>
      <span><strong>{value.coverage?.endpoint_delta ?? 0}</strong>Endpoint coverage delta</span>
    </div>
  );
}

function lines(value: string): string[] {
  return [...new Set(value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))];
}

function labelCategory(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function friendlyTitle(finding: WebFindingRecord): string {
  if (finding.category === "sql_injection") return "Possible SQL Injection";
  if (finding.category === "xss") return "Possible Cross-Site Scripting";
  if (finding.category === "access_control") return "Possible Authorization Inconsistency";
  if (finding.category === "csrf") return "Possible CSRF Control Gap";
  if (finding.category === "api_input_validation") return "API Input Validation Weakness";
  return finding.title;
}

function phaseLabel(value: string): string {
  const labels: Record<string, string> = {
    discovering: "Mapping application",
    crawling: "Crawling authorized scope",
    passive_analysis: "Passive analysis",
    active_testing: "Controlled active testing",
    correlating: "Verification & source correlation",
    completed: "Reporting",
  };
  return labels[value] ?? value.replaceAll("_", " ");
}

function phaseState(current: string | undefined, status: string | undefined, phase: string): string {
  const phases = ["discovering", "crawling", "passive_analysis", "active_testing", "correlating", "completed"];
  if (status === "completed") return "done";
  const currentIndex = phases.indexOf(current ?? "");
  const index = phases.indexOf(phase);
  if (index < currentIndex) return "done";
  if (index === currentIndex && (status === "failed" || status === "cancelled")) return status;
  if (index === currentIndex) return "current";
  return "waiting";
}

function sessionTitle(status: GuidedSecuritySessionRecord["status"]): string {
  switch (status) {
    case "completed": return "Guided security test completed";
    case "cancelled": return "Guided security test cancelled";
    case "failed": return "Guided security test failed safely";
    case "running": return "Guided security test in progress";
    case "approved": return "Guided security plan approved";
    case "awaiting_approval": return "Guided security plan awaiting approval";
    case "preparing": return "Guided security preparation in progress";
  }
}

function elapsed(started: string | null | undefined, finished: string | null | undefined): string {
  if (!started) return "Not started";
  const start = new Date(started).getTime();
  const end = finished ? new Date(finished).getTime() : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "Unknown";
  const seconds = Math.max(0, Math.round((end - start) / 1000));
  if (seconds < 60) return seconds + "s";
  return Math.floor(seconds / 60) + "m " + (seconds % 60) + "s";
}

function prettyJson(value: string): string {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}
