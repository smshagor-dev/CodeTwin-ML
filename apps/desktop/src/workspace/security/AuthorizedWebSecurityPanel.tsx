import { useCallback, useEffect, useMemo, useState } from "react";

import { chooseWebSecurityReportPath, workspaceApi } from "../api";
import { Icon } from "../Icon";
import type {
  WebEndpointRecord,
  WebEvidenceRecord,
  WebFindingRecord,
  WebScanRecord,
  WebScanStartRequest,
} from "../types";
import { EmptyState, Modal, Panel, StatusBadge, formatDate, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import { WebScanDialog } from "./WebScanDialog";

const phases = [
  "queued",
  "discovering",
  "crawling",
  "passive_analysis",
  "active_testing",
  "correlating",
  "completed",
] as const;

export function AuthorizedWebSecurityPanel() {
  const { projects, websites, activeProjectId, setToast } = useWorkspace();
  const [scans, setScans] = useState<WebScanRecord[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scan, setScan] = useState<WebScanRecord | null>(null);
  const [endpoints, setEndpoints] = useState<WebEndpointRecord[]>([]);
  const [findings, setFindings] = useState<WebFindingRecord[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<WebEvidenceRecord[]>([]);
  const [composerOpen, setComposerOpen] = useState(false);
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [confidence, setConfidence] = useState("all");
  const [findingStatus, setFindingStatus] = useState("all");
  const [endpointQuery, setEndpointQuery] = useState("");
  const [report, setReport] = useState<string | null>(null);
  const [reportFormat, setReportFormat] = useState<"markdown" | "json">("markdown");
  const [reportBusy, setReportBusy] = useState(false);

  const refreshHistory = useCallback(async () => {
    const next = await workspaceApi.listWebSecurityScans(null, null, 100);
    setScans(next);
    setSelectedScanId((current) =>
      current && next.some((item) => item.id === current) ? current : next[0]?.id ?? null,
    );
    return next;
  }, []);

  const refreshSelected = useCallback(async (scanId: string) => {
    const [nextScan, nextEndpoints, nextFindings] = await Promise.all([
      workspaceApi.getWebSecurityScan(scanId),
      workspaceApi.listWebSecurityEndpoints(scanId, 500),
      workspaceApi.listWebSecurityFindings(scanId, {
        severity: null,
        category: null,
        confidence: null,
        endpoint: null,
        status: null,
      }, 500),
    ]);
    setScan(nextScan);
    setEndpoints(nextEndpoints);
    setFindings(nextFindings);
    setSelectedFindingId((current) =>
      current && nextFindings.some((finding) => finding.id === current)
        ? current
        : nextFindings[0]?.id ?? null,
    );
    return nextScan;
  }, []);

  useEffect(() => {
    void refreshHistory()
      .catch((error) => setToast({ tone: "error", message: "Could not load web security history: " + String(error) }))
      .finally(() => setLoading(false));
  }, [refreshHistory, setToast]);

  useEffect(() => {
    if (!selectedScanId) {
      setScan(null);
      setEndpoints([]);
      setFindings([]);
      return;
    }
    void refreshSelected(selectedScanId).catch((error) =>
      setToast({ tone: "error", message: "Could not load web security scan: " + String(error) }),
    );
  }, [selectedScanId, refreshSelected, setToast]);

  useEffect(() => {
    if (!scan || !["queued", "running"].includes(scan.status)) return;
    const timer = window.setInterval(() => {
      void refreshSelected(scan.id)
        .then((next) => {
          if (next && !["queued", "running"].includes(next.status)) {
            void refreshHistory();
          }
        })
        .catch((error) => setToast({ tone: "error", message: "Scan refresh failed: " + String(error) }));
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [scan?.id, scan?.status, refreshHistory, refreshSelected, setToast]);

  useEffect(() => {
    if (!selectedFindingId) {
      setEvidence([]);
      return;
    }
    void workspaceApi.listWebSecurityEvidence(selectedFindingId, 50)
      .then(setEvidence)
      .catch((error) => setToast({ tone: "error", message: "Could not load finding evidence: " + String(error) }));
  }, [selectedFindingId, setToast]);

  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null;
  const categories = useMemo(
    () => [...new Set(findings.map((finding) => finding.category))].sort(),
    [findings],
  );
  const visibleFindings = useMemo(() => {
    const endpoint = endpointQuery.trim().toLowerCase();
    return findings.filter((finding) =>
      (severity === "all" || finding.severity === severity)
      && (category === "all" || finding.category === category)
      && (confidence === "all" || finding.confidence === confidence)
      && (findingStatus === "all" || finding.status === findingStatus)
      && (!endpoint || finding.endpoint_url.toLowerCase().includes(endpoint)),
    );
  }, [findings, severity, category, confidence, findingStatus, endpointQuery]);

  const severityCount = (value: string) =>
    findings.filter((finding) => finding.severity === value).length;

  async function start(request: WebScanStartRequest) {
    setStarting(true);
    try {
      const started = await workspaceApi.startWebSecurityScan(request);
      setComposerOpen(false);
      setSelectedScanId(started.id);
      setScan(started);
      await refreshHistory();
      setToast({
        tone: "success",
        message: request.config.scope.active_testing
          ? "Authorized active web security scan started."
          : "Authorized passive web security scan started.",
      });
    } catch (error) {
      setToast({ tone: "error", message: "Could not start web security scan: " + String(error) });
      throw error;
    } finally {
      setStarting(false);
    }
  }

  async function cancel() {
    if (!scan) return;
    try {
      const cancelled = await workspaceApi.cancelWebSecurityScan(scan.id);
      if (!cancelled) {
        setToast({ tone: "info", message: "The scan is no longer running." });
      }
      await refreshSelected(scan.id);
      await refreshHistory();
    } catch (error) {
      setToast({ tone: "error", message: "Could not cancel scan: " + String(error) });
    }
  }

  async function updateFindingStatus(status: WebFindingRecord["status"]) {
    if (!selectedFinding) return;
    try {
      await workspaceApi.updateWebSecurityFindingStatus(selectedFinding.id, status);
      await refreshSelected(selectedFinding.scan_id);
      setToast({ tone: "success", message: "Finding status updated." });
    } catch (error) {
      setToast({ tone: "error", message: "Could not update finding status: " + String(error) });
    }
  }

  async function openReport(format: "markdown" | "json") {
    if (!scan) return;
    setReportBusy(true);
    try {
      const generated = await workspaceApi.generateWebSecurityReport(scan.id, format);
      setReportFormat(format);
      setReport(generated);
    } catch (error) {
      setToast({ tone: "error", message: "Could not generate report: " + String(error) });
    } finally {
      setReportBusy(false);
    }
  }

  async function exportReport(format: "markdown" | "json") {
    if (!scan) return;
    try {
      const path = await chooseWebSecurityReportPath(format);
      if (!path) return;
      const saved = await workspaceApi.exportWebSecurityReport(scan.id, format, path);
      setToast({ tone: "success", message: "Security report exported to " + saved });
    } catch (error) {
      setToast({ tone: "error", message: "Could not export report: " + String(error) });
    }
  }

  if (loading) {
    return <p className="ws-inline-empty">Loading authorized web security history…</p>;
  }

  return (
    <div className="ws-security-tab-content">
      <div className="ws-security-toolbar">
        <div className="ws-safe-note ws-websec-safety">
          <Icon name="security"/>
          <p>
            <strong>Authorized testing boundary</strong>
            <span>Every scan stores explicit authorization and bounded scope. Redirects, DNS addresses, request count, response size, concurrency and timeouts are enforced by the scanner.</span>
          </p>
        </div>
        <button className="ws-button ws-button-primary" onClick={() => setComposerOpen(true)}>
          <Icon name="plus"/>New Scan
        </button>
      </div>

      {!scan ? (
        <EmptyState
          icon="security"
          title="No authorized web security scans yet"
          description="Start with a registered website or an explicitly authorized custom target. Passive crawling is conservative by default; active probes must be deliberately enabled."
          action={<button className="ws-button ws-button-primary" onClick={() => setComposerOpen(true)}>New Authorized Scan</button>}
        />
      ) : (
        <>
          <section className="ws-websec-summary">
            <div><span><Icon name="websites"/></span><strong>{scan.endpoints_discovered}</strong><small>Endpoints discovered</small></div>
            <div><span><Icon name="activity"/></span><strong>{scan.requests_performed}</strong><small>Requests performed</small></div>
            <div><span className="ws-critical"><Icon name="warning"/></span><strong>{severityCount("critical")}</strong><small>Critical</small></div>
            <div><span className="ws-high"><Icon name="security"/></span><strong>{severityCount("high")}</strong><small>High</small></div>
            <div><span><Icon name="security"/></span><strong>{scan.findings_count}</strong><small>Total findings</small></div>
          </section>

          <Panel
            title="Scan progress & scope"
            action={
              <div className="ws-button-row ws-websec-panel-actions">
                {["queued", "running"].includes(scan.status) && (
                  <button className="ws-button ws-button-danger-ghost" onClick={() => void cancel()}>
                    Cancel Scan
                  </button>
                )}
                <button className="ws-button ws-button-secondary" disabled={reportBusy} onClick={() => void openReport("markdown")}>Preview Report</button>
                <button className="ws-button ws-button-secondary" onClick={() => void exportReport("markdown")}>Export MD</button>
                <button className="ws-button ws-button-secondary" onClick={() => void exportReport("json")}>Export JSON</button>
              </div>
            }
          >
            <div className="ws-websec-scan-head">
              <div>
                <strong title={scan.target_url}>{shortPath(scan.target_url, 90)}</strong>
                <small>Created {formatDate(scan.created_at)} · <StatusBadge status={scan.status}/></small>
              </div>
              {scan.last_error && <p className="ws-form-error">{scan.last_error}</p>}
            </div>
            <div className="ws-websec-phases" aria-label="Scan phases">
              {phases.map((phase) => {
                const currentIndex = phases.indexOf(scan.phase as typeof phases[number]);
                const index = phases.indexOf(phase);
                const state =
                  scan.status === "failed" || scan.status === "cancelled"
                    ? phase === scan.phase ? scan.status : index < currentIndex ? "done" : "waiting"
                    : index < currentIndex || scan.status === "completed" ? "done" : index === currentIndex ? "current" : "waiting";
                return <span key={phase} data-state={state}>{phase.replaceAll("_", " ")}</span>;
              })}
            </div>
            <details className="ws-websec-scope-details">
              <summary>Stored authorization and scope configuration</summary>
              <pre>{prettyJson(scan.scope_json)}</pre>
              <p>Authentication metadata only: <code>{prettyJson(scan.auth_metadata_json)}</code></p>
            </details>
          </Panel>

          <div className="ws-websec-history-grid">
            <Panel title="Scan history" action={<span className="ws-count">{scans.length} scans</span>}>
              <div className="ws-websec-scan-list">
                {scans.map((item) => (
                  <button key={item.id} className={item.id === scan.id ? "selected" : ""} onClick={() => setSelectedScanId(item.id)}>
                    <StatusBadge status={item.status}/>
                    <span><strong title={item.target_url}>{shortPath(item.target_url, 50)}</strong><small>{item.phase.replaceAll("_", " ")} · {formatDate(item.created_at)}</small></span>
                    <span>{item.findings_count} findings</span>
                  </button>
                ))}
              </div>
            </Panel>

            <Panel title="Endpoint inventory" action={<span className="ws-count">{endpoints.length} endpoints</span>}>
              <div className="ws-websec-endpoints">
                {endpoints.map((endpoint) => (
                  <div key={endpoint.id}>
                    <b>{endpoint.method}</b>
                    <p>
                      <strong title={endpoint.url}>{shortPath(endpoint.url, 68)}</strong>
                      <small>
                        {endpoint.source} · depth {endpoint.depth}
                        {endpoint.status_code ? " · HTTP " + endpoint.status_code : ""}
                      </small>
                      {!!endpoint.parameter_names.length && (
                        <em>
                          Inputs: {endpoint.parameter_names.map((name) =>
                            name + " (" + (endpoint.parameter_locations[name] ?? "unknown") + ")",
                          ).join(", ")}
                        </em>
                      )}
                      {!!endpoint.cookie_names.length && <em>Cookies observed: {endpoint.cookie_names.join(", ")}</em>}
                    </p>
                  </div>
                ))}
                {!endpoints.length && <p className="ws-inline-empty">No endpoints persisted yet. A running scan may still be discovering the target.</p>}
              </div>
            </Panel>
          </div>

          <Panel
            title="Web security findings"
            action={<span className="ws-count">{visibleFindings.length} of {findings.length}</span>}
          >
            <div className="ws-websec-filters">
              <select aria-label="Filter severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
                <option value="all">All severities</option>
                {["critical", "high", "medium", "low", "informational"].map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
              <select aria-label="Filter category" value={category} onChange={(event) => setCategory(event.target.value)}>
                <option value="all">All categories</option>
                {categories.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}
              </select>
              <select aria-label="Filter confidence" value={confidence} onChange={(event) => setConfidence(event.target.value)}>
                <option value="all">All confidence</option>
                {["Potential", "Likely", "Confirmed"].map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
              <select aria-label="Filter finding status" value={findingStatus} onChange={(event) => setFindingStatus(event.target.value)}>
                <option value="all">All statuses</option>
                {["open", "resolved", "accepted_risk", "false_positive"].map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}
              </select>
              <input aria-label="Filter finding endpoint" placeholder="Filter endpoint…" value={endpointQuery} onChange={(event) => setEndpointQuery(event.target.value)}/>
            </div>
            <div className="ws-websec-finding-table">
              {visibleFindings.map((finding) => (
                <button key={finding.id} className={finding.id === selectedFindingId ? "selected" : ""} onClick={() => setSelectedFindingId(finding.id)}>
                  <StatusBadge status={finding.severity}/>
                  <span><strong>{finding.title}</strong><small>{finding.method} {shortPath(finding.endpoint_url, 64)}{finding.parameter_name ? " · " + finding.parameter_name : ""}</small></span>
                  <StatusBadge status={finding.confidence}/>
                  <StatusBadge status={finding.status}/>
                </button>
              ))}
              {!visibleFindings.length && <p className="ws-inline-empty">No observed findings match these filters. CodeTwin does not invent missing vulnerabilities.</p>}
            </div>
          </Panel>

          {selectedFinding && (
            <div className="ws-websec-detail-grid">
              <Panel title="Finding details" action={<StatusBadge status={selectedFinding.confidence}/>}>
                <div className="ws-websec-finding-detail">
                  <h3>{selectedFinding.title}</h3>
                  <dl className="ws-detail-grid">
                    <dt>Category</dt><dd>{selectedFinding.category.replaceAll("_", " ")}</dd>
                    <dt>Severity</dt><dd><StatusBadge status={selectedFinding.severity}/></dd>
                    <dt>Endpoint</dt><dd className="ws-mono">{selectedFinding.method} {selectedFinding.endpoint_url}</dd>
                    <dt>Parameter</dt><dd>{selectedFinding.parameter_name ?? "n/a"}</dd>
                    <dt>First detected</dt><dd>{formatDate(selectedFinding.first_detected)}</dd>
                    <dt>Last detected</dt><dd>{formatDate(selectedFinding.last_detected)}</dd>
                    <dt>Source</dt><dd>{selectedFinding.source_relative_path ?? "Not correlated"}{selectedFinding.source_symbol_name ? " → " + selectedFinding.source_symbol_name : ""}</dd>
                    <dt>Source confidence</dt><dd>{selectedFinding.source_confidence === null ? "n/a" : Math.round(selectedFinding.source_confidence * 100) + "% heuristic"}</dd>
                  </dl>
                  <h4>Description</h4><p>{selectedFinding.description}</p>
                  <h4>Impact</h4><p>{selectedFinding.impact}</p>
                  <h4>Reproduction summary</h4><p>{selectedFinding.reproduction_summary}</p>
                  <h4>Remediation</h4><p>{selectedFinding.remediation}</p>
                  {!!selectedFinding.references.length && <p><strong>References:</strong> {selectedFinding.references.join(", ")}</p>}
                  <label className="ws-field">
                    <span>Finding status</span>
                    <select value={selectedFinding.status} onChange={(event) => void updateFindingStatus(event.target.value as WebFindingRecord["status"])}>
                      <option value="open">Open</option>
                      <option value="resolved">Resolved</option>
                      <option value="accepted_risk">Accepted risk</option>
                      <option value="false_positive">False positive</option>
                    </select>
                  </label>
                </div>
              </Panel>

              <Panel title="Redacted evidence">
                <div className="ws-websec-evidence">
                  {evidence.map((item) => (
                    <details key={item.id}>
                      <summary>{item.summary}</summary>
                      <strong>Request metadata</strong>
                      <pre>{prettyJson(item.request_metadata_json)}</pre>
                      <strong>Response metadata</strong>
                      <pre>{prettyJson(item.response_metadata_json)}</pre>
                    </details>
                  ))}
                  {!evidence.length && <p className="ws-inline-empty">No evidence metadata was stored for this finding.</p>}
                </div>
              </Panel>
            </div>
          )}
        </>
      )}

      <WebScanDialog
        open={composerOpen}
        websites={websites}
        projects={projects}
        activeProjectId={activeProjectId}
        busy={starting}
        onClose={() => setComposerOpen(false)}
        onStart={start}
      />

      <Modal
        open={report !== null}
        onClose={() => setReport(null)}
        title={"Security Report Preview · " + reportFormat.toUpperCase()}
        description="Generated from persisted scan scope, inventory, findings, and redacted evidence."
        footer={<button className="ws-button ws-button-secondary" onClick={() => setReport(null)}>Close</button>}
      >
        <pre className="ws-websec-report-preview">{report ?? ""}</pre>
      </Modal>
    </div>
  );
}

function prettyJson(value: string): string {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}
