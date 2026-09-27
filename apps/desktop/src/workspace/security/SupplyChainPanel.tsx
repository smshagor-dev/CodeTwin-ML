import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type {
  AdvisoryMode,
  DependencyAuditRunRecord,
  DependencyFindingRecord,
  DependencyRecord,
  SecretFindingRecord,
  SecretScanRunRecord,
} from "../types";
import { EmptyState, Panel, ProjectSelect, StatusBadge, formatDate, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

type Busy = "secrets" | "dependencies" | null;

export function SupplyChainPanel() {
  const { projects, activeProjectId, setActiveProjectId, setToast } = useWorkspace();
  const [busy, setBusy] = useState<Busy>(null);
  const [status, setStatus] = useState("open");

  const [secrets, setSecrets] = useState<SecretFindingRecord[]>([]);
  const [secretRuns, setSecretRuns] = useState<SecretScanRunRecord[]>([]);

  const [dependencyFindings, setDependencyFindings] = useState<DependencyFindingRecord[]>([]);
  const [inventory, setInventory] = useState<DependencyRecord[]>([]);
  const [auditRuns, setAuditRuns] = useState<DependencyAuditRunRecord[]>([]);
  const [mode, setMode] = useState<AdvisoryMode>("offline");
  const [offlineDirectory, setOfflineDirectory] = useState("");
  const [networkConsent, setNetworkConsent] = useState(false);

  async function load(projectId: string) {
    const filter = status === "all" ? null : status;
    try {
      const [nextSecrets, nextSecretRuns, nextFindings, nextInventory, nextAuditRuns] = await Promise.all([
        workspaceApi.secretFindings(projectId, filter),
        workspaceApi.secretScanHistory(projectId),
        workspaceApi.dependencyFindings(projectId, filter),
        workspaceApi.dependencyInventory(projectId),
        workspaceApi.dependencyAuditHistory(projectId),
      ]);
      setSecrets(nextSecrets);
      setSecretRuns(nextSecretRuns);
      setDependencyFindings(nextFindings);
      setInventory(nextInventory);
      setAuditRuns(nextAuditRuns);
    } catch (error) {
      setToast({ tone: "error", message: "Could not load supply-chain evidence: " + String(error) });
    }
  }

  useEffect(() => {
    if (!activeProjectId) {
      setSecrets([]);
      setSecretRuns([]);
      setDependencyFindings([]);
      setInventory([]);
      setAuditRuns([]);
      return;
    }
    void load(activeProjectId);
  }, [activeProjectId, status]);

  async function runSecretScan() {
    if (!activeProjectId) return;
    setBusy("secrets");
    try {
      const summary = await workspaceApi.runSecretScan(activeProjectId);
      setToast({
        tone: summary.observations ? "info" : "success",
        message: `Secret scan: ${summary.files_scanned} files, ${summary.observations} secret(s) found, ${summary.findings_resolved} resolved.`
          + (summary.coverage_complete ? "" : " Some files could not be read, so nothing was marked resolved."),
      });
      await load(activeProjectId);
    } catch (error) {
      setToast({ tone: "error", message: "Secret scan failed: " + String(error) });
    } finally {
      setBusy(null);
    }
  }

  async function runDependencyAudit() {
    if (!activeProjectId) return;
    setBusy("dependencies");
    try {
      const summary = await workspaceApi.runDependencyAudit(
        activeProjectId,
        mode,
        mode === "offline" ? offlineDirectory.trim() || null : null,
        mode === "online" && networkConsent,
      );
      const incomplete = summary.coverage_complete
        ? ""
        : ` Coverage incomplete (${summary.manifest_errors.length} unreadable manifest(s) or missing advisories); nothing was marked resolved.`;
      setToast({
        tone: summary.vulnerable_packages ? "info" : "success",
        message: `Dependency audit: ${summary.packages} packages in ${summary.manifests} manifest(s), ${summary.vulnerable_packages} vulnerable.${incomplete}`,
      });
      await load(activeProjectId);
    } catch (error) {
      setToast({ tone: "error", message: "Dependency audit failed: " + String(error) });
    } finally {
      setBusy(null);
    }
  }

  async function exportSbom() {
    if (!activeProjectId) return;
    const path = await workspaceApi.chooseSbomPath().catch(() => null);
    if (!path) return;
    try {
      const result = await workspaceApi.exportDependencySbom(activeProjectId, path);
      setToast({
        tone: "success",
        message: `SBOM saved: ${result.components} components, ${result.vulnerabilities} open vulnerabilities → ${result.path}`,
      });
    } catch (error) {
      setToast({ tone: "error", message: "SBOM export failed: " + String(error) });
    }
  }

  async function chooseDirectory() {
    const selected = await workspaceApi.pickAdvisoryDirectory().catch(() => null);
    if (selected) setOfflineDirectory(selected);
  }

  const count = (items: { severity: string }[], severity: string) =>
    items.filter((item) => item.severity.toLowerCase() === severity).length;
  const vulnerablePackages = useMemo(
    () => inventory.filter((item) => item.open_advisories > 0).length,
    [inventory],
  );
  const canAudit =
    !!activeProjectId &&
    busy === null &&
    (mode === "online" ? networkConsent : offlineDirectory.trim().length > 0);

  if (!projects.length) {
    return (
      <EmptyState
        icon="security"
        title="No indexed project"
        description="Secret scanning and dependency auditing run against an imported project folder. Import a project first."
      />
    );
  }

  return (
    <div className="ws-security-tab-content">
      <div className="ws-security-toolbar">
        <ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/>
        <select aria-label="Finding status" value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
          <option value="all">All</option>
        </select>
      </div>

      <section className="ws-analysis-metrics">
        <div><span className="ws-critical"><Icon name="warning"/></span><strong>{count(secrets, "critical") + count(dependencyFindings, "critical")}</strong><small>Critical</small></div>
        <div><span className="ws-high"><Icon name="security"/></span><strong>{count(secrets, "high") + count(dependencyFindings, "high")}</strong><small>High</small></div>
        <div><span><Icon name="security"/></span><strong>{secrets.length}</strong><small>Secrets</small></div>
        <div><span><Icon name="activity"/></span><strong>{vulnerablePackages}/{inventory.length}</strong><small>Vulnerable packages</small></div>
      </section>

      <div className="ws-security-layout ws-supply-layout">
        <Panel
          title="Secrets in the repository"
          action={
            <button className="ws-button ws-button-primary" onClick={() => void runSecretScan()} disabled={!activeProjectId || busy !== null}>
              <Icon name="scan"/>
              {busy === "secrets" ? "Scanning…" : "Scan for secrets"}
            </button>
          }
        >
          <p className="ws-inline-empty">
            Scans every text file (including .env and key files). Values are never stored: only a redacted preview is kept.
            Add <code>codetwin:ignore-secret</code> on a line to suppress an intentional test value.
          </p>
          <div className="ws-finding-list">
            {secrets.map((finding) => (
              <article key={finding.id}>
                <StatusBadge status={finding.severity}/>
                <div>
                  <strong>{finding.title}</strong>
                  <p>
                    <code>{shortPath(finding.relative_path)}{finding.line ? `:${finding.line}` : ""}</code> · <code>{finding.redacted}</code>
                    {finding.in_test_path ? " · test/fixture path" : ""}
                  </p>
                  <small>{finding.remediation}</small>
                </div>
                <time>{formatDate(finding.last_seen)}</time>
              </article>
            ))}
            {!secrets.length && <p className="ws-inline-empty">No secret findings in this view.</p>}
          </div>
          <div className="ws-history-list">
            {secretRuns.slice(0, 5).map((run) => (
              <div key={run.run_id}>
                <StatusBadge status={run.status}/>
                <p>
                  <strong>{run.files_scanned} files scanned</strong>
                  <small>{run.observations} found · {run.findings_opened} new · {run.findings_resolved} resolved{run.coverage_complete ? "" : " · partial coverage"}</small>
                </p>
                <time>{formatDate(run.finished_at ?? run.started_at)}</time>
              </div>
            ))}
          </div>
        </Panel>

        <Panel
          title="Vulnerable dependencies"
          action={
            <div className="ws-sbom-actions">
              <button
                className="ws-button ws-button-secondary"
                onClick={() => void exportSbom()}
                disabled={!inventory.length || busy !== null}
                title="CycloneDX 1.5 JSON of the last dependency inventory"
              >
                Export SBOM
              </button>
              <button className="ws-button ws-button-primary" onClick={() => void runDependencyAudit()} disabled={!canAudit}>
                <Icon name="scan"/>
                {busy === "dependencies" ? "Auditing…" : "Audit dependencies"}
              </button>
            </div>
          }
        >
          <div className="ws-advisory-source" role="radiogroup" aria-label="Advisory source">
            <label>
              <input type="radio" name="advisory-mode" checked={mode === "offline"} onChange={() => setMode("offline")}/>
              Offline OSV directory (no network)
            </label>
            {mode === "offline" && (
              <div className="ws-advisory-path">
                <input
                  aria-label="Offline OSV advisory directory"
                  placeholder="Extracted OSV export, e.g. /data/osv"
                  value={offlineDirectory}
                  onChange={(event) => setOfflineDirectory(event.target.value)}
                />
                <button className="ws-button ws-button-secondary" onClick={() => void chooseDirectory()}>Browse…</button>
              </div>
            )}
            <label>
              <input type="radio" name="advisory-mode" checked={mode === "online"} onChange={() => setMode("online")}/>
              Online lookup via OSV.dev
            </label>
            {mode === "online" && (
              <label className="ws-consent">
                <input type="checkbox" checked={networkConsent} onChange={(event) => setNetworkConsent(event.target.checked)}/>
                I agree to send package names and versions (no source code or file paths) to api.osv.dev.
              </label>
            )}
          </div>
          <div className="ws-finding-list">
            {dependencyFindings.map((finding) => (
              <article key={finding.id}>
                <StatusBadge status={finding.severity}/>
                <div>
                  <strong>{finding.title}</strong>
                  <p>{finding.description}</p>
                  <small>
                    {finding.ecosystem} · <code>{shortPath(finding.manifest_path)}{finding.line ? `:${finding.line}` : ""}</code>
                    {finding.cvss_score !== null ? ` · CVSS ${finding.cvss_score.toFixed(1)}` : ""}
                    {finding.is_dev ? " · dev dependency" : ""}
                    {finding.fixed_versions.length ? ` · fixed in ${finding.fixed_versions.join(", ")}` : " · no fix published"}
                    {finding.references[0] ? <> · <a href={finding.references[0]} target="_blank" rel="noreferrer">{finding.advisory_id}</a></> : ` · ${finding.advisory_id}`}
                  </small>
                </div>
                <time>{formatDate(finding.last_seen)}</time>
              </article>
            ))}
            {!dependencyFindings.length && (
              <p className="ws-inline-empty">
                {inventory.length
                  ? `No vulnerable dependencies in this view (${inventory.length} packages inventoried).`
                  : "Run an audit to inventory lockfiles (npm, yarn, pnpm, bun, Cargo, PyPI, Go, Composer, RubyGems, Maven, Gradle, NuGet)."}
              </p>
            )}
          </div>
          <div className="ws-history-list">
            {auditRuns.slice(0, 5).map((run) => (
              <div key={run.run_id}>
                <StatusBadge status={run.status}/>
                <p>
                  <strong>{run.packages} packages · {run.vulnerable_packages} vulnerable</strong>
                  <small>{run.advisory_source.startsWith("osv_api") ? "OSV.dev" : "offline OSV"} · {run.findings_opened} new · {run.findings_resolved} resolved{run.coverage_complete ? "" : " · partial coverage"}</small>
                </p>
                <time>{formatDate(run.finished_at ?? run.started_at)}</time>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
