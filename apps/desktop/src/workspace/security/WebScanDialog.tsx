import { useEffect, useMemo, useState } from "react";

import type {
  ProjectOverview,
  WebCheckConfig,
  WebScanConfig,
  WebScanStartRequest,
  WebsiteRecord,
} from "../types";
import { Modal } from "../ui";
import {
  AUTHORIZATION_STATEMENT,
  buildWebScanRequest,
  defaultWebScanConfig,
  splitScopeValues,
  validateWebScanConfig,
  webCheckLabels,
} from "./webSecurityModel";

export function WebScanDialog({
  open,
  websites,
  projects,
  activeProjectId,
  busy,
  onClose,
  onStart,
}: {
  open: boolean;
  websites: WebsiteRecord[];
  projects: ProjectOverview[];
  activeProjectId: string | null;
  busy: boolean;
  onClose: () => void;
  onStart: (request: WebScanStartRequest) => Promise<void>;
}) {
  const firstWebsite = websites[0];
  const initialTarget = firstWebsite?.url ?? "";
  const [websiteId, setWebsiteId] = useState<string>("");
  const [projectId, setProjectId] = useState<string>("");
  const [config, setConfig] = useState<WebScanConfig>(() => defaultWebScanConfig(initialTarget));
  const [primaryCookie, setPrimaryCookie] = useState("");
  const [primaryBearer, setPrimaryBearer] = useState("");
  const [primaryHeaders, setPrimaryHeaders] = useState("");
  const [secondaryEnabled, setSecondaryEnabled] = useState(false);
  const [secondaryCookie, setSecondaryCookie] = useState("");
  const [secondaryBearer, setSecondaryBearer] = useState("");
  const [secondaryHeaders, setSecondaryHeaders] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const preferredWebsite = websites.find((website) => website.project_id === activeProjectId) ?? websites[0];
    const target = preferredWebsite?.url ?? "";
    setWebsiteId(preferredWebsite?.id ?? "");
    setProjectId(preferredWebsite?.project_id ?? activeProjectId ?? "");
    setConfig(defaultWebScanConfig(target));
    setPrimaryCookie("");
    setPrimaryBearer("");
    setPrimaryHeaders("");
    setSecondaryEnabled(false);
    setSecondaryCookie("");
    setSecondaryBearer("");
    setSecondaryHeaders("");
    setError(null);
  }, [open, activeProjectId, websites]);

  const selectedWebsite = useMemo(
    () => websites.find((website) => website.id === websiteId),
    [websiteId, websites],
  );

  function patchScope(next: Partial<WebScanConfig["scope"]>) {
    setConfig((current) => ({ ...current, scope: { ...current.scope, ...next } }));
  }

  function patchCheck(key: keyof WebCheckConfig, value: boolean) {
    setConfig((current) => ({ ...current, checks: { ...current.checks, [key]: value } }));
  }

  function targetChanged(value: string) {
    if (selectedWebsite && selectedWebsite.url !== value) {
      setWebsiteId("");
    }
    let host = "";
    try {
      host = new URL(value).hostname.toLowerCase();
    } catch {
      // The form-level validator provides the error while the user is typing.
    }
    setConfig((current) => ({
      ...current,
      scope: {
        ...current.scope,
        target_url: value,
        allowed_hostnames:
          current.scope.allowed_hostnames.length <= 1 && host
            ? [host]
            : current.scope.allowed_hostnames,
      },
    }));
  }

  function chooseWebsite(value: string) {
    setWebsiteId(value);
    const website = websites.find((item) => item.id === value);
    if (!website) return;
    setProjectId(website.project_id ?? activeProjectId ?? "");
    setConfig((current) => ({
      ...defaultWebScanConfig(website.url),
      checks: current.checks,
    }));
  }

  async function submit() {
    const validation = validateWebScanConfig(config);
    if (validation) {
      setError(validation);
      return;
    }
    try {
      const request = buildWebScanRequest({
        websiteId: selectedWebsite?.id ?? null,
        projectId: projectId || null,
        config,
        primaryCookie,
        primaryBearer,
        primaryHeaders,
        secondaryEnabled,
        secondaryCookie,
        secondaryBearer,
        secondaryHeaders,
      });
      setError(null);
      await onStart(request);
    } catch (value) {
      setError(String(value));
    }
  }

  return (
    <Modal
      open={open}
      onClose={() => !busy && onClose()}
      title="New Authorized Web Security Scan"
      description="Configure an explicit scope. CodeTwin will not silently follow redirects or generated requests outside it."
      footer={
        <>
          <button className="ws-button ws-button-secondary" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="ws-button ws-button-primary" onClick={() => void submit()} disabled={busy}>
            {busy ? "Starting…" : config.scope.active_testing ? "Start Authorized Active Scan" : "Start Passive Scan"}
          </button>
        </>
      }
    >
      <div className="ws-webscan-form">
        <section>
          <h3>1. Target & scope</h3>
          <label className="ws-field">
            <span>Registered website <small>optional</small></span>
            <select value={websiteId} onChange={(event) => chooseWebsite(event.target.value)}>
              <option value="">Custom target</option>
              {websites.map((website) => <option key={website.id} value={website.id}>{website.display_name} — {website.url}</option>)}
            </select>
          </label>
          <label className="ws-field">
            <span>Target URL</span>
            <input value={config.scope.target_url} onChange={(event) => targetChanged(event.target.value)} placeholder="https://staging.example.test"/>
          </label>
          <label className="ws-field">
            <span>Associated CodeTwin project <small>optional, enables source correlation</small></span>
            <select value={projectId} onChange={(event) => setProjectId(event.target.value)}>
              <option value="">No associated project</option>
              {projects.map((project) => <option key={project.id} value={project.id}>{project.display_name}</option>)}
            </select>
          </label>
          <div className="ws-webscan-two">
            <label className="ws-field">
              <span>Allowed hostnames</span>
              <textarea rows={3} value={config.scope.allowed_hostnames.join("\n")} onChange={(event) => patchScope({ allowed_hostnames: splitScopeValues(event.target.value) })}/>
            </label>
            <label className="ws-field">
              <span>Allowed subdomain roots</span>
              <textarea rows={3} value={config.scope.allowed_subdomains.join("\n")} onChange={(event) => patchScope({ allowed_subdomains: splitScopeValues(event.target.value) })} placeholder="staging.example.test"/>
            </label>
            <label className="ws-field">
              <span>Allowed paths</span>
              <textarea rows={3} value={config.scope.allowed_paths.join("\n")} onChange={(event) => patchScope({ allowed_paths: splitScopeValues(event.target.value) })}/>
            </label>
            <label className="ws-field">
              <span>Excluded paths</span>
              <textarea rows={3} value={config.scope.excluded_paths.join("\n")} onChange={(event) => patchScope({ excluded_paths: splitScopeValues(event.target.value) })}/>
            </label>
          </div>
          <div className="ws-webscan-limits">
            <label className="ws-field"><span>Crawl depth</span><input type="number" min={0} max={8} value={config.scope.max_crawl_depth} onChange={(event) => patchScope({ max_crawl_depth: Number(event.target.value) })}/></label>
            <label className="ws-field"><span>Max requests</span><input type="number" min={1} max={2000} value={config.scope.max_requests} onChange={(event) => patchScope({ max_requests: Number(event.target.value) })}/></label>
            <label className="ws-field"><span>Concurrency</span><input type="number" min={1} max={8} value={config.scope.concurrency} onChange={(event) => patchScope({ concurrency: Number(event.target.value) })}/></label>
            <label className="ws-field"><span>Timeout ms</span><input type="number" min={500} max={30000} step={500} value={config.scope.timeout_ms} onChange={(event) => patchScope({ timeout_ms: Number(event.target.value) })}/></label>
          </div>
          <div className="ws-webscan-options">
            <label className="ws-check-field"><input type="checkbox" checked={config.scope.allow_private_networks} onChange={(event) => patchScope({ allow_private_networks: event.target.checked })}/><span>Allow explicitly scoped private-network staging targets</span></label>
          </div>
        </section>

        <section>
          <h3>2. Authentication context</h3>
          <p className="ws-form-help">Credentials are held only for this running scan and are not stored in scan history or reports. They are sent only to the exact target origin, not sibling/subdomain discoveries.</p>
          <div className="ws-webscan-two">
            <label className="ws-field"><span>Primary session cookie <small>optional</small></span><input type="password" autoComplete="off" value={primaryCookie} onChange={(event) => setPrimaryCookie(event.target.value)} placeholder="session=…"/></label>
            <label className="ws-field"><span>Primary bearer token <small>optional</small></span><input type="password" autoComplete="off" value={primaryBearer} onChange={(event) => setPrimaryBearer(event.target.value)} placeholder="token only, without Bearer"/></label>
          </div>
          <label className="ws-field"><span>Primary custom headers <small>optional, one Name: value per line</small></span><textarea rows={3} value={primaryHeaders} onChange={(event) => setPrimaryHeaders(event.target.value)}/></label>
          <label className="ws-check-field"><input type="checkbox" checked={secondaryEnabled} onChange={(event) => setSecondaryEnabled(event.target.checked)}/><span>Compare with a second explicitly supplied test identity for access-control inconsistencies</span></label>
          {secondaryEnabled && (
            <div className="ws-webscan-secondary">
              <div className="ws-webscan-two">
                <label className="ws-field"><span>Secondary session cookie</span><input type="password" autoComplete="off" value={secondaryCookie} onChange={(event) => setSecondaryCookie(event.target.value)}/></label>
                <label className="ws-field"><span>Secondary bearer token</span><input type="password" autoComplete="off" value={secondaryBearer} onChange={(event) => setSecondaryBearer(event.target.value)}/></label>
              </div>
              <label className="ws-field"><span>Secondary custom headers</span><textarea rows={3} value={secondaryHeaders} onChange={(event) => setSecondaryHeaders(event.target.value)}/></label>
            </div>
          )}
        </section>

        <section>
          <h3>3. Testing mode & checks</h3>
          <label className="ws-check-field ws-webscan-active">
            <input type="checkbox" checked={config.scope.active_testing} onChange={(event) => patchScope({
              active_testing: event.target.checked,
              allow_non_idempotent_methods: event.target.checked ? config.scope.allow_non_idempotent_methods : false,
              enable_timing_probes: false,
            })}/>
            <span><strong>Enable bounded active testing</strong><small>Uses conservative non-destructive probes. Passive crawling and response analysis run either way.</small></span>
          </label>
          {config.scope.active_testing && (
            <div className="ws-webscan-risk-options">
              <label className="ws-check-field"><input type="checkbox" checked={config.scope.allow_non_idempotent_methods} onChange={(event) => patchScope({ allow_non_idempotent_methods: event.target.checked })}/><span>Allow probes against discovered POST/PUT/PATCH inputs <small>Off by default because these methods may change application state.</small></span></label>
            </div>
          )}
          <div className="ws-webscan-check-grid">
            {webCheckLabels.map(([key, label]) => (
              <label className="ws-check-field" key={key}>
                <input type="checkbox" checked={config.checks[key]} onChange={(event) => patchCheck(key, event.target.checked)}/>
                <span>{label}</span>
              </label>
            ))}
          </div>
        </section>

        <section className="ws-webscan-authorization">
          <h3>4. Authorization confirmation</h3>
          <label className="ws-check-field">
            <input type="checkbox" checked={config.scope.authorization_confirmed} onChange={(event) => patchScope({ authorization_confirmed: event.target.checked })}/>
            <span><strong>{AUTHORIZATION_STATEMENT}</strong><small>This confirmation and the exact bounded scope are stored with the scan record.</small></span>
          </label>
        </section>

        {error && <p className="ws-form-error" role="alert">{error}</p>}
      </div>
    </Modal>
  );
}
