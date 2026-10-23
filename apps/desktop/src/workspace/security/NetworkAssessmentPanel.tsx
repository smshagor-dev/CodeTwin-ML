import { useCallback, useEffect, useState } from "react";
import { workspaceApi } from "../api";
import { Panel, StatusBadge } from "../ui";

export type HttpsHeaderPosture = {
  http_status: number;
  hsts_state: "not_applicable_ip" | "not_observed" | "invalid" | "disabled" | "short_duration" | "long_duration";
  hsts_max_age_seconds: number | null;
  csp_observed: boolean;
  nosniff_observed: boolean;
  referrer_policy_observed: boolean;
};

type HttpsFailureKind =
  | "budget_exhausted"
  | "setup_failed"
  | "timeout"
  | "connection_or_tls_failure"
  | "request_failed";

const httpsFailureLabels: Record<HttpsFailureKind, string> = {
  budget_exhausted: "time budget exhausted",
  setup_failed: "request setup failed",
  timeout: "HTTPS request timed out",
  connection_or_tls_failure: "connection or TLS handshake/trust failed",
  request_failed: "HTTPS request failed",
};

export type NetworkProbe = {
  port: number;
  address: string;
  status: "open" | "closed" | "timeout" | "unreachable";
  elapsed_ms: number;
  tls_status: "verified" | "not_verified" | null;
  https_posture: HttpsHeaderPosture | null;
  https_failure_kind: HttpsFailureKind | null;
};

export type NetworkAssessmentRun = {
  id: string;
  target: string;
  ports: number[];
  addresses: string[];
  allow_private_networks: boolean;
  status: string;
  created_at: string;
  message: string | null;
  probes: NetworkProbe[];
};

export type NetworkAssessmentRequest = {
  target: string;
  ports: number[];
  authorization_confirmed: boolean;
  allow_private_networks: boolean;
  budget_seconds: number;
};

export function NetworkAssessmentPanel() {
  const [target, setTarget] = useState("127.0.0.1");
  const [ports, setPorts] = useState("80,443");
  const [consent, setConsent] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [budget, setBudget] = useState(20);
  const [runs, setRuns] = useState<NetworkAssessmentRun[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<NetworkAssessmentRun | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    const history = await workspaceApi.listNetworkAssessments(30);
    setRuns(history);
    setSelectedId(previous =>
      previous && history.some(run => run.id === previous) ? previous : history[0]?.id ?? null,
    );
  }, []);

  useEffect(() => {
    void refresh().catch(reason => setError(String(reason)));
  }, [refresh]);

  useEffect(() => {
    if (!selectedId) {
      setSelected(null);
      return;
    }
    let active = true;
    const update = () => workspaceApi.getNetworkAssessment(selectedId)
      .then(run => { if (active) setSelected(run); })
      .catch(reason => { if (active) setError(String(reason)); });
    void update();
    const timer = window.setInterval(() => { void update(); }, 1500);
    return () => { active = false; window.clearInterval(timer); };
  }, [selectedId]);

  async function prepare() {
    setError("");
    const entries = ports.split(",").map(port => port.trim());
    if (entries.some(port => !/^\d{1,5}$/.test(port))) {
      setError("Use a comma-separated list of explicit TCP ports, e.g. 80,443,8080.");
      return;
    }
    const numbers = entries.map(Number);
    if (numbers.length > 16 || numbers.some(port => port < 1 || port > 65535)
      || new Set(numbers).size !== numbers.length) {
      setError("Select 1–16 unique valid TCP ports.");
      return;
    }
    setBusy("prepare");
    try {
      const plan = await workspaceApi.prepareNetworkAssessment({
        target, ports: numbers, authorization_confirmed: consent,
        allow_private_networks: allowPrivate, budget_seconds: budget,
      });
      await refresh();
      setSelectedId(plan.id);
      setSelected(plan);
      setConsent(false);
    } catch (reason) { setError(String(reason)); }
    finally { setBusy(""); }
  }

  async function act(action: "approve" | "run" | "cancel") {
    if (!selected) return;
    setBusy(action);
    setError("");
    try {
      const run = action === "approve"
        ? await workspaceApi.approveNetworkAssessment(selected.id)
        : action === "cancel"
          ? await workspaceApi.cancelNetworkAssessment(selected.id)
          : await workspaceApi.runNetworkAssessment(selected.id);
      setSelected(run);
      await refresh();
    } catch (reason) {
      setError(String(reason));
      await refresh();
      const actual = await workspaceApi.getNetworkAssessment(selected.id).catch(() => null);
      if (actual) setSelected(actual);
    } finally { setBusy(""); }
  }

  return <div className="ws-form-stack">
    <Panel title="Authorized network service assessment">
      <p className="ws-form-help">
        Explicit single-host TCP discovery, DNS address verification and optional HTTPS
        certificate trust and bounded HTTPS response-header observations on ports 443/8443. No CIDR ranges, exploit payloads,
        credentials, arbitrary commands or stealth scanning. A completed run does not
        mean the target is secure.
      </p>
      <div className="ws-form-grid">
        <label className="ws-field"><span>Exact hostname or IP</span>
          <input value={target} maxLength={253} onChange={event => { setTarget(event.target.value); setConsent(false); }}
            placeholder="127.0.0.1 or approved.example.org" />
        </label>
        <label className="ws-field"><span>TCP ports (max 16)</span>
          <input value={ports} onChange={event => { setPorts(event.target.value); setConsent(false); }}
            placeholder="22,80,443,8080"/>
        </label>
        <label className="ws-field"><span>Overall budget (seconds)</span>
          <input type="number" value={budget} min={1} max={60}
            onChange={event => { setBudget(Math.max(1, Math.min(60, Number(event.target.value) || 1))); setConsent(false); }}/>
        </label>
      </div>
      <label className="ws-field">
        <span><input type="checkbox" checked={allowPrivate}
          onChange={event => { setAllowPrivate(event.target.checked); setConsent(false); }}/>
          Permit private/loopback IPs for my authorized local or staging environment
        </span>
      </label>
      <label className="ws-field">
        <span><input type="checkbox" checked={consent}
          onChange={event => setConsent(event.target.checked)}/>
          I own this target or have explicit written permission to test these exact TCP ports
        </span>
      </label>
      <div className="ws-top-actions">
        <button className="ws-button ws-button-primary" disabled={Boolean(busy) || !consent}
          onClick={() => void prepare()}>{busy === "prepare" ? "Preparing…" : "Prepare review"}</button>
      </div>
      {error && <p role="alert" className="ws-warning-box">{error}</p>}
    </Panel>

    <Panel title="Reviewed assessments">
      <div className="ws-top-actions">
        <button className="ws-button ws-button-secondary" disabled={Boolean(busy)}
          onClick={() => void refresh()}>Refresh history</button>
      </div>
      {!runs.length && <p className="ws-inline-empty">No network assessments saved.</p>}
      <div className="ws-history-list">
        {runs.map(run => <button key={run.id} type="button"
          className="ws-button ws-button-secondary"
          aria-pressed={selectedId === run.id}
          onClick={() => setSelectedId(run.id)}>
          {run.target} · {run.ports.length} ports · {run.status}
        </button>)}
      </div>
    </Panel>

    {selected && <Panel title="Selected network review">
      <StatusBadge status={selected.status}/>
      <p>Target: <strong>{selected.target}</strong></p>
      <p className="ws-form-help">Approved IP snapshot: {selected.addresses.join(", ")}</p>
      <p className="ws-form-help">Ports: {selected.ports.join(", ")} ·
        Private addresses: {selected.allow_private_networks ? "allowed" : "blocked"}</p>
      <div className="ws-top-actions">
        {selected.status === "planned" && <button className="ws-button ws-button-primary"
          disabled={Boolean(busy)} onClick={() => void act("approve")}>Approve exact scope</button>}
        {selected.status === "approved" && <button className="ws-button ws-button-primary"
          disabled={Boolean(busy)} onClick={() => void act("run")}>
          {busy === "run" ? "Testing ports…" : "Run authorized checks"}</button>}
        {["planned", "approved", "running"].includes(selected.status) &&
          <button className="ws-button ws-button-secondary" disabled={busy === "cancel"}
            onClick={() => void act("cancel")}>Cancel</button>}
      </div>
      {selected.message && <p role="alert" className="ws-warning-box">{selected.message}</p>}
      {selected.probes.length > 0 && <table className="ws-table"><thead><tr>
        <th>Port</th><th>TCP</th><th>Resolved address</th><th>Latency</th><th>HTTPS trust</th><th>HTTPS headers</th>
      </tr></thead><tbody>{selected.probes.map(result => <tr key={result.port}>
        <td>{result.port}</td><td>{result.status}</td><td>{result.address}</td>
        <td>{result.elapsed_ms} ms</td><td>{result.tls_status ?? "Not checked"}
          {result.https_failure_kind && ` · ${httpsFailureLabels[result.https_failure_kind]}`}</td>
        <td>{result.https_posture
          ? <span>HTTP {result.https_posture.http_status} · HSTS: {result.https_posture.hsts_state.replaceAll("_", " ")}
              {result.https_posture.hsts_max_age_seconds !== null && ` (max-age ${result.https_posture.hsts_max_age_seconds}s)`}
              {" · "}CSP {result.https_posture.csp_observed ? "observed" : "not observed"}
              {" · "}nosniff {result.https_posture.nosniff_observed ? "observed" : "not observed"}
              {" · "}Referrer-Policy {result.https_posture.referrer_policy_observed ? "observed" : "not observed"}</span>
          : "Not observed"}</td>
      </tr>)}</tbody></table>}
      <p className="ws-form-help">Evidence is scoped to this run. TLS verification checks
        system trust for a single HTTPS HEAD request. Header presence is observational (a HEAD response may differ from other routes); it does not audit cipher suites, protocol versions or certificate expiry. A failed HTTPS request is only classified into a short diagnostic category, not attributed to a specific certificate defect.</p>
    </Panel>}
  </div>;
}
