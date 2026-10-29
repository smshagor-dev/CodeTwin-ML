import { useCallback, useEffect, useState } from "react";

import { LoadingState, Panel, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import {
  agentConversation, API_SCOPES, downloadPdf, formatMs, formatPercent, platformApi, ROLES,
  type AccessOverview, type ApiStatus, type ApiToken, type AuditRecord, type Citation, type Comment,
  type GroupUsage, type LlmAnalytics, type MetricsSnapshot, type Role, type SearchProviderKind,
} from "../platformApi";
import { workflowApi, type PlanInfo, type ProviderSettings, type RunDetail } from "../workflowApi";

const time = (ms: number | null | undefined) => (ms ? new Date(ms).toLocaleString() : "—");

function useErrorToast() {
  const { setToast } = useWorkspace();
  return useCallback((error: unknown) => setToast({ tone: "error", message: String(error) }), [setToast]);
}

function useToast() {
  const { setToast } = useWorkspace();
  return useCallback((message: string) => setToast({ tone: "success", message }), [setToast]);
}

function UsageTable({ rows, label }: { rows: GroupUsage[]; label: string }) {
  if (rows.length === 0) return <p className="ws-form-help">No model calls recorded.</p>;
  return (
    <div className="wf-table-wrap">
      <table className="wf-table">
        <thead><tr><th scope="col">{label}</th><th scope="col">Calls</th><th scope="col">Success</th><th scope="col">Credits</th><th scope="col">Tokens (in/out)</th><th scope="col">p50</th><th scope="col">p95</th></tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.key}>
            <th scope="row">{r.key}</th>
            <td>{r.stats.calls}</td>
            <td>{formatPercent(r.stats.success_rate)}</td>
            <td>{r.stats.credits}</td>
            <td>{r.stats.calls_with_token_usage ? `${r.stats.prompt_tokens} / ${r.stats.completion_tokens}` : "not reported"}</td>
            <td>{formatMs(r.stats.p50_latency_ms)}</td>
            <td>{formatMs(r.stats.p95_latency_ms)}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

function DailyBars({ days }: { days: GroupUsage[] }) {
  if (days.length === 0) return null;
  const max = Math.max(1, ...days.map((d) => d.stats.calls));
  return (
    <ol className="wf-bars" aria-label="Model calls per day">
      {days.map((d) => (
        <li key={d.key} title={`${d.key}: ${d.stats.calls} call(s), ${d.stats.failed} failed, ${d.stats.credits} credit(s)`}>
          <span className="wf-bar" style={{ height: `${Math.max(4, (d.stats.calls / max) * 100)}%` }}>
            {d.stats.failed > 0 && <span className="wf-bar-failed" style={{ height: `${(d.stats.failed / d.stats.calls) * 100}%` }}/>}
          </span>
          <small>{d.key.slice(5)}</small>
        </li>
      ))}
    </ol>
  );
}

/** Agent activity, queue/lease health, alerts and LLM analytics. */
export function InsightsTab({ projectId }: { projectId: string }) {
  const onError = useErrorToast();
  const toast = useToast();
  const [days, setDays] = useState(30);
  const [analytics, setAnalytics] = useState<LlmAnalytics | null>(null);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [retention, setRetention] = useState(90);
  const load = useCallback(() => {
    platformApi.analytics(projectId, days).then(setAnalytics).catch(onError);
    platformApi.metrics(projectId).then(setMetrics).catch(onError);
  }, [projectId, days, onError]);
  useEffect(() => {
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [load]);
  if (!analytics || !metrics) return <LoadingState/>;
  const t = analytics.totals;
  return (
    <div className="wf-run">
      {metrics.alerts.length > 0 && (
        <Panel title="Alerts">
          <ul className="wf-tools">{metrics.alerts.map((a) => (
            <li key={a.code}><StatusBadge status={a.severity === "critical" ? "failed" : a.severity === "warning" ? "blocked" : "queued"}/> <strong>{a.code.replaceAll("_", " ")}</strong> <small>{a.message}</small></li>
          ))}</ul>
        </Panel>
      )}
      <Panel title="Agent activity" action={<button type="button" className="ws-button ws-button-secondary" onClick={load}>Refresh</button>}>
        <dl className="wf-meta">
          <div><dt>Queue depth</dt><dd>{metrics.queue_depth}</dd></div>
          <div><dt>Active workers (leases)</dt><dd>{metrics.live_leases}</dd></div>
          <div><dt>Stale leases</dt><dd>{metrics.stale_leases}</dd></div>
          <div><dt>Retries (24 h)</dt><dd>{metrics.retries_24h}</dd></div>
          <div><dt>Tool calls (24 h)</dt><dd>{metrics.tool_calls_24h}</dd></div>
          <div><dt>Unresolved side effects</dt><dd>{metrics.uncertain_side_effects}</dd></div>
        </dl>
        <div className="wf-grid">
          <div className="wf-col">
            <h3 className="wf-subhead">Runs by state</h3>
            {Object.keys(metrics.runs_by_state).length === 0 ? <p className="ws-form-help">No runs yet.</p> :
              <ul className="wf-tools">{Object.entries(metrics.runs_by_state).map(([k, v]) => <li key={k}><StatusBadge status={k}/> {v}</li>)}</ul>}
          </div>
          <div className="wf-col">
            <h3 className="wf-subhead">Tool denials (24 h)</h3>
            {Object.keys(metrics.tool_denials_24h).length === 0 ? <p className="ws-form-help">None.</p> :
              <ul className="wf-tools">{Object.entries(metrics.tool_denials_24h).map(([k, v]) => <li key={k}><code>{k}</code> {v}</li>)}</ul>}
          </div>
        </div>
        {metrics.role_latency.length > 0 && <>
          <h3 className="wf-subhead">Specialist performance (7 days)</h3>
          <div className="wf-table-wrap"><table className="wf-table">
            <thead><tr><th scope="col">Role</th><th scope="col">Completed</th><th scope="col">Failed</th><th scope="col">Avg</th><th scope="col">p95</th></tr></thead>
            <tbody>{metrics.role_latency.map((r) => <tr key={r.role}><th scope="row">{r.role}</th><td>{r.completed}</td><td>{r.failed}</td><td>{formatMs(r.avg_ms)}</td><td>{formatMs(r.p95_ms)}</td></tr>)}</tbody>
          </table></div>
        </>}
      </Panel>
      <Panel title="LLM analytics" action={
        <select aria-label="Analytics window" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[1, 7, 30, 90].map((d) => <option key={d} value={d}>Last {d} day{d > 1 ? "s" : ""}</option>)}
        </select>}>
        <dl className="wf-meta">
          <div><dt>Calls</dt><dd>{t.calls}</dd></div>
          <div><dt>Success rate</dt><dd>{formatPercent(t.success_rate)}</dd></div>
          <div><dt>Credits (cost)</dt><dd>{t.credits}</dd></div>
          <div><dt>Prompt / completion tokens</dt><dd>{t.prompt_tokens} / {t.completion_tokens}</dd></div>
          <div><dt>Latency p50 / p95</dt><dd>{formatMs(t.p50_latency_ms)} / {formatMs(t.p95_latency_ms)}</dd></div>
          <div><dt>Redactions applied</dt><dd>{t.redactions}</dd></div>
        </dl>
        <p className="ws-form-help">{analytics.cost_basis}. Token totals cover {t.calls_with_token_usage} of {t.calls} call(s).</p>
        <DailyBars days={analytics.by_day}/>
        <h3 className="wf-subhead">By model</h3>
        <UsageTable rows={analytics.by_model} label="Model"/>
        <h3 className="wf-subhead">By agent role</h3>
        <UsageTable rows={analytics.by_role} label="Role"/>
        {Object.keys(analytics.outcomes).length > 0 && <p className="ws-form-help">Outcomes: {Object.entries(analytics.outcomes).map(([k, v]) => `${k} ${v}`).join(" · ")}</p>}
      </Panel>
      <Panel title="Diagnostics and retention">
        <div className="ws-form-stack">
          <p className="ws-form-help">The diagnostics bundle holds versions, schema state, metrics and analytics only — no goals, prompts, model output, source, URLs or keys.</p>
          <div className="ws-button-row">
            <button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.exportDiagnostics().then((p) => toast(`Diagnostics saved to ${p}`)).catch(onError)}>Export diagnostics bundle</button>
          </div>
          <label className="ws-field"><span>Delete settled runs older than (days); the newest 20 per project are kept</span>
            <input type="number" min={1} max={3650} value={retention} onChange={(e) => setRetention(Number(e.target.value))}/>
          </label>
          <div className="ws-button-row">
            <button type="button" className="ws-button ws-button-secondary" onClick={() => {
              if (!window.confirm(`Delete settled runs, provider audit rows and audit records older than ${retention} days? This cannot be undone.`)) return;
              void platformApi.prune(retention, 20).then((r) => { toast(`Removed ${r.runs_deleted} run(s), ${r.provider_requests_deleted} provider row(s), ${r.audit_records_deleted} audit row(s)`); load(); }).catch(onError);
            }}>Apply retention</button>
          </div>
        </div>
      </Panel>
    </div>
  );
}

const PLANNER_ROLE = { role: "planner", display_name: "Planner (AI task decomposition)" };

/** Per-agent model routing, the local fallback model and the search provider. */
export function ModelsTab() {
  const onError = useErrorToast();
  const toast = useToast();
  const [roles, setRoles] = useState<Array<{ role: string; display_name: string }>>([]);
  const [cloud, setCloud] = useState<ProviderSettings | null>(null);
  const [cloudMap, setCloudMap] = useState<Record<string, string>>({});
  const [local, setLocal] = useState({ baseUrl: "http://127.0.0.1:11434/v1", enabled: false, model: "", map: {} as Record<string, string> });
  const [search, setSearch] = useState({ kind: "brave" as SearchProviderKind, baseUrl: "https://api.search.brave.com", enabled: false, max: 5 });
  const [keyStored, setKeyStored] = useState(false);
  const [searchKey, setSearchKey] = useState("");
  const load = useCallback(() => {
    workflowApi.roles().then((r) => setRoles([PLANNER_ROLE, ...r])).catch(onError);
    workflowApi.cloudStatus().then((s) => { setCloud(s.settings); setCloudMap(s.settings.role_models.cloud_by_role ?? {}); }).catch(onError);
    platformApi.localModelStatus().then(({ settings }) => {
      if (settings) setLocal({ baseUrl: settings.base_url, enabled: settings.enabled, model: settings.role_models.default_local ?? "", map: settings.role_models.local_by_role ?? {} });
    }).catch(onError);
    platformApi.searchStatus().then(({ settings, key_stored }) => {
      setKeyStored(key_stored);
      if (settings) setSearch({ kind: settings.config.kind, baseUrl: settings.config.base_url, enabled: settings.enabled, max: settings.config.max_results });
    }).catch(onError);
  }, [onError]);
  useEffect(load, [load]);
  if (!cloud) return <LoadingState/>;
  const saveLocal = () => platformApi.saveLocalModel(local.baseUrl, local.enabled, local.model || null, local.map);
  return (
    <div className="wf-run">
      <Panel title="Per-agent model selection">
        <p className="ws-form-help">Each specialist can use its own model. Empty fields use the provider default ({cloud.role_models.default_cloud ?? "openmindai-lite"} in the cloud, {local.model || "local"} locally). Model output is always an unverified hypothesis.</p>
        <div className="wf-table-wrap"><table className="wf-table">
          <thead><tr><th scope="col">Agent role</th><th scope="col">Cloud model</th><th scope="col">Local model</th></tr></thead>
          <tbody>{roles.map((r) => (
            <tr key={r.role}>
              <th scope="row">{r.display_name}</th>
              <td><input aria-label={`${r.display_name} cloud model`} value={cloudMap[r.role] ?? ""} placeholder="default" onChange={(e) => setCloudMap({ ...cloudMap, [r.role]: e.target.value })}/></td>
              <td><input aria-label={`${r.display_name} local model`} value={local.map[r.role] ?? ""} placeholder="default" onChange={(e) => setLocal({ ...local, map: { ...local.map, [r.role]: e.target.value } })}/></td>
            </tr>
          ))}</tbody>
        </table></div>
        <div className="ws-button-row">
          <button type="button" className="ws-button ws-button-primary" onClick={() => void Promise.all([
            platformApi.saveCloudRoleModels(cloud.base_url, cloud.enabled, cloud.role_models.default_cloud, cloudMap),
            ...(local.baseUrl ? [saveLocal()] : []),
          ]).then(() => { toast("Model routing saved"); load(); }).catch(onError)}>Save model routing</button>
        </div>
      </Panel>
      <Panel title="Local model (fallback and offline planning)">
        <div className="ws-form-stack">
          <p className="ws-form-help">An OpenAI-compatible server on this machine (for example llama.cpp or Ollama); it must listen on loopback. Workers fall back to it after a cloud outage only when the project consent allows local fallback. Offline projects can use it for AI planning.</p>
          <label className="ws-field"><span>Loopback base URL</span><input value={local.baseUrl} onChange={(e) => setLocal({ ...local, baseUrl: e.target.value })}/></label>
          <label className="ws-field"><span>Default local model</span><input value={local.model} onChange={(e) => setLocal({ ...local, model: e.target.value })} placeholder="e.g. qwen2.5-coder:7b"/></label>
          <label className="ws-check-field"><input type="checkbox" checked={local.enabled} onChange={(e) => setLocal({ ...local, enabled: e.target.checked })}/> Enable local model</label>
          <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" onClick={() => void saveLocal().then(() => toast("Local model saved")).catch(onError)}>Save local model</button></div>
        </div>
      </Panel>
      <Panel title="Web search provider">
        <div className="ws-form-stack">
          <p className="ws-form-help">Used only for search queries you type in the goal composer, and only for projects with web research enabled. Results are untrusted; each page is fetched by the SSRF-guarded retriever and cited with a content hash.</p>
          <label className="ws-field"><span>Provider</span>
            <select value={search.kind} onChange={(e) => {
              const kind = e.target.value as SearchProviderKind;
              setSearch({ ...search, kind, baseUrl: kind === "brave" ? "https://api.search.brave.com" : "https://" });
            }}>
              <option value="brave">Brave Search API</option>
              <option value="searxng">SearXNG (JSON output enabled)</option>
            </select>
          </label>
          <label className="ws-field"><span>HTTPS base URL</span><input value={search.baseUrl} onChange={(e) => setSearch({ ...search, baseUrl: e.target.value })}/></label>
          <label className="ws-field"><span>Results per query</span><input type="number" min={1} max={10} value={search.max} onChange={(e) => setSearch({ ...search, max: Number(e.target.value) })}/></label>
          <label className="ws-check-field"><input type="checkbox" checked={search.enabled} onChange={(e) => setSearch({ ...search, enabled: e.target.checked })}/> Enable search</label>
          <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.saveSearch(search.kind, search.baseUrl, search.enabled, search.max).then(() => toast("Search provider saved")).catch(onError)}>Save search provider</button></div>
          {search.kind === "brave" && <>
            <label className="ws-field"><span>API key {keyStored ? "(stored in the OS credential store)" : "(not set)"}</span>
              <input type="password" autoComplete="off" value={searchKey} onChange={(e) => setSearchKey(e.target.value)}/>
            </label>
            <div className="ws-button-row">
              <button type="button" className="ws-button ws-button-secondary" disabled={!searchKey} onClick={() => void platformApi.setSearchKey(searchKey).then(() => { setSearchKey(""); setKeyStored(true); toast("Search key stored"); }).catch(onError)}>Store key</button>
              {keyStored && <button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.clearSearchKey().then(() => setKeyStored(false)).catch(onError)}>Remove key</button>}
            </div>
          </>}
        </div>
      </Panel>
    </div>
  );
}

/** RBAC, invitations, audit trail and the loopback automation API. */
export function TeamTab({ projectId }: { projectId: string }) {
  const onError = useErrorToast();
  const toast = useToast();
  const [access, setAccess] = useState<AccessOverview | null>(null);
  const [audit, setAudit] = useState<AuditRecord[]>([]);
  const [api, setApi] = useState<ApiStatus | null>(null);
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [newMember, setNewMember] = useState({ id: "", name: "", role: "analyst" as Role });
  const [inviteRole, setInviteRole] = useState<Role>("viewer");
  const [secret, setSecret] = useState<{ label: string; value: string } | null>(null);
  const [tokenForm, setTokenForm] = useState({ label: "", scopes: ["runs:read", "reports:read"] as string[], ttl: 30 });
  const [port, setPort] = useState(8765);
  const [acceptCode, setAcceptCode] = useState("");
  const load = useCallback(() => {
    platformApi.access(projectId).then(setAccess).catch(onError);
    platformApi.auditLog(projectId).then(setAudit).catch(onError);
    platformApi.apiStatus().then(setApi).catch(onError);
    platformApi.listTokens(projectId).then(setTokens).catch(onError);
  }, [projectId, onError]);
  useEffect(load, [load]);
  if (!access || !api) return <LoadingState/>;
  const act = (p: Promise<unknown>, message?: string) => void p.then(() => { if (message) toast(message); load(); }).catch(onError);
  return (
    <div className="wf-run">
      {secret && (
        <Panel title={`${secret.label} — copy it now`} action={<button type="button" className="ws-button ws-button-secondary" onClick={() => setSecret(null)}>Done</button>}>
          <p className="ws-form-help">This value is shown once. CodeTwin stores only its SHA-256 verifier.</p>
          <code className="wf-secret">{secret.value}</code>
          <div className="ws-button-row"><button type="button" className="ws-button ws-button-secondary" onClick={() => void navigator.clipboard.writeText(secret.value)}>Copy</button></div>
        </Panel>
      )}
      <Panel title="Access control">
        <div className="ws-form-stack">
          <p className="ws-form-help">You are <code>{access.me}</code> ({access.my_role ?? "no role"}). With role enforcement off, the project behaves as a single-user workspace.</p>
          <label className="ws-check-field"><input type="checkbox" checked={access.policy.enforce_rbac} onChange={(e) => act(platformApi.setPolicy(projectId, e.target.checked, access.policy.separation_of_duties), "Access policy updated")}/> Enforce roles (viewer, analyst, approver, administrator)</label>
          <label className="ws-check-field"><input type="checkbox" checked={access.policy.separation_of_duties} onChange={(e) => act(platformApi.setPolicy(projectId, access.policy.enforce_rbac, e.target.checked), "Access policy updated")}/> Separation of duties: a run's creator cannot approve it</label>
        </div>
        <h3 className="wf-subhead">Members</h3>
        {access.members.length === 0 ? <p className="ws-form-help">No explicit members yet.</p> : (
          <div className="wf-table-wrap"><table className="wf-table">
            <thead><tr><th scope="col">Member</th><th scope="col">Role</th><th scope="col">Granted</th><th scope="col">Actions</th></tr></thead>
            <tbody>{access.members.map((m) => (
              <tr key={m.principal_id}>
                <th scope="row">{m.display_name}<br/><small><code>{m.principal_id}</code></small></th>
                <td><select aria-label={`Role of ${m.display_name}`} value={m.role} onChange={(e) => act(platformApi.grantRole(projectId, m.principal_id, e.target.value as Role, m.revision), "Role updated")}>
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select></td>
                <td><small>{m.granted_by} · {time(m.granted_ms)}</small></td>
                <td><button type="button" className="ws-button ws-button-secondary" onClick={() => act(platformApi.revokeRole(projectId, m.principal_id), "Member removed")}>Remove</button></td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
        <div className="wf-inline-form">
          <input aria-label="User id" placeholder="user id (e.g. alice)" value={newMember.id} onChange={(e) => setNewMember({ ...newMember, id: e.target.value })}/>
          <input aria-label="Display name" placeholder="display name" value={newMember.name} onChange={(e) => setNewMember({ ...newMember, name: e.target.value })}/>
          <select aria-label="New member role" value={newMember.role} onChange={(e) => setNewMember({ ...newMember, role: e.target.value as Role })}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select>
          <button type="button" className="ws-button ws-button-secondary" disabled={!newMember.id.trim()} onClick={() => act(
            platformApi.registerPrincipal(newMember.id.trim(), newMember.name.trim() || newMember.id.trim())
              .then((p) => platformApi.grantRole(projectId, p.id, newMember.role, null))
              .then(() => setNewMember({ id: "", name: "", role: "analyst" })), "Member added")}>Add member</button>
        </div>
        <h3 className="wf-subhead">Invitations</h3>
        <div className="wf-inline-form">
          <select aria-label="Invitation role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as Role)}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select>
          <button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.invite(projectId, inviteRole, 72).then(({ code }) => { setSecret({ label: `Invitation code (${inviteRole}, 72 h)`, value: code }); load(); }).catch(onError)}>Create invitation</button>
          <input aria-label="Invitation code to accept" placeholder="accept a code…" value={acceptCode} onChange={(e) => setAcceptCode(e.target.value)}/>
          <button type="button" className="ws-button ws-button-secondary" disabled={!acceptCode.trim()} onClick={() => act(platformApi.acceptInvitation(acceptCode.trim()).then(() => setAcceptCode("")), "Invitation accepted")}>Accept</button>
        </div>
        {access.invitations.length > 0 && <ul className="wf-tools">{access.invitations.map((i) => (
          <li key={i.id}><StatusBadge status={i.accepted_by ? "completed" : i.revoked_ms ? "cancelled" : i.expires_ms < Date.now() ? "failed" : "queued"}/> {i.role} <small>by {i.invited_by} · expires {time(i.expires_ms)}{i.accepted_by ? ` · accepted by ${i.accepted_by}` : ""}</small>
            {!i.accepted_by && !i.revoked_ms && <button type="button" className="ws-button ws-button-secondary" onClick={() => act(platformApi.revokeInvitation(i.id), "Invitation revoked")}>Revoke</button>}</li>
        ))}</ul>}
      </Panel>
      <Panel title="Automation API (loopback only)">
        <div className="ws-form-stack">
          <p className="ws-form-help">A REST API on 127.0.0.1 for scripts and CI on this machine. Browser requests are refused, every call needs a scoped project token, and approvals can only be given here in the desktop.</p>
          <p>{api.running ? <>Running at <code>{api.address}</code></> : "Stopped"}</p>
          <div className="wf-inline-form">
            {!api.running && <input type="number" aria-label="API port" min={1024} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))}/>}
            <button type="button" className="ws-button ws-button-secondary" onClick={() => void (api.running ? platformApi.stopApi() : platformApi.startApi(port)).then(setApi).catch(onError)}>{api.running ? "Stop API" : "Start API"}</button>
          </div>
          {api.running && <pre className="wf-report">{`curl -H "Authorization: Bearer <token>" ${api.address}/v1/runs
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \\
  -d '{"goal":"Review input validation"}' ${api.address}/v1/runs
GET /v1/runs/{id} · /v1/runs/{id}/events?cursor=0 · /v1/runs/{id}/report?format=markdown
POST /v1/runs/{id}/cancel · GET /v1/analytics?days=7 · GET /v1/metrics`}</pre>}
        </div>
        <h3 className="wf-subhead">Project tokens</h3>
        <div className="wf-inline-form">
          <input aria-label="Token label" placeholder="label (e.g. CI pipeline)" value={tokenForm.label} onChange={(e) => setTokenForm({ ...tokenForm, label: e.target.value })}/>
          {API_SCOPES.map((scope) => (
            <label key={scope} className="ws-check-field"><input type="checkbox" checked={tokenForm.scopes.includes(scope)} onChange={(e) => setTokenForm({ ...tokenForm, scopes: e.target.checked ? [...tokenForm.scopes, scope] : tokenForm.scopes.filter((s) => s !== scope) })}/> {scope}</label>
          ))}
          <input type="number" aria-label="Token lifetime in days" min={1} max={365} value={tokenForm.ttl} onChange={(e) => setTokenForm({ ...tokenForm, ttl: Number(e.target.value) })}/>
          <button type="button" className="ws-button ws-button-secondary" disabled={!tokenForm.label.trim() || tokenForm.scopes.length === 0} onClick={() => void platformApi.createToken(projectId, tokenForm.label.trim(), tokenForm.scopes, tokenForm.ttl)
            .then(({ plaintext, token }) => { setSecret({ label: `API token "${token.label}"`, value: plaintext }); setTokenForm({ ...tokenForm, label: "" }); load(); }).catch(onError)}>Create token</button>
        </div>
        {tokens.length > 0 && <ul className="wf-tools">{tokens.map((t) => (
          <li key={t.id}><StatusBadge status={t.revoked ? "cancelled" : t.expires_ms < Date.now() ? "failed" : "completed"}/> <strong>{t.label}</strong> <small>{t.scopes.join(", ")} · expires {time(t.expires_ms)} · last used {time(t.last_used_ms)}</small>
            {!t.revoked && <button type="button" className="ws-button ws-button-secondary" onClick={() => act(platformApi.revokeToken(t.id), "Token revoked")}>Revoke</button>}</li>
        ))}</ul>}
      </Panel>
      <Panel title="Audit trail">
        {audit.length === 0 ? <p className="ws-form-help">No audited actions yet.</p> : (
          <ol className="wf-timeline">{audit.map((a) => (
            <li key={a.seq}><small>{time(a.created_ms)}</small> <StatusBadge status={a.outcome === "allowed" ? "completed" : a.outcome === "denied" ? "blocked" : "failed"}/> <strong>{a.action.replaceAll("_", " ")}</strong> <span>{a.actor}{a.target ? ` → ${a.target}` : ""}</span></li>
          ))}</ol>
        )}
      </Panel>
    </div>
  );
}

function CommentThread({ projectId, runId }: { projectId: string; runId: string }) {
  const onError = useErrorToast();
  const [comments, setComments] = useState<Comment[]>([]);
  const [body, setBody] = useState("");
  const [replyTo, setReplyTo] = useState<string | null>(null);
  const load = useCallback(() => platformApi.comments(projectId, "run", runId).then(setComments).catch(onError), [projectId, runId, onError]);
  useEffect(() => { void load(); }, [load]);
  const render = (c: Comment) => (
    <li key={c.id}>
      <small>{c.author} · {time(c.created_ms)}{c.edited_ms ? " · edited" : ""}</small>
      <p>{c.deleted ? <em>deleted</em> : c.body}</p>
      {!c.deleted && <div className="ws-button-row">
        <button type="button" className="ws-button ws-button-secondary" onClick={() => setReplyTo(c.id)}>Reply</button>
        <button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.deleteComment(c.id).then(load).catch(onError)}>Delete</button>
      </div>}
      <ul className="wf-comments wf-replies">{comments.filter((r) => r.parent_id === c.id).map(render)}</ul>
    </li>
  );
  return (
    <Panel title={`Review thread (${comments.filter((c) => !c.deleted).length})`}>
      <ul className="wf-comments">{comments.filter((c) => !c.parent_id).map(render)}</ul>
      <div className="ws-form-stack">
        <label className="ws-field"><span>{replyTo ? "Reply" : "Comment"}</span><textarea rows={2} maxLength={4000} value={body} onChange={(e) => setBody(e.target.value)}/></label>
        <div className="ws-button-row">
          <button type="button" className="ws-button ws-button-primary" disabled={!body.trim()} onClick={() => void platformApi.addComment(projectId, "run", runId, replyTo, body).then(() => { setBody(""); setReplyTo(null); void load(); }).catch(onError)}>Post</button>
          {replyTo && <button type="button" className="ws-button ws-button-secondary" onClick={() => setReplyTo(null)}>Cancel reply</button>}
        </div>
      </div>
    </Panel>
  );
}

/** Plan provenance, agent conversation, citations, PDF and review thread for one run. */
export function RunExtras({ projectId, detail, plan, settled }: { projectId: string; detail: RunDetail; plan: PlanInfo | null; settled: boolean }) {
  const onError = useErrorToast();
  const [citations, setCitations] = useState<Citation[] | null>(null);
  const runId = detail.run.id;
  useEffect(() => { setCitations(null); }, [runId]);
  const conversation = agentConversation(detail.tasks);
  const roleOf = new Map(detail.tasks.map((t) => [t.id, t.role]));
  return (
    <>
      {plan && (
        <Panel title="Plan provenance">
          {plan.source.kind === "model"
            ? <p>AI-decomposed by <code>{plan.source.model}</code> via {plan.source.route}{plan.source.fallback_reason ? ` (local fallback after: ${plan.source.fallback_reason})` : ""}. Validated by deterministic policy; verification, report and review were added by CodeTwin.</p>
            : <p>Deterministic template plan — {plan.source.reason}.</p>}
          {plan.rationale && <p className="ws-form-help">Model rationale (unverified): {plan.rationale}</p>}
          {plan.rejected.length > 0 && <ul className="wf-tools">{plan.rejected.map((r) => <li key={r}><StatusBadge status="blocked"/> {r}</li>)}</ul>}
          {(plan.attempts ?? []).length > 0 && (
            <div className="wf-table-wrap"><table className="wf-table" aria-label="Planner model calls">
              <thead><tr><th scope="col">#</th><th scope="col">Mode</th><th scope="col">Output budget</th><th scope="col">Finish</th><th scope="col">Completion tokens</th><th scope="col">Outcome</th></tr></thead>
              <tbody>{plan.attempts.map((a) => (
                <tr key={a.attempt}>
                  <td>{a.attempt}</td>
                  <td>{a.mode === "tool" ? "structured call" : "JSON text"}</td>
                  <td>{a.max_tokens.toLocaleString()}</td>
                  <td>{a.finish_reason ?? "—"}</td>
                  <td>{a.completion_tokens?.toLocaleString() ?? "—"}</td>
                  <td>{a.outcome}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </Panel>
      )}
      <Panel title={`Agent conversation (${conversation.length})`}>
        {conversation.length === 0 ? <p className="ws-form-help">Agents have not reported yet.</p> : (
          <ol className="wf-conversation">{conversation.map((m) => (
            <li key={m.taskId}>
              <header><strong>{m.role.replaceAll("_", " ")}</strong> <small>{m.title}{m.evidenceClass ? ` · ${m.evidenceClass.replace("_", " ")}` : ""} · {time(m.at)}</small></header>
              {m.inReplyTo.length > 0 && <small className="wf-role">after {m.inReplyTo.map((id) => roleOf.get(id) ?? id).join(", ")}</small>}
              <p>{m.text}</p>
            </li>
          ))}</ol>
        )}
      </Panel>
      {settled && (
        <Panel title="Exports and sources" action={<div className="ws-button-row">
          <button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.reportPdf(runId).then((r) => downloadPdf(r.base64, `codetwin-${runId}.pdf`)).catch(onError)}>Download PDF report</button>
          <button type="button" className="ws-button ws-button-secondary" onClick={() => void platformApi.citations(runId).then(setCitations).catch(onError)}>Show citations</button>
        </div>}>
          {citations === null ? <p className="ws-form-help">The PDF embeds the SHA-256 of the stored Markdown report so it can be matched to it.</p> :
            citations.length === 0 ? <p className="ws-form-help">This run retrieved no research sources.</p> : (
              <ul className="wf-tools">{citations.map((c) => (
                <li key={c.id}><StatusBadge status={c.support === "supported" ? "completed" : "blocked"}/> <strong>{c.claim}</strong> — {c.support}
                  {c.quote && <blockquote>{c.quote}</blockquote>}
                  <small>{c.title ?? c.url} · sha256 {c.sha256?.slice(0, 12)} · {time(c.fetched_ms)}</small></li>
              ))}</ul>
            )}
        </Panel>
      )}
      <CommentThread projectId={projectId} runId={runId}/>
    </>
  );
}
