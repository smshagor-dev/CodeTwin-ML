import { useCallback, useEffect, useState } from "react";

import { workspaceApi } from "../api";
import { PageHeader, Panel } from "../ui";

type Provider = { name: string; kind: string };
type Connection = { configured: boolean; connected: boolean; detail: string; providers: Provider[] };
type Flow = {
  id: string; title: string; status: string; provider: Provider;
  created_at: string; updated_at: string;
};
type Task = {
  id: string; title: string; status: string; result: string;
  subtasks: { id: string; title: string; status: string; result: string }[];
};
type AgentLog = { id: string; executor: string; task: string; result: string; createdAt: string };
type ToolLog = { id: string; name: string; status: string; result: string; createdAt: string };
type Detail = { tasks: Task[]; agents: AgentLog[]; tools: ToolLog[] };

export function PentagiAgentsPage() {
  const [connection, setConnection] = useState<Connection | null>(null);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [detail, setDetail] = useState<Detail | null>(null);
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("");
  const [provider, setProvider] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    const status = await workspaceApi.pentagiStatus();
    setConnection(status);
    if (!status.connected) {
      setFlows([]);
      return;
    }
    const next = await workspaceApi.pentagiFlows();
    setFlows(next);
    setProvider(current => status.providers.some(item => item.name === current)
      ? current : status.providers[0]?.name ?? "");
  }, []);

  useEffect(() => {
    void refresh().catch(reason => setError(String(reason)));
    const interval = window.setInterval(() => {
      void refresh().catch(reason => setError(String(reason)));
    }, 12000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  useEffect(() => {
    if (!selectedId || !connection?.connected) {
      setDetail(null);
      return;
    }
    let active = true;
    const load = () => void workspaceApi.pentagiFlowDetail(selectedId)
      .then(value => { if (active) setDetail(value); })
      .catch(reason => { if (active) setError(String(reason)); });
    load();
    const interval = window.setInterval(load, 12000);
    return () => { active = false; window.clearInterval(interval); };
  }, [selectedId, connection?.connected]);

  async function createFlow() {
    setBusy(true); setError("");
    try {
      const flow = await workspaceApi.pentagiCreateFlow({ target, objective, provider, authorized });
      setSelectedId(flow.id);
      setTarget(""); setObjective(""); setAuthorized(false);
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function stopFlow(flowId: string) {
    if (!window.confirm("Stop this PentAGI flow? Already executed operations cannot be undone.")) return;
    setBusy(true); setError("");
    try {
      const stopped = await workspaceApi.pentagiStopFlow(flowId);
      if (!stopped) throw new Error("PentAGI did not confirm that the flow stopped.");
      await refresh();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  const selected = flows.find(flow => flow.id === selectedId);
  const ready = Boolean(connection?.connected && provider && target.trim() && objective.trim() && authorized && !busy);

  return <div>
    <PageHeader
      eyebrow="AUTONOMOUS SECURITY TESTING"
      title="PentAGI Agents"
      description="CodeTwin connects to the original PentAGI Go engine through the Rust backend. Autonomous execution occurs in PentAGI's own isolated environment."
      actions={<button className="ws-button ws-button-secondary" onClick={() => void refresh().catch(reason => setError(String(reason)))}>Refresh</button>}
    />
    <Panel title="Go engine connection">
      <p role="status"><strong>{connection?.connected ? "Connected" : "Not connected"}</strong> · {connection?.detail ?? "Checking connection…"}</p>
      <p className="ws-form-help">Configure CODETWIN_PENTAGI_URL and CODETWIN_PENTAGI_TOKEN in the desktop process environment. Tokens stay in the Rust process and are not sent to the WebView. See docs/integrations/PENTAGI.md.</p>
      {error && <p className="ws-warning-box" role="alert">{error}</p>}
    </Panel>
    <Panel title="Start an authorized security assessment">
      <div className="ws-form-stack">
        <label className="ws-field"><span>Approved target URL</span>
          <input type="url" value={target} onChange={event => setTarget(event.target.value)} placeholder="http://localhost:3000" maxLength={2048}/>
        </label>
        <label className="ws-field"><span>Objective and allowed testing scope</span>
          <textarea rows={4} value={objective} onChange={event => setObjective(event.target.value)} maxLength={2000} placeholder="Review authentication and configuration of my staging application. Do not change user data."/>
        </label>
        <label className="ws-field"><span>PentAGI model provider</span>
          <select value={provider} onChange={event => setProvider(event.target.value)}>
            <option value="">Select a configured provider</option>
            {connection?.providers.map(value => <option key={value.name} value={value.name}>{value.name} ({value.kind})</option>)}
          </select>
        </label>
        <label className="ws-field">
          <span><input type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked}/> I own this target or have explicit written authorization to test it and have checked the agreed scope.</span>
        </label>
        <p className="ws-form-help">PentAGI must also enforce scope and network restrictions server-side. An AI instruction alone cannot prevent out-of-scope tool calls. Review the PentAGI configuration before starting.</p>
        <button className="ws-button ws-button-primary" disabled={!ready} onClick={() => void createFlow()}>{busy ? "Working…" : "Start PentAGI Flow"}</button>
      </div>
    </Panel>
    <Panel title="Execution history">
      {!flows.length && <p className="ws-inline-empty">{connection?.connected ? "No PentAGI flows have been created." : "Connect PentAGI to view execution history."}</p>}
      <div className="ws-history-list">
        {flows.map(flow => <div key={flow.id}>
          <button className="ws-button ws-button-secondary" aria-pressed={selectedId === flow.id} onClick={() => setSelectedId(flow.id)}>
            {flow.title} · {flow.status} · {flow.provider.name}
          </button>
          {["created", "running", "waiting"].includes(flow.status) &&
            <button disabled={busy} className="ws-button ws-button-secondary" onClick={() => void stopFlow(flow.id)}>Stop</button>}
        </div>)}
      </div>
    </Panel>
    {selected && <Panel title={"Flow: " + selected.title}>
      <p><strong>Status:</strong> {selected.status} · <strong>Provider:</strong> {selected.provider.name}</p>
      {!detail && <p>Loading task and execution records…</p>}
      {detail && <>
        <h3>Tasks ({detail.tasks.length})</h3>
        {!detail.tasks.length && <p>No tasks reported yet.</p>}
        {detail.tasks.map(task => <details key={task.id}>
          <summary>{task.status}: {task.title} ({task.subtasks.length} subtasks)</summary>
          <pre className="ws-diagnostics">{task.result || "No task result yet"}</pre>
          {task.subtasks.map(subtask => <details key={subtask.id}>
            <summary>{subtask.status}: {subtask.title}</summary>
            <pre className="ws-diagnostics">{subtask.result || "Pending"}</pre>
          </details>)}
        </details>)}
        <h3>Agent activity ({detail.agents.length} most recent)</h3>
        {detail.agents.map(log => <details key={log.id}>
          <summary>{log.executor}: {log.task.slice(0, 140)}</summary>
          <pre className="ws-diagnostics">{log.result}</pre>
        </details>)}
        <h3>Tool executions ({detail.tools.length} most recent)</h3>
        {detail.tools.map(log => <details key={log.id}>
          <summary>{log.status}: {log.name}</summary>
          <pre className="ws-diagnostics">{log.result}</pre>
        </details>)}
      </>}
    </Panel>}
  </div>;
}
