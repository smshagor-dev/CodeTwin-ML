import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type { LanguageServerConfig, LanguageServerKind } from "../types";
import { PageHeader, Panel, StatusBadge } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

type Draft = { executable_path: string; arguments: string; enabled: boolean };

const labels: Record<LanguageServerKind, string> = {
  typescript: "TypeScript / JavaScript",
  pyright: "Python / Pyright",
  rust_analyzer: "Rust Analyzer",
};

const kinds: LanguageServerKind[] = ["typescript", "pyright", "rust_analyzer"];

function blankDraft(): Draft {
  return { executable_path: "", arguments: "", enabled: true };
}

export function IntegrationsPage() {
  const { setToast } = useWorkspace();
  const [configs, setConfigs] = useState<LanguageServerConfig[]>([]);
  const [drafts, setDrafts] = useState<Record<LanguageServerKind, Draft>>({
    typescript: blankDraft(),
    pyright: blankDraft(),
    rust_analyzer: blankDraft(),
  });
  const [busy, setBusy] = useState<LanguageServerKind | null>(null);

  async function load() {
    try {
      const next = await workspaceApi.languageServers();
      setConfigs(next);
      const updated: Record<LanguageServerKind, Draft> = {
        typescript: blankDraft(),
        pyright: blankDraft(),
        rust_analyzer: blankDraft(),
      };
      for (const config of next) {
        updated[config.kind] = {
          executable_path: config.executable_path,
          arguments: config.arguments.join("\n"),
          enabled: config.enabled,
        };
      }
      setDrafts(updated);
    } catch (error) {
      setToast({ tone: "error", message: "Could not load integrations: " + String(error) });
    }
  }

  useEffect(() => { void load(); }, []);

  const configured = useMemo(() => new Set(configs.map((item) => item.kind)), [configs]);

  function patch(kind: LanguageServerKind, next: Partial<Draft>) {
    setDrafts((current) => ({ ...current, [kind]: { ...current[kind], ...next } }));
  }

  async function save(kind: LanguageServerKind) {
    const draft = drafts[kind];
    if (!draft.executable_path.trim()) {
      setToast({ tone: "error", message: "Enter an absolute executable path for " + labels[kind] + "." });
      return;
    }
    setBusy(kind);
    try {
      await workspaceApi.saveLanguageServer({
        kind,
        executable_path: draft.executable_path.trim(),
        arguments: draft.arguments.split("\n").map((value) => value.trim()).filter(Boolean),
        initialization_options: null,
        enabled: draft.enabled,
      });
      await load();
      setToast({ tone: "success", message: labels[kind] + " integration saved." });
    } catch (error) {
      setToast({ tone: "error", message: "Could not save integration: " + String(error) });
    } finally {
      setBusy(null);
    }
  }

  async function remove(kind: LanguageServerKind) {
    setBusy(kind);
    try {
      await workspaceApi.removeLanguageServer(kind);
      await load();
      setToast({ tone: "success", message: labels[kind] + " integration removed." });
    } catch (error) {
      setToast({ tone: "error", message: "Could not remove integration: " + String(error) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="SUPPORTED INTEGRATIONS"
        title="Integrations"
        description="Manage the language-server integrations that CodeTwin already supports for optional semantic enrichment. Nothing is connected implicitly."
      />
      <div className="ws-integration-grid">
        {kinds.map((kind) => {
          const draft = drafts[kind];
          const isConfigured = configured.has(kind);
          return (
            <Panel key={kind} title={labels[kind]} action={<StatusBadge status={isConfigured ? (draft.enabled ? "configured" : "disabled") : "not_configured"}/>}>
              <div className="ws-form-stack">
                <label className="ws-field"><span>Executable path</span><input value={draft.executable_path} placeholder={kind === "typescript" ? "Absolute path to language server executable" : "Absolute executable path"} onChange={(event) => patch(kind, { executable_path: event.target.value })}/></label>
                <label className="ws-field"><span>Arguments <small>one per line</small></span><textarea rows={4} value={draft.arguments} onChange={(event) => patch(kind, { arguments: event.target.value })}/></label>
                <label className="ws-check-field"><input type="checkbox" checked={draft.enabled} onChange={(event) => patch(kind, { enabled: event.target.checked })}/><span>Enable this integration when semantic enrichment is explicitly requested.</span></label>
                <div className="ws-button-row">
                  <button className="ws-button ws-button-primary" onClick={() => void save(kind)} disabled={busy !== null}><Icon name="check"/>{busy === kind ? "Saving…" : "Save"}</button>
                  {isConfigured && <button className="ws-button ws-button-danger-ghost" onClick={() => void remove(kind)} disabled={busy !== null}><Icon name="trash"/>Remove</button>}
                </div>
              </div>
            </Panel>
          );
        })}
      </div>
      <div className="ws-safe-note"><Icon name="security"/><p><strong>Execution boundary</strong><span>Configuring an executable does not run it. Semantic enrichment remains an explicit action in the engineering workspace.</span></p></div>
    </div>
  );
}
