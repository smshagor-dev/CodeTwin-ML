import { useEffect, useState } from "react";

import { Icon } from "../Icon";
import type { AppPreferences } from "../types";
import { PageHeader, Panel } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function SettingsPage() {
  const { preferences, savePreferences } = useWorkspace();
  const [draft, setDraft] = useState<AppPreferences>(preferences);
  const [saving, setSaving] = useState(false);

  useEffect(() => setDraft(preferences), [preferences]);

  function patch(next: Partial<AppPreferences>) {
    setDraft((current) => ({ ...current, ...next }));
  }

  async function save() {
    setSaving(true);
    try {
      await savePreferences(draft);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="LOCAL PREFERENCES"
        title="Settings"
        description="These preferences are persisted in CodeTwin's application SQLite database and have direct effects on the desktop workspace."
        actions={<button className="ws-button ws-button-primary" onClick={() => void save()} disabled={saving}><Icon name="check"/>{saving ? "Saving…" : "Save Settings"}</button>}
      />
      <div className="ws-settings-grid">
        <Panel title="General">
          <label className="ws-field"><span>Local display name</span><input value={draft.display_name} maxLength={80} onChange={(event) => patch({ display_name: event.target.value })}/><small>Shown in the local profile controls. CodeTwin does not claim this is an authenticated identity.</small></label>
        </Panel>
        <Panel title="Appearance">
          <label className="ws-field"><span>Theme</span><select value={draft.theme} onChange={(event) => patch({ theme: event.target.value as AppPreferences["theme"] })}><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select><small>Applied immediately after saving and restored on next launch.</small></label>
        </Panel>
        <Panel title="Project & security automation">
          <div className="ws-form-stack">
            <label className="ws-check-field"><input type="checkbox" checked={draft.auto_run_security_on_import} onChange={(event) => patch({ auto_run_security_on_import: event.target.checked })}/><span><strong>Run static security analysis after project import</strong><small>Uses the existing source analyzer only. It never performs intrusive website testing.</small></span></label>
            <label className="ws-check-field"><input type="checkbox" checked={draft.auto_discover_tests_on_import} onChange={(event) => patch({ auto_discover_tests_on_import: event.target.checked })}/><span><strong>Discover QA evidence after project import</strong><small>Inventories tests and configs; it does not execute repository tests.</small></span></label>
          </div>
        </Panel>
        <Panel title="Agent preferences">
          <div className="ws-disabled-setting"><Icon name="agents"/><div><strong>Autonomous agent runtime is not implemented</strong><p>No agent scheduling preference is stored because there is currently no runtime for it to affect.</p></div></div>
        </Panel>
      </div>
    </div>
  );
}
