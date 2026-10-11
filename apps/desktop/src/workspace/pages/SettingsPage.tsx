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
        description="Manage your local profile, theme and import preferences."
        actions={<button className="ws-button ws-button-primary" onClick={() => void save()} disabled={saving}><Icon name="check"/>{saving ? "Saving…" : "Save Settings"}</button>}
      />
      <Panel title="Workspace preferences" className="ws-preferences-panel">
        <div className="ws-preference-row">
          <div><h3>Profile</h3><p>Used only in this local workspace.</p></div>
          <label className="ws-field"><span>Local display name</span><input value={draft.display_name} maxLength={80} onChange={(event) => patch({ display_name: event.target.value })}/></label>
        </div>
        <div className="ws-preference-row">
          <div><h3>Appearance</h3><p>Restored when you reopen CodeTwin.</p></div>
          <label className="ws-field"><span>Theme</span><select value={draft.theme} onChange={(event) => patch({ theme: event.target.value as AppPreferences["theme"] })}><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
        </div>
        <div className="ws-preference-row">
          <div><h3>On project import</h3><p>Static analysis and discovery only.</p></div>
          <div className="ws-form-stack">
            <label className="ws-check-field"><input type="checkbox" checked={draft.auto_run_security_on_import} onChange={(event) => patch({ auto_run_security_on_import: event.target.checked })}/><span><strong>Run static security analysis</strong><small>Does not test registered websites.</small></span></label>
            <label className="ws-check-field"><input type="checkbox" checked={draft.auto_discover_tests_on_import} onChange={(event) => patch({ auto_discover_tests_on_import: event.target.checked })}/><span><strong>Discover tests and configs</strong><small>Does not execute repository tests.</small></span></label>
          </div>
        </div>
      </Panel>
    </div>
  );
}
