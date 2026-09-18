import { useEffect, useMemo, useState } from "react";

import { Icon } from "../Icon";
import type { WebsiteRecord } from "../types";
import { ConfirmDialog, EmptyState, PageHeader, Panel, StatusBadge, formatDate, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function WebsitesPage() {
  const {
    websites,
    setWebsiteComposerOpen,
    checkWebsite,
    removeWebsite,
    setToast,
  } = useWorkspace();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const requestedWebsite = new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("website");
  const [selectedId, setSelectedId] = useState<string | null>(
    requestedWebsite && websites.some((website) => website.id === requestedWebsite)
      ? requestedWebsite
      : websites[0]?.id ?? null,
  );
  useEffect(() => {
    const syncSelection = () => {
      const requested = new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("website");
      if (requested && websites.some((website) => website.id === requested)) setSelectedId(requested);
    };
    syncSelection();
    window.addEventListener("hashchange", syncSelection);
    return () => window.removeEventListener("hashchange", syncSelection);
  }, [websites]);

  const [checkingId, setCheckingId] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<WebsiteRecord | null>(null);
  const [removing, setRemoving] = useState(false);

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return websites.filter((website) => {
      const matchesSearch = !normalized || website.display_name.toLowerCase().includes(normalized) || website.url.toLowerCase().includes(normalized);
      const matchesStatus = status === "all" || website.status === status;
      return matchesSearch && matchesStatus;
    });
  }, [query, status, websites]);

  const selected = websites.find((website) => website.id === selectedId) ?? null;

  async function runCheck(website: WebsiteRecord) {
    setCheckingId(website.id);
    try {
      await checkWebsite(website);
    } catch {
      // Context reports the actionable error.
    } finally {
      setCheckingId(null);
    }
  }

  async function confirmRemove() {
    if (!removeTarget) return;
    setRemoving(true);
    try {
      await removeWebsite(removeTarget);
      if (selectedId === removeTarget.id) setSelectedId(null);
      setRemoveTarget(null);
    } catch (error) {
      setToast({ tone: "error", message: "Could not remove website: " + String(error) });
    } finally {
      setRemoving(false);
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="REGISTERED ENDPOINTS"
        title="Websites"
        description="Website registration and availability checks are separate from security scanning. Adding a URL never launches an intrusive scan."
        actions={<button className="ws-button ws-button-primary" onClick={() => setWebsiteComposerOpen(true)}><Icon name="plus"/>Add Website Link</button>}
      />

      {!websites.length ? (
        <EmptyState
          icon="websites"
          title="No websites registered"
          description="Register an HTTP or HTTPS URL. CodeTwin stores it locally and only checks availability when you explicitly request a check."
          action={<button className="ws-button ws-button-primary" onClick={() => setWebsiteComposerOpen(true)}><Icon name="plus"/>Add Website Link</button>}
        />
      ) : (
        <div className="ws-split-layout">
          <Panel title="Website list" action={<span className="ws-count">{visible.length} websites</span>}>
            <div className="ws-filter-row">
              <label className="ws-search-field"><Icon name="search" size={18}/><input aria-label="Search websites" placeholder="Search name or URL…" value={query} onChange={(event) => setQuery(event.target.value)}/></label>
              <select aria-label="Filter website status" value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="all">All status</option>
                <option value="not_checked">Not checked</option>
                <option value="online">Online</option>
                <option value="degraded">Degraded</option>
                <option value="offline">Offline</option>
              </select>
            </div>
            <div className="ws-list-stack">
              {visible.map((website) => (
                <button key={website.id} className={"ws-website-row " + (selected?.id === website.id ? "selected" : "")} onClick={() => setSelectedId(website.id)}>
                  <span className="ws-project-icon"><Icon name="websites"/></span>
                  <span className="ws-list-main"><strong>{website.display_name}</strong><small title={website.url}>{shortPath(website.url, 62)}</small><em>{website.project_name ? "Project: " + website.project_name : "No associated project"}</em></span>
                  <StatusBadge status={website.status}/>
                </button>
              ))}
              {!visible.length && <p className="ws-inline-empty">No websites match the current filters.</p>}
            </div>
          </Panel>

          <Panel title={selected ? selected.display_name : "Website details"} className="ws-detail-panel">
            {!selected ? <p className="ws-inline-empty">Select a website to inspect its status.</p> : (
              <>
                <dl className="ws-detail-grid">
                  <dt>URL</dt><dd className="ws-mono">{selected.url}</dd>
                  <dt>Status</dt><dd><StatusBadge status={selected.status}/>{selected.http_status ? <span className="ws-http-code">HTTP {selected.http_status}</span> : null}</dd>
                  <dt>Last checked</dt><dd>{formatDate(selected.last_checked_at)}</dd>
                  <dt>Project</dt><dd>{selected.project_name ?? "Not associated"}</dd>
                  <dt>Registered</dt><dd>{formatDate(selected.created_at)}</dd>
                  <dt>Last error</dt><dd>{selected.last_error ?? "None"}</dd>
                </dl>
                <div className="ws-safe-note"><Icon name="security"/><p><strong>Safety boundary</strong><span>Availability check performs a bounded HTTP request only. Security analysis remains an explicit project workflow.</span></p></div>
                <div className="ws-button-row">
                  <button className="ws-button ws-button-primary" onClick={() => void runCheck(selected)} disabled={checkingId === selected.id}><Icon name="refresh"/>{checkingId === selected.id ? "Checking…" : "Refresh Check"}</button>
                  <button className="ws-button ws-button-secondary" onClick={() => void navigator.clipboard.writeText(selected.url).then(() => setToast({ tone: "success", message: "URL copied." })).catch((error) => setToast({ tone: "error", message: "Could not copy URL: " + String(error) }))}>Copy URL</button>
                  <button className="ws-button ws-button-danger-ghost" onClick={() => setRemoveTarget(selected)}><Icon name="trash"/>Remove</button>
                </div>
              </>
            )}
          </Panel>
        </div>
      )}

      <ConfirmDialog
        open={removeTarget !== null}
        title="Remove website?"
        description={removeTarget ? "Remove " + removeTarget.display_name + " from the local CodeTwin website list?" : ""}
        busy={removing}
        onClose={() => setRemoveTarget(null)}
        onConfirm={() => void confirmRemove()}
      />
    </div>
  );
}
