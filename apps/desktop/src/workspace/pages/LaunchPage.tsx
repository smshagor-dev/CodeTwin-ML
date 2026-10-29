import { useState } from "react";

import { Icon, type IconName } from "../Icon";
import { navigate } from "../routes";
import { GUIDED_AUTHORIZATION_STATEMENT } from "../security/guidedSecurityModel";
import type { WebsiteRecord } from "../types";
import { formatDate, LoadingState, Modal } from "../ui";
import { useWorkspace } from "../WorkspaceContext";
import "../launch.css";

const WEB_AUTH_KEY = "codetwin.webauth.";
function isWebAuthorized(id: string): boolean {
  try { return window.localStorage.getItem(WEB_AUTH_KEY + id) === "1"; } catch { return false; }
}
function rememberWebAuth(id: string) {
  try { window.localStorage.setItem(WEB_AUTH_KEY + id, "1"); } catch { /* storage unavailable */ }
}

export type TargetMode = "local" | "web";

const MODE_KEY = "codetwin.targetMode";

/** Remember the operator's last chosen entry mode so the workspace can bias toward it. */
export function readTargetMode(): TargetMode | null {
  try {
    const value = window.localStorage.getItem(MODE_KEY);
    return value === "local" || value === "web" ? value : null;
  } catch {
    return null;
  }
}

function writeTargetMode(mode: TargetMode) {
  try { window.localStorage.setItem(MODE_KEY, mode); } catch { /* storage unavailable */ }
}

// Web scans stream in the same unified workspace terminal as local scans, not on a
// separate Security page. Setting this makes the workspace open in Web mode, where it
// auto-selects the newest guided session (ordered created_at DESC) and streams it.
const WORKSPACE_SOURCE_KEY = "codetwin.workspace.sourceWeb";
function openWorkspaceInWebMode() {
  try { window.localStorage.setItem(WORKSPACE_SOURCE_KEY, "1"); } catch { /* storage unavailable */ }
}

/** Capabilities that run identically whether the target is a local codebase or a live web app. */
const SHARED_TOOLS: Array<{ icon: IconName; label: string; detail: string }> = [
  { icon: "code", label: "Per-line syntax scan", detail: "Every file parsed to an AST; every line walked for weaknesses." },
  { icon: "folder", label: "Persistent DB index", detail: "Symbols, routes and findings stored in the local database." },
  { icon: "scan", label: "Secrets & dependencies", detail: "Secret and vulnerable-dependency detection across the tree." },
  { icon: "security", label: "Authorized security testing", detail: "Scoped, consented assessment — no action without approval." },
  { icon: "activity", label: "Live terminal stream", detail: "Every step, tool and finding prints to the terminal as it happens." },
];

export function LaunchPage() {
  const { projects, websites, loading, pickAndImportProject, scanNow, scanWebNow, setWebsiteComposerOpen } = useWorkspace();
  const [mode, setMode] = useState<TargetMode | null>(() => readTargetMode());
  const [importing, setImporting] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  // Web authorization popup — the only question the web path ever asks, once per target.
  const [authTarget, setAuthTarget] = useState<WebsiteRecord | null>(null);
  const [authConfirmed, setAuthConfirmed] = useState(false);

  function choose(next: TargetMode) {
    setMode(next);
    writeTargetMode(next);
  }

  async function importAndOpen() {
    choose("local");
    setImporting(true);
    try {
      await pickAndImportProject();
      navigate("workspace");
    } finally {
      setImporting(false);
    }
  }

  // One click: start the full read-only scan and jump straight to the live terminal.
  async function startLocalScan(id: string) {
    choose("local");
    setBusy(id);
    try {
      await scanNow(id);
      navigate("workspace");
    } catch { /* toast already shown */ } finally {
      setBusy(null);
    }
  }

  function addWebTarget() {
    choose("web");
    setWebsiteComposerOpen(true);
    navigate("websites");
  }

  // Web one click: confirm authorization once, then run and show live progress.
  async function startWebScan(website: WebsiteRecord) {
    choose("web");
    if (!isWebAuthorized(website.id)) {
      setAuthConfirmed(false);
      setAuthTarget(website);
      return;
    }
    setBusy(website.id);
    try {
      await scanWebNow(website);
      openWorkspaceInWebMode();
      navigate("workspace");
    } catch { /* toast already shown */ } finally {
      setBusy(null);
    }
  }

  async function confirmWebAuth() {
    const website = authTarget;
    if (!website || !authConfirmed) return;
    rememberWebAuth(website.id);
    setAuthTarget(null);
    setBusy(website.id);
    try {
      await scanWebNow(website);
      openWorkspaceInWebMode();
      navigate("workspace");
    } catch { /* toast already shown */ } finally {
      setBusy(null);
    }
  }

  // Every added target persists until the operator deletes it, with its indexed progress.
  const allProjects = projects;
  const allWebsites = websites;

  return (
    <div className="lp">
      <div className="lp-scanline" aria-hidden="true"/>
      <main className="lp-inner">
        <header className="lp-head">
          <span className="lp-brand"><Icon name="code" size={26}/><strong>CodeTwin</strong></span>
          <p className="lp-tagline">
            <span className="lp-prompt">$</span> choose a target — one engine assesses both
            <span className="lp-caret" aria-hidden="true">_</span>
          </p>
          <h1>Where do you want to start?</h1>
          <p className="lp-sub">
            Local codebase or live web target: both run the same tools — every page, every line, syntax &amp; database
            analysis plus authorized security testing — all streaming to the terminal.
          </p>
        </header>

        {loading ? (
          <LoadingState label="Loading workspace…"/>
        ) : (
          <div className="lp-cards">
            <section className={"lp-card" + (mode === "local" ? " lp-card-active" : "")} aria-labelledby="lp-local-h">
              <button type="button" className="lp-card-face" onClick={() => choose("local")} aria-pressed={mode === "local"}>
                <span className="lp-card-icon"><Icon name="code" size={30}/></span>
                <span className="lp-card-kind">Local</span>
                <h2 id="lp-local-h">Local Codebase</h2>
                <p>Import a repository folder. CodeTwin indexes every file into an AST + symbol database, then assesses it line by line.</p>
              </button>
              <div className="lp-card-actions">
                <button type="button" className="lp-btn lp-btn-primary" onClick={() => void importAndOpen()} disabled={importing}>
                  <Icon name="plus" size={17}/>{importing ? "Selecting folder…" : "Import project folder"}
                </button>
                {allProjects.length > 0 ? (
                  <ul className="lp-recent" aria-label="Local projects">
                    {allProjects.map((p) => (
                      <li key={p.id}>
                        <button type="button" aria-label={"Scan " + p.display_name} disabled={busy === p.id} onClick={() => void startLocalScan(p.id)}>
                          <Icon name="projects" size={16}/>
                          <span className="lp-recent-main">
                            <strong>{p.display_name}</strong>
                            <small>{p.file_count} files · {p.symbol_count} symbols{p.last_opened_at ? ` · ${formatDate(p.last_opened_at)}` : ""}</small>
                          </span>
                          <span className="lp-scan-cta">{busy === p.id ? "Starting…" : "Scan now ▸"}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="lp-recent-empty">No projects yet — import a folder to begin. Added projects stay here until you delete them.</p>
                )}
                {allProjects.length > 0 && <p className="lp-recent-count">{allProjects.length} saved project{allProjects.length === 1 ? "" : "s"} · click one to run the full scan</p>}
              </div>
            </section>

            <section className={"lp-card" + (mode === "web" ? " lp-card-active" : "")} aria-labelledby="lp-web-h">
              <button type="button" className="lp-card-face" onClick={() => choose("web")} aria-pressed={mode === "web"}>
                <span className="lp-card-icon"><Icon name="websites" size={30}/></span>
                <span className="lp-card-kind">Web</span>
                <h2 id="lp-web-h">Web Target</h2>
                <p>Register a URL. The same engine maps every page and endpoint, then runs scoped, authorized security testing.</p>
              </button>
              <div className="lp-card-actions">
                <button type="button" className="lp-btn lp-btn-primary" onClick={addWebTarget}>
                  <Icon name="plus" size={17}/>Add web target
                </button>
                {allWebsites.length > 0 ? (
                  <ul className="lp-recent" aria-label="Web targets">
                    {allWebsites.map((w) => (
                      <li key={w.id}>
                        <button type="button" aria-label={"Scan " + w.display_name} disabled={busy === w.id} onClick={() => void startWebScan(w)}>
                          <span className={"lp-dot lp-dot-" + w.status} aria-hidden="true"/>
                          <span className="lp-recent-main">
                            <strong>{w.display_name}</strong>
                            <small>{w.normalized_url}{w.last_checked_at ? ` · ${formatDate(w.last_checked_at)}` : ""}</small>
                          </span>
                          <span className="lp-scan-cta">{busy === w.id ? "Starting…" : "Scan now ▸"}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="lp-recent-empty">No web targets yet — add a URL to begin. Added targets stay here until you delete them.</p>
                )}
                {allWebsites.length > 0 && <p className="lp-recent-count">{allWebsites.length} saved target{allWebsites.length === 1 ? "" : "s"} · click one to run the full scan</p>}
              </div>
            </section>
          </div>
        )}

        <section className="lp-tools" aria-label="Shared capabilities">
          <p className="lp-tools-label">Same tools, both targets</p>
          <ul>
            {SHARED_TOOLS.map((t) => (
              <li key={t.label} title={t.detail}>
                <Icon name={t.icon} size={18}/>
                <span><strong>{t.label}</strong><small>{t.detail}</small></span>
              </li>
            ))}
          </ul>
        </section>

        <footer className="lp-foot">
          <button type="button" className="lp-link" onClick={() => navigate("dashboard")}>Skip to full workspace →</button>
          <span className="lp-note"><Icon name="security" size={14}/> Local-first. Assessments run only against authorized, approved scopes.</span>
        </footer>
      </main>

      <Modal
        open={!!authTarget}
        onClose={() => busy ? undefined : setAuthTarget(null)}
        title="Confirm authorization"
        description={authTarget ? `Before CodeTwin tests ${authTarget.display_name} (${authTarget.normalized_url}), confirm you are allowed to.` : ""}
        footer={<>
          <button className="ws-button ws-button-secondary" onClick={() => setAuthTarget(null)} disabled={!!busy}>Cancel</button>
          <button className="ws-button ws-button-primary" onClick={() => void confirmWebAuth()} disabled={!authConfirmed || !!busy}>
            <Icon name="security"/>{busy ? "Starting…" : "Authorize & scan"}
          </button>
        </>}
      >
        <label className="ws-field" style={{ flexDirection: "row", alignItems: "flex-start", gap: 10 }}>
          <input type="checkbox" checked={authConfirmed} onChange={(e) => setAuthConfirmed(e.target.checked)} style={{ width: "auto", marginTop: 3 }}/>
          <span>{GUIDED_AUTHORIZATION_STATEMENT}</span>
        </label>
        <p className="lp-recent-empty">This confirmation is recorded and remembered for this target. CodeTwin runs a bounded, authorized-production assessment — no destructive or state-changing actions.</p>
      </Modal>
    </div>
  );
}
