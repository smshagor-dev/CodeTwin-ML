import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type ProjectProfile = {
  languages: string[];
  frameworks: string[];
  package_managers: string[];
  build_systems: string[];
  test_frameworks: string[];
  databases: string[];
  ci_providers: string[];
  project_kinds: string[];
};

export function App() {
  const [path, setPath] = useState("");
  const [profile, setProfile] = useState<ProjectProfile | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function analyze() {
    setError(null);
    try {
      const result = await invoke<ProjectProfile>("discover_project", { path });
      setProfile(result);
    } catch (value) {
      setProfile(null);
      setError(String(value));
    }
  }

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand" aria-label="CodeTwin ML">
          <img src="/app-icon.png" alt="" />
        </div>
        <button className="nav active">Overview</button>
        <button className="nav" disabled>Digital Twin</button>
        <button className="nav" disabled>Findings</button>
        <button className="nav" disabled>Repair Lab</button>
      </aside>
      <section className="workspace">
        <header>
          <div><p className="eyebrow">LOCAL ONLY</p><h1>CodeTwin ML</h1><p>Engineering intelligence workstation</p></div>
        </header>
        <section className="panel">
          <h2>Open a project</h2>
          <p>The current foundation performs real stack discovery without executing repository commands.</p>
          <div className="row">
            <input aria-label="Repository path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="C:\\work\\project or /home/user/project" />
            <button onClick={analyze} disabled={!path.trim()}>Inspect</button>
          </div>
          {error && <p className="error" role="alert">{error}</p>}
        </section>
        {profile && <section className="grid" aria-label="Detected project profile">
          {Object.entries(profile).map(([key, values]) => <article className="card" key={key}><h3>{key.replaceAll("_", " ")}</h3><p>{values.length ? values.join(", ") : "Not detected"}</p></article>)}
        </section>}
      </section>
    </main>
  );
}
