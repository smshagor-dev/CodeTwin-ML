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

type IndexedSymbol = {
  kind: string;
  name: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

type IndexedFile = {
  relative_path: string;
  language: string;
  content_hash: string;
  byte_size: number;
  ast_root_kind: string;
  parse_state: "parsed" | "parsed_with_errors";
  symbols: IndexedSymbol[];
};

type IndexResult = {
  indexed_files: IndexedFile[];
  unchanged_files: string[];
  skipped_files: { relative_path: string; reason: string }[];
};

export function App() {
  const [path, setPath] = useState("");
  const [profile, setProfile] = useState<ProjectProfile | null>(null);
  const [index, setIndex] = useState<IndexResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function analyze() {
    setError(null);
    setBusy(true);
    try {
      const [projectProfile, sourceIndex] = await Promise.all([
        invoke<ProjectProfile>("discover_project", { path }),
        invoke<IndexResult>("index_project", { path }),
      ]);
      setProfile(projectProfile);
      setIndex(sourceIndex);
    } catch (value) {
      setProfile(null);
      setIndex(null);
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  const symbolCount = index?.indexed_files.reduce(
    (total, file) => total + file.symbols.length,
    0,
  );
  const parseErrorCount = index?.indexed_files.filter(
    (file) => file.parse_state === "parsed_with_errors",
  ).length;

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand">CT</div>
        <button className="nav active">Overview</button>
        <button className="nav" disabled>Digital Twin</button>
        <button className="nav" disabled>Findings</button>
        <button className="nav" disabled>Repair Lab</button>
      </aside>
      <section className="workspace">
        <header>
          <div>
            <p className="eyebrow">LOCAL ONLY</p>
            <h1>CodeTwin ML</h1>
            <p>Engineering intelligence workstation</p>
          </div>
        </header>
        <section className="panel">
          <h2>Open a project</h2>
          <p>
            Inspect stack metadata and build a Tree-sitter source index without executing
            repository commands.
          </p>
          <div className="row">
            <input
              aria-label="Repository path"
              value={path}
              onChange={(event) => setPath(event.target.value)}
              placeholder="C:\\work\\project or /home/user/project"
            />
            <button onClick={analyze} disabled={!path.trim() || busy}>
              {busy ? "Indexing…" : "Inspect"}
            </button>
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </section>
        {index && (
          <section className="grid index-summary" aria-label="Source index summary">
            <article className="card">
              <h3>indexed files</h3>
              <p>{index.indexed_files.length}</p>
            </article>
            <article className="card">
              <h3>symbols</h3>
              <p>{symbolCount ?? 0}</p>
            </article>
            <article className="card">
              <h3>parse errors</h3>
              <p>{parseErrorCount ?? 0}</p>
            </article>
            <article className="card">
              <h3>skipped files</h3>
              <p>{index.skipped_files.length}</p>
            </article>
          </section>
        )}
        {profile && (
          <section className="grid" aria-label="Detected project profile">
            {Object.entries(profile).map(([key, values]) => (
              <article className="card" key={key}>
                <h3>{key.replaceAll("_", " ")}</h3>
                <p>{values.length ? values.join(", ") : "Not detected"}</p>
              </article>
            ))}
          </section>
        )}
      </section>
    </main>
  );
}
