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

type IndexDelta = {
  files_scanned: number;
  files_added: number;
  files_modified: number;
  files_unchanged: number;
  files_deleted: number;
  symbols_added: number;
  symbols_updated: number;
  symbols_removed: number;
  parse_errors: number;
  skipped_files: number;
};

type IndexSummary = {
  project_id: string;
  run_id: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
  delta: IndexDelta;
  graph_node_count: number;
  graph_edge_count: number;
  duration_ms: number;
};

type SourceFileRecord = {
  id: string;
  project_id: string;
  relative_path: string;
  relative_path_identity: string;
  language: string | null;
  content_hash: string;
  byte_size: number;
  ast_root_kind: string | null;
  parse_state: string | null;
  is_active: boolean;
};

type SymbolRecord = {
  id: string;
  project_id: string;
  file_id: string;
  kind: string;
  name: string;
  qualified_name: string | null;
  parent_symbol_id: string | null;
  fingerprint: string;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
};

type ImportReferenceRecord = {
  id: string;
  source_file_id: string;
  raw_specifier: string;
  kind: string;
  resolution_state: "observed" | "resolved_local" | "external" | "unresolved" | "unsupported";
  resolved_target_file_id: string | null;
};

type ImpactedFileRecord = {
  file_id: string;
  relative_path: string;
  language: string | null;
  depth: number;
  via_import_id: string;
  via_source_file_id: string;
  via_raw_specifier: string;
};

type ImpactReport = {
  root: SourceFileRecord;
  affected_files: ImpactedFileRecord[];
  requested_depth: number;
  effective_depth: number;
  limit: number;
  truncated: boolean;
};

type GraphSummary = {
  node_count: number;
  edge_count: number;
};

type IndexRunRecord = {
  id: string;
  status: IndexSummary["status"];
  analyzer_version: string;
  query_version: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  delta: IndexDelta;
};

type View = "overview" | "digital-twin";

export function App() {
  const [view, setView] = useState<View>("overview");
  const [path, setPath] = useState("");
  const [profile, setProfile] = useState<ProjectProfile | null>(null);
  const [summary, setSummary] = useState<IndexSummary | null>(null);
  const [graph, setGraph] = useState<GraphSummary | null>(null);
  const [files, setFiles] = useState<SourceFileRecord[]>([]);
  const [history, setHistory] = useState<IndexRunRecord[]>([]);
  const [fileSearch, setFileSearch] = useState("");
  const [selectedFile, setSelectedFile] = useState<SourceFileRecord | null>(null);
  const [fileSymbols, setFileSymbols] = useState<SymbolRecord[]>([]);
  const [dependencies, setDependencies] = useState<ImportReferenceRecord[]>([]);
  const [dependents, setDependents] = useState<ImportReferenceRecord[]>([]);
  const [impact, setImpact] = useState<ImpactReport | null>(null);
  const [symbolSearch, setSymbolSearch] = useState("");
  const [symbolResults, setSymbolResults] = useState<SymbolRecord[]>([]);
  const [selectedSymbol, setSelectedSymbol] = useState<SymbolRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadProject(projectId: string, search?: string) {
    const [projectFiles, graphSummary, runs] = await Promise.all([
      invoke<SourceFileRecord[]>("list_project_files", {
        projectId,
        search: search?.trim() || null,
        limit: 200,
      }),
      invoke<GraphSummary>("get_graph_summary", { projectId }),
      invoke<IndexRunRecord[]>("index_history", { projectId, limit: 20 }),
    ]);
    setFiles(projectFiles);
    setGraph(graphSummary);
    setHistory(runs);
  }

  async function analyze() {
    setError(null);
    setBusy(true);
    try {
      const projectProfile = await invoke<ProjectProfile>("discover_project", { path });
      const indexSummary = await invoke<IndexSummary>("index_project", { path });
      setProfile(projectProfile);
      setSummary(indexSummary);
      setSelectedFile(null);
      setSelectedSymbol(null);
      setFileSymbols([]);
      setDependencies([]);
      setDependents([]);
      setImpact(null);
      setSymbolResults([]);
      await loadProject(indexSummary.project_id);
    } catch (value) {
      setError(String(value));
    } finally {
      setBusy(false);
    }
  }

  async function searchFiles() {
    if (!summary) return;
    setError(null);
    try {
      await loadProject(summary.project_id, fileSearch);
    } catch (value) {
      setError(String(value));
    }
  }

  async function selectFile(file: SourceFileRecord) {
    setError(null);
    setSelectedFile(file);
    setSelectedSymbol(null);
    try {
      const [symbols, imports, incoming, impactReport] = await Promise.all([
        invoke<SymbolRecord[]>("list_file_symbols", { fileId: file.id, limit: 300 }),
        invoke<ImportReferenceRecord[]>("list_dependencies", { fileId: file.id, limit: 200 }),
        invoke<ImportReferenceRecord[]>("list_dependents", { fileId: file.id, limit: 200 }),
        invoke<ImpactReport | null>("analyze_file_impact", {
          fileId: file.id,
          maxDepth: 6,
          limit: 200,
        }),
      ]);
      setFileSymbols(symbols);
      setDependencies(imports);
      setDependents(incoming);
      setImpact(impactReport);
    } catch (value) {
      setImpact(null);
      setError(String(value));
    }
  }

  async function runSymbolSearch() {
    if (!summary || !symbolSearch.trim()) {
      setSymbolResults([]);
      return;
    }
    setError(null);
    try {
      const results = await invoke<SymbolRecord[]>("search_symbols", {
        projectId: summary.project_id,
        search: {
          query: symbolSearch.trim(),
          mode: "substring",
          kind: null,
          language: null,
          file: null,
          qualified_only: false,
          limit: 200,
        },
      });
      setSymbolResults(results);
    } catch (value) {
      setError(String(value));
    }
  }

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand" aria-label="CodeTwin ML">
          <img src="/app-icon.png" alt="" />
        </div>
        <button className={`nav ${view === "overview" ? "active" : ""}`} onClick={() => setView("overview")}>
          Overview
        </button>
        <button
          className={`nav ${view === "digital-twin" ? "active" : ""}`}
          disabled={!summary}
          onClick={() => setView("digital-twin")}
        >
          Digital Twin
        </button>
        <button className="nav" disabled>Findings</button>
        <button className="nav" disabled>Repair Lab</button>
      </aside>

      <section className="workspace">
        <header>
          <div>
            <p className="eyebrow">LOCAL ONLY</p>
            <h1>{view === "overview" ? "CodeTwin ML" : "Software Digital Twin"}</h1>
            <p>
              {view === "overview"
                ? "Engineering intelligence workstation"
                : "Persisted files, symbols, dependencies, proven relationships, and bounded impact"}
            </p>
          </div>
        </header>

        {error && <p className="error banner" role="alert">{error}</p>}

        {view === "overview" && (
          <>
            <section className="panel">
              <h2>Open a project</h2>
              <p>
                Inspect stack metadata and update the persistent Tree-sitter Digital Twin without
                executing repository commands.
              </p>
              <div className="row">
                <input
                  aria-label="Repository path"
                  value={path}
                  onChange={(event) => setPath(event.target.value)}
                  placeholder="C:\\work\\project or /home/user/project"
                />
                <button onClick={analyze} disabled={!path.trim() || busy}>
                  {busy ? "Indexing…" : "Inspect & index"}
                </button>
              </div>
            </section>

            {summary && (
              <section className="grid index-summary" aria-label="Persistent index summary">
                <Metric label="files scanned" value={summary.delta.files_scanned} />
                <Metric label="files added" value={summary.delta.files_added} />
                <Metric label="files modified" value={summary.delta.files_modified} />
                <Metric label="files unchanged" value={summary.delta.files_unchanged} />
                <Metric label="files deleted" value={summary.delta.files_deleted} />
                <Metric label="symbol changes" value={summary.delta.symbols_added + summary.delta.symbols_updated + summary.delta.symbols_removed} />
                <Metric label="graph nodes" value={summary.graph_node_count} />
                <Metric label="graph edges" value={summary.graph_edge_count} />
                <Metric label="parse errors" value={summary.delta.parse_errors} />
                <Metric label="skipped files" value={summary.delta.skipped_files} />
                <Metric label="duration" value={`${summary.duration_ms} ms`} />
                <Metric label="status" value={summary.status} />
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
          </>
        )}

        {view === "digital-twin" && summary && (
          <section className="twin-layout">
            <div className="twin-column">
              <section className="panel compact">
                <div className="section-heading">
                  <div>
                    <h2>Files</h2>
                    <p>{graph ? `${graph.node_count} active nodes · ${graph.edge_count} active edges` : "Loading graph summary"}</p>
                  </div>
                </div>
                <div className="row search-row">
                  <input
                    aria-label="Search project files"
                    value={fileSearch}
                    onChange={(event) => setFileSearch(event.target.value)}
                    onKeyDown={(event) => event.key === "Enter" && void searchFiles()}
                    placeholder="Search relative path"
                  />
                  <button onClick={searchFiles}>Search</button>
                </div>
                <div className="result-list">
                  {files.map((file) => (
                    <button
                      key={file.id}
                      className={`result-item ${selectedFile?.id === file.id ? "selected" : ""}`}
                      onClick={() => void selectFile(file)}
                    >
                      <strong>{file.relative_path}</strong>
                      <span>{file.language ?? "Unknown"} · {file.parse_state ?? "unknown parse state"}</span>
                    </button>
                  ))}
                  {!files.length && <p className="empty">No matching indexed files.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Symbol search</h2>
                <div className="row search-row">
                  <input
                    aria-label="Search symbols"
                    value={symbolSearch}
                    onChange={(event) => setSymbolSearch(event.target.value)}
                    onKeyDown={(event) => event.key === "Enter" && void runSymbolSearch()}
                    placeholder="Name or qualified name"
                  />
                  <button onClick={runSymbolSearch}>Search</button>
                </div>
                <div className="result-list small-list">
                  {symbolResults.map((symbol) => (
                    <button key={symbol.id} className="result-item" onClick={() => setSelectedSymbol(symbol)}>
                      <strong>{symbol.qualified_name ?? symbol.name}</strong>
                      <span>{symbol.kind} · line {symbol.start_line}</span>
                    </button>
                  ))}
                </div>
              </section>
            </div>

            <div className="twin-column wide">
              <section className="panel compact detail-panel">
                <h2>File detail</h2>
                {selectedFile ? (
                  <>
                    <dl className="metadata-grid">
                      <dt>Path</dt><dd>{selectedFile.relative_path}</dd>
                      <dt>Language</dt><dd>{selectedFile.language ?? "Unknown"}</dd>
                      <dt>Bytes</dt><dd>{selectedFile.byte_size}</dd>
                      <dt>AST root</dt><dd>{selectedFile.ast_root_kind ?? "Unavailable"}</dd>
                      <dt>Parse</dt><dd>{selectedFile.parse_state ?? "Unknown"}</dd>
                      <dt>Hash</dt><dd className="mono">{selectedFile.content_hash}</dd>
                    </dl>

                    <h3>Symbols</h3>
                    <div className="result-list small-list">
                      {fileSymbols.map((symbol) => (
                        <button key={symbol.id} className="result-item" onClick={() => setSelectedSymbol(symbol)}>
                          <strong>{symbol.qualified_name ?? symbol.name}</strong>
                          <span>{symbol.kind} · {symbol.start_line}:{symbol.start_column}</span>
                        </button>
                      ))}
                      {!fileSymbols.length && <p className="empty">No definition symbols persisted for this file.</p>}
                    </div>

                    <div className="relationship-grid">
                      <RelationshipList title="Imports" records={dependencies} direction="out" />
                      <RelationshipList title="Dependents" records={dependents} direction="in" />
                    </div>
                  </>
                ) : (
                  <p className="empty">Select an indexed file to inspect persisted metadata and direct relationships.</p>
                )}
              </section>

              <section className="panel compact">
                <h2>Impact analysis</h2>
                {impact ? (
                  <>
                    <p>
                      Evidence-backed reverse dependency impact from <strong>{impact.root.relative_path}</strong>.
                      Depth is capped at {impact.effective_depth}; at most {impact.limit} files are returned.
                    </p>
                    <div className="result-list small-list">
                      {impact.affected_files.map((file) => (
                        <div key={file.file_id} className="relationship-item">
                          <strong>{file.relative_path}</strong>
                          <span>{file.language ?? "Unknown"} · depth {file.depth}</span>
                          <small className="mono">via {file.via_raw_specifier}</small>
                        </div>
                      ))}
                      {!impact.affected_files.length && (
                        <p className="empty">No active files are proven to depend on this file through resolved local imports.</p>
                      )}
                    </div>
                    {impact.truncated && <p className="error">Result limit reached; refine the target before relying on the visible set.</p>}
                  </>
                ) : (
                  <p className="empty">Select an indexed file to calculate bounded reverse dependency impact.</p>
                )}
              </section>

              <section className="panel compact">
                <h2>Symbol detail</h2>
                {selectedSymbol ? (
                  <dl className="metadata-grid">
                    <dt>Name</dt><dd>{selectedSymbol.name}</dd>
                    <dt>Qualified</dt><dd>{selectedSymbol.qualified_name ?? "Unavailable"}</dd>
                    <dt>Kind</dt><dd>{selectedSymbol.kind}</dd>
                    <dt>Range</dt><dd>{selectedSymbol.start_line}:{selectedSymbol.start_column}–{selectedSymbol.end_line}:{selectedSymbol.end_column}</dd>
                    <dt>Parent</dt><dd className="mono">{selectedSymbol.parent_symbol_id ?? "None"}</dd>
                    <dt>Fingerprint</dt><dd className="mono">{selectedSymbol.fingerprint}</dd>
                  </dl>
                ) : (
                  <p className="empty">Select a symbol from the file or bounded search results.</p>
                )}
              </section>

              <section className="panel compact">
                <h2>Index history</h2>
                <div className="history-list">
                  {history.map((run) => (
                    <div key={run.id} className="history-item">
                      <div><strong>{run.status}</strong><span>{run.started_at ?? "time unavailable"}</span></div>
                      <span>{run.delta.files_added}+ / {run.delta.files_modified}~ / {run.delta.files_deleted}− · {run.duration_ms ?? 0} ms</span>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          </section>
        )}
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <article className="card">
      <h3>{label}</h3>
      <p>{value}</p>
    </article>
  );
}

function RelationshipList({
  title,
  records,
  direction,
}: {
  title: string;
  records: ImportReferenceRecord[];
  direction: "out" | "in";
}) {
  return (
    <div>
      <h3>{title}</h3>
      <div className="relationship-list">
        {records.map((record) => (
          <div key={record.id} className="relationship-item">
            <strong>{record.raw_specifier}</strong>
            <span>{record.resolution_state}</span>
            <small className="mono">
              {direction === "out"
                ? record.resolved_target_file_id ?? "no local target"
                : record.source_file_id}
            </small>
          </div>
        ))}
        {!records.length && <p className="empty">No persisted relationships.</p>}
      </div>
    </div>
  );
}
