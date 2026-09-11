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

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";

type IndexSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
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
  status: AnalysisStatus;
  analyzer_version: string;
  query_version: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  delta: IndexDelta;
};

type LanguageServerKind = "typescript" | "pyright" | "rust_analyzer";

type LanguageServerConfig = {
  kind: LanguageServerKind;
  executable_path: string;
  arguments: string[];
  initialization_options: unknown | null;
  enabled: boolean;
};

type ServerDraft = {
  executablePath: string;
  argumentsText: string;
  enabled: boolean;
};

type SemanticServerRun = {
  kind: LanguageServerKind;
  status: "completed" | "failed" | "not_configured" | "disabled" | "no_files";
  files_processed: number;
  symbols_processed: number;
  symbols_matched: number;
  reference_locations: number;
  definitions_resolved: number;
  relations_persisted: number;
  graph_edges_materialized: number;
  imports_upgraded: number;
  errors: number;
  error: string | null;
  server_name: string | null;
  server_version: string | null;
};

type SemanticRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  files_processed: number;
  symbols_processed: number;
  symbols_matched: number;
  reference_locations: number;
  definitions_resolved: number;
  relations_persisted: number;
  graph_edges_materialized: number;
  imports_upgraded: number;
  errors: number;
  duration_ms: number;
  servers: SemanticServerRun[];
};

type SemanticRunRecord = Omit<SemanticRunSummary, "servers" | "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type SemanticSymbolStateRecord = {
  symbol_id: string;
  project_id: string;
  run_id: string;
  provider_kind: LanguageServerKind;
  state: "resolved" | "no_references" | "unmatched" | "unresolved" | "unsupported" | "error" | "stale";
  reference_locations: number;
  definitions_resolved: number;
  last_error: string | null;
};

type SemanticRelationRecord = {
  id: string;
  subject_symbol_id: string;
  occurrence_file_id: string;
  container_symbol_id: string | null;
  target_file_id: string;
  target_symbol_id: string | null;
  relationship: string;
  occurrence_start_line: number;
  occurrence_start_column: number;
  target_start_line: number;
  target_start_column: number;
  provider_kind: LanguageServerKind;
  server_name: string | null;
  server_version: string | null;
};

type SemanticImportResolutionRecord = {
  id: string;
  import_reference_id: string;
  source_file_id: string;
  target_file_id: string;
  provider_kind: LanguageServerKind;
  target_start_line: number;
  target_start_column: number;
};

type View = "overview" | "digital-twin" | "semantics";

const SERVER_KINDS: LanguageServerKind[] = ["typescript", "pyright", "rust_analyzer"];
const SERVER_LABELS: Record<LanguageServerKind, string> = {
  typescript: "TypeScript / JavaScript",
  pyright: "Python / Pyright",
  rust_analyzer: "Rust Analyzer",
};

const EMPTY_SERVER_DRAFTS: Record<LanguageServerKind, ServerDraft> = {
  typescript: { executablePath: "", argumentsText: "", enabled: true },
  pyright: { executablePath: "", argumentsText: "", enabled: true },
  rust_analyzer: { executablePath: "", argumentsText: "", enabled: true },
};

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
  const [serverDrafts, setServerDrafts] = useState<Record<LanguageServerKind, ServerDraft>>(() => ({
    typescript: { ...EMPTY_SERVER_DRAFTS.typescript },
    pyright: { ...EMPTY_SERVER_DRAFTS.pyright },
    rust_analyzer: { ...EMPTY_SERVER_DRAFTS.rust_analyzer },
  }));
  const [semanticTrusted, setSemanticTrusted] = useState(false);
  const [semanticBusy, setSemanticBusy] = useState(false);
  const [semanticSummary, setSemanticSummary] = useState<SemanticRunSummary | null>(null);
  const [semanticHistory, setSemanticHistory] = useState<SemanticRunRecord[]>([]);
  const [semanticState, setSemanticState] = useState<SemanticSymbolStateRecord | null>(null);
  const [semanticRelations, setSemanticRelations] = useState<SemanticRelationRecord[]>([]);
  const [semanticImports, setSemanticImports] = useState<SemanticImportResolutionRecord[]>([]);
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

  async function loadSemanticWorkspace(projectId: string) {
    const [configs, runs] = await Promise.all([
      invoke<LanguageServerConfig[]>("list_language_server_configs"),
      invoke<SemanticRunRecord[]>("semantic_history", { projectId, limit: 20 }),
    ]);
    const next: Record<LanguageServerKind, ServerDraft> = {
      typescript: { ...EMPTY_SERVER_DRAFTS.typescript },
      pyright: { ...EMPTY_SERVER_DRAFTS.pyright },
      rust_analyzer: { ...EMPTY_SERVER_DRAFTS.rust_analyzer },
    };
    for (const config of configs) {
      next[config.kind] = {
        executablePath: config.executable_path,
        argumentsText: config.arguments.join("\n"),
        enabled: config.enabled,
      };
    }
    setServerDrafts(next);
    setSemanticHistory(runs);
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
      setSemanticState(null);
      setSemanticRelations([]);
      setSemanticImports([]);
      setSemanticSummary(null);
      await Promise.all([loadProject(indexSummary.project_id), loadSemanticWorkspace(indexSummary.project_id)]);
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
    setSemanticState(null);
    setSemanticRelations([]);
    try {
      const [symbols, imports, incoming, impactReport, lspImports] = await Promise.all([
        invoke<SymbolRecord[]>("list_file_symbols", { fileId: file.id, limit: 300 }),
        invoke<ImportReferenceRecord[]>("list_dependencies", { fileId: file.id, limit: 200 }),
        invoke<ImportReferenceRecord[]>("list_dependents", { fileId: file.id, limit: 200 }),
        invoke<ImpactReport | null>("analyze_file_impact", {
          fileId: file.id,
          maxDepth: 6,
          limit: 200,
        }),
        invoke<SemanticImportResolutionRecord[]>("list_file_semantic_imports", {
          fileId: file.id,
          limit: 200,
        }),
      ]);
      setFileSymbols(symbols);
      setDependencies(imports);
      setDependents(incoming);
      setImpact(impactReport);
      setSemanticImports(lspImports);
    } catch (value) {
      setImpact(null);
      setSemanticImports([]);
      setError(String(value));
    }
  }

  async function selectSymbol(symbol: SymbolRecord) {
    setSelectedSymbol(symbol);
    setError(null);
    try {
      const [state, relations] = await Promise.all([
        invoke<SemanticSymbolStateRecord | null>("get_symbol_semantic_state", { symbolId: symbol.id }),
        invoke<SemanticRelationRecord[]>("list_symbol_semantic_relations", {
          symbolId: symbol.id,
          direction: "all",
          limit: 100,
        }),
      ]);
      setSemanticState(state);
      setSemanticRelations(relations);
    } catch (value) {
      setSemanticState(null);
      setSemanticRelations([]);
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

  function updateServerDraft(kind: LanguageServerKind, patch: Partial<ServerDraft>) {
    setServerDrafts((current) => ({
      ...current,
      [kind]: { ...current[kind], ...patch },
    }));
  }

  async function saveServerConfig(kind: LanguageServerKind) {
    const draft = serverDrafts[kind];
    if (!draft.executablePath.trim()) {
      setError(`Configure an absolute executable path for ${SERVER_LABELS[kind]}.`);
      return;
    }
    setError(null);
    try {
      await invoke("set_language_server_config", {
        config: {
          kind,
          executable_path: draft.executablePath.trim(),
          arguments: draft.argumentsText
            .split("\n")
            .map((value) => value.trim())
            .filter(Boolean),
          initialization_options: null,
          enabled: draft.enabled,
        } satisfies LanguageServerConfig,
      });
    } catch (value) {
      setError(String(value));
    }
  }

  async function removeServerConfig(kind: LanguageServerKind) {
    setError(null);
    try {
      await invoke<boolean>("remove_language_server_config", { kind });
      updateServerDraft(kind, { executablePath: "", argumentsText: "", enabled: true });
    } catch (value) {
      setError(String(value));
    }
  }

  async function runSemanticEnrichment() {
    if (!summary) return;
    if (!semanticTrusted) {
      setError("Explicit project trust is required before external language servers can run.");
      return;
    }
    const serverKinds = SERVER_KINDS.filter(
      (kind) => serverDrafts[kind].enabled && serverDrafts[kind].executablePath.trim(),
    );
    if (!serverKinds.length) {
      setError("Configure and enable at least one language server before semantic enrichment.");
      return;
    }
    setSemanticBusy(true);
    setError(null);
    try {
      const result = await invoke<SemanticRunSummary>("enrich_project_semantics", {
        projectId: summary.project_id,
        request: {
          server_kinds: serverKinds,
          trusted_project: true,
          max_files: 100,
          max_symbols: 500,
          max_references_per_symbol: 25,
          max_definition_lookups: 1500,
          request_timeout_ms: 5000,
        },
      });
      setSemanticSummary(result);
      await Promise.all([loadSemanticWorkspace(summary.project_id), loadProject(summary.project_id)]);
      if (selectedFile) await selectFile(selectedFile);
      if (selectedSymbol) await selectSymbol(selectedSymbol);
    } catch (value) {
      setError(String(value));
    } finally {
      setSemanticBusy(false);
    }
  }

  async function cancelSemanticEnrichment() {
    try {
      await invoke<boolean>("cancel_semantic_enrichment");
    } catch (value) {
      setError(String(value));
    }
  }

  async function openSemanticView() {
    if (!summary) return;
    setView("semantics");
    setError(null);
    try {
      await loadSemanticWorkspace(summary.project_id);
    } catch (value) {
      setError(String(value));
    }
  }

  const title = view === "overview" ? "CodeTwin ML" : view === "digital-twin" ? "Software Digital Twin" : "Semantic Navigation";

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand" aria-label="CodeTwin ML"><img src="/app-icon.png" alt="" /></div>
        <button className={`nav ${view === "overview" ? "active" : ""}`} onClick={() => setView("overview")}>Overview</button>
        <button className={`nav ${view === "digital-twin" ? "active" : ""}`} disabled={!summary} onClick={() => setView("digital-twin")}>Digital Twin</button>
        <button className={`nav ${view === "semantics" ? "active" : ""}`} disabled={!summary} onClick={() => void openSemanticView()}>Semantics</button>
        <button className="nav" disabled>Findings</button>
        <button className="nav" disabled>Repair Lab</button>
      </aside>

      <section className="workspace">
        <header>
          <div>
            <p className="eyebrow">LOCAL FIRST</p>
            <h1>{title}</h1>
            <p>
              {view === "overview"
                ? "Engineering intelligence workstation"
                : view === "digital-twin"
                  ? "Persisted files, symbols, dependencies, proven relationships, and bounded impact"
                  : "Explicitly trusted language servers enriching persisted source evidence"}
            </p>
          </div>
        </header>

        {error && <p className="error banner" role="alert">{error}</p>}

        {view === "overview" && (
          <>
            <section className="panel">
              <h2>Open a project</h2>
              <p>Inspect stack metadata and update the persistent Tree-sitter Digital Twin without executing repository commands.</p>
              <div className="row">
                <input aria-label="Repository path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="C:\\work\\project or /home/user/project" />
                <button onClick={analyze} disabled={!path.trim() || busy}>{busy ? "Indexing…" : "Inspect & index"}</button>
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
                  <article className="card" key={key}><h3>{key.replaceAll("_", " ")}</h3><p>{values.length ? values.join(", ") : "Not detected"}</p></article>
                ))}
              </section>
            )}
          </>
        )}

        {view === "digital-twin" && summary && (
          <section className="twin-layout">
            <div className="twin-column">
              <section className="panel compact">
                <div className="section-heading"><div><h2>Files</h2><p>{graph ? `${graph.node_count} active nodes · ${graph.edge_count} active edges` : "Loading graph summary"}</p></div></div>
                <div className="row search-row">
                  <input aria-label="Search project files" value={fileSearch} onChange={(event) => setFileSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void searchFiles()} placeholder="Search relative path" />
                  <button onClick={searchFiles}>Search</button>
                </div>
                <div className="result-list">
                  {files.map((file) => (
                    <button key={file.id} className={`result-item ${selectedFile?.id === file.id ? "selected" : ""}`} onClick={() => void selectFile(file)}>
                      <strong>{file.relative_path}</strong><span>{file.language ?? "Unknown"} · {file.parse_state ?? "unknown parse state"}</span>
                    </button>
                  ))}
                  {!files.length && <p className="empty">No matching indexed files.</p>}
                </div>
              </section>

              <section className="panel compact">
                <h2>Symbol search</h2>
                <div className="row search-row">
                  <input aria-label="Search symbols" value={symbolSearch} onChange={(event) => setSymbolSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void runSymbolSearch()} placeholder="Name or qualified name" />
                  <button onClick={runSymbolSearch}>Search</button>
                </div>
                <div className="result-list small-list">
                  {symbolResults.map((symbol) => (
                    <button key={symbol.id} className="result-item" onClick={() => void selectSymbol(symbol)}><strong>{symbol.qualified_name ?? symbol.name}</strong><span>{symbol.kind} · line {symbol.start_line}</span></button>
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
                      <dt>Path</dt><dd>{selectedFile.relative_path}</dd><dt>Language</dt><dd>{selectedFile.language ?? "Unknown"}</dd>
                      <dt>Bytes</dt><dd>{selectedFile.byte_size}</dd><dt>AST root</dt><dd>{selectedFile.ast_root_kind ?? "Unavailable"}</dd>
                      <dt>Parse</dt><dd>{selectedFile.parse_state ?? "Unknown"}</dd><dt>Hash</dt><dd className="mono">{selectedFile.content_hash}</dd>
                    </dl>
                    <h3>Symbols</h3>
                    <div className="result-list small-list">
                      {fileSymbols.map((symbol) => (
                        <button key={symbol.id} className="result-item" onClick={() => void selectSymbol(symbol)}><strong>{symbol.qualified_name ?? symbol.name}</strong><span>{symbol.kind} · {symbol.start_line}:{symbol.start_column}</span></button>
                      ))}
                      {!fileSymbols.length && <p className="empty">No definition symbols persisted for this file.</p>}
                    </div>
                    <div className="relationship-grid">
                      <RelationshipList title="Imports" records={dependencies} direction="out" />
                      <RelationshipList title="Dependents" records={dependents} direction="in" />
                    </div>
                    <h3>LSP import evidence</h3>
                    <div className="relationship-list">
                      {semanticImports.map((item) => (
                        <div key={item.id} className="relationship-item"><strong>{item.provider_kind}</strong><span>{item.source_file_id} → {item.target_file_id}</span><small>{item.target_start_line}:{item.target_start_column}</small></div>
                      ))}
                      {!semanticImports.length && <p className="empty">No current LSP-proven local import evidence.</p>}
                    </div>
                  </>
                ) : <p className="empty">Select an indexed file to inspect persisted metadata and direct relationships.</p>}
              </section>

              <section className="panel compact">
                <h2>Impact analysis</h2>
                {impact ? (
                  <>
                    <p>Evidence-backed reverse dependency impact from <strong>{impact.root.relative_path}</strong>. Depth is capped at {impact.effective_depth}; at most {impact.limit} files are returned.</p>
                    <div className="result-list small-list">
                      {impact.affected_files.map((file) => (
                        <div key={file.file_id} className="relationship-item"><strong>{file.relative_path}</strong><span>{file.language ?? "Unknown"} · depth {file.depth}</span><small className="mono">via {file.via_raw_specifier}</small></div>
                      ))}
                      {!impact.affected_files.length && <p className="empty">No active files are proven to depend on this file through resolved local imports.</p>}
                    </div>
                    {impact.truncated && <p className="error">Result limit reached; refine the target before relying on the visible set.</p>}
                  </>
                ) : <p className="empty">Select an indexed file to calculate bounded reverse dependency impact.</p>}
              </section>

              <section className="panel compact">
                <h2>Symbol detail</h2>
                {selectedSymbol ? (
                  <>
                    <dl className="metadata-grid">
                      <dt>Name</dt><dd>{selectedSymbol.name}</dd><dt>Qualified</dt><dd>{selectedSymbol.qualified_name ?? "Unavailable"}</dd>
                      <dt>Kind</dt><dd>{selectedSymbol.kind}</dd><dt>Range</dt><dd>{selectedSymbol.start_line}:{selectedSymbol.start_column}–{selectedSymbol.end_line}:{selectedSymbol.end_column}</dd>
                      <dt>Parent</dt><dd className="mono">{selectedSymbol.parent_symbol_id ?? "None"}</dd><dt>Fingerprint</dt><dd className="mono">{selectedSymbol.fingerprint}</dd>
                    </dl>
                    <h3>LSP semantic state</h3>
                    {semanticState ? <p>{semanticState.provider_kind} · {semanticState.state} · {semanticState.reference_locations} references · {semanticState.definitions_resolved} local definitions</p> : <p className="empty">No current semantic state for this symbol.</p>}
                    <div className="relationship-list">
                      {semanticRelations.map((relation) => (
                        <div key={relation.id} className="relationship-item"><strong>{relation.relationship}</strong><span>{relation.provider_kind} · {relation.occurrence_file_id}:{relation.occurrence_start_line}:{relation.occurrence_start_column}</span><small className="mono">target {relation.target_symbol_id ?? relation.target_file_id} · {relation.target_start_line}:{relation.target_start_column}</small></div>
                      ))}
                      {!semanticRelations.length && <p className="empty">No current persisted LSP relationship evidence.</p>}
                    </div>
                  </>
                ) : <p className="empty">Select a symbol from the file or bounded search results.</p>}
              </section>

              <section className="panel compact">
                <h2>Index history</h2>
                <div className="history-list">
                  {history.map((run) => (
                    <div key={run.id} className="history-item"><div><strong>{run.status}</strong><span>{run.started_at ?? "time unavailable"}</span></div><span>{run.delta.files_added}+ / {run.delta.files_modified}~ / {run.delta.files_deleted}− · {run.duration_ms ?? 0} ms</span></div>
                  ))}
                </div>
              </section>
            </div>
          </section>
        )}

        {view === "semantics" && summary && (
          <section className="semantic-workspace">
            <section className="panel">
              <h2>Language servers</h2>
              <p>CodeTwin never discovers or executes a server from the analyzed repository. Configure an absolute executable outside the project. Put one process argument per line.</p>
              <div className="server-grid">
                {SERVER_KINDS.map((kind) => {
                  const draft = serverDrafts[kind];
                  return (
                    <article className="card server-card" key={kind}>
                      <h3>{SERVER_LABELS[kind]}</h3>
                      <label>Executable path<input value={draft.executablePath} onChange={(event) => updateServerDraft(kind, { executablePath: event.target.value })} placeholder="Absolute executable path" /></label>
                      <label>Arguments<textarea value={draft.argumentsText} onChange={(event) => updateServerDraft(kind, { argumentsText: event.target.value })} placeholder="One argument per line" rows={3} /></label>
                      <label className="check-row"><input type="checkbox" checked={draft.enabled} onChange={(event) => updateServerDraft(kind, { enabled: event.target.checked })} /> Enabled</label>
                      <div className="button-row"><button onClick={() => void saveServerConfig(kind)}>Save</button><button className="secondary" onClick={() => void removeServerConfig(kind)}>Remove</button></div>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="panel">
              <h2>Semantic enrichment run</h2>
              <label className="trust-row"><input type="checkbox" checked={semanticTrusted} onChange={(event) => setSemanticTrusted(event.target.checked)} /> I trust this project and allow the configured external language servers to inspect its source files.</label>
              <p>Runs are bounded to 100 files, 500 symbols, 25 references per symbol, 1,500 definition lookups, and a 5-second request timeout.</p>
              <div className="button-row"><button onClick={() => void runSemanticEnrichment()} disabled={semanticBusy || !semanticTrusted}>{semanticBusy ? "Running…" : "Run semantic enrichment"}</button><button className="secondary" onClick={() => void cancelSemanticEnrichment()} disabled={!semanticBusy}>Cancel</button></div>
              {semanticSummary && (
                <div className="grid semantic-metrics">
                  <Metric label="files" value={semanticSummary.files_processed} /><Metric label="symbols" value={semanticSummary.symbols_processed} />
                  <Metric label="matched" value={semanticSummary.symbols_matched} /><Metric label="references" value={semanticSummary.reference_locations} />
                  <Metric label="definitions" value={semanticSummary.definitions_resolved} /><Metric label="relations" value={semanticSummary.relations_persisted} />
                  <Metric label="graph edges" value={semanticSummary.graph_edges_materialized} /><Metric label="LSP imports" value={semanticSummary.imports_upgraded} />
                  <Metric label="errors" value={semanticSummary.errors} /><Metric label="duration" value={`${semanticSummary.duration_ms} ms`} />
                </div>
              )}
              {semanticSummary?.servers.map((server) => (
                <div className="history-item" key={server.kind}><div><strong>{SERVER_LABELS[server.kind]}</strong><span>{server.server_name ?? "server name unavailable"} {server.server_version ?? ""}</span></div><span>{server.status} · {server.errors} errors</span>{server.error && <small className="error">{server.error}</small>}</div>
              ))}
            </section>

            <section className="panel compact">
              <h2>Semantic history</h2>
              <div className="history-list">
                {semanticHistory.map((run) => (
                  <div className="history-item" key={run.run_id}><div><strong>{run.status}</strong><span>{run.started_at ?? "time unavailable"}</span></div><span>{run.definitions_resolved} definitions · {run.graph_edges_materialized} edges · {run.errors} errors · {run.duration_ms ?? 0} ms</span></div>
                ))}
                {!semanticHistory.length && <p className="empty">No LSP semantic run has been persisted for this project.</p>}
              </div>
            </section>
          </section>
        )}
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <article className="card"><h3>{label}</h3><p>{value}</p></article>;
}

function RelationshipList({ title, records, direction }: { title: string; records: ImportReferenceRecord[]; direction: "out" | "in" }) {
  return (
    <div><h3>{title}</h3><div className="relationship-list">
      {records.map((record) => (
        <div key={record.id} className="relationship-item"><strong>{record.raw_specifier}</strong><span>{record.resolution_state}</span><small className="mono">{direction === "out" ? record.resolved_target_file_id ?? "no local target" : record.source_file_id}</small></div>
      ))}
      {!records.length && <p className="empty">No persisted relationships.</p>}
    </div></div>
  );
}
