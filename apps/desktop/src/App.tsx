import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type View = "overview" | "digital-twin" | "semantics" | "findings" | "security";
type LanguageServerKind = "typescript" | "pyright" | "rust_analyzer";
type FindingFilter = "open" | "resolved" | "all";

type ProjectProfile = Record<
  "languages" | "frameworks" | "package_managers" | "build_systems" | "test_frameworks" | "databases" | "ci_providers" | "project_kinds",
  string[]
>;

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

type ImpactReport = {
  root: SourceFileRecord;
  affected_files: Array<{
    file_id: string;
    relative_path: string;
    language: string | null;
    depth: number;
    via_import_id: string;
    via_source_file_id: string;
    via_raw_specifier: string;
  }>;
  requested_depth: number;
  effective_depth: number;
  limit: number;
  truncated: boolean;
};

type GraphSummary = { node_count: number; edge_count: number };

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

type LanguageServerConfig = {
  kind: LanguageServerKind;
  executable_path: string;
  arguments: string[];
  initialization_options: unknown | null;
  enabled: boolean;
};

type ServerDraft = { executablePath: string; argumentsText: string; enabled: boolean };

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
  servers: Array<{
    kind: LanguageServerKind;
    status: "completed" | "failed" | "not_configured" | "disabled" | "no_files";
    errors: number;
    error: string | null;
    server_name: string | null;
    server_version: string | null;
  }>;
};

type SemanticRunRecord = Omit<SemanticRunSummary, "servers" | "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type SemanticSymbolStateRecord = {
  symbol_id: string;
  provider_kind: LanguageServerKind;
  state: string;
  reference_locations: number;
  definitions_resolved: number;
  last_error: string | null;
};

type SemanticRelationRecord = {
  id: string;
  relationship: string;
  occurrence_file_id: string;
  target_file_id: string;
  target_symbol_id: string | null;
  occurrence_start_line: number;
  occurrence_start_column: number;
  target_start_line: number;
  target_start_column: number;
  provider_kind: LanguageServerKind;
};

type SemanticImportResolutionRecord = {
  id: string;
  source_file_id: string;
  target_file_id: string;
  provider_kind: LanguageServerKind;
  target_start_line: number;
  target_start_column: number;
};

type QualityRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  rules_evaluated: number;
  observations: number;
  findings_opened: number;
  findings_refreshed: number;
  findings_resolved: number;
  oversized_definitions: number;
  deep_declarations: number;
  high_fan_out_files: number;
  dependency_cycles: number;
  duration_ms: number;
};

type QualityRunRecord = Omit<QualityRunSummary, "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type QualityFindingRecord = {
  id: string;
  project_id: string;
  run_id: string;
  rule_id: string;
  severity: string;
  confidence: number | null;
  title: string;
  description: string;
  file_id: string | null;
  symbol_id: string | null;
  source_start_line: number | null;
  source_end_line: number | null;
  status: string;
  fingerprint: string;
  rule_version: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
};

type FindingEvidenceRecord = {
  id: string;
  finding_id: string;
  evidence_type: string;
  uri: string | null;
  line_start: number | null;
  line_end: number | null;
  summary: string;
  metadata_json: string;
};

type QualityRuleRecord = {
  id: string;
  title: string;
  description: string;
  threshold: string;
};

type SecurityRunSummary = {
  project_id: string;
  run_id: string;
  status: AnalysisStatus;
  coverage_complete: boolean;
  files_considered: number;
  files_analyzed: number;
  files_stale: number;
  files_skipped: number;
  observations: number;
  findings_opened: number;
  findings_refreshed: number;
  findings_resolved: number;
  hardcoded_credentials: number;
  dynamic_execution: number;
  weak_crypto: number;
  unsafe_c_apis: number;
  duration_ms: number;
};

type SecurityRunRecord = Omit<SecurityRunSummary, "duration_ms"> & {
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

type SecurityFindingRecord = {
  id: string;
  project_id: string;
  run_id: string;
  rule_id: string;
  severity: string;
  confidence: number | null;
  title: string;
  description: string;
  file_id: string | null;
  symbol_id: string | null;
  source_start_line: number | null;
  source_end_line: number | null;
  cwe: string | null;
  owasp: string | null;
  status: string;
  fingerprint: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
};

type SecurityRuleRecord = {
  id: string;
  title: string;
  description: string;
  cwe: string;
  owasp: string | null;
  confidence: number;
};

const SERVER_KINDS: LanguageServerKind[] = ["typescript", "pyright", "rust_analyzer"];
const SERVER_LABELS: Record<LanguageServerKind, string> = {
  typescript: "TypeScript / JavaScript",
  pyright: "Python / Pyright",
  rust_analyzer: "Rust Analyzer",
};
const emptyServerDrafts = (): Record<LanguageServerKind, ServerDraft> => ({
  typescript: { executablePath: "", argumentsText: "", enabled: true },
  pyright: { executablePath: "", argumentsText: "", enabled: true },
  rust_analyzer: { executablePath: "", argumentsText: "", enabled: true },
});

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

  const [serverDrafts, setServerDrafts] = useState<Record<LanguageServerKind, ServerDraft>>(emptyServerDrafts);
  const [semanticTrusted, setSemanticTrusted] = useState(false);
  const [semanticBusy, setSemanticBusy] = useState(false);
  const [semanticSummary, setSemanticSummary] = useState<SemanticRunSummary | null>(null);
  const [semanticHistory, setSemanticHistory] = useState<SemanticRunRecord[]>([]);
  const [semanticState, setSemanticState] = useState<SemanticSymbolStateRecord | null>(null);
  const [semanticRelations, setSemanticRelations] = useState<SemanticRelationRecord[]>([]);
  const [semanticImports, setSemanticImports] = useState<SemanticImportResolutionRecord[]>([]);

  const [qualityBusy, setQualityBusy] = useState(false);
  const [qualitySummary, setQualitySummary] = useState<QualityRunSummary | null>(null);
  const [qualityHistory, setQualityHistory] = useState<QualityRunRecord[]>([]);
  const [qualityFindings, setQualityFindings] = useState<QualityFindingRecord[]>([]);
  const [qualityRules, setQualityRules] = useState<QualityRuleRecord[]>([]);
  const [findingFilter, setFindingFilter] = useState<FindingFilter>("open");
  const [selectedFinding, setSelectedFinding] = useState<QualityFindingRecord | null>(null);
  const [findingEvidence, setFindingEvidence] = useState<FindingEvidenceRecord[]>([]);

  const [securityBusy, setSecurityBusy] = useState(false);
  const [securitySummary, setSecuritySummary] = useState<SecurityRunSummary | null>(null);
  const [securityHistory, setSecurityHistory] = useState<SecurityRunRecord[]>([]);
  const [securityFindings, setSecurityFindings] = useState<SecurityFindingRecord[]>([]);
  const [securityRules, setSecurityRules] = useState<SecurityRuleRecord[]>([]);
  const [securityFilter, setSecurityFilter] = useState<FindingFilter>("open");
  const [selectedSecurityFinding, setSelectedSecurityFinding] = useState<SecurityFindingRecord | null>(null);
  const [securityEvidence, setSecurityEvidence] = useState<FindingEvidenceRecord[]>([]);

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
    const next = emptyServerDrafts();
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

  async function loadQualityWorkspace(projectId: string, filter: FindingFilter = findingFilter) {
    const status = filter === "all" ? null : filter;
    const [findings, runs, rules] = await Promise.all([
      invoke<QualityFindingRecord[]>("list_quality_findings", { projectId, status, limit: 300 }),
      invoke<QualityRunRecord[]>("quality_history", { projectId, limit: 30 }),
      invoke<QualityRuleRecord[]>("list_quality_rules"),
    ]);
    setQualityFindings(findings);
    setQualityHistory(runs);
    setQualityRules(rules);
    if (selectedFinding && !findings.some((finding) => finding.id === selectedFinding.id)) {
      setSelectedFinding(null);
      setFindingEvidence([]);
    }
  }

  async function loadSecurityWorkspace(projectId: string, filter: FindingFilter = securityFilter) {
    const status = filter === "all" ? null : filter;
    const [findings, runs, rules] = await Promise.all([
      invoke<SecurityFindingRecord[]>("list_security_findings", { projectId, status, limit: 300 }),
      invoke<SecurityRunRecord[]>("security_history", { projectId, limit: 30 }),
      invoke<SecurityRuleRecord[]>("list_security_rules"),
    ]);
    setSecurityFindings(findings);
    setSecurityHistory(runs);
    setSecurityRules(rules);
    if (selectedSecurityFinding && !findings.some((finding) => finding.id === selectedSecurityFinding.id)) {
      setSelectedSecurityFinding(null);
      setSecurityEvidence([]);
    }
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
      setSelectedFinding(null);
      setSelectedSecurityFinding(null);
      setFileSymbols([]);
      setDependencies([]);
      setDependents([]);
      setImpact(null);
      setSymbolResults([]);
      setSemanticState(null);
      setSemanticRelations([]);
      setSemanticImports([]);
      setSemanticSummary(null);
      setQualitySummary(null);
      setSecuritySummary(null);
      setFindingEvidence([]);
      setSecurityEvidence([]);
      await Promise.all([
        loadProject(indexSummary.project_id),
        loadSemanticWorkspace(indexSummary.project_id),
        loadQualityWorkspace(indexSummary.project_id),
        loadSecurityWorkspace(indexSummary.project_id),
      ]);
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
    setSelectedFile(file);
    setSelectedSymbol(null);
    setSemanticState(null);
    setSemanticRelations([]);
    setError(null);
    try {
      const [symbols, imports, incoming, impactReport, lspImports] = await Promise.all([
        invoke<SymbolRecord[]>("list_file_symbols", { fileId: file.id, limit: 300 }),
        invoke<ImportReferenceRecord[]>("list_dependencies", { fileId: file.id, limit: 200 }),
        invoke<ImportReferenceRecord[]>("list_dependents", { fileId: file.id, limit: 200 }),
        invoke<ImpactReport | null>("analyze_file_impact", { fileId: file.id, maxDepth: 6, limit: 200 }),
        invoke<SemanticImportResolutionRecord[]>("list_file_semantic_imports", { fileId: file.id, limit: 200 }),
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
    setServerDrafts((current) => ({ ...current, [kind]: { ...current[kind], ...patch } }));
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
          arguments: draft.argumentsText.split("\n").map((value) => value.trim()).filter(Boolean),
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
    setError(null);
    try {
      await invoke<boolean>("cancel_semantic_enrichment");
    } catch (value) {
      setError(String(value));
    }
  }

  async function runQualityAnalysis() {
    if (!summary) return;
    setQualityBusy(true);
    setError(null);
    try {
      const result = await invoke<QualityRunSummary>("run_code_quality", { projectId: summary.project_id });
      setQualitySummary(result);
      await loadQualityWorkspace(summary.project_id);
    } catch (value) {
      setError(String(value));
    } finally {
      setQualityBusy(false);
    }
  }

  async function selectFinding(finding: QualityFindingRecord) {
    setSelectedFinding(finding);
    setError(null);
    try {
      const evidence = await invoke<FindingEvidenceRecord[]>("list_finding_evidence", {
        findingId: finding.id,
        limit: 200,
      });
      setFindingEvidence(evidence);
    } catch (value) {
      setFindingEvidence([]);
      setError(String(value));
    }
  }

  async function changeFindingFilter(filter: FindingFilter) {
    setFindingFilter(filter);
    if (!summary) return;
    setSelectedFinding(null);
    setFindingEvidence([]);
    setError(null);
    try {
      await loadQualityWorkspace(summary.project_id, filter);
    } catch (value) {
      setError(String(value));
    }
  }

  async function runSecurityAnalysis() {
    if (!summary) return;
    setSecurityBusy(true);
    setError(null);
    try {
      const result = await invoke<SecurityRunSummary>("run_security_analysis", {
        projectId: summary.project_id,
      });
      setSecuritySummary(result);
      await loadSecurityWorkspace(summary.project_id);
    } catch (value) {
      setError(String(value));
    } finally {
      setSecurityBusy(false);
    }
  }

  async function selectSecurityFinding(finding: SecurityFindingRecord) {
    setSelectedSecurityFinding(finding);
    setError(null);
    try {
      const evidence = await invoke<FindingEvidenceRecord[]>("list_security_evidence", {
        findingId: finding.id,
        limit: 200,
      });
      setSecurityEvidence(evidence);
    } catch (value) {
      setSecurityEvidence([]);
      setError(String(value));
    }
  }

  async function changeSecurityFilter(filter: FindingFilter) {
    setSecurityFilter(filter);
    if (!summary) return;
    setSelectedSecurityFinding(null);
    setSecurityEvidence([]);
    setError(null);
    try {
      await loadSecurityWorkspace(summary.project_id, filter);
    } catch (value) {
      setError(String(value));
    }
  }

  async function openView(next: View) {
    if (next !== "overview" && !summary) return;
    setView(next);
    setError(null);
    try {
      if (next === "semantics" && summary) await loadSemanticWorkspace(summary.project_id);
      if (next === "findings" && summary) await loadQualityWorkspace(summary.project_id);
      if (next === "security" && summary) await loadSecurityWorkspace(summary.project_id);
    } catch (value) {
      setError(String(value));
    }
  }

  const title =
    view === "overview"
      ? "CodeTwin ML"
      : view === "digital-twin"
        ? "Software Digital Twin"
        : view === "semantics"
          ? "Semantic Navigation"
          : view === "findings"
            ? "Code Quality Findings"
            : "AppSec Review";

  const subtitle =
    view === "overview"
      ? "Engineering intelligence workstation"
      : view === "digital-twin"
        ? "Persisted files, symbols, dependencies, proven relationships, and bounded impact"
        : view === "semantics"
          ? "Explicitly trusted language servers enriching persisted source evidence"
          : view === "findings"
            ? "Deterministic findings derived only from persisted source structure and resolved local dependencies"
            : "Evidence-backed security review signals from hash-verified indexed source";

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brand" aria-label="CodeTwin ML"><img src="/app-icon.png" alt="" /></div>
        <NavButton active={view === "overview"} onClick={() => void openView("overview")}>Overview</NavButton>
        <NavButton active={view === "digital-twin"} disabled={!summary} onClick={() => void openView("digital-twin")}>Digital Twin</NavButton>
        <NavButton active={view === "semantics"} disabled={!summary} onClick={() => void openView("semantics")}>Semantics</NavButton>
        <NavButton active={view === "findings"} disabled={!summary} onClick={() => void openView("findings")}>Findings</NavButton>
        <NavButton active={view === "security"} disabled={!summary} onClick={() => void openView("security")}>Security</NavButton>
        <button className="nav" disabled>Repair Lab</button>
      </aside>

      <section className="workspace">
        <header>
          <div>
            <p className="eyebrow">LOCAL FIRST</p>
            <h1>{title}</h1>
            <p>{subtitle}</p>
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
                <button onClick={() => void analyze()} disabled={!path.trim() || busy}>{busy ? "Indexing…" : "Inspect & index"}</button>
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
                <h2>Files</h2>
                <p>{graph ? `${graph.node_count} active nodes · ${graph.edge_count} active edges` : "Loading graph summary"}</p>
                <div className="row search-row">
                  <input aria-label="Search project files" value={fileSearch} onChange={(event) => setFileSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void searchFiles()} placeholder="Search relative path" />
                  <button onClick={() => void searchFiles()}>Search</button>
                </div>
                <div className="result-list">
                  {files.map((file) => (
                    <button key={file.id} className={`result-item ${selectedFile?.id === file.id ? "selected" : ""}`} onClick={() => void selectFile(file)}>
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
                  <input aria-label="Search symbols" value={symbolSearch} onChange={(event) => setSymbolSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void runSymbolSearch()} placeholder="Name or qualified name" />
                  <button onClick={() => void runSymbolSearch()}>Search</button>
                </div>
                <div className="result-list small-list">
                  {symbolResults.map((symbol) => (
                    <button key={symbol.id} className="result-item" onClick={() => void selectSymbol(symbol)}>
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
                        <button key={symbol.id} className="result-item" onClick={() => void selectSymbol(symbol)}>
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
                    <h3>LSP import evidence</h3>
                    <div className="relationship-list">
                      {semanticImports.map((item) => (
                        <div key={item.id} className="relationship-item">
                          <strong>{item.provider_kind}</strong>
                          <span>{item.source_file_id} → {item.target_file_id}</span>
                          <small>{item.target_start_line}:{item.target_start_column}</small>
                        </div>
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
                        <div key={file.file_id} className="relationship-item">
                          <strong>{file.relative_path}</strong>
                          <span>{file.language ?? "Unknown"} · depth {file.depth}</span>
                          <small className="mono">via {file.via_raw_specifier}</small>
                        </div>
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
                      <dt>Name</dt><dd>{selectedSymbol.name}</dd>
                      <dt>Qualified</dt><dd>{selectedSymbol.qualified_name ?? "Unavailable"}</dd>
                      <dt>Kind</dt><dd>{selectedSymbol.kind}</dd>
                      <dt>Range</dt><dd>{selectedSymbol.start_line}:{selectedSymbol.start_column}–{selectedSymbol.end_line}:{selectedSymbol.end_column}</dd>
                      <dt>Parent</dt><dd className="mono">{selectedSymbol.parent_symbol_id ?? "None"}</dd>
                      <dt>Fingerprint</dt><dd className="mono">{selectedSymbol.fingerprint}</dd>
                    </dl>
                    <h3>LSP semantic state</h3>
                    {semanticState ? (
                      <p>{semanticState.provider_kind} · {semanticState.state} · {semanticState.reference_locations} references · {semanticState.definitions_resolved} local definitions</p>
                    ) : <p className="empty">No current semantic state for this symbol.</p>}
                    <div className="relationship-list">
                      {semanticRelations.map((relation) => (
                        <div key={relation.id} className="relationship-item">
                          <strong>{relation.relationship}</strong>
                          <span>{relation.provider_kind} · {relation.occurrence_file_id}:{relation.occurrence_start_line}:{relation.occurrence_start_column}</span>
                          <small className="mono">target {relation.target_symbol_id ?? relation.target_file_id} · {relation.target_start_line}:{relation.target_start_column}</small>
                        </div>
                      ))}
                      {!semanticRelations.length && <p className="empty">No current persisted LSP relationship evidence.</p>}
                    </div>
                  </>
                ) : <p className="empty">Select a symbol from the file or bounded search results.</p>}
              </section>

              <section className="panel compact">
                <h2>Index history</h2>
                <HistoryList items={history.map((run) => ({
                  id: run.id,
                  title: run.status,
                  subtitle: run.started_at ?? "time unavailable",
                  detail: `${run.delta.files_added}+ / ${run.delta.files_modified}~ / ${run.delta.files_deleted}− · ${run.duration_ms ?? 0} ms`,
                }))} empty="No index history." />
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
                      <div className="button-row">
                        <button onClick={() => void saveServerConfig(kind)}>Save</button>
                        <button className="secondary" onClick={() => void removeServerConfig(kind)}>Remove</button>
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="panel">
              <h2>Semantic enrichment run</h2>
              <label className="trust-row"><input type="checkbox" checked={semanticTrusted} onChange={(event) => setSemanticTrusted(event.target.checked)} /> I trust this project and allow the configured external language servers to inspect its source files.</label>
              <p>Runs are bounded to 100 files, 500 symbols, 25 references per symbol, 1,500 definition lookups, and a 5-second request timeout.</p>
              <div className="button-row">
                <button onClick={() => void runSemanticEnrichment()} disabled={semanticBusy || !semanticTrusted}>{semanticBusy ? "Running…" : "Run semantic enrichment"}</button>
                <button className="secondary" onClick={() => void cancelSemanticEnrichment()} disabled={!semanticBusy}>Cancel</button>
              </div>
              {semanticSummary && (
                <section className="grid semantic-metrics">
                  <Metric label="files" value={semanticSummary.files_processed} />
                  <Metric label="symbols" value={semanticSummary.symbols_processed} />
                  <Metric label="matched" value={semanticSummary.symbols_matched} />
                  <Metric label="references" value={semanticSummary.reference_locations} />
                  <Metric label="definitions" value={semanticSummary.definitions_resolved} />
                  <Metric label="relations" value={semanticSummary.relations_persisted} />
                  <Metric label="graph edges" value={semanticSummary.graph_edges_materialized} />
                  <Metric label="LSP imports" value={semanticSummary.imports_upgraded} />
                  <Metric label="errors" value={semanticSummary.errors} />
                  <Metric label="duration" value={`${semanticSummary.duration_ms} ms`} />
                </section>
              )}
              {semanticSummary?.servers.map((server) => (
                <div className="history-item" key={server.kind}>
                  <div><strong>{SERVER_LABELS[server.kind]}</strong><span>{server.server_name ?? "server name unavailable"} {server.server_version ?? ""}</span></div>
                  <span>{server.status} · {server.errors} errors</span>
                  {server.error && <small className="error">{server.error}</small>}
                </div>
              ))}
            </section>

            <section className="panel compact">
              <h2>Semantic history</h2>
              <HistoryList items={semanticHistory.map((run) => ({
                id: run.run_id,
                title: run.status,
                subtitle: run.started_at ?? "time unavailable",
                detail: `${run.definitions_resolved} definitions · ${run.graph_edges_materialized} edges · ${run.errors} errors · ${run.duration_ms ?? 0} ms`,
              }))} empty="No LSP semantic run has been persisted for this project." />
            </section>
          </section>
        )}

        {view === "findings" && summary && (
          <section className="findings-workspace">
            <section className="panel">
              <div className="section-heading">
                <div>
                  <h2>Deterministic code quality</h2>
                  <p>Rules consume only active persisted symbols and resolved-local import evidence. No repository command, model score, or guessed relationship is used.</p>
                </div>
                <button onClick={() => void runQualityAnalysis()} disabled={qualityBusy}>{qualityBusy ? "Analyzing…" : "Run quality analysis"}</button>
              </div>
              {qualitySummary && (
                <section className="grid quality-metrics">
                  <Metric label="rules" value={qualitySummary.rules_evaluated} />
                  <Metric label="observations" value={qualitySummary.observations} />
                  <Metric label="opened" value={qualitySummary.findings_opened} />
                  <Metric label="refreshed" value={qualitySummary.findings_refreshed} />
                  <Metric label="resolved" value={qualitySummary.findings_resolved} />
                  <Metric label="large definitions" value={qualitySummary.oversized_definitions} />
                  <Metric label="deep declarations" value={qualitySummary.deep_declarations} />
                  <Metric label="high fan-out" value={qualitySummary.high_fan_out_files} />
                  <Metric label="cycles" value={qualitySummary.dependency_cycles} />
                  <Metric label="duration" value={`${qualitySummary.duration_ms} ms`} />
                </section>
              )}
            </section>

            <section className="quality-layout">
              <div className="twin-column">
                <section className="panel compact">
                  <div className="section-heading">
                    <div><h2>Findings</h2><p>{qualityFindings.length} bounded result{qualityFindings.length === 1 ? "" : "s"}</p></div>
                    <FindingFilterSelect value={findingFilter} onChange={(filter) => void changeFindingFilter(filter)} label="Finding status filter" />
                  </div>
                  <div className="result-list">
                    {qualityFindings.map((finding) => (
                      <button key={finding.id} className={`result-item finding-item ${selectedFinding?.id === finding.id ? "selected" : ""}`} onClick={() => void selectFinding(finding)}>
                        <strong>{finding.title}</strong>
                        <span><Severity value={finding.severity} /> · {finding.status}</span>
                        <small className="mono">{finding.rule_id}</small>
                      </button>
                    ))}
                    {!qualityFindings.length && <p className="empty">No persisted findings match this status.</p>}
                  </div>
                </section>

                <section className="panel compact">
                  <h2>Rule set</h2>
                  <div className="relationship-list">
                    {qualityRules.map((rule) => (
                      <div className="relationship-item" key={rule.id}>
                        <strong>{rule.title}</strong>
                        <span>{rule.threshold}</span>
                        <small>{rule.description}</small>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

              <div className="twin-column wide">
                <section className="panel compact">
                  <h2>Finding evidence</h2>
                  {selectedFinding ? (
                    <>
                      <div className="finding-title-row"><Severity value={selectedFinding.severity} /><strong>{selectedFinding.title}</strong></div>
                      <p>{selectedFinding.description}</p>
                      <dl className="metadata-grid">
                        <dt>Status</dt><dd>{selectedFinding.status}</dd>
                        <dt>Rule</dt><dd className="mono">{selectedFinding.rule_id}</dd>
                        <dt>Confidence</dt><dd>{selectedFinding.confidence ?? "Unavailable"}</dd>
                        <dt>Source range</dt><dd>{selectedFinding.source_start_line ?? "—"}–{selectedFinding.source_end_line ?? "—"}</dd>
                        <dt>First seen</dt><dd>{selectedFinding.first_seen}</dd>
                        <dt>Last seen</dt><dd>{selectedFinding.last_seen}</dd>
                      </dl>
                      <EvidenceList evidence={findingEvidence} empty="No evidence records are persisted for this finding." />
                    </>
                  ) : <p className="empty">Select a finding to inspect its persisted source or dependency evidence.</p>}
                </section>

                <section className="panel compact">
                  <h2>Quality history</h2>
                  <HistoryList items={qualityHistory.map((run) => ({
                    id: run.run_id,
                    title: run.status,
                    subtitle: run.started_at ?? "time unavailable",
                    detail: `${run.observations} observations · ${run.findings_opened} opened · ${run.findings_resolved} resolved · ${run.duration_ms ?? 0} ms`,
                  }))} empty="No code quality run has been persisted for this project." />
                </section>
              </div>
            </section>
          </section>
        )}

        {view === "security" && summary && (
          <section className="security-workspace">
            <section className="panel">
              <div className="section-heading">
                <div>
                  <h2>Deterministic AppSec review</h2>
                  <p>These are review signals backed by hash-verified indexed source. They are not confirmed exploits and do not claim taint flow or attacker reachability.</p>
                </div>
                <button onClick={() => void runSecurityAnalysis()} disabled={securityBusy}>{securityBusy ? "Reviewing…" : "Run AppSec review"}</button>
              </div>
              {securitySummary && (
                <>
                  {!securitySummary.coverage_complete && (
                    <p className="warning banner" role="status">Coverage is incomplete: stale or skipped files were not used as evidence. Existing missing AppSec findings were not auto-resolved.</p>
                  )}
                  <section className="grid security-metrics">
                    <Metric label="coverage" value={securitySummary.coverage_complete ? "complete" : "incomplete"} />
                    <Metric label="files analyzed" value={`${securitySummary.files_analyzed}/${securitySummary.files_considered}`} />
                    <Metric label="stale files" value={securitySummary.files_stale} />
                    <Metric label="skipped files" value={securitySummary.files_skipped} />
                    <Metric label="observations" value={securitySummary.observations} />
                    <Metric label="opened" value={securitySummary.findings_opened} />
                    <Metric label="refreshed" value={securitySummary.findings_refreshed} />
                    <Metric label="resolved" value={securitySummary.findings_resolved} />
                    <Metric label="credential literals" value={securitySummary.hardcoded_credentials} />
                    <Metric label="dynamic execution" value={securitySummary.dynamic_execution} />
                    <Metric label="weak hash" value={securitySummary.weak_crypto} />
                    <Metric label="unsafe C APIs" value={securitySummary.unsafe_c_apis} />
                    <Metric label="duration" value={`${securitySummary.duration_ms} ms`} />
                  </section>
                </>
              )}
            </section>

            <section className="quality-layout">
              <div className="twin-column">
                <section className="panel compact">
                  <div className="section-heading">
                    <div><h2>Security review findings</h2><p>{securityFindings.length} bounded result{securityFindings.length === 1 ? "" : "s"}</p></div>
                    <FindingFilterSelect value={securityFilter} onChange={(filter) => void changeSecurityFilter(filter)} label="Security finding status filter" />
                  </div>
                  <div className="result-list">
                    {securityFindings.map((finding) => (
                      <button key={finding.id} className={`result-item finding-item ${selectedSecurityFinding?.id === finding.id ? "selected" : ""}`} onClick={() => void selectSecurityFinding(finding)}>
                        <strong>{finding.title}</strong>
                        <span><Severity value={finding.severity} /> · {finding.status} · {finding.cwe ?? "CWE unavailable"}</span>
                        <small className="mono">{finding.rule_id}</small>
                      </button>
                    ))}
                    {!securityFindings.length && <p className="empty">No persisted AppSec findings match this status.</p>}
                  </div>
                </section>

                <section className="panel compact">
                  <h2>Security rule set</h2>
                  <div className="relationship-list">
                    {securityRules.map((rule) => (
                      <div className="relationship-item" key={rule.id}>
                        <strong>{rule.title}</strong>
                        <span>{rule.cwe}{rule.owasp ? ` · ${rule.owasp}` : ""} · confidence {rule.confidence}</span>
                        <small>{rule.description}</small>
                      </div>
                    ))}
                  </div>
                </section>
              </div>

              <div className="twin-column wide">
                <section className="panel compact">
                  <h2>Security evidence</h2>
                  {selectedSecurityFinding ? (
                    <>
                      <div className="finding-title-row"><Severity value={selectedSecurityFinding.severity} /><strong>{selectedSecurityFinding.title}</strong></div>
                      <p>{selectedSecurityFinding.description}</p>
                      <dl className="metadata-grid">
                        <dt>Status</dt><dd>{selectedSecurityFinding.status}</dd>
                        <dt>Rule</dt><dd className="mono">{selectedSecurityFinding.rule_id}</dd>
                        <dt>CWE</dt><dd>{selectedSecurityFinding.cwe ?? "Unavailable"}</dd>
                        <dt>OWASP</dt><dd>{selectedSecurityFinding.owasp ?? "Not mapped"}</dd>
                        <dt>Confidence</dt><dd>{selectedSecurityFinding.confidence ?? "Unavailable"}</dd>
                        <dt>Source range</dt><dd>{selectedSecurityFinding.source_start_line ?? "—"}–{selectedSecurityFinding.source_end_line ?? "—"}</dd>
                        <dt>First seen</dt><dd>{selectedSecurityFinding.first_seen}</dd>
                        <dt>Last seen</dt><dd>{selectedSecurityFinding.last_seen}</dd>
                      </dl>
                      <p className="security-note">Credential values are redacted before persistence. Evidence metadata contains hashes, positions, and rule metadata only.</p>
                      <EvidenceList evidence={securityEvidence} empty="No source evidence is persisted for this security finding." />
                    </>
                  ) : <p className="empty">Select a security review finding to inspect its redacted persisted evidence.</p>}
                </section>

                <section className="panel compact">
                  <h2>Security history</h2>
                  <HistoryList items={securityHistory.map((run) => ({
                    id: run.run_id,
                    title: `${run.status} · ${run.coverage_complete ? "complete coverage" : "incomplete coverage"}`,
                    subtitle: run.started_at ?? "time unavailable",
                    detail: `${run.observations} observations · ${run.findings_opened} opened · ${run.findings_resolved} resolved · ${run.files_stale} stale · ${run.duration_ms ?? 0} ms`,
                  }))} empty="No AppSec review run has been persisted for this project." />
                </section>
              </div>
            </section>
          </section>
        )}
      </section>
    </main>
  );
}

function NavButton({ active, disabled, onClick, children }: { active: boolean; disabled?: boolean; onClick: () => void; children: string }) {
  return <button className={`nav ${active ? "active" : ""}`} disabled={disabled} onClick={onClick}>{children}</button>;
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <article className="card"><h3>{label}</h3><p>{value}</p></article>;
}

function Severity({ value }: { value: string }) {
  return <span className={`severity severity-${value}`}>{value}</span>;
}

function FindingFilterSelect({ value, onChange, label }: { value: FindingFilter; onChange: (value: FindingFilter) => void; label: string }) {
  return (
    <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value as FindingFilter)}>
      <option value="open">Open</option>
      <option value="resolved">Resolved</option>
      <option value="all">All</option>
    </select>
  );
}

function EvidenceList({ evidence, empty }: { evidence: FindingEvidenceRecord[]; empty: string }) {
  return (
    <div className="relationship-list">
      {evidence.map((item) => (
        <div className="relationship-item" key={item.id}>
          <strong>{item.evidence_type}</strong>
          <span>{item.uri ?? "project-level evidence"}{item.line_start ? `:${item.line_start}` : ""}</span>
          <small>{item.summary}</small>
        </div>
      ))}
      {!evidence.length && <p className="empty">{empty}</p>}
    </div>
  );
}

function HistoryList({ items, empty }: { items: Array<{ id: string; title: string; subtitle: string; detail: string }>; empty: string }) {
  return (
    <div className="history-list">
      {items.map((item) => (
        <div key={item.id} className="history-item">
          <div><strong>{item.title}</strong><span>{item.subtitle}</span></div>
          <span>{item.detail}</span>
        </div>
      ))}
      {!items.length && <p className="empty">{empty}</p>}
    </div>
  );
}

function RelationshipList({ title, records, direction }: { title: string; records: ImportReferenceRecord[]; direction: "out" | "in" }) {
  return (
    <div>
      <h3>{title}</h3>
      <div className="relationship-list">
        {records.map((record) => (
          <div key={record.id} className="relationship-item">
            <strong>{record.raw_specifier}</strong>
            <span>{record.resolution_state}</span>
            <small className="mono">{direction === "out" ? record.resolved_target_file_id ?? "no local target" : record.source_file_id}</small>
          </div>
        ))}
        {!records.length && <p className="empty">No persisted relationships.</p>}
      </div>
    </div>
  );
}
