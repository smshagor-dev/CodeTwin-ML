import { useEffect, useMemo, useState } from "react";

import { workspaceApi } from "../api";
import { Icon } from "../Icon";
import type { SourceFileRecord, SymbolRecord } from "../types";
import { EmptyState, PageHeader, Panel, ProjectSelect, StatusBadge, shortPath } from "../ui";
import { useWorkspace } from "../WorkspaceContext";

export function CodeAnalysisPage() {
  const { projects, activeProjectId, setActiveProjectId, activeProject, reindexProject, operation, setToast } = useWorkspace();
  const [files, setFiles] = useState<SourceFileRecord[]>([]);
  const [symbols, setSymbols] = useState<SymbolRecord[]>([]);
  const [query, setQuery] = useState(() => new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("q") ?? "");
  const [kind, setKind] = useState("all");
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load(projectId: string) {
    setLoading(true);
    try {
      const [nextFiles, nextSymbols] = await Promise.all([
        workspaceApi.listFiles(projectId, null, 500),
        workspaceApi.searchSymbols(projectId, "", null, 500),
      ]);
      setFiles(nextFiles);
      setSymbols(nextSymbols);
      setSelectedFileId((current) => current && nextFiles.some((file) => file.id === current) ? current : nextFiles[0]?.id ?? null);
    } catch (error) {
      setToast({ tone: "error", message: "Could not load code index: " + String(error) });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!activeProjectId) {
      setFiles([]);
      setSymbols([]);
      return;
    }
    void load(activeProjectId);
  }, [activeProjectId]);

  const filteredSymbols = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return symbols.filter((symbol) => {
      const file = files.find((item) => item.id === symbol.file_id);
      const matchesText = !normalized || symbol.name.toLowerCase().includes(normalized) || (file?.relative_path.toLowerCase().includes(normalized) ?? false);
      const matchesKind = kind === "all" || symbol.kind === kind;
      const matchesFile = !selectedFileId || symbol.file_id === selectedFileId || Boolean(normalized);
      return matchesText && matchesKind && matchesFile;
    });
  }, [files, kind, query, selectedFileId, symbols]);

  const languages = useMemo(() => {
    const counts = new Map<string, number>();
    for (const file of files) counts.set(file.language ?? "Unknown", (counts.get(file.language ?? "Unknown") ?? 0) + 1);
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [files]);

  const kindCount = (value: string) => symbols.filter((symbol) => symbol.kind === value).length;
  const selectedFile = files.find((file) => file.id === selectedFileId) ?? null;

  if (!projects.length) {
    return <><PageHeader eyebrow="PERSISTED SOURCE INDEX" title="Code Analysis" description="Browse Tree-sitter files and symbols from the existing CodeTwin index."/>
      <EmptyState icon="code" title="Index a project first" description="Code Analysis reads the persistent project index. Add a local project folder from Projects or Dashboard."/></>;
  }

  return (
    <div>
      <PageHeader
        eyebrow="PERSISTED SOURCE INDEX"
        title="Code Analysis"
        description="Inspect indexed files and Tree-sitter symbols. This view reuses CodeTwin's existing persistent source index rather than creating a second parser."
        actions={<div className="ws-header-tools"><ProjectSelect projects={projects} value={activeProjectId} onChange={setActiveProjectId}/>{activeProject && <button className="ws-button ws-button-secondary" disabled={operation !== null} onClick={() => void reindexProject(activeProject).then(() => activeProjectId && load(activeProjectId))}><Icon name="refresh"/>Re-index</button>}</div>}
      />

      <section className="ws-analysis-metrics">
        <div><span><Icon name="file"/></span><strong>{files.length}</strong><small>Indexed files</small></div>
        <div><span><Icon name="function"/></span><strong>{kindCount("function") + kindCount("method")}</strong><small>Functions & methods</small></div>
        <div><span><Icon name="class"/></span><strong>{kindCount("class")}</strong><small>Classes</small></div>
        <div><span><Icon name="interface"/></span><strong>{kindCount("interface") + kindCount("type")}</strong><small>Interfaces & types</small></div>
      </section>

      <div className="ws-analysis-layout">
        <Panel title="Files" action={<span className="ws-count">{languages.length} languages</span>}>
          <label className="ws-search-field"><Icon name="search" size={18}/><input aria-label="Search indexed files and symbols" placeholder="Search files or symbols…" value={query} onChange={(event) => setQuery(event.target.value)}/></label>
          <div className="ws-language-strip">{languages.slice(0, 8).map(([language, count]) => <span key={language}>{language}<b>{count}</b></span>)}</div>
          <div className="ws-file-list">
            {files.filter((file) => !query.trim() || file.relative_path.toLowerCase().includes(query.trim().toLowerCase()) || symbols.some((symbol) => symbol.file_id === file.id && symbol.name.toLowerCase().includes(query.trim().toLowerCase()))).map((file) => (
              <button key={file.id} className={file.id === selectedFileId ? "selected" : ""} onClick={() => setSelectedFileId(file.id)}>
                <Icon name="file" size={17}/><span><strong title={file.relative_path}>{shortPath(file.relative_path, 46)}</strong><small>{file.language ?? "Unknown"} · {file.parse_state ?? "state unavailable"}</small></span>
              </button>
            ))}
          </div>
        </Panel>

        <Panel title={selectedFile ? "Symbols · " + selectedFile.relative_path : "Symbols"} action={
          <select aria-label="Filter symbol kind" value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="all">All kinds</option><option value="function">Functions</option><option value="method">Methods</option><option value="class">Classes</option><option value="interface">Interfaces</option><option value="type">Types</option>
          </select>
        }>
          {loading ? <p className="ws-inline-empty">Loading persistent index…</p> : (
            <div className="ws-symbol-list">
              {filteredSymbols.map((symbol) => (
                <div key={symbol.id}>
                  <span className="ws-symbol-kind">{symbol.kind}</span>
                  <p><strong>{symbol.qualified_name ?? symbol.name}</strong><small>line {symbol.start_line}:{symbol.start_column} – {symbol.end_line}:{symbol.end_column}</small></p>
                </div>
              ))}
              {!filteredSymbols.length && <p className="ws-inline-empty">No symbols match the current file, search, and type filters.</p>}
            </div>
          )}
          {selectedFile && <div className="ws-file-meta"><StatusBadge status={selectedFile.parse_state}/><span>{selectedFile.byte_size.toLocaleString()} bytes</span><span>{selectedFile.ast_root_kind ?? "AST root unavailable"}</span></div>}
        </Panel>
      </div>
    </div>
  );
}
