# Software Digital Twin

CodeTwin ML persists a local Software Digital Twin in SQLite. The schema stores projects, analysis runs, files, symbols, graph nodes, graph edges, normalized findings, evidence, artifacts, settings, and import observations. File, symbol, node, and edge identities are deterministic so incremental indexing updates existing entities rather than creating arbitrary duplicates.

## Persisted source index

`ProjectIndexService` performs content-hash incremental indexing in a transaction. Active files whose content identity is unchanged are reused; changed files are reparsed and rewritten; files no longer present are marked inactive together with stale symbols and graph materialization. Index runs persist analyzer/query/config identity, timing, counts, parse errors, and skipped-file totals.

## Graph evidence

The graph currently materializes deterministic Project, File, and Symbol nodes plus relationships directly supported by indexed structure and local import resolution. Unresolved or external imports remain observations and do not become fabricated local dependency edges.

The UI and service layer use bounded queries rather than loading an entire repository graph into memory or React.

## Query and navigation services

The core query service supports active file lookup, bounded symbol listing/search, graph summary and neighborhoods, direct dependencies/dependents, and index history. Tauri handlers delegate to core services instead of embedding persistence logic in command functions.

## Impact analysis

File-level impact analysis traverses the persisted local-import relation in reverse and returns only dependents supported by `resolved_local` import evidence. Traversal is deterministic, cycle-safe, depth-bounded, result-bounded, and explicitly reports truncation. See `IMPACT_ANALYSIS.md` for the evidence model and limitations.

Future semantic analyzers may add symbol references, call relationships, path-alias/package resolution, runtime traces, and other relationship types only when those edges can be supported by concrete evidence.
