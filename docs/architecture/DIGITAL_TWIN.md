# Software Digital Twin

CodeTwin ML persists a local Software Digital Twin in SQLite. The schema stores projects, analysis runs, files, symbols, graph nodes, graph edges, normalized findings, evidence, artifacts, settings, import observations, source-backed symbol-reference observations, conservative semantic-resolution state, and optional LSP semantic evidence. File, symbol, node, and edge identities are deterministic so incremental indexing updates existing entities rather than creating arbitrary duplicates.

## Persisted source index

`ProjectIndexService` performs content-hash incremental indexing in a transaction. Active files whose content identity is unchanged are reused; changed files are reparsed and rewritten; files no longer present are marked inactive together with stale symbols and graph materialization. Index runs persist analyzer/query/config identity, timing, counts, parse errors, and skipped-file totals.

Passive source indexing does not execute repository commands, package scripts, tests, compilers, hooks, or language servers.

## Graph evidence

The baseline graph materializes deterministic Project, File, and Symbol nodes plus relationships directly supported by indexed structure and deterministic local import resolution. Unresolved or external imports remain observations and do not become fabricated local dependency edges.

Additional semantic layers remain evidence-specific:

- Source-backed reference observations record syntactic reference sites without pretending the target is known.
- Conservative same-file resolution records a target only when the existing evidence uniquely proves the same-file function or class target.
- Explicit LSP enrichment can persist reference-to-definition evidence and materialize `SYMBOL_REFERENCES_SYMBOL` only when both local symbols are deterministically mapped.
- LSP-proven local import evidence is represented separately as `FILE_IMPORTS_FILE_LSP`; it does not overwrite static import resolution.

The UI and service layer use bounded queries rather than loading an entire repository graph into memory or React.

## Query and navigation services

The core query services support active file lookup, bounded symbol listing/search, graph summary and neighborhoods, direct dependencies/dependents, index history, reverse dependency impact, semantic run history, per-symbol semantic state/relations, and per-file LSP import evidence. Tauri handlers delegate to core services instead of embedding persistence logic in command functions.

## Impact analysis

File-level impact analysis traverses the persisted local-import relation in reverse and returns only dependents supported by `resolved_local` import evidence. Traversal is deterministic, cycle-safe, depth-bounded, result-bounded, and explicitly reports truncation. See `IMPACT_ANALYSIS.md` for the evidence model and limitations.

## LSP semantic enrichment

LSP enrichment is not part of passive indexing. It requires explicit project trust plus a user-configured absolute language-server executable outside the analyzed repository. Persisted semantic evidence carries source/target hashes and is invalidated when those files or symbols become stale. See `LSP_SEMANTIC_ENRICHMENT.md` for the process, evidence, security, and bounded-execution model.

## Current boundary

A complete call graph, control-flow graph, data-flow graph, dynamic dispatch model, runtime trace graph, QA/security finding graph, and repair-verification graph are not yet claimed. Those relationships will be added only when their dedicated analyzers can persist concrete evidence and regression tests.
