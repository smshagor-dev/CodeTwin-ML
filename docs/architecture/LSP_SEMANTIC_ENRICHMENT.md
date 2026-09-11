# LSP Semantic Enrichment

CodeTwin ML uses language servers as an optional, explicit semantic enrichment layer on top of the persisted Tree-sitter source index. Passive source indexing remains non-executing. Language servers are never discovered or launched by the source indexer.

## Trust and process boundary

Semantic enrichment requires explicit project trust for every run. A language-server configuration must name an absolute executable path. CodeTwin canonicalizes that path, requires a regular file, rejects executables located inside the analyzed project, and launches the executable directly without a shell. On Windows, `.cmd`, `.bat`, and `.ps1` launchers are rejected. Arguments are bounded and passed directly to the configured executable.

CodeTwin does not execute package scripts, repository hooks, test commands, compilers, or a repository-provided language-server binary as part of semantic enrichment. The LSP client refuses workspace edits. Rust Analyzer initialization disables proc macros, Cargo build scripts, and check-on-save in CodeTwin's default options. Language-server behavior outside the LSP protocol remains part of the configured external tool's trust boundary, which is why project trust is mandatory.

## Supported providers

The current semantic layer supports explicitly configured providers for:

- TypeScript and JavaScript
- Python through Pyright
- Rust through Rust Analyzer

Provider configuration is persisted in the application settings table. CodeTwin does not auto-install or auto-discover these executables in this subsystem.

## Evidence workflow

A semantic run starts from active, already indexed files and symbols. Before a file is sent to a language server, CodeTwin reads it from the canonical project root and verifies that its SHA-256 content hash still matches the persisted index. Changed, unreadable, oversized, invalid, or out-of-root files are rejected from the semantic run and previous semantic evidence for those files is invalidated.

For each supported file, CodeTwin uses `textDocument/documentSymbol` to conservatively map language-server symbols to persisted Tree-sitter symbols. It then uses `textDocument/references` and `textDocument/definition`. LSP UTF-16 character offsets are converted to the byte-column convention used by the persisted source index.

A `semantic_relations` record stores the subject symbol, occurrence file and range, optional containing symbol, definition file and range, optional target symbol, provider identity, server identity, and source/target content hashes. A `SYMBOL_REFERENCES_SYMBOL` graph edge is materialized only when both the occurrence container and target can be mapped to active persisted symbols. Ambiguous or external targets remain evidence without a fabricated symbol edge.

For TypeScript/JavaScript, unresolved import observations may also be checked through definition lookup. A proven local result is persisted separately in `semantic_import_resolutions` and can materialize `FILE_IMPORTS_FILE_LSP`. This never overwrites the deterministic static import-resolution state.

## Staleness

Semantic evidence is content-bound. SQLite triggers deactivate semantic relations, semantic import resolutions, and their graph edges when an involved file hash changes or a file is deactivated. Symbol deactivation also invalidates relations that depend on that symbol. Symbol semantic states become `stale` rather than being presented as current evidence.

Queries additionally require active files/symbols and matching persisted content hashes, so stale rows cannot become current results merely because a trigger was missed by a future migration.

## Bounded execution

The desktop request applies hard upper bounds to files, symbols, references per symbol, definition lookups, source-file size, cached snapshots, LSP message size, process arguments, and individual request timeout. The UI currently requests at most 100 files, 500 symbols, 25 references per symbol, 1,500 definition lookups, and a 5-second per-request timeout.

Only one semantic enrichment run can be active from the desktop at a time. The run uses a dedicated SQLite connection so the primary desktop database mutex is not held while waiting for external LSP I/O. Cancellation is cooperative and checked between bounded operations.

## Persisted status and queries

Each semantic run is recorded as an `analysis_runs` row with `run_kind = 'lsp_semantic'`. Additional metrics include processed files and symbols, matched symbols, reference locations, resolved definitions, persisted relations, graph edges, LSP-proven imports, errors, and duration.

The application exposes bounded queries for semantic run history, per-symbol semantic state and relationships, and per-file LSP import evidence. The Semantics workspace displays only these persisted results and actual provider status.

## Not claimed by this subsystem

This subsystem does not claim a complete call graph, control-flow graph, data-flow graph, dynamic dispatch resolution, framework routing, runtime behavior, vulnerability result, code-quality finding, or repair verification. Those require separate evidence-producing analyzers and tests.
