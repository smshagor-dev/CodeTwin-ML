# Impact Analysis

CodeTwin ML provides bounded file-level impact analysis over the persisted Digital Twin.

The current implementation answers one conservative question: **which active source files are proven to depend on this file through resolved local imports?** It traverses the persisted `import_references` relation in reverse, breadth-first, and only follows rows whose `resolution_state` is `resolved_local`.

## Evidence model

Every returned hop includes the persisted import observation that justifies it: the import record ID, source file ID, and raw module specifier. The service does not invent call edges, runtime behavior, package alias resolution, dynamic dependency relationships, or semantic references that the current index cannot prove.

This means an empty result is intentionally different from a claim that a file has no runtime consumers. It only means CodeTwin ML has no active, locally resolved import evidence for a dependent within the indexed graph.

## Bounds and determinism

Impact traversal is cycle-safe and deterministic. Dependents are ordered by relative path and import source location before breadth-first expansion. The public service clamps traversal depth to 8 and result count to 500 files. The desktop currently requests depth 6 and at most 200 impacted files.

The response reports the requested depth, effective bounded depth, result limit, and whether the result was truncated. Callers must surface truncation rather than treating a partial result as complete.

## Desktop and Tauri boundary

The Tauri command `analyze_file_impact` accepts a persisted file ID, maximum depth, and result limit. It delegates to `ImpactAnalysisService`; command handlers do not contain database traversal logic.

The Digital Twin file detail view runs impact analysis when a file is selected and displays each evidenced dependent with its depth and import specifier.

## Current limitations

The implementation is intentionally file-level. Symbol references, call graphs, re-export semantics, path aliases, package-manager resolution, framework routing, generated-code relationships, and runtime traces require separate evidence-producing analyzers before they can participate in impact analysis.
