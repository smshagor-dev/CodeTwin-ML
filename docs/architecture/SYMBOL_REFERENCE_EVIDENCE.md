# Symbol Reference Evidence

CodeTwin ML treats symbol-reference data as evidence, not as an inferred runtime call graph.

## Current evidence scope

The first reference analyzer supports TypeScript, TSX, and JavaScript. It records only direct identifier syntax in these forms:

- `functionName()` as a `call` observation.
- `new ClassName()` as a `constructor` observation.

Each observation stores the exact identifier text, source file, source range, analyzer version, and a deterministic identity.

Member calls such as `object.method()` are deliberately excluded because an identifier-only syntax pass cannot prove which method declaration is targeted. Chained calls, dynamic property access, aliases, package exports, framework routing, runtime dispatch, and reflection are also outside this analyzer's evidence boundary.

## Persistence

Reference observations are stored in `symbol_reference_observations`. Refreshing a project replaces its previous observation set transactionally, so removed calls do not remain as stale evidence.

The refresh service reads only active files already known to the persistent source index. It canonicalizes each file path and rejects paths outside the indexed project root.

## Resolution boundary

This unit does not connect an observation to a target symbol and does not materialize `calls`, `called_by`, or equivalent graph edges. Matching an identifier name to a declaration is not sufficient proof because lexical shadowing, imports, aliases, overloads, dynamic dispatch, and language-specific name resolution can change the target.

A later resolver may add target relationships only when it has language-aware, unambiguous evidence. Until then, observations remain source facts rather than semantic graph claims.

## Query boundary

The desktop Tauri boundary exposes:

- `refresh_symbol_references(project_id)` to regenerate evidence for an indexed project.
- `list_file_reference_observations(file_id, limit)` to retrieve deterministic source-ordered evidence, capped by the core service.

The initial maximum query result is 500 observations per request.

## Testing

The reference indexer verifies that direct calls and constructors are captured while member calls are excluded. Core integration tests verify persistence, unsupported-language skipping, and stale-observation replacement after a source change and re-index.
