# Deterministic Code Quality Analysis

CodeTwin ML's first quality-analysis layer consumes the already persisted Software Digital Twin. It does not execute repository commands, package scripts, tests, compilers, hooks, language servers, or model inference. The analyzer reads active persisted symbols and import references whose state is already `resolved_local`, applies bounded deterministic rules, and writes normalized findings plus concrete evidence to SQLite.

## Implemented rules

The baseline rule set is intentionally small and auditable.

- `quality.oversized_definition`: flags an active persisted definition whose source range spans at least 120 lines. Definitions spanning at least 300 lines are high severity; other matches are medium severity.
- `quality.deep_declaration_nesting`: flags an active definition with at least five persisted structural declaration-parent levels. A depth of at least eight is medium severity; other matches are low severity.
- `quality.high_local_fan_out`: flags a file with at least 20 distinct `resolved_local` import targets. A fan-out of at least 40 targets is medium severity; other matches are low severity.
- `quality.local_dependency_cycle`: finds strongly connected components in the `resolved_local` file import graph. Components with at least six files are high severity; smaller cycles are medium severity. A proven self-import is also treated as a cycle.

These thresholds are rule configuration, not statistical or ML predictions. A deterministic match is persisted with confidence `1.0` to distinguish it from probabilistic model output; `model_version` remains null.

## Evidence and lifecycle

Each quality finding has a deterministic fingerprint scoped to the project, rule, and evidence-bearing entity or component. Re-running the same rule against unchanged evidence refreshes the existing finding instead of creating a duplicate. When a previously open finding is no longer observed, it is retained and marked `resolved` with a resolution timestamp. If concrete evidence returns later, the same durable finding can become open again.

Source-range rules attach source evidence containing the persisted file path, line range, measured value, and threshold. Dependency rules attach evidence only for persisted `resolved_local` import records. Unresolved, external, unsupported, or merely observed imports are not promoted to local dependency evidence.

The analyzer never changes findings owned by other analyzers. `analyzer_key = code_quality` scopes refresh and resolution behavior to this subsystem.

## Bounds

A run refuses to analyze more than 200,000 active persisted symbols or more than 50,000 resolved-local import edges. Finding, evidence, and history APIs are independently result-bounded. Dependency-cycle evidence is capped per cycle so a single component cannot create an unbounded response surface.

The desktop Findings workspace shows only persisted rule metadata, run metrics/history, open or resolved findings, and their stored evidence. It contains no placeholder findings or synthetic scores.

## Current boundary

This baseline does not claim cyclomatic complexity, CFG/data-flow quality, dead-code proof, clone detection, test quality, security findings, runtime reliability, ML defect prediction, or repair verification. Those require dedicated evidence-producing analyzers and are not inferred from the four rules above.
