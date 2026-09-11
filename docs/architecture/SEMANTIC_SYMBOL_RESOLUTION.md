# Semantic Symbol Resolution

CodeTwin separates syntax observations from semantic claims. The source-backed reference pass records direct identifier calls and constructor sites first; this resolver is a second stage that may attach a declaration target only when the persisted evidence is unambiguous.

## First supported resolution rule

This version resolves only same-file references for validated direct syntax:

- `name()` may resolve to one active symbol with the same name and kind `function` in the same file.
- `new Name()` may resolve to one active symbol with the same name and kind `class` in the same file.

Exactly one compatible active declaration is required. The observation is stored as `resolved_same_file` with its target symbol ID.

## Conservative states

- `observed`: raw reference evidence exists but semantic resolution has not run yet.
- `resolved_same_file`: exactly one compatible same-file declaration is proven by persisted index evidence.
- `ambiguous`: more than one compatible same-file declaration exists, so CodeTwin refuses to choose one.
- `unresolved`: no compatible same-file declaration can be proven.

## What is intentionally not resolved

This unit does not claim cross-file imports, aliases, re-exports, member dispatch, inheritance, overload dispatch, package resolution, framework routing, dynamic imports, runtime binding, or reflection semantics.

A matching identifier in another file is not proof of a relationship. Current import persistence records module specifiers and resolved files, but it does not yet persist imported binding names strongly enough to prove that an observed identifier maps to a particular exported symbol. Those observations remain unresolved.

## Graph boundary

Semantic resolution metadata does not automatically create `calls` or `called_by` graph edges. A later graph-materialization unit may derive call edges only from resolution states whose evidence contract is strong enough for that relationship.

## Determinism and safety

Observations are processed in deterministic file/range/name order. Candidate symbols are active indexed symbols only. At most two candidates are loaded because resolution only needs to distinguish zero, one, or multiple matches. Resolution is transactional per project, and rerunning it first clears previous targets before recomputing current evidence.
