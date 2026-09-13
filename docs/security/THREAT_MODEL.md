# Threat Model

## Protected assets

CodeTwin ML protects analyzed source code, credentials, local files outside the selected project, Git and database credentials, model artifacts, dataset packages, analysis evidence, repair proposals/backups, reports, and developer feedback.

## Trust assumptions

The analyzed repository is untrusted input. Source files, manifests, test configuration, Docker/Compose files, database artifacts, model packages, datasets, language-server output, and persisted evidence must not be trusted merely because they are local.

Explicitly configured external executables are separate trust decisions. Semantic enrichment requires a user-configured external language-server executable. ML inference requires an explicitly configured local Python executable and sidecar root. These workflows are distinct from passive deterministic analysis.

## Primary threats

- Malicious repository content, parser abuse, and prompt/instruction injection in source or documentation.
- Dependency, package, test, build, or repository scripts attempting unexpected command execution.
- Path traversal, symlink/reparse-point escape, or unsafe canonicalization from an approved project/workspace.
- Secret leakage through logs, reports, persisted evidence, model context, environment inheritance, or external tools.
- Resource exhaustion, fork/process-tree abuse, excessive output, and denial of service.
- Network exfiltration by untrusted project execution.
- Malicious or substituted model/dataset/runtime artifacts.
- Database credential exposure or accidental/destructive interaction with the analyzed project's database.
- Supply-chain compromise of CodeTwin dependencies, CI actions, external runtimes, models, or datasets.
- Repair time-of-check/time-of-use races, partial multi-file mutation, backup corruption, and rollback conflicts.
- False security claims caused by treating missing, stale, ML-derived, or unexecuted evidence as verified results.

## Passive-analysis controls

Project discovery, Tree-sitter indexing, deterministic quality/security/database/runtime analysis, and passive QA discovery inspect bounded repository data without executing repository commands. Database analysis does not connect to or mutate the analyzed project's database. Security findings persist bounded/redacted evidence where applicable.

SQLite foreign keys are enabled and schema changes are controlled through numbered migrations. Dashboard evidence-loading failures are surfaced as unavailable rather than silently converted into zero findings.

## Semantic and ML controls

Language-server enrichment is an explicit trusted workflow and does not auto-discover an executable from the analyzed repository.

ML packages are treated as data and are integrity-checked before use. The desktop ML bridge requires explicit local executable/root configuration, uses a bounded schema-checked stdio protocol, applies request/response and source-size limits, verifies current indexed source hashes before inference, and stores inference provenance separately from deterministic finding authority. ML observations must not be promoted to confirmed deterministic findings merely because a model produced a score.

## Repair controls

Repair proposals are pinned to indexed source hashes. Approval rechecks the proposal base. Apply & Rollback is a separate explicit mutation boundary: application is limited to approved bounded file replacements, rejects unsafe paths/symlinks/root escapes, revalidates live base SHA-256 values before swaps, stages replacement and backup files, and records application evidence. Rollback refuses to overwrite post-apply manual edits when the current file no longer matches the applied proposal hash.

Repair application is not a crash-proof filesystem transaction and does not eliminate every TOCTOU race. If a partial application/rollback cannot restore a known state, automatic retry is blocked and the plan is superseded. An applied repair is not verified until a fresh index and, where applicable, the responsible deterministic analyzer confirm the post-state.

## QA execution controls and limitations

QA discovery is passive. Execution planning and the Windows containment foundation include bounded project mirroring, hash-pinned approval evidence, declared external runtime/toolchain provenance, write-restricted low-integrity process identity, explicit inherited-handle control, suspended Job Object assignment, sanitized environment, resource/time/output bounds, and cancellation.

Public QA execution remains disabled. Filesystem isolation is not claimed because undeclared host reads are not yet denied and declared runtime trees are not held immutable for the whole execution lifetime. Network isolation, restricted desktop/window-station hardening, and adversarial Windows validation are also incomplete. No execution plan or containment scaffold should be presented as a test result.

## Distribution and supply chain

Optional OpenMindAI Dataset installation uses release manifests plus asset size/SHA-256 validation and must preserve upstream terms. The base desktop installer must remain usable when optional datasets are skipped or unavailable.

Dependency lockfiles and required CI validation are release gates. A CI job that never allocates a runner or executes steps is an infrastructure failure, not a successful validation result.

## Residual risks

- Full QA filesystem/network/desktop isolation is incomplete and public execution remains disabled.
- Repair mutation is recoverable/bounded but not a crash-proof filesystem transaction.
- External language servers and local ML runtimes are trusted local executables and expand the trust boundary when explicitly enabled.
- Dependency/model/dataset provenance reduces but does not eliminate upstream supply-chain risk.
- Static analyzers can produce false positives/negatives and do not prove runtime exploitability or availability.
