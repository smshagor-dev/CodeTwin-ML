# Passive assessment jobs (CS-02)

Tool Library now provides **Save assessment plan → review scope → Start assessment** for an imported, indexed project. Opening the page, refreshing history and restarting the app do not execute a plan.

## Implemented boundary

The initial runner registers two typed adapters: `code.sast` (existing source security analyzer) and `code.quality` (existing persisted-index quality analyzer). Tools execute serially on a blocking worker with its own database connection. The adapter whitelist is compiled; catalog metadata cannot dispatch commands. This assessment selection does not add another entry to the 41-entry Tool Library registry.

This is a passive indexed-source assessment, not a universal scheduler or an active engagement authorization system. Web scans and external QA execution retain their separate existing scope/approval/isolation checks. Network targets, consent records and active adapter integration remain later work.

## Saved scope and input checks

Migration 0028 stores immutable project scope revisions, plan bindings and ordered job steps. Each new plan creates a revision and supersedes older unstarted plans. Scope cannot be revised while its project has a running assessment.

The saved scope contains canonical project root, indexed-file count, input fingerprint, file budget and time budget. The fingerprint binds the configured root, canonical root, ordered active indexed paths/content hashes/sizes/languages/parse states/index run IDs, active quality symbols/resolved imports (bounded to 200,000 symbols/50,000 imports), latest completed source-index and LSP semantic run IDs, and assessment/analyzer definition versions. The latest source-index run must have completed. Actual file bytes must match the index when saving and before/after each analyzer. Revision or input drift fails the job and prevents the next adapter from starting. Reindex and save a fresh plan to proceed.

Limits: 1–2000 indexed files; 5 MiB per regular file; 32 MiB total source bytes; 1–3600 seconds. Unsafe relative paths, symlink components and static non-regular files are rejected. Scope covers **active indexed files**, not unindexed or ignored repository contents. This is validation of mutable local inputs, not an immutable filesystem snapshot or an OS isolation guarantee. Another process can still modify files while an analyzer runs; the runner checks again afterwards and fails on observed drift. Existing analyzer evidence remains inspectable.

## Lifecycle and cancellation

Job states are `planned`, `running`, `completed`, `failed`, `cancelled`, `interrupted`. Persisted step states and analyzer run IDs provide progress and evidence references. Completion means execution finished; it is not a security pass or a test verdict. Source partial coverage fails the assessment. Quality coverage remains unspecified rather than being inferred from completion.

Starting reserves the app's indexing, semantic enrichment, source security and quality worker flags for the whole assessment. Failed reservation releases flags already acquired. Workers do not hold the shared app database mutex during analysis; reads and cancel requests use another connection. File database connections use a five-second SQLite busy timeout for concurrent writes.

Cancellation is durable and cooperative. A planned job cancels immediately; a running job finishes its current non-interruptible analyzer, then stops before the next. Cancellation wins a simultaneous final completion. The time budget is also checked **at analyzer boundaries**, not a hard timeout or process kill. A single analyzer can exceed it; that assessment fails at the next boundary. Completed evidence is retained and untouched steps become cancelled/interrupted, not completed.

Native app setup explicitly marks running jobs and unfinished steps interrupted before workers are created. Opening an additional database connection does not recover or interrupt another worker. Saved plans remain planned across restart; interrupted/terminal jobs cannot be resumed. Create a fresh plan instead.

## Validation

- Real SQLite/indexed-source tests exercise both existing analyzers, findings and linked run IDs, source edits, reindex drift, superseded revisions, immutable bindings, typed tool selection, budgets, unsafe paths and symlinks.
- Lifecycle tests cover cancellation versus completion and cooperative deadline checks. Disk reopen tests verify explicit recovery and no automatic execution.
- Production browser tests with fixture IPC cover explicit save/start, running and planned cancellation, progress, revision controls, errors, project-switch stale responses, reload persistence and light/dark desktop/mobile overflow.
- Browser fixtures are UI evidence only. Native Windows GUI physical validation remains pending; CI compilation and Windows core tests do not replace it.
