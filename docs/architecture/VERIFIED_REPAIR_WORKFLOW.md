# Verified Repair Workflow

CodeTwin separates repair proposal, repository mutation, and post-state verification into distinct trust boundaries. A proposal is pinned to exact indexed source hashes. Approval rechecks that indexed base. File mutation is available only through the explicit **Apply & Rollback** workspace, where live repository bytes are checked again before any write. Verification still requires a later re-indexed state and preserves the originating analyzer's authority over finding resolution.

## Proposal and verification lifecycle

A repair plan starts in `draft`. A draft may reference an existing finding and may contain one or more existing indexed-file replacements. Each replacement stores the file path, indexed base SHA-256, proposed UTF-8 content, proposed SHA-256, and byte size.

`approve_plan` is a precondition check. It refuses a plan with no changes, inactive target files, or indexed content hashes that differ from the recorded base hashes. Approval does not itself write repository files.

`verify_plan` compares every proposed hash with the current active indexed file at the same project-relative path. Its result is one of:

- `mismatch`: at least one present file does not match its proposed hash;
- `incomplete`: at least one proposed file is missing from the active index;
- `applied_finding_open`: every proposed hash matches, but the linked finding is still open;
- `verified`: every proposed hash matches and, when a finding is linked, that finding has been resolved by its analyzer lifecycle.

Only the final condition transitions a plan to `verified`. A hash match does not directly resolve an analyzer finding.

## Desktop Repair Lab

The **Repair Lab** remains the proposal and verification workspace. It can open/index a project, list bounded findings, create/select/approve/reject plans, load a source snapshot after current byte-size/SHA-256 revalidation, persist edited full-file replacement proposals, re-index the repository, and display verification evidence.

Source loading is read-only. The query service rejects absolute or parent-traversing persisted paths, symlinked source files, project-root escapes, files larger than 1 MiB, non-UTF-8 input, and current content that no longer matches the persisted index.

## Explicit Apply & Rollback workspace

Repository mutation is intentionally separated into a second workspace. The **Apply & Rollback** workspace requires an already approved plan and an explicit user confirmation before invoking file application.

`RepairApplicationService::apply_plan` performs a full preflight before swaps:

1. the plan must still be `approved`;
2. at most 500 existing file replacements are accepted;
3. the project root must be a regular non-symlink directory;
4. every repair path must be a safe project-relative path;
5. every target must be a regular non-symlink file whose canonical path remains under the project root;
6. target files are bounded to 5 MiB for application reads;
7. current live repository bytes must still match the proposal's base SHA-256;
8. persisted proposed bytes must match the persisted proposed SHA-256 and byte size;
9. app-data backup files and same-directory staged replacement files are created before the first swap.

For each file, CodeTwin renames the current target to a same-directory sidecar and then renames the already staged replacement into place. Keeping the original sidecars until the batch finishes allows a failed multi-file application to attempt reverse rollback in reverse order. Successful original bytes are also persisted as hash-pinned backup files under the application's app-data `repair-backups` directory; backup source bytes are not duplicated into SQLite.

A successful application moves the plan to `applied`. The repository must then be indexed again before verification. If a linked finding exists, the appropriate analyzer must also run again and resolve the finding before the plan can become `verified`.

### Explicit rollback

A successful application can be rolled back only while both the application run and plan are still `applied`. Before restoring any backup, CodeTwin requires every current live target to still match the corresponding proposed SHA-256. This prevents rollback from overwriting post-apply manual edits.

Backup files must be regular non-symlink files and must match the persisted backup/base SHA-256. Restores are staged before swaps. If rollback succeeds, the plan returns to `draft`, forcing a fresh index and approval precondition before any future application. This prevents a stale post-apply index from being reused as verification evidence after rollback.

If automatic recovery from a partial application or rollback cannot restore a known state, the application run becomes `rollback_failed` and the repair plan becomes `superseded`. Automatic retry is then blocked; the persisted backup evidence is retained for manual recovery.

## Persistence

Migration `0011_verified_repair_workflow.sql` adds:

- `repair_plans` for lifecycle state and optional finding linkage;
- `repair_changes` for exact base/proposed file evidence;
- `repair_verification_runs` for immutable verification summaries;
- `repair_verification_items` for per-change expected/observed hash evidence.

Migration `0012_repair_transactional_application.sql` adds:

- `repair_application_runs` for application/rollback state, counts, backup-set identity, and bounded error evidence;
- `repair_application_items` for per-change base/proposed/backup hashes, safe backup filenames, and application state.

Migration version 10 remains reserved for the already-open ML inference provenance work. SQLite migration versions do not need to be contiguous; when both branches eventually exist together, version 10 can be applied before versions 11 and 12.

## Bounds, confidentiality, and execution policy

Titles/rationales are bounded, each proposed UTF-8 replacement is limited to 1 MiB, application reads are bounded to 5 MiB per current file, and history/item queries are bounded. A byte-identical proposal is rejected as a no-op.

Repair application writes only the approved replacement file bytes and its own staging/backup files. It never invokes a shell, compiler, package manager, test runner, language server, repository hook, analyzed project command, or arbitrary executable. Backup storage is chosen by CodeTwin under app data, never discovered from the analyzed repository.

Proposed source content in SQLite and original source bytes in repair backup files should be treated with repository-level confidentiality. This layer does not claim secret redaction within source code.

## Residual limitations

This implementation provides hash-preconditioned multi-file staging with reverse rollback, but it is not a crash-proof filesystem transaction. A process, OS, power, or storage failure during a rename window can leave staged/sidecar state that requires manual recovery from the persisted app-data backup set. The implementation does not claim filesystem locking against every time-of-check/time-of-use race.

The following remain outside this slice:

- automatic patch generation;
- automatic test/CI execution;
- sandboxed repair validation;
- crash-recovery orchestration for interrupted rename windows;
- merge/PR automation;
- ML-driven repair promotion.

Future repair capabilities must preserve explicit approval, live base-hash preconditions, bounded mutation, recoverable evidence, and independent post-state verification rather than treating generated or applied bytes as verified automatically.
