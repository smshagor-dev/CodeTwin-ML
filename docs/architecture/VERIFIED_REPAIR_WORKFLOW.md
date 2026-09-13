# Verified Repair Workflow

The verified-repair foundation is deliberately separated from code generation and command execution. It records a repair proposal against an exact indexed source state, requires explicit approval while that base state is still current, and later verifies an externally applied change from the re-indexed file hashes.

## Lifecycle

A repair plan starts in `draft`. A draft may reference an existing finding and may contain one or more existing indexed-file replacements. Each replacement stores the file path, the indexed base SHA-256, the proposed UTF-8 content, the proposed SHA-256, and its byte size.

Approval is a precondition check, not an application step. `approve_plan` refuses a plan if it has no changes, if a target file is no longer active, or if any current indexed content hash differs from the recorded base hash. An approved plan therefore identifies the exact repository snapshot against which it was reviewed.

CodeTwin does not write the proposed bytes to the repository in this baseline. A user or a later separately approved patch-application subsystem may apply the change. The repository must then be indexed again.

`verify_plan` compares every proposed hash with the current active indexed file at the same project-relative path. The verification result is one of:

- `mismatch`: at least one present file does not match its proposed hash;
- `incomplete`: at least one proposed file is missing from the active index;
- `applied_finding_open`: every proposed hash matches, but the linked finding is still open;
- `verified`: every proposed hash matches and, when a finding is linked, that finding has been resolved by its analyzer lifecycle.

Only the final condition transitions a plan to `verified`. A hash match alone cannot falsely resolve an analyzer finding.

## Desktop Repair Lab

The desktop exposes this lifecycle as a separate **Repair Lab** workspace. The workspace can:

- open and index a project using the same persistent project identity as the Digital Twin;
- list bounded existing findings that may be linked to a repair plan;
- create, select, approve, reject, and verify repair plans;
- list proposed file replacements and verification history;
- load an active indexed source file into an editor only after the current filesystem bytes are re-checked against the persisted SHA-256 and byte size;
- persist an edited full-file replacement as proposal data;
- re-index after a user applies changes through an external trusted workflow;
- display immutable per-change expected/observed verification hashes.

Source loading is read-only. The query service rejects absolute or parent-traversing persisted paths, symlinked source files, project-root escapes, files larger than 1 MiB, non-UTF-8 input, and any current content that no longer matches the index. A stale editor buffer therefore cannot silently become a proposal precondition.

The workspace intentionally has no **Apply patch**, shell, test, compiler, package-manager, hook, or language-server execution button. Approval means only that the proposal's base hashes still match; verification means only that a later indexed state matches the proposed hashes and, when linked, the original analyzer finding is resolved.

## Persistence

Migration `0011_verified_repair_workflow.sql` adds:

- `repair_plans` for lifecycle state and optional finding linkage;
- `repair_changes` for exact base/proposed file evidence;
- `repair_verification_runs` for immutable verification summaries;
- `repair_verification_items` for per-change expected/observed hash evidence.

Migration version 10 is intentionally left available for the already-open ML inference provenance work. SQLite migration versions do not need to be contiguous; when both slices are eventually present, version 10 can be applied before version 11.

## Bounds and safety

Titles and rationales are bounded, each proposed UTF-8 file replacement is limited to 1 MiB, and list/history queries are bounded. A byte-identical replacement is rejected as a no-op.

The repair service never invokes a shell, compiler, package manager, test runner, language server, repository hook, or analyzed project command. It does not modify repository files. Verification is based only on persisted project/file identities, current active indexed hashes, and the linked finding status.

Because proposed replacement content is persisted locally in SQLite, it should be treated with the same confidentiality as the analyzed source repository. This baseline does not claim secret redaction inside proposed source code.

## Not implemented yet

The following are intentionally outside this foundation:

- automatic patch generation;
- atomic multi-file filesystem application;
- rollback/backup orchestration;
- automatic test/CI execution;
- sandboxed repair validation;
- merge/PR automation;
- ML-driven repair promotion.

Those capabilities must preserve the base-hash precondition and evidence-backed verification model rather than treating a generated patch as verified merely because it was proposed.
