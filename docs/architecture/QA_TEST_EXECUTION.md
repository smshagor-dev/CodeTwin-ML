# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a separate trust boundary and requires an explicit typed plan, trusted toolchain, user approval, immutable project-input provenance, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The QA execution foundation implements typed planning, policy validation, command generation, durable plan persistence, approval state, reserved run/result persistence, bounded output helpers, test-verdict rules, selected-target snapshot hashing, trusted-toolchain hash revalidation, Windows Job Object containment, write-restricted low-integrity primary-token launch, explicit inherited-handle control, bounded full-project detached mirroring, and approval-time project-manifest binding.

The public `QaExecutionService` still reports `execution_enabled = false` and exposes no execute method. `filesystem_isolation` and `network_isolation` remain false, so normal strict plans remain blocked and there is no unsandboxed fallback.

## Typed runner model

Only allow-listed runner kinds can be represented: Pytest, Rust `cargo test` integration tests, Go `go test`, Vitest, Jest, and PHPUnit. A plan stores an exact trusted absolute executable path and a generated argument vector. It never stores or executes a shell command string or package-script entrypoint.

Every request contains explicit project-relative targets. Absolute paths, parent traversal, Windows-style backslash targets, empty targets, and requests beyond the configured target bound are rejected. Rust integration-test targets are restricted to conventional `tests/*.rs` paths before a `cargo test --test <name>` command can be planned.

Planning creates `TestExecutionPlan.approved_project_manifest_sha256 = None`. A project manifest is not guessed or captured before approval. The manifest becomes execution authority only when the durable approval workflow successfully binds it.

## Default sandbox policy

The default policy requires process isolation, filesystem/write isolation, network isolation, CPU and memory limits, reliable cancellation, a wall-clock timeout, bounded output and target count, and no inherited host environment.

`SandboxCapabilities` describes only what a trusted backend actually guarantees. Missing required capabilities make a plan `blocked`. Controls that exist but are not yet strong enough to prove a capability remain limitations rather than being promoted.

## Approval-bound project manifest

A future-capable `planned` plan cannot transition to `approved` by changing status alone. Approval performs a bounded, non-executing project snapshot:

1. read the project's persisted root path;
2. re-snapshot the explicit selected test targets and verify their hashes;
3. build the existing bounded dependency-complete detached project mirror outside the source tree;
4. reject symlinks, Windows reparse-point entries, unsupported filesystem entries, unsafe paths, source mutation during staging, or mirror drift;
5. obtain the deterministic full-project manifest SHA-256 plus file count, directory count, and total regular-file bytes;
6. remove the temporary approval mirror;
7. atomically persist the digest and typed manifest metadata while transitioning the plan to `approved`.

Approval does not run repository commands, package scripts, interpreters, compilers, browsers, hooks, or tests. It only reads, hashes, and temporarily copies the bounded project tree through the same detached-mirror primitive used by the lower execution layer.

The manifest captures project-local tree state, not host-wide filesystem state. It does not include arbitrary external compiler/runtime installations, package registries, user caches, or network-fetched dependencies.

### Durable approval invariants

Migration `0015_qa_execution_manifest_binding.sql` adds:

- `qa_execution_plans.approved_project_manifest_sha256`;
- `qa_execution_plans.approved_project_manifest_json`;
- `qa_execution_runs.project_manifest_sha256`.

Database triggers enforce three independent rules:

- a plan cannot transition to `approved` without a bound manifest;
- once manifest columns are populated they are immutable;
- a future execution-run row cannot be inserted unless its manifest digest exactly matches the approved plan digest.

Older approved rows that predate manifest binding are not silently trusted. The service fails closed and requires a new plan and approval.

`QaExecutionPlanRecord::execution_plan` reconstructs the low-level typed `TestExecutionPlan`. For an approved record it requires manifest evidence and copies the approved digest into `approved_project_manifest_sha256`. A non-approved record carrying approval evidence is treated as inconsistent rather than normalized silently.

Concurrent approval is first-writer-wins only when both callers captured the same manifest. If another approval binds a different project snapshot while a caller is capturing evidence, that caller receives an explicit approval-manifest error instead of silently treating the different snapshot as its approval.

## Bounded dependency-complete project mirror

`prepare_dependency_complete_workspace` mirrors the accepted project-local tree under detached `inputs/` and records `dependency_complete = true` only after full verification. The current bounds are:

- at most 8,192 regular files;
- at most 4,096 directories;
- at most 256 MiB total regular-file bytes.

The mirror includes empty directories and all accepted project-local regular files. It rejects symbolic links, Windows reparse-point entries, non-Unicode/unsafe paths, and special filesystem objects. Selected target snapshots must match entries in the full-tree manifest.

Each source file is rechecked immediately before copying, each copied file is rehashed and marked read-only, the source tree is rescanned after copy, and the detached tree is independently rescanned. Missing files, extra files, directory drift, size drift, hash drift, or source mutation fail closed.

Exact-target staging remains a separate compatibility primitive with `dependency_complete = false`; it must not be confused with the full-project mirror.

## Windows restricted suspended launcher

The crate-level Windows execution path uses the following ordering:

1. require an approved project-manifest SHA-256 on the typed execution plan;
2. canonicalize the live project root and revalidate selected target snapshots;
3. build a fresh bounded dependency-complete detached mirror;
4. require the fresh mirror digest to exactly equal the approved plan digest;
5. probe the restricted-identity write matrix before any repository code can run;
6. derive a fresh `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED` low-integrity primary token;
7. revalidate the trusted runner path and SHA-256;
8. create stdin/stdout/stderr handles and restrict inheritance with `STARTUPINFOEXW` plus `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`;
9. pass the exact trusted executable through `lpApplicationName` and use a writable Unicode command-line buffer for the generated argv;
10. construct a minimal Unicode environment and redirect supported writable caches/temp state into generated detached directories;
11. call `CreateProcessAsUserW` with `CREATE_SUSPENDED`;
12. assign the still-suspended process to the configured Job Object;
13. resume the exact primary-thread handle returned by process creation and require the prior suspend count to be exactly one;
14. enforce bounded timeout, cancellation, job CPU/memory controls, and bounded stdout/stderr capture;
15. close the kill-on-close Job before final output drain/workspace cleanup so surviving descendants cannot extend the execution lifetime.

The digest equality check happens before restricted process creation. A non-target source/config/dependency change after approval therefore produces a different freshly prepared manifest and blocks launch rather than becoming an unreviewed execution input.

There is intentionally no normal-token or alternate-logon fallback when restricted process creation fails.

## Restricted identity and write boundary

The Windows identity layer creates a `WRITE_RESTRICTED`, low-integrity token using `WinWriteRestrictedCodeSid`, preserves existing generated-workspace DACLs while adding restricting-SID ACEs, and applies low-integrity mandatory labels.

The probe requires mutation-capable access to the original source root and mirrored project inputs to be denied while `artifacts/` and `temp/` remain writable. The original repository ACL is not modified.

This is a write boundary, not a host-wide read sandbox. A restricted process may still be able to read host objects permitted by Windows ACL/MIC rules if it knows their absolute paths. That remaining boundary is one reason `filesystem_isolation` is still false.

## Environment, handles, and process containment

The launcher does not inherit the full host environment. Required Windows system-root values are retained, while explicit CodeTwin/test controls are supplied. Writable state is redirected where supported through `TEMP`, `TMP`, `GOTMPDIR`, `CARGO_TARGET_DIR`, `GOCACHE`, `NPM_CONFIG_CACHE`, and `XDG_CACHE_HOME`. Python user-site imports and bytecode writes are disabled, `NO_COLOR` is set, and `CI=1` is supplied.

Only the explicit standard-I/O handles are inheritable by the child. The runner is born suspended, receives Job Object membership before its primary thread can execute untrusted user-mode code, and has no weaker pre-assignment path.

A raw process completion is not automatically a test verdict. Pass/fail requires a completed execution, completed runner-specific parser, and exit code. Timeout, cancellation, infrastructure failure, setup failure, manifest mismatch, or incomplete parsing produce no pass/fail claim.

## Current capability truth

On Windows, `current_backend_info()` can report process-tree containment, CPU limit, memory limit, and cancellation because those controls are enforced by the Job Object path.

`filesystem_isolation` remains false even though project-local execution now uses an approval-bound detached mirror. Remaining reasons include:

- the restricted token is not a host-wide read sandbox;
- external toolchain/package/runtime reads are not yet reduced to an explicit verified allow-list;
- the runner still shares the caller desktop/window station;
- adversarial Windows integration tests have not actually executed in CI;
- the capability has therefore not been promoted from component evidence to an end-to-end guarantee.

`network_isolation` remains false because no OS-level network denial mechanism is enforced.

The strict policy therefore continues to block normal execution plans, and the public desktop/service layer still has no execute method.

## Remaining hardening steps

The next Windows filesystem hardening should explicitly constrain or attest the external read surface needed by each trusted runner rather than assuming that a restricted token is a complete filesystem namespace. A restricted desktop/window station or equivalent UI isolation should also be added before public execution.

Adversarial Windows integration tests must then exercise approval-manifest mismatch, original-source write denial, mirror immutability, artifact/temp writability, explicit handle inheritance, process-tree containment, cancellation, CPU/memory limits, timeout behavior, command-line quoting, token restrictions, descendant cleanup, and host-read escape attempts.

Only after those end-to-end tests pass should `filesystem_isolation` be considered for promotion. Network isolation remains an independent strict blocker and must be implemented and verified before public repository execution can be enabled. Linux and macOS execution backends remain future work.

## Security boundary

Repositories remain untrusted data throughout planning and approval. The public desktop/service layer still does not invoke repository commands, package scripts, interpreters, test runners, compilers, browsers, or hooks. The restricted Windows launcher exists below that public boundary and remains unreachable through normal strict plans while required capabilities are missing.

Future public execution wiring must consume only approved typed plans, preserve the bound project-manifest digest into run provenance, revalidate exact trusted-toolchain provenance, enforce every required sandbox capability, bound output/results, support cancellation, and report infrastructure failure separately from test failure.
