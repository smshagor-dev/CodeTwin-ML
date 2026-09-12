# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a different trust boundary and requires an explicit typed plan, trusted toolchain, user approval, pinned inputs, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The foundation implements planning, policy validation, command generation, durable plan persistence, approval state, future run/result schema, output bounding, test-verdict rules, selected-target SHA-256 snapshots, trusted-toolchain hash revalidation, Windows Job Object containment, restricted-token/ACL/MIC controls, a suspended restricted-process launcher, and a bounded full-project mirror used below the public execution boundary.

On Windows the lower-level execution path now creates a project-local dependency-complete mirror before reaching the existing restricted launcher. The mirror contains every regular project file and empty directory accepted by the bounded filesystem contract, is hash-pinned and read-only, and is revalidated against the source tree after copy and before use. The restricted runner receives the mirror—not the live repository—as its project root, so normal relative imports, configuration, fixtures, and project-local dependency reads resolve inside the detached copy.

This does **not** enable public test execution. `filesystem_isolation` and `network_isolation` remain false. A write-restricted low-integrity Windows token is not a host-wide read sandbox; code that already knows an absolute host path may still be able to read it. Separate desktop/window-station isolation, external dependency/toolchain access policy, adversarial Windows validation, and OS-level network denial are also pending. `QaExecutionService` therefore still reports `execution_enabled = false`, exposes no execute method, and strict plans remain `blocked`.

## Typed runner model

Only allow-listed runner kinds can be represented: Pytest, Rust `cargo test` integration tests, Go `go test`, Vitest, Jest, and PHPUnit. The plan stores an exact trusted absolute executable path and generated argument vector. It never stores or executes a shell command string or package-script entrypoint.

Every request requires explicit project-relative targets. Absolute paths, parent traversal, Windows-style backslash targets, empty targets, and requests beyond the configured target bound are rejected. Rust integration-test targets are restricted to conventional `tests/*.rs` paths before `cargo test --test <name>` is planned.

## Default sandbox policy

The default policy requires process isolation, filesystem/write isolation, network isolation, CPU and memory limits, reliable cancellation, wall-clock timeout, bounded output and target count, and no inherited host environment. Missing required capabilities make a plan `blocked`. Controls that exist but are not strong enough to prove a capability remain limitations rather than being promoted.

## Dependency-complete project-local mirror

`prepare_dependency_complete_workspace` is the full-tree staging primitive. Its meaning of `dependency_complete = true` is deliberately narrow and testable: **all accepted project-local filesystem entries are mirrored**, including configuration files, source files, fixtures, assets, and empty directories. It does not claim that external package registries, compiler sysroots, language runtime installations, user caches, or network-fetched dependencies are part of the mirror.

The mirror is bounded to:

- 8,192 regular files;
- 4,096 directories;
- 256 MiB total regular-file bytes.

The preparation sequence is:

1. canonicalize the source and workspace-parent directories and require the generated workspace to live outside the source tree;
2. revalidate the already approved selected-target snapshots;
3. enumerate the entire source tree into a deterministic manifest;
4. reject non-Unicode paths that cannot be represented deterministically by the execution contract;
5. reject symbolic links and, on Windows, every entry carrying `FILE_ATTRIBUTE_REPARSE_POINT`, covering junction/reparse-point traversal rather than checking symbolic-link type alone;
6. reject special filesystem entries that are neither regular files nor directories;
7. enforce file-count, directory-count, and aggregate-byte bounds while hashing every regular file;
8. require each approved target hash and size to match the corresponding full-tree manifest entry;
9. recreate every directory under detached `inputs/`, preserving empty directories;
10. before each file copy, recheck type, containment, size, and SHA-256 against the first-pass manifest;
11. copy each file, mark it read-only, and immediately recheck destination size and SHA-256;
12. rescan the source tree after all copies and require the entire source manifest to be unchanged;
13. independently scan the detached tree and require it to match the source manifest exactly;
14. persist the sorted project-directory list and a domain-separated SHA-256 manifest digest in the workspace record;
15. run full workspace verification before returning the mirror.

This closes the normal copy-time mutation race: a file cannot silently change between approval validation and detached copy without producing a source-manifest or destination-manifest mismatch. If the source tree changes after preparation, later verification fails rather than silently accepting a stale mirror.

The existing `prepare_detached_workspace` exact-target API remains available and keeps `dependency_complete = false`; it is still useful for hash-pinned target-only staging and readiness tests. Exact-target workspaces cannot self-promote by setting project-mirror metadata.

## Windows restricted project-mirror routing

The Windows crate-level route is layered rather than rewriting the already-audited process launcher:

1. build and verify the full project-local mirror from the original source root;
2. run the restricted-identity ACL/MIC probe against that full mirror while also proving the original source-root write denial expected by the current token model;
3. require `dependency_complete = true` and a retained full-tree manifest digest;
4. pass the detached mirror's `inputs/` directory as the project root to the existing restricted launcher;
5. let that launcher revalidate the selected target hashes against the mirror;
6. create its bounded writable execution workspace for `TEMP`, build/cache state, and output support;
7. launch the exact trusted toolchain under the restricted primary token from the mirror working directory.

As a result, relative project reads no longer need the live repository. The original source path is not used as the runner's working directory and is not substituted as a compatibility fallback.

The two-stage workspace structure is intentionally conservative for now: the outer workspace is the read-only full project mirror, while the existing inner restricted-launch workspace provides the already-audited writable `artifacts/` and `temp/` contract. A later refactor may combine them only if it preserves the same evidence and cleanup properties.

## Windows restricted suspended launcher

The existing Windows launcher still enforces:

1. exact trusted executable SHA-256 revalidation;
2. fresh selected-target hash revalidation;
3. a `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED`, low-integrity primary token;
4. exact `lpApplicationName` plus a writable Unicode command-line buffer;
5. `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, limiting child inheritance to stdin/stdout/stderr;
6. a minimal Unicode environment rather than host-environment inheritance;
7. `CREATE_SUSPENDED` process creation;
8. Job Object assignment before the returned primary thread is resumed;
9. exact `ResumeThread` suspend-count validation;
10. Job Object CPU time, memory, kill-on-close, wall-clock timeout, and cancellation controls;
11. bounded stdout/stderr capture and bounded drain time;
12. termination of surviving descendants before final output drain/workspace cleanup;
13. no normal-token or alternate-logon fallback if restricted process creation fails.

Writable temporary state remains redirected to detached paths through variables such as `TEMP`, `TMP`, `GOTMPDIR`, `CARGO_TARGET_DIR`, `GOCACHE`, `NPM_CONFIG_CACHE`, and `XDG_CACHE_HOME` where the corresponding tool respects them.

## Windows restricted identity

The identity layer creates `WRITE_RESTRICTED` low-integrity tokens with `WinWriteRestrictedCodeSid`, preserves existing generated-workspace DACLs while adding restricting-SID access, applies low mandatory-integrity labels, and performs non-mutating access probes. Source-root and staged-input mutation rights must be denied; `artifacts/` and `temp/` writes must be allowed. Impersonation is always reverted before evidence is returned.

For dependency-complete workspaces, the file manifest contains the full mirrored project, so the same staged-file write checks cover every mirrored regular file. The generated `inputs/` directory itself is also tested for mutation-capable directory rights. This remains a write-boundary claim, not a host-wide read-isolation claim.

## Current capability truth

`current_backend_info()` continues to report these Windows capabilities as enforced:

- process-tree containment;
- CPU limit;
- memory limit;
- cancellation.

`filesystem_isolation` remains **false** even though project-local execution now runs from a dependency-complete read-only mirror. Reasons include:

- the restricted token does not deny arbitrary host-file reads;
- external runtime/toolchain/package-cache access has not yet been reduced to an explicit read-only allow-list;
- the process still shares the caller desktop/window station;
- adversarial Windows integration tests have not executed because GitHub-hosted runners are currently not being allocated to this repository/account;
- capability promotion requires executed evidence, not only source inspection.

`network_isolation` is also **false** because no OS-level network denial mechanism is enforced.

## Execution input and runner integrity

Selected execution inputs remain individually snapshotted with `snapshot_execution_inputs`. Each selected target must be a regular non-symlink project file and is limited to 8 MiB. Those selected-target hashes are checked again against the full project manifest and again by the restricted launcher inside the detached mirror.

The trusted runner remains an absolute regular non-symlink executable outside the analyzed project with a pinned 64-hex-character SHA-256. The executable is rehashed immediately before restricted launch and passed through exact `lpApplicationName` rather than executable-name search.

## Durable state and truth rules

Migration `0014_qa_test_execution.sql` stores typed execution plans and reserves `qa_execution_runs` for future bounded results. The public service exposes availability plus plan create, approve, get, and list operations only; it still exposes no execute method and creates no execution-run records.

A raw process completion is not automatically a test verdict. Pass/fail requires completed execution, a completed runner-specific parser, and an exit code. Timeout, cancellation, infrastructure failure, setup failure, or incomplete parsing produce no pass/fail claim.

The new full-tree manifest is currently ephemeral workspace evidence. Before public execution is enabled, the approval/persistence model should bind the approved plan to the exact full-tree manifest digest (or an equivalent immutable project snapshot), so non-target dependency changes between approval and execution cannot enter the execution set merely because they were present at launch time.

## Next sandbox hardening steps

The next Windows security work should focus on the boundaries that are still genuinely missing rather than promoting a capability early:

- persist and bind the full project-manifest digest to approval/run provenance;
- define explicit read/execute access for trusted external runtime/toolchain/package locations instead of relying on ambient host readability;
- add a separate restricted desktop/window station or equivalent UI boundary;
- implement OS-level network denial;
- run adversarial Windows tests for source-write denial, mirror immutability, host-path access, artifact/temp writability, process-tree containment, child cleanup, handle inheritance, timeout/cancellation, CPU/memory limits, command-line quoting, and token restrictions.

Only after the relevant Windows tests actually execute and pass should `filesystem_isolation` be considered for promotion. Network isolation remains an independent strict blocker. Linux and macOS execution backends remain future work.

## Security boundary

Repositories remain untrusted data. The public desktop/service layer still does not invoke test runners or repository code. The lower-level Windows primitives exist below that boundary and remain unreachable through normal strict plans while required capabilities are missing. Future public wiring must consume only approved typed plans, preserve exact toolchain and full-project provenance, enforce every required capability, bound outputs/results, support cancellation, and report infrastructure failures separately from test failures.
