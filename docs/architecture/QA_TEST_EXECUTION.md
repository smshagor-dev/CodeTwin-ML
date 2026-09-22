# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Repositories remain untrusted data. Test execution is a separate trust boundary and requires an explicit typed plan, trusted toolchain, user approval, immutable approval provenance, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The QA execution subsystem now implements a complete Windows execution path in addition to passive discovery and typed planning. An executable run requires an immutable typed plan, an explicitly trusted and SHA-256-pinned runner, explicit user approval, an approval-bound project manifest, an approval-bound external runtime/toolchain read surface, and the strict Windows LPAC backend. Unsupported platforms remain planning-only.

The Windows path stages a dependency-complete project mirror and an integrity-verified copy of the approved runtime/toolchain material into a generated workspace. The **actual resumed test runner**, not only a readiness probe, is created suspended as a write-restricted low-integrity zero-capability LPAC process. Its token is attested before resume, it is assigned to a bounded Job Object before untrusted code can execute, and it receives only explicit standard-I/O handles and a sanitized environment.

The public `QaExecutionService` exposes availability, plan creation, approval, execution, cancellation, and durable run history. A process exit is not automatically treated as a test result: CodeTwin records pass/fail only when a supported runner-specific output parser completed. Sandbox setup failures, timeouts, cancellation, stale approval evidence, or unrecognized output produce no test verdict.

There is no weaker unsandboxed fallback. If LPAC creation, ACL preparation, project/runtime provenance verification, exact runner verification, Job Object setup, token attestation, or output handling fails, execution fails closed.

**Validation status:** the implementation is wired for Windows, but the current GitHub Actions environment has repeatedly failed before allocating a runner (`steps = null`). Therefore this document distinguishes implemented enforcement from CI execution evidence; it does not claim that the current PR has completed adversarial Windows integration validation.

## Typed runner and toolchain model

Only allow-listed runner kinds can be represented: Pytest, Rust `cargo test` integration tests, Go `go test`, Vitest, Jest, and PHPUnit. A plan stores an exact trusted absolute executable path and a generated argument vector. It never stores or executes a shell command string or package-script entrypoint.

Every request contains explicit project-relative targets. Absolute targets, parent traversal, Windows-style backslash targets, empty targets, and requests beyond the configured target bound are rejected. Rust integration-test targets are restricted to conventional `tests/*.rs` paths before a `cargo test --test <name>` command can be planned.

`TrustedToolchain` may additionally declare explicit external read roots needed by a future execution path. A declaration contains a typed purpose and an absolute path. Supported purpose labels are runtime root, standard library, compiler sysroot, toolchain support, package store, and extension directory. Planning validates declaration shape but does not execute the toolchain to discover roots automatically. This preserves the non-executing planning/approval boundary.

Planning creates both `approved_project_manifest_sha256 = None` and `approved_external_read_surface = None`. Approval evidence is never guessed during planning.

## Default sandbox policy

The default policy requires process isolation, filesystem/write isolation, network isolation, CPU and memory limits, reliable cancellation, a wall-clock timeout, bounded output and target count, and no inherited host environment.

`SandboxCapabilities` describes only controls that an OS backend actually enforces. Missing required capabilities make a plan blocked. A component-level hardening measure is not promoted to a capability unless the end-to-end property is enforced and validated.

## Approval-bound project manifest

A planned execution plan cannot transition to approved by changing status alone. Project approval evidence is captured without running repository code:

1. read the persisted project root;
2. re-snapshot the explicit selected test targets and verify their hashes;
3. build a bounded dependency-complete detached project mirror outside the source tree;
4. reject symbolic links, Windows reparse-point entries, unsupported filesystem entries, unsafe paths, source mutation during staging, or mirror drift;
5. obtain a deterministic full-project SHA-256 manifest plus file count, directory count, and total regular-file bytes;
6. remove the temporary approval mirror;
7. persist the project evidence only as part of the approval transition.

Project-mirror bounds are 8,192 regular files, 4,096 directories, and 256 MiB total regular-file bytes. Empty directories are retained. Source files are rechecked before copy, copied files are rehashed and marked read-only, the source tree is rescanned, and the detached tree is independently rescanned.

The project manifest captures project-local state only. It does not describe host runtime installations, compiler sysroots, package stores, or arbitrary host files.

## Approval-bound external read provenance

Migration `0016_qa_external_read_provenance.sql` adds a second approval binding for explicitly declared host-side runtime/toolchain trees. Approval still does not invoke Python, Cargo, Rustc, Go, Node, npm, PHP, package scripts, repository hooks, tests, or any other interpreter/compiler command to discover these roots. They must already be explicit trusted-toolchain metadata.

Current external-surface bounds are:

- at most 8 declared roots;
- at most 65,536 regular files across all roots;
- at most 16,384 directories across all roots;
- at most 2 GiB total regular-file bytes across all roots.

For each declaration CodeTwin requires an absolute directory, canonicalizes it, rejects a symlink/reparse-point root, and requires it to be disjoint from the analyzed repository. A declared root may neither reside inside the repository nor contain the repository. Multiple declarations may not canonicalize to the same root.

The tree walker accepts only regular files and directories, requires deterministic Unicode-relative paths, rejects symbolic links, Windows reparse points and special filesystem objects, canonicalizes every entry back under its declared root, and content-hashes every regular file. It records a deterministic per-root manifest containing directory names, file names, file sizes and file SHA-256 values.

The aggregate surface digest is domain-separated from project manifests and includes each root's kind, canonical path, root manifest digest, file count, directory count and total bytes. Approval performs two independent bounded scans of the complete declared surface and requires exact equality. If the surface changes while approval provenance is being captured, approval fails closed rather than storing an unstable snapshot.

An empty declared-root list is permitted during passive planning for backward compatibility, but an execution-capable plan cannot be approved without at least one explicit external root. Existing approved rows that predate this provenance layer are not silently upgraded; typed reconstruction fails closed and requires a new plan/approval.

At execution time the Windows project-mirror path rescans the declared external surface and requires exact equality with the approved typed evidence before restricted process creation. A changed standard library, compiler/sysroot file, package-store file, root path, file size, directory layout or content hash therefore blocks launch.

This is provenance attestation, not read access enforcement. CodeTwin does not yet prevent the restricted process from reading an undeclared host path that Windows ACL/MIC rules otherwise permit. It also does not hold every file in a declared directory immutable for the full process lifetime. External-tree mutation after the pre-launch attestation remains a reason `filesystem_isolation` is false.

## Durable approval invariants

Migration `0015_qa_execution_manifest_binding.sql` binds the project manifest. Migration `0016_qa_external_read_provenance.sql` adds:

- `qa_execution_plans.approved_external_read_surface_sha256`;
- `qa_execution_plans.approved_external_read_surface_json`;
- `qa_execution_runs.external_read_surface_sha256`.

Database triggers enforce the following rules:

- project and external evidence can be bound only during an approval transition;
- a non-approved inserted plan cannot already carry approval evidence;
- approved project/external evidence is immutable;
- plan execution specification is immutable from creation; changing project identity, discovery identity, runner, request, toolchain, policy, capabilities, command or blocking reasons requires a new plan;
- approval may append approval provenance while transitioning from planned to approved, but approved provenance is immutable afterward;
- approved status cannot be downgraded;
- every execution run row must carry a project-manifest digest matching its approved plan;
- every execution run row must also carry an external-read-surface digest matching its approved plan.

The service additionally performs compare-and-update approval: the persisted request/toolchain/policy/capability/command/blocking/provenance JSON must still equal the originally loaded plan while project and external evidence are being captured. A concurrent approval is idempotent only when the resulting approved evidence is exactly the same.

`QaExecutionPlanRecord::execution_plan` requires both evidence sets for an approved plan and carries them into the low-level typed `TestExecutionPlan`. A non-approved plan carrying either approval evidence set is treated as inconsistent instead of normalized silently.

## Exact trusted-runner launch attestation

The exact executable image selected as the trusted runner has a stronger launch-time lock than the directory-level provenance layer.

Before entering the lower restricted launcher, Windows execution:

1. requires `plan.command.program` to exactly equal the approved trusted-toolchain path;
2. requires the runner path to be absolute, regular, outside the analyzed repository, and not a symbolic-link/reparse-point file;
3. canonicalizes the runner and its immediate toolchain directory;
4. canonicalizes `SYSTEMROOT` and `WINDIR`, requires both outside the repository, and requires them to identify the same Windows root;
5. requires the approved runner SHA-256 and verifies it from the same file handle used for the launch lock;
6. opens the canonical runner with Windows sharing restricted to `FILE_SHARE_READ`, denying new write/delete/rename opens while the guard exists;
7. keeps that handle alive across the complete lower restricted-launch call.

The lower launcher retains its independent runner path/hash verification as defense in depth. This stronger handle lifetime currently applies to the exact runner executable, not every file in the declared runtime/toolchain trees.

## Windows zero-capability LPAC production launcher

CodeTwin uses a stable per-user AppContainer profile named `CodeTwinML.QA.RestrictedRunner.V1`. For every approved execution, the generated runner process is created with the profile package SID and **zero capability SIDs**, with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` / `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`.

The approved runtime/toolchain roots are copied into a generated per-run bundle after their approval manifests are re-attested. The copied runner is verified against the approved runner SHA-256. The AppContainer package SID receives narrowly scoped access to the generated project/runtime material and writable artifact/temp locations instead of changing ACLs on the original repository or arbitrary host runtime trees.

The actual runner is created through `CreateProcessAsUserW` with `CREATE_SUSPENDED`. Before its primary thread is resumed, CodeTwin opens the **actual child token** and requires:

- `TokenIsAppContainer = true`;
- `TokenIsLessPrivilegedAppContainer = true`;
- the token is restricted;
- the `WinWriteRestrictedCodeSid` restricted SID is present;
- the low-integrity label is present;
- the AppContainer SID equals the expected profile SID;
- the token has zero capability SIDs.

Only after these checks does CodeTwin assign the child to the configured Job Object and resume the exact primary thread returned by process creation. Any token, profile, process, ACL, handle, or Job Object mismatch fails closed before repository test code is allowed to run.

A separate never-resumed LPAC readiness probe remains as defense-in-depth composition evidence, but it is no longer the production isolation boundary.

## Windows LPAC execution ordering

The Windows execution path uses the following ordering:

1. require an approved plan with project-manifest and external-read-surface evidence;
2. canonicalize the live project root and revalidate selected target snapshots;
3. build a fresh bounded dependency-complete detached project mirror;
4. require the fresh project digest to exactly equal the approved project digest;
5. lock/re-attest the approved runner and rescan the complete declared external surface;
6. prepare an integrity-verified generated LPAC runtime/toolchain bundle and narrow AppContainer ACLs;
7. verify the restricted low-integrity identity/write boundary;
8. create the actual test runner suspended with the zero-capability LPAC attributes and explicit inherited stdio handles only;
9. attest the suspended child token against the restricted/low-integrity/LPAC/zero-capability contract;
10. assign the still-suspended process to the Job Object;
11. resume the exact primary thread and require the expected initial suspend count;
12. enforce bounded timeout, cancellation, CPU/memory/process-tree controls, and bounded stdout/stderr;
13. parse supported runner output and create a test verdict only when parsing completes;
14. persist the run evidence with the exact approved project/runtime digests;
15. terminate descendants and clean generated workspace material on completion/error.

There is intentionally no normal-token, non-LPAC, shell-based, or alternate-logon fallback when a required step fails.

## Restricted identity and write boundary

The Windows identity layer creates a `WRITE_RESTRICTED`, low-integrity token using `WinWriteRestrictedCodeSid`, preserves existing generated-workspace DACLs while adding restricting-SID ACEs, and applies low-integrity mandatory labels.

The probe requires mutation-capable access to the original source root and mirrored project inputs to be denied while generated `artifacts/` and `temp/` remain writable. The original repository ACL is never modified.

This is a write boundary, not a host-wide read sandbox. A restricted process may still read host objects permitted by Windows ACL/MIC rules if it knows their paths.

## Environment, handles, and process containment

The launcher does not inherit the full host environment or a host `PATH`. Required Windows system-root values are retained only after canonical checks. Writable state is redirected where supported through `TEMP`, `TMP`, `GOTMPDIR`, `CARGO_TARGET_DIR`, `GOCACHE`, `NPM_CONFIG_CACHE`, and `XDG_CACHE_HOME`. Python user-site imports and bytecode writes are disabled; `NO_COLOR` and `CI=1` are supplied.

Only explicit standard-I/O handles are inheritable. The actual test runner is born suspended and receives Job Object membership before its primary thread can execute untrusted user-mode code.

A raw process completion is not automatically a test verdict. Pass/fail requires a completed execution, a completed runner-specific parser and an exit code. Timeout, cancellation, infrastructure/setup failure, project-manifest mismatch, external-surface mismatch, toolchain-attestation failure, LPAC-readiness failure or incomplete parsing produces no pass/fail claim.

## Current capability truth

On Windows, the production path is implemented around the strict capability floor required by `SandboxPolicy::default()`: process isolation, generated-workspace filesystem isolation for the project/approved runtime material, zero-capability LPAC network denial, Job Object CPU/memory/process-tree containment, reliable cancellation, wall-clock timeout, bounded output, and a sanitized environment.

The source repository remains outside the generated execution workspace and is not modified. Approved external runtime/toolchain material is re-attested and copied into the per-run bundle rather than executed directly from mutable host paths. The actual child token is attested before resume.

On non-Windows platforms, `current_backend_info()` remains planning-only and `QaExecutionService::availability().execution_enabled` is false. There is no portability fallback that weakens the Windows policy.

The current PR still lacks fresh GitHub-hosted Windows execution evidence because Actions jobs have been failing before runner allocation. That infrastructure limitation does not become a passing sandbox test; Windows runtime/adversarial validation remains an explicit release gate.

## Remaining validation and hardening

Before treating the Windows backend as release-validated across machines, run the real Windows test matrix on a host that supports the required AppContainer/LPAC APIs. The adversarial suite should cover project-manifest mismatch, external-root drift, undeclared-host-read attempts, source write denial, runtime mutation races, artifact/temp writability, runner replacement, inherited-handle escape attempts, descendant process containment, cancellation, CPU/memory limits, timeout behavior, token restrictions, LPAC identity, network-denial attempts, parser truthfulness, and cleanup.

Platform-specific runtime layouts also need coverage for Python, Rust, Go, Node/Vitest/Jest, and PHP/PHPUnit so a runner cannot silently fall back to an ambient package/toolchain store that was not part of the approved bundle.

These are validation/hardening obligations, not permission to fall back to unsandboxed execution. If the strict backend cannot establish its contract on a machine, CodeTwin reports execution unavailable or infrastructure failure and does not fabricate a test verdict.
