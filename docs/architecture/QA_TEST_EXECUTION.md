# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a different trust boundary and requires an explicit typed plan, trusted toolchain, user approval, pinned execution inputs, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The foundation implements planning, policy validation, command generation, durable plan persistence, approval state, future run/result schema, output bounding helpers, test-verdict rules, target snapshot hashing, trusted-toolchain hash revalidation, a Windows Job Object constrained-execution backend, detached hash-pinned input staging, and a Windows restricted-identity readiness probe.

The Windows backend creates the runner with `CREATE_SUSPENDED`, assigns the still-suspended process to the configured Job Object, resolves the one initial thread, and resumes it only after assignment succeeds. This removes the earlier interval in which repository code could run before Job Object membership. The backend therefore promotes process-tree containment, CPU limit, memory limit, and cancellation into enforced capability flags.

Detached staging copies only approved, hash-pinned inputs to a generated workspace outside the analyzed repository. The new Windows identity readiness path can create a write-restricted, low-integrity token, apply an explicit workspace ACL/mandatory-integrity contract, impersonate the token, and verify the intended write boundary. This is evidence that the Windows host can establish the security contract; it is **not** execution authority. The actual runner launcher still uses the caller's normal primary token.

Accordingly, the public `QaExecutionService` still reports `execution_enabled = false` and exposes no execute method. `filesystem_isolation` and `network_isolation` remain false, normal strict plans remain `blocked`, and there is no unsandboxed fallback.

## Typed runner model

Only allow-listed runner kinds can be represented: Pytest, Rust `cargo test` integration tests, Go `go test`, Vitest, Jest, and PHPUnit. The plan stores an exact trusted absolute executable path and generated argument vector. It never stores or executes a shell command string or package-script entrypoint.

Every request must contain explicit project-relative targets. Absolute paths, parent traversal, Windows-style backslash targets, empty targets, and requests beyond the configured target bound are rejected. Rust integration-test targets are restricted to conventional `tests/*.rs` paths before a `cargo test --test <name>` command can be planned.

## Default sandbox policy

The default policy requires process isolation, filesystem/write isolation, network isolation, CPU and memory limits, reliable cancellation, a wall-clock timeout, bounded output and target count, and no inherited host environment.

A `SandboxCapabilities` record describes what a trusted backend actually guarantees. Missing required capabilities make the plan `blocked`. Controls that exist but have not yet been connected to the actual runner must not be promoted into capability flags.

## Windows suspended-launch Job Object backend

The Windows execution primitive provides:

- Job Object creation and resource policy before launch;
- `CREATE_SUSPENDED` runner creation;
- Job Object assignment before the initial thread resumes;
- fail-closed thread-state verification;
- kill-on-job-close, job CPU time and job memory limits;
- bounded wall-clock timeout and explicit cancellation through `TerminateJobObject`;
- no shell command execution;
- cleared host environment with a minimal Windows allow-list;
- bounded stdout/stderr capture and bounded drain wait;
- trusted runner path and SHA-256 revalidation;
- exact selected-input SHA-256 revalidation and symlink/root-escape rejection.

`current_backend_info()` reports `process_isolation`, `cpu_limit`, `memory_limit`, and `cancellation` on Windows. Here `process_isolation` means process-tree containment under the Job Object; it does not mean a reduced Windows security identity or isolated filesystem/network namespace.

## Detached execution workspace

`prepare_detached_workspace` accepts only already snapshotted inputs, revalidates them against the live source tree, and copies them into a generated workspace outside the analyzed repository. The workspace is bounded to 128 inputs and 64 MiB total staged input bytes.

Approved inputs are copied under `inputs/`, rehashed, and marked read-only. Separate `artifacts/` and `temp/` directories are created for future writable execution state. Workspace verification checks canonical containment, copied hashes and sizes, the read-only marker, and the aggregate byte count. Cleanup is restricted to verified CodeTwin-generated workspace roots.

The workspace deliberately records `dependency_complete = false`. It does not yet copy the complete import/config/build/runtime dependency closure required by arbitrary Pytest, Cargo, Go, Vitest, Jest, or PHPUnit runs, so it is not yet a general execution root.

## Windows restricted-identity readiness

`probe_restricted_identity` is a security-readiness check for a verified detached workspace. On Windows it:

1. opens the current process token only for the access needed to derive a restricted token;
2. creates a token with `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED`;
3. adds `WinWriteRestrictedCodeSid` as the restricting SID and verifies that the resulting token is restricted;
4. assigns the token a low mandatory-integrity label;
5. preserves existing workspace DACLs while granting the restricting SID read/execute access to the workspace root and staged inputs, and read/write/execute access to `artifacts/` and `temp/`;
6. applies a low-integrity mandatory label to the generated workspace tree;
7. temporarily impersonates the restricted token and performs real Windows access probes;
8. requires source-repository-root write access to be denied;
9. requires staged-input write access to be denied;
10. requires `artifacts/` and `temp/` write access to be allowed;
11. reverts impersonation before returning any evidence.

The source repository's ACL is not modified. The write restriction comes from the token's restricting SID plus mandatory-integrity policy. If any access result differs from the expected contract, the probe fails closed.

This readiness evidence explicitly reports `executor_uses_restricted_token = false`, `filesystem_isolation_promoted = false`, and `network_isolation_enforced = false`. The production execution primitive still launches through the existing normal-token `Command` path, so a successful probe must not be interpreted as sandboxed execution.

## Suspended-process ordering

The current process-containment ordering is security-significant: configure Job Object, construct direct executable/argv, request `CREATE_SUSPENDED`, assign the returned process to the Job Object, prove one suspended initial thread, resume exactly once, then enter timeout/cancellation/result handling. Assignment or thread-state failure terminates the process/job instead of permitting execution outside containment.

## Execution input and runner integrity

Execution inputs can be snapshotted with `snapshot_execution_inputs`. Each selected test target must resolve to a regular, non-symlink file inside the canonical project root and is limited to 8 MiB. The snapshot stores relative path, byte size, and SHA-256. `verify_execution_inputs` requires the execution-time target set and bytes to match exactly.

The runner itself must be an absolute, regular, non-symlink executable outside the analyzed repository with a 64-hex-character SHA-256 pinned in the trusted toolchain record. The executable is hashed again immediately before launch.

## Durable state and truth rules

Migration `0014_qa_test_execution.sql` stores typed execution plans and reserves `qa_execution_runs` for future bounded results. The current service exposes availability plus plan create, approve, get, and list operations; it exposes no execute method and creates no execution-run records.

Planning provenance records that repository commands, package scripts, and tests were not executed. A raw process completion is not automatically a test verdict: pass/fail requires completed execution, a completed runner-specific parser, and an exit code. Timeout, cancellation, infrastructure errors, failed setup, or incomplete parsing produce no pass/fail claim.

## Next sandbox hardening steps

Before filesystem isolation can be promoted, the restricted token and workspace contract must be wired into the **actual** Windows launcher while preserving suspended creation, pre-resume Job Object assignment, trusted toolchain provenance, sanitized environment, stdio capture, timeout, cancellation, and failure cleanup. The detached workspace must also become dependency-complete for the selected runner without falling back to the live source repository.

After that, adversarial integration tests must prove source-tree write denial, staged-input immutability, writable artifact/temp scope, process-tree containment, resource limits, cancellation, and escape resistance. Network isolation remains an independent strict blocker and must be implemented and verified before public repository execution can be enabled.

Linux and macOS backends remain future work.

## Security boundary

The planner treats repository metadata and targets as untrusted input. The public desktop/service layer still does not invoke shells, package managers, repository hooks, interpreters, test runners, compilers, browsers, or repository executables. The lower-level Windows execution and identity primitives are intentionally not connected to public execution authority yet. Future wiring must consume only approved typed plans, persist and revalidate input snapshots, preserve exact toolchain provenance, enforce every required sandbox capability, bound logs/results, support cancellation, and report infrastructure failure separately from test failure.
