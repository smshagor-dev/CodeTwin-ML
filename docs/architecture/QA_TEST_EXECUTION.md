# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a different trust boundary and requires an explicit typed plan, trusted toolchain, user approval, pinned execution inputs, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The foundation implements planning, policy validation, command generation, durable plan persistence, approval state, future run/result schema, output bounding helpers, test-verdict rules, target snapshot hashing, trusted-toolchain hash revalidation, and a first Windows Job Object execution primitive.

The current public `QaExecutionService` remains planning-only and exposes no execute method. The Windows primitive is intentionally **not** promoted to a full sandbox: it assigns the process to a Job Object after spawn, has no restricted-token/AppContainer boundary, and does not isolate filesystem or network access. Therefore the default strict policy still produces a blocked plan and there is no unsandboxed fallback in the desktop/service layer.

## Typed runner model

Only allow-listed runner kinds can be represented:

- Pytest;
- Rust `cargo test` integration tests;
- Go `go test` packages derived from explicit targets;
- Vitest;
- Jest;
- PHPUnit.

The plan stores an exact trusted absolute executable path and a generated argument vector. It never stores or executes a shell command string. Package-script entrypoints such as `npm test` are deliberately outside this contract.

Every request must contain explicit project-relative targets. Absolute paths, parent traversal, Windows-style backslash targets, empty targets, and requests beyond the configured target bound are rejected. Rust integration-test targets are restricted to conventional `tests/*.rs` paths before a `cargo test --test <name>` command can be planned.

## Default sandbox policy

The default policy requires all of the following:

- process isolation;
- isolated filesystem/write scope;
- network isolation;
- CPU-time enforcement;
- memory-limit enforcement;
- reliable cancellation;
- a wall-clock timeout;
- bounded output capture;
- bounded target count;
- no inherited host environment.

A `SandboxCapabilities` record describes what a trusted backend actually guarantees. Missing required capabilities make the plan `blocked`. Controls that exist but are not strong enough to satisfy a sandbox guarantee are reported separately and must not be promoted into capability flags.

## Windows Job Object primitive

On Windows the `qa-execution` crate now exposes a constrained execution primitive around a Job Object. It provides these concrete controls:

- Job Object creation before runner launch;
- kill-on-job-close;
- job-wide CPU-time limit;
- job-wide memory limit;
- wall-clock timeout polling;
- explicit cancellation through `TerminateJobObject`;
- no shell command execution;
- cleared host environment with a minimal Windows environment allow-list;
- byte-bounded stdout/stderr capture with a bounded post-termination drain wait;
- trusted runner path validation outside the analyzed repository;
- required runner SHA-256 revalidation immediately before launch;
- exact selected test-input SHA-256 snapshots and pre-launch revalidation;
- symlink and root-escape rejection for selected test inputs and trusted runner paths.

These controls are useful, but the current implementation assigns the child process to the Job Object **after** `spawn()`. A process could theoretically create a child before assignment. Because of that race, the backend does not claim process isolation, cancellation containment, CPU containment, or memory containment as sandbox guarantees yet. It also has no filesystem or network isolation. `current_backend_info()` reports these limitations explicitly and leaves all `SandboxCapabilities` false.

The execution primitive only accepts an already-approved plan whose capability record exactly matches the current backend and whose blocking reasons are empty. Because the current public service creates plans against a planning-only/strict capability set, normal strict plans remain blocked. End-to-end service wiring must not relax this automatically.

## Execution input integrity

Execution inputs can be snapshotted with `snapshot_execution_inputs`. Each selected test target must resolve to a regular, non-symlink file inside the canonical project root and is limited to 8 MiB. The snapshot stores relative path, byte size, and SHA-256.

`verify_execution_inputs` requires the execution-time target set to match the approved snapshot exactly and rejects changed content or size. This prevents a selected test file from being silently replaced between approval and launch when a caller persists and reuses the approved snapshot.

The runner itself receives the same treatment. Execution requires an absolute, regular, non-symlink executable outside the analyzed repository and a 64-hex-character SHA-256 pinned in the trusted toolchain record. The executable is hashed again immediately before launch.

## Durable state

Migration `0014_qa_test_execution.sql` adds two tables.

`qa_execution_plans` stores project/discovery provenance, runner kind, status (`blocked`, `planned`, `approved`), typed request/toolchain/policy/capabilities/command JSON, blocking reasons, and approval timestamps.

`qa_execution_runs` reserves bounded result persistence for a future service-level executor. Run states are `queued`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, and `infrastructure_error`. It stores bounded stdout/stderr excerpts, original byte counts, truncation flags, exit code, parser completion, optional test verdict, and structured result JSON.

The current service exposes availability plus plan create, approve, get, and list operations. It deliberately exposes no execute method and does not create or claim execution-run records. The new Windows primitive lives in the lower-level `qa-execution` crate; end-to-end persistence and desktop invocation remain a separate step.

## Provenance and truth rules

A plan may reference a completed `qa_discovery` run from the same project. Plan provenance also records the project's last indexed time and explicit facts that repository commands, package scripts, and tests were not executed during planning.

A raw process completion is not automatically a test verdict. The Windows primitive returns `parser_completed = false` and `tests_passed = null`. A pass/fail verdict is only allowed when a runner process has a `completed` status, the runner-specific result parser completed, and an exit code exists. Timeout, cancellation, infrastructure errors, failed setup, or incomplete parsing produce no pass/fail claim.

Output excerpts are byte-bounded and retain the original byte count plus a truncation flag. If pipe draining does not finish within the bounded post-process interval, the primitive returns an infrastructure error instead of hanging or claiming a clean result.

## Next sandbox hardening steps

The Windows path still needs a pre-execution security boundary before its controls can be promoted to sandbox capabilities:

- create the process suspended so Job Object assignment happens before untrusted code runs;
- use a restricted token or AppContainer-style identity;
- restrict filesystem writes to an isolated workspace;
- disable or isolate network access;
- then independently verify child-process containment, resource limits, cancellation, and escape resistance.

Linux and macOS backends remain future work. Plausible directions include Linux namespaces/seccomp/cgroups with a trusted sandbox launcher and an OS sandbox profile or equivalent constrained process backend on macOS.

## Security boundary

The planner treats repository metadata and targets as untrusted input. The public desktop/service layer still does not invoke shells, package managers, repository hooks, interpreters, test runners, compilers, browsers, or repository executables. The lower-level Windows primitive is intentionally not connected to that public execution authority yet. Future wiring must consume only approved typed plans, persist and revalidate input snapshots, preserve exact toolchain provenance, enforce the declared sandbox policy, bound logs/results, support cancellation, and report infrastructure failure separately from test failure.
