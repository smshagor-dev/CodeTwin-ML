# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a different trust boundary and requires an explicit typed plan, trusted toolchain, user approval, pinned execution inputs, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The foundation implements planning, policy validation, command generation, durable plan persistence, approval state, future run/result schema, output bounding helpers, test-verdict rules, target snapshot hashing, trusted-toolchain hash revalidation, and a Windows Job Object constrained-execution backend.

The Windows backend now creates the runner with `CREATE_SUSPENDED`, assigns the still-suspended process to the configured Job Object, resolves the one initial thread, and resumes it only after assignment succeeds. This removes the earlier interval in which repository code could run before Job Object membership. The backend therefore promotes process-tree containment, CPU limit, memory limit, and cancellation into enforced capability flags.

The public `QaExecutionService` still reports `execution_enabled = false` and exposes no execute method. Filesystem/write isolation and network isolation are not implemented, and restricted-token/AppContainer identity hardening is still pending. Because the default strict policy requires all of those controls, public plans remain `blocked` and there is no unsandboxed fallback.

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

## Windows suspended-launch Job Object backend

On Windows the `qa-execution` crate provides these concrete controls:

- Job Object creation and resource policy configuration before runner launch;
- runner creation with the Windows `CREATE_SUSPENDED` flag;
- Job Object assignment while the initial thread is still suspended;
- exact single-thread discovery for the newly created process before `ResumeThread`;
- refusal to continue when the expected initial suspended-thread state cannot be proven;
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

`current_backend_info()` now reports the Windows backend as enforcing `process_isolation`, `cpu_limit`, `memory_limit`, and `cancellation`. Here `process_isolation` means process-tree containment under the Job Object: the runner cannot execute before membership is established. It does **not** mean that the process has a reduced Windows security identity or isolated filesystem/network namespace.

The remaining strict blockers are intentionally visible: filesystem/write isolation and network isolation are false, and restricted-token/AppContainer identity hardening is not yet implemented. These gaps keep normal public plans blocked.

## Suspended-process ordering

The ordering is security-significant:

1. construct and configure the Job Object;
2. build the direct executable/argv runner command with cleared environment and piped output;
3. request `CREATE_SUSPENDED` from the Windows process creation path;
4. assign the returned process handle to the Job Object while its initial thread cannot run;
5. enumerate the new process threads and require exactly one initial thread;
6. resume that thread exactly once and require the prior suspend count to be one;
7. only then begin normal timeout/cancellation/result handling.

If Job assignment or thread-state verification fails, CodeTwin terminates the suspended process/job instead of allowing execution outside the intended containment boundary.

This design deliberately preserves Rust's standard Windows process argument handling, stdio plumbing, and environment construction instead of reimplementing Windows command-line quoting in CodeTwin.

## Execution input integrity

Execution inputs can be snapshotted with `snapshot_execution_inputs`. Each selected test target must resolve to a regular, non-symlink file inside the canonical project root and is limited to 8 MiB. The snapshot stores relative path, byte size, and SHA-256.

`verify_execution_inputs` requires the execution-time target set to match the approved snapshot exactly and rejects changed content or size. This prevents a selected test file from being silently replaced between approval and launch when a caller persists and reuses the approved snapshot.

The runner itself receives the same treatment. Execution requires an absolute, regular, non-symlink executable outside the analyzed repository and a 64-hex-character SHA-256 pinned in the trusted toolchain record. The executable is hashed again immediately before launch.

## Durable state

Migration `0014_qa_test_execution.sql` adds two tables.

`qa_execution_plans` stores project/discovery provenance, runner kind, status (`blocked`, `planned`, `approved`), typed request/toolchain/policy/capabilities/command JSON, blocking reasons, and approval timestamps.

`qa_execution_runs` reserves bounded result persistence for a future service-level executor. Run states are `queued`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, and `infrastructure_error`. It stores bounded stdout/stderr excerpts, original byte counts, truncation flags, exit code, parser completion, optional test verdict, and structured result JSON.

The current service exposes availability plus plan create, approve, get, and list operations. It deliberately exposes no execute method and does not create or claim execution-run records. The Windows backend lives in the lower-level `qa-execution` crate; end-to-end persistence and desktop invocation remain a separate step.

## Provenance and truth rules

A plan may reference a completed `qa_discovery` run from the same project. Plan provenance also records the project's last indexed time and explicit facts that repository commands, package scripts, and tests were not executed during planning.

A raw process completion is not automatically a test verdict. The Windows primitive returns `parser_completed = false` and `tests_passed = null`. A pass/fail verdict is only allowed when a runner process has a `completed` status, the runner-specific result parser completed, and an exit code exists. Timeout, cancellation, infrastructure errors, failed setup, or incomplete parsing produce no pass/fail claim.

Output excerpts are byte-bounded and retain the original byte count plus a truncation flag. If pipe draining does not finish within the bounded post-process interval, the primitive returns an infrastructure error instead of hanging or claiming a clean result.

## Next sandbox hardening steps

The Windows path still needs the remaining security boundaries before public repository execution can be enabled:

- create and verify a restricted primary token or AppContainer-style identity;
- restrict filesystem writes to an isolated workspace rather than the analyzed repository;
- disable or isolate network access;
- add adversarial Windows integration tests for child-process containment, cancellation, resource-limit enforcement, filesystem denial, network denial, and token restrictions;
- only then wire approved plans to durable execution-run persistence and the desktop QA workspace.

Linux and macOS backends remain future work. Plausible directions include Linux namespaces/seccomp/cgroups with a trusted sandbox launcher and an OS sandbox profile or equivalent constrained process backend on macOS.

## Security boundary

The planner treats repository metadata and targets as untrusted input. The public desktop/service layer still does not invoke shells, package managers, repository hooks, interpreters, test runners, compilers, browsers, or repository executables. The lower-level Windows backend is intentionally not connected to public execution authority yet. Future wiring must consume only approved typed plans, persist and revalidate input snapshots, preserve exact toolchain provenance, enforce every required sandbox capability, bound logs/results, support cancellation, and report infrastructure failure separately from test failure.
