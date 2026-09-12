# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a different trust boundary and requires an explicit typed plan, trusted toolchain, user approval, and an OS sandbox backend that can prove the required controls are enforced.

## Current implementation status

This foundation implements planning, policy validation, command generation, durable plan persistence, approval state, future run/result schema, output bounding helpers, and test-verdict rules. **It does not execute repository tests.** The built-in backend availability is `planning_only` and reports `execution_enabled = false`.

A plan created through the current public service is blocked because CodeTwin does not yet have a portable OS sandbox that can enforce process, filesystem, network, CPU, memory, and cancellation guarantees. There is no unsandboxed fallback and callers cannot override the public service's enforced capability set.

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

A `SandboxCapabilities` record describes what a trusted backend actually enforces. Missing required capabilities make the plan `blocked`. The public service currently supplies only its own `planning_only` capability set; it does not accept capability claims from an external caller. A fully capable future internal backend may produce a `planned` plan, which can then move to `approved`; approval still does not imply execution.

## Durable state

Migration `0014_qa_test_execution.sql` adds two tables.

`qa_execution_plans` stores project/discovery provenance, runner kind, status (`blocked`, `planned`, `approved`), typed request/toolchain/policy/capabilities/command JSON, blocking reasons, and approval timestamps.

`qa_execution_runs` reserves bounded result persistence for a future executor. Run states are `queued`, `running`, `completed`, `failed`, `timed_out`, `cancelled`, and `infrastructure_error`. It stores bounded stdout/stderr excerpts, original byte counts, truncation flags, exit code, parser completion, optional test verdict, and structured result JSON.

The current service exposes availability plus plan create, approve, get, and list operations. It deliberately exposes no execute method and does not create or claim execution-run records. The run table is a schema contract for the future sandbox executor rather than evidence that execution already exists.

## Provenance and truth rules

A plan may reference a completed `qa_discovery` run from the same project. Plan provenance also records the project's last indexed time and explicit facts that repository commands, package scripts, and tests were not executed during planning.

A test verdict is only allowed when a future runner process has a `completed` status, the result parser completed, and an exit code exists. Timeout, cancellation, infrastructure errors, failed setup, or incomplete parsing produce no pass/fail claim.

Output excerpts are byte-bounded on UTF-8 boundaries and retain the original byte count plus a truncation flag.

## Future sandbox backends

Actual execution must be added with platform-specific isolation and independently verified capability reporting. Plausible directions include:

- Linux: namespaces, seccomp, cgroups, and a trusted sandbox launcher such as a bubblewrap-style backend;
- Windows: restricted token/AppContainer plus Job Objects and an isolated writable workspace;
- macOS: an OS sandbox profile or equivalent constrained process backend.

These are future implementation directions, not current guarantees. CodeTwin should not advertise microVM/container/network isolation until the corresponding backend exists and demonstrates those controls.

## Security boundary

The planner treats repository metadata and targets as untrusted input. It does not invoke shells, package managers, repository hooks, interpreters, test runners, compilers, browsers, or repository executables. A future executor must consume only approved typed plans, preserve exact toolchain provenance, enforce the declared sandbox policy, bound logs/results, support cancellation, and report infrastructure failure separately from test failure.
