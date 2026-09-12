# QA / Test Execution Foundation

CodeTwin separates passive QA discovery from repository test execution. Passive discovery may inventory tests and framework configuration without granting execution authority. Test execution is a different trust boundary and requires an explicit typed plan, trusted toolchain, user approval, pinned execution inputs, and an OS backend whose enforced controls are represented conservatively.

## Current implementation status

The foundation implements planning, policy validation, command generation, durable plan persistence, approval state, future run/result schema, output bounding helpers, test-verdict rules, target snapshot hashing, trusted-toolchain hash revalidation, Windows Job Object containment, detached hash-pinned input staging, restricted-token/ACL/MIC readiness probing, and a crate-level Windows restricted-process launcher.

The Windows crate-level execution path now derives a `WRITE_RESTRICTED`, low-integrity primary token and launches the exact trusted toolchain through `CreateProcessAsUserW`. The process is created with `CREATE_SUSPENDED`, inherits only an explicit standard-I/O handle list, is assigned to the Job Object before execution, and is resumed directly through the primary thread handle returned by process creation. CPU time, job memory, wall-clock time, output capture, cancellation, trusted-toolchain hashing, and selected-input hashing remain bounded and revalidated.

This does **not** enable public test execution. The strict default policy still requires `filesystem_isolation` and `network_isolation`, while both capabilities remain false. The current restricted runner reads project dependencies from the live source tree under a write-restricted/low-integrity identity and redirects common writable temp/cache state into the generated detached workspace, but the workspace is still `dependency_complete = false`. Separate desktop/window-station isolation and adversarial Windows validation are also pending. The public `QaExecutionService` therefore continues to report `execution_enabled = false`, exposes no execute method, and normal strict plans remain `blocked`.

## Typed runner model

Only allow-listed runner kinds can be represented: Pytest, Rust `cargo test` integration tests, Go `go test`, Vitest, Jest, and PHPUnit. The plan stores an exact trusted absolute executable path and generated argument vector. It never stores or executes a shell command string or package-script entrypoint.

Every request must contain explicit project-relative targets. Absolute paths, parent traversal, Windows-style backslash targets, empty targets, and requests beyond the configured target bound are rejected. Rust integration-test targets are restricted to conventional `tests/*.rs` paths before a `cargo test --test <name>` command can be planned.

## Default sandbox policy

The default policy requires process isolation, filesystem/write isolation, network isolation, CPU and memory limits, reliable cancellation, a wall-clock timeout, bounded output and target count, and no inherited host environment.

A `SandboxCapabilities` record describes what a trusted backend actually guarantees. Missing required capabilities make the plan `blocked`. Controls that exist but are not yet strong enough to prove a capability remain visible as limitations rather than being promoted.

## Windows restricted suspended launcher

The crate-level Windows execution path performs this sequence:

1. canonicalize the project root and revalidate the exact trusted executable SHA-256;
2. revalidate the selected test-input snapshots;
3. create a bounded detached workspace outside the repository;
4. apply the restricted-identity workspace ACL/MIC contract and probe the expected write matrix;
5. derive a fresh `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED` low-integrity primary token;
6. create inherited stdin/stdout/stderr handles, then constrain inheritance with `STARTUPINFOEXW` and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` so no unrelated inheritable host handles are passed to the child;
7. provide the trusted executable separately through `lpApplicationName` and construct a writable Unicode command-line buffer for the allow-listed argv;
8. build a minimal Unicode environment instead of inheriting the host environment;
9. point `TEMP`, `TMP`, `GOTMPDIR`, Cargo target output, Go cache, npm cache, and generic cache state at the detached workspace;
10. call `CreateProcessAsUserW` with `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW`;
11. assign the returned process handle to the configured Job Object while the primary thread is still suspended;
12. call `ResumeThread` on the exact primary-thread handle returned by process creation and require an initial suspend count of one;
13. enter bounded timeout/cancellation/output handling only after assignment and resume succeed;
14. fail closed and terminate the suspended process/job if setup, assignment, token use, or resume verification fails.

There is intentionally no weaker alternate-logon or normal-token fallback if restricted process creation fails. `CreateProcessAsUserW` privilege or access failures are infrastructure failures.

The explicit application path avoids executable-name ambiguity. The child receives only stdin/stdout/stderr handles; stdout/stderr parent read handles are explicitly marked non-inheritable. This is stricter than generic `bInheritHandles = TRUE` inheritance.

## Current capability truth

`current_backend_info()` continues to report `process_isolation`, `cpu_limit`, `memory_limit`, and `cancellation` on Windows. `process_isolation` still means process-tree containment under the Job Object. The restricted primary token is now an additional enforced launcher control, but `filesystem_isolation` is intentionally still false because:

- execution still reads dependencies/configuration from the live source tree rather than a dependency-complete detached root;
- the detached workspace records `dependency_complete = false`;
- source write denial has not yet been exercised by adversarial Windows integration tests in CI;
- the restricted runner still shares the caller desktop/window station;
- the current write-boundary probes cover the source root and staged inputs but do not yet constitute an exhaustive proof over every possible host filesystem object.

`network_isolation` is also false because no OS-level network denial mechanism is enforced yet.

## Detached execution workspace

`prepare_detached_workspace` accepts only already snapshotted inputs, revalidates them against the live source tree, and copies them into a generated workspace outside the analyzed repository. The workspace is bounded to 128 inputs and 64 MiB total staged input bytes.

Approved inputs are copied under `inputs/`, rehashed, and marked read-only. Separate `artifacts/` and `temp/` directories are created for writable execution state. Workspace verification checks canonical containment, copied hashes and sizes, the read-only marker, and the aggregate byte count. Cleanup is restricted to verified CodeTwin-generated workspace roots.

The restricted launcher currently uses the live source tree as its working directory so project imports/configuration remain resolvable while the token prevents the write accesses covered by the verified contract. Common temporary/build caches are redirected into `artifacts/` or `temp/`. This is an intermediate compatibility step, not the final filesystem sandbox design.

## Windows restricted identity

The Windows identity layer:

- opens the current process token only for the access needed to derive a restricted token;
- creates a restricted token with `DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED`;
- uses `WinWriteRestrictedCodeSid` as the restricting SID and verifies that the token is restricted;
- applies a low mandatory-integrity label;
- preserves existing generated-workspace DACLs while adding restricting-SID ACEs;
- grants read/execute to workspace root and staged inputs and read/write/execute to `artifacts/` and `temp/`;
- applies low-integrity mandatory labels to the generated workspace tree;
- impersonates a restricted token for non-mutating access probes;
- requires source-root mutation-capable rights and staged-input mutation rights to be denied;
- requires artifact/temp writable rights to be allowed;
- always reverts impersonation before returning evidence.

The source repository ACL is not modified. A second freshly derived token using the same restricted-token construction is used by the actual Windows launcher after the readiness probe succeeds.

## Suspended-process ordering

The current restricted launcher no longer needs ToolHelp enumeration to find the initial thread. `CreateProcessAsUserW` returns the primary thread handle directly. CodeTwin therefore creates the process suspended, assigns the returned process handle to the Job Object, resumes the exact returned primary thread, and requires the prior suspend count to equal one. This removes an unnecessary enumeration step and keeps the pre-execution ordering explicit.

The older Job Object primitive remains internal implementation history, but the crate-level Windows `execute_approved_plan` routing now selects the restricted launcher when execution eventually becomes eligible under the strict capability floor.

## Environment and output boundary

The launcher does not inherit the host environment. It carries forward only required Windows system-root values and explicit CodeTwin/test controls. Writable state is redirected where supported: `TEMP`, `TMP`, `GOTMPDIR`, `CARGO_TARGET_DIR`, `GOCACHE`, `NPM_CONFIG_CACHE`, and `XDG_CACHE_HOME` point inside the detached workspace. Python user-site imports and bytecode writes are disabled, `NO_COLOR` is set, and `CI=1` is supplied.

Output is captured through separate stdout/stderr pipes with independent byte budgets. Reader threads retain original byte counts and truncation state. A bounded post-process drain timeout converts stuck output inheritance into an infrastructure error instead of hanging or claiming a clean result.

## Execution input and runner integrity

Execution inputs can be snapshotted with `snapshot_execution_inputs`. Each selected test target must resolve to a regular, non-symlink file inside the canonical project root and is limited to 8 MiB. The snapshot stores relative path, byte size, and SHA-256. `verify_execution_inputs` requires the execution-time target set and bytes to match exactly.

The runner itself must be an absolute, regular, non-symlink executable outside the analyzed repository with a 64-hex-character SHA-256 pinned in the trusted toolchain record. The executable is hashed again immediately before restricted launch. The exact executable path is also passed via `lpApplicationName` instead of relying on search-path parsing.

## Durable state and truth rules

Migration `0014_qa_test_execution.sql` stores typed execution plans and reserves `qa_execution_runs` for future bounded results. The current service exposes availability plus plan create, approve, get, and list operations; it exposes no execute method and creates no execution-run records.

Planning provenance records that repository commands, package scripts, and tests were not executed. A raw process completion is not automatically a test verdict: pass/fail requires completed execution, a completed runner-specific parser, and an exit code. Timeout, cancellation, infrastructure errors, failed setup, or incomplete parsing produce no pass/fail claim.

## Next sandbox hardening steps

The next Windows filesystem slice should replace live-source dependency reads with a dependency-complete, bounded execution snapshot/closure or another stronger isolated-root mechanism. It must preserve trusted toolchain provenance and exact target hashes while keeping only approved writable state under `artifacts/` and `temp/`.

A separate restricted desktop/window station or equivalent UI isolation should be added before public execution, because restricted-token guidance warns against running untrusted restricted applications on the caller's default desktop.

After that, adversarial Windows integration tests must prove source-tree write denial, staged-input immutability, artifact/temp writability, explicit handle inheritance, process-tree containment, cancellation, CPU/memory limits, timeout behavior, command-line quoting, token restrictions, and failure cleanup. Only after those tests pass should `filesystem_isolation` be considered for promotion.

Network isolation remains an independent strict blocker and must be implemented and verified before public repository execution can be enabled. Linux and macOS backends remain future work.

## Security boundary

The planner treats repository metadata and targets as untrusted input. The public desktop/service layer still does not invoke shells, package managers, repository hooks, interpreters, test runners, compilers, browsers, or repository executables. The restricted Windows launcher exists below that public boundary and is unreachable through normal strict plans while required capabilities are missing. Future public wiring must consume only approved typed plans, persist and revalidate input snapshots, preserve exact toolchain provenance, enforce every required sandbox capability, bound logs/results, support cancellation, and report infrastructure failure separately from test failure.
