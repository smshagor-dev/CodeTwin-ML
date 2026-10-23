# Go security planner with SQLite persistence

CodeTwin has an optional Go process for proposing a **bounded passive** review
task graph. The desktop and authorization supervisor remain Rust/Tauri. All
approved review plans, steps, handoffs, and findings are persisted by Rust in
the existing `codetwin.sqlite3` database (SQLite WAL). No PostgreSQL,
pgvector, Go SQLite driver, Docker service or network server is required for
this bridge.

## Build and use

From `services/security-engine`:

```bash
go test ./...
go build -trimpath -o codetwin-security .
```

On Windows use `go build -trimpath -o codetwin-security.exe .`.
Tauri's `beforeBuildCommand` and `beforeDevCommand` now run
`npm run build:go-sidecar`. This compiles the Go binary for the Rust target
triple into `apps/desktop/src-tauri/binaries/`, and `bundle.externalBin`
includes it in desktop packages. Developers building from source need Go 1.23+,
Rust and Node. For cross-compilation, set `TAURI_ENV_TARGET_TRIPLE` or
`CARGO_BUILD_TARGET` explicitly. Universal macOS packaging is not supported
by this single-target builder.

At runtime, Rust locates the bundled executable next to the desktop binary.
`CODETWIN_GO_SECURITY_BIN` is an optional development override requiring an
absolute file path. A two-second `--health` handshake checks protocol identity
before accepting a plan; no PostgreSQL daemon is started.

Use **Agents → Propose with local Go** after indexing a project. Inspect the
proposed DAG, choose **Use this reviewed task plan**, then create and separately
approve/run the existing Rust review.

## Protocol and security boundaries

- Rust sends one versioned JSON request on stdin, containing only the
  user-authored objective and at most twelve project-scoped role/status pairs
  from terminal review memory. Go sends one JSON `TaskProposal` on stdout.
  Neither raw source nor findings, run IDs, file paths or credentials are shared.
- There is no shell interpolation or HTTP port, no command execution, and no
  autonomous vulnerability exploitation in this Go module.
- A two-second sidecar handshake, ten-second planning deadline, 6000-byte response cap, strict JSON input,
  six-role allowlist and Rust DAG validation reject unexpected output.
- Go uses failed prior specialist outcomes to suggest bounded follow-up roles
  when appropriate. Every memory item must have a registered role and a
  terminal completed/failed status; unknown fields and oversized history fail
  closed. A memory suggestion never authorizes execution.
- Go chooses registered passive specialists; Rust checks the indexed project,
  hashes, user approval, budgets, dependencies, cancellation and audit state.
- An unconfigured or unavailable binary is reported explicitly, not silently
  simulated. Go receives no credentials, project paths, source code, raw
  findings or stored report content.
- The same existing SQLite `native_agent_*` tables store approved reviews;
  no alternate database is created.

## Upstream and scope

PentAGI's Flow/Task/Subtask/Agent separation informed this adapter's design.
**The original PentAGI orchestrator, exploit-tool packages, and
PostgreSQL-based services have not been copied into this module.** They cannot
be dropped unchanged into an SQLite-only desktop application. Reusing upstream
source directly will require a separately reviewed SQLite storage adapter,
dependency-license inventory, tool sandboxing, engagement authorization,
recovery tests, and a process-boundary contract. Do not present this
first bridge as full PentAGI parity.

See PentAGI's MIT LICENSE and NOTICE at
https://github.com/vxcontrol/pentagi; third-party and Cloud SDK service
restrictions must be reviewed before distributing derived components.
