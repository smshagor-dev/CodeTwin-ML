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
Set `CODETWIN_GO_SECURITY_BIN` to the **absolute path** of that executable
before launching the desktop application. Use **Agents → Propose with local Go**
after indexing a project. Inspect the proposed DAG, choose **Use this reviewed
task plan**, then create and separately approve/run the existing Rust review.
The Go binary is not automatically bundled in desktop installers yet.

## Protocol and security boundaries

- Rust sends one versioned JSON request on stdin, containing only the
  user-authored objective. Go sends one JSON `TaskProposal` on stdout.
- There is no shell interpolation or HTTP port, no command execution, and no
  autonomous vulnerability exploitation in this Go module.
- A ten-second process deadline, 6000-byte response cap, strict JSON input,
  six-role allowlist and Rust DAG validation reject unexpected output.
- Go chooses registered passive specialists; Rust checks the indexed project,
  hashes, user approval, budgets, dependencies, cancellation and audit state.
- An unconfigured or unavailable binary is reported explicitly, not silently
  simulated. Go receives no credentials, project paths, source code, or findings.
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
