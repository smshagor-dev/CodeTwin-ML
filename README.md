# CodeTwin ML

**Local Software Digital Twin for Predictive Quality, Security, Reliability, and Verified Repair**

CodeTwin ML is a local-first engineering intelligence desktop application. It combines deterministic program analysis, project metadata, persisted evidence, bounded semantic enrichment, and measurable ML components into a durable Software Digital Twin.

## Current capability status

| Capability | Status |
| --- | --- |
| Monorepo + Tauri/React desktop shell | Implemented foundation |
| Local SQLite WAL + numbered migrations | Implemented |
| Project stack discovery | Implemented |
| Tree-sitter source indexing | Implemented baseline for TypeScript/TSX, JavaScript/JSX, Python, Rust, Go, C, C++, PHP |
| Persistent incremental file/symbol index | Implemented |
| Static import observations + deterministic local TS/JS resolution | Implemented baseline |
| Project/File/Symbol Digital Twin graph | Implemented baseline |
| Bounded dependency/impact queries | Implemented baseline |
| Source-backed symbol reference observations | Implemented baseline |
| Conservative same-file semantic symbol resolution | Implemented baseline |
| Explicit LSP semantic enrichment | Implemented baseline for configured TypeScript/JavaScript, Pyright, and Rust Analyzer servers |
| Deterministic code-quality findings | Implemented baseline for large definitions, deep declaration nesting, high local fan-out, and resolved-local dependency cycles |
| Deterministic AppSec + web request-flow findings | Implemented baseline with desktop workspace and durable finding lifecycle for hard-coded credential literals, dynamic execution, weak hashes, unsafe C/C++ APIs, direct request-to-SQL/ORM sinks, unsafe raw SQL APIs, dynamic SQL identifiers, header injection, SSRF, and request-to-process execution |
| Python web security review | Implemented broader static CLI layer for SQL/ORM injection hardening, XSS, SSRF, command/path injection, deserialization, CORS/CSRF/session/JWT, database TLS configuration, dynamic SQL artifacts, and debug-mode evidence |
| Deterministic database artifact analysis | Implemented baseline with desktop workspace for SQL/Prisma artifact inventory, destructive migration review, unscoped UPDATE/DELETE, SQLite foreign-key disable, and literal Prisma datasource URLs |
| Deterministic runtime reliability analysis | Implemented baseline with desktop workspace for Dockerfile/Compose artifact inventory, mutable image references, healthcheck review, and explicit no-restart policies |
| Passive QA/test discovery | Implemented baseline with desktop workspace for bounded test/config inventory and framework evidence without executing tests |
| Sandboxed QA/test execution | Planning/persistence foundation plus Windows suspended Job Object containment, detached hash-pinned input staging, and restricted-token/ACL/MIC readiness probing; public execution remains blocked until the actual launcher uses the restricted identity, the staged workspace is dependency-complete, and network isolation is enforced |
| OpenMindAI Dataset catalog + action routing | Implemented foundation |
| Local ML model package registry + action readiness routing | Implemented foundation with SHA-256/size verification and evaluation provenance |
| Runtime telemetry / live process tracing | Planned |
| Browser QA execution | Planned; passive discovery and execution planning do not imply browser execution |
| ML inference execution adapters | Planned; registry installation does not imply prediction capability |
| Verified repair workflow | Planned |

Planned capabilities are not presented as available results. Semantic graph relationships, quality findings, AppSec/web findings, database review findings, runtime reliability review findings, QA framework/test inventory, QA execution plans, and Python web-security findings are materialized only from concrete persisted or source-backed evidence; ambiguous, unresolved, external, stale, skipped, or unverified runtime/exploitability/execution claims are not converted into guessed facts. An approved QA execution plan is not a test result. The Windows backend closes the pre-assignment execution race through suspended launch and Job Object membership before resume. Detached input staging and the restricted-token readiness probe further establish a candidate write boundary, but the production runner is still launched under the caller's normal token, so filesystem isolation is not yet claimed. Network isolation is also not implemented. Installed ML packages are reported separately from executable inference capability: package integrity and declared evaluation provenance can be verified without claiming that benchmark metrics were independently reproduced or that predictions can already run.

## Development

Prerequisites: Node.js 22+, Rust 1.82+, Python 3.12+, platform dependencies required by Tauri 2.

```bash
npm install
npm run typecheck
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python -m unittest discover -s services/ml/tests
python -m unittest discover -s services/security/tests
python services/security/run.py /path/to/project --format text
```

See `docs/development/SETUP.md`, `docs/architecture/DIGITAL_TWIN.md`, `docs/architecture/LSP_SEMANTIC_ENRICHMENT.md`, `docs/architecture/CODE_QUALITY_ANALYSIS.md`, `docs/architecture/SECURITY_ANALYSIS.md`, `docs/architecture/WEB_SECURITY_REVIEW.md`, `docs/architecture/DATABASE_ANALYSIS.md`, `docs/architecture/RUNTIME_RELIABILITY.md`, `docs/architecture/QA_TEST_DISCOVERY.md`, `docs/architecture/QA_TEST_EXECUTION.md`, and `docs/architecture/ML_MODEL_REGISTRY.md`.

## Privacy and security

Passive source indexing, Digital Twin persistence, deterministic code-quality analysis, deterministic AppSec/web request-flow analysis, Python web-security review, deterministic database analysis, deterministic runtime reliability analysis, passive QA discovery, and QA execution planning treat repositories as untrusted data and do not execute repository commands. The desktop Web Security workspace uses the persisted deterministic security analyzer over current hash-verified indexed source; it does not crawl websites, send exploit payloads, connect to project databases, or execute target code. The Python web-security service performs bounded static source/config inspection only: it does not send HTTP requests, crawl targets, connect to project databases, execute SQL, import project modules, run payloads, or start project code. Secret-like evidence values are redacted. QA discovery reads only bounded conventional test/config candidates and does not invoke test runners, package scripts, browsers, compilers, interpreters, or hooks. The desktop QA workspace exposes only this passive discovery service and persisted evidence. QA execution planning uses allow-listed runner kinds, explicit project-relative targets, trusted absolute toolchain paths, no shell command strings, strict resource/isolation requirements, and durable approval state. The lower-level Windows Job Object backend revalidates trusted runner SHA-256 and selected input hashes, clears inherited environment, launches the runner suspended, assigns it to the Job Object before its initial thread resumes, applies job CPU/memory limits, bounds wall-clock time/log capture, and supports Job Object termination. Detached staging copies only approved hash-pinned inputs outside the source tree. A separate Windows readiness probe can derive a `WRITE_RESTRICTED`, low-integrity token, apply workspace DACL/mandatory-label rules, and verify that the restricted context cannot write the source root or staged inputs while it can write `artifacts/` and `temp/`. That probe does not launch repository code and does not promote filesystem isolation: the production executor still uses the normal caller token, the staged workspace is not yet dependency-complete, and network isolation is absent. The public desktop/service layer therefore still has no execute method. Runtime reliability analysis reads only bounded Dockerfile/Compose artifacts and does not start containers, processes, services, health checks, or network probes; its findings describe configuration evidence rather than live availability. Database analysis reads only bounded SQL/Prisma artifacts, never opens the analyzed project's database, and never executes migrations or queries. Literal Prisma datasource values are redacted before persistence. AppSec source reads are restricted to active indexed files whose current bytes still match the persisted content hash; potential credential literals are redacted and are never persisted. LSP semantic enrichment is a separate explicit workflow: it requires project trust and a user-configured absolute external language-server executable. CodeTwin does not discover or execute a language server from the analyzed repository. The ML model registry treats packages as data only: it validates safe paths, license metadata, pinned evaluation provenance, byte sizes, and SHA-256 hashes, and it does not import or execute code from model packages.
