# CodeTwin ML

**A local-first desktop app that understands your codebase, finds quality and security problems, and helps you fix them safely — with proof.**

CodeTwin ML builds a *Software Digital Twin* of a project on your machine: a searchable, persistent model of its files, symbols, dependencies, findings, and evidence. On top of that it runs code-quality, security, database, runtime, and QA analysis, optional local ML, and hash-verified repair workflows.

> **Core rule:** CodeTwin records only what it can prove. Missing, skipped, or uncertain evidence is shown as such — it is never quietly turned into a "pass".

---

## Pick your path

| I am a… | I want to… | Start here |
| --- | --- | --- |
| **User** | install the app and analyze my project | [For users](#for-users) |
| **Developer** | build, run, test, or change CodeTwin | [For developers](#for-developers) |
| **DevOps / release engineer** | run CI, build installers, cut a release | [For DevOps](#for-devops) |
| Anyone | check what is implemented, and what is not | [Reference](#reference) |

---

## For users

### What CodeTwin does for you

| You want to… | CodeTwin… |
| --- | --- |
| Understand an unfamiliar codebase | detects languages, frameworks, package managers, tests, databases and CI, then indexes files, functions, classes, imports and references (TypeScript/JS, Python, Rust, Go, C, C++, PHP) |
| See what a change would break | shows dependencies, dependents, and reverse impact for any file or symbol |
| Find code problems | flags oversized/deeply nested code, dependency cycles, risky security patterns, leaked secrets (values never stored), and vulnerable dependencies (OSV) |
| Review database and Docker setup | passively checks SQL/Prisma migrations and Dockerfile/Compose files — it never connects to your database or starts containers |
| Know your test coverage surface | finds test frameworks, test files and config; on Windows it can also run selected tests in a strict sandbox |
| Security-test your own web app | runs guided, scope-limited tests against sites you are authorized to test, and links findings back to source code |
| Fix a problem safely | proposes a small patch, shows the exact diff, applies it only after you approve, backs up originals, and re-tests to confirm the fix |
| Use AI without sending code away | runs integrity-checked local ONNX / GGUF models; no model is bundled and nothing is uploaded |

### Quick start

1. **Install** the desktop app (Windows installer from the project's GitHub Releases), or [build it yourself](#for-developers).
2. **Add a project** — *Dashboard → Add Project Folder* and pick a local repository. CodeTwin indexes it without running any of its code.
3. **Explore** — open **Code Analysis** to browse files, symbols, dependencies and impact.
4. **Analyze** — run quality, security, database and runtime checks; review findings with their evidence.
5. **Test (optional)** — under **Testing / QA**, see discovered tests; on Windows you can run selected ones in the sandbox.
6. **Security-test a website (optional)** — register it under **Websites**, then follow **Developer Security Test**.
7. **Fix** — open a finding, review the proposed patch, approve, and let CodeTwin verify it.

### A typical project walkthrough

**1. Add a local project.** CodeTwin validates the folder, discovers the stack, hashes every supported file (SHA-256), parses it with Tree-sitter, and saves the result. Re-indexing only re-parses changed files; a deleted file is marked inactive only when the scan can prove it is gone.

**2. Inspect the Digital Twin.** In **Code Analysis** you can see parse state, functions/classes/types, imports, resolved local dependencies, symbol references, and optional LSP-backed semantic evidence. An unresolved import is shown as unresolved — never as a made-up link.

**3. Run analysis.** All of these work on the indexed source, without running your application:

- **Code quality** — oversized definitions, deep nesting, high fan-out, dependency cycles.
- **Static security** — credential-like literals (redacted), dynamic code execution, weak hashes, unsafe C/C++ string APIs, risky request flows.
- **Database** — destructive DDL, unscoped `UPDATE`/`DELETE`, disabled SQLite foreign keys, literal Prisma datasource URLs.
- **Runtime config** — Dockerfile/Compose reproducibility and health/restart risks.

**4. Discover QA evidence.** Test discovery is passive and never implies the tests ran. On Windows, explicitly selected tests can run inside a zero-capability LPAC sandbox with Job Object limits. A pass/fail verdict is recorded only when the runner finished *and* its output was understood; timeouts, crashes or unknown output give **no verdict**, not a pass.

**5. Register a website.** Saving a URL only stores it (and can run an availability check). It never starts a security test on its own. You may link it to an indexed project so findings map back to source.

### Authorized web-security testing

> Only test localhost, local labs, dev/staging systems, or targets you have **explicit permission** to test.

Two modes:

- **Developer Security Test** — guided and risk-aware, for app owners and developers.
- **Expert Web Testing** — lower-level scan configuration and evidence review.

The guided flow, step by step:

1. **Target** — a registered website or custom URL, optionally linked to a project.
2. **Environment** — local, development, staging, or authorized production.
3. **Depth** — quick, standard, deep, or custom.
4. **Authentication (optional)** — existing session, test account A, or accounts A + B to compare access control.
5. **Scope** — allowed hosts/paths, request budget, crawl depth, concurrency, timeouts, redirects, and policies for state-changing requests, private networks, and timing probes.
6. **Preflight** — validates scope, pins the resolved address, keeps destructive actions off.
7. **Mapping** — bounded discovery of pages, forms, APIs, parameters and cookies; routes found in your source code are used as extra, in-scope seeds.
8. **Plan** — every check is labeled SAFE, CAUTION, or RESTRICTED; restricted ones are never auto-selected.
9. **Approve** — nothing active runs until you approve the plan.
10. **Run** — checks for SQL injection, XSS, CSRF, open redirect, path traversal, SSRF, template injection, CORS/method/session policy, access control, and API input validation, all within your budget. Requests are rate-limited (4 req/s, burst 2) and unsafe payload shapes are blocked by the engine itself.
11. **Review** — findings include severity, confidence, endpoint, reproduction summary, impact, fix advice and redacted evidence, plus scorecards, risk graphs, retests and scan comparisons.

Credential values are not stored as evidence. How source routes are matched to live endpoints, per framework, is in [docs/architecture/SOURCE_ROUTE_MAPPING.md](docs/architecture/SOURCE_ROUTE_MAPPING.md).

### Fixing a finding: Fix & Verify

CodeTwin treats *patch generated*, *approved*, *applied*, *validated*, and *verified* as **five different states**. The lifecycle:

1. **Eligibility** — `AUTO_FIX_CANDIDATE`, `GUIDED_FIX_CANDIDATE`, `MANUAL_REMEDIATION`, or `INSUFFICIENT_EVIDENCE`.
2. **Root cause** — source candidates are ranked by evidence (matching route → handler declaring the parameter → handler named like the route → file-name heuristics; config findings prefer config files). A patch is auto-generated only at ≥ 0.82 confidence.
3. **Strategy** — expected behavior, likely files, compatibility risks, forbidden shortcuts, suggested regression test, required retest.
4. **Bounded patch** — small by design, tied to source hashes.
5. **Safety review** — `SAFE_TO_REVIEW`, `CAUTION`, or `REJECTED`.
6. **Review the diff** — files, patch hash, changed lines, planned validation and retest.
7. **Approve** — approval is bound to the exact patch hash and files; `CAUTION` needs an extra acknowledgement.
8. **Apply** — only if files still match the approved hashes; originals are backed up; multi-file changes can roll back.
9. **Re-index and validate** — results recorded as `PASS`, `FAIL`, or `NOT_EXECUTED`.
10. **Retest** — the relevant check is rerun: `FIX_VERIFIED`, `STILL_VULNERABLE`, `UNABLE_TO_VERIFY`, or `REGRESSION_DETECTED`.
11. **Truth enforcement** — `FIX_VERIFIED` requires a successful post-apply retest; it cannot be set directly.
12. **Rollback** — restores backups only if nobody edited the files since; recovery is recorded.

**Remediation campaigns** apply the same lifecycle to a group of related findings from one scan: CodeTwin finds shared root causes and conflicts, proposes an order, needs your approval of the plan (which does *not* pre-approve patches), re-checks later approvals when earlier patches change code, and requires a fresh retest for every finding. Outcomes: `VERIFIED`, `STILL_VULNERABLE`, `UNABLE_TO_VERIFY`, `REGRESSION_DETECTED`, `MANUAL_ACTION_REQUIRED`, `BLOCKED`, or `SKIPPED`.

**Repair Lab** offers the same hash-pinned *plan → review → approve → apply → re-index → verify → rollback* cycle for any change, outside security findings. An applied repair is never automatically "verified".

### Local ML

1. Install or register an integrity-verified model package (size + SHA-256 checked).
2. Check inventory and readiness.
3. Create a bounded inference plan.
4. Run local ONNX classification, or a GGUF code model through a separately SHA-256-pinned `llama.cpp` executable.
5. Review results — ML observations are always shown separately from analyzer findings.

No model weights ship with the app. Generated code is review-only: it is never executed or used as a web-test payload. Prompts are passed via a temporary file (not the command line), with bounded time and output. Model packages cannot include shell hooks, plugins, or native libraries.

### Your privacy and safety

- Your source code is not sent to external services.
- Passive analysis never runs commands from the analyzed repository.
- Static findings do not claim exploitability.
- Active web tests need your authorization and a bounded scope; destructive operations are never auto-selected.
- Secret-like values are redacted where supported.
- LSP enrichment only uses a language server you explicitly configure and trust.
- Every write to your code needs approval, matching hashes, a backup, and later verification.
- QA execution is offered only where the strict sandbox is fully available (currently Windows); elsewhere it stays planning-only.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## For developers

### Prerequisites

| Tool | Version | Why |
| --- | --- | --- |
| Node.js | 22+ | React/Vite frontend |
| Rust | 1.82+ | core crates and Tauri shell |
| Tauri CLI | 2.8.4 | `cargo install tauri-cli --version 2.8.4 --locked` |
| Go | 1.23+ | builds the bundled security-engine sidecar |
| Python | 3.12+ | ML sidecar and static web-security CLI |
| Platform deps | — | Windows: MSVC C++ Build Tools + WebView2. Linux: Tauri/WebKitGTK packages. |

### Set up and run

From the repository root (Windows PowerShell shown; same commands on Linux/macOS):

~~~powershell
npm ci                                            # install exactly what package-lock.json pins
cargo install tauri-cli --version 2.8.4 --locked  # once
npm run tauri:dev                                 # build the Go sidecar, start Vite, open the desktop app
~~~

`npm run tauri:dev` opens the real **CodeTwin ML desktop window**. The first run compiles ~500 Rust crates and takes several minutes; later runs are incremental.

Other useful commands:

| Command | What it does |
| --- | --- |
| `npm run dev` | frontend only, in a browser at `http://127.0.0.1:5173` (no Tauri window, no backend) |
| `npm run tauri:build` | build a desktop installer |
| `npm run build:go-sidecar` | rebuild only the Go security-engine binary |
| `pnpm tauri dev` | same as `npm run tauri:dev`, if you use pnpm |

> **Package manager:** the repository commits `package-lock.json`, so `npm ci` is the supported install. pnpm works too; on drives without symlink support (e.g. exFAT), run `pnpm install --config.node-linker=hoisted`.

### Test and validate

~~~bash
# Frontend
npm run typecheck
npm run test
npm run build

# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Python
python -m unittest discover -s services/ml/tests -v
python -m unittest discover -s services/security/tests -v
python -m compileall -q services/ml/codetwin_ml services/security/codetwin_security

# End-to-end: index a repository and run every deterministic analyzer on it
cargo run --release -p codetwin-core --example e2e_smoke -- <path-to-repo>
~~~

On Linux/macOS, `scripts/check-all.sh` runs all of the above in one go (set `SKIP_DESKTOP=1` if Tauri/WebKitGTK prerequisites are missing). More setup detail: [docs/development/SETUP.md](docs/development/SETUP.md).

### Static web-security CLI

The broader Python static review runs on its own and never starts, crawls, or attacks the target:

~~~bash
python services/security/run.py /path/to/project --format text
python services/security/run.py /path/to/project --format json
python services/security/run.py /path/to/project --fail-on high
~~~

### Architecture

~~~mermaid
flowchart LR
    UI[React / TypeScript Desktop UI]
    TAURI[Tauri 2 Command Boundary]
    CORE[Rust Core Services]
    DB[(SQLite WAL Software Digital Twin)]
    INDEX[Project Discovery + Tree-sitter Indexers]
    ANALYZERS[Quality / AppSec / DB / Runtime / QA]
    WEB[Authorized Web Security Engine]
    GO[Go Security Engine Sidecar]
    REPAIR[Repair + Security Fix Services]
    ML[Local Python Sidecar / ONNX + GGUF llama.cpp]
    ART[App-data Artifacts + Repair Backups]

    UI --> TAURI
    TAURI --> CORE
    CORE --> INDEX
    INDEX --> DB
    CORE --> ANALYZERS
    ANALYZERS --> DB
    CORE --> WEB
    WEB --> DB
    CORE <--> GO
    CORE --> REPAIR
    REPAIR --> DB
    REPAIR --> ART
    CORE <--> ML
    ML --> DB
~~~

**Trust boundaries** — keep these intact when changing code:

1. The UI never owns privileged filesystem operations; everything goes through Tauri commands.
2. Repository content is untrusted input.
3. Passive analyzers never execute repository commands.
4. LSP enrichment needs explicit trust and an externally configured server.
5. Active web testing needs explicit authorization and a validated scope.
6. QA execution runs only when the full strict sandbox is available (Windows: detached hash-bound mirror, approved runtime copy, zero-capability LPAC, Job Object limits, bounded handles/output) — no weaker fallback.
7. ML requests use explicit local schemas; repository text is never treated as instructions.
8. Applying a repair is a separate mutation boundary: approval, hash preconditions, backups, independent verification.

### Repository layout

~~~text
CodeTwin-ML/
├─ apps/
│  └─ desktop/                  React frontend + Tauri desktop shell (src-tauri/)
├─ crates/
│  ├─ codetwin-core/            SQLite schema, digital twin, findings, repairs, guided fix state
│  ├─ project-discovery/        Project stack discovery
│  ├─ source-indexer/           Tree-sitter source indexing
│  ├─ reference-indexer/        Source-backed reference evidence
│  ├─ lsp-enrichment/           Explicit LSP semantic enrichment
│  ├─ security-analyzer/        Deterministic static AppSec
│  ├─ secret-scanner/           Redacted secret scanning (working tree + git history)
│  ├─ dependency-audit/         OSV dependency vulnerability audit
│  ├─ web-security-testing/     Authorization-gated scoped web testing
│  ├─ database-analyzer/        Passive SQL/Prisma review
│  ├─ runtime-analyzer/         Passive Docker/runtime config review
│  ├─ qa-analyzer/              Passive QA discovery
│  ├─ qa-execution/             Strict Windows LPAC execution backend (planning-only elsewhere)
│  └─ dataset-benchmark/        Analyzer scoring against pinned datasets
├─ services/
│  ├─ ml/                       Local ML sidecar and tests
│  ├─ security/                 Python static web-security CLI
│  └─ security-engine/          Go security-engine sidecar bundled with the desktop app
├─ packages/shared-types/       Shared TypeScript types
├─ docs/                        architecture/, development/, security/
├─ datasets/  fixtures/  scripts/
└─ Cargo.toml  package.json  pyproject.toml
~~~

### Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing analyzers, persistence, security boundaries, QA execution, repair workflows, or capability claims. Keep changes focused, add tests for behavior changes, preserve evidence provenance, and never weaken authorization, scope, hash, rollback, or verification rules.

---

## For DevOps

### CI workflows

| Workflow | Trigger | What it checks |
| --- | --- | --- |
| [`ci.yml`](.github/workflows/ci.yml) | push, pull request | `rust` (fmt, clippy, tests, `e2e_smoke`), `windows-qa`, `python`, `frontend` |
| [`go-security.yml`](.github/workflows/go-security.yml) | push, pull request | Go security engine tests + packaged companion build per OS |
| [`desktop-release.yml`](.github/workflows/desktop-release.yml) | `v*.*.*` tag, manual | full validation, signed Windows installer, install/uninstall smoke, publish |
| [`openmindai-dataset-release.yml`](.github/workflows/openmindai-dataset-release.yml) | manual | builds and publishes the optional, pinned dataset package |
| [`offline-sandbox-smoke.yml`](.github/workflows/offline-sandbox-smoke.yml) | manual | offline scanner integration |
| [`local-neural-smoke.yml`](.github/workflows/local-neural-smoke.yml) | manual | real local neural-embedding model integration |

Pinned toolchain in release CI: Node 22, Python 3.12, Rust 1.82.0, Tauri CLI 2.8.4.

> A job that never got a runner, ran zero steps, or has no logs is an **infrastructure failure, not a pass**. When hosted runners are unavailable, `scripts/check-all.sh` reproduces the gates locally (except `windows-qa`); keep its output as evidence.

### Cutting a desktop release

1. Make sure `package-lock.json` and `Cargo.lock` are committed and generated by the real package managers.
2. Bump the version to the same `MAJOR.MINOR.PATCH` in the root `package.json`, the Cargo workspace, and the Tauri config.
3. Confirm `npm audit` and `cargo audit` are clean (known upstream Tauri-GTK warnings are not blockers on their own).
4. Push a tag `vMAJOR.MINOR.PATCH` pointing to the release commit, or run **Desktop Release** manually with that tag.
5. The workflow re-runs the `rust`, `windows-qa`, `python` and `frontend` gates, builds and **signs** the NSIS installer, silently installs it on a clean runner, runs `--release-smoke`, starts the GUI, and uninstalls.
6. With `publish` enabled, it creates the GitHub Release with SHA-256 checksums, Cargo metadata, npm inventory and build provenance. It refuses to overwrite an existing release.

Required secrets: `WINDOWS_CERTIFICATE`, `WINDOWS_CERTIFICATE_PASSWORD`, `WINDOWS_TIMESTAMP_URL`. Optional variable: `ENABLE_GITHUB_ATTESTATION=true` for artifact attestations.

The base app must install without the optional OpenMindAI Dataset; silent installs never accept its terms. Full rules: [docs/development/RELEASE_GATES.md](docs/development/RELEASE_GATES.md).

### Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Waiting for your frontend dev server` | Vite must be on `127.0.0.1:5173` (it matches Tauri's `devUrl`). Check with `Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5173/`, make sure nothing else uses port 5173, then Ctrl+C and retry. |
| `icon.ico not found` (Windows) | Pull the latest `main`; `apps/desktop/src-tauri/icons/icon.ico` is committed. |
| `no such command: tauri` | `cargo install tauri-cli --version 2.8.4 --locked` |
| `Go companion build failed` | Install Go 1.23+ and make sure `go` is on `PATH`. |
| pnpm `EISDIR` / "drive does not support symlinks" | Use `npm ci`, or `pnpm install --config.node-linker=hoisted`. |
| First desktop build is slow | Expected — Rust compiles all dependencies once. |

---

## Reference

### Capability status

| Capability | Status |
| --- | --- |
| Tauri 2 + React/TypeScript desktop workspace | Implemented |
| Dashboard, Projects, Websites, Code Analysis, Security, Testing workspaces | Implemented |
| SQLite WAL + numbered migrations | Implemented; migrations 0001–0025 registered |
| Project stack discovery | Implemented |
| Tree-sitter source indexing | Implemented baseline |
| Persistent incremental file/symbol index | Implemented |
| Static import observations + deterministic local resolution | Implemented baseline |
| Project/File/Symbol Digital Twin graph | Implemented baseline |
| Dependency, dependent, graph-neighborhood and reverse-impact queries | Implemented baseline |
| Source-backed symbol reference observations | Implemented baseline for TypeScript/JavaScript; other indexed languages record no reference observations |
| Conservative same-file semantic resolution | Implemented baseline |
| Explicit LSP semantic enrichment | Implemented baseline for configured TypeScript/JavaScript, Pyright, and Rust Analyzer servers |
| Deterministic code-quality findings | Implemented baseline |
| Static AppSec + request-flow findings | Implemented baseline |
| Python broader static web-security CLI | Implemented |
| Authorized scope-bounded web security | Implemented |
| Guided Developer Security Test | Implemented |
| Application map + risk-aware test plan + explicit approval | Implemented |
| Source-aware route extraction and source → live endpoint mapping | Implemented baseline for Express, Next.js App Router, FastAPI/Pydantic, Flask, Django, Laravel, Go Gin/Echo/Chi/net/http, and Rust Axum/Actix/Rocket |
| Cross-file router mount resolution and field-aware live seeding | Implemented baseline |
| Finding/source correlation, scorecard, risk graph, targeted retest, scan comparison | Implemented |
| Guided Security Fix & Verify | Implemented baseline |
| Guided Security Remediation Campaigns | Implemented baseline |
| Hash-guarded Apply & Rollback | Implemented baseline |
| Secret scanning (redacted, lifecycle-tracked) | Implemented for the working tree and for git history (all refs, introducing commit, still-present flag) |
| CycloneDX 1.5 SBOM export (components with package URLs, open vulnerabilities) | Implemented from the dependency inventory; no dependency graph yet |
| Dependency vulnerability audit (OSV) | Implemented for npm/yarn/pnpm/bun, Cargo, PyPI (uv/poetry/Pipfile/requirements), Go, Composer, RubyGems, Maven/Gradle and NuGet manifests; offline OSV directory or consented OSV.dev lookup |
| Deterministic database artifact analysis | Implemented baseline |
| Deterministic runtime configuration analysis | Implemented baseline |
| Passive QA/test discovery | Implemented |
| Sandboxed QA/test execution | Implemented on Windows through explicit plan/approval + zero-capability LPAC; planning-only on unsupported platforms |
| Java static security analysis (flow-sensitive taint; SQLi, command injection, XSS, path traversal, LDAP, XPath, SSRF, crypto, TLS, XXE, deserialization, Spring CSRF) | Implemented; OWASP Benchmark v1.2 score +87.7 over 9 categories, see [SECURITY_ANALYSIS.md](docs/architecture/SECURITY_ANALYSIS.md) |
| OpenMindAI Dataset catalog/installer path | Implemented: Windows setup hook and a cross-platform installer script, both SHA-256 verified |
| Dataset benchmarks (analyzers scored against pinned Hugging Face datasets, HTML/Markdown/JSON reports) | Implemented for vulnerability detection, fix pairs and secret-scanner noise; offline, integrity-checked |
| Local ML model package registry | Implemented foundation |
| Local ONNX classification inference | Implemented bounded compatible adapter |
| Local GGUF generative code inference | Implemented through integrity-checked packages + separately SHA-256-pinned llama.cpp runtime; output is review-only and never auto-executed as a web payload |
| ML desktop workspace | Implemented baseline |
| Live runtime telemetry/process tracing | Planned |
| Browser-driven QA execution | Planned |
| Automatic CI/PR remediation automation | Planned |
| Deployment execution | Not implemented |

### Evidence types

CodeTwin keeps these evidence classes separate:

| Evidence | Meaning |
| --- | --- |
| Deterministic finding | produced by a defined analyzer rule |
| Runtime web finding | observed during an explicitly authorized, scoped scan |
| ML observation | model output, with model/package provenance |
| QA discovery evidence | test/config artifacts were *found* — not that tests ran |
| Repair proposal | candidate bytes tied to a base hash |
| Applied repair | bytes were written successfully |
| Verified repair / security fix | post-change evidence proved the required condition |

Web-security evidence stores bounded metadata and hashes. Response excerpts are kept only for text/JSON/XML/form content and are redacted for credentials, tokens and direct PII; binary or unknown content keeps only hash, size and headers.

### Current limitations

CodeTwin does **not** currently claim:

- a complete interprocedural call graph;
- full control-flow/data-flow/taint proof across every supported language;
- cross-file or field-level taint: Java taint tracking is per file (flow-sensitive within methods, with same-file helper summaries); other languages only match request input inside the sink call;
- dependency-CVE completeness beyond the supported manifests (no Swift or Dart yet; unpinned requirements, and Maven versions inherited from a parent POM or BOM, cannot be matched);
- secrets in git objects that no ref reaches (unreachable or reflog-only commits) or in submodules;
- benchmark scores as absolute detection rates: public vulnerability labels are noisy and samples are often fragments, so dataset benchmarks are a regression signal between versions. C#, Ruby, Kotlin and other languages without a security-analyzer grammar are read but not scored;
- symbol reference observations outside TypeScript/JavaScript;
- router prefixes applied through helper-function calls (for example a Gin group passed to `addUserRoutes(v1)` in another function); such routes are indexed without that prefix;
- live database state or query-plan telemetry;
- live container/process tracing;
- production incident correlation;
- browser-driven QA automation;
- sandboxed QA execution on platforms without a strict supported backend;
- unrestricted autonomous remediation;
- automatic Git/PR/CI remediation;
- guaranteed exploitability proof;
- universally crash-proof filesystem transactions across arbitrary filesystems or hardware failures. Repair Apply & Rollback does perform startup reconciliation: exact proposed bytes are restored from verified backups, exact base bytes are accepted as recovered, and unknown/manual bytes are left untouched and surfaced as rollback-failed recovery state.

A capability is promoted only when implementation, persistence semantics, safety boundaries, and executable validation all support the claim.

### Documentation index

| Area | Documents |
| --- | --- |
| Overview | [OVERVIEW](docs/architecture/OVERVIEW.md), [DIGITAL_TWIN](docs/architecture/DIGITAL_TWIN.md) |
| Indexing & semantics | [SOURCE_INDEXING](docs/architecture/SOURCE_INDEXING.md), [SYMBOL_REFERENCE_EVIDENCE](docs/architecture/SYMBOL_REFERENCE_EVIDENCE.md), [SEMANTIC_SYMBOL_RESOLUTION](docs/architecture/SEMANTIC_SYMBOL_RESOLUTION.md), [LSP_SEMANTIC_ENRICHMENT](docs/architecture/LSP_SEMANTIC_ENRICHMENT.md), [IMPACT_ANALYSIS](docs/architecture/IMPACT_ANALYSIS.md) |
| Analysis | [CODE_QUALITY_ANALYSIS](docs/architecture/CODE_QUALITY_ANALYSIS.md), [SECURITY_ANALYSIS](docs/architecture/SECURITY_ANALYSIS.md), [SUPPLY_CHAIN_SCANNING](docs/architecture/SUPPLY_CHAIN_SCANNING.md), [DATABASE_ANALYSIS](docs/architecture/DATABASE_ANALYSIS.md), [RUNTIME_RELIABILITY](docs/architecture/RUNTIME_RELIABILITY.md) |
| Web security | [WEB_SECURITY_REVIEW](docs/architecture/WEB_SECURITY_REVIEW.md), [SOURCE_ROUTE_MAPPING](docs/architecture/SOURCE_ROUTE_MAPPING.md), [GO_SECURITY_ENGINE](docs/architecture/GO_SECURITY_ENGINE.md), [CYBERSECURITY_PLATFORM_WORKFLOW](docs/architecture/CYBERSECURITY_PLATFORM_WORKFLOW.md), [CYBERSECURITY_TOOL_CATALOG](docs/architecture/CYBERSECURITY_TOOL_CATALOG.json), [RUNTIME_TOOL_CATALOG](docs/architecture/RUNTIME_TOOL_CATALOG.md) |
| QA | [QA_TEST_DISCOVERY](docs/architecture/QA_TEST_DISCOVERY.md), [QA_TEST_EXECUTION](docs/architecture/QA_TEST_EXECUTION.md), [QA_DETACHED_WORKSPACE](docs/architecture/QA_DETACHED_WORKSPACE.md), [WINDOWS_LPAC_READINESS](docs/architecture/WINDOWS_LPAC_READINESS.md) |
| ML | [ML_MODEL_REGISTRY](docs/architecture/ML_MODEL_REGISTRY.md), [ONNX_INFERENCE_RUNTIME](docs/architecture/ONNX_INFERENCE_RUNTIME.md), [ML_INFERENCE_ISOLATION](docs/architecture/ML_INFERENCE_ISOLATION.md), [ML_INFERENCE_PROVENANCE](docs/architecture/ML_INFERENCE_PROVENANCE.md), [ML_DESKTOP_WORKSPACE](docs/architecture/ML_DESKTOP_WORKSPACE.md), [DATASET_BENCHMARKS](docs/architecture/DATASET_BENCHMARKS.md) |
| Repair | [VERIFIED_REPAIR_WORKFLOW](docs/architecture/VERIFIED_REPAIR_WORKFLOW.md) |
| Development & release | [SETUP](docs/development/SETUP.md), [RELEASE_GATES](docs/development/RELEASE_GATES.md) |
| Security | [THREAT_MODEL](docs/security/THREAT_MODEL.md), [EVIDENCE_SIGNING](docs/security/EVIDENCE_SIGNING.md), [BOUNDED_AUTONOMOUS_PLANNER](docs/security/BOUNDED_AUTONOMOUS_PLANNER.md), [SECURITY.md](SECURITY.md) |

## License

Apache-2.0. See [LICENSE](LICENSE).
