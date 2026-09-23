# CodeTwin ML

**Local-first Software Digital Twin for code intelligence, application security, quality, reliability, ML-assisted review, and verified repair.**

CodeTwin ML is a Tauri 2 desktop engineering workspace that turns a local software project into a persistent, evidence-backed Software Digital Twin. It combines deterministic source analysis, dependency and symbol intelligence, static and authorized web security testing, QA evidence discovery, local ML inference, database/runtime review, and hash-verified repair workflows.

The core design rule is simple: **CodeTwin records what it can prove, keeps uncertain evidence explicit, and does not silently convert missing or incomplete evidence into a successful result.**

## What CodeTwin does

CodeTwin can:

- register and persist local software projects;
- discover project languages, frameworks, package managers, test frameworks, databases, build systems, and CI hints;
- build an incremental Tree-sitter source index for TypeScript/TSX, JavaScript/JSX, Python, Rust, Go, C, C++, and PHP;
- persist files, symbols, imports, references, findings, evidence, analysis runs, repair history, web-security sessions, and ML provenance in SQLite;
- build a bounded Project → File → Symbol Software Digital Twin graph;
- inspect dependencies, dependents, symbols, references, and reverse impact;
- run deterministic code-quality, AppSec, database, and runtime-configuration analysis;
- discover test frameworks and test/config artifacts without executing untrusted repository code;
- run authorization-gated, scope-bounded web application security testing;
- prepare a guided developer security plan before active testing begins;
- correlate runtime web findings with indexed source candidates;
- prepare bounded security fixes, review a diff, apply with hash guards and backups, validate, retest, and record verified or unresolved outcomes;
- install integrity-verified local ML model packages and run bounded local ONNX classification;
- keep deterministic findings, runtime evidence, ML observations, and repair state as separate evidence classes.

## Product workflow

### 1. Add a local project

From **Dashboard → Add Project Folder** or **Projects → Add Project Folder**, select an existing repository.

CodeTwin then:

1. validates the selected root;
2. discovers the project stack;
3. walks supported source files without executing repository commands;
4. hashes file content with SHA-256;
5. parses supported languages with Tree-sitter;
6. persists files, symbols, imports, parse state, and run metrics;
7. creates or refreshes the Software Digital Twin.

Unchanged content is reused on later indexing runs. Changed files are reparsed. Files that disappear are marked inactive only when the scan has enough evidence to prove the absence.

### 2. Inspect the Software Digital Twin

Use **Code Analysis** and the advanced engineering views to inspect:

- indexed files and parse state;
- functions, methods, classes, interfaces, and types;
- local import observations;
- resolved local file dependencies;
- source-backed symbol references;
- conservative same-file semantic resolution;
- optional LSP-backed semantic evidence;
- dependency neighborhoods and reverse impact.

Static observations and LSP evidence remain separate. An unresolved import or reference is not turned into a fabricated edge.

### 3. Run deterministic engineering analysis

CodeTwin can analyze the indexed project without running application code.

**Code quality**

Current deterministic checks include oversized definitions, deep declaration nesting, high local dependency fan-out, and resolved-local dependency cycles.

**Static AppSec**

The indexed-source analyzer can report evidence such as hard-coded credential-like literals with redacted values, dynamic code execution primitives, weak cryptographic hashes, unsafe legacy C/C++ string APIs, and selected web request-flow risks.

**Database analysis**

CodeTwin passively reviews schema.prisma and SQL artifacts for selected migration/schema risks such as destructive DDL, unscoped UPDATE/DELETE, disabled SQLite foreign keys, and literal Prisma datasource URLs. It does not connect to the application database.

**Runtime reliability**

CodeTwin passively reviews Dockerfile and Docker Compose configuration for selected reproducibility and health/restart risks. It does not start containers or claim live-runtime telemetry.

### 4. Discover QA evidence

The **Testing / QA** workflow inventories supported test frameworks, test files, and configuration evidence.

QA discovery remains passive and never implies execution. On Windows, CodeTwin can additionally run explicitly selected tests through the strict QA execution lifecycle: immutable plan → trusted runner hash pin → project/runtime approval manifests → zero-capability LPAC launch → Job Object resource/process containment → runner-output parsing → durable run evidence. Other platforms remain planning-only until an equally strict backend exists.

A completed process is not automatically a passing test run. CodeTwin records a pass/fail verdict only when the runner completed and its output matched the supported parser contract; timeout, cancellation, setup failure, or unrecognized output produces no test verdict.

### 5. Register a website

The **Websites** workspace stores an HTTP/HTTPS target locally and can perform an explicit bounded availability check.

Registering a URL does not automatically start security testing.

A website may optionally be associated with an indexed project so later web findings can be correlated with source files and symbols.

## Authorized web-security workflow

CodeTwin includes two related web-security experiences:

- **Developer Security Test** — guided, risk-aware workflow intended for application owners and developers;
- **Expert Web Testing** — lower-level authorized scan configuration and evidence review.

Active testing is only for localhost, local labs, development/staging systems, or other targets for which the user has explicit authorization.

### Source-aware endpoint mapping

When an authorized web target is associated with an indexed project, CodeTwin bridges static source evidence and live testing instead of treating them as unrelated data sets.

The source-aware flow is:

1. Tree-sitter extracts supported backend route declarations from Express/JavaScript/TypeScript, Next.js App Router `app/**/route.*` handlers, FastAPI/Python, Flask/Blueprint Python, direct Laravel `Route::get/post/put/patch/delete/options/head` PHP calls, static Gin/Echo/Chi Go routes (including nested Gin/Echo-style groups), Go 1.22+ method-qualified `net/http` ServeMux patterns, and static Actix Web/Rocket attribute plus Axum `.route(...)` Rust routes.
2. Route method, path template, handler, path/query/form/JSON fields, framework, file, source hash, and line range are persisted.
3. Router mount evidence and import bindings resolve same-file and supported cross-file prefixes, including nested mount chains. Python relative imports are resolved for Flask Blueprint mounts, and mount metadata distinguishes prefix prepend from explicit router-prefix override semantics.
4. Effective source routes are converted into bounded live endpoint seeds under the existing authorized target and path scope.
5. Source-backed GET routes are prioritized in discovery; non-GET routes enter the application map without an automatic discovery-side state-changing request.
6. The active planner preserves the source-declared HTTP method and input location so bounded checks target the relevant query, form, JSON, header, or path field.
7. Each persisted live endpoint can be linked back to the source route with match kind, confidence, parameter overlap, effective mounted path, file, framework, and handler.
8. Finding correlation prefers method + exact/template route evidence before falling back to the older filename/symbol heuristic.
9. The route template remains attached through guided fix and targeted retest so dynamic path parameters keep their source identity.

Wildcard routes are not blindly materialized. Dynamic path values use deterministic harmless samples, including type-compatible integer/UUID/float/bool values for supported route converters, and state-changing probes remain subject to the existing explicit approval and scope policy.

Current framework coverage now includes FastAPI/Pydantic input-name correlation for static `Field(alias=...)` / `validation_alias` values and explicit FastAPI parameter aliases, including the framework's default Header underscore→hyphen conversion. Complex/dynamic Pydantic alias choices/generators remain unresolved rather than guessed. Static Laravel `prefix(...)->group(...)` / array-prefix groups plus `resource` and `apiResource` REST expansion, including nested middleware/prefix chains. Laravel route arrays and resource routes preserve `Controller.method` identity; conventional `App\...` / `Tests\...` PHP namespace imports resolve to indexed local files, and explicit controller Request access through `query`, `header`, `cookie`, `json`, `post`, and `route` is merged back onto route evidence across files. Imported Laravel FormRequest classes now contribute top-level static `rules()` keys across the controller import graph. Those fields remain `body` when the request encoding is ambiguous, are promoted to `json`/`form` only when independent route/controller evidence proves that encoding, and ambiguous `body` fields are not actively probed. Grouped and comma-separated PHP class imports are expanded into concrete import references with aliases preserved, so grouped controller/FormRequest imports participate in the same resolver; grouped `function`/`const` items are not treated as controller bindings. Static Laravel resource/API-resource `->parameters(['resource' => 'param'])` maps are applied to generated member-route placeholders. If a `parameters(...)` override is present but not a fully static short-array map, CodeTwin skips that resource expansion rather than guessing the live placeholder. Static inline `$request->validate([...])` and `request()->validate([...])` rule keys are also mapped: they remain ambiguous `body` fields unless independent JSON/form evidence in the same handler proves the encoding. Dynamic/computed validation arrays and ambiguous Laravel `input`/`all` sources remain intentionally unresolved rather than guessed. Project indexing now reads bounded root `composer.json` `autoload.psr-4` and `autoload-dev.psr-4` mappings (including string or directory-array values) and uses those roots before the conservative `App\`/`Tests\` fallback when resolving PHP class imports. Cross-file Flask Blueprint registration models explicit `url_prefix` override semantics for relative Python imports, while Flask handler correlation maps static `request.args`, `request.form`, `request.headers`, `request.cookies`, `request.json`, and `request.get_json()` keys—including simple aliases—back onto route evidence. Ambiguous `request.values`, uploads, and dynamic keys are intentionally skipped. Next.js App Router supports direct and named/re-exported HTTP handlers plus dynamic and catch-all segments using a bounded single-segment materialization. App Router handler correlation maps static `nextUrl.searchParams` keys, request-header lookups, `NextRequest.cookies` keys (including simple aliases), JSON destructuring/body-member access, and `FormData` keys back onto the route while preserving the local handler identity for named re-exports. Go route correlation maps statically named handler inputs for common Gin/Echo/Chi/net-http APIs (query, form, path, and header keys) back onto the route record. Explicit Gin JSON binds and `encoding/json` decoder calls also expand top-level exported Go struct fields using `json` tags or the default exported field name. Rust route correlation now associates Axum method-router handlers and Actix/Rocket attribute handlers, expands top-level struct fields for `Query<T>`, `Json<T>`, `Form<T>`, and `Path<T>`, records static `HeaderMap` lookups, separates Rocket route-query parameters from the live path, and honors static serde `rename_all` conventions plus field-level `rename` overrides for supported extractor structs. Dynamic key expressions, runtime-computed Next.js request schemas, generic/tuple extractor shapes, embedded/nested struct promotion, multiline/dynamic serde attributes, custom serializer naming, and other runtime-computed schemas remain intentionally unresolved rather than guessed.

All active requests pass through a shared token-bucket pacing floor (4 requests/second with a burst of 2) and the global request budget. Active payloads also pass through a central bounded safety policy that rejects oversized values, line-break/header injection, destructive database statements, UNION/data-extraction shapes, delay/timing functions, metadata-service targets, shell-execution syntax, and non-HTTP outbound schemes before a request can be built. These controls are internal to the engine rather than model-controlled.

### Guided Developer Security Test

The guided workflow is:

1. **Choose target**
   - registered website or custom URL;
   - optional associated CodeTwin project.

2. **Choose environment**
   - local;
   - development;
   - staging;
   - authorized production.

3. **Choose testing depth**
   - quick;
   - standard;
   - deep;
   - custom.

4. **Provide optional authorized authentication**
   - existing session;
   - test account A;
   - test accounts A + B for authorization comparison.

5. **Confirm authorization and scope**
   - target host;
   - allowed hostnames/subdomains;
   - allowed and excluded paths;
   - request budget;
   - crawl depth;
   - concurrency;
   - timeout;
   - redirect limit;
   - state-changing policy;
   - private-network policy;
   - timing-probe policy.

6. **Preflight**
   - validates the scope;
   - resolves and pins the target address;
   - records host/path/request boundaries;
   - keeps destructive actions disabled in the guided plan.

7. **Application mapping**
   - performs bounded discovery;
   - records pages, forms, API endpoints, parameters, cookies, status codes, and authentication boundaries;
   - can attach source hints when an associated indexed project provides enough evidence.

8. **Risk-aware test planning**
   - operations are classified as SAFE, CAUTION, or RESTRICTED;
   - restricted destructive/state-changing operations are not automatically selected;
   - the user reviews the plan before active execution.

9. **Explicit approval**
   - active checks do not start until the prepared plan is approved.

10. **Bounded execution**
    - CodeTwin enforces the approved scope and request budget;
    - supported detector families include SQL-injection indicators, XSS/reflection context, CSRF review, open redirect, path traversal indicators, SSRF indicators, template-injection indicators, HTTP method/CORS/session policy, access-control comparison, and API input validation;
    - scan progress, endpoints, findings, and evidence are persisted.

11. **Correlation and review**
    - findings include severity, confidence, endpoint, method, parameter when applicable, reproduction summary, impact, remediation, and bounded/redacted evidence;
    - findings can be correlated back to indexed source candidates;
    - scorecards, risk graphs, activity history, targeted retests, and scan comparisons are available.

Authentication secret values are not treated as durable project evidence. CodeTwin persists authentication metadata rather than using credentials as finding content.

## Guided security fix and verification workflow

PR #72 added a dedicated security-fix lifecycle on top of the guided security operator. PR #77 extends this foundation with guided remediation campaigns for multiple related findings.

For an eligible web-security finding, CodeTwin can:

1. **Evaluate fix eligibility**
   - AUTO_FIX_CANDIDATE;
   - GUIDED_FIX_CANDIDATE;
   - MANUAL_REMEDIATION;
   - INSUFFICIENT_EVIDENCE.

2. **Correlate root cause**
   - inspect bounded source candidates;
   - record confidence and reasoning;
   - avoid pretending a source location is proven when evidence is insufficient.

3. **Build a fix strategy**
   - expected behavior;
   - likely files;
   - compatibility risks;
   - prohibited shortcuts;
   - regression-test suggestion;
   - security retest requirement.

4. **Generate or provide a bounded patch**
   - maximum patch scope is intentionally limited;
   - the proposed replacement is tied to source hashes and a repair plan.

5. **Run patch safety review**
   - SAFE_TO_REVIEW;
   - CAUTION;
   - REJECTED.

6. **Review the exact diff**
   - affected files;
   - patch hash;
   - changed-line count;
   - expected behavior;
   - planned validation;
   - targeted security retest.

7. **Approve explicitly**
   - approval is tied to the exact patch hash, file set, safety class, and source identity;
   - CAUTION requires explicit acknowledgement;
   - approved identity becomes immutable in persistence.

8. **Apply with hash guards**
   - live files must still match the approved base SHA-256;
   - replacements are staged;
   - originals are backed up under CodeTwin app data;
   - multi-file application uses reverse rollback support.

9. **Re-index and validate**
   - CodeTwin refreshes the source index after application;
   - deterministic static post-state evidence is captured;
   - supported validation results are persisted as PASS, FAIL, or NOT_EXECUTED with a classification.

10. **Run targeted security retest**
    - the relevant bounded detector family is rerun against the original authorized target;
    - the result becomes one of:
      - FIX_VERIFIED;
      - STILL_VULNERABLE;
      - UNABLE_TO_VERIFY;
      - REGRESSION_DETECTED.

11. **Enforce verification truth**
    - FIX_VERIFIED cannot be inserted directly;
    - persistence requires a successful post-apply targeted retest;
    - blocking patch-introduced or unknown validation failures prevent verified status.

12. **Rollback when needed**
    - rollback checks current live content before restoring backups;
    - a rollback will not silently overwrite unrelated post-apply edits;
    - recovery evidence is persisted.

This workflow deliberately separates **patch generated**, **patch approved**, **patch applied**, **validation completed**, and **security fix verified**. They are not equivalent states.

## Guided remediation campaigns

For a set of related findings from the same authorized scan, CodeTwin can create a bounded remediation campaign that:

1. binds the campaign to the exact project, target, guided session, scan, environment, scope, and selected findings;
2. analyzes shared root causes, source overlap, validation dependencies, retest dependencies, and potential conflicts;
3. creates a deterministic remediation order for review;
4. requires explicit campaign-plan approval without pre-authorizing future code patches;
5. processes each finding through the existing Fix & Verify lifecycle;
6. blocks stale later approvals when an earlier mutation changes required source identity;
7. requires independent fresh targeted retest evidence for every selected finding before campaign completion;
8. records factual outcomes such as VERIFIED, STILL_VULNERABLE, UNABLE_TO_VERIFY, REGRESSION_DETECTED, MANUAL_ACTION_REQUIRED, BLOCKED, or SKIPPED;
9. performs dependency-aware rollback checks instead of a blind campaign-wide rollback;
10. persists before/after comparison, unresolved security debt, final verification boundaries, and append-only activity history.

Campaign orchestration does not bypass the underlying hash, approval, validation, retest, rollback, or verification invariants.

## Generic Repair Lab workflow

The generic **Repair Lab** is available for explicit hash-pinned replacement plans even outside the guided security-fix flow.

Lifecycle:

1. create a draft repair plan;
2. pin base file hashes;
3. persist proposed replacement bytes and proposed hashes;
4. review the change;
5. approve explicitly;
6. apply with live base-hash checks;
7. persist backup/application evidence;
8. re-index the project;
9. rerun the originating analyzer when applicable;
10. mark verified only when post-state evidence proves the linked issue is resolved;
11. rollback when required and safe.

An applied repair is never automatically described as verified.

## Local ML workflow

The ML subsystem is local-first and provenance-aware.

1. install or register an integrity-verified model package;
2. validate package size and SHA-256;
3. inspect model inventory and readiness;
4. create a bounded inference plan;
5. run the compatible bounded local ONNX classifier when classification is requested;
6. optionally run an integrity-checked GGUF code model through a separately SHA-256-pinned local llama.cpp executable;
7. persist classifier model/package/evaluation provenance and keep generated suggestions source-hash-bound for review;
8. surface ML observations separately from deterministic analyzer findings.

No model weights are bundled by default. Registry installation does not by itself prove that the runtime dependencies required for inference are available.

### Local generative code model

CodeTwin also supports integrity-checked `llama-cpp-gguf-v1` packages for bounded local code generation. The llama.cpp executable is configured separately and must match an explicit SHA-256 pin. Source-bearing prompts are passed through a temporary prompt file rather than the process command line, execution has a bounded timeout/output size, and generated text is returned for review only. It is not converted into a web-security payload or executed automatically.

The model package contract does not allow package-provided shell hooks, repository commands, arbitrary Python plugins, or arbitrary native libraries.

## Architecture

~~~mermaid
flowchart LR
    UI[React / TypeScript Desktop UI]
    TAURI[Tauri 2 Command Boundary]
    CORE[Rust Core Services]
    DB[(SQLite WAL Software Digital Twin)]
    INDEX[Project Discovery + Tree-sitter Indexers]
    ANALYZERS[Quality / AppSec / DB / Runtime / QA]
    WEB[Authorized Web Security Engine]
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
    CORE --> REPAIR
    REPAIR --> DB
    REPAIR --> ART
    CORE <--> ML
    ML --> DB
~~~

### Trust boundaries

1. The desktop UI does not directly own privileged filesystem operations.
2. Repository content is untrusted input.
3. Passive analyzers do not execute repository commands.
4. LSP enrichment requires explicit trust and an externally configured language server.
5. Active web testing requires explicit authorization and a validated scope.
6. QA execution is enabled only when the current OS backend exposes the complete strict capability floor. The Windows path uses a detached hash-bound project mirror, copied approved runtime/toolchain surface, zero-capability LPAC identity, Job Object limits, bounded handles/output, and no weaker fallback.
7. ML requests use explicit local schemas; repository text is not treated as instructions.
8. Repair application is a separate mutation boundary with approval, hash preconditions, backups, and independent verification.

## Current capability status

| Capability | Status |
| --- | --- |
| Tauri 2 + React/TypeScript desktop workspace | Implemented |
| Dashboard, Projects, Websites, Code Analysis, Security, Testing workspaces | Implemented |
| SQLite WAL + numbered migrations | Implemented; migrations 0001–0022 registered |
| Project stack discovery | Implemented |
| Tree-sitter source indexing | Implemented baseline |
| Persistent incremental file/symbol index | Implemented |
| Static import observations + deterministic local resolution | Implemented baseline |
| Project/File/Symbol Digital Twin graph | Implemented baseline |
| Dependency, dependent, graph-neighborhood and reverse-impact queries | Implemented baseline |
| Source-backed symbol reference observations | Implemented baseline |
| Conservative same-file semantic resolution | Implemented baseline |
| Explicit LSP semantic enrichment | Implemented baseline for configured TypeScript/JavaScript, Pyright, and Rust Analyzer servers |
| Deterministic code-quality findings | Implemented baseline |
| Static AppSec + request-flow findings | Implemented baseline |
| Python broader static web-security CLI | Implemented |
| Authorized scope-bounded web security | Implemented |
| Guided Developer Security Test | Implemented |
| Application map + risk-aware test plan + explicit approval | Implemented |
| Source-aware route extraction and source → live endpoint mapping | Implemented baseline for Express and FastAPI |
| Cross-file router mount resolution and field-aware live seeding | Implemented baseline |
| Finding/source correlation, scorecard, risk graph, targeted retest, scan comparison | Implemented |
| Guided Security Fix & Verify | Implemented baseline |
| Guided Security Remediation Campaigns | Implemented baseline |
| Hash-guarded Apply & Rollback | Implemented baseline |
| Deterministic database artifact analysis | Implemented baseline |
| Deterministic runtime configuration analysis | Implemented baseline |
| Passive QA/test discovery | Implemented |
| Sandboxed QA/test execution | Implemented on Windows through explicit plan/approval + zero-capability LPAC; planning-only on unsupported platforms |
| OpenMindAI Dataset catalog/installer path | Implemented foundation |
| Local ML model package registry | Implemented foundation |
| Local ONNX classification inference | Implemented bounded compatible adapter |
| Local GGUF generative code inference | Implemented through integrity-checked packages + separately SHA-256-pinned llama.cpp runtime; output is review-only and never auto-executed as a web payload |
| ML desktop workspace | Implemented baseline |
| Live runtime telemetry/process tracing | Planned |
| Browser-driven QA execution | Planned |
| Automatic CI/PR remediation automation | Planned |
| Deployment execution | Not implemented |

## Evidence model

CodeTwin distinguishes:

- **deterministic finding** — analyzer-backed evidence from a defined rule;
- **runtime web finding** — evidence observed during an explicitly authorized scoped scan;
- **ML observation** — model output with model/package provenance;
- **QA discovery evidence** — proof that test/config artifacts were found, not that tests ran;
- **repair proposal** — candidate bytes tied to a base hash;
- **applied repair** — bytes were written successfully;
- **verified repair/security fix** — post-state evidence proved the required condition.

Missing, stale, skipped, incomplete, or failed evidence is not converted to a successful zero-result state.

## Repository layout

~~~text
CodeTwin-ML/
├─ apps/
│  └─ desktop/                  React frontend + Tauri desktop shell
├─ crates/
│  ├─ codetwin-core/            SQLite schema, digital twin, findings, repairs, guided fix state
│  ├─ project-discovery/        Project stack discovery
│  ├─ source-indexer/           Tree-sitter source indexing
│  ├─ reference-indexer/        Source-backed reference evidence
│  ├─ lsp-enrichment/           Explicit LSP semantic enrichment
│  ├─ security-analyzer/        Deterministic static AppSec
│  ├─ web-security-testing/     Authorization-gated scoped web testing
│  ├─ database-analyzer/        Passive SQL/Prisma review
│  ├─ runtime-analyzer/         Passive Docker/runtime config review
│  ├─ qa-analyzer/              Passive QA discovery
│  └─ qa-execution/             Strict Windows LPAC execution backend + planning-only fallback elsewhere
├─ services/
│  ├─ ml/                       Local ML sidecar and tests
│  └─ security/                 Broader Python static web-security CLI
├─ packages/
│  └─ shared-types/
├─ docs/
│  ├─ architecture/
│  ├─ development/
│  └─ security/
├─ datasets/
├─ fixtures/
├─ scripts/
├─ SECURITY.md
├─ CONTRIBUTING.md
├─ Cargo.toml
├─ package.json
└─ pyproject.toml
~~~

## Development

### Prerequisites

- Node.js 22+
- Rust 1.82+
- Python 3.12+
- platform dependencies required by Tauri 2

### Install JavaScript dependencies

~~~bash
npm install
~~~

### Frontend development

~~~bash
npm run dev
~~~

### Build and validation

~~~bash
npm run typecheck
npm run test
npm run build

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

python -m unittest discover -s services/ml/tests -v
python -m unittest discover -s services/security/tests -v
python -m compileall -q services/ml/codetwin_ml services/security/codetwin_security
~~~

A CI job is only meaningful when it actually receives a runner and executes its steps. An empty or unallocated workflow is infrastructure failure, not validation success.

### Static web-security CLI

The broader Python static review can be run separately:

~~~bash
python services/security/run.py /path/to/project --format text
python services/security/run.py /path/to/project --format json
python services/security/run.py /path/to/project --fail-on high
~~~

This CLI performs static review. It does not start, crawl, or exploit the target application.

## Architecture documentation

Key documents:

- docs/architecture/OVERVIEW.md
- docs/architecture/SOURCE_INDEXING.md
- docs/architecture/DIGITAL_TWIN.md
- docs/architecture/IMPACT_ANALYSIS.md
- docs/architecture/SYMBOL_REFERENCE_EVIDENCE.md
- docs/architecture/SEMANTIC_SYMBOL_RESOLUTION.md
- docs/architecture/LSP_SEMANTIC_ENRICHMENT.md
- docs/architecture/CODE_QUALITY_ANALYSIS.md
- docs/architecture/SECURITY_ANALYSIS.md
- docs/architecture/WEB_SECURITY_REVIEW.md
- docs/architecture/DATABASE_ANALYSIS.md
- docs/architecture/RUNTIME_RELIABILITY.md
- docs/architecture/QA_TEST_DISCOVERY.md
- docs/architecture/QA_TEST_EXECUTION.md
- docs/architecture/QA_DETACHED_WORKSPACE.md
- docs/architecture/WINDOWS_LPAC_READINESS.md
- docs/architecture/ML_MODEL_REGISTRY.md
- docs/architecture/ONNX_INFERENCE_RUNTIME.md
- docs/architecture/ML_INFERENCE_ISOLATION.md
- docs/architecture/ML_INFERENCE_PROVENANCE.md
- docs/architecture/ML_DESKTOP_WORKSPACE.md
- docs/architecture/VERIFIED_REPAIR_WORKFLOW.md

## Security and privacy

CodeTwin is designed for local analysis and explicit authorization.

- It does not intentionally transmit analyzed source code to external services.
- Passive source, database, runtime, and QA discovery workflows do not execute repository commands.
- Static security analysis does not claim exploitability.
- Active web testing requires authorization confirmation and a bounded scope.
- The guided workflow does not automatically select restricted destructive/state-changing operations.
- Secret-like evidence is redacted where supported.
- LSP enrichment uses only an explicitly configured trusted external executable.
- ML model packages are integrity checked and cannot declare arbitrary execution hooks through the package contract.
- Repair writes require explicit approval, hash identity checks, staged replacement, backups, and later verification.
- QA execution is exposed only when the runtime reports the complete strict isolation capability floor; unsupported platforms remain planning-only with no weaker fallback.

See SECURITY.md for vulnerability reporting and subsystem-specific documentation for detailed trust boundaries.

## Current limitations

CodeTwin does not currently claim:

- a complete interprocedural call graph;
- full control-flow/data-flow/taint proof across every supported language;
- dependency-CVE completeness;
- live database state or query-plan telemetry;
- live container/process tracing;
- production incident correlation;
- browser-driven QA automation;
- sandboxed QA execution on platforms without a strict supported backend;
- unrestricted autonomous remediation;
- automatic Git/PR/CI remediation;
- guaranteed exploitability proof;
- crash-proof filesystem transactions.

Capabilities are promoted only when implementation, persistence semantics, safety boundaries, and executable validation support the claim.

## Contributing

Read CONTRIBUTING.md before changing analyzer behavior, persistence, security boundaries, QA execution, repair workflows, or capability claims.

Keep changes focused, add tests for behavior changes, preserve evidence provenance, and do not weaken authorization, scope, hash, rollback, or verification invariants.

## License

Apache-2.0. See LICENSE.
