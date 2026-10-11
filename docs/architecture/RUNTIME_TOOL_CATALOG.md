# Runtime tool catalog (CS-01)

The desktop Tool Library (`#/tools`) reads a compiled Rust registry through `list_security_tools`. The 41 metadata entries in `crates/codetwin-core/src/tool_catalog.json` supply names, categories and roadmap descriptions. Only explicit matches in `tool_catalog::registered` expose existing desktop workflows. Neither this metadata nor the separate documentation planning inventory is an execution grant.

Availability describes workflow access, not permission to run a tool:

- `available`: a registered workflow can be opened; its existing target, toolchain, scope and approval checks still apply.
- `requires_setup`: select/import a project or enable a trusted LSP configuration. The action opens setup, never execution.
- `blocked`: strict QA execution capability is not exposed by the current OS backend. No workflow action or unsandboxed fallback is supplied.
- `planned`: no desktop workflow is registered for that catalog entry. Buttons remain disabled even if unexpected metadata supplies a route.

The catalog does not invoke Git, language servers, package managers or remote targets during discovery. Installed executable paths, source freshness, Git-root identity, advisory/dataset availability, authentication and manifests are checked inside the opened workflow. An enabled LSP configuration is setup evidence, not proof of a runnable/trusted executable. QA availability uses the existing strict backend service rather than guessing from the browser's platform.

Opening source, secret/dependency, web or benchmark entries selects the corresponding Security tab through a bounded mode deep link. UI actions allow only known workflow routes. Search, category, availability and operation filters operate on the returned inventory. Project changes and refresh discard stale responses. Catalog and run-history failures remain separate and retryable; there is no fabricated local catalog fallback.

`recent_security_tool_runs` provides at most 100 normalized records (UI requests 20) from existing analysis, authorized web and QA execution stores. It preserves source ID, run kind, status, times and measured duration where available. Project-scoped queries reject missing projects. Chronological sorting normalizes supported SQLite/ISO timestamps with `julianday`, with deterministic per-store tie ordering. No source code, target credentials or raw output is included.

Only a completed QA run with `parser_completed=1` exposes its persisted test verdict. Other scan/execution records show no test verdict; completed does not imply successful tests or complete security coverage. This is a read-only summary of existing stores, not the CS-02 scheduler or a new lifecycle migration.

Validation: native unit tests for unique inventory/explicit registration, missing/corrupt setup data, platform blocking, scoped/bounded history, mixed timestamp formats and absent parser verdicts; frontend tests for forged planned/blocked routes and setup routing; production browser fixture-IPC checks for all inventory entries, filters, navigation, errors/retry, stale project responses and responsive themes. Native desktop GUI physical validation remains a separate obligation.
