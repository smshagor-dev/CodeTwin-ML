# Reference capability matrix

How CodeTwin-ML covers the capabilities of 25 reference projects, built natively in Rust, Go, TypeScript and SQLite.

Last updated: 2026-10-29, branch `durable-orchestration-platform`. This matrix extends [CAPABILITY_GAP_AUDIT.md](CAPABILITY_GAP_AUDIT.md), which remains the source of truth for the orchestration, gateway and collaboration rows it already covers.

## How to read this

**Status:**

| Status | Meaning |
|---|---|
| **IMPLEMENTED** | Production code plus automated tests in this repository. |
| **PARTIAL** | Part of the capability works. The gap is stated in the row. |
| **MISSING** | No implementation yet. |
| **BLOCKED** | Cannot be completed or verified without something external (named in the row). |
| **DECLINED** | Deliberately not built, because it conflicts with CodeTwin's safety model. |

**Review basis.** The reference projects were assessed from their public architecture, documentation and APIs.

- No reference code was copied, vendored or embedded.
- No reference repository was cloned into this project.
- The review was architectural, not a line-by-line source audit. Where a row depends on a reference detail that should be re-checked against the current upstream source, the row says so.

**Evidence rule.** A row is IMPLEMENTED only if its listed test exists and passes. See the verification record at the end.

## Capabilities added in this pass

| Area | Inspired by | New code | Migration |
|---|---|---|---|
| robots.txt compliance (RFC 9309 subset) | Firecrawl, Crawl4AI | `crates/research-retrieval/src/robots.rs` | — |
| Markdown extraction, SimHash duplicate detection, freshness | Firecrawl, Crawl4AI | `crates/research-retrieval/src/sources.rs`, wired into `research.fetch` in `agent_tools.rs` | — |
| Cross-analyzer correlation, normalisation, risk ranking, policy gate, audited suppressions, hashed snapshots | Semgrep, CodeQL, Trivy, Gitleaks | `crates/codetwin-core/src/security_intelligence.rs` | `0052_security_intelligence.sql` |
| Temporal knowledge graph, memory versioning, contradiction-aware reconcile, human-resolved conflicts | Graphiti, Mem0, Cognee | `crates/codetwin-core/src/knowledge_memory/temporal.rs` | `0053_temporal_memory.sql` |
| Neural embeddings for memory (loopback model, or consented remote) | LlamaIndex, Mem0, sqlite-vec | `crates/codetwin-core/src/knowledge_memory/embeddings.rs` | `0053` (`memory_neural_vectors`) |
| Run comparison and stall (deadlock) diagnosis | LangGraph, Microsoft Agent Framework | `crates/task-orchestrator/src/compare.rs` | — |
| Desktop: *Security intelligence*, *Knowledge & conflicts*, *Compare & diagnose* tabs | Langfuse, Dify | `apps/desktop/src/workspace/pages/IntelligencePanels.tsx`, `intelligenceApi.ts`, `src-tauri/src/intelligence_commands.rs` | — |

## A. Multi-agent orchestration — LangGraph, CrewAI, Microsoft Agent Framework

| Capability | Status | CodeTwin implementation (paths) | Tests | Remaining gap / risk |
|---|---|---|---|---|
| Dynamic multi-agent workflows | IMPLEMENTED | `task-orchestrator` (`executor.rs`, `store.rs`), `codetwin-core/src/model_planner.rs`, `specialist_workers.rs` (10 roles) | `tests/workflow_platform.rs`, `tests/platform_features.rs` | Models propose plans; deterministic validation and a human approve them. |
| Stateful task execution | IMPLEMENTED | Typed run/task finite-state machines with compare-and-set transitions (`state.rs`, `store.rs`) | `state.rs` unit tests | — |
| Specialist coordination | IMPLEMENTED | `specialist_workers.rs` | `read_only_investigation_runs_end_to_end_and_is_verified` | — |
| Agent-to-agent delegation | IMPLEMENTED | `Store::insert_delegated_task`, `native_agent_delegation.rs` (typed; no permission inheritance) | `delegation_does_not_inherit_permissions` | — |
| Dependency-aware scheduling | IMPLEMENTED | `dag.rs`, `Orchestrator::select_batch` | `dag.rs` tests | — |
| Parallel read-only execution | IMPLEMENTED | `GlobalLimits`, resource-key serialisation | `independent_read_only_tasks_run_concurrently_within_budget` | No CPU or memory metering. |
| Workflow checkpoints | PARTIAL | Every task output, attempt and event is durable, and `recover()` resumes after a crash. `TaskContext::checkpoint` is a cooperative cancel/deadline check. | crash-recovery test | No LangGraph-style named checkpoints or fork-from-checkpoint. |
| Automatic retry and recovery | IMPLEMENTED | Backoff retries, lease expiry, `Store::recover` | `transient_failures_retry…`, `crash_recovery_…` | Time limits are cooperative. |
| Bounded replanning | IMPLEMENTED | `Store::submit_plan` replan budget | `replanning_is_bounded…` | — |
| Execution reflection | IMPLEMENTED | `quality_reviewer`, `report::classify_outcome` | `model_text_never_verifies_a_run` | — |
| Loop detection | IMPLEMENTED | `MAX_IDENTICAL_TOOL_CALLS`, `tool_call_loop_detected` | `repeated_identical_tool_calls_are_stopped_as_a_loop` | — |
| Deadlock detection | IMPLEMENTED (new) | Static: cycle rejection in `dag.rs`. Runtime: `compare::diagnose_stall` names stuck tasks and their failed, cancelled or blocked root causes. | `compare::tests::detects_runs_that_cannot_progress` | Diagnosis is on demand (desktop *Compare & diagnose*). It does not raise an automatic alert yet. |
| Persistent task state | IMPLEMENTED | Migration 47 | `tests/orchestration.rs` | — |
| Human approval gates | IMPLEMENTED | Scope-digest-bound approvals; automation principals cannot approve | `mutations_need_scope_bound_task_approval…`, `rbac_and_separation_of_duties…` | — |
| Structured event streams | IMPLEMENTED | `workflow_events.seq`, `events_since` cursor | e2e cursor replay | The UI polls; there is no push channel. |
| Workflow replay and comparison | IMPLEMENTED (new) | Replay: the durable event cursor. Comparison: `compare::compare_runs`, which matches tasks by plan key and compares state, output hash, attempts and duration. | `compare::tests::compares_runs_by_task_key` | Comparison is per task. It does not diff task outputs field by field. |

## B. Browser automation and web research — Browser Use, Playwright, Firecrawl, SearXNG, Crawl4AI

| Capability | Status | CodeTwin implementation (paths) | Tests | Remaining gap / risk |
|---|---|---|---|---|
| Research orchestration | IMPLEMENTED | `research_analyst` worker, `research.fetch` and `research.search` tools | `specialist_workers` tests | — |
| Search query planning | PARTIAL | Queries come from the operator-approved plan input | — | By design, the model cannot invent queries or URLs (prompt-injection boundary). |
| Configurable search providers | IMPLEMENTED | `research-retrieval/src/search.rs` (Brave, SearXNG). The key is kept in the OS store and never follows a redirect. | `searches_a_loopback_fixture_and_sends_the_key` | — |
| HTTPS page retrieval with SSRF protection | IMPLEMENTED | `research-retrieval/src/lib.rs`: public-IP pinning, DNS-rebinding defence, redirect revalidation, size, type and time limits | 6 tests, including metadata-IP redirects | — |
| robots.txt and access policy | IMPLEMENTED (new) | `robots.rs`: product-token groups, longest match, `*` and `$` wildcards; 4xx means allow, 5xx or unreachable means disallow; checked on every hop including redirects; one-hour cache per origin | `robots::tests::*` (4); `robots_txt_is_honoured_on_the_wire` (live loopback server) | Crawl-delay is ignored; fetches are single, operator-approved requests, not crawls. |
| JavaScript-rendered pages through an isolated browser | BLOCKED | — | — | Needs a sandboxed headless-browser adapter (Chromium via Playwright or CDP) with a network policy as strict as `FetchPolicy`. Not shipped: no OS-level sandbox exists for it on Linux or macOS (see audit row D3), and a weaker fallback is not acceptable. |
| Screenshot capture | BLOCKED | — | — | Depends on the browser adapter above. |
| Browser navigation history | PARTIAL | Redirect chain per fetch; `research_sources` log per project | e2e | No interactive navigation, by design. |
| Structured and Markdown extraction | IMPLEMENTED (new) | `sources::extract_markdown` keeps headings, lists, code and safe links; `javascript:` and `data:` links are reduced to text | `markdown_keeps_structure_and_drops_unsafe_links` | Regex-based. Complex layouts (tables, nested frames) flatten. |
| Source metadata, citations, provenance | IMPLEMENTED | `research_sources` and `research_citations` (migration 50), with content SHA-256 | `platform_features` | — |
| Duplicate source detection | IMPLEMENTED (new) | `sources::simhash` and `duplicate_groups`; `research.fetch` returns `duplicate_of` (same bytes or ≤ 3-bit SimHash distance) | `near_duplicates_are_grouped_but_distinct_pages_are_not` | Compares against the latest 200 project sources. |
| Source freshness | IMPLEMENTED (new) | `sources::freshness` (Last-Modified: current < 90 days, aging < 2 years, stale, unknown); returned by `research.fetch` | `http_dates_and_freshness` | Only the HTTP header is used; dates inside the page are not parsed. |
| Contradiction detection | IMPLEMENTED | `contradiction_candidates` (negation heuristic), marked `needs_human_review` | `quotes_and_contradictions` | Heuristic only. |
| Retrieved content treated as untrusted | IMPLEMENTED | `untrusted: true`, `instruction_like_phrases` signal; content never reaches the tool dispatcher | `extracts_text_and_flags_injection_without_obeying_it` | — |
| Authenticated browsing, form submission, purchases | DECLINED | — | — | Out of scope. It would require separate approvals and a credential vault for third-party sites. |
| Live browsing timeline and research reports | PARTIAL | Tool cards in the event stream; `report.rs` | e2e | No dedicated research timeline view. |

## C. Security analysis and verification — Semgrep, CodeQL, Trivy, Gitleaks, OWASP ZAP, Nuclei

| Capability | Status | CodeTwin implementation (paths) | Tests | Remaining gap / risk |
|---|---|---|---|---|
| Static security rules | IMPLEMENTED | `crates/security-analyzer`, `security_analysis.rs`, Go `services/security-engine` | analyzer test suites | — |
| Cross-file data flow and taint | PARTIAL | Call-site evidence with `taint_proven: false`, `review_required: true` (`security-analyzer/src/lib.rs`); native security flows (migrations 44–46) | analyzer tests | No proven inter-procedural taint propagation. Findings say so, rather than over-claiming. |
| Rule packs | PARTIAL | Built-in rules with `rule_version` | — | No external rule-pack loader. Importing third-party packs would need provenance review. |
| Dependency and supply-chain analysis | IMPLEMENTED | `dependency_audit.rs` (OSV), `sbom.rs` | `tests/dependency_audit*` | — |
| Container image metadata | PARTIAL | Digest-pinned offline Docker/Trivy worker (`native_agent_workers.rs`) | worker tests | Requires a local Docker daemon and the pinned image. |
| Infrastructure-as-Code checks | PARTIAL | Dockerfile and Compose healthcheck observations (`runtime_analysis.rs`) | runtime analysis tests | No Terraform or Kubernetes misconfiguration rules. |
| Secret detection, redaction, exposure history | IMPLEMENTED | `secret_scanning.rs`, `secret_history.rs`, `model_gateway::redact` | `tests/secret_scanning.rs` | Redaction is pattern-based. |
| False-positive suppression with audit trail | IMPLEMENTED (new) | Expiring suppressions (≤ 365 days) by fingerprint, rule or path prefix. Approver authority is required, and automation principals are refused. Terms are immutable (revoke and recreate), and the audit log is append-only (SQLite triggers). Current `false_positive` reviews also hide findings, with the cause shown. Analyzer rows are never modified. | `end_to_end_correlation_suppression_audit_and_snapshot` | — |
| Evidence correlation across analyzers | IMPLEMENTED (new) | `security_intelligence::correlate`: same path, ≤ 3 lines apart, same CWE (or category); union-find clusters with stable ids | `independent_analyzers_corroborate_and_raise_confidence` | Location-based. Findings without a path are not correlated. |
| Vulnerability deduplication | IMPLEMENTED | Per-analyzer `UNIQUE(project_id, fingerprint)` plus cross-analyzer clusters | as above | — |
| Severity and confidence normalisation | IMPLEMENTED (new) | `Severity::normalize` (CVSS words, SARIF levels; unknown maps to medium). A missing confidence gets a per-analyzer default. Combined confidence is a noisy-OR over distinct analyzers only. | `severity_vocabularies_normalise_conservatively`, `same_analyzer_duplicates_do_not_inflate_confidence` | The defaults are judgement calls, documented in code. |
| Risk prioritisation | IMPLEMENTED (new) | Severity weight × combined confidence × corroboration boost × confirmed-review boost, capped at 10 | correlation tests | Not exploitability-aware. |
| Security policy evaluation | IMPLEMENTED (new) | `evaluate_policy`: max critical, max high, minimum confidence, fail on secrets | `policy_gate_counts_confident_clusters_and_secrets` | — |
| Authorized web-security checks (ZAP/Nuclei-inspired) | IMPLEMENTED | `crates/web-security-testing`: passive by default, scoped, paced active checks | `tests/local_lab.rs` | Unrestricted templates are DECLINED. |
| Finding lifecycle and regression verification | IMPLEMENTED | `findings.status`, `resolved_at`, guided lifecycle, security-fix verify, campaigns | `tests/security_fix_e2e.rs` | — |
| Signed, provenance-linked reports | PARTIAL | Review evidence: Ed25519 with external signer custody (`native_evidence_signatures.rs`). Correlation snapshots and workflow reports are content-hashed (SHA-256, tamper-evident). | `verify_snapshot` tamper test | Workflow reports and snapshots are hashed, not signed. A hash is not authentication; the UI says so. |
| Exploit chains, brute force, credential attacks, lateral movement | DECLINED | — | — | Prohibited by CodeTwin's authorization model. |

## D. Memory, RAG and knowledge graph — Mem0, Graphiti, LlamaIndex, sqlite-vec, Cognee

| Capability | Status | CodeTwin implementation (paths) | Tests | Remaining gap / risk |
|---|---|---|---|---|
| Layered memory (working, episodic, project fact, approved, evidence) | IMPLEMENTED | `knowledge_memory.rs`, migration 49 | 4 unit tests | — |
| Project isolation, expiry, user deletion, retention | IMPLEMENTED | as above | `dedup_expiry_deletion_and_approval` | — |
| Neural embedding generation | PARTIAL (code complete) / BLOCKED (live run) | `knowledge_memory/embeddings.rs`. `HttpEmbedder` calls an OpenAI-compatible `/embeddings` endpoint, either loopback-only or remote under a project consent that allows cloud **and** source excerpts. Remote text is redacted and size-bounded. Vectors are stored per model in `memory_neural_vectors`, pinned to the embedded content hash. | `loopback_embedder_speaks_the_openai_wire_format` (real HTTP), `remote_embedding_requires_matching_consent_before_any_network`, `neural_vectors_rank_synonyms_and_go_stale_on_revision` | **No live neural model has been run in this environment.** No local server was found, and it is not verified that OpenMindAI offers an embeddings endpoint. The desktop exposes loopback embedding only. |
| Vector similarity search in SQLite | IMPLEMENTED | Bounded Rust-native cosine over at most 2,000 vectors per project and model, stored as BLOBs | memory tests | See the sqlite-vec decision below. |
| Hybrid keyword + semantic retrieval | IMPLEMENTED | FTS5 BM25 + vector score + trust boost; `retrieve_with` reports the model actually used | `hybrid_retrieval_is_project_isolated_and_budgeted` | — |
| Reranking | PARTIAL | Weighted fusion and a verified/approved trust boost | — | No cross-encoder reranker. |
| Evidence-grounded RAG | IMPLEMENTED | Cloud reviewer cites `[M:id]`; `context_compaction.rs` | e2e | — |
| Temporal knowledge graph | IMPLEMENTED (new) | `kg_edges.valid_from_ms`, `invalidated_ms`, `superseded_by`; `neighborhood_at(t)`; `assert_fact` makes `(from, relation)` single-valued and keeps the old edge | `exclusive_facts_supersede_and_remain_queryable_as_of_a_time` | Only `assert_fact` callers get exclusive semantics; `link` stays multi-valued. |
| Source-backed edges, confidence, provenance | IMPLEMENTED | Every edge has `source_ref`, `confidence`, and `verified` or `inferred` | `graph_edges_carry_provenance…` | — |
| Contradiction-aware memory updates | IMPLEMENTED (new) | `reconcile` returns added, unchanged, revised or conflict. An unverified update never overwrites verified memory; it waits in `knowledge_conflicts` for a human approver. | `reconcile_adds_revises_and_never_lets_unverified_overwrite_verified` | Matching is by layer and normalised title, not by semantic similarity. |
| Memory versioning | IMPLEMENTED (new) | Append-only `memory_item_versions`; optimistic concurrency on `version` | `revisions_keep_append_only_history_and_detect_lost_updates` | — |
| Entity and relationship extraction | PARTIAL | Graph nodes and edges come from structured run data (tasks, findings, files, sources) | `ingest_workflow_run` e2e | No natural-language entity extraction. A model-based extractor would produce only `inferred` edges. |
| Cross-session retrieval and context compression | IMPLEMENTED | Persistent memory; `context_compaction.rs` (extractive) | 4 unit tests | — |
| Retrieval evaluation | MISSING | — | — | Next: a recall@k / MRR harness over a labelled local fixture set. |

**sqlite-vec decision.** sqlite-vec was evaluated and not adopted for now:

- It is a loadable extension, so the app would have to enable `load_extension`. That is additional attack surface in a process that also opens operator-supplied databases.
- It needs a per-platform native binary (Windows, Linux, macOS on x64 and arm64) to be packaged and signed.
- Memory is capped at 5,000 items per project. A bounded brute-force scan over at most 2,000 vectors is adequate at that size.

Revisit if the caps are raised.

## E. Observability, model management and automation — Langfuse, LiteLLM, Dify, n8n, Promptfoo

| Capability | Status | CodeTwin implementation (paths) | Tests | Remaining gap / risk |
|---|---|---|---|---|
| Workflow, agent and tool traces | IMPLEMENTED | `workflow_events`, `workflow_tool_invocations`, run, task and request id correlation | e2e | No OpenTelemetry exporter. |
| Model latency, token usage, provider health | IMPLEMENTED | `observability.rs` (`llm_analytics`, `metrics_snapshot` with alerts) | 2 unit tests + e2e | Tokens are counted only when the provider reports them; streams carry no usage. |
| Cost estimation | PARTIAL | Provider credits are counted | — | No currency price table. |
| Routing, fallback, rate limits, circuit breakers | IMPLEMENTED | `model-gateway` (`router.rs`, `resilience.rs`) | gateway contract tests | Fallback runs from cloud to local only, with consent. |
| OpenMindAI Cloud integration | IMPLEMENTED | `model-gateway/src/client.rs`; key in the OS store | Mock contract suite; opt-in live test (passed 2026-10-28, per the gap audit) | The live test needs a key. |
| Model quality evaluations and prompt regression tests | MISSING | — | — | Next: a Promptfoo-style local suite (fixtures → assertions) run against the configured model. |
| Prompt-injection resistance testing | PARTIAL | Hostile planner output, injected worker and malicious page fixtures exist as unit and e2e tests | `hostile_planner_output_falls_back_to_the_template`, `injected_worker_cannot_escalate_or_self_verify`, `extracts_text_and_flags_injection…` | No dedicated, extensible red-team fixture suite yet. |
| Workflow builder | PARTIAL | Goal composer, model-proposed DAG and approval | — | No visual DAG editor. |
| Typed nodes and dependency graphs | IMPLEMENTED | Typed roles and tool descriptors, DAG | — | — |
| Conditional branches | MISSING | — | — | — |
| Event-driven and scheduled triggers | MISSING | — | — | Must reuse plan approval, not bypass it. |
| Workflow templates | PARTIAL | Built-in investigation template (planner fallback) | — | No user-defined templates. |
| Workflow versioning and safe import/export | MISSING | — | — | — |
| Approval-required actions | IMPLEMENTED | — | — | — |
| Regression dashboards | MISSING | — | — | — |
| Unrestricted shell or remote-command nodes | DECLINED | `PolicyEngine::hard_deny` | `hard_denials_fail_closed` | — |

## F. PentAGI

The capabilities PentAGI brings beyond rows A–E are listed below.

| PentAGI capability | CodeTwin position |
|---|---|
| Per-task isolated containers for security tools | PARTIAL. The digest-pinned Docker/Trivy worker and the Windows strict QA sandbox exist. General workflow subprocesses stay disabled without an enforced sandbox (audit row D3). |
| Vector memory of past assessments | Covered by row D (memory, episodic layer, knowledge graph). |
| Observability stack (Langfuse, Grafana) | Covered natively in row E, without external services. |
| Autonomous offensive testing (exploitation, lateral movement) | DECLINED. It conflicts with explicit authorisation, fail-closed scope and the no-exploit-chain rules. |

## Verification record (2026-10-29, Windows 11, Rust 1.97)

- `cargo test -p research-retrieval`: 18 passed. The three `live_*` tests are opt-in (`CODETWIN_TEST_LIVE_WEB=1`); they did not run against the internet here and are not evidence.
- `cargo test -p codetwin-core --lib -- knowledge_memory db::tests security_intelligence`: all passed, including the migration upgrade and backup test at schema 53.
- `cargo test -p task-orchestrator --lib compare`: 2 passed.
- `npm run typecheck` and `npx vitest run` (apps/desktop): 14 files, 64 tests passed.
- The full-suite result for this branch is recorded in the PR description.
- **Not verified:**
  - the desktop UI in a running window;
  - a live neural embedding model;
  - a live robots.txt check on the public internet.
