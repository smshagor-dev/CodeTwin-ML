# Capability gap audit

Source-backed status of every item in the *CodeTwin-ML gap-only advanced platform implementation* specification (sections A–J).
Last updated: 2026-10-29, branch `durable-orchestration-platform` (base `0db82ef`).

**Status key:**

| Status | Meaning |
|---|---|
| **verified** | Implemented, and covered by automated tests or a recorded live run. |
| **partial** | Some of the item works; the remainder is listed as a gap. |
| **blocked** | Cannot proceed without something external. |
| **not started** | No work done yet. |

A README claim is never counted as evidence.

For capabilities compared against the 25 reference projects (research hygiene, security correlation and suppression, temporal memory, neural embeddings, run comparison), see [REFERENCE_CAPABILITY_MATRIX.md](REFERENCE_CAPABILITY_MATRIX.md).

## What already existed (audited, preserved, not rewritten)

The repository already had a mature, approval-gated **native review supervisor**. It was audited, not replaced:

- **Supervisor and DAG:** `crates/codetwin-core/src/native_agents.rs`, `native_agent_delegation.rs`, `native_flow_queue.rs`, migrations 29–46.
  - Six fixed passive roles, a persisted delegation DAG, and handoff digests.
  - Bounded two-thread concurrency and restart → `interrupted`.
- **Provenance memory:**
  - `native_agent_memory.rs` and `native_agent_knowledge.rs`: 64-dim hashed vectors.
  - `native_neural_embeddings.rs`: optional OpenAI-compatible embeddings.
  - `native_graph_reasoning.rs`.
- **Optional model features:** `native_agent_reasoning.rs` provides OpenAI-compatible model interpretation and role suggestion. It is env-configured, consented per request, and the token lives in an environment variable.
- **Isolated worker:**
  - `native_agent_workers.rs`: an offline, digest-pinned Docker/Trivy worker.
  - `native_worker_audit.rs`.
  - The Windows strict QA sandbox in `crates/qa-execution`.
- **Analysis and repair engines:** source and indexing, quality, AppSec, DB, runtime, secrets, OSV and SBOM, repair and campaign, and web security engines, plus Ed25519 evidence signing (`native_evidence_signatures.rs`).

**Gap that motivated the new work:** none of the above was a general goal-driven orchestrator. It lacked:

- typed run and task state machines;
- leases and idempotent tool invocations;
- scope-digest approvals and replanning;
- layered memory and an evidence knowledge graph spanning tasks, findings, sources and outcomes;
- an OpenMindAI provider with OS-stored credentials;
- SSRF-safe research retrieval;
- an operator UI for any of this.

## Matrix

| # | Capability | Status | Code | Tests / runtime proof | Remaining gaps / risks |
|---|---|---|---|---|---|
| A1 | Typed run/task FSM, reason codes, stale-transition rejection | **verified** | `crates/task-orchestrator/src/state.rs`, `store.rs` (compare-and-set transitions) | `state.rs` unit tests (terminal states, no approval bypass) | — |
| A2 | Durable SQLite runs/tasks/deps/attempts/leases/events/approvals/tool invocations/reports, retention | **verified** | migration `0047_workflow_orchestration.sql`, `store.rs`, `WorkflowPlatform::prune` | `tests/orchestration.rs`, `db.rs` migration tests, `platform_features.rs::pdf_reports_metrics_and_retention` | - |
| A3 | DAG cycle/unknown/self detection; runaway replanning; replan budget; tool-call loop detection | **verified** | `dag.rs`, `Store::submit_plan`, executor gate (`MAX_IDENTICAL_TOOL_CALLS`, deny code `tool_call_loop_detected`) | `dag.rs` property-style test; `replanning_is_bounded_and_rejects_identical_plans_and_cycles`; `repeated_identical_tool_calls_are_stopped_as_a_loop` | - |
| A4 | Approval gates bound to scope digest, plan revision, expiry; automated principals cannot approve | **verified** | `Store::decide_approval`, `has_live_task_approval` | `approved_investigation_runs_end_to_end…`, `mutations_need_scope_bound_task_approval_and_replans_stale_it` | Single local operator identity (OS user); no multi-user separation of duties (see H) |
| A5 | Deterministic policy engine is final authority; no inherited permissions | **verified** | `policy.rs`, executor `Gate` | `policy.rs` tests; `injected_worker_cannot_escalate_or_self_verify`; `delegation_does_not_inherit_permissions` | — |
| A6 | Bounded concurrency, resource-key serialization, mutation isolation, global backpressure | **verified** | `executor.rs` (`select_batch`, `GlobalLimits`) | `independent_read_only_tasks_run_concurrently_within_budget` (peak = 2), `resource_keys_serialize_conflicting_work` (peak = 1) | Per-project quota is per-run `max_parallel` + global limit; no CPU/memory measurement |
| A7 | Pause/resume/cancel, timeouts, retries with backoff, crash recovery, idempotent side effects | **verified** | `executor.rs`, `Store::recover`, `begin_tool` idempotency | `crash_recovery_blocks_uncertain_side_effects_and_retries_read_only_work`, `cancellation_and_timeouts…`, `transient_failures_retry…`, `concurrent_claims_never_double_execute` | Time limits are **cooperative** (a long analyzer call is not forcibly killed) |
| A8 | Specialist workers with independent contracts | **verified** | `crates/codetwin-core/src/specialist_workers.rs` (10 roles) | `tests/workflow_platform.rs::read_only_investigation_runs_end_to_end_and_is_verified` on a real indexed fixture | Repair Strategist role not added: repairs stay in the existing hash-pinned repair flow |
| A9 | LLM-generated plans | **verified** | `model_planner.rs`: the model proposes tasks; deterministic validation (plannable roles only, at most 8 tasks, safe keys, DAG check, inputs reduced to role schemas); the verify/report/quality tail is added by code; template fallback; `plan_source` event | `model_planner` unit tests (hostile, cyclic, oversized output); `platform_features.rs::ai_planning_decomposes_validates_and_executes_with_a_local_model`, `hostile_planner_output_falls_back_to_the_template` | The model cannot add capabilities, URLs, queries or side effects; execution still needs human approval |
| B1 | OpenMindAI Cloud adapter against a verified real contract | **verified** | `crates/model-gateway/src/client.rs`, `sse.rs`, `error.rs` | Mock contract suite `tests/provider_contract.rs` (10); **live** `tests/openmindai_live.rs` passed 2026-10-28 (models, catalog, chat, native tool call, SSE stream) | Live test is opt-in; requires a key |
| B2 | Secure credentials (OS store), never SQLite/logs/WebView | **verified** | `credentials.rs` (`keyring` 3.6), desktop `set_cloud_provider_token` | `credentials.rs` tests; `cloud_settings` test asserts no secret columns | Linux backend is the kernel keyring (does not survive reboot); Secret Service not enabled to avoid a libdbus build dependency |
| B3 | Consent, preview, redaction, bounded payload, offline-only default, revocation | **verified** | `consent.rs`, `redact.rs`, `cloud_settings.rs` (migration 48) | `consent.rs`, `redact.rs`, `cloud_chat_refuses_unapproved_or_altered_payloads_without_network`, `consent_grant_revoke…` | Redaction is pattern-based; unusual secret formats may pass |
| B4 | Retries with jitter, circuit breaker, concurrency limit, timeouts, cancellation, request IDs | **verified** | `resilience.rs`, `client.rs` | `retries_429_and_503_but_not_auth…`, `circuit_opens_after_repeated_outages`, resilience unit tests | — |
| B5 | Streaming, tool-call validation, truthful usage | **verified** | `sse.rs` (`reasoning_content` discarded, `[DONE]` required) | stream tests (mock and live) | Streams carry no `usage` (observed live), so only credits are counted for streams |
| B6 | Per-role models, cloud to local fallback only when allowed | **verified** | `router.rs` (`RoleModels.local_by_role`), `model_access.rs` (role-aware, audited calls with consented fallback), desktop *Models & search* tab | `model_review_uses_rag_and_compaction_and_falls_back_to_local_with_consent`, `local_fallback_requires_consent` | The local endpoint must be loopback and OpenAI-compatible |
| C1 | Layered memory (working/episodic/fact/approved/evidence) in SQLite | **verified** | `knowledge_memory.rs`, migration 49 | 4 unit tests and the e2e ingest assertion | — |
| C2 | Hybrid keyword (FTS5) + vector retrieval with budgets and omission reporting | **verified** | `KnowledgeMemory::retrieve` | `hybrid_retrieval_is_project_isolated_and_budgeted`, `corrupt_vectors_are_ignored` | Default vectors are **lexical hashed vectors, not neural**. Neural vectors from a loopback or consented embedding model can now be stored per model (`knowledge_memory/embeddings.rs`, migration 53); no live neural model has been verified yet |
| C3 | Evidence knowledge graph with source refs, confidence, verified vs inferred | **verified** | `upsert_node`, `link`, `neighborhood`, `ingest_workflow_run` | `graph_edges_carry_provenance…`; e2e asserts verified `references` edges | — |
| C4 | Cross-project isolation, dedup, expiry, deletion, reindex, operator approval | **verified** | `knowledge_memory.rs` | `dedup_expiry_deletion_and_approval` | — |
| C5 | Context compaction and RAG for model prompts | **verified** | `context_compaction.rs` (prioritized sections, JSON flattening, extractive summaries, reported omissions); the cloud reviewer retrieves project memory and asks for `[M:id]` citations | 4 unit tests; e2e asserts `context` stats, `retrieved_memory`, `cited_memory` | Extractive, not abstractive; token counts are estimates (about 4 characters per token) |
| D1 | Typed tool descriptors (capability, schema, timeout, budget, destinations, roots, audit, availability) | **verified** | `policy.rs::ToolDescriptor`, `agent_tools.rs` (12 tools) | schema tests; e2e tool invocations | — |
| D2 | First-party read-only tools (Git, code search, deps, SBOM, findings, tests, evidence, memory) | **verified** | `agent_tools.rs` | e2e; `evidence_verification_detects_drift` | Safe document/PDF ingestion is **not implemented** (PDFs are refused) |
| D3 | No shell/raw network; subprocess fails closed without enforced sandbox | **verified** | `PolicyEngine::hard_deny`, capability matrix | `hard_denials_fail_closed`; e2e matrix assertion | The Linux/macOS sandbox for workflow subprocesses does not exist, so the capability stays disabled |
| D4 | Operator-visible capability matrix | **verified** | `CoreToolRuntime::capability_matrix`, UI *Capabilities* tab | e2e | — |
| E1 | SSRF-resistant retrieval (HTTPS, public IPs, DNS pinning, redirect revalidation, size/type caps) | **verified** | `crates/research-retrieval` | 6 tests including a metadata-IP redirect and IPv4-mapped IPv6 | No live internet fetch in CI |
| E2 | Source snapshots, hashes, timestamps, citation records, untrusted marking, web search | **verified** | `research_retrieval::search` (Brave, SearXNG through the SSRF-safe fetcher; the key never follows a redirect), `research.search` tool, `research.fetch` writes `research_citations` per goal claim; settings in migration 51, key in the OS store | `search.rs` tests incl. a loopback provider fixture; `search_settings` test | No live search in CI; no headless browser (JavaScript-rendered pages are fetched as served) |
| E3 | Contradiction detection, unsupported-claim marking | **verified** | The research analyst marks each claim supported/unsupported and runs `contradiction_candidates` across sources (`needs_human_review`) | unit tests | Heuristic only |
| F1 | Post-task validation, reviewer that cannot self-approve, truthful outcomes | **verified** | `SuccessCriterion`, `report::classify_outcome`, `quality_reviewer` | `model_text_never_verifies_a_run`, e2e (`verified` only via the deterministic verifier) | — |
| F2 | Max iterations/cost/runtime, lease expiry, stale workers, restart without duplicate side effects | **verified** | executor budgets, `recover`, `begin_tool` | crash-recovery test | — |
| G1 | Goal composer, consent selection, DAG view, roster, timeline, tool cards, approval inbox, budgets, pause/resume/cancel, retry diagnostics, report, memory explorer, history | **partial** | Terminal-first Workspace (`pages/AssessmentWorkspace.tsx`, `assessmentApi.ts`, `codetwin-core::assessment_stream`; see [ASSESSMENT_WORKSPACE.md](ASSESSMENT_WORKSPACE.md)) plus the Workflows management page | `npm run typecheck`, `npm run build`, vitest (`assessmentApi.test.ts`, `workflowApi.test.ts`, routes and integration), Rust `assessment_stream_merges_events_and_real_finding_cards` | **Not yet driven in a running desktop window.** DAG is view-only; no run comparison; lazy rendering uses `content-visibility` plus a 600-row window, not full virtualization |
| G2 | Durable event cursor with replay | **verified** | `workflow_events.seq`, `events_since` | cursor replay assertion in e2e test | UI polls once per second; no push channel |
| H1 | Roles, separation of duties, invitations, comment threads, audit | **verified** | `collaboration.rs`, migration 51; enforced in `WorkflowPlatform::create_planned_investigation` and `decide`; desktop *Team & API* tab | 3 unit tests; `rbac_and_separation_of_duties_gate_run_creation_and_approval` | One shared local database: collaborators use the same machine/DB file, with no network sync service. Principals are local identities, not authenticated accounts |
| H2 | Local automation REST API | **verified** | `automation_api.rs`: loopback bind, scoped expiring project tokens (SHA-256 verifiers), Origin/Host checks, rate limit, bounded parsing, audit, **no approval endpoint** | `automation_api_is_scoped_authenticated_and_cannot_approve` (real socket) | Off by default; GraphQL intentionally not added |
| I1 | Reproducible Markdown/JSON/PDF reports, evidence classes separated, limitations disclosed | **verified** | `report.rs`, `workflow_run_reports`, `pdf_report.rs` (dependency-free PDF 1.4 that embeds the Markdown SHA-256) | e2e report assertions; PDF xref/structure test; `pdf_reports_metrics_and_retention` | Standard fonts (WinAnsi): other scripts render as `?` |
| I2 | Metrics, alerts, diagnostics export, LLM analytics | **verified** | `observability.rs` (`llm_analytics`, `metrics_snapshot` with alerts, redacted `export_diagnostics`), desktop *Insights* tab, `/v1/metrics` | 2 unit tests; e2e metrics/analytics assertions | No OpenTelemetry exporter; correlation is by run, task and request ids in SQLite |
| I3 | Signed evidence for workflow reports | **not started** | Existing `native_evidence_signatures.rs` untouched | — | Workflow reports are content-hashed, **not signed**; an external signer integration is needed |
| J1 | Pre-migration backups and upgrade tests | **verified** | `Database::backup_before_migration` (`VACUUM INTO`, keeps 3) | `upgrades_take_a_restorable_backup_and_prune_old_ones` | — |
| J2 | Startup recovery, cloud never required to open a project | **verified** | `main.rs` setup → `recover_workflows`; cloud is built only when enabled and a key is stored | e2e `recover()`; offline default | — |
| J3 | Feature flags, signed updates, cross-platform docs | **partial** | Cloud and research are per-project consent flags | — | No updater signature verification added |

## Feature checklist (45-item comparison list)

| # | Item | Status | Matrix rows |
|---|---|---|---|
| 1 | Autonomous goal execution | verified (human plan approval stays mandatory) | A1-A9 |
| 2 | AI-generated task decomposition | verified | A9 |
| 3 | Specialized AI agents | verified (10 roles) | A8 |
| 4 | Concurrent independent agents | verified | A6 |
| 5 | Agent-to-agent delegation | verified (typed, no permission inheritance) | A5 |
| 6 | Automatic replanning | verified (bounded) | A3, F1 |
| 7 | Task dependency graph | partial: generated and shown by stage; not editable in the UI | A3, G1 |
| 8 | Loop detection | verified | A3 |
| 9 | Execution reflection | verified | F1 |
| 10 | Persistent workflow recovery | verified | A2, A7, J2 |
| 11 | Multi-flow parallel execution | verified (runs share a global limit of 4 workers) | A6 |
| 12 | Long-term semantic memory | partial: durable layered memory, but default vectors are lexical hashed vectors, not neural | C1-C4 |
| 13 | Vector similarity search | partial: same caveat as 12 | C2 |
| 14 | Episodic agent memory | verified | C1 |
| 15 | Working memory management | verified | C1, C4 |
| 16 | Knowledge graph | verified | C3 |
| 17 | Cross-session knowledge reuse | verified | C2, C5 |
| 18 | Retrieval-augmented generation | verified | C5 |
| 19 | Context summarization | verified (extractive) | C5 |
| 20 | AI-directed security workflows | partial: AI plans read-only security review; active testing stays in the dedicated authorized workflow by design | A5, D3 |
| 21 | 20+ security tool integrations | unchanged: `tool_catalog.json` catalogues 41 tools; workflow workers expose only first-party read-only tools by design | D2 |
| 22 | Isolated execution containers | blocked on Linux/macOS: the Docker/Trivy worker and Windows strict sandbox exist, but no workflow subprocess sandbox exists elsewhere, so the capability stays disabled | D3 |
| 23 | Tool execution audit | verified | D1, H1 |
| 24 | Browser-based research | partial: SSRF-safe retrieval with citations; no headless JavaScript browser | E1-E3 |
| 25 | External search providers | verified (Brave, SearXNG) | E2 |
| 26 | Multiple LLM providers | verified (OpenMindAI Cloud and a loopback OpenAI-compatible local model) | B1, B6 |
| 27 | Cloud model inference | verified | B1 |
| 28 | Per-agent model selection | verified | B6 |
| 29 | Model fallback | verified (consented, cloud to local only) | B6 |
| 30 | Streaming agent responses | verified for interactive questions; workers return complete replies and stream progress as durable events | B5, G2 |
| 31 | Structured tool calling | verified in the gateway (schema-validated proposals); workflow workers call tools deterministically | B5, D1 |
| 32 | Token and cost tracking | verified (credits always; tokens only when the provider reports them) | I2 |
| 33 | Context compression | verified | C5 |
| 34 | OpenMindAI Cloud API integration | verified (live test 2026-10-28) | B1 |
| 35 | Agent activity dashboard | verified (*Insights* tab) | I2 |
| 36 | Live execution timeline | verified | G2 |
| 37 | Task/flow visualization | verified (stage view and plan provenance) | G1 |
| 38 | Tool output streaming | verified (tool cards from the event stream) | G1, G2 |
| 39 | Agent conversation history | verified (per-run conversation view) | G1 |
| 40 | Multi-user collaboration | partial: roles, invitations, threads and audit on a shared local database; no network sync | H1 |
| 41 | Role-based access control | verified | H1 |
| 42 | REST automation API | verified (loopback REST; GraphQL intentionally not added) | H2 |
| 43 | Observability and distributed tracing | partial: metrics, alerts, diagnostics and id correlation; no OpenTelemetry export | I2 |
| 44 | LLM analytics | verified | I2 |
| 45 | PDF/Markdown workflow reports | verified | I1 |

## Known blockers and disclosures

1. **The OpenMindAI server leaks debug traces.**
   - An unknown model returns a full Laravel stack trace with server paths, which suggests `APP_DEBUG=true` in production (observed 2026-10-28).
   - The client never logs or surfaces these bodies.
   - The server operator should disable debug mode.
2. **The live provider test needs a key.**
   - CI runs it only through `workflow_dispatch` with an `OPENMINDAI_API_KEY` secret.
   - A green mock suite is not proof of live behavior.
3. **No PR or merge yet.**
   - The work is on the local branch `durable-orchestration-platform`. Pushing, PR creation and merging need maintainer confirmation.
   - The CI results below are local runs only.

## Local verification record (2026-10-28, Windows 11, Rust 1.97.1)

- `cargo test -p codetwin-core -p task-orchestrator -p model-gateway -p research-retrieval`: 421 passed, 0 failed.
- The opt-in live test run against `https://api.openmindai.org/api/v1/openmindai` passed:

  ```text
  CODETWIN_TEST_OPENMINDAI_LIVE=1 OPENMINDAI_API_KEY=… cargo test -p model-gateway --test openmindai_live
  ```

- `npm run typecheck` (apps/desktop) passed; vitest runs the new `workflowApi.test.ts` and the updated route tests.
