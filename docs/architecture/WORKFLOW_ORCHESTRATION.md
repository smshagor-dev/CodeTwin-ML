# Workflow orchestration, model gateway, memory and research

This document describes the durable workflow platform added alongside the existing native review supervisor (see [NATIVE_AGENTS.md](NATIVE_AGENTS.md)). For the per-item implementation status, see [CAPABILITY_GAP_AUDIT.md](CAPABILITY_GAP_AUDIT.md).

## Components

| Crate / module | Responsibility |
|---|---|
| `crates/task-orchestrator` | Typed run/task state machines, DAG checks, deterministic policy, the SQLite store, the bounded executor, reports |
| `crates/model-gateway` | OpenMindAI Cloud and loopback chat clients, consent/preview/redaction, OS credential store, resilience, routing |
| `crates/research-retrieval` | SSRF-resistant HTTPS retrieval, text extraction, quote and contradiction helpers |
| `codetwin-core::agent_tools` | 12 typed first-party tools wrapping existing analyzers |
| `codetwin-core::specialist_workers` | 10 specialist roles and the deterministic investigation planner |
| `codetwin-core::knowledge_memory` | Layered memory, hybrid FTS5 + vector retrieval, the evidence knowledge graph |
| `codetwin-core::cloud_settings` | Provider settings, project consent, provider request audit (no secrets) |
| `codetwin-core::workflow_platform` | Glue used by the desktop: plan, approve, execute, recover, report |
| `apps/desktop/.../workflow_commands.rs`, `WorkflowsPage.tsx` | Tauri commands and the *Workflows* page |

The four new migrations, 47–50, add the following tables:

- **47:** `workflow_*`
- **48:** `provider_settings`, `cloud_consents`, `provider_requests`
- **49:** `memory_*`, `kg_*`
- **50:** `research_*`

Existing databases are copied with `VACUUM INTO` before any pending migration is applied, and the last three backups are kept.

## Lifecycle

```text
run:  draft → planned → awaiting_approval → queued → running ⇄ paused
                                  ↑                    ↓
                             (replan) ←──────── validating → completed | failed | blocked
                                                any non-terminal → cancelled
task: planned → awaiting_approval → queued → running → validating → completed
                          retry_wait ⇄ queued;  failed | cancelled | blocked (operator override)
```

1. **Plan.** `create_investigation` validates the plan:
   - the roles exist;
   - inputs match each contract's schema;
   - capabilities are within the role contract;
   - the graph is a DAG within the task budget.

   It then stores the plan and creates approval requests. **Planning executes nothing.**
2. **Approve.** A plan approval covers read-only capabilities. Every external or mutating capability (web research, cloud inference) needs its own task approval. An approval is bound to:
   - the exact **scope digest**;
   - the plan revision;
   - an expiry.

   Replanning supersedes pending approvals. Principals named `model:`, `worker:`, `agent:`, `tool:` or `plugin:` are refused.
3. **Execute.** The coordinator:
   - claims dependency-ready tasks with crash-safe leases (an `IMMEDIATE` transaction, one live lease per task);
   - runs independent read-only tasks concurrently up to `max_parallel` and the global limit;
   - runs side-effecting tasks alone, and never overlaps tasks that share a `resource_key`.

   Workers call tools only through the policy gate, which:
   - validates arguments against the tool's schema;
   - re-checks capability grants and live approvals;
   - records every call (including denials) as SHA-256 digests.
4. **Validate.** Each output is checked against the task's success criteria and the role's permitted evidence class. The run outcome:
   - is `verified` only when every evidence-class task cites evidence **and** the deterministic `evidence_verifier` re-checked it against persisted hashes;
   - is never `verified` on the strength of model text, which is always `hypothesis` or `recommendation`.
5. **Recover.** At startup:
   - leases from other process instances or past their expiry are reconciled;
   - read-only tasks are retried;
   - tasks with a `started` side-effecting tool call become `blocked / uncertain_side_effect` until the operator confirms whether it was applied;
   - executing runs are `paused`.

## Investigation workflow (built in)

```text
repo ─┬─ source ──────┐
      ├─ deps ────────┤
      ├─ security ────┼─ verify ─┬─ (cloud review, optional) ─┬─ report ─ quality
      ├─ qa ──────────┤          └───────────────────────────┘
      └─ research? ───┘
```

- **Research** needs project consent with `allow_web_research` plus a task approval. URLs are operator-supplied (at most 5); there is no search-engine integration.
- **Cloud review** needs project consent, a configured provider and a stored key. It sends only redacted task summaries, bounded by the consent's payload limit. The digest of every request is recorded in `provider_requests`.
- **The quality reviewer** flags sections that cite no evidence. It may request one bounded, read-only re-verification. It cannot approve anything.

## OpenMindAI Cloud (verified contract)

These are the documented endpoints at <https://api.openmindai.org/docs>, verified against live responses on 2026-10-28:

| Item | Value |
|---|---|
| Base URL | `https://api.openmindai.org/api/v1/openmindai` |
| Auth | `Authorization: Bearer <developer key>` (keys expire after 90 days) |
| Discovery | `GET /models`, `GET /catalog` (ids `openmindai-super`, `openmindai-ultra`, `openmindai-lite`) |
| Chat | `POST /chat/completions` with `model`, `messages`, `tools`, `stream`, `max_tokens`, `temperature` |
| Tool calls | Native function calls, at most 64 tools; arguments are a JSON string |
| Streaming | SSE `data:` frames ending with `data: [DONE]` |
| Errors | `{"error":{"message"}}` (gateway), `{"message"}` / `{"message","errors"}` (backend); 401/403/404/422/429/502/503 |
| Usage | Non-stream responses include token `usage`; streams send `usage: null`. Billing is one application credit per successful call |

Adapter behavior derived from the observed responses:

- The models return hidden `reasoning_content`. The adapter counts and **discards** it, and never displays or stores it.
- With a small `max_tokens`, the reasoning consumes the budget and `content` is `null`. That case is reported as `incomplete`, not as an empty answer.
- 429, 5xx and timeouts are retried with jittered backoff. 401, 403, 404 and 422 are not retried.
- Streams are never retried once bytes have arrived.
- The circuit breaker opens after repeated infrastructure failures.
- Redirects are refused.
- Error bodies are reduced to a 200-character message. Framework `exception`, `file` and `trace` fields are never read.

### Configuration (no credentials in files)

1. Open the *Workflows → Cloud & consent* tab.
2. Keep the base URL above (or a self-hosted portal URL; it must be HTTPS), choose a default model, and enable the provider.
3. Paste the developer key and choose **Store key**. It is written to the OS credential store under service `codetwin-ml.model-gateway`. SQLite stores only the non-secret settings.
4. Choose **Test connection**. It lists models only and sends no project data.
5. Grant consent for the project, and optionally allow redacted source excerpts, local fallback or web research. **Revoke now** takes effect immediately.

The opt-in live smoke test uses environment variables only:

```bash
CODETWIN_TEST_OPENMINDAI_LIVE=1 OPENMINDAI_API_KEY=<key> \
  cargo test -p model-gateway --test openmindai_live -- --nocapture
# optional: OPENMINDAI_BASE_URL, OPENMINDAI_TEST_MODEL
```

The manually triggered workflow `.github/workflows/openmindai-smoke.yml` runs the same test with the `OPENMINDAI_API_KEY` repository secret.

## Memory and evidence graph

- **Layers:**
  - `working`: worker notes, with a 7-day expiry.
  - `episodic`: per-task run summaries.
  - `project_fact`
  - `approved_knowledge`: operator promotion only.
  - `evidence_ref`
- **Retrieval:** a project-scoped hybrid of FTS5 bm25 and cosine over 128-dim **hashed lexical vectors** (`hashed-lexical-v1`), with a trust boost for verified or approved items. The item and character budget reports how much was omitted.
- **Graph edges:** every edge has a `source_ref`, a `confidence` and a `provenance` of `verified` or `inferred`. Model hypotheses only produce inferred edges.

## Security boundaries

- **No shell or raw network for workers.** The capability matrix shows `subprocess`, `local_mutation`, `active_security` and `credential_use` as disabled for workflows, with reasons.
- **Cloud egress fails closed.** It requires consent, redaction, a size bound and a digest-matched approval.
- **Research fetches are tightly bounded.** They allow HTTPS on port 443 only, and only to public addresses. The validated IP is pinned against DNS rebinding, and each redirect (at most 3) is revalidated. Content is limited to 2 MB, text-like types only, and returned as untrusted text with an instruction-likeness counter.
- **Tokens never reach the WebView.** It only learns whether a key is stored.

## Known limitations

- Worker time limits are cooperative.
- Linux credentials use the freedesktop Secret Service (GNOME Keyring, KWallet) and survive restarts and reboots. When no Secret Service is running or it is locked, credential operations fail closed with recovery guidance; keys are never stored in plaintext.
- PDF ingestion, multi-user collaboration, a local automation API, signed workflow reports and model-generated orchestrator plans are not implemented.

See the audit for the full list.
