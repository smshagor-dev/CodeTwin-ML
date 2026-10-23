# CodeTwin native review agents

CodeTwin's local agents are written entirely in Rust. Their workflow supervisor lives in
\`crates/codetwin-core/src/native_agents.rs\` and its desktop commands live in
\`apps/desktop/src-tauri/src/native_agent_commands.rs\`.

## Current execution model

1. Select an **indexed local project**.
2. Create a review plan. The source assessment planner binds the source index, verified file hashes, and a file and time budget.
3. Review the registered roles (Project Recon and Source Auditor are mandatory; other passive specialists can be selected individually), then explicitly approve the resulting plan.
4. Run the approved review. The supervisor executes a deterministic chain of existing **passive** services: project metadata, source AppSec and quality, secrets scanning, QA evidence discovery, database review and runtime configuration review.
5. Inspect each role's persisted outcome, any incomplete coverage, and the overall status. Copy an evidence-backed Markdown report.

State is persisted in \`native_agent_runs\` and \`native_agent_steps\` in the existing SQLite database.
A review with an unfinished, failed or cancelled analyzer is not marked completed. Interrupted work is
marked interrupted at next app startup, not automatically replayed.

## Controls and limits

- Nothing executes just by importing a project or typing an objective.
- A review must be approved by a separate action.
- No agent tools can run generated shell commands, scripts, exploits or active web probes.
- All role tools are fixed native service calls. Optional roles must match a strict allowlist; duplicate and unknown roles are rejected. LLM text cannot enlarge tool permissions.
- Existing source assessment controls check hashes and reject stale/over-budget source trees.
- Each step checks for cancellation and elapsed time at analyzer boundaries.
- Concurrent index, semantic, source security and quality work is blocked through existing desktop reservations.
- Current time limits are **cooperative at boundaries**. They do not forcibly terminate an individual long-running analyzer call.
- Passive analyzer execution stays on-device. An optional, explicitly consented model-interpretation action can send up to 9,000 characters of the report to a configured endpoint. It is not part of the automatic tool chain.
- Run status records that tools finished; it is not a security assurance.

## What is not implemented

This is a native **deterministic supervisor**, not yet a fully autonomous LLM-driven cybersecurity system. It does not yet implement:
- dynamic LLM planning, multi-model routing or arbitrary agent-driven tool calls;
- embedded/vector memory, retrieval augmentation or a knowledge graph;
- sandboxed arbitrary security-tool plugins, Docker worker execution or remote task dispatch;
- automatic multi-agent model handoffs, self-healing loops or token streaming;
- autonomous network penetration testing or exploit execution.

These are separate features requiring threat modeling, explicit scoped approvals, tool sandboxing and integration tests before being enabled. Do not label the current implementation as providing those features.

## Test and review

Run the existing Rust formatter, Clippy and test suite, and the desktop frontend typecheck.
The unit test verifies that an indexed project and user approval are required, and that cancellation is terminal.
An integration test with source-control and real project fixtures is still needed to validate all six analyzer outputs and report behavior.

## Optional model interpretation

Set `CODETWIN_MODEL_ENDPOINT` to the complete OpenAI-compatible `/chat/completions` endpoint,
`CODETWIN_MODEL_ID` to a model accepted by the backend, and (for remote endpoints) `CODETWIN_MODEL_TOKEN`.
Remote requests require HTTPS; local loopback HTTP is allowed. Credentials are read by Rust and are
not exposed to the WebView. Model output is stored separately in the SQLite
`native_agent_insights` table as **unverified interpretation**, never as a scan verdict.
A completed or failed review and explicit per-request user consent are prerequisites. The optional
model cannot call tools, change scope, patch code or turn incomplete evidence into passing tests.

## Project review memory

Completed and failed specialist-role outcomes are indexed in `native_agent_memory` on a per-project
basis. Each entry retains only the specialist role, registered tool ID, terminal step state, timestamp,
original review ID and position. Review evidence must be opened from the original saved run.
Source file contents, secret discoveries, raw scan output and optional LLM interpretations are
**not** copied into memory. The memory is strictly read-only context for the UI and does not
automatically authorize new tests or alter plans.

The Agents page provides project-scoped filtering and an explicit **Clear project memory** action.
This erases only the derived memory rows, not the original review history. Memory storage is bounded
to the latest 500 role outcomes per project, and retrieval is capped at 50 rows. Query escaping
prevents LIKE wildcards from broadening user-entered search terms.

## AI-assisted review planning

CodeTwin can ask the configured OpenAI-compatible model to suggest **only** a subset of six
registered passive specialist roles. The request contains the user-authored objective, indexed
file count, indexed symbol count, language count, at most twelve earlier role/status
pairs from this project's review memory, and fixed available-role identifiers. It excludes
local file paths, source code, credentials, project IDs, findings, prior scan outputs,
previous review IDs and timestamps.

The user must explicitly opt in each time. The Rust adapter limits the model request duration,
response size and output tokens, rejects redirects, and validates a strict JSON schema.
Unknown/duplicate role identifiers, omitted mandatory `scout`/`source` roles, unexpected JSON
fields and oversized explanations are rejected. A malformed model proposal gets at most one
additional read-only correction attempt using the same privacy-reduced input. No speculative
tool call is performed, and further malformed output is rejected. The application always restores the audited
execution order instead of trusting any order proposed by the model.

The UI shows the proposed specialists and explanation for review. Accepting a suggestion only
updates the role selection. **Prepare review**, **Approve plan** and **Run approved review** remain
distinct, manual actions. The objective or project changing invalidates the displayed suggestion.
The model does not receive tool schemas and cannot execute commands, add privileges or widen scope.

Without a configured model, the existing manual role selector and deterministic local review
workflow continue to function without inference or network access.

## Specialist handoff chain and supervisor validation

Native reviews now persist source-to-destination specialist handoffs in the SQLite
`native_agent_handoffs` table (migration 32). After each completed passive specialist tool:

- The supervisor binds the next role to the already-approved ordered plan.
- Only the prior role name, destination role, step coordinates, timestamp and SHA-256
  digest of the stored evidence are copied into the handoff. Raw tool output is not
  duplicated or sent to external providers.
- Immediately before the next specialist runs, Rust validates that the previous
  tool completed, that the handoff matches both approved roles, and that the prior
  evidence still hashes to the stored digest.
- A missing or changed handoff fails the run closed. A completed chain receives a
  deterministic final verification pass before the run can remain `completed`.
- The Agents interface displays the persisted handoff chain and verification issues.

These are **structured, auditable native specialist handoffs**, not yet autonomous
conversational delegation or model-controlled execution. The registered passive
CodeTwin analyzers are the only tools these specialists can invoke.
No model is allowed to add tools, run shell commands, bypass authorization, or
expand the scan scope. All operations are local until a user explicitly consents to
the separate optional model features.

## Dependency-gated delegation

Each approved review has a SQLite task DAG in `native_delegation_tasks` and
`native_delegation_dependencies`. The graph is constructed before approval using the
user-selected roles. Project Recon precedes Source Auditor, and optional passive
specialists depend on the source review. The Rust supervisor checks the fixed role,
pending status and completed prerequisites before dispatch, and checks task completion
during final verification. Arbitrary model-proposed command execution is not supported;
the current executor remains sequential, while the dependencies are explicit and
persisted. Free-form recursive model-to-model delegation is not implemented.

## Local knowledge vectors and provenance graph

`native_knowledge_nodes` stores project-isolated role/tool/status nodes and
64-dimensional deterministic, normalized hashed-token vectors. Similarity is
cosine on those vectors; **this is lexical recall, not neural semantic search**.
Only provenance from terminal review steps is indexed; no source text, raw scan
output, secrets or AI response is embedded. Storage is bounded to 500 records
per project. `native_knowledge_edges` stores previously verified specialist
handoff relations. Users can query or explicitly clear this derived knowledge
without deleting the original review history. A neural ONNX embeddings service,
knowledge-graph reasoning and cross-project transfer remain separate future work.

## Optional isolated offline worker

The desktop exposes a separate, explicitly approved offline Trivy filesystem scan
for a local indexed project in an already-approved review. This does **not** happen
automatically or through an AI prompt. This worker is opt-in and **disabled**
unless both environment settings are supplied:

- `CODETWIN_DOCKER_PATH`: absolute path to a trusted Docker CLI executable.
- `CODETWIN_TRIVY_IMAGE`: existing local image reference pinned as
  `repository@sha256:<64 hex digits>`. It is never pulled during a scan.
- `CODETWIN_TRIVY_DB_DIR`: absolute path to an already-downloaded Trivy
  vulnerability database directory containing `trivy.db` and `metadata.json`.
  Download the DB explicitly beforehand, outside the worker (the optional
  GitHub Actions sandbox workflow does this setup separately).

CodeTwin mounts the vulnerability database **read-only** at
`/tmp/trivy/db` under the container's writable in-memory `/tmp` filesystem,
while the scanner uses `--cache-dir /tmp/trivy`, `--skip-db-update`,
`--skip-java-db-update`, `--skip-check-update`, and `--offline-scan`.
Only the vulnerability scanner is enabled in this offline worker; secrets
and misconfiguration checks are separate CodeTwin analyzers. The host
project directory remains read-only.

The container runs without network access, Docker socket mounts, writable project
access, elevated capabilities or shell command delegation. Arguments, mount points,
read-only root filesystem and isolation settings are fixed in Rust. The container
has limits for CPU, memory, process count and duration; untrusted output is
parsed to aggregated finding counts and a SHA-256 report digest. The original
report is temporary and not retained in the app database. Mount roots containing
Docker option separators are rejected. On Unix, the worker uses the non-root host
identity so a private temporary output directory remains writable.

This is an initial **offline scanner integration**, not a generic container tool
marketplace or a guarantee against a compromised Docker daemon or malicious scanner
image. Local Docker availability, a pinned scanner image, a preloaded offline
vulnerability database, supported Docker host platform and actual end-to-end
execution must still be tested. A timeout kills the Docker client and attempts forced removal of the named
container with a separate five-second cleanup deadline. The resulting status
explicitly says when removal cannot be confirmed. Recovery after a daemon crash
is not independently verified.

Do not enable network-enabled pentest workers or arbitrary tool execution without
separate target authorization, network egress enforcement, security review and
real isolated integration tests.

## Model-decomposed review task plans

The model can now return a structured task proposal with per-specialist objectives
and named dependencies. Rust accepts only the six registered passive roles in
their audited order and validates that Project Recon is initial, Source Auditor
depends on it, and all optional roles require source review. Unexpected JSON
fields, unapproved tools, cycles, duplicate roles, long explanations and
forward references are rejected. Users inspect the proposed DAG in the UI.

Accepted tasks are bound to a fresh, unapproved review and persisted in
`native_task_intents` and `native_delegation_dependencies`. The default
review still works without an AI model. Approval and starting the review are
separate actions. A `native_task_schedule` API calculates dependency-ready
batches capped at two specialists; **the native analyzer runtime still executes
serially** because current shared SQLite analyzer state and linear handoffs
have not been proven concurrency-safe.

## Optional genuine neural vectors

Configure `CODETWIN_EMBEDDING_ENDPOINT` with an OpenAI-compatible `/embeddings`
URL, `CODETWIN_EMBEDDING_MODEL`, and `CODETWIN_EMBEDDING_TOKEN` for remote
providers. Remote endpoints must use HTTPS. Only explicit, consented actions
send short role/tool/status strings or a user-entered query to the configured
embedding model. Response count, index, dimension (16–3072), finiteness and
norm are validated. Vectors are isolated by project and model ID and stored
in `native_neural_embeddings`. Neural cosine search is separate from the
local hashed lexical fallback. No model, inference provider or live result
is silently simulated. Neural recall has not been live-validated with a
connected provider.

## Graph reasoning

`native_graph_reasoning.rs` can trace bounded predecessors, downstream
dependents, shortest stored provenance paths and disconnected nodes within a
single project's verified handoff graph. The graph view shows count and
dependency explanations. These are **provenance relationships**, not a
claim that vulnerabilities were proved, exploited, or eliminated.

## Durable isolated-worker audit

`native_worker_audit` records worker attempts, aggregated counts,
status, report digest and timestamps. It does not retain raw scanner
data, credentials, arbitrary arguments or source paths. An interrupted
application marks unfinished audit entries accordingly after restart.
An audit receipt is independent of the review's analyzer findings.

Worker audit start and successful finish now use single SQLite statements that
require the parent review to remain approved and uncancelled. A successful
receipt is accepted only for the **same review ID** as its audit entry. When
approval is revoked before result persistence, the audit is finalized as
failed without the scanner's image digest or finding counts. The desktop
receives an error instead of a false successful result.

Failed attempts retain fixed privacy-reduced error codes: `worker_failed`,
`worker_cancelled`, `worker_cleanup_unconfirmed` and
`worker_cancelled_cleanup_unconfirmed`. The last two are emitted only for
explicit, recognized Docker cleanup failures, not arbitrary raw error text.
They mean that container removal was **not independently confirmed** and
require manual inspection of the Docker host. Audit records are not digitally
signed attestations of a machine or daemon state.


## Real sandbox test harness

`crates/codetwin-core/tests/native_real_sandbox.rs` invokes a real
Docker daemon and validates the offline scanner's report digest and persisted
audit, **only when** `CODETWIN_TEST_REAL_SANDBOX=1` is explicitly set.
Provide `CODETWIN_DOCKER_PATH` and `CODETWIN_TRIVY_IMAGE` as described
above. The manually triggered workflow `.github/workflows/offline-sandbox-smoke.yml`
accepts a maintainer-approved digest-pinned image with its vulnerability DB
already included, preloads it outside the sandbox, then runs the real
network-disabled integration test. Merely compiling this harness does not
mean a real sandbox test passed.

## Dependency-ready scheduling

The Rust delegation service exposes `ready_batch`, which returns up to two pending specialists whose approved predecessor tasks completed. This is a **dispatch candidate scheduler** and never invokes tools. Execution still happens sequentially in `NativeAgents::run_steps`; concurrent execution needs separate SQLite connections, re-entrant analyzer safety, cancellation propagation, and deterministic join/verification before it can be enabled. The new unit test covers mandatory prerequisites and bounded independent candidates.

## Actual concurrent passive specialists

After the mandatory Project Recon and hash-bound Source Auditor complete, independent
optional passive specialists may run concurrently in bounded batches of **two** Rust
threads. Each worker opens its own SQLite WAL connection; the supervisor joins all
threads and writes role outcomes and SHA-256 evidence handoffs in the original
approved order. Workers are never detached. Cancellation and the overall time
budget are checked before/after each batch and before committing the serial role
results; individual analyzer APIs still enforce their own service constraints.
The in-memory database used by unit tests cannot be shared across connections
and retains the sequential fallback. If an approved model-generated task plan
introduces optional-to-optional dependencies, it also falls back to sequential
execution; prerequisites are never speculatively bypassed.

A file-backed integration fixture covers a review containing two optional
specialists, the final handoff chain and persisted delegation status. This is
bounded concurrency among **existing passive project analyzers**, not an
unrestricted external penetration-testing agent.

## Neural embedding provider connectivity

Set `CODETWIN_EMBEDDING_ENDPOINT` to the complete OpenAI-compatible
`/embeddings` URL, `CODETWIN_EMBEDDING_MODEL` to the provider's embedding
model ID and (for remote HTTPS) `CODETWIN_EMBEDDING_TOKEN`.
The CodeTwin Agents page now has **Test embedding connection**. It sends one fixed
non-sensitive sample phrase and checks real returned vector shape/normalization,
reporting model, dimensionality and latency. It does not access source files,
findings or existing chat content.

The core test suite includes a local HTTP protocol fixture that verifies the
request JSON and returned numeric vectors without external credentials.
To explicitly validate a live model with your configured provider:

```bash
CODETWIN_TEST_REAL_EMBEDDINGS=1 cargo test -p codetwin-core --test native_embedding_provider -- --nocapture
```

This live test is opt-in; without that environment variable it skips.
`NeuralMemory::index_run` and `NeuralMemory::search` remain
separate consent-gated actions, and the ready-state check only verifies
configuration, not live model availability. No live provider response is
claimed until the probe or opt-in test actually succeeds.

## Local pretrained neural embedding server (no remote API key)

CodeTwin now includes an optional OpenAI-compatible HTTP embeddings server
implemented in \`services/ml/codetwin_ml/embedding_api.py\`. It uses
\`sentence-transformers\` to infer **actual pretrained neural vectors** from
a model directory already downloaded on the user's computer. No pretrained
weights ship with the app. The server refuses remote downloads and custom
model code (\`local_files_only=True\`, \`trust_remote_code=False\`), listens
on \`127.0.0.1\` only, and uses bounded requests.

Install the optional dependencies into your Python virtual environment:

\`\`\`bash
python -m pip install -r services/ml/requirements-embeddings.txt
\`\`\`

Start CodeTwin's provider with a trusted, already-downloaded local
SentenceTransformer model directory:

\`\`\`bash
PYTHONPATH=services/ml python -m codetwin_ml.embedding_api \
  --model-dir /path/to/local/sentence-transformer --port 8765
\`\`\`

Windows PowerShell:

\`\`\`powershell
$env:PYTHONPATH = "services/ml"
python -m codetwin_ml.embedding_api --model-dir "D:\models\my-sentence-transformer" --port 8765
\`\`\`

Point the desktop at this self-hosted model:

\`\`\`text
CODETWIN_EMBEDDING_ENDPOINT=http://127.0.0.1:8765/v1/embeddings
CODETWIN_EMBEDDING_MODEL=codetwin-local-embedding
\`\`\`

Use the Agents page's **Test embedding connection** action, then explicitly
consent to indexing/querying the provenance-only memory. A no-dependency
HTTP contract fixture (\`test_local_embedding_api.py\`) runs in the normal
Python CI; actual pretrained weights and an accelerated runtime remain
optional and must be supplied by the operator. The server accepts only
bounded batches of role/tool/status-style short text; avoid exposing the
loopback port publicly. External HTTPS embedding providers continue to work
through the same client API.

## Offline report handling and cleanup safeguards

The worker rejects reports larger than 2 MB, reports that are symlinks or other
nonregular files, invalid JSON, malformed finding arrays and more than 2,000
individual result groups. No group is silently truncated before computing the
aggregate counts and SHA-256 report digest. The scanner image remains pinned,
network-disabled and bound to an explicit approved local review.

If Docker reports an unsuccessful run, CodeTwin attempts bounded cleanup of the
uniquely named container. An unresponsive daemon cannot be certified clean: in
that case the failure tells the operator that container removal is unconfirmed.
The unit suite covers report integrity, invalid structures, counts, symlinks
(on Unix) and cleanup command exit status. A real Docker and offline Trivy DB
integration check remains separately opt-in, because the default CI does not
supply a privileged daemon or pinned scanner DB. Never describe these unit
checks as a successful physical sandbox integration run.

## Revoking worker authorization

The existing native review cancellation action now also revokes permission for
a separately approved Docker scanner using the same review. A worker checks
that its parent review is still approved and has no cancellation request
immediately before launch, on each supervisor polling interval while the
container runs, and after exit before reading its report. Revocation kills
its Docker CLI process, requests bounded forced removal of its named container
and returns failure rather than saving a successful scan receipt. If Docker
cannot confirm removal, the operator receives an explicit unconfirmed-cleanup
status. Scanner audit entries use the constant `worker_cancelled` code after
review revocation; neither a raw command-line error nor a path is stored.

This is application-controlled cancellation while the desktop process runs;
it is not independent proof of cleanup after app termination or daemon crash.

## Offline subprocess contract integration tests

The normal Linux Rust unit suite now launches a **real, test-controlled local
subprocess**, using the same guarded launch, timeout, approval polling, argument
construction, JSON report parsing and SQLite audit path as the production
offline scanner. The fixture validates the generated Docker CLI command
includes `--network none`, a read-only root and no image pull, and it
emits a fixed JSON report into the expected private output path. A second
file-backed SQLite WAL fixture revokes review approval while the child is
still running, exercises process termination and verifies the durable
`worker_cancelled` audit without persisted scan findings. These fixtures
use only a locally written shell script and localhost-free filesystem
operations. They do not require Docker or any external target.

**Important:** This is process-contract integration coverage, not proof of
Docker daemon or Trivy correctness. The separate, explicitly authorized
`native_real_sandbox` test remains the physical isolation and vulnerability
database integration gate. Do not describe a green regular CI run as a
successful real Docker/Trivy verification.
