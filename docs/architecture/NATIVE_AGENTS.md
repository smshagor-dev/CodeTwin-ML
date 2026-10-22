# CodeTwin native review agents

CodeTwin's local agents are written entirely in Rust. Their workflow supervisor lives in
\`crates/codetwin-core/src/native_agents.rs\` and its desktop commands live in
\`apps/desktop/src-tauri/src/native_agent_commands.rs\`.

## Current execution model

1. Select an **indexed local project**.
2. Create a review plan. The source assessment planner binds the source index, verified file hashes, and a file and time budget.
3. Inspect the six predeclared roles and approve the review.
4. Run the approved review. The supervisor executes a deterministic chain of existing **passive** services: project metadata, source AppSec and quality, secrets scanning, QA evidence discovery, database review and runtime configuration review.
5. Inspect each role's persisted outcome, any incomplete coverage, and the overall status. Copy an evidence-backed Markdown report.

State is persisted in \`native_agent_runs\` and \`native_agent_steps\` in the existing SQLite database.
A review with an unfinished, failed or cancelled analyzer is not marked completed. Interrupted work is
marked interrupted at next app startup, not automatically replayed.

## Controls and limits

- Nothing executes just by importing a project or typing an objective.
- A review must be approved by a separate action.
- No agent tools can run generated shell commands, scripts, exploits or active web probes.
- All role tools are fixed native service calls. LLM text cannot enlarge tool permissions.
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
