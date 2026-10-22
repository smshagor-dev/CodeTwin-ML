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
- Imported source stays on-device; no new AI provider calls or external server is configured by this implementation.
- Run status records that tools finished; it is not a security assurance.

## What is not implemented

This is a native **deterministic supervisor**, not yet a fully autonomous LLM-driven cybersecurity system. It does not yet implement:
- dynamic LLM planning or model/provider configuration;
- embedded/vector memory, retrieval augmentation or a knowledge graph;
- sandboxed arbitrary security-tool plugins, Docker worker execution or remote task dispatch;
- a language-model critic/mentor, self-healing loops or streaming token generation;
- autonomous network penetration testing or exploit execution.

These are separate features requiring threat modeling, explicit scoped approvals, tool sandboxing and integration tests before being enabled. Do not label the current implementation as providing those features.

## Test and review

Run the existing Rust formatter, Clippy and test suite, and the desktop frontend typecheck.
The unit test verifies that an indexed project and user approval are required, and that cancellation is terminal.
An integration test with source-control and real project fixtures is still needed to validate all six analyzer outputs and report behavior.
