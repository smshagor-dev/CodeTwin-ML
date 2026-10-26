# Bounded autonomous planning boundary

`scripts/bounded_task_planner.py` provides a deterministic, non-executing
task DAG preflight for CodeTwin. It accepts a nonempty project identity and up
to 32 tasks, validates task IDs, descriptions, dependencies and a closed
capability allowlist, rejects cycles, and emits stable parallel-ready levels.

Passive capabilities: `source_index`, `static_analysis`, `qa_discovery`,
`evidence_review`. Active capabilities: `web_security_test`,
`repair_apply`, `qa_execute`. Active capability preflight requires the
corresponding approval mapping entry to be the boolean `True`.

**Security boundary:** This is not an executor, approval authority, LLM,
neural planner, persistent agent memory, or sandbox. Approval mapping inputs
are untrusted assertions; the actual executor MUST independently revalidate
project identity, explicit scoped authorization, allowed targets, immutable
plans, resource bounds, evidence and cancellation before every tool call.
No network access, code execution, SQLite writes or filesystem mutations are
performed by the planner. It does not widen web-security testing scope.

Run regression tests from the repository root with:
`python -m unittest scripts.tests.test_bounded_task_planner`.

Remaining integration work includes a Rust-side orchestration API, durable
SQLite execution records, isolated specialist workers, UI lifecycle, and
end-to-end authorization and recovery tests. Do not claim autonomous
execution or AGI capability from this planner alone.
