-- Durable, dependency-aware workflow orchestration owned by the Rust
-- `task-orchestrator` crate. Timestamps are Unix epoch milliseconds so lease
-- expiry and retry backoff compare without text parsing. Model output never
-- writes these rows directly; every state change goes through the
-- deterministic transition table in Rust inside a transaction.
CREATE TABLE workflow_runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    goal TEXT NOT NULL CHECK(length(goal) BETWEEN 1 AND 4000),
    owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 120),
    state TEXT NOT NULL CHECK(state IN (
        'draft','planned','awaiting_approval','queued','running','paused',
        'validating','completed','failed','cancelled','blocked')),
    outcome TEXT CHECK(outcome IS NULL OR outcome IN (
        'verified','unverified','blocked','failed','cancelled')),
    reason_code TEXT CHECK(reason_code IS NULL OR length(reason_code) <= 64),
    plan_revision INTEGER NOT NULL DEFAULT 0 CHECK(plan_revision >= 0),
    plan_digest TEXT,
    approved_revision INTEGER,
    approved_capabilities_json TEXT NOT NULL DEFAULT '[]',
    replan_count INTEGER NOT NULL DEFAULT 0,
    max_replans INTEGER NOT NULL CHECK(max_replans BETWEEN 0 AND 10),
    max_parallel INTEGER NOT NULL CHECK(max_parallel BETWEEN 1 AND 8),
    max_runtime_ms INTEGER NOT NULL CHECK(max_runtime_ms BETWEEN 1000 AND 86400000),
    max_attempts_per_task INTEGER NOT NULL CHECK(max_attempts_per_task BETWEEN 1 AND 5),
    max_tasks INTEGER NOT NULL CHECK(max_tasks BETWEEN 1 AND 64),
    max_credits INTEGER NOT NULL CHECK(max_credits >= 0),
    credits_used INTEGER NOT NULL DEFAULT 0 CHECK(credits_used >= 0),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
    pause_requested INTEGER NOT NULL DEFAULT 0 CHECK(pause_requested IN (0,1)),
    cloud_mode TEXT NOT NULL DEFAULT 'offline' CHECK(cloud_mode IN ('offline','cloud_consented')),
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    started_ms INTEGER,
    finished_ms INTEGER
);
CREATE INDEX idx_workflow_runs_project ON workflow_runs(project_id, created_ms);
CREATE INDEX idx_workflow_runs_state ON workflow_runs(state);

CREATE TABLE workflow_tasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    plan_revision INTEGER NOT NULL,
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
    parent_task_id TEXT REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    delegation_depth INTEGER NOT NULL DEFAULT 0 CHECK(delegation_depth BETWEEN 0 AND 2),
    role TEXT NOT NULL CHECK(length(role) BETWEEN 1 AND 64),
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
    input_json TEXT NOT NULL CHECK(length(input_json) <= 16384),
    success_criteria_json TEXT NOT NULL CHECK(length(success_criteria_json) <= 4096),
    side_effect TEXT NOT NULL CHECK(side_effect IN ('read_only','local_mutation','external')),
    capabilities_json TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK(length(scope_digest) = 64),
    resource_key TEXT,
    priority INTEGER NOT NULL DEFAULT 0 CHECK(priority BETWEEN -100 AND 100),
    state TEXT NOT NULL CHECK(state IN (
        'draft','planned','awaiting_approval','queued','running','validating',
        'retry_wait','completed','failed','cancelled','blocked')),
    reason_code TEXT CHECK(reason_code IS NULL OR length(reason_code) <= 64),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 5),
    timeout_ms INTEGER NOT NULL CHECK(timeout_ms BETWEEN 100 AND 3600000),
    not_before_ms INTEGER,
    output_json TEXT CHECK(output_json IS NULL OR length(output_json) <= 262144),
    output_sha256 TEXT CHECK(output_sha256 IS NULL OR length(output_sha256) = 64),
    summary TEXT CHECK(summary IS NULL OR length(summary) <= 2000),
    evidence_class TEXT CHECK(evidence_class IS NULL OR evidence_class IN (
        'observation','hypothesis','recommendation','applied_change','validated_result')),
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    started_ms INTEGER,
    finished_ms INTEGER,
    -- A replan supersedes unfinished tasks and may reuse their keys in the new
    -- revision; completed work is carried forward instead of re-executed.
    -- Duplicate side effects are prevented separately by the revision
    -- independent tool-invocation idempotency key.
    UNIQUE(run_id, plan_revision, idempotency_key)
);
CREATE INDEX idx_workflow_tasks_run_state ON workflow_tasks(run_id, state, priority);

CREATE TABLE workflow_task_dependencies (
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    depends_on TEXT NOT NULL REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    PRIMARY KEY(task_id, depends_on),
    CHECK(task_id <> depends_on)
);
CREATE INDEX idx_workflow_deps_run ON workflow_task_dependencies(run_id);

CREATE TABLE workflow_task_attempts (
    task_id TEXT NOT NULL REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    attempt_no INTEGER NOT NULL CHECK(attempt_no >= 1),
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running','succeeded','failed','cancelled','abandoned')),
    error_category TEXT CHECK(error_category IS NULL OR error_category IN (
        'transient','permanent','policy','timeout','cancelled','validation','budget','crash')),
    error_detail TEXT CHECK(error_detail IS NULL OR length(error_detail) <= 500),
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER,
    PRIMARY KEY(task_id, attempt_no)
);

-- At most one live lease per task. A lease belongs to one process instance;
-- leases from another instance or past expiry are stale and are reconciled.
CREATE TABLE workflow_worker_leases (
    task_id TEXT PRIMARY KEY REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    instance_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL,
    acquired_ms INTEGER NOT NULL,
    heartbeat_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL
);

-- Append-only event log; `seq` is the durable replay cursor for the UI.
CREATE TABLE workflow_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    task_id TEXT,
    kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
    detail_json TEXT NOT NULL CHECK(length(detail_json) <= 4096),
    correlation_id TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE INDEX idx_workflow_events_run ON workflow_events(run_id, seq);

-- Every tool call requested by a worker, including denials. Arguments and
-- outputs are stored only as SHA-256 digests.
CREATE TABLE workflow_tool_invocations (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    attempt_no INTEGER NOT NULL,
    tool_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    side_effect TEXT NOT NULL CHECK(side_effect IN ('read_only','local_mutation','external')),
    idempotency_key TEXT NOT NULL UNIQUE,
    args_sha256 TEXT NOT NULL CHECK(length(args_sha256) = 64),
    status TEXT NOT NULL CHECK(status IN ('denied','started','succeeded','failed','uncertain')),
    decision_reason TEXT NOT NULL CHECK(length(decision_reason) <= 120),
    output_sha256 TEXT,
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER
);
CREATE INDEX idx_workflow_tools_task ON workflow_tool_invocations(task_id, attempt_no);

-- Approvals are bound to an exact scope digest, plan revision and expiry.
-- Only the operator-facing API can decide them; workers and models cannot.
CREATE TABLE workflow_approval_requests (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    task_id TEXT REFERENCES workflow_tasks(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('plan','task_capability')),
    capabilities_json TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK(length(scope_digest) = 64),
    plan_revision INTEGER NOT NULL,
    summary TEXT NOT NULL CHECK(length(summary) <= 2000),
    status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','expired','superseded')),
    requested_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL
);
CREATE INDEX idx_workflow_approvals_run ON workflow_approval_requests(run_id, status);

CREATE TABLE workflow_approval_decisions (
    request_id TEXT PRIMARY KEY REFERENCES workflow_approval_requests(id) ON DELETE CASCADE,
    decision TEXT NOT NULL CHECK(decision IN ('approve','reject')),
    decided_by TEXT NOT NULL CHECK(length(decided_by) BETWEEN 1 AND 120),
    scope_digest TEXT NOT NULL CHECK(length(scope_digest) = 64),
    note TEXT CHECK(note IS NULL OR length(note) <= 500),
    decided_ms INTEGER NOT NULL
);

-- Reproducible run reports; content-addressed and immutable once written.
CREATE TABLE workflow_run_reports (
    run_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    format TEXT NOT NULL CHECK(format IN ('markdown','json')),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    body TEXT NOT NULL CHECK(length(body) <= 1048576),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY(run_id, format, sha256)
);
