-- Native, scoped, approval-gated autonomous reviews.
CREATE TABLE native_agent_runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    objective TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned' CHECK(status IN (
        'planned','approved','running','completed','failed','cancelled','interrupted')),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
    max_files INTEGER NOT NULL CHECK(max_files BETWEEN 1 AND 2000),
    budget_seconds INTEGER NOT NULL CHECK(budget_seconds BETWEEN 1 AND 3600),
    assessment_id TEXT NOT NULL REFERENCES assessment_jobs(id),
    message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX idx_native_agent_runs_project ON native_agent_runs(project_id, created_at);
CREATE UNIQUE INDEX idx_native_agents_running
ON native_agent_runs(project_id)
WHERE status IN ('approved','running');

CREATE TABLE native_agent_steps (
    run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    role TEXT NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','running','completed','failed','skipped','cancelled','interrupted')),
    result_json TEXT,
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY(run_id,position)
);
