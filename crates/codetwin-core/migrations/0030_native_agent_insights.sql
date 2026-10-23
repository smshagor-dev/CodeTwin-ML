-- Optional model interpretations are not validated security findings.
CREATE TABLE native_agent_insights (
    run_id TEXT PRIMARY KEY REFERENCES native_agent_runs(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
