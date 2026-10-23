-- Evidence-indexed, project-isolated memory of specialist review outcomes.
-- Never copy source snippets, discovered secrets, or unverified LLM text here.
CREATE TABLE native_agent_memory (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    role TEXT NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed','failed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(run_id,position)
);
CREATE INDEX native_agent_memory_project_history
    ON native_agent_memory(project_id, created_at DESC, run_id);
