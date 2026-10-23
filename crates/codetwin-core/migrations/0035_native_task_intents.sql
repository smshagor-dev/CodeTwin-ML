-- Per-review model-proposed tasks remain immutable after manual approval.
CREATE TABLE native_task_intents (
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  role TEXT NOT NULL,
  objective TEXT NOT NULL CHECK(length(objective) BETWEEN 1 AND 300),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(run_id,position),
  FOREIGN KEY(run_id,position) REFERENCES native_delegation_tasks(run_id,position)
);
