-- Audited, approved task dependencies. Only pre-registered native specialists execute.
CREATE TABLE native_delegation_tasks (
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  role TEXT NOT NULL,
  tool TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','running','completed','failed','cancelled')),
  PRIMARY KEY(run_id,position),
  FOREIGN KEY(run_id,position) REFERENCES native_agent_steps(run_id,position)
);
CREATE TABLE native_delegation_dependencies (
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  requires_position INTEGER NOT NULL,
  PRIMARY KEY(run_id,position,requires_position),
  FOREIGN KEY(run_id,position) REFERENCES native_delegation_tasks(run_id,position),
  FOREIGN KEY(run_id,requires_position) REFERENCES native_delegation_tasks(run_id,position),
  CHECK(requires_position < position)
);
CREATE INDEX native_delegation_by_run ON native_delegation_tasks(run_id,status);
