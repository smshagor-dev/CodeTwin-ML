CREATE TABLE repair_application_runs (
  id TEXT PRIMARY KEY,
  repair_id TEXT NOT NULL REFERENCES repair_plans(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL
    CHECK(status IN ('running','applied','rolled_back','failed','rollback_failed')),
  changes_total INTEGER NOT NULL DEFAULT 0,
  changes_applied INTEGER NOT NULL DEFAULT 0,
  rollback_performed INTEGER NOT NULL DEFAULT 0 CHECK(rollback_performed IN (0,1)),
  backup_dir_name TEXT NOT NULL,
  error_message TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
);
CREATE INDEX idx_repair_application_runs_repair
  ON repair_application_runs(repair_id, created_at DESC);

CREATE TABLE repair_application_items (
  run_id TEXT NOT NULL REFERENCES repair_application_runs(id) ON DELETE CASCADE,
  change_id TEXT NOT NULL REFERENCES repair_changes(id) ON DELETE CASCADE,
  relative_path TEXT NOT NULL,
  base_content_hash TEXT NOT NULL,
  proposed_content_hash TEXT NOT NULL,
  backup_content_hash TEXT NOT NULL,
  backup_file_name TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK(state IN ('pending','applied','rolled_back')),
  PRIMARY KEY(run_id, change_id),
  UNIQUE(run_id, relative_path),
  UNIQUE(run_id, backup_file_name)
);
CREATE INDEX idx_repair_application_items_run
  ON repair_application_items(run_id, relative_path);
