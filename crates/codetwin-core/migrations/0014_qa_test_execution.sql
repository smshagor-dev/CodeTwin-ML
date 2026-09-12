CREATE TABLE qa_execution_plans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  discovery_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  runner_kind TEXT NOT NULL CHECK(runner_kind IN ('pytest','rust_cargo_test','go_test','vitest','jest','php_unit')),
  status TEXT NOT NULL CHECK(status IN ('blocked','planned','approved')),
  request_json TEXT NOT NULL,
  toolchain_json TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  command_json TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  blocking_reasons_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approved_at TEXT,
  superseded_at TEXT
);
CREATE INDEX idx_qa_execution_plans_project_status
  ON qa_execution_plans(project_id, status, created_at DESC);
CREATE INDEX idx_qa_execution_plans_discovery_run
  ON qa_execution_plans(discovery_run_id, created_at DESC);

CREATE TABLE qa_execution_runs (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES qa_execution_plans(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','timed_out','cancelled','infrastructure_error')),
  started_at TEXT,
  finished_at TEXT,
  duration_ms INTEGER,
  exit_code INTEGER,
  parser_completed INTEGER NOT NULL DEFAULT 0 CHECK(parser_completed IN (0,1)),
  tests_passed INTEGER CHECK(tests_passed IS NULL OR tests_passed IN (0,1)),
  stdout_excerpt TEXT NOT NULL DEFAULT '',
  stderr_excerpt TEXT NOT NULL DEFAULT '',
  stdout_original_bytes INTEGER NOT NULL DEFAULT 0,
  stderr_original_bytes INTEGER NOT NULL DEFAULT 0,
  stdout_truncated INTEGER NOT NULL DEFAULT 0 CHECK(stdout_truncated IN (0,1)),
  stderr_truncated INTEGER NOT NULL DEFAULT 0 CHECK(stderr_truncated IN (0,1)),
  result_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_qa_execution_runs_project_created
  ON qa_execution_runs(project_id, created_at DESC);
CREATE INDEX idx_qa_execution_runs_plan_created
  ON qa_execution_runs(plan_id, created_at DESC);
