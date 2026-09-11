CREATE TABLE security_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  files_considered INTEGER NOT NULL DEFAULT 0,
  files_analyzed INTEGER NOT NULL DEFAULT 0,
  files_stale INTEGER NOT NULL DEFAULT 0,
  files_skipped INTEGER NOT NULL DEFAULT 0,
  observations INTEGER NOT NULL DEFAULT 0,
  findings_opened INTEGER NOT NULL DEFAULT 0,
  findings_refreshed INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0,
  hardcoded_credentials INTEGER NOT NULL DEFAULT 0,
  dynamic_execution INTEGER NOT NULL DEFAULT 0,
  weak_crypto INTEGER NOT NULL DEFAULT 0,
  unsafe_c_apis INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_security_runs_project_started
  ON analysis_runs(project_id, run_kind, started_at DESC)
  WHERE run_kind = 'security_analysis';
