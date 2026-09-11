ALTER TABLE findings ADD COLUMN analyzer_key TEXT;
ALTER TABLE findings ADD COLUMN last_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN resolved_at TEXT;

CREATE INDEX idx_findings_project_analyzer_status
  ON findings(project_id, analyzer_key, status, severity, last_seen DESC);

CREATE TABLE quality_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  rules_evaluated INTEGER NOT NULL DEFAULT 0,
  observations INTEGER NOT NULL DEFAULT 0,
  findings_opened INTEGER NOT NULL DEFAULT 0,
  findings_refreshed INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0,
  oversized_definitions INTEGER NOT NULL DEFAULT 0,
  deep_declarations INTEGER NOT NULL DEFAULT 0,
  high_fan_out_files INTEGER NOT NULL DEFAULT 0,
  dependency_cycles INTEGER NOT NULL DEFAULT 0
);
