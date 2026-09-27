-- Secret scanning across git history. Findings reuse the shared findings/finding_evidence
-- tables with analyzer_key 'secret_history'; one finding per distinct leaked value.

CREATE TABLE secret_history_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  coverage_complete INTEGER NOT NULL CHECK(coverage_complete IN (0,1)),
  commits_scanned INTEGER NOT NULL DEFAULT 0,
  commit_limit_reached INTEGER NOT NULL DEFAULT 0 CHECK(commit_limit_reached IN (0,1)),
  shallow_clone INTEGER NOT NULL DEFAULT 0 CHECK(shallow_clone IN (0,1)),
  file_changes_scanned INTEGER NOT NULL DEFAULT 0,
  file_changes_skipped INTEGER NOT NULL DEFAULT 0,
  observations INTEGER NOT NULL DEFAULT 0,
  still_in_working_tree INTEGER NOT NULL DEFAULT 0,
  findings_opened INTEGER NOT NULL DEFAULT 0,
  findings_refreshed INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0
);
