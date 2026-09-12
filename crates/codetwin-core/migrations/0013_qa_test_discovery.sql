CREATE TABLE qa_test_artifacts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  relative_path TEXT NOT NULL,
  path_identity TEXT NOT NULL,
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('test_file','config_file')),
  framework TEXT NOT NULL,
  evidence_kind TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  last_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  UNIQUE(project_id, path_identity, framework, evidence_kind)
);

CREATE INDEX idx_qa_test_artifacts_project_active
  ON qa_test_artifacts(project_id, is_active, framework, artifact_kind, relative_path);

CREATE TABLE qa_discovery_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  coverage_complete INTEGER NOT NULL DEFAULT 0 CHECK (coverage_complete IN (0, 1)),
  candidate_files INTEGER NOT NULL DEFAULT 0,
  artifacts_discovered INTEGER NOT NULL DEFAULT 0,
  artifacts_skipped INTEGER NOT NULL DEFAULT 0,
  test_files INTEGER NOT NULL DEFAULT 0,
  config_files INTEGER NOT NULL DEFAULT 0,
  framework_count INTEGER NOT NULL DEFAULT 0
);
