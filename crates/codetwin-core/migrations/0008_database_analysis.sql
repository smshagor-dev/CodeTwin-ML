CREATE TABLE database_artifacts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  relative_path TEXT NOT NULL,
  path_identity TEXT NOT NULL,
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('sql_migration','sql_schema','prisma_schema')),
  framework TEXT,
  content_hash TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  last_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  UNIQUE(project_id, path_identity)
);

CREATE INDEX idx_database_artifacts_project_active
  ON database_artifacts(project_id, is_active, artifact_kind, relative_path);

CREATE TABLE database_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  coverage_complete INTEGER NOT NULL DEFAULT 0 CHECK (coverage_complete IN (0, 1)),
  artifacts_considered INTEGER NOT NULL DEFAULT 0,
  artifacts_analyzed INTEGER NOT NULL DEFAULT 0,
  artifacts_skipped INTEGER NOT NULL DEFAULT 0,
  sql_files INTEGER NOT NULL DEFAULT 0,
  prisma_schemas INTEGER NOT NULL DEFAULT 0,
  observations INTEGER NOT NULL DEFAULT 0,
  findings_opened INTEGER NOT NULL DEFAULT 0,
  findings_refreshed INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0,
  destructive_statements INTEGER NOT NULL DEFAULT 0,
  unscoped_writes INTEGER NOT NULL DEFAULT 0,
  foreign_keys_disabled INTEGER NOT NULL DEFAULT 0,
  literal_datasource_urls INTEGER NOT NULL DEFAULT 0
);
