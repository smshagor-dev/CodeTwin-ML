-- No raw scanner output, project paths, credentials or arbitrary tool arguments stored.
CREATE TABLE native_worker_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'running'
    CHECK(status IN ('running','success','failed','interrupted')),
  image_digest TEXT,
  report_sha256 TEXT CHECK(report_sha256 IS NULL OR length(report_sha256)=64),
  vulnerability_count INTEGER CHECK(vulnerability_count IS NULL OR vulnerability_count>=0),
  misconfiguration_count INTEGER CHECK(misconfiguration_count IS NULL OR misconfiguration_count>=0),
  error_code TEXT,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT
);
CREATE INDEX native_worker_audit_run ON native_worker_audit(run_id,id DESC);
