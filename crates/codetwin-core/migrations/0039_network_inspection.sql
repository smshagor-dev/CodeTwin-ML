-- Durable evidence for explicitly authorized bounded network service inspections.
-- Observations contain only destination IP, TCP port, state and timing.
CREATE TABLE IF NOT EXISTS network_inspection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    scope_sha256 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
      CHECK (status IN ('running','completed','failed','interrupted')),
    ports_requested INTEGER NOT NULL CHECK (ports_requested BETWEEN 1 AND 32),
    ports_tested INTEGER NOT NULL DEFAULT 0,
    result_json TEXT,
    result_sha256 TEXT,
    failure_code TEXT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    CHECK (length(scope_sha256) = 64),
    CHECK (result_sha256 IS NULL OR length(result_sha256) = 64)
);
CREATE INDEX IF NOT EXISTS idx_network_inspection_recent
  ON network_inspection_runs (id DESC);
