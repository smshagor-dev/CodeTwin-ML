CREATE TABLE websites (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  normalized_url TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'not_checked'
    CHECK(status IN ('not_checked','online','degraded','offline')),
  http_status INTEGER,
  last_checked_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_websites_project_updated
  ON websites(project_id, updated_at DESC);

CREATE INDEX idx_websites_status_checked
  ON websites(status, last_checked_at DESC);
