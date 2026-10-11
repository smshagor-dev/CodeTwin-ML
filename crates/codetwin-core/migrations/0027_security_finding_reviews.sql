CREATE TABLE security_finding_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_run_id TEXT NOT NULL,
  indexed_content_hash TEXT,
  verdict TEXT NOT NULL CHECK(verdict IN ('confirmed','false_positive','needs_review')),
  note TEXT NOT NULL CHECK(length(note) BETWEEN 1 AND 2000),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_security_reviews_project ON security_finding_reviews(project_id, id DESC);
CREATE INDEX idx_security_reviews_finding ON security_finding_reviews(finding_id, id DESC);
