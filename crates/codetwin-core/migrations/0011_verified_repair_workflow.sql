CREATE TABLE repair_plans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  rationale TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft'
    CHECK(status IN ('draft','approved','applied','verified','rejected','superseded')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approved_at TEXT,
  verified_at TEXT
);
CREATE INDEX idx_repair_plans_project_status
  ON repair_plans(project_id, status, updated_at DESC);
CREATE INDEX idx_repair_plans_finding
  ON repair_plans(finding_id, status);

CREATE TABLE repair_changes (
  id TEXT PRIMARY KEY,
  repair_id TEXT NOT NULL REFERENCES repair_plans(id) ON DELETE CASCADE,
  file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  relative_path TEXT NOT NULL,
  base_content_hash TEXT NOT NULL,
  proposed_content_hash TEXT NOT NULL,
  proposed_content TEXT NOT NULL,
  proposed_byte_size INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(repair_id, relative_path)
);
CREATE INDEX idx_repair_changes_repair ON repair_changes(repair_id, relative_path);

CREATE TABLE repair_verification_runs (
  id TEXT PRIMARY KEY,
  repair_id TEXT NOT NULL REFERENCES repair_plans(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL
    CHECK(status IN ('verified','applied_finding_open','mismatch','incomplete')),
  finding_status TEXT,
  matched_changes INTEGER NOT NULL DEFAULT 0,
  mismatched_changes INTEGER NOT NULL DEFAULT 0,
  missing_changes INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_repair_verification_runs_repair
  ON repair_verification_runs(repair_id, created_at DESC);

CREATE TABLE repair_verification_items (
  run_id TEXT NOT NULL REFERENCES repair_verification_runs(id) ON DELETE CASCADE,
  change_id TEXT NOT NULL REFERENCES repair_changes(id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK(state IN ('matched','mismatch','missing')),
  expected_hash TEXT NOT NULL,
  observed_hash TEXT,
  PRIMARY KEY(run_id, change_id)
);
