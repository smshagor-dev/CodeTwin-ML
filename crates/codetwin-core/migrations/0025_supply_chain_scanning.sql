-- Secret scanning and dependency vulnerability auditing. Findings reuse the shared
-- findings/finding_evidence tables (analyzer_key 'secret_scanning' / 'dependency_audit');
-- these tables hold per-run metrics, the dependency inventory and cached OSV advisories.

CREATE TABLE secret_scan_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  coverage_complete INTEGER NOT NULL CHECK(coverage_complete IN (0,1)),
  files_considered INTEGER NOT NULL DEFAULT 0,
  files_scanned INTEGER NOT NULL DEFAULT 0,
  files_skipped INTEGER NOT NULL DEFAULT 0,
  observations INTEGER NOT NULL DEFAULT 0,
  observations_in_test_paths INTEGER NOT NULL DEFAULT 0,
  findings_opened INTEGER NOT NULL DEFAULT 0,
  findings_refreshed INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE dependency_inventory (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  is_dev INTEGER NOT NULL DEFAULT 0 CHECK(is_dev IN (0,1)),
  last_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
  UNIQUE(project_id, ecosystem, name, version, manifest_path)
);
CREATE INDEX idx_dependency_inventory_project
  ON dependency_inventory(project_id, is_active, ecosystem, name);

CREATE TABLE osv_advisories (
  id TEXT PRIMARY KEY,
  modified TEXT,
  record_json TEXT NOT NULL,
  fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE dependency_audit_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  coverage_complete INTEGER NOT NULL CHECK(coverage_complete IN (0,1)),
  advisory_source TEXT NOT NULL,
  manifests INTEGER NOT NULL DEFAULT 0,
  packages INTEGER NOT NULL DEFAULT 0,
  unpinned_requirements INTEGER NOT NULL DEFAULT 0,
  vulnerable_packages INTEGER NOT NULL DEFAULT 0,
  observations INTEGER NOT NULL DEFAULT 0,
  findings_opened INTEGER NOT NULL DEFAULT 0,
  findings_refreshed INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0
);
