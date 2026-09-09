CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  root_path TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analysis_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled','interrupted')),
  analyzer_version TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  configuration_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_analysis_runs_project_status ON analysis_runs(project_id, status);

CREATE TABLE files (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  relative_path TEXT NOT NULL,
  language TEXT,
  content_hash TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, relative_path)
);
CREATE INDEX idx_files_project_language ON files(project_id, language);

CREATE TABLE symbols (
  id TEXT PRIMARY KEY,
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  qualified_name TEXT,
  start_line INTEGER NOT NULL,
  start_column INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  end_column INTEGER NOT NULL,
  signature TEXT
);
CREATE INDEX idx_symbols_file_kind ON symbols(file_id, kind);

CREATE TABLE graph_nodes (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  node_type TEXT NOT NULL,
  external_key TEXT NOT NULL,
  label TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(project_id, node_type, external_key)
);
CREATE INDEX idx_graph_nodes_project_type ON graph_nodes(project_id, node_type);

CREATE TABLE graph_edges (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_node_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  target_node_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
  relationship TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(project_id, source_node_id, target_node_id, relationship)
);
CREATE INDEX idx_graph_edges_source ON graph_edges(source_node_id, relationship);
CREATE INDEX idx_graph_edges_target ON graph_edges(target_node_id, relationship);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  sub_category TEXT,
  severity TEXT NOT NULL,
  confidence REAL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  source_start_line INTEGER,
  source_end_line INTEGER,
  cwe TEXT,
  owasp TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  fingerprint TEXT NOT NULL,
  rule_version TEXT,
  model_version TEXT,
  first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, fingerprint)
);
CREATE INDEX idx_findings_project_severity ON findings(project_id, severity, status);

CREATE TABLE finding_evidence (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  uri TEXT,
  line_start INTEGER,
  line_end INTEGER,
  summary TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_finding_evidence_finding ON finding_evidence(finding_id);

CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  artifact_type TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  content_hash TEXT,
  byte_size INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE settings (
  scope TEXT NOT NULL,
  key TEXT NOT NULL,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(scope, key)
);
