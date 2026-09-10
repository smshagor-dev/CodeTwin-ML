ALTER TABLE projects ADD COLUMN path_identity TEXT;
ALTER TABLE projects ADD COLUMN git_remote TEXT;
ALTER TABLE projects ADD COLUMN last_opened_at TEXT;
ALTER TABLE projects ADD COLUMN last_indexed_at TEXT;
CREATE UNIQUE INDEX idx_projects_path_identity
  ON projects(path_identity)
  WHERE path_identity IS NOT NULL;

ALTER TABLE analysis_runs ADD COLUMN run_kind TEXT NOT NULL DEFAULT 'analysis';
ALTER TABLE analysis_runs ADD COLUMN files_scanned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN files_added INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN files_modified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN files_unchanged INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN files_deleted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN symbols_added INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN symbols_updated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN symbols_removed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN parse_errors INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN skipped_files INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN duration_ms INTEGER;
ALTER TABLE analysis_runs ADD COLUMN query_version TEXT;
ALTER TABLE analysis_runs ADD COLUMN config_fingerprint TEXT;
CREATE INDEX idx_analysis_runs_project_kind_started
  ON analysis_runs(project_id, run_kind, started_at DESC);

ALTER TABLE files ADD COLUMN relative_path_identity TEXT;
ALTER TABLE files ADD COLUMN ast_root_kind TEXT;
ALTER TABLE files ADD COLUMN parse_state TEXT;
ALTER TABLE files ADD COLUMN analysis_fingerprint TEXT;
ALTER TABLE files ADD COLUMN last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL;
ALTER TABLE files ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE files ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE files ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1));
CREATE UNIQUE INDEX idx_files_project_path_identity
  ON files(project_id, relative_path_identity)
  WHERE relative_path_identity IS NOT NULL;
CREATE INDEX idx_files_project_active_path
  ON files(project_id, is_active, relative_path);
CREATE INDEX idx_files_project_hash
  ON files(project_id, content_hash);

ALTER TABLE symbols ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE symbols ADD COLUMN parent_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL;
ALTER TABLE symbols ADD COLUMN fingerprint TEXT;
ALTER TABLE symbols ADD COLUMN last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL;
ALTER TABLE symbols ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE symbols ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE symbols ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1));
CREATE UNIQUE INDEX idx_symbols_project_fingerprint
  ON symbols(project_id, fingerprint)
  WHERE project_id IS NOT NULL AND fingerprint IS NOT NULL;
CREATE INDEX idx_symbols_project_name
  ON symbols(project_id, name, kind);
CREATE INDEX idx_symbols_project_qualified_name
  ON symbols(project_id, qualified_name);
CREATE INDEX idx_symbols_file_active
  ON symbols(file_id, is_active, kind);

ALTER TABLE graph_nodes ADD COLUMN last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL;
ALTER TABLE graph_nodes ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE graph_nodes ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE graph_nodes ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1));
CREATE INDEX idx_graph_nodes_project_active_type
  ON graph_nodes(project_id, is_active, node_type);

ALTER TABLE graph_edges ADD COLUMN last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL;
ALTER TABLE graph_edges ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE graph_edges ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE graph_edges ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1));
CREATE INDEX idx_graph_edges_project_active_relationship
  ON graph_edges(project_id, is_active, relationship);

CREATE TABLE import_references (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  raw_specifier TEXT NOT NULL,
  kind TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  start_column INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  end_column INTEGER NOT NULL,
  resolution_state TEXT NOT NULL CHECK(resolution_state IN ('observed','resolved_local','external','unresolved','unsupported')),
  resolved_target_file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, source_file_id, kind, raw_specifier, start_line, start_column, end_line, end_column)
);
CREATE INDEX idx_import_references_source
  ON import_references(source_file_id, resolution_state);
CREATE INDEX idx_import_references_target
  ON import_references(resolved_target_file_id, resolution_state);
CREATE INDEX idx_import_references_project_state
  ON import_references(project_id, resolution_state);
