CREATE TABLE source_routes (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  framework TEXT NOT NULL,
  router_name TEXT NOT NULL,
  http_method TEXT NOT NULL,
  path_template TEXT NOT NULL,
  handler_name TEXT,
  parameter_names_json TEXT NOT NULL DEFAULT '[]',
  parameter_locations_json TEXT NOT NULL DEFAULT '{}',
  request_content_type TEXT,
  source_content_hash TEXT NOT NULL,
  start_line INTEGER NOT NULL CHECK(start_line >= 1),
  end_line INTEGER NOT NULL CHECK(end_line >= start_line),
  last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, file_id, http_method, path_template, start_line)
);

CREATE INDEX idx_source_routes_project_active_method
  ON source_routes(project_id, is_active, http_method, path_template);
CREATE INDEX idx_source_routes_file_active
  ON source_routes(file_id, is_active, start_line);
CREATE INDEX idx_source_routes_symbol
  ON source_routes(symbol_id, is_active);
