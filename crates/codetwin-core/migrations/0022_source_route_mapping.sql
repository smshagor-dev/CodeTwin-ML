ALTER TABLE import_references ADD COLUMN bindings_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE web_security_endpoints ADD COLUMN route_template TEXT;

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

CREATE TABLE source_route_mounts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  framework TEXT NOT NULL,
  parent_router TEXT NOT NULL,
  mounted_binding TEXT NOT NULL,
  prefix TEXT NOT NULL,
  start_line INTEGER NOT NULL CHECK(start_line >= 1),
  end_line INTEGER NOT NULL CHECK(end_line >= start_line),
  last_index_run_id TEXT REFERENCES analysis_runs(id) ON DELETE SET NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, source_file_id, parent_router, mounted_binding, prefix, start_line)
);

CREATE INDEX idx_source_route_mounts_project_active
  ON source_route_mounts(project_id, is_active, source_file_id);
CREATE INDEX idx_source_route_mounts_binding
  ON source_route_mounts(source_file_id, mounted_binding, is_active);

CREATE TABLE web_source_endpoint_links (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES web_security_scans(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES web_security_endpoints(id) ON DELETE CASCADE,
  source_route_id TEXT NOT NULL REFERENCES source_routes(id) ON DELETE CASCADE,
  match_kind TEXT NOT NULL CHECK(match_kind IN ('seeded','exact_static','template')),
  confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
  parameter_overlap_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scan_id, endpoint_id, source_route_id)
);

CREATE INDEX idx_web_source_endpoint_links_scan
  ON web_source_endpoint_links(scan_id, confidence DESC);
CREATE INDEX idx_web_source_endpoint_links_route
  ON web_source_endpoint_links(source_route_id, scan_id);
