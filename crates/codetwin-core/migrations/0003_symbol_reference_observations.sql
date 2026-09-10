CREATE TABLE symbol_reference_observations (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('call','constructor')),
  start_line INTEGER NOT NULL,
  start_column INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  end_column INTEGER NOT NULL,
  analyzer_version TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, source_file_id, kind, name, start_line, start_column, end_line, end_column)
);

CREATE INDEX idx_symbol_reference_observations_file
  ON symbol_reference_observations(source_file_id, start_line, start_column);
CREATE INDEX idx_symbol_reference_observations_project_name
  ON symbol_reference_observations(project_id, name, kind);
