CREATE TABLE semantic_run_metrics (
  run_id TEXT PRIMARY KEY REFERENCES analysis_runs(id) ON DELETE CASCADE,
  files_processed INTEGER NOT NULL DEFAULT 0,
  symbols_processed INTEGER NOT NULL DEFAULT 0,
  symbols_matched INTEGER NOT NULL DEFAULT 0,
  reference_locations INTEGER NOT NULL DEFAULT 0,
  definitions_resolved INTEGER NOT NULL DEFAULT 0,
  relations_persisted INTEGER NOT NULL DEFAULT 0,
  graph_edges_materialized INTEGER NOT NULL DEFAULT 0,
  imports_upgraded INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE semantic_relations (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
  subject_symbol_id TEXT NOT NULL REFERENCES symbols(id) ON DELETE CASCADE,
  occurrence_file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  container_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  target_file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  target_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL,
  relationship TEXT NOT NULL CHECK(relationship IN ('reference_definition')),
  occurrence_start_line INTEGER NOT NULL,
  occurrence_start_column INTEGER NOT NULL,
  occurrence_end_line INTEGER NOT NULL,
  occurrence_end_column INTEGER NOT NULL,
  target_start_line INTEGER NOT NULL,
  target_start_column INTEGER NOT NULL,
  target_end_line INTEGER NOT NULL,
  target_end_column INTEGER NOT NULL,
  provider_kind TEXT NOT NULL CHECK(provider_kind IN ('typescript','pyright','rust_analyzer')),
  server_name TEXT,
  server_version TEXT,
  occurrence_content_hash TEXT NOT NULL,
  target_content_hash TEXT NOT NULL,
  graph_edge_id TEXT REFERENCES graph_edges(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
  UNIQUE(
    project_id,
    relationship,
    occurrence_file_id,
    occurrence_start_line,
    occurrence_start_column,
    occurrence_end_line,
    occurrence_end_column,
    target_file_id,
    target_start_line,
    target_start_column,
    target_end_line,
    target_end_column
  )
);
CREATE INDEX idx_semantic_relations_subject
  ON semantic_relations(subject_symbol_id, is_active, relationship);
CREATE INDEX idx_semantic_relations_container
  ON semantic_relations(container_symbol_id, is_active, relationship);
CREATE INDEX idx_semantic_relations_target
  ON semantic_relations(target_symbol_id, is_active, relationship);
CREATE INDEX idx_semantic_relations_project
  ON semantic_relations(project_id, is_active, provider_kind);

CREATE TABLE semantic_symbol_states (
  symbol_id TEXT PRIMARY KEY REFERENCES symbols(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
  provider_kind TEXT NOT NULL CHECK(provider_kind IN ('typescript','pyright','rust_analyzer')),
  state TEXT NOT NULL CHECK(state IN ('resolved','no_references','unmatched','unsupported','error','stale')),
  reference_locations INTEGER NOT NULL DEFAULT 0,
  definitions_resolved INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_semantic_symbol_states_project
  ON semantic_symbol_states(project_id, provider_kind, state);

CREATE TRIGGER invalidate_semantics_after_file_change
AFTER UPDATE OF content_hash, is_active ON files
WHEN OLD.content_hash <> NEW.content_hash OR (OLD.is_active = 1 AND NEW.is_active = 0)
BEGIN
  UPDATE graph_edges
  SET is_active = 0, updated_at = CURRENT_TIMESTAMP
  WHERE id IN (
    SELECT graph_edge_id
    FROM semantic_relations
    WHERE graph_edge_id IS NOT NULL
      AND (occurrence_file_id = NEW.id OR target_file_id = NEW.id)
  );

  UPDATE semantic_relations
  SET is_active = 0, updated_at = CURRENT_TIMESTAMP
  WHERE occurrence_file_id = NEW.id OR target_file_id = NEW.id;

  UPDATE semantic_symbol_states
  SET state = 'stale', updated_at = CURRENT_TIMESTAMP
  WHERE symbol_id IN (SELECT id FROM symbols WHERE file_id = NEW.id);
END;
