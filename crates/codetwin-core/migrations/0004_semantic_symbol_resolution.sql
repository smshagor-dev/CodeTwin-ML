ALTER TABLE symbol_reference_observations
  ADD COLUMN resolution_state TEXT NOT NULL DEFAULT 'observed'
  CHECK(resolution_state IN ('observed','resolved_same_file','ambiguous','unresolved'));

ALTER TABLE symbol_reference_observations
  ADD COLUMN resolved_target_symbol_id TEXT REFERENCES symbols(id) ON DELETE SET NULL;

CREATE INDEX idx_symbol_reference_observations_resolution
  ON symbol_reference_observations(project_id, resolution_state, resolved_target_symbol_id);
