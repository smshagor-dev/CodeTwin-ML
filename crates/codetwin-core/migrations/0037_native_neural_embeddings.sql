-- Optional neural vectors: only non-sensitive role provenance reaches the embedding model.
CREATE TABLE native_neural_embeddings (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  model_id TEXT NOT NULL,
  dimensions INTEGER NOT NULL CHECK(dimensions BETWEEN 16 AND 3072),
  vector_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(run_id,position,model_id),
  FOREIGN KEY(run_id,position) REFERENCES native_agent_steps(run_id,position)
);
CREATE INDEX neural_project_model_idx ON native_neural_embeddings(project_id,model_id);
