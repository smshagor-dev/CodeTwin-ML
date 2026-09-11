CREATE TABLE ml_inference_records (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  source_file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
  source_content_hash TEXT,
  input_sha256 TEXT NOT NULL,
  input_utf8_bytes INTEGER NOT NULL CHECK(input_utf8_bytes >= 0 AND input_utf8_bytes <= 65536),
  preprocessing TEXT NOT NULL,
  model_id TEXT NOT NULL,
  model_version TEXT NOT NULL,
  backend TEXT NOT NULL,
  package_digest TEXT NOT NULL,
  prediction_label TEXT NOT NULL,
  prediction_confidence REAL NOT NULL CHECK(prediction_confidence >= 0.0 AND prediction_confidence <= 1.0),
  scores_json TEXT NOT NULL,
  runtime_json TEXT NOT NULL,
  evaluation_provenance_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ml_inference_project_created
  ON ml_inference_records(project_id, created_at DESC, id);
CREATE INDEX idx_ml_inference_project_action
  ON ml_inference_records(project_id, action, created_at DESC);
CREATE INDEX idx_ml_inference_source_file
  ON ml_inference_records(source_file_id, created_at DESC)
  WHERE source_file_id IS NOT NULL;
CREATE INDEX idx_ml_inference_model
  ON ml_inference_records(model_id, model_version, created_at DESC);

CREATE TABLE ml_finding_links (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  inference_record_id TEXT NOT NULL REFERENCES ml_inference_records(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  relationship TEXT NOT NULL CHECK(relationship IN ('supports_review','contradicts_review','related')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, inference_record_id, finding_id, relationship)
);
CREATE INDEX idx_ml_finding_links_inference
  ON ml_finding_links(inference_record_id, relationship);
CREATE INDEX idx_ml_finding_links_finding
  ON ml_finding_links(finding_id, relationship);
