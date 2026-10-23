-- Local, bounded project-scoped knowledge. No source or raw scanner output is persisted.
CREATE TABLE native_knowledge_nodes (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  role TEXT NOT NULL,
  tool TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('completed','failed')),
  vector_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(run_id, position),
  FOREIGN KEY(run_id,position) REFERENCES native_agent_steps(run_id,position)
);
CREATE INDEX native_knowledge_nodes_project ON native_knowledge_nodes(project_id,created_at);
CREATE TABLE native_knowledge_edges (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
  from_position INTEGER NOT NULL,
  to_position INTEGER NOT NULL,
  relation TEXT NOT NULL CHECK(relation='verified_handoff'),
  PRIMARY KEY(run_id,from_position,to_position),
  FOREIGN KEY(run_id,from_position) REFERENCES native_knowledge_nodes(run_id,position),
  FOREIGN KEY(run_id,to_position) REFERENCES native_knowledge_nodes(run_id,position)
);
CREATE INDEX native_knowledge_edges_project ON native_knowledge_edges(project_id,run_id);
