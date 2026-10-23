-- Persistent, minimal Go scheduling decision evidence.
-- The Go process never opens SQLite; only the Rust review supervisor writes here.
CREATE TABLE go_dispatch_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  role TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK(verdict IN ('allowed','denied')),
  ready_json TEXT NOT NULL CHECK(json_valid(ready_json)),
  reason TEXT NOT NULL CHECK(length(reason) <= 320),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(run_id,position)
    REFERENCES native_agent_steps(run_id,position) ON DELETE CASCADE
);
CREATE INDEX go_dispatch_audit_by_run ON go_dispatch_audit(run_id,id);
