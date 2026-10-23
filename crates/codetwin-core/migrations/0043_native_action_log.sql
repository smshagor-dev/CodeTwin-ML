-- Bounded per-specialist execution receipts. Rust exclusively owns these writes.
-- Source and tool output remain in existing evidence tables, not in this ledger.
CREATE TABLE native_action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('scout','source','secrets','qa','database','runtime')),
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed','interrupted')),
    result_sha256 TEXT CHECK(result_sha256 IS NULL OR length(result_sha256)=64),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    FOREIGN KEY(run_id, position) REFERENCES native_agent_steps(run_id, position) ON DELETE CASCADE,
    UNIQUE(run_id, position)
);
CREATE INDEX idx_native_action_log_run ON native_action_log(run_id, id);
