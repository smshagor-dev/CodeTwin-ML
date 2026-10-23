-- One approved local flow owns an immutable native review and its existing
-- SQLite delegation, subtask and action receipts. The parent review remains the
-- single source of truth for status, cancellation and execution authorization.
CREATE TABLE native_security_flows (
    review_id TEXT PRIMARY KEY REFERENCES native_agent_runs(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK(mode = 'go-verified'),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TEXT
);
