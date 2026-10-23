-- Only already-approved local flows can enter the bounded queue.
-- The Rust supervisor remains responsible for the whole approved review.
CREATE TABLE native_flow_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id TEXT NOT NULL UNIQUE REFERENCES native_security_flows(review_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK(status IN ('queued','running','completed','failed','cancelled','interrupted')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    finished_at TEXT,
    detail TEXT NOT NULL DEFAULT '' CHECK(length(detail) <= 240)
);
CREATE INDEX idx_native_flow_queue_order ON native_flow_queue(status,id);
