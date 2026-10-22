-- Verified, append-only role handoffs for native approved reviews.
-- Results stay in their original run; only a digest and trusted role IDs are replicated.
CREATE TABLE native_agent_handoffs (
    run_id TEXT NOT NULL REFERENCES native_agent_runs(id) ON DELETE CASCADE,
    from_position INTEGER NOT NULL,
    to_position INTEGER NOT NULL,
    from_role TEXT NOT NULL,
    to_role TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256) = 64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(run_id, to_position),
    FOREIGN KEY(run_id, from_position) REFERENCES native_agent_steps(run_id, position),
    FOREIGN KEY(run_id, to_position) REFERENCES native_agent_steps(run_id, position),
    CHECK(to_position > from_position)
);
CREATE INDEX native_agent_handoffs_lookup
    ON native_agent_handoffs(run_id, from_position);
