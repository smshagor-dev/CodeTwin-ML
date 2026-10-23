-- Immutable, unapproved follow-up plans for previously reviewed local flows.
-- Go supplies a proposal only; Rust enforces the original specialist scope.
CREATE TABLE native_flow_followups (
    review_id TEXT PRIMARY KEY REFERENCES native_security_flows(review_id) ON DELETE CASCADE,
    proposal_json TEXT NOT NULL CHECK(json_valid(proposal_json) AND length(proposal_json) <= 6000),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
