-- Cross-analyzer security intelligence: audited suppressions and
-- reproducible correlation snapshots.
--
-- Suppressions never modify analyzer-owned `findings` rows. They are an
-- operator overlay that hides findings from prioritised views and policy
-- gates, always expire, and can only be created by a human approver.

CREATE TABLE security_suppressions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- fingerprint: one finding; rule: an analyzer rule id (findings.sub_category);
    -- path: a relative path prefix.
    scope TEXT NOT NULL CHECK(scope IN ('fingerprint','rule','path')),
    matcher TEXT NOT NULL CHECK(length(matcher) BETWEEN 1 AND 512),
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 2000),
    created_by TEXT NOT NULL CHECK(length(created_by) BETWEEN 1 AND 160),
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL,
    revoked_by TEXT,
    revoked_ms INTEGER,
    CHECK(expires_ms > created_ms),
    CHECK((revoked_by IS NULL) = (revoked_ms IS NULL))
);
CREATE INDEX idx_security_suppressions_project ON security_suppressions(project_id, expires_ms);

-- Append-only audit trail for suppressions.
CREATE TABLE security_suppression_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    suppression_id TEXT NOT NULL REFERENCES security_suppressions(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('created','revoked')),
    actor TEXT NOT NULL,
    detail TEXT NOT NULL CHECK(length(detail) <= 2000),
    created_ms INTEGER NOT NULL
);
CREATE TRIGGER security_suppression_events_no_update BEFORE UPDATE ON security_suppression_events
BEGIN SELECT RAISE(ABORT, 'suppression audit is append-only'); END;
CREATE TRIGGER security_suppression_events_no_delete BEFORE DELETE ON security_suppression_events
WHEN EXISTS (SELECT 1 FROM security_suppressions WHERE id = old.suppression_id)
BEGIN SELECT RAISE(ABORT, 'suppression audit is append-only'); END;
-- Revocation is the only permitted update; terms cannot be widened in place.
CREATE TRIGGER security_suppressions_immutable BEFORE UPDATE OF scope, matcher, reason, created_by, created_ms, expires_ms ON security_suppressions
BEGIN SELECT RAISE(ABORT, 'suppressions are immutable; revoke and recreate'); END;

-- A correlation snapshot is the exact, hashed result shown to the operator
-- and used by policy gates, so a report can cite what was evaluated.
CREATE TABLE security_correlation_snapshots (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_ms INTEGER NOT NULL,
    finding_count INTEGER NOT NULL CHECK(finding_count >= 0),
    cluster_count INTEGER NOT NULL CHECK(cluster_count >= 0),
    suppressed_count INTEGER NOT NULL CHECK(suppressed_count >= 0),
    policy_verdict TEXT NOT NULL CHECK(policy_verdict IN ('pass','fail')),
    report_json TEXT NOT NULL,
    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64)
);
CREATE INDEX idx_security_correlation_snapshots_project ON security_correlation_snapshots(project_id, created_ms);
