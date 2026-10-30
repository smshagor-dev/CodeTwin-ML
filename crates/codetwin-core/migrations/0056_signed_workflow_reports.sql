-- Signed workflow reports. Reports are canonical JSON, content-addressed,
-- append-only and chained per run (sequence + previous hash) so a replayed
-- older report is detectable. Only public keys are stored: signatures are
-- produced outside CodeTwin and attached; there is no private key column.

CREATE TABLE workflow_reports (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    previous_sha256 TEXT CHECK(previous_sha256 IS NULL OR length(previous_sha256) = 64),
    report_json TEXT NOT NULL CHECK(length(report_json) <= 4000000),
    report_sha256 TEXT NOT NULL CHECK(length(report_sha256) = 64),
    created_ms INTEGER NOT NULL,
    UNIQUE(run_id, sequence),
    CHECK((sequence = 1) = (previous_sha256 IS NULL))
);
CREATE TRIGGER workflow_reports_append_only BEFORE UPDATE ON workflow_reports
BEGIN SELECT RAISE(ABORT, 'workflow reports are append-only'); END;

-- Operator-pinned verification keys. Adding a key is an explicit act; a
-- revoked key no longer verifies anything signed after revocation.
CREATE TABLE trusted_report_signers (
    public_key_hex TEXT PRIMARY KEY CHECK(length(public_key_hex) = 64),
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 120),
    added_by TEXT NOT NULL,
    added_ms INTEGER NOT NULL,
    revoked_ms INTEGER
);

CREATE TABLE workflow_report_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT NOT NULL REFERENCES workflow_reports(id) ON DELETE CASCADE,
    public_key_hex TEXT NOT NULL CHECK(length(public_key_hex) = 64),
    signature_hex TEXT NOT NULL CHECK(length(signature_hex) = 128),
    signer_label TEXT CHECK(signer_label IS NULL OR length(signer_label) <= 120),
    attached_by TEXT NOT NULL,
    attached_ms INTEGER NOT NULL,
    UNIQUE(report_id, public_key_hex)
);
