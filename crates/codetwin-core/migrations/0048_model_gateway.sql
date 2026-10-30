-- Model provider settings, project cloud-disclosure consent and request audit.
-- API tokens are NEVER stored here: they live in the OS credential store.
-- Audit rows hold metadata and payload digests only, never prompt/response text.
CREATE TABLE provider_settings (
    provider TEXT PRIMARY KEY CHECK(length(provider) BETWEEN 1 AND 64),
    kind TEXT NOT NULL CHECK(kind IN ('cloud','local')),
    base_url TEXT NOT NULL CHECK(length(base_url) <= 512),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
    role_models_json TEXT NOT NULL DEFAULT '{}' CHECK(length(role_models_json) <= 4096),
    updated_ms INTEGER NOT NULL
);

CREATE TABLE cloud_consents (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    allow_cloud INTEGER NOT NULL CHECK(allow_cloud IN (0,1)),
    allow_source_excerpts INTEGER NOT NULL DEFAULT 0 CHECK(allow_source_excerpts IN (0,1)),
    allow_local_fallback INTEGER NOT NULL DEFAULT 0 CHECK(allow_local_fallback IN (0,1)),
    allow_web_research INTEGER NOT NULL DEFAULT 0 CHECK(allow_web_research IN (0,1)),
    max_payload_bytes INTEGER NOT NULL CHECK(max_payload_bytes BETWEEN 1024 AND 262144),
    granted_by TEXT NOT NULL CHECK(length(granted_by) BETWEEN 1 AND 120),
    granted_ms INTEGER NOT NULL,
    revoked_ms INTEGER
);

CREATE TABLE provider_requests (
    request_id TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    run_id TEXT,
    task_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    operation TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(length(outcome) <= 32),
    http_status INTEGER,
    attempts INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    payload_sha256 TEXT CHECK(payload_sha256 IS NULL OR length(payload_sha256) = 64),
    redactions INTEGER NOT NULL DEFAULT 0,
    credits INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    streamed INTEGER NOT NULL DEFAULT 0 CHECK(streamed IN (0,1)),
    created_ms INTEGER NOT NULL
);
CREATE INDEX idx_provider_requests_project ON provider_requests(project_id, created_ms);
