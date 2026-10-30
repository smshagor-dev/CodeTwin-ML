-- Optional multi-user collaboration, role-based access, comment threads,
-- the loopback automation API and its tokens, a general audit log, and
-- external search provider settings.
--
-- Secrets are never stored: API tokens and invitation codes are kept only as
-- SHA-256 verifiers of 256-bit random values; search API keys live in the
-- OS credential store.

CREATE TABLE search_provider_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    kind TEXT NOT NULL CHECK(kind IN ('brave','searxng')),
    base_url TEXT NOT NULL CHECK(length(base_url) BETWEEN 8 AND 512),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
    max_results INTEGER NOT NULL DEFAULT 5 CHECK(max_results BETWEEN 1 AND 10),
    updated_ms INTEGER NOT NULL
);

CREATE TABLE principals (
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 3 AND 120),
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 120),
    kind TEXT NOT NULL CHECK(kind IN ('human','automation')),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
    created_ms INTEGER NOT NULL
);

CREATE TABLE project_access_policies (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    enforce_rbac INTEGER NOT NULL DEFAULT 0 CHECK(enforce_rbac IN (0,1)),
    separation_of_duties INTEGER NOT NULL DEFAULT 0 CHECK(separation_of_duties IN (0,1)),
    updated_by TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);

CREATE TABLE project_memberships (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','approver','administrator')),
    granted_by TEXT NOT NULL,
    granted_ms INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),
    PRIMARY KEY (project_id, principal_id)
);
CREATE INDEX idx_memberships_principal ON project_memberships(principal_id);

CREATE TABLE project_invitations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','approver','administrator')),
    code_sha256 TEXT NOT NULL UNIQUE CHECK(length(code_sha256) = 64),
    invited_by TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL,
    accepted_by TEXT,
    accepted_ms INTEGER,
    revoked_ms INTEGER
);
CREATE INDEX idx_invitations_project ON project_invitations(project_id, created_ms);

CREATE TABLE collaboration_comments (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL CHECK(target_kind IN ('run','task','approval','finding','report')),
    target_id TEXT NOT NULL CHECK(length(target_id) BETWEEN 1 AND 200),
    parent_id TEXT REFERENCES collaboration_comments(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 4000),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),
    created_ms INTEGER NOT NULL,
    edited_ms INTEGER,
    deleted_ms INTEGER
);
CREATE INDEX idx_comments_target ON collaboration_comments(project_id, target_kind, target_id, created_ms);

CREATE TABLE collaboration_comment_revisions (
    comment_id TEXT NOT NULL REFERENCES collaboration_comments(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    body TEXT NOT NULL,
    edited_by TEXT NOT NULL,
    edited_ms INTEGER NOT NULL,
    PRIMARY KEY (comment_id, revision)
);

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 120),
    token_sha256 TEXT NOT NULL UNIQUE CHECK(length(token_sha256) = 64),
    scopes_json TEXT NOT NULL CHECK(length(scopes_json) <= 512),
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL,
    last_used_ms INTEGER,
    revoked_ms INTEGER
);

CREATE TABLE audit_records (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 160),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 64),
    project_id TEXT,
    target TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('allowed','denied','error')),
    detail_json TEXT NOT NULL DEFAULT '{}' CHECK(length(detail_json) <= 2048),
    created_ms INTEGER NOT NULL
);
CREATE INDEX idx_audit_records_project ON audit_records(project_id, seq);
CREATE INDEX idx_audit_records_created ON audit_records(created_ms);
