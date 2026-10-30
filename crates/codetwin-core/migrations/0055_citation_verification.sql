-- Evidence-backed citations. Sources gain canonical identity, metadata,
-- provenance and a hashed text snapshot; claims are first-class; every
-- verification and link check is kept as history.

ALTER TABLE research_sources ADD COLUMN canonical_url TEXT
    CHECK(canonical_url IS NULL OR length(canonical_url) <= 2048);
ALTER TABLE research_sources ADD COLUMN origin TEXT NOT NULL DEFAULT 'web'
    CHECK(origin IN ('web','markdown','pdf'));
ALTER TABLE research_sources ADD COLUMN metadata_json TEXT
    CHECK(metadata_json IS NULL OR length(metadata_json) <= 8000);
ALTER TABLE research_sources ADD COLUMN published_ms INTEGER;
-- How the source was found: search provider and query, redirect chain.
ALTER TABLE research_sources ADD COLUMN provenance_json TEXT
    CHECK(provenance_json IS NULL OR length(provenance_json) <= 8000);
ALTER TABLE research_sources ADD COLUMN duplicate_of TEXT;
CREATE INDEX idx_research_sources_canonical ON research_sources(project_id, canonical_url);

-- The exact text citations are checked against, with its own hash so a
-- modified snapshot is detected instead of silently re-verified.
CREATE TABLE research_source_text (
    source_id TEXT PRIMARY KEY REFERENCES research_sources(id) ON DELETE CASCADE,
    text TEXT NOT NULL CHECK(length(text) <= 200000),
    text_sha256 TEXT NOT NULL CHECK(length(text_sha256) = 64)
);

CREATE TABLE research_claims (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT,
    text TEXT NOT NULL CHECK(length(text) BETWEEN 1 AND 1000),
    claim_sha256 TEXT NOT NULL CHECK(length(claim_sha256) = 64),
    created_ms INTEGER NOT NULL
);
CREATE INDEX idx_research_claims_run ON research_claims(project_id, run_id);

-- Citation → claim (many citations may support one claim).
CREATE TABLE research_citation_claims (
    citation_id TEXT PRIMARY KEY REFERENCES research_citations(id) ON DELETE CASCADE,
    claim_id TEXT NOT NULL REFERENCES research_claims(id) ON DELETE CASCADE
);
CREATE INDEX idx_research_citation_claims_claim ON research_citation_claims(claim_id);

CREATE TABLE citation_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    citation_id TEXT NOT NULL REFERENCES research_citations(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('verified','quote_not_found','unrelated_quote',
        'contradicted','source_unavailable','source_changed')),
    source_sha256 TEXT,
    quote_start INTEGER,
    quote_end INTEGER,
    term_coverage REAL NOT NULL DEFAULT 0,
    missing_terms_json TEXT NOT NULL DEFAULT '[]' CHECK(length(missing_terms_json) <= 4000),
    verified_ms INTEGER NOT NULL
);
CREATE INDEX idx_citation_verifications_citation ON citation_verifications(citation_id, id);
CREATE TRIGGER citation_verifications_append_only BEFORE UPDATE ON citation_verifications
BEGIN SELECT RAISE(ABORT, 'verification history is append-only'); END;

CREATE TABLE research_link_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL REFERENCES research_sources(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('ok','changed','redirected','broken','unreachable','blocked')),
    http_status INTEGER,
    final_url TEXT CHECK(final_url IS NULL OR length(final_url) <= 2048),
    content_sha256 TEXT,
    error TEXT CHECK(error IS NULL OR length(error) <= 300),
    checked_ms INTEGER NOT NULL
);
CREATE INDEX idx_research_link_checks_source ON research_link_checks(source_id, id);

CREATE TABLE research_reports (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT,
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 300),
    markdown TEXT NOT NULL CHECK(length(markdown) <= 500000),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    citations_total INTEGER NOT NULL,
    citations_verified INTEGER NOT NULL,
    created_ms INTEGER NOT NULL
);
