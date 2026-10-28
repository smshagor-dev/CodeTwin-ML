-- Consented web/document research. Retrieved text is untrusted data, never
-- instructions. Snapshots are content-addressed; bounded excerpts only.
CREATE TABLE research_sources (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT,
    requested_url TEXT NOT NULL CHECK(length(requested_url) <= 2048),
    final_url TEXT CHECK(final_url IS NULL OR length(final_url) <= 2048),
    host TEXT NOT NULL,
    http_status INTEGER,
    content_type TEXT,
    bytes INTEGER NOT NULL DEFAULT 0,
    content_sha256 TEXT CHECK(content_sha256 IS NULL OR length(content_sha256) = 64),
    title TEXT CHECK(title IS NULL OR length(title) <= 300),
    excerpt TEXT CHECK(excerpt IS NULL OR length(excerpt) <= 20000),
    last_modified TEXT,
    error TEXT CHECK(error IS NULL OR length(error) <= 300),
    fetched_ms INTEGER NOT NULL
);
CREATE INDEX idx_research_sources_project ON research_sources(project_id, fetched_ms);
CREATE INDEX idx_research_sources_hash ON research_sources(project_id, content_sha256);

CREATE TABLE research_citations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    run_id TEXT,
    task_id TEXT,
    source_id TEXT NOT NULL REFERENCES research_sources(id) ON DELETE CASCADE,
    claim TEXT NOT NULL CHECK(length(claim) BETWEEN 1 AND 1000),
    quote TEXT CHECK(quote IS NULL OR length(quote) <= 1000),
    support TEXT NOT NULL CHECK(support IN ('supported','unsupported','contradicted')),
    created_ms INTEGER NOT NULL
);
CREATE INDEX idx_research_citations_run ON research_citations(run_id);
