-- Neural semantic memory: model registry, per-project settings, durable
-- background index jobs and content-free deletion tombstones.

-- Every stored vector model with its dimensionality and version. A label
-- may never change dimensions: vectors from a different model build would
-- otherwise be compared as if they lived in the same space.
CREATE TABLE embedding_models (
    model TEXT PRIMARY KEY CHECK(length(model) BETWEEN 1 AND 200),
    dims INTEGER NOT NULL CHECK(dims BETWEEN 8 AND 4096),
    kind TEXT NOT NULL CHECK(kind IN ('lexical','local','loopback','remote')),
    revision TEXT CHECK(revision IS NULL OR length(revision) <= 100),
    weights_sha256 TEXT CHECK(weights_sha256 IS NULL OR length(weights_sha256) = 64),
    registered_ms INTEGER NOT NULL
);
INSERT INTO embedding_models(model, dims, kind, registered_ms)
VALUES ('hashed-lexical-v1', 128, 'lexical', 0);
-- Vectors written before the registry existed define their model's size.
INSERT OR IGNORE INTO embedding_models(model, dims, kind, registered_ms)
SELECT model, MIN(dims), 'loopback', MIN(created_ms) FROM memory_neural_vectors GROUP BY model;

CREATE TRIGGER memory_neural_vectors_dims BEFORE INSERT ON memory_neural_vectors
WHEN NOT EXISTS (SELECT 1 FROM embedding_models WHERE model = new.model AND dims = new.dims)
BEGIN SELECT RAISE(ABORT, 'vector does not match its registered embedding model'); END;

-- Retrieval settings and retention per project. JSON is validated in Rust.
CREATE TABLE memory_settings (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    active_model TEXT REFERENCES embedding_models(model),
    ranking_json TEXT CHECK(ranking_json IS NULL OR length(ranking_json) <= 4000),
    retention_json TEXT CHECK(retention_json IS NULL OR length(retention_json) <= 2000),
    updated_ms INTEGER NOT NULL
);

-- Background embedding jobs. A job left `running` by a crash is marked
-- `interrupted` on the next start; the work itself is incremental, so a
-- re-run only embeds what is still missing.
CREATE TABLE memory_index_jobs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    model TEXT NOT NULL REFERENCES embedding_models(model),
    state TEXT NOT NULL CHECK(state IN ('running','completed','cancelled','failed','interrupted')),
    total INTEGER NOT NULL DEFAULT 0 CHECK(total >= 0),
    done INTEGER NOT NULL DEFAULT 0 CHECK(done >= 0),
    error TEXT CHECK(error IS NULL OR length(error) <= 500),
    started_ms INTEGER NOT NULL,
    finished_ms INTEGER
);
CREATE INDEX idx_memory_index_jobs_project ON memory_index_jobs(project_id, started_ms);
CREATE UNIQUE INDEX idx_memory_index_jobs_running ON memory_index_jobs(project_id)
    WHERE state = 'running';

-- Remove a deleted memory's tokens from the full-text index immediately
-- instead of leaving them in old segments until the next merge.
INSERT INTO memory_fts(memory_fts, rank) VALUES ('secure-delete', 1);

-- What was deleted, by whom and why — never the deleted content.
CREATE TABLE memory_deletions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    reason TEXT NOT NULL CHECK(reason IN ('operator','retention','expired','project_clear')),
    actor TEXT NOT NULL CHECK(length(actor) BETWEEN 1 AND 120),
    deleted_ms INTEGER NOT NULL
);
CREATE INDEX idx_memory_deletions_project ON memory_deletions(project_id, deleted_ms);
