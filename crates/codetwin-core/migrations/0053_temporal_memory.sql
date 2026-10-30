-- Temporal knowledge graph and versioned, contradiction-aware memory.
--
-- * Edges get a validity interval. Superseded facts are invalidated, never
--   deleted, so "what did we believe at time T" stays answerable.
-- * Memory revisions keep the prior content in an append-only history.
-- * An unverified update that contradicts verified knowledge is not applied;
--   it is recorded as a conflict for a human to resolve.

ALTER TABLE kg_edges ADD COLUMN valid_from_ms INTEGER;
ALTER TABLE kg_edges ADD COLUMN invalidated_ms INTEGER;
ALTER TABLE kg_edges ADD COLUMN superseded_by TEXT;
UPDATE kg_edges SET valid_from_ms = created_ms WHERE valid_from_ms IS NULL;
CREATE INDEX idx_kg_edges_current ON kg_edges(project_id, from_node, relation)
    WHERE invalidated_ms IS NULL;

ALTER TABLE memory_items ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- Neural vectors live beside the lexical ones (one per item and model).
-- `content_sha256` pins the text that was embedded; vectors of revised
-- items no longer match and are ignored until re-embedded.
CREATE TABLE memory_neural_vectors (
    item_id TEXT NOT NULL REFERENCES memory_items(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 200 AND model <> 'hashed-lexical-v1'),
    dims INTEGER NOT NULL CHECK(dims BETWEEN 8 AND 4096),
    vector BLOB NOT NULL,
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    created_ms INTEGER NOT NULL,
    PRIMARY KEY (item_id, model)
);
CREATE INDEX idx_memory_neural_vectors_project ON memory_neural_vectors(project_id, model);

CREATE TABLE memory_item_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id TEXT NOT NULL REFERENCES memory_items(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    confidence REAL NOT NULL,
    verified INTEGER NOT NULL CHECK(verified IN (0,1)),
    source_ref TEXT NOT NULL,
    change_kind TEXT NOT NULL CHECK(change_kind IN ('revised','superseded')),
    changed_by TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    UNIQUE(item_id, version)
);
CREATE TRIGGER memory_item_versions_no_update BEFORE UPDATE ON memory_item_versions
BEGIN SELECT RAISE(ABORT, 'memory history is append-only'); END;

CREATE TABLE knowledge_conflicts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('memory','edge')),
    existing_ref TEXT NOT NULL,
    proposed_json TEXT NOT NULL CHECK(length(proposed_json) <= 12000),
    reason TEXT NOT NULL CHECK(length(reason) <= 500),
    created_ms INTEGER NOT NULL,
    resolved_ms INTEGER,
    resolved_by TEXT,
    resolution TEXT CHECK(resolution IS NULL OR resolution IN ('accepted','rejected')),
    CHECK((resolved_ms IS NULL) = (resolution IS NULL))
);
CREATE INDEX idx_knowledge_conflicts_open ON knowledge_conflicts(project_id, created_ms)
    WHERE resolved_ms IS NULL;
