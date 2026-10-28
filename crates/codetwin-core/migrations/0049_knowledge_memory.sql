-- Layered, project-isolated memory and an evidence-grounded knowledge graph.
-- Memory is retrieval context, never authorization. Every graph edge carries
-- a source reference, a confidence and whether it is verified or inferred.
CREATE TABLE memory_items (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    layer TEXT NOT NULL CHECK(layer IN (
        'working','episodic','project_fact','approved_knowledge','evidence_ref')),
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
    body TEXT NOT NULL CHECK(length(body) <= 8000),
    source_kind TEXT NOT NULL CHECK(length(source_kind) BETWEEN 1 AND 64),
    source_ref TEXT NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 512),
    source_sha256 TEXT CHECK(source_sha256 IS NULL OR length(source_sha256) = 64),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    run_id TEXT,
    task_id TEXT,
    confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)),
    approved_by TEXT,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    expires_ms INTEGER,
    UNIQUE(project_id, layer, content_sha256),
    -- Only operators promote knowledge into the approved layer.
    CHECK(layer <> 'approved_knowledge' OR approved_by IS NOT NULL)
);
CREATE INDEX idx_memory_items_project ON memory_items(project_id, layer, updated_ms);

CREATE VIRTUAL TABLE memory_fts USING fts5(
    title, body, content='memory_items', content_rowid='rowid', tokenize='unicode61');
CREATE TRIGGER memory_items_ai AFTER INSERT ON memory_items BEGIN
    INSERT INTO memory_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;
CREATE TRIGGER memory_items_ad AFTER DELETE ON memory_items BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, title, body) VALUES ('delete', old.rowid, old.title, old.body);
END;
CREATE TRIGGER memory_items_au AFTER UPDATE OF title, body ON memory_items BEGIN
    INSERT INTO memory_fts(memory_fts, rowid, title, body) VALUES ('delete', old.rowid, old.title, old.body);
    INSERT INTO memory_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;

-- Bounded local vector index. `model` names the embedding source; the
-- default `hashed-lexical-v1` is lexical recall, not neural semantics.
CREATE TABLE memory_vectors (
    item_id TEXT PRIMARY KEY REFERENCES memory_items(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    dims INTEGER NOT NULL CHECK(dims BETWEEN 8 AND 4096),
    vector BLOB NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE INDEX idx_memory_vectors_project ON memory_vectors(project_id, model);

CREATE TABLE kg_nodes (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN (
        'task','hypothesis','finding','test','patch','source','decision','outcome','file','symbol','memory','run')),
    ref_id TEXT NOT NULL CHECK(length(ref_id) BETWEEN 1 AND 512),
    label TEXT NOT NULL CHECK(length(label) <= 200),
    created_ms INTEGER NOT NULL,
    UNIQUE(project_id, kind, ref_id)
);

CREATE TABLE kg_edges (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    from_node TEXT NOT NULL REFERENCES kg_nodes(id) ON DELETE CASCADE,
    to_node TEXT NOT NULL REFERENCES kg_nodes(id) ON DELETE CASCADE,
    relation TEXT NOT NULL CHECK(relation IN (
        'supports','contradicts','derived_from','tests','fixes','cites','decided','produced','references','depends_on')),
    source_ref TEXT NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 512),
    confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
    provenance TEXT NOT NULL CHECK(provenance IN ('verified','inferred')),
    created_ms INTEGER NOT NULL,
    UNIQUE(from_node, to_node, relation),
    CHECK(from_node <> to_node)
);
CREATE INDEX idx_kg_edges_project ON kg_edges(project_id, from_node);
CREATE INDEX idx_kg_edges_to ON kg_edges(to_node);
