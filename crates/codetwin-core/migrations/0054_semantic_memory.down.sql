-- Reverts 0054. Neural vectors and memory items are kept; only the
-- registry, settings, job history and tombstones introduced here go.
INSERT INTO memory_fts(memory_fts, rank) VALUES ('secure-delete', 0);
DROP TRIGGER memory_neural_vectors_dims;
DROP TABLE memory_deletions;
DROP TABLE memory_index_jobs;
DROP TABLE memory_settings;
DROP TABLE embedding_models;
