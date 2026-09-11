use codetwin_core::Database;
use rusqlite::params;

#[test]
fn file_hash_change_invalidates_semantic_evidence_and_edge() {
    let database = Database::open_in_memory().expect("database");
    let connection = database.connection();

    connection
        .execute(
            "INSERT INTO projects(id, root_path, display_name, path_identity) VALUES ('project:p', '/tmp/p', 'p', '/tmp/p')",
            [],
        )
        .expect("project");
    connection
        .execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, configuration_json, run_kind)\
             VALUES ('run:r', 'project:p', 'completed', 'test', '{}', 'lsp_semantic')",
            [],
        )
        .expect("run");

    for (id, path, hash) in [("file:a", "a.ts", "hash-a"), ("file:b", "b.ts", "hash-b")] {
        connection
            .execute(
                "INSERT INTO files(id, project_id, relative_path, relative_path_identity, language, content_hash, byte_size, is_active)\
                 VALUES (?1, 'project:p', ?2, ?2, 'TypeScript', ?3, 10, 1)",
                params![id, path, hash],
            )
            .expect("file");
    }

    for (id, file_id, name, fingerprint) in [
        ("symbol:a", "file:a", "source", "fingerprint:a"),
        ("symbol:b", "file:b", "target", "fingerprint:b"),
    ] {
        connection
            .execute(
                "INSERT INTO symbols(\
                   id, file_id, project_id, kind, name, start_line, start_column, end_line, end_column, fingerprint, is_active\
                 ) VALUES (?1, ?2, 'project:p', 'function', ?3, 1, 0, 1, 5, ?4, 1)",
                params![id, file_id, name, fingerprint],
            )
            .expect("symbol");
    }

    connection
        .execute(
            "INSERT INTO graph_nodes(id, project_id, node_type, external_key, label, is_active) VALUES\
             ('node:a', 'project:p', 'SYMBOL', 'symbol:a', 'source', 1),\
             ('node:b', 'project:p', 'SYMBOL', 'symbol:b', 'target', 1)",
            [],
        )
        .expect("nodes");
    connection
        .execute(
            "INSERT INTO graph_edges(id, project_id, source_node_id, target_node_id, relationship, metadata_json, is_active)\
             VALUES ('edge:e', 'project:p', 'node:a', 'node:b', 'SYMBOL_REFERENCES_SYMBOL', '{}', 1)",
            [],
        )
        .expect("edge");
    connection
        .execute(
            "INSERT INTO semantic_symbol_states(\
               symbol_id, project_id, run_id, provider_kind, state, reference_locations, definitions_resolved\
             ) VALUES ('symbol:a', 'project:p', 'run:r', 'typescript', 'resolved', 1, 1)",
            [],
        )
        .expect("state");
    connection
        .execute(
            "INSERT INTO semantic_relations(\
               id, project_id, run_id, subject_symbol_id, occurrence_file_id, container_symbol_id, target_file_id, target_symbol_id,\
               relationship, occurrence_start_line, occurrence_start_column, occurrence_end_line, occurrence_end_column,\
               target_start_line, target_start_column, target_end_line, target_end_column, provider_kind,\
               occurrence_content_hash, target_content_hash, graph_edge_id, is_active\
             ) VALUES (\
               'relation:r', 'project:p', 'run:r', 'symbol:a', 'file:a', 'symbol:a', 'file:b', 'symbol:b',\
               'reference_definition', 1, 0, 1, 5, 1, 0, 1, 5, 'typescript',\
               'hash-a', 'hash-b', 'edge:e', 1\
             )",
            [],
        )
        .expect("relation");

    connection
        .execute("UPDATE files SET content_hash = 'hash-a-2' WHERE id = 'file:a'", [])
        .expect("change hash");

    let relation_active: i64 = connection
        .query_row(
            "SELECT is_active FROM semantic_relations WHERE id = 'relation:r'",
            [],
            |row| row.get(0),
        )
        .expect("relation state");
    let edge_active: i64 = connection
        .query_row(
            "SELECT is_active FROM graph_edges WHERE id = 'edge:e'",
            [],
            |row| row.get(0),
        )
        .expect("edge state");
    let semantic_state: String = connection
        .query_row(
            "SELECT state FROM semantic_symbol_states WHERE symbol_id = 'symbol:a'",
            [],
            |row| row.get(0),
        )
        .expect("semantic state");

    assert_eq!(relation_active, 0);
    assert_eq!(edge_active, 0);
    assert_eq!(semantic_state, "stale");
}
