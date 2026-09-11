use codetwin_core::{CodeQualityService, Database};
use rusqlite::params;

#[test]
fn persists_evidence_backed_quality_findings_and_history() {
    let database = Database::open_in_memory().expect("database");
    seed_project(&database);
    insert_file(&database, "file:a", "a.ts");
    insert_file(&database, "file:b", "b.ts");

    database
        .connection()
        .execute(
            "INSERT INTO symbols(\
               id, file_id, project_id, kind, name, qualified_name, start_line, start_column, end_line, end_column, fingerprint, is_active\
             ) VALUES ('symbol:large', 'file:a', 'project:p', 'function', 'large', 'large', 1, 0, 140, 1, 'fp:large', 1)",
            [],
        )
        .expect("large symbol");

    for (id, parent, depth) in [
        ("symbol:n0", None, 0usize),
        ("symbol:n1", Some("symbol:n0"), 1),
        ("symbol:n2", Some("symbol:n1"), 2),
        ("symbol:n3", Some("symbol:n2"), 3),
        ("symbol:n4", Some("symbol:n3"), 4),
        ("symbol:n5", Some("symbol:n4"), 5),
    ] {
        database
            .connection()
            .execute(
                "INSERT INTO symbols(\
                   id, file_id, project_id, kind, name, parent_symbol_id, start_line, start_column, end_line, end_column, fingerprint, is_active\
                 ) VALUES (?1, 'file:a', 'project:p', 'function', ?1, ?2, ?3, 0, ?4, 1, ?5, 1)",
                params![id, parent, 150 + depth, 160 + depth, format!("fp:{id}")],
            )
            .expect("nested symbol");
    }

    insert_import(&database, "import:a-b", "file:a", "file:b", "./b");

    let summary = CodeQualityService::new(&database)
        .analyze_project("project:p")
        .expect("quality analysis");
    assert_eq!(summary.status.as_str(), "completed");
    assert_eq!(summary.rules_evaluated, 4);
    assert_eq!(summary.oversized_definitions, 1);
    assert_eq!(summary.deep_declarations, 1);
    assert_eq!(summary.dependency_cycles, 0);
    assert_eq!(summary.findings_opened, 2);

    let findings = CodeQualityService::new(&database)
        .list_findings("project:p", Some("open"), 20)
        .expect("findings");
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "quality.oversized_definition"));
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "quality.deep_declaration_nesting"));

    let large = findings
        .iter()
        .find(|finding| finding.rule_id == "quality.oversized_definition")
        .expect("large finding");
    let evidence = CodeQualityService::new(&database)
        .finding_evidence(&large.id, 20)
        .expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].uri.as_deref(), Some("a.ts"));
    assert_eq!(evidence[0].line_start, Some(1));
    assert_eq!(evidence[0].line_end, Some(140));

    let history = CodeQualityService::new(&database)
        .history("project:p", 10)
        .expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].observations, 2);
}

#[test]
fn refreshes_stable_finding_and_resolves_it_when_evidence_disappears() {
    let database = Database::open_in_memory().expect("database");
    seed_project(&database);
    insert_file(&database, "file:a", "a.ts");
    database
        .connection()
        .execute(
            "INSERT INTO symbols(\
               id, file_id, project_id, kind, name, qualified_name, start_line, start_column, end_line, end_column, fingerprint, is_active\
             ) VALUES ('symbol:large', 'file:a', 'project:p', 'function', 'large', 'large', 1, 0, 140, 1, 'fp:large', 1)",
            [],
        )
        .expect("symbol");

    let first = CodeQualityService::new(&database)
        .analyze_project("project:p")
        .expect("first");
    assert_eq!(first.findings_opened, 1);
    let first_record = CodeQualityService::new(&database)
        .list_findings("project:p", Some("open"), 10)
        .expect("first finding")
        .pop()
        .expect("finding");

    let second = CodeQualityService::new(&database)
        .analyze_project("project:p")
        .expect("second");
    assert_eq!(second.findings_opened, 0);
    assert_eq!(second.findings_refreshed, 1);
    let second_record = CodeQualityService::new(&database)
        .list_findings("project:p", Some("open"), 10)
        .expect("second finding")
        .pop()
        .expect("finding");
    assert_eq!(first_record.id, second_record.id);
    assert_eq!(first_record.fingerprint, second_record.fingerprint);

    database
        .connection()
        .execute(
            "UPDATE symbols SET end_line = 20 WHERE id = 'symbol:large'",
            [],
        )
        .expect("shrink symbol");
    let third = CodeQualityService::new(&database)
        .analyze_project("project:p")
        .expect("third");
    assert_eq!(third.observations, 0);
    assert_eq!(third.findings_resolved, 1);
    assert!(CodeQualityService::new(&database)
        .list_findings("project:p", Some("open"), 10)
        .expect("open")
        .is_empty());
    let resolved = CodeQualityService::new(&database)
        .list_findings("project:p", Some("resolved"), 10)
        .expect("resolved");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].id, first_record.id);
    assert!(resolved[0].resolved_at.is_some());
}

#[test]
fn finds_resolved_local_cycles_and_high_fan_out_without_guessing() {
    let database = Database::open_in_memory().expect("database");
    seed_project(&database);
    insert_file(&database, "file:hub", "hub.ts");
    insert_file(&database, "file:a", "a.ts");
    insert_file(&database, "file:b", "b.ts");

    insert_import(&database, "import:a-b", "file:a", "file:b", "./b");
    insert_import(&database, "import:b-a", "file:b", "file:a", "./a");

    for index in 0..20 {
        let file_id = format!("file:t{index}");
        let path = format!("t{index}.ts");
        insert_file(&database, &file_id, &path);
        insert_import(
            &database,
            &format!("import:hub-{index}"),
            "file:hub",
            &file_id,
            &format!("./t{index}"),
        );
    }

    database
        .connection()
        .execute(
            "INSERT INTO import_references(\
               id, project_id, source_file_id, raw_specifier, kind, start_line, start_column, end_line, end_column, resolution_state\
             ) VALUES ('import:unresolved', 'project:p', 'file:hub', '@alias/missing', 'import', 99, 0, 99, 14, 'unresolved')",
            [],
        )
        .expect("unresolved import");

    let summary = CodeQualityService::new(&database)
        .analyze_project("project:p")
        .expect("quality analysis");
    assert_eq!(summary.dependency_cycles, 1);
    assert_eq!(summary.high_fan_out_files, 1);

    let findings = CodeQualityService::new(&database)
        .list_findings("project:p", Some("open"), 20)
        .expect("findings");
    let cycle = findings
        .iter()
        .find(|finding| finding.rule_id == "quality.local_dependency_cycle")
        .expect("cycle finding");
    let cycle_evidence = CodeQualityService::new(&database)
        .finding_evidence(&cycle.id, 20)
        .expect("cycle evidence");
    assert_eq!(cycle_evidence.len(), 2);
    assert!(cycle_evidence
        .iter()
        .all(|evidence| evidence.evidence_type == "dependency"));

    let fan_out = findings
        .iter()
        .find(|finding| finding.rule_id == "quality.high_local_fan_out")
        .expect("fan-out finding");
    let fan_out_evidence = CodeQualityService::new(&database)
        .finding_evidence(&fan_out.id, 100)
        .expect("fan-out evidence");
    assert_eq!(fan_out_evidence.len(), 20);
    assert!(fan_out_evidence
        .iter()
        .all(|evidence| !evidence.summary.contains("@alias/missing")));
}

fn seed_project(database: &Database) {
    database
        .connection()
        .execute(
            "INSERT INTO projects(id, root_path, display_name, path_identity)\
             VALUES ('project:p', '/tmp/quality-p', 'quality-p', '/tmp/quality-p')",
            [],
        )
        .expect("project");
}

fn insert_file(database: &Database, id: &str, path: &str) {
    database
        .connection()
        .execute(
            "INSERT INTO files(\
               id, project_id, relative_path, relative_path_identity, language, content_hash, byte_size, is_active\
             ) VALUES (?1, 'project:p', ?2, ?2, 'TypeScript', ?3, 10, 1)",
            params![id, path, format!("hash:{path}")],
        )
        .expect("file");
}

fn insert_import(
    database: &Database,
    id: &str,
    source_file_id: &str,
    target_file_id: &str,
    specifier: &str,
) {
    database
        .connection()
        .execute(
            "INSERT INTO import_references(\
               id, project_id, source_file_id, raw_specifier, kind, start_line, start_column, end_line, end_column,\
               resolution_state, resolved_target_file_id\
             ) VALUES (?1, 'project:p', ?2, ?3, 'import', 1, 0, 1, 10, 'resolved_local', ?4)",
            params![id, source_file_id, specifier, target_file_id],
        )
        .expect("import");
}
