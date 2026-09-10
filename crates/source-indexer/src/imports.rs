use std::collections::BTreeSet;

use tree_sitter::Node;

use crate::IndexedImport;

pub(crate) fn extract_imports(language: &str, source: &str, root: Node<'_>) -> Vec<IndexedImport> {
    let mut imports = Vec::new();
    visit(root, language, source, &mut imports);
    imports.sort_by(|left, right| {
        (
            left.start_line,
            left.start_column,
            &left.kind,
            &left.raw_specifier,
        )
            .cmp(&(
                right.start_line,
                right.start_column,
                &right.kind,
                &right.raw_specifier,
            ))
    });
    let mut seen = BTreeSet::new();
    imports.retain(|reference| {
        seen.insert((
            reference.kind.clone(),
            reference.raw_specifier.clone(),
            reference.start_line,
            reference.start_column,
            reference.end_line,
            reference.end_column,
        ))
    });
    imports
}

fn visit(node: Node<'_>, language: &str, source: &str, imports: &mut Vec<IndexedImport>) {
    match language {
        "TypeScript" | "TypeScript TSX" | "JavaScript" => {
            extract_javascript_like(node, source, imports)
        }
        "Python" => extract_python(node, source, imports),
        "Rust" => extract_rust(node, source, imports),
        "Go" => extract_go(node, source, imports),
        "PHP" => extract_php(node, source, imports),
        "C" | "C++" => extract_c_family(node, source, imports),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit(child, language, source, imports);
    }
}

fn extract_javascript_like(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    match node.kind() {
        "import_statement" => {
            if let Some(specifier) = node.child_by_field_name("source") {
                if let Some(raw) = literal_text(specifier, source) {
                    push(imports, "import", raw, specifier);
                }
            }
        }
        "export_statement" => {
            if let Some(specifier) = node.child_by_field_name("source") {
                if let Some(raw) = literal_text(specifier, source) {
                    push(imports, "export_from", raw, specifier);
                }
            }
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return;
            };
            if text(function, source).as_deref() != Some("require") {
                return;
            }
            let Some(arguments) = node.child_by_field_name("arguments") else {
                return;
            };
            if let Some(specifier) = find_descendant(arguments, &["string"]) {
                if let Some(raw) = literal_text(specifier, source) {
                    push(imports, "require", raw, specifier);
                }
            }
        }
        _ => {}
    }
}

fn extract_python(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    let Some(statement) = text(node, source) else {
        return;
    };
    match node.kind() {
        "import_statement" => {
            let Some(rest) = statement.trim().strip_prefix("import ") else {
                return;
            };
            for item in rest.split(',') {
                let raw = item.split_once(" as ").map_or(item, |(name, _)| name).trim();
                if !raw.is_empty() {
                    push(imports, "import", raw.to_string(), node);
                }
            }
        }
        "import_from_statement" => {
            let statement = statement.trim();
            let Some(rest) = statement.strip_prefix("from ") else {
                return;
            };
            let Some((module, _)) = rest.split_once(" import ") else {
                return;
            };
            let module = module.trim();
            if !module.is_empty() {
                push(imports, "from_import", module.to_string(), node);
            }
        }
        _ => {}
    }
}

fn extract_rust(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    if node.kind() != "use_declaration" {
        return;
    }
    let Some(statement) = text(node, source) else {
        return;
    };
    let raw = statement
        .trim()
        .strip_prefix("use ")
        .unwrap_or(statement.trim())
        .trim_end_matches(';')
        .trim();
    if !raw.is_empty() {
        push(imports, "use", raw.to_string(), node);
    }
}

fn extract_go(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    if node.kind() == "import_spec" {
        if let Some(specifier) = find_descendant(
            node,
            &["interpreted_string_literal", "raw_string_literal"],
        ) {
            if let Some(raw) = literal_text(specifier, source) {
                push(imports, "import", raw, specifier);
            }
        }
        return;
    }
    if node.kind() == "import_declaration"
        && find_descendant(node, &["import_spec"]).is_none()
    {
        if let Some(specifier) = find_descendant(
            node,
            &["interpreted_string_literal", "raw_string_literal"],
        ) {
            if let Some(raw) = literal_text(specifier, source) {
                push(imports, "import", raw, specifier);
            }
        }
    }
}

fn extract_php(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    let Some(statement) = text(node, source) else {
        return;
    };
    match node.kind() {
        "namespace_use_declaration" => {
            let raw = statement
                .trim()
                .strip_prefix("use ")
                .unwrap_or(statement.trim())
                .trim_end_matches(';')
                .trim();
            if !raw.is_empty() {
                push(imports, "use", raw.to_string(), node);
            }
        }
        "require_expression" | "require_once_expression" | "include_expression"
        | "include_once_expression" | "expression_statement" => {
            let trimmed = statement.trim().trim_end_matches(';').trim();
            for (keyword, kind) in [
                ("require_once", "require_once"),
                ("require", "require"),
                ("include_once", "include_once"),
                ("include", "include"),
            ] {
                if let Some(rest) = trimmed.strip_prefix(keyword) {
                    let raw = rest.trim().trim_start_matches('(').trim_end_matches(')').trim();
                    let raw = strip_literal_delimiters(raw);
                    if !raw.is_empty() {
                        push(imports, kind, raw, node);
                    }
                    break;
                }
            }
        }
        _ => {}
    }
}

fn extract_c_family(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    if node.kind() != "preproc_include" {
        return;
    }
    let Some(statement) = text(node, source) else {
        return;
    };
    let raw = statement
        .trim()
        .strip_prefix("#include")
        .unwrap_or(statement.trim())
        .trim();
    let raw = strip_literal_delimiters(raw);
    if !raw.is_empty() {
        push(imports, "include", raw, node);
    }
}

fn find_descendant<'tree>(node: Node<'tree>, kinds: &[&str]) -> Option<Node<'tree>> {
    if kinds.contains(&node.kind()) {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_descendant(child, kinds) {
            return Some(found);
        }
    }
    None
}

fn literal_text(node: Node<'_>, source: &str) -> Option<String> {
    let value = text(node, source)?;
    let stripped = strip_literal_delimiters(value.trim());
    (!stripped.is_empty()).then_some(stripped)
}

fn strip_literal_delimiters(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0] as char;
        let last = trimmed.as_bytes()[trimmed.len() - 1] as char;
        if matches!((first, last), ('\'', '\'') | ('"', '"') | ('`', '`') | ('<', '>')) {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

fn text(node: Node<'_>, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes()).ok().map(str::to_string)
}

fn push(imports: &mut Vec<IndexedImport>, kind: &str, raw_specifier: String, node: Node<'_>) {
    let start = node.start_position();
    let end = node.end_position();
    imports.push(IndexedImport {
        raw_specifier,
        kind: kind.to_string(),
        start_line: start.row + 1,
        start_column: start.column,
        end_line: end.row + 1,
        end_column: end.column,
    });
}
