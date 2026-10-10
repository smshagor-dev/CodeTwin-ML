use std::collections::BTreeSet;

use tree_sitter::Node;

use crate::{IndexedImport, IndexedImportBinding};

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
        "Java" => extract_java(node, source, imports),
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
                    let bindings = text(node, source)
                        .map(|statement| javascript_import_bindings(&statement))
                        .unwrap_or_default();
                    push_with_bindings(imports, "import", raw, specifier, bindings);
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
                    let bindings = require_bindings(node, source);
                    push_with_bindings(imports, "require", raw, specifier, bindings);
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
                let item = item.trim();
                let (raw, local) = item
                    .split_once(" as ")
                    .map(|(name, alias)| (name.trim(), alias.trim()))
                    .unwrap_or_else(|| {
                        let name = item.trim();
                        let local = name.split('.').next().unwrap_or(name);
                        (name, local)
                    });
                if !raw.is_empty() && !local.is_empty() {
                    push_with_bindings(
                        imports,
                        "import",
                        raw.to_string(),
                        node,
                        vec![IndexedImportBinding {
                            local_name: local.to_string(),
                            imported_name: "*".to_string(),
                        }],
                    );
                }
            }
        }
        "import_from_statement" => {
            let statement = statement.trim();
            let Some(rest) = statement.strip_prefix("from ") else {
                return;
            };
            let Some((module, names)) = rest.split_once(" import ") else {
                return;
            };
            let module = module.trim();
            if !module.is_empty() {
                let bindings = python_from_bindings(names);
                push_with_bindings(imports, "from_import", module.to_string(), node, bindings);
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
        if let Some(specifier) =
            find_descendant(node, &["interpreted_string_literal", "raw_string_literal"])
        {
            if let Some(raw) = literal_text(specifier, source) {
                push(imports, "import", raw, specifier);
            }
        }
        return;
    }
    if node.kind() == "import_declaration" && find_descendant(node, &["import_spec"]).is_none() {
        if let Some(specifier) =
            find_descendant(node, &["interpreted_string_literal", "raw_string_literal"])
        {
            if let Some(raw) = literal_text(specifier, source) {
                push(imports, "import", raw, specifier);
            }
        }
    }
}

/// `import a.b.C;`, `import a.b.*;` and `import static a.b.C.member;`.
fn extract_java(node: Node<'_>, source: &str, imports: &mut Vec<IndexedImport>) {
    if node.kind() != "import_declaration" {
        return;
    }
    let Some(statement) = text(node, source) else {
        return;
    };
    let body = statement
        .trim()
        .trim_start_matches("import")
        .trim()
        .trim_end_matches(';')
        .trim();
    let (kind, target) = match body.strip_prefix("static") {
        Some(rest) if rest.starts_with(char::is_whitespace) => ("static_import", rest.trim()),
        _ => ("import", body),
    };
    let target: String = target.chars().filter(|c| !c.is_whitespace()).collect();
    if !target.is_empty() {
        push(imports, kind, target, node);
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
                let expanded = php_class_use_imports(raw);
                if expanded.is_empty() {
                    push(imports, "use", raw.to_string(), node);
                } else {
                    for (specifier, binding) in expanded {
                        push_with_bindings(imports, "use", specifier, node, vec![binding]);
                    }
                }
            }
        }
        "require_expression"
        | "require_once_expression"
        | "include_expression"
        | "include_once_expression"
        | "expression_statement" => {
            let trimmed = statement.trim().trim_end_matches(';').trim();
            for (keyword, kind) in [
                ("require_once", "require_once"),
                ("require", "require"),
                ("include_once", "include_once"),
                ("include", "include"),
            ] {
                if let Some(rest) = trimmed.strip_prefix(keyword) {
                    let raw = rest
                        .trim()
                        .trim_start_matches('(')
                        .trim_end_matches(')')
                        .trim();
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

fn php_class_use_imports(raw: &str) -> Vec<(String, IndexedImportBinding)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }

    let mut imports = Vec::new();
    if let (Some(open), Some(close)) = (raw.find('{'), raw.rfind('}')) {
        if close > open {
            let prefix = raw[..open]
                .trim()
                .trim_start_matches('\\')
                .trim_end_matches('\\');
            let inside = &raw[open + 1..close];
            for item in inside.split(',') {
                if let Some(reference) = php_class_use_item(Some(prefix), item) {
                    imports.push(reference);
                }
            }
            return imports;
        }
    }

    for item in raw.split(',') {
        if let Some(reference) = php_class_use_item(None, item) {
            imports.push(reference);
        }
    }
    imports
}

fn php_class_use_item(
    prefix: Option<&str>,
    raw_item: &str,
) -> Option<(String, IndexedImportBinding)> {
    let item = raw_item.trim();
    if item.is_empty() {
        return None;
    }
    let lower = item.to_ascii_lowercase();
    if lower.starts_with("function ") || lower.starts_with("const ") {
        return None;
    }

    let (qualified, alias) = php_split_alias(item);
    let qualified = qualified.trim().trim_start_matches('\\');
    if qualified.is_empty() {
        return None;
    }
    let specifier = if let Some(prefix) = prefix.filter(|value| !value.is_empty()) {
        format!(
            "{}\\{}",
            prefix.trim_end_matches('\\'),
            qualified.trim_start_matches('\\')
        )
    } else {
        qualified.to_string()
    };
    let imported = qualified.rsplit('\\').next()?.trim();
    let local = alias.unwrap_or(imported).trim();
    if !is_identifier(imported) || !is_identifier(local) {
        return None;
    }
    Some((
        specifier,
        IndexedImportBinding {
            local_name: local.to_string(),
            imported_name: imported.to_string(),
        },
    ))
}

fn php_split_alias(value: &str) -> (&str, Option<&str>) {
    let lower = value.to_ascii_lowercase();
    if let Some(index) = lower.rfind(" as ") {
        (&value[..index], Some(&value[index + 4..]))
    } else {
        (value, None)
    }
}

fn javascript_import_bindings(statement: &str) -> Vec<IndexedImportBinding> {
    let trimmed = statement.trim();
    let Some(rest) = trimmed.strip_prefix("import ") else {
        return Vec::new();
    };
    let Some((clause, _source)) = rest.rsplit_once(" from ") else {
        return Vec::new();
    };
    let clause = clause.trim();
    let mut bindings = Vec::new();

    if let Some(namespace) = clause.strip_prefix("* as ") {
        let local = namespace.trim();
        if is_identifier(local) {
            bindings.push(IndexedImportBinding {
                local_name: local.to_string(),
                imported_name: "*".to_string(),
            });
        }
        return bindings;
    }

    let mut remaining = clause;
    if !remaining.starts_with('{') {
        let default = remaining.split(',').next().map(str::trim).unwrap_or("");
        if is_identifier(default) {
            bindings.push(IndexedImportBinding {
                local_name: default.to_string(),
                imported_name: "default".to_string(),
            });
        }
        remaining = remaining
            .split_once(',')
            .map(|(_, tail)| tail.trim())
            .unwrap_or("");
    }

    if let Some(named) = remaining
        .strip_prefix('{')
        .and_then(|value| value.rsplit_once('}').map(|(inside, _)| inside))
    {
        for item in named.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (imported, local) = item
                .split_once(" as ")
                .map(|(name, alias)| (name.trim(), alias.trim()))
                .unwrap_or((item, item));
            if is_identifier(imported) && is_identifier(local) {
                bindings.push(IndexedImportBinding {
                    local_name: local.to_string(),
                    imported_name: imported.to_string(),
                });
            }
        }
    }
    bindings
}

fn require_bindings(node: Node<'_>, source: &str) -> Vec<IndexedImportBinding> {
    let Some(parent) = node.parent() else {
        return Vec::new();
    };
    if parent.kind() != "variable_declarator" {
        return Vec::new();
    }
    let Some(name) = parent.child_by_field_name("name") else {
        return Vec::new();
    };
    let Some(local) = text(name, source).map(|value| value.trim().to_string()) else {
        return Vec::new();
    };
    if !is_identifier(&local) {
        return Vec::new();
    }
    vec![IndexedImportBinding {
        local_name: local,
        imported_name: "default".to_string(),
    }]
}

fn python_from_bindings(names: &str) -> Vec<IndexedImportBinding> {
    let names = names
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    let mut bindings = Vec::new();
    for item in names.split(',') {
        let item = item.trim();
        if item.is_empty() || item == "*" {
            continue;
        }
        let (imported, local) = item
            .split_once(" as ")
            .map(|(name, alias)| (name.trim(), alias.trim()))
            .unwrap_or((item, item));
        if is_identifier(imported) && is_identifier(local) {
            bindings.push(IndexedImportBinding {
                local_name: local.to_string(),
                imported_name: imported.to_string(),
            });
        }
    }
    bindings
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
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
        if matches!(
            (first, last),
            ('\'', '\'') | ('"', '"') | ('`', '`') | ('<', '>')
        ) {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

fn text(node: Node<'_>, source: &str) -> Option<String> {
    node.utf8_text(source.as_bytes()).ok().map(str::to_string)
}

fn push(imports: &mut Vec<IndexedImport>, kind: &str, raw_specifier: String, node: Node<'_>) {
    push_with_bindings(imports, kind, raw_specifier, node, Vec::new());
}

fn push_with_bindings(
    imports: &mut Vec<IndexedImport>,
    kind: &str,
    raw_specifier: String,
    node: Node<'_>,
    bindings: Vec<IndexedImportBinding>,
) {
    let start = node.start_position();
    let end = node.end_position();
    imports.push(IndexedImport {
        raw_specifier,
        bindings,
        kind: kind.to_string(),
        start_line: start.row + 1,
        start_column: start.column,
        end_line: end.row + 1,
        end_column: end.column,
    });
}

#[cfg(test)]
mod tests {
    use tree_sitter::Parser;

    use super::extract_imports;

    #[test]
    fn expands_grouped_and_multi_php_class_imports() {
        let source = r#"<?php
use App\Http\Controllers\{UserController, AdminController as Admin};
use App\Http\Requests\StoreUserRequest, App\Http\Requests\UpdateUserRequest as UpdateRequest;
use App\Support\{Thing, function helper, const FLAG};
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("language");
        let tree = parser.parse(source, None).expect("tree");
        let imports = extract_imports("PHP", source, tree.root_node());

        let expected = [
            (
                "App\\Http\\Controllers\\UserController",
                "UserController",
                "UserController",
            ),
            (
                "App\\Http\\Controllers\\AdminController",
                "Admin",
                "AdminController",
            ),
            (
                "App\\Http\\Requests\\StoreUserRequest",
                "StoreUserRequest",
                "StoreUserRequest",
            ),
            (
                "App\\Http\\Requests\\UpdateUserRequest",
                "UpdateRequest",
                "UpdateUserRequest",
            ),
            ("App\\Support\\Thing", "Thing", "Thing"),
        ];

        for (specifier, local, imported) in expected {
            let reference = imports
                .iter()
                .find(|reference| reference.raw_specifier == specifier)
                .unwrap_or_else(|| panic!("missing import {specifier}"));
            assert_eq!(reference.bindings.len(), 1);
            assert_eq!(reference.bindings[0].local_name, local);
            assert_eq!(reference.bindings[0].imported_name, imported);
        }

        assert!(!imports.iter().any(|reference| {
            reference
                .bindings
                .iter()
                .any(|binding| matches!(binding.local_name.as_str(), "helper" | "FLAG"))
        }));
    }
}
