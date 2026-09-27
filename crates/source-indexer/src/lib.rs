mod imports;
mod routes;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};
use walkdir::{DirEntry, WalkDir};

const MAX_SOURCE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_PROJECT_SOURCE_FILES: usize = 20_000;
const MAX_PROJECT_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROJECT_INDEX_ELAPSED: Duration = Duration::from_secs(120);
const TYPESCRIPT_DEFINITIONS_QUERY: &str = include_str!("../queries/typescript.scm");
pub const INDEXER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const QUERY_VERSION: &str = "definitions-v2-imports-v3-routes-v45-handlers-v34";

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("project root does not exist: {0}")]
    MissingRoot(String),
    #[error("project root is not a directory: {0}")]
    NotDirectory(String),
    #[error("source index resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("source index cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseState {
    Parsed,
    ParsedWithErrors,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedSymbol {
    pub kind: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub parent_scope: Option<String>,
    pub signature: Option<String>,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedImportBinding {
    pub local_name: String,
    pub imported_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedImport {
    pub raw_specifier: String,
    pub bindings: Vec<IndexedImportBinding>,
    pub kind: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedRouteParameter {
    pub name: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedHandlerInput {
    pub handler_name: String,
    pub parameters: Vec<IndexedRouteParameter>,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedRouteMount {
    pub framework: String,
    pub parent_router: String,
    pub mounted_binding: String,
    pub prefix: String,
    #[serde(default = "default_route_prefix_mode")]
    pub prefix_mode: String,
    pub start_line: usize,
    pub end_line: usize,
}

fn default_route_prefix_mode() -> String {
    "prepend".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedRoute {
    pub framework: String,
    pub router_name: String,
    #[serde(default)]
    pub router_prefix: String,
    pub http_method: String,
    pub path_template: String,
    pub handler_name: Option<String>,
    pub parameters: Vec<IndexedRouteParameter>,
    pub request_content_type: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedFile {
    pub relative_path: String,
    pub language: String,
    pub content_hash: String,
    pub byte_size: u64,
    pub ast_root_kind: String,
    pub parse_state: ParseState,
    pub symbols: Vec<IndexedSymbol>,
    pub imports: Vec<IndexedImport>,
    pub routes: Vec<IndexedRoute>,
    pub route_mounts: Vec<IndexedRouteMount>,
    pub handler_inputs: Vec<IndexedHandlerInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedFile {
    pub relative_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IndexResult {
    pub indexed_files: Vec<IndexedFile>,
    pub unchanged_files: Vec<String>,
    pub skipped_files: Vec<SkippedFile>,
}

impl IndexResult {
    pub fn symbol_count(&self) -> usize {
        self.indexed_files
            .iter()
            .map(|file| file.symbols.len())
            .sum()
    }

    pub fn parse_error_count(&self) -> usize {
        self.indexed_files
            .iter()
            .filter(|file| file.parse_state == ParseState::ParsedWithErrors)
            .count()
    }

    pub fn import_count(&self) -> usize {
        self.indexed_files
            .iter()
            .map(|file| file.imports.len())
            .sum()
    }
}

struct LanguageSpec {
    name: &'static str,
    language: Language,
    definitions_query: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct IndexLimits {
    max_file_bytes: u64,
    max_source_files: usize,
    max_total_source_bytes: u64,
    max_elapsed: Duration,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: MAX_SOURCE_BYTES,
            max_source_files: MAX_PROJECT_SOURCE_FILES,
            max_total_source_bytes: MAX_PROJECT_SOURCE_BYTES,
            max_elapsed: MAX_PROJECT_INDEX_ELAPSED,
        }
    }
}

pub fn index_project(
    root: impl AsRef<Path>,
    known_hashes: &BTreeMap<String, String>,
) -> Result<IndexResult, IndexError> {
    index_project_with_limits(root.as_ref(), known_hashes, IndexLimits::default())
}

pub fn index_project_with_cancel(
    root: impl AsRef<Path>,
    known_hashes: &BTreeMap<String, String>,
    cancelled: &AtomicBool,
) -> Result<IndexResult, IndexError> {
    index_project_with_limits_and_cancel(
        root.as_ref(),
        known_hashes,
        IndexLimits::default(),
        Some(cancelled),
    )
}

fn index_project_with_limits(
    root: &Path,
    known_hashes: &BTreeMap<String, String>,
    limits: IndexLimits,
) -> Result<IndexResult, IndexError> {
    index_project_with_limits_and_cancel(root, known_hashes, limits, None)
}

fn index_project_with_limits_and_cancel(
    root: &Path,
    known_hashes: &BTreeMap<String, String>,
    limits: IndexLimits,
    cancelled: Option<&AtomicBool>,
) -> Result<IndexResult, IndexError> {
    if !root.exists() {
        return Err(IndexError::MissingRoot(root.display().to_string()));
    }
    if !root.is_dir() {
        return Err(IndexError::NotDirectory(root.display().to_string()));
    }

    let mut result = IndexResult::default();
    let mut source_files_seen = 0usize;
    let mut source_bytes_seen = 0u64;
    let started = Instant::now();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !should_prune(entry));

    for entry in walker.filter_map(Result::ok) {
        if cancelled.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return Err(IndexError::Cancelled);
        }
        if started.elapsed() > limits.max_elapsed {
            return Err(IndexError::ResourceLimit(format!(
                "elapsed_time_ms>{}",
                limits.max_elapsed.as_millis()
            )));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(spec) = language_spec(path) else {
            continue;
        };
        source_files_seen = source_files_seen.saturating_add(1);
        if source_files_seen > limits.max_source_files {
            return Err(IndexError::ResourceLimit(format!(
                "source_file_count>{}; last_path={}",
                limits.max_source_files,
                normalized_relative_path(root, path)
            )));
        }
        let relative_path = normalized_relative_path(root, path);
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                result.skipped_files.push(SkippedFile {
                    relative_path,
                    reason: format!("metadata_error:{error}"),
                });
                continue;
            }
        };
        if metadata.len() > limits.max_file_bytes {
            result.skipped_files.push(SkippedFile {
                relative_path,
                reason: format!("source_too_large:{}", metadata.len()),
            });
            continue;
        }
        source_bytes_seen = source_bytes_seen
            .checked_add(metadata.len())
            .ok_or_else(|| IndexError::ResourceLimit("source_byte_counter_overflow".to_string()))?;
        if source_bytes_seen > limits.max_total_source_bytes {
            return Err(IndexError::ResourceLimit(format!(
                "total_source_bytes>{}; last_path={relative_path}",
                limits.max_total_source_bytes
            )));
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                result.skipped_files.push(SkippedFile {
                    relative_path,
                    reason: format!("read_error:{error}"),
                });
                continue;
            }
        };
        let content_hash = sha256_hex(&bytes);
        if known_hashes
            .get(&relative_path)
            .is_some_and(|known| known == &content_hash)
        {
            result.unchanged_files.push(relative_path);
            continue;
        }
        let source = match String::from_utf8(bytes) {
            Ok(source) => source,
            Err(_) => {
                result.skipped_files.push(SkippedFile {
                    relative_path,
                    reason: "invalid_utf8".to_string(),
                });
                continue;
            }
        };
        match parse_source(
            relative_path.clone(),
            &source,
            spec,
            content_hash,
            metadata.len(),
        ) {
            Ok(indexed) => result.indexed_files.push(indexed),
            Err(reason) => result.skipped_files.push(SkippedFile {
                relative_path,
                reason,
            }),
        }
    }

    result
        .indexed_files
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    result.unchanged_files.sort();
    result
        .skipped_files
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(result)
}

fn parse_source(
    relative_path: String,
    source: &str,
    spec: LanguageSpec,
    content_hash: String,
    byte_size: u64,
) -> Result<IndexedFile, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&spec.language)
        .map_err(|error| format!("parser_language_error:{error}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "parser_cancelled".to_string())?;
    let parse_state = if tree.root_node().has_error() {
        ParseState::ParsedWithErrors
    } else {
        ParseState::Parsed
    };
    let query = Query::new(&spec.language, spec.definitions_query)
        .map_err(|error| format!("definition_query_error:{error}"))?;
    let symbols = collect_symbols(source, &tree, &query);
    let imports = imports::extract_imports(spec.name, source, tree.root_node());
    let (routes, route_mounts, handler_inputs) =
        routes::extract_routes(spec.name, &relative_path, source, tree.root_node());

    Ok(IndexedFile {
        relative_path,
        language: spec.name.to_string(),
        content_hash,
        byte_size,
        ast_root_kind: tree.root_node().kind().to_string(),
        parse_state,
        symbols,
        imports,
        routes,
        route_mounts,
        handler_inputs,
    })
}

#[derive(Debug)]
struct CapturedSymbol {
    kind: String,
    name: String,
    signature: Option<String>,
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
    start_byte: usize,
    end_byte: usize,
}

fn collect_symbols(source: &str, tree: &tree_sitter::Tree, query: &Query) -> Vec<IndexedSymbol> {
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
    let mut captured = Vec::new();
    let mut seen = BTreeSet::new();

    while let Some(query_match) = matches.next() {
        let mut name_node = None;
        let mut definition = None;
        for capture in query_match.captures {
            let capture_name = capture_names[capture.index as usize];
            if capture_name == "name" {
                name_node = Some(capture.node);
            } else if let Some(kind) = capture_name.strip_prefix("definition.") {
                definition = Some((kind, capture.node));
            }
        }
        let (Some(name_node), Some((kind, definition_node))) = (name_node, definition) else {
            continue;
        };
        let Ok(name) = name_node.utf8_text(source.as_bytes()) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let identity = (
            kind.to_string(),
            name.to_string(),
            definition_node.start_byte(),
            definition_node.end_byte(),
        );
        if !seen.insert(identity) {
            continue;
        }
        let start = definition_node.start_position();
        let end = definition_node.end_position();
        captured.push(CapturedSymbol {
            kind: kind.to_string(),
            name: name.to_string(),
            signature: declaration_signature(source, definition_node),
            start_line: start.row + 1,
            start_column: start.column,
            end_line: end.row + 1,
            end_column: end.column,
            start_byte: definition_node.start_byte(),
            end_byte: definition_node.end_byte(),
        });
    }

    captured.sort_by(|left, right| {
        (left.start_byte, left.end_byte, &left.name).cmp(&(
            right.start_byte,
            right.end_byte,
            &right.name,
        ))
    });
    let parents: Vec<Option<usize>> = (0..captured.len())
        .map(|child_index| structural_parent(&captured, child_index))
        .collect();
    let mut qualified_names = Vec::with_capacity(captured.len());
    for (index, symbol) in captured.iter().enumerate() {
        let qualified = parents[index]
            .and_then(|parent| qualified_names.get(parent))
            .map_or_else(
                || symbol.name.clone(),
                |parent: &String| format!("{parent}.{}", symbol.name),
            );
        qualified_names.push(qualified);
    }

    captured
        .into_iter()
        .enumerate()
        .map(|(index, symbol)| IndexedSymbol {
            kind: symbol.kind,
            name: symbol.name,
            qualified_name: Some(qualified_names[index].clone()),
            parent_scope: parents[index].map(|parent| qualified_names[parent].clone()),
            signature: symbol.signature,
            start_line: symbol.start_line,
            start_column: symbol.start_column,
            end_line: symbol.end_line,
            end_column: symbol.end_column,
        })
        .collect()
}

fn structural_parent(symbols: &[CapturedSymbol], child_index: usize) -> Option<usize> {
    let child = &symbols[child_index];
    symbols
        .iter()
        .enumerate()
        .filter(|(index, candidate)| {
            *index != child_index
                && candidate.start_byte <= child.start_byte
                && candidate.end_byte >= child.end_byte
                && (candidate.start_byte != child.start_byte
                    || candidate.end_byte != child.end_byte)
        })
        .min_by_key(|(_, candidate)| candidate.end_byte.saturating_sub(candidate.start_byte))
        .map(|(index, _)| index)
}

fn declaration_signature(source: &str, node: tree_sitter::Node<'_>) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    let first_line = text.lines().next().unwrap_or(text);
    let head = first_line
        .split_once('{')
        .map_or(first_line, |(head, _)| head)
        .split_once("=>")
        .map_or(first_line, |(head, _)| head)
        .trim()
        .trim_end_matches(';')
        .trim();
    if head.is_empty() {
        None
    } else {
        Some(head.split_whitespace().collect::<Vec<_>>().join(" "))
    }
}

fn language_spec(path: &Path) -> Option<LanguageSpec> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "ts" => Some(LanguageSpec {
            name: "TypeScript",
            language: tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            definitions_query: TYPESCRIPT_DEFINITIONS_QUERY,
        }),
        "tsx" => Some(LanguageSpec {
            name: "TypeScript TSX",
            language: tree_sitter_typescript::LANGUAGE_TSX.into(),
            definitions_query: TYPESCRIPT_DEFINITIONS_QUERY,
        }),
        "js" | "jsx" | "mjs" | "cjs" => Some(LanguageSpec {
            name: "JavaScript",
            language: tree_sitter_javascript::LANGUAGE.into(),
            definitions_query: tree_sitter_javascript::TAGS_QUERY,
        }),
        "py" => Some(LanguageSpec {
            name: "Python",
            language: tree_sitter_python::LANGUAGE.into(),
            definitions_query: tree_sitter_python::TAGS_QUERY,
        }),
        "rs" => Some(LanguageSpec {
            name: "Rust",
            language: tree_sitter_rust::LANGUAGE.into(),
            definitions_query: tree_sitter_rust::TAGS_QUERY,
        }),
        "go" => Some(LanguageSpec {
            name: "Go",
            language: tree_sitter_go::LANGUAGE.into(),
            definitions_query: tree_sitter_go::TAGS_QUERY,
        }),
        "c" | "h" => Some(LanguageSpec {
            name: "C",
            language: tree_sitter_c::LANGUAGE.into(),
            definitions_query: tree_sitter_c::TAGS_QUERY,
        }),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => Some(LanguageSpec {
            name: "C++",
            language: tree_sitter_cpp::LANGUAGE.into(),
            definitions_query: tree_sitter_cpp::TAGS_QUERY,
        }),
        "php" => Some(LanguageSpec {
            name: "PHP",
            language: tree_sitter_php::LANGUAGE_PHP.into(),
            definitions_query: tree_sitter_php::TAGS_QUERY,
        }),
        _ => None,
    }
}

fn should_prune(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return false;
    }
    matches!(
        entry.file_name().to_str(),
        Some(
            ".git"
                | "node_modules"
                | "target"
                | ".venv"
                | "venv"
                | "dist"
                | "build"
                | "coverage"
                | ".next"
                | ".turbo"
                | ".cache"
        )
    )
}

fn normalized_relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path, sync::atomic::AtomicBool, time::Duration};

    use tempfile::tempdir;

    use super::{
        index_project, index_project_with_cancel, index_project_with_limits, language_spec,
        parse_source, sha256_hex, IndexError, IndexLimits, IndexedFile, ParseState,
    };

    fn parse_fixture(path: &str, source: &str) -> IndexedFile {
        let spec = language_spec(Path::new(path)).expect("language spec");
        parse_source(
            path.to_string(),
            source,
            spec,
            sha256_hex(source.as_bytes()),
            source.len() as u64,
        )
        .expect("parse source")
    }

    fn assert_has_symbol(indexed: &IndexedFile, kind: &str, name: &str) {
        assert!(
            indexed
                .symbols
                .iter()
                .any(|symbol| symbol.kind == kind && symbol.name == name),
            "missing {kind} symbol {name} in {}: {:?}",
            indexed.relative_path,
            indexed.symbols
        );
    }

    #[test]
    fn extracts_definition_symbols_across_initial_languages() {
        let cases = [
            (
                "sample.ts",
                "export function add(a: number, b: number): number { return a + b; }",
                "add",
            ),
            ("sample.js", "function add(a, b) { return a + b; }", "add"),
            ("sample.py", "def add(a, b):\n    return a + b\n", "add"),
            (
                "sample.rs",
                "fn add(a: i32, b: i32) -> i32 { a + b }",
                "add",
            ),
            (
                "sample.go",
                "package sample\nfunc add(a int, b int) int { return a + b }",
                "add",
            ),
            ("sample.c", "int add(int a, int b) { return a + b; }", "add"),
            (
                "sample.cpp",
                "int add(int a, int b) { return a + b; }",
                "add",
            ),
            (
                "sample.php",
                "<?php function add($a, $b) { return $a + $b; }",
                "add",
            ),
        ];
        for (path, source, expected_name) in cases {
            let indexed = parse_fixture(path, source);
            assert_eq!(indexed.parse_state, ParseState::Parsed, "{path}");
            assert!(indexed
                .symbols
                .iter()
                .any(|symbol| symbol.name == expected_name));
        }
    }

    #[test]
    fn extracts_common_typescript_and_tsx_definitions() {
        let typescript = r#"
export function exportedFunction(): number { return 1; }
async function asyncFunction(): Promise<number> { return 2; }
export class Service {
    run(): void {}
}
export interface Config { enabled: boolean; }
export type Result = { ok: boolean };
const localArrow = (value: number) => value + 1;
export const exportedArrow = async () => 3;
"#;
        let indexed = parse_fixture("sample.ts", typescript);
        assert_eq!(indexed.parse_state, ParseState::Parsed);
        assert_has_symbol(&indexed, "function", "exportedFunction");
        assert_has_symbol(&indexed, "function", "asyncFunction");
        assert_has_symbol(&indexed, "class", "Service");
        assert_has_symbol(&indexed, "method", "run");
        assert_has_symbol(&indexed, "interface", "Config");
        assert_has_symbol(&indexed, "type", "Result");
        assert_has_symbol(&indexed, "function", "localArrow");
        assert_has_symbol(&indexed, "function", "exportedArrow");
        let run = indexed
            .symbols
            .iter()
            .find(|symbol| symbol.name == "run")
            .expect("run");
        assert_eq!(run.parent_scope.as_deref(), Some("Service"));
        assert_eq!(run.qualified_name.as_deref(), Some("Service.run"));

        let tsx = r#"
export interface Props { label: string; }
export const Button = (props: Props) => <button>{props.label}</button>;
export class View {
    render(): JSX.Element { return <Button label="ok" />; }
}
"#;
        let indexed = parse_fixture("sample.tsx", tsx);
        assert_eq!(indexed.parse_state, ParseState::Parsed);
        assert_has_symbol(&indexed, "interface", "Props");
        assert_has_symbol(&indexed, "function", "Button");
        assert_has_symbol(&indexed, "class", "View");
        assert_has_symbol(&indexed, "method", "render");
    }

    #[test]
    fn javascript_common_definitions_remain_indexed() {
        let source = r#"
export function exportedFunction() { return 1; }
async function asyncFunction() { return 2; }
class Service { run() { return true; } }
const localArrow = (value) => value + 1;
export const exportedArrow = async () => 3;
"#;
        let indexed = parse_fixture("sample.js", source);
        assert_eq!(indexed.parse_state, ParseState::Parsed);
        assert_has_symbol(&indexed, "function", "exportedFunction");
        assert_has_symbol(&indexed, "function", "asyncFunction");
        assert_has_symbol(&indexed, "class", "Service");
        assert_has_symbol(&indexed, "method", "run");
        assert_has_symbol(&indexed, "function", "localArrow");
        assert_has_symbol(&indexed, "function", "exportedArrow");
    }

    #[test]
    fn extracts_import_references_from_supported_syntax() {
        let ts = parse_fixture(
            "sample.ts",
            "import { x } from './x'; export { y } from \"../y\"; const z = require('pkg');",
        );
        assert!(ts
            .imports
            .iter()
            .any(|item| item.kind == "import" && item.raw_specifier == "./x"));
        assert!(ts
            .imports
            .iter()
            .any(|item| item.kind == "export_from" && item.raw_specifier == "../y"));
        assert!(ts
            .imports
            .iter()
            .any(|item| item.kind == "require" && item.raw_specifier == "pkg"));

        let python = parse_fixture(
            "sample.py",
            "import os, pkg.mod as mod\nfrom .local import value\n",
        );
        assert!(python.imports.iter().any(|item| item.raw_specifier == "os"));
        assert!(python
            .imports
            .iter()
            .any(|item| item.raw_specifier == "pkg.mod"));
        assert!(python
            .imports
            .iter()
            .any(|item| item.raw_specifier == ".local"));

        let rust = parse_fixture("sample.rs", "use crate::module::Thing;\nfn main() {}\n");
        assert!(rust
            .imports
            .iter()
            .any(|item| item.raw_specifier == "crate::module::Thing"));
        let go = parse_fixture(
            "sample.go",
            "package sample\nimport \"fmt\"\nfunc main() {}\n",
        );
        assert!(go.imports.iter().any(|item| item.raw_specifier == "fmt"));
        let c = parse_fixture(
            "sample.c",
            "#include <stdio.h>\nint main(void) { return 0; }\n",
        );
        assert!(c.imports.iter().any(|item| item.raw_specifier == "stdio.h"));
    }

    #[test]
    fn skips_unchanged_files_by_content_hash() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join("sample.ts"),
            "export function value() { return 1; }",
        )
        .expect("write fixture");
        let first = index_project(dir.path(), &BTreeMap::new()).expect("first index");
        assert_eq!(first.indexed_files.len(), 1);
        let indexed = &first.indexed_files[0];
        let known = BTreeMap::from([(indexed.relative_path.clone(), indexed.content_hash.clone())]);
        let second = index_project(dir.path(), &known).expect("second index");
        assert!(second.indexed_files.is_empty());
        assert_eq!(second.unchanged_files, vec!["sample.ts"]);
    }

    #[test]
    fn project_source_file_budget_fails_closed_without_partial_result() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.js"), "function a() { return 1; }").expect("a");
        fs::write(dir.path().join("b.js"), "function b() { return 2; }").expect("b");

        let error = index_project_with_limits(
            dir.path(),
            &BTreeMap::new(),
            IndexLimits {
                max_file_bytes: 1_024,
                max_source_files: 1,
                max_total_source_bytes: 4_096,
                max_elapsed: Duration::from_secs(5),
            },
        )
        .expect_err("file-count limit must fail the whole index");

        assert!(matches!(error, IndexError::ResourceLimit(_)));
        assert!(error.to_string().contains("source_file_count"));
    }

    #[test]
    fn project_source_byte_budget_fails_closed_without_partial_result() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.js"), "function a() { return 1; }").expect("a");
        fs::write(dir.path().join("b.js"), "function b() { return 2; }").expect("b");

        let error = index_project_with_limits(
            dir.path(),
            &BTreeMap::new(),
            IndexLimits {
                max_file_bytes: 1_024,
                max_source_files: 10,
                max_total_source_bytes: 30,
                max_elapsed: Duration::from_secs(5),
            },
        )
        .expect_err("byte limit must fail the whole index");

        assert!(matches!(error, IndexError::ResourceLimit(_)));
        assert!(error.to_string().contains("total_source_bytes"));
    }

    #[test]
    fn project_elapsed_budget_fails_closed_without_partial_result() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.js"), "function a() { return 1; }").expect("a");

        let error = index_project_with_limits(
            dir.path(),
            &BTreeMap::new(),
            IndexLimits {
                max_file_bytes: 1_024,
                max_source_files: 10,
                max_total_source_bytes: 4_096,
                max_elapsed: Duration::ZERO,
            },
        )
        .expect_err("elapsed-time limit must fail the whole index");

        assert!(matches!(error, IndexError::ResourceLimit(_)));
        assert!(error.to_string().contains("elapsed_time_ms"));
    }

    #[test]
    fn explicit_cancellation_fails_closed_before_partial_result() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.js"), "function a() { return 1; }").expect("a");
        let cancelled = AtomicBool::new(true);

        let error = index_project_with_cancel(dir.path(), &BTreeMap::new(), &cancelled)
            .expect_err("cancelled index must not return a partial result");
        assert!(matches!(error, IndexError::Cancelled));
    }

    #[test]
    fn prunes_dependency_and_build_directories() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src");
        fs::create_dir_all(dir.path().join("node_modules/pkg")).expect("node_modules");
        fs::write(
            dir.path().join("src/main.js"),
            "function local() { return true; }",
        )
        .expect("source");
        fs::write(
            dir.path().join("node_modules/pkg/index.js"),
            "function dependency() { return true; }",
        )
        .expect("dependency");
        let result = index_project(dir.path(), &BTreeMap::new()).expect("index");
        assert_eq!(result.indexed_files.len(), 1);
        assert_eq!(result.indexed_files[0].relative_path, "src/main.js");
    }
}
