use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};
use walkdir::{DirEntry, WalkDir};

const MAX_SOURCE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("project root does not exist: {0}")]
    MissingRoot(String),
    #[error("project root is not a directory: {0}")]
    NotDirectory(String),
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
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
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
        self.indexed_files.iter().map(|file| file.symbols.len()).sum()
    }

    pub fn parse_error_count(&self) -> usize {
        self.indexed_files
            .iter()
            .filter(|file| file.parse_state == ParseState::ParsedWithErrors)
            .count()
    }
}

struct LanguageSpec {
    name: &'static str,
    language: Language,
    tags_query: &'static str,
}

pub fn index_project(
    root: impl AsRef<Path>,
    known_hashes: &BTreeMap<String, String>,
) -> Result<IndexResult, IndexError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(IndexError::MissingRoot(root.display().to_string()));
    }
    if !root.is_dir() {
        return Err(IndexError::NotDirectory(root.display().to_string()));
    }

    let mut result = IndexResult::default();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !should_prune(entry));

    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let Some(spec) = language_spec(path) else {
            continue;
        };
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

        if metadata.len() > MAX_SOURCE_BYTES {
            result.skipped_files.push(SkippedFile {
                relative_path,
                reason: format!("source_too_large:{}", metadata.len()),
            });
            continue;
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

        match parse_source(relative_path.clone(), &source, spec, content_hash, metadata.len()) {
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
    let query = Query::new(&spec.language, spec.tags_query)
        .map_err(|error| format!("tag_query_error:{error}"))?;
    let symbols = collect_symbols(source, &tree, &query);

    Ok(IndexedFile {
        relative_path,
        language: spec.name.to_string(),
        content_hash,
        byte_size,
        ast_root_kind: tree.root_node().kind().to_string(),
        parse_state,
        symbols,
    })
}

fn collect_symbols(source: &str, tree: &tree_sitter::Tree, query: &Query) -> Vec<IndexedSymbol> {
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
    let mut symbols = Vec::new();
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

        let start = definition_node.start_position();
        let end = definition_node.end_position();
        let identity = (
            kind.to_string(),
            name.to_string(),
            definition_node.start_byte(),
            definition_node.end_byte(),
        );
        if !seen.insert(identity) {
            continue;
        }

        symbols.push(IndexedSymbol {
            kind: kind.to_string(),
            name: name.to_string(),
            start_line: start.row + 1,
            start_column: start.column,
            end_line: end.row + 1,
            end_column: end.column,
        });
    }

    symbols.sort_by(|left, right| {
        (left.start_line, left.start_column, &left.name).cmp(&(
            right.start_line,
            right.start_column,
            &right.name,
        ))
    });
    symbols
}

fn language_spec(path: &Path) -> Option<LanguageSpec> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "ts" => Some(LanguageSpec {
            name: "TypeScript",
            language: tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            tags_query: tree_sitter_typescript::TAGS_QUERY,
        }),
        "tsx" => Some(LanguageSpec {
            name: "TypeScript TSX",
            language: tree_sitter_typescript::LANGUAGE_TSX.into(),
            tags_query: tree_sitter_typescript::TAGS_QUERY,
        }),
        "js" | "jsx" | "mjs" | "cjs" => Some(LanguageSpec {
            name: "JavaScript",
            language: tree_sitter_javascript::LANGUAGE.into(),
            tags_query: tree_sitter_javascript::TAGS_QUERY,
        }),
        "py" => Some(LanguageSpec {
            name: "Python",
            language: tree_sitter_python::LANGUAGE.into(),
            tags_query: tree_sitter_python::TAGS_QUERY,
        }),
        "rs" => Some(LanguageSpec {
            name: "Rust",
            language: tree_sitter_rust::LANGUAGE.into(),
            tags_query: tree_sitter_rust::TAGS_QUERY,
        }),
        "go" => Some(LanguageSpec {
            name: "Go",
            language: tree_sitter_go::LANGUAGE.into(),
            tags_query: tree_sitter_go::TAGS_QUERY,
        }),
        "c" | "h" => Some(LanguageSpec {
            name: "C",
            language: tree_sitter_c::LANGUAGE.into(),
            tags_query: tree_sitter_c::TAGS_QUERY,
        }),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => Some(LanguageSpec {
            name: "C++",
            language: tree_sitter_cpp::LANGUAGE.into(),
            tags_query: tree_sitter_cpp::TAGS_QUERY,
        }),
        "php" => Some(LanguageSpec {
            name: "PHP",
            language: tree_sitter_php::LANGUAGE_PHP.into(),
            tags_query: tree_sitter_php::TAGS_QUERY,
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
    use std::{collections::BTreeMap, fs, path::Path};

    use tempfile::tempdir;

    use super::{index_project, language_spec, parse_source, sha256_hex, ParseState};

    #[test]
    fn extracts_definition_symbols_across_initial_languages() {
        let cases = [
            ("sample.ts", "export function add(a: number, b: number): number { return a + b; }", "add"),
            ("sample.js", "function add(a, b) { return a + b; }", "add"),
            ("sample.py", "def add(a, b):\n    return a + b\n", "add"),
            ("sample.rs", "fn add(a: i32, b: i32) -> i32 { a + b }", "add"),
            ("sample.go", "package sample\nfunc add(a int, b int) int { return a + b }", "add"),
            ("sample.c", "int add(int a, int b) { return a + b; }", "add"),
            ("sample.cpp", "int add(int a, int b) { return a + b; }", "add"),
            ("sample.php", "<?php function add($a, $b) { return $a + $b; }", "add"),
        ];

        for (path, source, expected_name) in cases {
            let spec = language_spec(Path::new(path)).expect("language spec");
            let indexed = parse_source(
                path.to_string(),
                source,
                spec,
                sha256_hex(source.as_bytes()),
                source.len() as u64,
            )
            .expect("parse source");
            assert_eq!(indexed.parse_state, ParseState::Parsed, "{path}");
            assert!(
                indexed.symbols.iter().any(|symbol| symbol.name == expected_name),
                "missing symbol {expected_name} in {path}: {:?}",
                indexed.symbols
            );
        }
    }

    #[test]
    fn skips_unchanged_files_by_content_hash() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("sample.ts"), "export function value() { return 1; }")
            .expect("write fixture");

        let first = index_project(dir.path(), &BTreeMap::new()).expect("first index");
        assert_eq!(first.indexed_files.len(), 1);
        let indexed = &first.indexed_files[0];
        let known = BTreeMap::from([(
            indexed.relative_path.clone(),
            indexed.content_hash.clone(),
        )]);

        let second = index_project(dir.path(), &known).expect("second index");
        assert!(second.indexed_files.is_empty());
        assert_eq!(second.unchanged_files, vec!["sample.ts"]);
    }

    #[test]
    fn prunes_dependency_and_build_directories() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("src")).expect("src");
        fs::create_dir_all(dir.path().join("node_modules/pkg")).expect("node_modules");
        fs::write(dir.path().join("src/main.js"), "function local() { return true; }")
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
