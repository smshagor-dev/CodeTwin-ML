use serde::{Deserialize, Serialize};
use thiserror::Error;
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");

const TS_QUERY: &str = r#"
(call_expression
  function: (identifier) @reference.call)
(new_expression
  constructor: (identifier) @reference.constructor)
"#;

#[derive(Debug, Error)]
pub enum ReferenceIndexError {
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),
    #[error("failed to configure parser: {0}")]
    ParserLanguage(String),
    #[error("parser cancelled")]
    ParserCancelled,
    #[error("invalid reference query: {0}")]
    Query(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedReference {
    pub name: String,
    pub kind: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

pub fn extract_references(
    language_name: &str,
    source: &str,
) -> Result<Vec<ObservedReference>, ReferenceIndexError> {
    let language = language_for(language_name)?;
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ReferenceIndexError::ParserLanguage(error.to_string()))?;
    let tree = parser
        .parse(source, None)
        .ok_or(ReferenceIndexError::ParserCancelled)?;
    let query = Query::new(&language, TS_QUERY)
        .map_err(|error| ReferenceIndexError::Query(error.to_string()))?;
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let mut observations = Vec::new();

    while let Some(query_match) = matches.next() {
        for capture in query_match.captures {
            let capture_name = capture_names[capture.index as usize];
            let Some(kind) = capture_name.strip_prefix("reference.") else {
                continue;
            };
            let node = capture.node;
            let Ok(name) = node.utf8_text(source.as_bytes()) else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let start = node.start_position();
            let end = node.end_position();
            observations.push(ObservedReference {
                name: name.to_string(),
                kind: kind.to_string(),
                start_line: start.row + 1,
                start_column: start.column,
                end_line: end.row + 1,
                end_column: end.column,
            });
        }
    }

    observations.sort_by(|left, right| {
        (
            left.start_line,
            left.start_column,
            left.end_line,
            left.end_column,
            &left.kind,
            &left.name,
        )
            .cmp(&(
                right.start_line,
                right.start_column,
                right.end_line,
                right.end_column,
                &right.kind,
                &right.name,
            ))
    });
    observations.dedup();
    Ok(observations)
}

fn language_for(language_name: &str) -> Result<Language, ReferenceIndexError> {
    match language_name {
        "TypeScript" => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "TypeScript TSX" => Ok(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "JavaScript" => Ok(tree_sitter_javascript::LANGUAGE.into()),
        other => Err(ReferenceIndexError::UnsupportedLanguage(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::extract_references;

    #[test]
    fn extracts_only_direct_identifier_calls_and_constructors() {
        let source = r#"
function local() { return 1; }
class Service {}
local();
new Service();
obj.method();
factory().next();
"#;
        let refs = extract_references("TypeScript", source).expect("extract references");
        assert!(refs.iter().any(|item| item.kind == "call" && item.name == "local"));
        assert!(refs.iter().any(|item| item.kind == "constructor" && item.name == "Service"));
        assert!(!refs.iter().any(|item| item.name == "method"));
        assert!(!refs.iter().any(|item| item.name == "next"));
    }

    #[test]
    fn rejects_languages_without_a_validated_reference_query() {
        let error = extract_references("Python", "print('x')").expect_err("unsupported");
        assert!(error.to_string().contains("unsupported language"));
    }
}
