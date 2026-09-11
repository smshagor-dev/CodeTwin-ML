use serde::{Deserialize, Serialize};
use serde_json::json;

pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RULESET_VERSION: &str = "database-review-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseArtifactKind {
    SqlMigration,
    SqlSchema,
    PrismaSchema,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseObservation {
    pub rule_id: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub start_line: usize,
    pub end_line: usize,
    pub anchor: String,
    pub evidence_summary: String,
    pub metadata_json: String,
}

pub fn analyze_artifact(kind: DatabaseArtifactKind, source: &str) -> Vec<DatabaseObservation> {
    match kind {
        DatabaseArtifactKind::SqlMigration | DatabaseArtifactKind::SqlSchema => analyze_sql(source),
        DatabaseArtifactKind::PrismaSchema => analyze_prisma(source),
    }
}

pub fn analyze_sql(source: &str) -> Vec<DatabaseObservation> {
    let mut observations = Vec::new();
    for statement in split_sql_statements(source) {
        let tokens = sql_tokens(&statement.text);
        if tokens.is_empty() {
            continue;
        }
        let normalized = tokens.join(" ");
        let first = tokens.first().map(String::as_str).unwrap_or_default();

        if is_destructive_statement(&tokens) {
            observations.push(DatabaseObservation {
                rule_id: "database.destructive_migration".into(),
                severity: "medium".into(),
                confidence: 0.98,
                title: "Destructive database change requires review".into(),
                description: "A destructive DDL statement is present. This is not automatically incorrect, but production rollout should verify backup, compatibility, rollback, and data-retention expectations before execution.".into(),
                start_line: statement.start_line,
                end_line: statement.end_line,
                anchor: normalized.clone(),
                evidence_summary: format!("Destructive SQL operation `{}` is present in this database artifact.", destructive_label(&tokens)),
                metadata_json: json!({
                    "statement_kind": destructive_label(&tokens),
                    "execution_observed": false,
                    "review_required": true
                }).to_string(),
            });
        }

        if matches!(first, "DELETE" | "UPDATE") && !tokens.iter().any(|token| token == "WHERE") {
            observations.push(DatabaseObservation {
                rule_id: "database.unscoped_data_write".into(),
                severity: "high".into(),
                confidence: 0.96,
                title: "Unscoped UPDATE/DELETE requires review".into(),
                description: "A DELETE or UPDATE statement has no WHERE token in the parsed statement. This can be intentional for full-table maintenance, but it can also affect every row. Review the migration intent and rollback plan before execution.".into(),
                start_line: statement.start_line,
                end_line: statement.end_line,
                anchor: normalized.clone(),
                evidence_summary: format!("{first} statement contains no WHERE token; full-table modification is possible."),
                metadata_json: json!({
                    "statement_kind": first,
                    "where_token_present": false,
                    "execution_observed": false,
                    "review_required": true
                }).to_string(),
            });
        }

        if pragma_foreign_keys_disabled(&tokens) {
            observations.push(DatabaseObservation {
                rule_id: "database.sqlite_foreign_keys_disabled".into(),
                severity: "high".into(),
                confidence: 0.99,
                title: "SQLite foreign-key enforcement is disabled".into(),
                description: "The SQL artifact explicitly disables SQLite foreign-key enforcement. If this statement runs on a live connection, referential-integrity checks will not be enforced until re-enabled on that connection.".into(),
                start_line: statement.start_line,
                end_line: statement.end_line,
                anchor: normalized.clone(),
                evidence_summary: "`PRAGMA foreign_keys` is explicitly set to OFF/0 in this SQL artifact.".into(),
                metadata_json: json!({
                    "dialect": "sqlite",
                    "pragma": "foreign_keys",
                    "enabled": false,
                    "execution_observed": false
                }).to_string(),
            });
        }
    }

    sort_and_dedup(&mut observations);
    observations
}

pub fn analyze_prisma(source: &str) -> Vec<DatabaseObservation> {
    let mut observations = Vec::new();
    let mut in_datasource = false;
    let mut brace_depth = 0usize;

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = strip_line_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if !in_datasource && line.starts_with("datasource ") && line.contains('{') {
            in_datasource = true;
            brace_depth = brace_delta(line);
            continue;
        }

        if in_datasource {
            if let Some((name, value)) = split_assignment(line) {
                if matches!(name, "url" | "directUrl" | "shadowDatabaseUrl") {
                    let trimmed = value.trim();
                    if let Some(literal) = quoted_literal(trimmed) {
                        if !literal_is_placeholder(literal) {
                            observations.push(DatabaseObservation {
                                rule_id: "database.literal_datasource_url".into(),
                                severity: "high".into(),
                                confidence: 0.95,
                                title: "Literal Prisma datasource URL requires review".into(),
                                description: "A Prisma datasource connection URL is stored as a string literal instead of an environment-backed expression. Connection strings can contain credentials or deployment-specific endpoints, so the literal value is intentionally redacted from persisted evidence.".into(),
                                start_line: line_number,
                                end_line: line_number,
                                anchor: format!("prisma-datasource:{name}"),
                                evidence_summary: format!("Prisma datasource field `{name}` is assigned a literal connection string (value redacted; {} characters).", literal.chars().count()),
                                metadata_json: json!({
                                    "field": name,
                                    "literal_length": literal.chars().count(),
                                    "literal_redacted": true,
                                    "environment_expression": false
                                }).to_string(),
                            });
                        }
                    }
                }
            }
            brace_depth = brace_depth.saturating_add(brace_delta(line));
            if line.contains('}') && brace_depth == 0 {
                in_datasource = false;
            }
        }
    }

    sort_and_dedup(&mut observations);
    observations
}

#[derive(Debug)]
struct SqlStatement {
    text: String,
    start_line: usize,
    end_line: usize,
}

fn split_sql_statements(source: &str) -> Vec<SqlStatement> {
    let bytes = source.as_bytes();
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut line = 1usize;
    let mut start_line = 1usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);

        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                current.push('\n');
                line += 1;
            }
            index += 1;
            continue;
        }
        if in_block_comment {
            if ch == '*' && next == Some('/') {
                in_block_comment = false;
                index += 2;
                continue;
            }
            if ch == '\n' {
                line += 1;
            }
            index += 1;
            continue;
        }

        if !in_single && !in_double && !in_backtick {
            if ch == '-' && next == Some('-') {
                in_line_comment = true;
                index += 2;
                continue;
            }
            if ch == '/' && next == Some('*') {
                in_block_comment = true;
                index += 2;
                continue;
            }
        }

        if ch == '\'' && !in_double && !in_backtick {
            if in_single && next == Some('\'') {
                current.push(ch);
                current.push('\'');
                index += 2;
                continue;
            }
            in_single = !in_single;
            current.push(ch);
            index += 1;
            continue;
        }
        if ch == '"' && !in_single && !in_backtick {
            in_double = !in_double;
            current.push(ch);
            index += 1;
            continue;
        }
        if ch == '`' && !in_single && !in_double {
            in_backtick = !in_backtick;
            current.push(ch);
            index += 1;
            continue;
        }

        if ch == ';' && !in_single && !in_double && !in_backtick {
            push_statement(&mut statements, &mut current, start_line, line);
            start_line = line;
            index += 1;
            continue;
        }

        current.push(ch);
        if ch == '\n' {
            line += 1;
            if current.trim().is_empty() {
                start_line = line;
            }
        }
        index += 1;
    }
    push_statement(&mut statements, &mut current, start_line, line);
    statements
}

fn push_statement(output: &mut Vec<SqlStatement>, current: &mut String, start_line: usize, end_line: usize) {
    let text = current.trim().to_string();
    current.clear();
    if !text.is_empty() {
        output.push(SqlStatement { text, start_line, end_line });
    }
}

fn sql_tokens(statement: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut chars = statement.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\'' && !in_double && !in_backtick {
            if in_single && chars.peek() == Some(&'\'') {
                chars.next();
                continue;
            }
            in_single = !in_single;
            flush_token(&mut tokens, &mut current);
            continue;
        }
        if ch == '"' && !in_single && !in_backtick {
            in_double = !in_double;
            flush_token(&mut tokens, &mut current);
            continue;
        }
        if ch == '`' && !in_single && !in_double {
            in_backtick = !in_backtick;
            flush_token(&mut tokens, &mut current);
            continue;
        }
        if in_single || in_double || in_backtick {
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch.to_ascii_uppercase());
        } else {
            flush_token(&mut tokens, &mut current);
            if ch == '=' {
                tokens.push("=".into());
            }
        }
    }
    flush_token(&mut tokens, &mut current);
    tokens
}

fn flush_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

fn is_destructive_statement(tokens: &[String]) -> bool {
    starts_with_tokens(tokens, &["DROP", "TABLE"])
        || starts_with_tokens(tokens, &["DROP", "DATABASE"])
        || starts_with_tokens(tokens, &["TRUNCATE", "TABLE"])
        || (starts_with_tokens(tokens, &["ALTER", "TABLE"]) && contains_sequence(tokens, &["DROP", "COLUMN"]))
}

fn destructive_label(tokens: &[String]) -> &'static str {
    if starts_with_tokens(tokens, &["DROP", "TABLE"]) {
        "DROP TABLE"
    } else if starts_with_tokens(tokens, &["DROP", "DATABASE"]) {
        "DROP DATABASE"
    } else if starts_with_tokens(tokens, &["TRUNCATE", "TABLE"]) {
        "TRUNCATE TABLE"
    } else {
        "ALTER TABLE DROP COLUMN"
    }
}

fn pragma_foreign_keys_disabled(tokens: &[String]) -> bool {
    if !starts_with_tokens(tokens, &["PRAGMA", "FOREIGN_KEYS"]) {
        return false;
    }
    tokens.iter().any(|token| matches!(token.as_str(), "OFF" | "0"))
}

fn starts_with_tokens(tokens: &[String], expected: &[&str]) -> bool {
    tokens.len() >= expected.len()
        && tokens.iter().take(expected.len()).map(String::as_str).eq(expected.iter().copied())
}

fn contains_sequence(tokens: &[String], expected: &[&str]) -> bool {
    tokens.windows(expected.len()).any(|window| {
        window.iter().map(String::as_str).eq(expected.iter().copied())
    })
}

fn strip_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(prefix, _)| prefix)
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let (left, right) = line.split_once('=')?;
    let name = left.trim();
    if name.is_empty() {
        None
    } else {
        Some((name, right.trim()))
    }
}

fn quoted_literal(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote = bytes[0];
    if !matches!(quote, b'\'' | b'"') || bytes[bytes.len() - 1] != quote {
        return None;
    }
    Some(&value[1..value.len() - 1])
}

fn literal_is_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.is_empty()
        || normalized.contains("localhost")
        || normalized.contains("example")
        || normalized.contains("changeme")
        || normalized.contains("<password>")
        || normalized.contains("${")
}

fn brace_delta(line: &str) -> usize {
    let opens = line.chars().filter(|ch| *ch == '{').count();
    let closes = line.chars().filter(|ch| *ch == '}').count();
    opens.saturating_sub(closes)
}

fn sort_and_dedup(observations: &mut Vec<DatabaseObservation>) {
    observations.sort_by(|left, right| {
        (left.start_line, left.end_line, &left.rule_id, &left.anchor)
            .cmp(&(right.start_line, right.end_line, &right.rule_id, &right.anchor))
    });
    observations.dedup_by(|left, right| {
        left.rule_id == right.rule_id
            && left.start_line == right.start_line
            && left.end_line == right.end_line
            && left.anchor == right.anchor
    });
}

#[cfg(test)]
mod tests {
    use super::{analyze_prisma, analyze_sql};

    #[test]
    fn detects_destructive_and_unscoped_sql_without_reading_literals() {
        let findings = analyze_sql(
            "-- release migration\nDELETE FROM audit_log;\nALTER TABLE users DROP COLUMN legacy_token;\nUPDATE users SET active = 1 WHERE id = 7;\n",
        );
        assert!(findings.iter().any(|item| item.rule_id == "database.unscoped_data_write"));
        assert!(findings.iter().any(|item| item.rule_id == "database.destructive_migration"));
        assert_eq!(findings.iter().filter(|item| item.rule_id == "database.unscoped_data_write").count(), 1);
    }

    #[test]
    fn does_not_treat_where_inside_string_as_scope() {
        let findings = analyze_sql("UPDATE jobs SET note = 'WHERE id = 1';");
        assert!(findings.iter().any(|item| item.rule_id == "database.unscoped_data_write"));
    }

    #[test]
    fn detects_foreign_key_disable() {
        let findings = analyze_sql("PRAGMA foreign_keys = OFF;");
        assert!(findings.iter().any(|item| item.rule_id == "database.sqlite_foreign_keys_disabled"));
    }

    #[test]
    fn prisma_literal_is_redacted_but_env_expression_is_not_flagged() {
        let findings = analyze_prisma(
            "datasource db {\n  provider = \"postgresql\"\n  url = \"postgresql://user:secret@db.internal/app\"\n}\n\ndatasource reporting {\n  provider = \"postgresql\"\n  url = env(\"REPORTING_URL\")\n}\n",
        );
        let finding = findings.iter().find(|item| item.rule_id == "database.literal_datasource_url").expect("literal datasource finding");
        assert!(!finding.evidence_summary.contains("secret"));
        assert!(!finding.metadata_json.contains("secret"));
        assert_eq!(findings.len(), 1);
    }
}
