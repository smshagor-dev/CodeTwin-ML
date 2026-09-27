use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tree_sitter::{Language, Node, Parser};

mod java;

pub const ANALYZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RULESET_VERSION: &str = "appsec-source-v3";

#[derive(Debug, Error)]
pub enum SecurityAnalyzerError {
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),
    #[error("failed to configure parser: {0}")]
    ParserLanguage(String),
    #[error("parser returned no syntax tree")]
    ParserCancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityObservation {
    pub rule_id: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub cwe: String,
    pub owasp: Option<String>,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub anchor: String,
    pub evidence_summary: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceSecurityResult {
    pub parsed_with_errors: bool,
    pub observations: Vec<SecurityObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LanguageFamily {
    TypeScript,
    JavaScript,
    Python,
    Rust,
    Go,
    C,
    Cpp,
    Php,
    Java,
}

pub fn analyze_source(
    language_name: &str,
    source: &str,
) -> Result<SourceSecurityResult, SecurityAnalyzerError> {
    let (language, family) = language_spec(language_name)
        .ok_or_else(|| SecurityAnalyzerError::UnsupportedLanguage(language_name.to_string()))?;
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| SecurityAnalyzerError::ParserLanguage(error.to_string()))?;
    let tree = parser
        .parse(source, None)
        .ok_or(SecurityAnalyzerError::ParserCancelled)?;

    let mut observations = Vec::new();
    visit(tree.root_node(), source, family, &mut observations);
    if family == LanguageFamily::Java {
        java::analyze(tree.root_node(), source, &mut observations);
    }
    observations.sort_by(|left, right| {
        (
            left.start_line,
            left.start_column,
            left.end_line,
            &left.rule_id,
            &left.anchor,
        )
            .cmp(&(
                right.start_line,
                right.start_column,
                right.end_line,
                &right.rule_id,
                &right.anchor,
            ))
    });
    observations.dedup_by(|left, right| {
        left.rule_id == right.rule_id
            && left.start_line == right.start_line
            && left.start_column == right.start_column
            && left.end_line == right.end_line
            && left.anchor == right.anchor
    });

    Ok(SourceSecurityResult {
        parsed_with_errors: tree.root_node().has_error(),
        observations,
    })
}

fn visit(
    node: Node<'_>,
    source: &str,
    family: LanguageFamily,
    observations: &mut Vec<SecurityObservation>,
) {
    inspect_assignment(node, source, observations);
    if family != LanguageFamily::Java {
        inspect_call(node, source, family, observations);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit(child, source, family, observations);
    }
}

fn inspect_assignment(node: Node<'_>, source: &str, observations: &mut Vec<SecurityObservation>) {
    if !matches!(
        node.kind(),
        "variable_declarator"
            | "assignment_expression"
            | "assignment"
            | "let_declaration"
            | "short_var_declaration"
            | "var_spec"
            | "init_declarator"
    ) {
        return;
    }

    let Some((left, right)) = assignment_parts(node) else {
        return;
    };
    if !is_plain_string_literal(right) {
        return;
    }

    let Ok(left_text) = left.utf8_text(source.as_bytes()) else {
        return;
    };
    let normalized_name = normalize_identifier(left_text);
    if !looks_like_credential_name(&normalized_name) {
        return;
    }

    let Ok(literal_text) = right.utf8_text(source.as_bytes()) else {
        return;
    };
    let literal = strip_string_delimiters(literal_text.trim());
    if literal.len() < 4 || literal_is_placeholder(literal) {
        return;
    }

    observations.push(observation(
        "security.hardcoded_credential_literal",
        "high",
        0.90,
        "Potential hard-coded credential literal",
        "A credential-like variable is initialized from a non-placeholder string literal. Review whether this value is a real secret and move real credentials to an appropriate secret source. The literal value is intentionally not persisted in finding evidence.",
        "CWE-798",
        Some("OWASP A07:2021 Identification and Authentication Failures"),
        node,
        normalized_name.clone(),
        format!(
            "Credential-like identifier `{}` is assigned a string literal (value redacted; {} characters).",
            normalized_name,
            literal.chars().count()
        ),
        json!({
            "identifier": normalized_name,
            "literal_length": literal.chars().count(),
            "literal_redacted": true
        }),
    ));
}

fn inspect_call(
    node: Node<'_>,
    source: &str,
    family: LanguageFamily,
    observations: &mut Vec<SecurityObservation>,
) {
    if family == LanguageFamily::Php && node.kind() == "eval_expression" {
        observations.push(dynamic_code_observation(node, "eval"));
        return;
    }

    if !matches!(
        node.kind(),
        "call_expression" | "call" | "function_call_expression"
    ) {
        return;
    }

    let Some(callee_node) = call_callee(node) else {
        return;
    };
    let Ok(callee_text) = callee_node.utf8_text(source.as_bytes()) else {
        return;
    };
    let callee = normalize_callee(callee_text);
    let base = callee_basename(&callee);

    if is_dynamic_execution_callee(&callee, family) {
        observations.push(dynamic_code_observation(node, &callee));
    }

    if matches!(base.as_str(), "md5" | "sha1")
        || create_hash_uses_weak_algorithm(node, source, &base)
    {
        observations.push(observation(
            "security.weak_cryptographic_hash",
            "medium",
            0.82,
            "Weak cryptographic hash primitive",
            "The source invokes MD5 or SHA-1 hashing. These algorithms are collision-broken for security-sensitive integrity/signature uses. Review the purpose before replacing it because non-security checksums can be intentional.",
            "CWE-327",
            Some("OWASP A02:2021 Cryptographic Failures"),
            node,
            callee.clone(),
            format!("Weak hash primitive observed at call `{callee}`; usage context requires review."),
            json!({"callee": callee, "review_required": true}),
        ));
    }

    if matches!(family, LanguageFamily::C | LanguageFamily::Cpp)
        && matches!(
            base.as_str(),
            "gets" | "strcpy" | "strcat" | "sprintf" | "vsprintf"
        )
    {
        observations.push(observation(
            "security.unsafe_c_string_api",
            "medium",
            0.78,
            "Unsafe C/C++ string API requires bounds review",
            "A C/C++ string API with no intrinsic destination bound is used. This is not proof of an overflow, but the call requires a concrete bounds review or replacement with an explicitly bounded operation.",
            "CWE-120",
            None,
            node,
            callee.clone(),
            format!("Potentially unsafe C/C++ API call `{callee}` is present."),
            json!({"callee": callee, "review_required": true}),
        ));
    }

    inspect_web_call(node, source, family, &callee, &base, observations);
}

fn inspect_web_call(
    node: Node<'_>,
    source: &str,
    family: LanguageFamily,
    callee: &str,
    base: &str,
    observations: &mut Vec<SecurityObservation>,
) {
    if !matches!(
        family,
        LanguageFamily::TypeScript
            | LanguageFamily::JavaScript
            | LanguageFamily::Python
            | LanguageFamily::Php
    ) {
        return;
    }
    let Ok(call_text) = node.utf8_text(source.as_bytes()) else {
        return;
    };
    let normalized = call_text.to_ascii_lowercase();
    let request_controlled = contains_request_input(&normalized);

    let sql_sink = matches!(
        base,
        "execute"
            | "executemany"
            | "query"
            | "raw"
            | "mysqli_query"
            | "queryrawunsafe"
            | "executerawunsafe"
    ) || callee.contains("$queryrawunsafe")
        || callee.contains("$executerawunsafe");

    if sql_sink && request_controlled {
        observations.push(observation(
            "web.sql.request_to_query",
            "critical",
            0.99,
            "Request-controlled data reaches a SQL/ORM query sink",
            "Request input is used directly inside a database query call. Keep SQL structure fixed and bind every data value through the driver/ORM parameter API. Dynamic identifiers must be mapped through a fixed allow-list rather than concatenated.",
            "CWE-89",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.to_string(),
            format!("Request-controlled data reaches database call `{callee}`; query parameterization is required."),
            json!({
                "callee": callee,
                "request_controlled": true,
                "repository_command_executed": false,
                "exploit_attempted": false
            }),
        ));
    } else if is_explicitly_unsafe_raw_sql(callee) {
        observations.push(observation(
            "web.sql.unsafe_raw_api",
            "high",
            0.92,
            "Explicitly unsafe/raw SQL API requires injection review",
            "An API intended for raw SQL construction is present. Prefer parameterized/tagged query APIs; if dynamic identifiers are unavoidable, map them from a fixed application allow-list.",
            "CWE-89",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.to_string(),
            format!("Raw/unsafe SQL API `{callee}` is used; input provenance and parameterization require review."),
            json!({"callee": callee, "request_controlled": false, "review_required": true}),
        ));
    }

    if sql_sink && request_controlled && contains_sql_identifier_position(&normalized) {
        observations.push(observation(
            "web.sql.dynamic_identifier",
            "high",
            0.96,
            "Request-controlled SQL identifier or ordering value",
            "SQL parameters protect data values, not table/column/order identifiers. Map user choices to fixed known identifiers and reject everything else.",
            "CWE-89",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.to_string(),
            "Request-controlled input appears in a SQL identifier/order context; use a strict identifier allow-list.".into(),
            json!({"callee": callee, "identifier_allowlist_required": true}),
        ));
    }

    if is_header_sink(callee, base) && request_controlled {
        observations.push(observation(
            "web.header.request_to_response",
            "high",
            0.94,
            "Request-controlled value reaches an HTTP response header",
            "Reject carriage-return/line-feed characters and prefer fixed or allow-listed header values. Redirect targets should be validated against an explicit destination policy.",
            "CWE-113",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.to_string(),
            format!("Request-controlled data reaches response-header call `{callee}`; CR/LF and destination validation are required."),
            json!({"callee": callee, "request_controlled": true}),
        ));
    }

    if is_outbound_http_sink(callee) && request_controlled {
        observations.push(observation(
            "web.ssrf.request_url",
            "high",
            0.94,
            "Request-controlled URL reaches an outbound HTTP client",
            "Allow-list destination schemes and hosts, reject credentials in URLs, and block private, loopback, link-local, and metadata-service address ranges before making outbound requests.",
            "CWE-918",
            Some("OWASP A10:2021 Server-Side Request Forgery"),
            node,
            callee.to_string(),
            format!("Request-controlled data reaches outbound HTTP call `{callee}`; destination validation is required."),
            json!({"callee": callee, "request_controlled": true}),
        ));
    }

    if is_process_sink(callee, base) && request_controlled {
        observations.push(observation(
            "web.command.request_to_process",
            "critical",
            0.97,
            "Request-controlled value reaches a process execution sink",
            "Do not pass request data to a shell. Use a fixed executable and fixed argument schema with strict allow-list validation, or remove the execution path.",
            "CWE-78",
            Some("OWASP A03:2021 Injection"),
            node,
            callee.to_string(),
            format!("Request-controlled data reaches process call `{callee}`; shell/command injection is possible."),
            json!({"callee": callee, "request_controlled": true}),
        ));
    }
}

fn contains_request_input(value: &str) -> bool {
    [
        "request.args",
        "request.form",
        "request.json",
        "request.values",
        "request.get",
        "request.post",
        "request.query_params",
        "request.path_params",
        "req.query",
        "req.body",
        "req.params",
        "ctx.request",
        "$_get",
        "$_post",
        "$_request",
        "params[",
        "request[",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn contains_sql_identifier_position(value: &str) -> bool {
    [
        " from ",
        " join ",
        " order by ",
        " group by ",
        " update ",
        " into ",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn is_explicitly_unsafe_raw_sql(callee: &str) -> bool {
    callee.contains("$queryrawunsafe")
        || callee.contains("$executerawunsafe")
        || callee.ends_with(".raw")
        || callee.contains("sequelize.literal")
        || callee.contains("knex.raw")
}

fn is_header_sink(callee: &str, base: &str) -> bool {
    matches!(base, "setheader" | "header" | "set")
        && (callee.contains("res.") || callee.contains("response") || base == "header")
}

fn is_outbound_http_sink(callee: &str) -> bool {
    matches!(
        callee,
        "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.delete"
            | "httpx.get"
            | "httpx.post"
            | "httpx.put"
            | "httpx.delete"
            | "axios.get"
            | "axios.post"
            | "axios.put"
            | "axios.delete"
            | "fetch"
            | "urllib.request.urlopen"
    )
}

fn is_process_sink(callee: &str, base: &str) -> bool {
    matches!(
        base,
        "system" | "popen" | "run" | "call" | "check_output" | "exec" | "execsync"
    ) && (callee.starts_with("os.")
        || callee.starts_with("subprocess.")
        || callee.starts_with("child_process.")
        || matches!(base, "exec" | "execsync"))
}

fn is_dynamic_execution_callee(callee: &str, family: LanguageFamily) -> bool {
    match family {
        LanguageFamily::TypeScript | LanguageFamily::JavaScript => {
            matches!(callee, "eval" | "window.eval" | "globalthis.eval")
        }
        LanguageFamily::Python => matches!(callee, "eval" | "exec"),
        LanguageFamily::Php => callee == "eval",
        LanguageFamily::Rust
        | LanguageFamily::Go
        | LanguageFamily::C
        | LanguageFamily::Cpp
        | LanguageFamily::Java => false,
    }
}

fn dynamic_code_observation(node: Node<'_>, callee: &str) -> SecurityObservation {
    observation(
        "security.dynamic_code_execution",
        "medium",
        0.68,
        "Dynamic code execution primitive requires input review",
        "A dynamic code execution primitive is present. Its existence alone does not prove code injection; review whether untrusted or attacker-controlled data can reach the executed code string.",
        "CWE-95",
        Some("OWASP A03:2021 Injection"),
        node,
        callee.to_string(),
        format!("Dynamic execution primitive `{callee}` is called; input provenance is not proven by this analyzer."),
        json!({"callee": callee, "taint_proven": false, "review_required": true}),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn observation(
    rule_id: &str,
    severity: &str,
    confidence: f64,
    title: &str,
    description: &str,
    cwe: &str,
    owasp: Option<&str>,
    node: Node<'_>,
    anchor: String,
    evidence_summary: String,
    metadata: serde_json::Value,
) -> SecurityObservation {
    let start = node.start_position();
    let end = node.end_position();
    SecurityObservation {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        confidence,
        title: title.to_string(),
        description: description.to_string(),
        cwe: cwe.to_string(),
        owasp: owasp.map(str::to_string),
        start_line: start.row + 1,
        start_column: start.column,
        end_line: end.row + 1,
        end_column: end.column,
        anchor,
        evidence_summary,
        metadata_json: metadata.to_string(),
    }
}

fn assignment_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let left = ["name", "left", "pattern", "declarator"]
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .or_else(|| node.named_child(0))?;
    let right = ["value", "right"]
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .or_else(|| {
            let count = node.named_child_count();
            count
                .checked_sub(1)
                .and_then(|index| node.named_child(index))
        })?;
    if left.id() == right.id() {
        None
    } else {
        Some((left, right))
    }
}

fn call_callee(node: Node<'_>) -> Option<Node<'_>> {
    ["function", "name", "callee"]
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .or_else(|| node.named_child(0))
}

fn create_hash_uses_weak_algorithm(node: Node<'_>, source: &str, base: &str) -> bool {
    if base != "createhash" {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments").or_else(|| {
        let mut cursor = node.walk();
        let arguments = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "arguments");
        arguments
    }) else {
        return false;
    };
    let mut cursor = arguments.walk();
    let weak = arguments.named_children(&mut cursor).any(|argument| {
        if !is_plain_string_literal(argument) {
            return false;
        }
        argument
            .utf8_text(source.as_bytes())
            .ok()
            .map(strip_string_delimiters)
            .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "md5" | "sha1"))
    });
    weak
}

fn is_plain_string_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "encapsed_string"
    )
}

fn normalize_identifier(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .to_ascii_lowercase()
}

fn looks_like_credential_name(value: &str) -> bool {
    let compact: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    [
        "password",
        "passwd",
        "secret",
        "apikey",
        "accesstoken",
        "authtoken",
        "clientsecret",
        "privatekey",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn literal_is_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.is_empty()
        || [
            "changeme",
            "change-me",
            "example",
            "example-secret",
            "placeholder",
            "your-secret",
            "your-password",
            "your-api-key",
            "dummy",
            "test",
            "testing",
            "<secret>",
            "<password>",
        ]
        .contains(&normalized.as_str())
}

fn strip_string_delimiters(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if matches!(first, b'\'' | b'"' | b'`') && first == last {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn normalize_callee(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn callee_basename(value: &str) -> String {
    value
        .rsplit(['.', ':', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(value)
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .to_string()
}

fn language_spec(name: &str) -> Option<(Language, LanguageFamily)> {
    match name {
        "TypeScript" => Some((
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            LanguageFamily::TypeScript,
        )),
        "TypeScript TSX" => Some((
            tree_sitter_typescript::LANGUAGE_TSX.into(),
            LanguageFamily::TypeScript,
        )),
        "JavaScript" => Some((
            tree_sitter_javascript::LANGUAGE.into(),
            LanguageFamily::JavaScript,
        )),
        "Python" => Some((tree_sitter_python::LANGUAGE.into(), LanguageFamily::Python)),
        "Rust" => Some((tree_sitter_rust::LANGUAGE.into(), LanguageFamily::Rust)),
        "Go" => Some((tree_sitter_go::LANGUAGE.into(), LanguageFamily::Go)),
        "C" => Some((tree_sitter_c::LANGUAGE.into(), LanguageFamily::C)),
        "C++" => Some((tree_sitter_cpp::LANGUAGE.into(), LanguageFamily::Cpp)),
        "PHP" => Some((tree_sitter_php::LANGUAGE_PHP.into(), LanguageFamily::Php)),
        "Java" => Some((tree_sitter_java::LANGUAGE.into(), LanguageFamily::Java)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_source;

    #[test]
    fn detects_hardcoded_secret_without_persisting_literal() {
        let result = analyze_source("TypeScript", "const apiKey = \"sk_live_supersecret\";\n")
            .expect("analyze");
        let finding = result
            .observations
            .iter()
            .find(|item| item.rule_id == "security.hardcoded_credential_literal")
            .expect("hardcoded credential");
        assert_eq!(finding.cwe, "CWE-798");
        assert!(!finding.evidence_summary.contains("sk_live_supersecret"));
        assert!(!finding.metadata_json.contains("sk_live_supersecret"));
    }

    #[test]
    fn ignores_documented_placeholder_secret() {
        let result = analyze_source("Python", "password = \"changeme\"\n").expect("analyze");
        assert!(result
            .observations
            .iter()
            .all(|item| item.rule_id != "security.hardcoded_credential_literal"));
    }

    #[test]
    fn detects_dynamic_execution_as_review_not_proven_injection() {
        let result = analyze_source("JavaScript", "eval(source);\n").expect("analyze");
        let finding = result
            .observations
            .iter()
            .find(|item| item.rule_id == "security.dynamic_code_execution")
            .expect("dynamic execution");
        assert_eq!(finding.cwe, "CWE-95");
        assert!(finding.description.contains("does not prove"));
    }

    #[test]
    fn does_not_treat_javascript_regex_exec_as_dynamic_code_execution() {
        let result =
            analyze_source("JavaScript", "const ok = /a/.exec(value);\n").expect("analyze");
        assert!(result
            .observations
            .iter()
            .all(|item| item.rule_id != "security.dynamic_code_execution"));
    }

    #[test]
    fn detects_weak_hash_and_c_unsafe_api() {
        let python = analyze_source("Python", "import hashlib\nhashlib.sha1(data).digest()\n")
            .expect("python");
        assert!(python
            .observations
            .iter()
            .any(|item| item.rule_id == "security.weak_cryptographic_hash"));

        let c = analyze_source("C", "void f(char *d, char *s) { strcpy(d, s); }\n").expect("c");
        assert!(c
            .observations
            .iter()
            .any(|item| item.rule_id == "security.unsafe_c_string_api"));
    }

    #[test]
    fn detects_direct_request_to_sql_query() {
        let result = analyze_source(
            "Python",
            "cursor.execute(f\"SELECT * FROM users WHERE id={request.args['id']}\")\n",
        )
        .expect("analyze");
        assert!(result
            .observations
            .iter()
            .any(|item| item.rule_id == "web.sql.request_to_query" && item.cwe == "CWE-89"));
    }

    #[test]
    fn does_not_flag_parameterized_sql_without_request_in_sql_text() {
        let result = analyze_source(
            "Python",
            "user_id = request.args['id']\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n",
        )
        .expect("analyze");
        assert!(result
            .observations
            .iter()
            .all(|item| item.rule_id != "web.sql.request_to_query"));
    }

    #[test]
    fn detects_request_to_header_and_ssrf_sinks() {
        let js = analyze_source(
            "JavaScript",
            "res.setHeader('X-Next', req.query.next);\nfetch(req.query.url);\n",
        )
        .expect("analyze");
        assert!(js
            .observations
            .iter()
            .any(|item| item.rule_id == "web.header.request_to_response"));
        assert!(js
            .observations
            .iter()
            .any(|item| item.rule_id == "web.ssrf.request_url"));
    }
}
