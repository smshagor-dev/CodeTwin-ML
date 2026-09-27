//! Deterministic secret detection for repository text files.
//!
//! The scanner never returns a raw secret. Each observation carries a redacted preview
//! and the matched value only as an opaque byte range, so callers can hash it for a
//! stable fingerprint without persisting it.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

pub const ANALYZER_VERSION: &str = "secret-scanner-v1";
pub const RULESET_VERSION: &str = "1";

/// Lines containing this marker are skipped (for intentional, documented test values).
pub const SUPPRESSION_MARKER: &str = "codetwin:ignore-secret";

/// Generic `password = "..."` style assignments must look random to be reported.
const GENERIC_MIN_ENTROPY: f64 = 3.5;
const MAX_LINE_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretObservation {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: f64,
    /// 1-based line of the match.
    pub line: usize,
    /// Redacted preview safe to show and persist, e.g. `AKIA…MPLE`.
    pub redacted: String,
    /// Byte range of the secret value within the scanned text. Callers may hash
    /// `text[secret_range]` for a fingerprint; it must never be stored or displayed.
    pub secret_range: (usize, usize),
    /// True when the file path looks like a test/fixture/example location.
    pub in_test_path: bool,
    pub remediation: &'static str,
}

struct Rule {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    confidence: f64,
    pattern: &'static str,
    /// Capture group holding the secret value (0 = whole match).
    group: usize,
    /// Apply placeholder and entropy filters (for loosely structured rules).
    generic: bool,
    remediation: &'static str,
}

const ROTATE: &str = "Revoke and rotate this credential at the issuer, remove it from the \
repository (including history), and load it from a secret manager or environment variable.";

const RULES: &[Rule] = &[
    Rule {
        id: "secret.private_key",
        title: "Private key committed to the repository",
        severity: Severity::Critical,
        confidence: 0.98,
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        group: 0,
        generic: false,
        remediation:
            "Treat the key as compromised: revoke it, issue a new key pair, remove the file \
from the repository and its history, and store keys outside source control.",
    },
    Rule {
        id: "secret.aws_access_key_id",
        title: "AWS access key ID",
        severity: Severity::High,
        confidence: 0.95,
        pattern: r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.aws_secret_access_key",
        title: "AWS secret access key",
        severity: Severity::Critical,
        confidence: 0.95,
        pattern: r#"(?i)aws_?secret_?access_?key\s*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b"#,
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.github_token",
        title: "GitHub token",
        severity: Severity::Critical,
        confidence: 0.97,
        pattern: r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.gitlab_token",
        title: "GitLab personal access token",
        severity: Severity::Critical,
        confidence: 0.96,
        pattern: r"\b(glpat-[A-Za-z0-9_\-]{20})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.slack_token",
        title: "Slack token",
        severity: Severity::High,
        confidence: 0.95,
        pattern: r"\b(xox[abposr]-[A-Za-z0-9-]{10,72})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.slack_webhook",
        title: "Slack incoming webhook URL",
        severity: Severity::High,
        confidence: 0.95,
        pattern: r"(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.stripe_live_key",
        title: "Stripe live secret key",
        severity: Severity::Critical,
        confidence: 0.97,
        pattern: r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.google_api_key",
        title: "Google API key",
        severity: Severity::High,
        confidence: 0.9,
        pattern: r"\b(AIza[0-9A-Za-z_\-]{35})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.npm_token",
        title: "npm access token",
        severity: Severity::Critical,
        confidence: 0.96,
        pattern: r"\b(npm_[A-Za-z0-9]{36})\b",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.ai_provider_key",
        title: "AI provider API key",
        severity: Severity::Critical,
        confidence: 0.93,
        pattern: r"\b(sk-(?:ant-[A-Za-z0-9_\-]{20,}|proj-[A-Za-z0-9_\-]{20,}))",
        group: 1,
        generic: false,
        remediation: ROTATE,
    },
    Rule {
        id: "secret.jwt",
        title: "JSON Web Token",
        severity: Severity::Medium,
        confidence: 0.75,
        pattern: r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
        group: 1,
        generic: false,
        remediation:
            "Check whether this token is still valid; if so revoke it or rotate the signing \
key. Do not commit issued tokens.",
    },
    Rule {
        id: "secret.connection_string_password",
        title: "Database or broker URL with an embedded password",
        severity: Severity::High,
        confidence: 0.85,
        pattern: r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^:@\s/]+:([^@\s/]{3,})@",
        group: 1,
        generic: true,
        remediation: "Rotate the database password and move the URL (or at least the password) \
into environment configuration or a secret manager.",
    },
    Rule {
        id: "secret.generic_assignment",
        title: "Hard-coded credential assigned to a secret-named key",
        severity: Severity::Medium,
        confidence: 0.6,
        pattern: r#"(?i)\b[a-z0-9_.\-]*(?:secret|password|passwd|pwd|api[_\-]?key|access[_\-]?token|auth[_\-]?token|private[_\-]?key|client[_\-]?secret)[a-z0-9_.\-]*["']?\s*(?::=|=>|[:=])\s*["']([^"'\s]{8,})["']"#,
        group: 1,
        generic: true,
        remediation: "Remove the literal and load the value from environment configuration or a \
secret manager. Rotate it if it was ever a real credential.",
    },
    Rule {
        id: "secret.env_file_assignment",
        title: "Credential in a committed environment file",
        severity: Severity::High,
        confidence: 0.8,
        pattern: r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*['\x22]?([^\s'\x22#]{8,})",
        group: 1,
        generic: true,
        remediation:
            "Do not commit real .env files: add them to .gitignore, commit a .env.example \
with placeholders instead, and rotate any value that was exposed.",
    },
];

fn compiled() -> &'static [(Regex, &'static Rule)] {
    static COMPILED: OnceLock<Vec<(Regex, &'static Rule)>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .map(|rule| (Regex::new(rule.pattern).expect("valid secret rule"), rule))
            .collect()
    })
}

/// True for dotenv-style files (`.env`, `.env.production`, `prod.env`), excluding
/// conventional templates such as `.env.example`.
pub fn is_env_file(path: &str) -> bool {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    let is_env = name == ".env" || name.starts_with(".env.") || name.ends_with(".env");
    let template = ["example", "sample", "template", "dist", "defaults"]
        .iter()
        .any(|marker| name.contains(marker));
    is_env && !template
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    [
        "test",
        "tests",
        "spec",
        "__tests__",
        "fixture",
        "fixtures",
        "example",
        "examples",
        "mock",
        "mocks",
        "testdata",
        "docs",
    ]
    .iter()
    .any(|segment| lower.split('/').any(|part| part == *segment))
        || lower.contains(".test.")
        || lower.contains(".spec.")
        || lower.contains("_test.")
}

/// Values that are obviously not real credentials.
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "example",
        "changeme",
        "change_me",
        "change-me",
        "changethis",
        "your",
        "xxxx",
        "placeholder",
        "dummy",
        "sample",
        "redacted",
        "replace",
        "insert",
        "todo",
        "fake",
        "notreal",
        "secret123",
        "password123",
        "****",
        "....",
    ];
    if MARKERS.iter().any(|marker| lower.contains(marker)) {
        return true;
    }
    // Template or environment indirection rather than a literal value.
    if value.contains("${")
        || value.contains("{{")
        || value.starts_with('$')
        || value.starts_with('<')
        || lower.starts_with("process.env")
        || lower.starts_with("os.environ")
        || lower.starts_with("env(")
    {
        return true;
    }
    let first = value.chars().next();
    value.chars().all(|c| Some(c) == first)
}

/// Generic assignments match many ordinary strings (`displayName = "PasswordInput"`,
/// validation rules like `'required|min:12'`). Only values that look machine-generated
/// are reported: high entropy and not a plain word/identifier.
fn looks_generated(value: &str) -> bool {
    let word_like = value
        .chars()
        .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '-' | '.'));
    let lower = value.to_ascii_lowercase();
    let url = lower.starts_with("http://") || lower.starts_with("https://");
    // `password_change_template = "admin/password_change.html"` is a path, not a secret.
    let file_path = value.contains('/')
        && value.rsplit_once('.').is_some_and(|(_, ext)| {
            (2..=5).contains(&ext.len()) && ext.chars().all(|c| c.is_ascii_alphabetic())
        });
    !word_like
        && !url
        && !file_path
        && !value.contains('|')
        && shannon_entropy(value) >= GENERIC_MIN_ENTROPY
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = value.as_bytes();
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Redacted preview: keeps at most a 4-character prefix and 2-character suffix, and
/// hides everything for short values.
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 12 {
        return "********".to_string();
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 2..].iter().collect();
    format!("{prefix}…{suffix}")
}

/// Scans one file's text. `path` is only used for file-type and test-path decisions.
pub fn scan_text(path: &str, text: &str) -> Vec<SecretObservation> {
    let env_file = is_env_file(path);
    let in_test_path = is_test_path(path);
    let mut observations = Vec::new();
    let mut offset = 0usize;

    for (index, line) in text.split_inclusive('\n').enumerate() {
        let line_start = offset;
        offset += line.len();
        if line.len() > MAX_LINE_BYTES || line.contains(SUPPRESSION_MARKER) {
            continue;
        }
        let mut matched_ranges: Vec<(usize, usize)> = Vec::new();
        for (regex, rule) in compiled() {
            if rule.id == "secret.env_file_assignment" && !env_file {
                continue;
            }
            for captures in regex.captures_iter(line) {
                let Some(found) = captures.get(rule.group) else {
                    continue;
                };
                let value = found.as_str();
                let range = (line_start + found.start(), line_start + found.end());
                // One report per value: specific rules run first and win over generic ones.
                if matched_ranges
                    .iter()
                    .any(|&(start, end)| range.0 < end && start < range.1)
                {
                    continue;
                }
                if rule.generic && is_placeholder(value) {
                    continue;
                }
                if rule.id == "secret.generic_assignment" && !looks_generated(value) {
                    continue;
                }
                matched_ranges.push(range);
                let redacted = if rule.id == "secret.private_key" {
                    "-----BEGIN … PRIVATE KEY----- (content withheld)".to_string()
                } else {
                    redact(value)
                };
                let confidence = if in_test_path {
                    (rule.confidence * 0.6 * 100.0).round() / 100.0
                } else {
                    rule.confidence
                };
                observations.push(SecretObservation {
                    rule_id: rule.id,
                    title: rule.title,
                    severity: rule.severity,
                    confidence,
                    line: index + 1,
                    redacted,
                    secret_range: range,
                    in_test_path,
                    remediation: rule.remediation,
                });
            }
        }
    }
    observations
}

/// Heuristic binary check: a NUL byte in the first 8 KiB.
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8 * 1024).any(|&byte| byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(path: &str, text: &str) -> Vec<&'static str> {
        scan_text(path, text)
            .into_iter()
            .map(|item| item.rule_id)
            .collect()
    }

    // Test tokens are assembled at runtime so this file never contains a literal token.
    fn token(prefix: &str, body_len: usize) -> String {
        let alphabet = "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0";
        let body: String = alphabet.chars().cycle().take(body_len).collect();
        format!("{prefix}{body}")
    }

    #[test]
    fn detects_well_known_token_formats() {
        let github = token("ghp_", 36);
        let aws = format!("AKIA{}", "QWERTYUIOPASDFGH");
        let stripe = token("sk_live_", 24);
        let text = format!("const a = \"{github}\";\nkey = {aws}\nstripe = '{stripe}'\n");
        let found = rules("src/config.ts", &text);
        assert!(found.contains(&"secret.github_token"));
        assert!(found.contains(&"secret.aws_access_key_id"));
        assert!(found.contains(&"secret.stripe_live_key"));
    }

    #[test]
    fn never_returns_the_raw_secret() {
        let github = token("ghp_", 36);
        let text = format!("token = \"{github}\"\n");
        let observation = scan_text("src/a.py", &text).remove(0);
        assert!(!observation.redacted.contains(&github[4..30]));
        let (start, end) = observation.secret_range;
        assert_eq!(&text[start..end], github);
        assert!(!format!("{observation:?}").contains(&github));
    }

    #[test]
    fn private_key_headers_are_critical() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n";
        let found = scan_text("deploy/id_rsa", text);
        assert_eq!(found[0].rule_id, "secret.private_key");
        assert_eq!(found[0].severity, Severity::Critical);
        assert!(found[0].redacted.contains("withheld"));
    }

    #[test]
    fn generic_assignments_require_entropy_and_skip_placeholders() {
        let random = token("", 24);
        assert!(rules("src/app.py", &format!("api_key = \"{random}\"\n"))
            .contains(&"secret.generic_assignment"));
        for benign in [
            "password = \"changeme123\"",
            "api_key = \"your-api-key-here\"",
            "secret = \"${API_SECRET}\"",
            "password = \"aaaaaaaaaaaa\"",
            "password = \"password\"",
            "PasswordInput.displayName = \"PasswordInput\"",
            "SECRET_KEY = \"django_tests_secret_key\"",
            "\"password\" => 'required|min:12',",
            "SECRET_KEY=\"changethis\"",
            "password_change_template = \"custom_admin/password_change_form.html\"",
            "api_key_docs = \"https://example.org/docs/keys\"",
        ] {
            assert!(rules("src/app.py", benign).is_empty(), "{benign}");
        }
    }

    #[test]
    fn specific_rules_win_over_generic_ones() {
        let github = token("ghp_", 36);
        let found = rules("src/a.js", &format!("const apiKey = \"{github}\";"));
        assert_eq!(found, vec!["secret.github_token"]);
    }

    #[test]
    fn env_files_are_scanned_but_templates_are_not() {
        let value = token("", 20);
        let line = format!("DATABASE_PASSWORD={value}\n");
        assert!(rules(".env", &line).contains(&"secret.env_file_assignment"));
        assert!(rules("config/.env.production", &line).contains(&"secret.env_file_assignment"));
        assert!(rules(".env.example", &line).is_empty());
        assert!(!rules("src/main.rs", &line).contains(&"secret.env_file_assignment"));
    }

    #[test]
    fn connection_string_passwords_are_detected_but_not_placeholders() {
        let password = token("", 16);
        let url = format!("DATABASE_URL=\"postgres://app:{password}@db:5432/app\"");
        assert!(rules("src/db.ts", &url).contains(&"secret.connection_string_password"));
        assert!(rules(
            "src/db.ts",
            "url = \"postgres://app:${DB_PASSWORD}@db/app\""
        )
        .is_empty());
    }

    #[test]
    fn suppression_marker_and_test_paths() {
        let github = token("ghp_", 36);
        let suppressed = format!("t = \"{github}\" // {SUPPRESSION_MARKER}\n");
        assert!(rules("src/a.ts", &suppressed).is_empty());
        let in_test = scan_text("tests/fixtures/auth.ts", &format!("t = \"{github}\"\n"));
        assert!(in_test[0].in_test_path);
        assert!(in_test[0].confidence < 0.97);
    }

    #[test]
    fn redaction_hides_short_values_entirely() {
        assert_eq!(redact("short"), "********");
        assert_eq!(redact("AKIAABCDEFGHIJKLMNOP"), "AKIA…OP");
    }

    #[test]
    fn binary_detection() {
        assert!(looks_binary(b"abc\0def"));
        assert!(!looks_binary(b"plain text"));
    }
}
