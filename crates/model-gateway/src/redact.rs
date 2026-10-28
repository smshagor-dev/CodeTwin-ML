//! Secret redaction applied to every cloud-bound payload and preview.
use std::sync::OnceLock;

use regex::Regex;

fn patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            (r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED:private_key]"),
            (r"\b\d+\|om_[A-Za-z0-9]{16,}\b", "[REDACTED:openmindai_key]"),
            (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED:aws_access_key]"),
            (r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", "[REDACTED:github_token]"),
            (r"\bgithub_pat_[A-Za-z0-9_]{40,}\b", "[REDACTED:github_token]"),
            (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "[REDACTED:slack_token]"),
            (r"\bsk-[A-Za-z0-9_-]{20,}\b", "[REDACTED:api_key]"),
            (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED:jwt]"),
            (r"(?i)\bbearer\s+[A-Za-z0-9._~+/|=-]{12,}", "Bearer [REDACTED:token]"),
            (r"(?i)\b(?:[a-z][a-z0-9_]*[_-])?(?:api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\x22]?[^\s'\x22,;]{6,}", "[REDACTED:assignment]"),
            (r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@", "[REDACTED:url_credentials]@"),
        ]
        .into_iter()
        .map(|(p, r)| (Regex::new(p).expect("valid redaction regex"), r))
        .collect()
    })
}

/// Redact secrets; returns the redacted text and the number of replacements.
pub fn redact(text: &str) -> (String, usize) {
    let mut out = text.to_owned();
    let mut count = 0;
    for (regex, replacement) in patterns() {
        let n = regex.find_iter(&out).count();
        if n > 0 {
            count += n;
            out = regex.replace_all(&out, *replacement).into_owned();
        }
    }
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secret_shapes() {
        // Fixtures are assembled at runtime so the repository's tracked
        // private-key guard and secret scanners never see literal key shapes.
        let armor = |edge: &str| format!("-----{edge} RSA {}-----", ["PRIVATE", "KEY"].join(" "));
        let input = format!(
            "key=7|om_SyntheticTestValue0000000 and {aws}\n\
             password: hunter2hunter2 {gh}\n\
             Authorization: Bearer abcdefghijklmnop.qrstuvwxyz\n\
             postgres://admin:s3cret@db.local/app\n\
             {begin}\nMIIEow\n{end}",
            aws = ["AKIA", "SYNTHETICTEST000"].concat(),
            gh = ["gh", "p_", "syntheticfixture000000000000000000"].concat(),
            begin = armor("BEGIN"),
            end = armor("END"),
        );
        let (out, n) = redact(&input);
        for leaked in [
            "om_Synthetic",
            "SYNTHETICTEST000",
            "hunter2",
            "syntheticfixture",
            "abcdefghijklmnop.qrs",
            "s3cret",
            "MIIEow",
        ] {
            assert!(!out.contains(leaked), "{leaked} leaked in {out}");
        }
        assert!(n >= 7);
    }

    #[test]
    fn leaves_ordinary_code_alone() {
        let code = "fn token_count(tokens: &[Token]) -> usize { tokens.len() }";
        assert_eq!(redact(code), (code.to_owned(), 0));
    }
}
