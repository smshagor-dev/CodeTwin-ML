use crate::request::RequestError;

const MAX_PAYLOAD_BYTES: usize = 256;

pub(crate) fn validate_active_payload(payload: &str) -> Result<(), RequestError> {
    if payload.as_bytes().len() > MAX_PAYLOAD_BYTES {
        return Err(RequestError::PayloadPolicy(format!(
            "active probe payload exceeds {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    if payload.contains('\0') || payload.contains('\r') || payload.contains('\n') {
        return Err(RequestError::PayloadPolicy(
            "active probe payload contains forbidden control characters".to_string(),
        ));
    }

    let normalized = payload.to_ascii_lowercase();
    let compact = normalized.split_whitespace().collect::<Vec<_>>().join(" ");

    const DESTRUCTIVE_SQL: &[&str] = &[
        "drop table",
        "drop database",
        "truncate table",
        "delete from",
        "insert into",
        "alter table",
        "create table",
        "create database",
        "grant ",
        "revoke ",
        "replace into",
        "merge into",
        "into outfile",
        "into dumpfile",
        "load_file(",
        "pg_read_file(",
        "pg_write_file(",
        "xp_cmdshell",
        "sp_oacreate",
        "copy ",
    ];
    if DESTRUCTIVE_SQL.iter().any(|needle| compact.contains(needle)) {
        return Err(RequestError::PayloadPolicy(
            "destructive or file-access SQL payloads are forbidden".to_string(),
        ));
    }
    if compact.contains("update ") && compact.contains(" set ") {
        return Err(RequestError::PayloadPolicy(
            "state-changing SQL UPDATE payloads are forbidden".to_string(),
        ));
    }

    const COMMAND_EXECUTION: &[&str] = &[
        "cmd.exe",
        "powershell",
        "pwsh ",
        "/bin/sh",
        "/bin/bash",
        "bash -c",
        "sh -c",
        "rm -",
        "del /",
        "curl ",
        "wget ",
        "certutil ",
        "bitsadmin ",
        "nc ",
        "netcat ",
    ];
    if COMMAND_EXECUTION.iter().any(|needle| compact.contains(needle)) {
        return Err(RequestError::PayloadPolicy(
            "command-execution or downloader payloads are forbidden".to_string(),
        ));
    }

    const FORBIDDEN_SCHEMES: &[&str] = &[
        "file://",
        "gopher://",
        "dict://",
        "ftp://",
        "smb://",
        "ldap://",
    ];
    if FORBIDDEN_SCHEMES
        .iter()
        .any(|scheme| normalized.contains(scheme))
    {
        return Err(RequestError::PayloadPolicy(
            "non-HTTP network/file protocol payloads are forbidden".to_string(),
        ));
    }

    if compact.contains("<script")
        || compact.contains("javascript:")
        || compact.contains("onerror=")
        || compact.contains("onload=")
    {
        return Err(RequestError::PayloadPolicy(
            "executable browser-script payloads are forbidden; use reflection markers only"
                .to_string(),
        ));
    }

    if compact.contains("sleep(") && !compact.contains("sleep(1)") {
        return Err(RequestError::PayloadPolicy(
            "timing probes are capped to one second".to_string(),
        ));
    }
    if compact.contains("pg_sleep(") && !compact.contains("pg_sleep(1)") {
        return Err(RequestError::PayloadPolicy(
            "timing probes are capped to one second".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_active_payload;

    #[test]
    fn allows_bounded_non_destructive_probe_shapes() {
        for payload in [
            "'",
            "' OR '1'='1' -- ",
            "' UNION SELECT NULL-- ",
            "1' OR SLEEP(1)-- ",
            "<codetwin-xss-marker>",
            "codetwin-{{7*7}}",
        ] {
            validate_active_payload(payload).expect(payload);
        }
    }

    #[test]
    fn blocks_destructive_and_execution_payloads() {
        for payload in [
            "'; DROP TABLE users; --",
            "'; DELETE FROM users; --",
            "1; UPDATE users SET admin=1",
            "file:///etc/passwd",
            "powershell -enc AAA",
            "<script>alert(1)</script>",
            "1' OR SLEEP(10)-- ",
        ] {
            assert!(validate_active_payload(payload).is_err(), "{payload}");
        }
    }
}
