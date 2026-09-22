const MAX_ACTIVE_PAYLOAD_BYTES: usize = 512;

pub fn validate_active_payload(payload: &str) -> Result<(), &'static str> {
    if payload.as_bytes().len() > MAX_ACTIVE_PAYLOAD_BYTES {
        return Err("payload exceeds the bounded active-probe size");
    }
    if payload.contains('\0') {
        return Err("NUL bytes are not allowed in active probes");
    }
    if payload.contains("\r\n") || payload.contains('\n') || payload.contains('\r') {
        return Err("line-break injection is not allowed in active probes");
    }

    let lower = payload.to_ascii_lowercase();
    for prohibited in [
        "drop table",
        "drop database",
        "truncate table",
        "delete from",
        "insert into",
        "update ",
        "alter table",
        "create table",
        "grant ",
        "revoke ",
        "shutdown",
        "reboot",
        "xp_cmdshell",
        "sp_oacreate",
        "load_file(",
        "pg_read_file",
        "pg_write_file",
        "lo_import",
        "lo_export",
        "into outfile",
        "into dumpfile",
        "union select",
        "sleep(",
        "benchmark(",
        "pg_sleep(",
        "waitfor delay",
        "/etc/passwd",
        "169.254.169.254",
        "metadata.google.internal",
        "powershell",
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "curl ",
        "wget ",
        "certutil",
        "invoke-webrequest",
        "netcat",
    ] {
        if lower.contains(prohibited) {
            return Err("destructive, extraction, delay, or command primitive is not allowed in active probes");
        }
    }

    for shell in ["&&", "$(", "`", "| powershell", "| cmd", "| sh ", "| bash"] {
        if lower.contains(shell) {
            return Err("shell execution syntax is not allowed in active probes");
        }
    }

    for scheme in ["file://", "gopher://", "dict://", "ftp://"] {
        if lower.contains(scheme) {
            return Err("non-HTTP outbound scheme is not allowed in active probes");
        }
    }

    // Outbound URL-shaped test values are restricted to documentation-only
    // destinations. Validate every occurrence so a safe first URL cannot mask
    // a later arbitrary destination in the same payload.
    for scheme in ["http://", "https://"] {
        for (index, _) in lower.match_indices(scheme) {
            let tail = &lower[index..];
            let allowed = tail.starts_with("http://192.0.2.1/")
                || tail.starts_with("https://192.0.2.1/")
                || tail.starts_with("http://example.invalid/")
                || tail.starts_with("https://example.invalid/");
            if !allowed {
                return Err("outbound URL is outside the fixed non-routable probe allow-list");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_active_payload;

    #[test]
    fn allows_current_non_destructive_probe_shapes() {
        for payload in [
            "",
            "'",
            "' OR '1'='1' -- ",
            "' AND '1'='2' -- ",
            "<codetwin-xss-marker>",
            "../../../../codetwin-nonexistent.txt",
            "http://192.0.2.1/codetwin-test",
            "https://example.invalid/codetwin-test",
            "codetwin-{{7*7}}",
            "CODETWIN_INVALID_marker_%00_[]{}",
        ] {
            validate_active_payload(payload).expect(payload);
        }
    }

    #[test]
    fn rejects_destructive_extraction_delay_or_shell_shapes() {
        for payload in [
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL-- ",
            "1' OR SLEEP(1)-- ",
            "' UNION SELECT load_file('/etc/passwd')--",
            "x && rm -rf /",
            "$(whoami)",
            "file:///etc/passwd",
            "x\r\nX-Test: injected",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/admin",
            "http://192.0.2.1/codetwin-test http://10.0.0.5/admin",
            "https://example.invalid/codetwin-test https://169.254.169.254/latest/meta-data/",
            "powershell -enc AAAA",
        ] {
            assert!(validate_active_payload(payload).is_err(), "{payload}");
        }
    }

    #[test]
    fn rejects_oversized_payloads() {
        assert!(validate_active_payload(&"a".repeat(513)).is_err());
    }
}
