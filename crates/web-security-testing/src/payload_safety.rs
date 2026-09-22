use thiserror::Error;

pub const MAX_ACTIVE_PAYLOAD_BYTES: usize = 512;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PayloadSafetyError {
    #[error("active probe payload is empty")]
    Empty,
    #[error("active probe payload exceeds the bounded {MAX_ACTIVE_PAYLOAD_BYTES}-byte limit")]
    TooLarge,
    #[error("active probe payload contains a NUL byte")]
    NulByte,
    #[error("active probe payload contains a prohibited destructive or exfiltration primitive")]
    ProhibitedPrimitive,
    #[error("active probe payload contains an unapproved outbound URL")]
    UnapprovedOutboundUrl,
}

pub fn validate_active_payload(payload: &str) -> Result<(), PayloadSafetyError> {
    if payload.is_empty() {
        return Err(PayloadSafetyError::Empty);
    }
    if payload.as_bytes().len() > MAX_ACTIVE_PAYLOAD_BYTES {
        return Err(PayloadSafetyError::TooLarge);
    }
    if payload.contains('\0') {
        return Err(PayloadSafetyError::NulByte);
    }

    let normalized = payload.to_ascii_lowercase();
    let prohibited = [
        "drop table",
        "drop database",
        "truncate table",
        "delete from",
        "insert into",
        "update ",
        " into outfile",
        " into dumpfile",
        "load_file(",
        "xp_cmdshell",
        "sp_oacreate",
        "copy ",
        "pg_read_file",
        "pg_write_file",
        "lo_import",
        "lo_export",
        "shutdown",
        "reboot",
        "powershell",
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "curl ",
        "wget ",
        "certutil",
        "invoke-webrequest",
        "nc ",
        "netcat",
        "169.254.169.254",
        "metadata.google.internal",
    ];
    if prohibited.iter().any(|needle| normalized.contains(needle)) {
        return Err(PayloadSafetyError::ProhibitedPrimitive);
    }

    // Active SSRF indicators are intentionally limited to documentation-only
    // TEST-NET destinations. Any other absolute outbound URL is rejected here.
    for scheme in ["http://", "https://"] {
        if let Some(index) = normalized.find(scheme) {
            let tail = &normalized[index..];
            let allowed = tail.starts_with("http://192.0.2.1/")
                || tail.starts_with("https://example.invalid/")
                || tail.starts_with("http://example.invalid/")
                || tail.starts_with("https://192.0.2.1/");
            if !allowed {
                return Err(PayloadSafetyError::UnapprovedOutboundUrl);
            }
        }
    }

    // Timing probes are capped to the one-second, fixed detector shape used by
    // CodeTwin. Longer or alternative delay functions are not permitted.
    if normalized.contains("sleep(") && !normalized.contains("sleep(1)") {
        return Err(PayloadSafetyError::ProhibitedPrimitive);
    }
    if normalized.contains("pg_sleep(")
        || normalized.contains("waitfor delay")
        || normalized.contains("benchmark(")
    {
        return Err(PayloadSafetyError::ProhibitedPrimitive);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_active_payload, PayloadSafetyError};

    #[test]
    fn accepts_bounded_detector_payloads() {
        for payload in [
            "'",
            "' OR '1'='1' -- ",
            "' UNION SELECT NULL-- ",
            "1' OR SLEEP(1)-- ",
            "<codetwin-xss-abc>",
            "../../../../codetwin-nonexistent-abc.txt",
            "http://192.0.2.1/codetwin-abc",
            "https://example.invalid/codetwin-abc",
            "codetwin-abc-{{7*7}}",
            "CODETWIN_INVALID_abc_%00_[]{}",
        ] {
            validate_active_payload(payload).expect(payload);
        }
    }

    #[test]
    fn rejects_destructive_or_exfiltration_payloads() {
        for payload in [
            "'; DROP TABLE users; --",
            "' UNION SELECT load_file('/etc/passwd')--",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/admin",
            "1' OR SLEEP(15)--",
            "powershell -enc AAAA",
        ] {
            assert!(validate_active_payload(payload).is_err(), "{payload}");
        }
    }

    #[test]
    fn rejects_oversized_payloads() {
        let payload = "a".repeat(513);
        assert_eq!(
            validate_active_payload(&payload),
            Err(PayloadSafetyError::TooLarge)
        );
    }
}
