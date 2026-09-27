use url::Url;

use crate::{
    headers_map, response_evidence, response_header, CheckConfig, EndpointObservation,
    FindingObservation, ObservedResponse,
};

pub fn analyze_response(
    target: &Url,
    endpoint: &EndpointObservation,
    response: &ObservedResponse,
    checks: &CheckConfig,
) -> Vec<FindingObservation> {
    let mut findings = Vec::new();
    let headers = headers_map(response);
    let content_type = response
        .content_type
        .clone()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body = String::from_utf8_lossy(&response.body);
    let body_lower = body.to_ascii_lowercase();

    if content_type.contains("text/html") {
        header_presence_findings(target, endpoint, response, &headers, &mut findings);
        if target.scheme() == "https" && body_lower.contains("http://") {
            findings.push(simple(
                target,
                endpoint,
                "mixed_content",
                "medium",
                "Potential",
                "HTTPS page contains HTTP resource references",
                "The response contains an http:// reference. Review whether active content or sensitive resources can be loaded over cleartext.",
                "Mixed content can weaken transport guarantees and may be blocked by modern browsers.",
                "Serve all page resources over HTTPS and use CSP upgrade-insecure-requests where appropriate.",
                response_evidence("mixed-content indicator", &endpoint.method, target, response),
            ));
        }
    }

    if checks.session {
        for value in response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value)
        {
            let lower = value.to_ascii_lowercase();
            let cookie_name = value.split('=').next().unwrap_or("cookie").trim();
            if target.scheme() == "https" && !lower.contains("; secure") {
                findings.push(simple(
                    target,
                    endpoint,
                    "session_cookie",
                    "medium",
                    "Likely",
                    "Session cookie may be missing Secure",
                    &format!("Cookie {cookie_name} was set over HTTPS without an observed Secure attribute."),
                    "A cookie without Secure may be exposed over a cleartext connection if the application permits one.",
                    "Set Secure on authentication/session cookies and keep the application HTTPS-only.",
                    response_evidence("Set-Cookie attributes", &endpoint.method, target, response),
                ));
            }
            if !lower.contains("httponly") {
                findings.push(simple(
                    target,
                    endpoint,
                    "session_cookie",
                    "low",
                    "Likely",
                    "Cookie may be missing HttpOnly",
                    &format!(
                        "Cookie {cookie_name} was set without an observed HttpOnly attribute."
                    ),
                    "Script-readable session cookies increase the impact of client-side injection.",
                    "Set HttpOnly on session cookies that do not require JavaScript access.",
                    response_evidence("Set-Cookie attributes", &endpoint.method, target, response),
                ));
            }
            if !lower.contains("samesite=") {
                findings.push(simple(
                    target,
                    endpoint,
                    "session_cookie",
                    "low",
                    "Potential",
                    "Cookie has no explicit SameSite attribute",
                    &format!("Cookie {cookie_name} did not include an explicit SameSite attribute."),
                    "Cross-site cookie sending can increase CSRF exposure depending on browser defaults and request patterns.",
                    "Set SameSite=Lax or Strict where compatible; use SameSite=None only with Secure when cross-site use is required.",
                    response_evidence("Set-Cookie attributes", &endpoint.method, target, response),
                ));
            }
        }

        let authenticated = response_header(response, "set-cookie").is_some();
        if authenticated {
            let cache = headers
                .get("cache-control")
                .map(String::as_str)
                .unwrap_or("");
            if !cache.to_ascii_lowercase().contains("no-store")
                && !cache.to_ascii_lowercase().contains("private")
            {
                findings.push(simple(
                    target,
                    endpoint,
                    "sensitive_cache_control",
                    "low",
                    "Potential",
                    "Authenticated response may be cacheable",
                    "A response that sets cookies did not advertise no-store or private cache semantics.",
                    "Sensitive authenticated content may be retained by intermediary or shared caches depending on surrounding controls.",
                    "Use Cache-Control: no-store for highly sensitive responses, or private with an appropriate cache policy.",
                    response_evidence("cache-control review", &endpoint.method, target, response),
                ));
            }
        }
    }

    if checks.cors {
        if let Some(origin) = headers.get("access-control-allow-origin") {
            let credentials = headers
                .get("access-control-allow-credentials")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            if origin.trim() == "*" && credentials {
                findings.push(simple(
                    target,
                    endpoint,
                    "cors",
                    "high",
                    "Likely",
                    "Wildcard CORS combined with credential allowance",
                    "The response advertises Access-Control-Allow-Origin: * together with credential allowance.",
                    "Overly broad cross-origin policy can expose authenticated APIs if browsers or middleware interpret the combination unsafely.",
                    "Return an explicit trusted origin allow-list and do not enable credentials for untrusted origins.",
                    response_evidence("CORS headers", &endpoint.method, target, response),
                ));
            } else if origin.trim() == "*" {
                findings.push(simple(
                    target,
                    endpoint,
                    "cors",
                    "low",
                    "Potential",
                    "Wildcard CORS policy observed",
                    "The response advertises Access-Control-Allow-Origin: *.",
                    "Public cross-origin reads may be intentional, but sensitive APIs should not expose data to every origin.",
                    "Restrict Access-Control-Allow-Origin to required origins for non-public resources.",
                    response_evidence("CORS headers", &endpoint.method, target, response),
                ));
            }
        }
    }

    if response.status >= 500
        && [
            "stack trace",
            "traceback (most recent call last)",
            "sqlstate[",
            "syntaxerror:",
            "referenceerror:",
            "exception in thread",
        ]
        .iter()
        .any(|needle| body_lower.contains(needle))
    {
        findings.push(simple(
            target,
            endpoint,
            "verbose_error",
            "medium",
            "Likely",
            "Verbose application error disclosed",
            "A server-error response contains stack/error details characteristic of application internals.",
            "Verbose errors can reveal code paths, frameworks, database behavior, or other details useful for further attacks.",
            "Return generic production error responses and keep detailed traces in protected server-side logs.",
            response_evidence("verbose error response", &endpoint.method, target, response),
        ));
    }

    for header in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(value) = headers.get(header) {
            if value.chars().any(|character| character.is_ascii_digit()) {
                findings.push(simple(
                    target,
                    endpoint,
                    "information_disclosure",
                    "informational",
                    "Potential",
                    "Technology/version response header disclosed",
                    &format!("Response header {header} exposes a product/version-like value."),
                    "Version disclosure can make targeted vulnerability research easier but is not itself proof of exploitability.",
                    "Suppress unnecessary framework/server version headers where practical.",
                    response_evidence("response header disclosure", &endpoint.method, target, response),
                ));
            }
        }
    }

    findings
}

pub fn analyze_form(
    target: &Url,
    endpoint: &EndpointObservation,
    hidden_names: &[String],
    checks: &CheckConfig,
) -> Vec<FindingObservation> {
    if !checks.csrf
        || !matches!(
            endpoint.method.as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        )
    {
        return Vec::new();
    }
    let token_present = hidden_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        [
            "csrf",
            "xsrf",
            "requestverificationtoken",
            "authenticity_token",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    });
    if token_present {
        return Vec::new();
    }
    vec![FindingObservation {
        category: "csrf".to_string(),
        severity: "low".to_string(),
        confidence: "Potential".to_string(),
        target: target.to_string(),
        endpoint: endpoint.url.clone(),
        method: endpoint.method.clone(),
        parameter: None,
        title: "State-changing form has no observed anti-CSRF field".to_string(),
        description: "A state-changing HTML form was discovered without a recognizable anti-CSRF hidden input. Framework-level Origin/Referer validation or SameSite protections may still prevent CSRF.".to_string(),
        reproduction_summary: "Inspect the discovered form and server-side CSRF validation. No state-changing request was submitted by CodeTwin.".to_string(),
        impact: "If no server-side anti-CSRF control exists, another site may be able to trigger an authenticated state change.".to_string(),
        remediation: "Use the framework's anti-CSRF middleware/token validation and appropriate SameSite cookie policy. Treat Origin/Referer validation as defense in depth.".to_string(),
        references: vec!["CWE-352".to_string(), "OWASP A01:2021 Broken Access Control".to_string()],
        evidence: vec![],
    }]
}

fn header_presence_findings(
    target: &Url,
    endpoint: &EndpointObservation,
    response: &ObservedResponse,
    headers: &std::collections::HashMap<String, String>,
    output: &mut Vec<FindingObservation>,
) {
    let checks = [
        ("content-security-policy", "csp", "medium", "Content-Security-Policy header is missing", "Define a restrictive Content-Security-Policy appropriate to the application."),
        ("x-content-type-options", "security_headers", "low", "X-Content-Type-Options header is missing", "Send X-Content-Type-Options: nosniff."),
        ("referrer-policy", "security_headers", "low", "Referrer-Policy header is missing", "Set a Referrer-Policy such as strict-origin-when-cross-origin or stricter where appropriate."),
        ("permissions-policy", "security_headers", "informational", "Permissions-Policy header is missing", "Restrict browser capabilities that the application does not require."),
    ];
    for (header, category, severity, title, remediation) in checks {
        if !headers.contains_key(header) {
            output.push(simple(
                target,
                endpoint,
                category,
                severity,
                "Likely",
                title,
                &format!("The HTML response did not include the {header} header."),
                "Missing browser security headers can reduce defense in depth; severity depends on the application's content and threat model.",
                remediation,
                response_evidence("response header review", &endpoint.method, target, response),
            ));
        }
    }
    if target.scheme() == "https" && !headers.contains_key("strict-transport-security") {
        output.push(simple(
            target,
            endpoint,
            "hsts",
            "medium",
            "Likely",
            "Strict-Transport-Security header is missing",
            "An HTTPS response did not include an HSTS policy.",
            "Without HSTS, first-visit downgrade opportunities may remain on deployments that also expose HTTP.",
            "Enable HSTS after confirming the complete site and relevant subdomains are HTTPS-ready.",
            response_evidence("HSTS review", &endpoint.method, target, response),
        ));
    }
}

fn simple(
    target: &Url,
    endpoint: &EndpointObservation,
    category: &str,
    severity: &str,
    confidence: &str,
    title: &str,
    description: &str,
    impact: &str,
    remediation: &str,
    evidence: crate::EvidenceObservation,
) -> FindingObservation {
    FindingObservation {
        category: category.to_string(),
        severity: severity.to_string(),
        confidence: confidence.to_string(),
        target: target.to_string(),
        endpoint: endpoint.url.clone(),
        method: endpoint.method.clone(),
        parameter: None,
        title: title.to_string(),
        description: description.to_string(),
        reproduction_summary: "Request the endpoint and inspect the cited response metadata. CodeTwin stores redacted bounded evidence only.".to_string(),
        impact: impact.to_string(),
        remediation: remediation.to_string(),
        references: Vec::new(),
        evidence: vec![evidence],
    }
}
