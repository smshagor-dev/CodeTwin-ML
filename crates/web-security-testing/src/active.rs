use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use reqwest::Method;
use url::Url;

use crate::{
    body_hash, endpoint_request_key, fingerprint, operator::check_applicable,
    parameter_has_location, payload_policy::validate_active_payload, response_evidence,
    response_header, single_parameter_location, AuthContext, EndpointObservation,
    FindingObservation, ObservedResponse, RequestError, RequestSeedContext, ScanConfig,
    ScanError, ScopePolicy, ScopedRequester,
};

pub(crate) struct ActiveCheckContext<'a> {
    pub policy: &'a ScopePolicy,
    pub requester: &'a ScopedRequester,
    pub secondary_auth: Option<&'a AuthContext>,
    pub config: &'a ScanConfig,
    pub endpoints: &'a [EndpointObservation],
    pub baselines: &'a HashMap<String, ObservedResponse>,
    pub request_seeds: &'a HashMap<String, RequestSeedContext>,
    pub cancelled: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ProbeTask {
    endpoint: EndpointObservation,
    baseline: Option<ObservedResponse>,
    parameter: String,
    request_seed: RequestSeedContext,
}

pub(crate) fn run_active_checks(
    context: ActiveCheckContext<'_>,
    on_progress: &mut impl FnMut(usize),
) -> Result<Vec<FindingObservation>, ScanError> {
    let ActiveCheckContext {
        policy,
        requester,
        secondary_auth,
        config,
        endpoints,
        baselines,
        request_seeds,
        cancelled,
    } = context;
    let mut findings = Vec::new();
    let mut tasks = Vec::new();
    for endpoint in endpoints {
        if !method_probe_allowed(&endpoint.method, config.scope.allow_non_idempotent_methods) {
            continue;
        }
        let baseline = baselines
            .get(&baseline_key(&endpoint.method, &endpoint.url))
            .or_else(|| {
                (endpoint.method == "GET")
                    .then(|| baselines.get(&normalized_key(&endpoint.url)))
                    .flatten()
            })
            .cloned();
        let request_seed = request_seeds
            .get(&endpoint_request_key(&endpoint.method, &endpoint.url))
            .cloned()
            .unwrap_or_default();
        for parameter in &endpoint.parameter_names {
            tasks.push(ProbeTask {
                endpoint: endpoint.clone(),
                baseline: baseline.clone(),
                parameter: parameter.clone(),
                request_seed: request_seed.clone(),
            });
        }
    }

    let concurrency = policy.config().concurrency.max(1);
    for chunk in tasks.chunks(concurrency) {
        if cancelled.load(Ordering::SeqCst) {
            return Err(ScanError::Cancelled);
        }
        let mut chunk_results = Vec::new();
        let chunk_state = thread::scope(|scope| -> Result<bool, ScanError> {
            let mut handles = Vec::new();
            for task in chunk.iter().cloned() {
                let requester = requester.clone();
                let policy = policy.clone();
                let config = config.clone();
                let cancelled = Arc::clone(&cancelled);
                handles.push(scope.spawn(move || {
                    probe_parameter(&policy, &requester, &config, &task, cancelled)
                }));
            }

            let mut cancelled_observed = false;
            let mut first_error = None;
            let mut worker_panicked = false;
            for handle in handles {
                match handle.join() {
                    Ok(Ok(mut observed)) => chunk_results.append(&mut observed),
                    Ok(Err(ScanError::Cancelled)) => cancelled_observed = true,
                    Ok(Err(error)) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                    Err(_) => worker_panicked = true,
                }
            }

            if worker_panicked {
                return Err(ScanError::Discovery(
                    "active probe worker panicked before producing a result".to_string(),
                ));
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            Ok(cancelled_observed)
        })?;
        if chunk_state || cancelled.load(Ordering::SeqCst) {
            return Err(ScanError::Cancelled);
        }
        findings.append(&mut chunk_results);
        on_progress(findings.len());
    }

    for endpoint in endpoints.iter().filter(|item| item.method == "GET").take(256) {
        if cancelled.load(Ordering::SeqCst) {
            return Err(ScanError::Cancelled);
        }
        if config.checks.cors || config.checks.method_misconfiguration {
            findings.extend(probe_options(requester, endpoint, config)?);
            on_progress(findings.len());
        }
    }

    if config.checks.access_control {
        if let Some(secondary) = secondary_auth.filter(|auth| {
            auth.cookie_header.as_ref().is_some_and(|value| !value.trim().is_empty())
                || auth.bearer_token.as_ref().is_some_and(|value| !value.trim().is_empty())
                || !auth.custom_headers.is_empty()
        }) {
            let secondary_requester = ScopedRequester::new(
                policy.clone(),
                secondary.clone(),
                requester.budget().clone(),
                Arc::clone(&cancelled),
            );
            for endpoint in endpoints.iter().filter(|item| item.method == "GET").take(128) {
                if !looks_object_specific(endpoint) {
                    continue;
                }
                let Ok(url) = policy.normalize_and_assert(&endpoint.url) else { continue };
                let Some(primary) = baselines
                    .get(&baseline_key("GET", &endpoint.url))
                    .or_else(|| baselines.get(&normalized_key(&endpoint.url)))
                else {
                    continue;
                };
                match secondary_requester.get(&url) {
                    Ok(secondary_response) => {
                        if (200..300).contains(&primary.status)
                            && (200..300).contains(&secondary_response.status)
                            && primary.body.len() > 32
                            && body_hash(&primary.body) == body_hash(&secondary_response.body)
                        {
                            findings.push(FindingObservation {
                                category: "access_control".into(),
                                severity: "medium".into(),
                                confidence: "Potential".into(),
                                target: policy.target().to_string(),
                                endpoint: endpoint.url.clone(),
                                method: "GET".into(),
                                parameter: None,
                                title: "Different supplied identities received identical object response".into(),
                                description: "Two explicitly supplied authorization contexts received byte-identical success responses for an object-like endpoint. This can be legitimate shared access, so CodeTwin does not label it confirmed IDOR.".into(),
                                reproduction_summary: "Repeat the same object request with the two configured test identities and verify the intended authorization policy. No identifier enumeration was performed.".into(),
                                impact: "If the secondary identity should not access this object, object-level authorization may be missing.".into(),
                                remediation: "Enforce authorization on the server for every object lookup using the authenticated principal and object policy, independent of client-supplied identifiers.".into(),
                                references: vec!["CWE-639".into(), "OWASP API1:2023 Broken Object Level Authorization".into()],
                                evidence: vec![
                                    response_evidence("primary identity", "GET", &url, primary),
                                    response_evidence("secondary identity", "GET", &url, &secondary_response),
                                ],
                            });
                            on_progress(findings.len());
                        }
                    }
                    Err(RequestError::BudgetExhausted) => break,
                    Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
                    Err(_) => {}
                }
            }
        }
    }

    Ok(findings)
}

fn probe_parameter(
    policy: &ScopePolicy,
    requester: &ScopedRequester,
    config: &ScanConfig,
    task: &ProbeTask,
    cancelled: Arc<AtomicBool>,
) -> Result<Vec<FindingObservation>, ScanError> {
    if cancelled.load(Ordering::SeqCst) {
        return Err(ScanError::Cancelled);
    }
    let endpoint_url = policy.normalize_and_assert(&task.endpoint.url)?;
    let baseline = match task.baseline.clone() {
        Some(value) => value,
        None => match send_task_payload(requester, task, &endpoint_url, "") {
            Ok(value) => value,
            Err(RequestError::BudgetExhausted) => return Ok(Vec::new()),
            Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
            Err(_) => return Ok(Vec::new()),
        },
    };
    let marker = short_marker(&task.endpoint.url, &task.parameter);
    let mut findings = Vec::new();

    if config.checks.sql_injection && check_applicable(&task.endpoint, &task.parameter, "sql_injection") {
        findings.extend(probe_sqli(requester, policy, task, &endpoint_url, &baseline)?);
    }
    if config.checks.xss && check_applicable(&task.endpoint, &task.parameter, "xss") {
        if let Some(finding) = probe_xss(requester, policy, task, &endpoint_url, &baseline, &marker)? {
            findings.push(finding);
        }
    }
    if config.checks.open_redirect && looks_redirect_parameter(&task.parameter) {
        if let Some(finding) = probe_open_redirect(requester, policy, task, &endpoint_url, &marker)? {
            findings.push(finding);
        }
    }
    if config.checks.path_traversal && looks_path_parameter(&task.parameter) {
        if let Some(finding) = probe_path_traversal(requester, policy, task, &endpoint_url, &baseline, &marker)? {
            findings.push(finding);
        }
    }
    if config.checks.ssrf_indicators && looks_url_parameter(&task.parameter) {
        if let Some(finding) = probe_ssrf_indicator(requester, policy, task, &endpoint_url, &baseline, &marker)? {
            findings.push(finding);
        }
    }
    if config.checks.template_command_indicators && check_applicable(&task.endpoint, &task.parameter, "template_injection") {
        if let Some(finding) = probe_template_indicator(requester, policy, task, &endpoint_url, &baseline, &marker)? {
            findings.push(finding);
        }
    }
    if config.checks.api_validation && check_applicable(&task.endpoint, &task.parameter, "api_validation") {
        if let Some(finding) = probe_input_validation(requester, policy, task, &endpoint_url, &baseline, &marker)? {
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn probe_sqli(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    baseline: &ObservedResponse,
) -> Result<Vec<FindingObservation>, ScanError> {
    let mut findings = Vec::new();
    let quote = match send_task_payload(requester, task, url, "'") {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(findings),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(findings),
    };
    if !contains_sql_error(&baseline.body) && contains_sql_error(&quote.body) {
        findings.push(FindingObservation {
            category: "sql_injection".into(),
            severity: "high".into(),
            confidence: "Likely".into(),
            target: policy.target().to_string(),
            endpoint: task.endpoint.url.clone(),
            method: task.endpoint.method.clone(),
            parameter: Some(task.parameter.clone()),
            title: "SQL error behavior triggered by a quote probe".into(),
            description: "A conservative quote-only probe produced database/parser error indicators that were not present in the baseline response.".into(),
            reproduction_summary: format!("Compare the baseline response with a request where parameter {} is replaced by a single quote. Do not use data-extraction payloads.", task.parameter),
            impact: "If user input reaches SQL syntax, an attacker may be able to alter query behavior depending on the database API and surrounding query.".into(),
            remediation: "Keep SQL structure fixed and bind data through prepared/parameterized APIs. Map dynamic identifiers through fixed allow-lists.".into(),
            references: vec!["CWE-89".into(), "OWASP A03:2021 Injection".into()],
            evidence: vec![
                response_evidence("baseline", &task.endpoint.method, url, baseline),
                response_evidence("quote probe", &task.endpoint.method, url, &quote),
            ],
        });
    }

    let true_payload = "' OR '1'='1' -- ";
    let false_payload = "' AND '1'='2' -- ";
    let true_response = match send_task_payload(requester, task, url, true_payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(findings),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(findings),
    };
    let false_response = match send_task_payload(requester, task, url, false_payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(findings),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(findings),
    };
    if similar_response(baseline, &true_response) && materially_different(baseline, &false_response) {
        let mut confidence = "Likely";
        let mut evidence = vec![
            response_evidence("baseline", &task.endpoint.method, url, baseline),
            response_evidence("boolean true probe", &task.endpoint.method, url, &true_response),
            response_evidence("boolean false probe", &task.endpoint.method, url, &false_response),
        ];
        if let (Ok(true_repeat), Ok(false_repeat)) = (
            send_task_payload(requester, task, url, true_payload),
            send_task_payload(requester, task, url, false_payload),
        ) {
            if similar_response(baseline, &true_repeat)
                && materially_different(baseline, &false_repeat)
                && similar_response(&false_response, &false_repeat)
            {
                confidence = "Confirmed";
                evidence.push(response_evidence("boolean true repeat", &task.endpoint.method, url, &true_repeat));
                evidence.push(response_evidence("boolean false repeat", &task.endpoint.method, url, &false_repeat));
            }
        }
        findings.push(FindingObservation {
            category: "sql_injection".into(),
            severity: if confidence == "Confirmed" { "critical".into() } else { "high".into() },
            confidence: confidence.into(),
            target: policy.target().to_string(),
            endpoint: task.endpoint.url.clone(),
            method: task.endpoint.method.clone(),
            parameter: Some(task.parameter.clone()),
            title: "Boolean SQL response differential observed".into(),
            description: "True/false SQL predicate probes produced a repeatable response differential relative to the baseline. Confirmation requires the repeated pattern; no data extraction was attempted.".into(),
            reproduction_summary: format!("Compare baseline, boolean-true, and boolean-false requests for parameter {}. Reproduce only within the authorized scope.", task.parameter),
            impact: "Confirmed query-behavior control may permit unauthorized query manipulation even though CodeTwin does not attempt database extraction.".into(),
            remediation: "Use prepared statements/parameter binding for all data values and fixed allow-lists for identifiers. Add regression tests for the affected request path.".into(),
            references: vec!["CWE-89".into(), "OWASP A03:2021 Injection".into()],
            evidence,
        });
    }


    Ok(findings)
}

fn probe_xss(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    baseline: &ObservedResponse,
    marker: &str,
) -> Result<Option<FindingObservation>, ScanError> {
    let payload = format!("<codetwin-xss-{marker}>");
    let response = match send_task_payload(requester, task, url, &payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(None),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(None),
    };
    let body = String::from_utf8_lossy(&response.body);
    if !body.contains(&payload) {
        return Ok(None);
    }
    let baseline_body = String::from_utf8_lossy(&baseline.body);
    if baseline_body.contains(&payload) {
        return Ok(None);
    }
    let context = reflection_context(&body, &payload);
    let (confidence, severity, title) = match context {
        ReflectionContext::ScriptOrAttribute => ("Likely", "high", "Unescaped XSS marker reached executable browser context"),
        ReflectionContext::HtmlMarkup => ("Likely", "medium", "Unescaped XSS marker reached HTML markup context"),
        ReflectionContext::Text => ("Potential", "low", "User-controlled marker is reflected without encoding"),
    };
    Ok(Some(FindingObservation {
        category: "xss".into(),
        severity: severity.into(),
        confidence: confidence.into(),
        target: policy.target().to_string(),
        endpoint: task.endpoint.url.clone(),
        method: task.endpoint.method.clone(),
        parameter: Some(task.parameter.clone()),
        title: title.into(),
        description: "A harmless non-script marker supplied through the parameter was reflected in the response. CodeTwin distinguishes plain reflection from contexts that appear executable; it does not execute browser script.".into(),
        reproduction_summary: format!("Submit the non-executable marker {payload} in parameter {} and inspect the returned HTML context.", task.parameter),
        impact: "If attacker-controlled markup reaches an executable HTML/JavaScript context without contextual encoding, script execution may become possible.".into(),
        remediation: "Apply context-aware output encoding, avoid unsafe HTML sinks, and use a restrictive CSP as defense in depth.".into(),
        references: vec!["CWE-79".into(), "OWASP A03:2021 Injection".into()],
        evidence: vec![response_evidence("reflection probe", &task.endpoint.method, url, &response)],
    }))
}

fn probe_open_redirect(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    marker: &str,
) -> Result<Option<FindingObservation>, ScanError> {
    let destination = format!("https://example.invalid/codetwin-{marker}");
    let response = match send_task_payload(requester, task, url, &destination) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(None),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(None),
    };
    let location = response.location.as_deref().unwrap_or("");
    if !(300..400).contains(&response.status) || location != destination {
        return Ok(None);
    }
    Ok(Some(FindingObservation {
        category: "open_redirect".into(),
        severity: "medium".into(),
        confidence: "Confirmed".into(),
        target: policy.target().to_string(),
        endpoint: task.endpoint.url.clone(),
        method: task.endpoint.method.clone(),
        parameter: Some(task.parameter.clone()),
        title: "User-controlled external redirect confirmed".into(),
        description: "The server returned a redirect Location exactly matching the harmless external marker supplied in the tested parameter. CodeTwin did not follow the redirect.".into(),
        reproduction_summary: format!("Set {} to the example.invalid marker and verify the Location response header.", task.parameter),
        impact: "Open redirects can facilitate phishing and can weaken OAuth or trust-boundary assumptions when redirect URIs are not independently constrained.".into(),
        remediation: "Use relative destinations or map user choices to an allow-list of trusted destinations.".into(),
        references: vec!["CWE-601".into()],
        evidence: vec![response_evidence("redirect probe", &task.endpoint.method, url, &response)],
    }))
}

fn probe_path_traversal(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    baseline: &ObservedResponse,
    marker: &str,
) -> Result<Option<FindingObservation>, ScanError> {
    let payload = format!("../../../../codetwin-nonexistent-{marker}.txt");
    let response = match send_task_payload(requester, task, url, &payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(None),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(None),
    };
    let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let baseline_text = String::from_utf8_lossy(&baseline.body).to_ascii_lowercase();
    let indicators = ["no such file", "file not found", "enoent", "path traversal", "invalid path"];
    let new_indicator = indicators.iter().any(|value| text.contains(value) && !baseline_text.contains(value));
    if !new_indicator {
        return Ok(None);
    }
    Ok(Some(FindingObservation {
        category: "path_traversal".into(),
        severity: "medium".into(),
        confidence: "Potential".into(),
        target: policy.target().to_string(),
        endpoint: task.endpoint.url.clone(),
        method: task.endpoint.method.clone(),
        parameter: Some(task.parameter.clone()),
        title: "Traversal-shaped input changed filesystem error behavior".into(),
        description: "A nonexistent traversal-shaped path produced filesystem-oriented error evidence that was absent from the baseline. No real file was requested.".into(),
        reproduction_summary: "Repeat only with a deliberately nonexistent marker filename; do not request system or application secrets.".into(),
        impact: "If traversal normalization is incomplete, an attacker may be able to access files outside the intended directory.".into(),
        remediation: "Resolve against a fixed base directory, reject parent traversal, disallow symlink/root escape, and prefer opaque server-side identifiers over user-provided paths.".into(),
        references: vec!["CWE-22".into()],
        evidence: vec![response_evidence("nonexistent traversal probe", &task.endpoint.method, url, &response)],
    }))
}

fn probe_ssrf_indicator(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    baseline: &ObservedResponse,
    marker: &str,
) -> Result<Option<FindingObservation>, ScanError> {
    let payload = format!("http://192.0.2.1/codetwin-{marker}");
    let response = match send_task_payload(requester, task, url, &payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(None),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(None),
    };
    let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let baseline_text = String::from_utf8_lossy(&baseline.body).to_ascii_lowercase();
    let indicators = ["connection refused", "connect timeout", "connection timed out", "failed to connect", "name or service not known"];
    if !indicators.iter().any(|value| text.contains(value) && !baseline_text.contains(value)) {
        return Ok(None);
    }
    Ok(Some(FindingObservation {
        category: "ssrf".into(),
        severity: "medium".into(),
        confidence: "Potential".into(),
        target: policy.target().to_string(),
        endpoint: task.endpoint.url.clone(),
        method: task.endpoint.method.clone(),
        parameter: Some(task.parameter.clone()),
        title: "Outbound-request error indicator observed".into(),
        description: "Supplying a reserved TEST-NET URL caused new outbound connection error evidence. This is only an SSRF indicator; CodeTwin does not contact metadata services or use external callback infrastructure.".into(),
        reproduction_summary: "Use only a reserved documentation address and compare server error behavior. Do not target internal services.".into(),
        impact: "If the application performs unrestricted server-side requests, attackers may be able to reach unintended network destinations.".into(),
        remediation: "Allow-list outbound schemes/hosts, resolve and validate addresses, block private/link-local/metadata ranges, and revalidate redirects.".into(),
        references: vec!["CWE-918".into(), "OWASP A10:2021 SSRF".into()],
        evidence: vec![response_evidence("reserved-address SSRF indicator", &task.endpoint.method, url, &response)],
    }))
}

fn probe_template_indicator(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    baseline: &ObservedResponse,
    marker: &str,
) -> Result<Option<FindingObservation>, ScanError> {
    let payload = format!("codetwin-{marker}-{{{{7*7}}}}");
    let response = match send_task_payload(requester, task, url, &payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(None),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(None),
    };
    let text = String::from_utf8_lossy(&response.body);
    let baseline_text = String::from_utf8_lossy(&baseline.body);
    let evaluated = text.contains(&format!("codetwin-{marker}-49")) && !baseline_text.contains(&format!("codetwin-{marker}-49"));
    if !evaluated {
        return Ok(None);
    }
    Ok(Some(FindingObservation {
        category: "template_injection".into(),
        severity: "high".into(),
        confidence: "Likely".into(),
        target: policy.target().to_string(),
        endpoint: task.endpoint.url.clone(),
        method: task.endpoint.method.clone(),
        parameter: Some(task.parameter.clone()),
        title: "Harmless template expression appears to have been evaluated".into(),
        description: "A marker containing the arithmetic template expression {{7*7}} was returned with 49 substituted into the same marker. CodeTwin did not attempt command execution.".into(),
        reproduction_summary: "Repeat the arithmetic-only template marker and verify that the marker changes from the literal expression to 49.".into(),
        impact: "Server-side template evaluation of attacker input can become code execution in vulnerable template engines.".into(),
        remediation: "Never render untrusted input as a template. Pass it only as data to a fixed template and enable framework sandboxing where applicable.".into(),
        references: vec!["CWE-1336".into()],
        evidence: vec![response_evidence("arithmetic template probe", &task.endpoint.method, url, &response)],
    }))
}

fn probe_input_validation(
    requester: &ScopedRequester,
    policy: &ScopePolicy,
    task: &ProbeTask,
    url: &Url,
    baseline: &ObservedResponse,
    marker: &str,
) -> Result<Option<FindingObservation>, ScanError> {
    let payload = format!("CODETWIN_INVALID_{marker}_%00_[]{{}}");
    let response = match send_task_payload(requester, task, url, &payload) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(None),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(None),
    };
    if response.status < 500 || baseline.status >= 500 {
        return Ok(None);
    }
    Ok(Some(FindingObservation {
        category: "api_input_validation".into(),
        severity: "medium".into(),
        confidence: "Likely".into(),
        target: policy.target().to_string(),
        endpoint: task.endpoint.url.clone(),
        method: task.endpoint.method.clone(),
        parameter: Some(task.parameter.clone()),
        title: "Malformed input triggered a new server error".into(),
        description: "A bounded malformed-input marker changed a non-5xx baseline into a server-error response. This may indicate missing validation or unsafe error handling.".into(),
        reproduction_summary: format!("Submit the bounded invalid marker to {} and compare the HTTP status and redacted response metadata.", task.parameter),
        impact: "Unhandled malformed input can expose internals or reach unsafe parser/application paths.".into(),
        remediation: "Validate request schemas before business logic, return deterministic 4xx errors for invalid input, and avoid verbose exception disclosure.".into(),
        references: vec!["OWASP API8:2023 Security Misconfiguration".into()],
        evidence: vec![
            response_evidence("baseline", &task.endpoint.method, url, baseline),
            response_evidence("malformed-input probe", &task.endpoint.method, url, &response),
        ],
    }))
}

fn probe_options(
    requester: &ScopedRequester,
    endpoint: &EndpointObservation,
    config: &ScanConfig,
) -> Result<Vec<FindingObservation>, ScanError> {
    let Ok(url) = Url::parse(&endpoint.url) else { return Ok(Vec::new()) };
    let response = match requester.send(
        Method::OPTIONS,
        &url,
        None,
        &[("Origin", "https://example.invalid"), ("Access-Control-Request-Method", "GET")],
    ) {
        Ok(value) => value,
        Err(RequestError::BudgetExhausted) => return Ok(Vec::new()),
        Err(RequestError::Cancelled) => return Err(ScanError::Cancelled),
        Err(_) => return Ok(Vec::new()),
    };
    let mut findings = Vec::new();
    if config.checks.cors {
        let origin = response_header(&response, "access-control-allow-origin").unwrap_or_default();
        let credentials = response_header(&response, "access-control-allow-credentials").unwrap_or_default();
        if origin == "https://example.invalid" && credentials.eq_ignore_ascii_case("true") {
            findings.push(FindingObservation {
                category: "cors".into(),
                severity: "high".into(),
                confidence: "Likely".into(),
                target: config.scope.target_url.clone(),
                endpoint: endpoint.url.clone(),
                method: "OPTIONS".into(),
                parameter: None,
                title: "Arbitrary Origin appears accepted with credentials".into(),
                description: "The server reflected the untrusted example.invalid Origin and also allowed credentials.".into(),
                reproduction_summary: "Send an OPTIONS preflight with Origin: https://example.invalid and inspect Access-Control-Allow-Origin/Credentials.".into(),
                impact: "If sensitive endpoints share this policy, attacker-controlled sites may be able to read credentialed responses.".into(),
                remediation: "Validate Origin against an exact trusted allow-list and only enable credentials where required.".into(),
                references: vec!["CWE-942".into()],
                evidence: vec![response_evidence("CORS preflight", "OPTIONS", &url, &response)],
            });
        }
    }
    if config.checks.method_misconfiguration {
        if let Some(allow) = response_header(&response, "allow") {
            let upper = allow.to_ascii_uppercase();
            if upper.split(',').any(|method| method.trim() == "TRACE") {
                findings.push(FindingObservation {
                    category: "http_method".into(),
                    severity: "low".into(),
                    confidence: "Likely".into(),
                    target: config.scope.target_url.clone(),
                    endpoint: endpoint.url.clone(),
                    method: "OPTIONS".into(),
                    parameter: None,
                    title: "TRACE method advertised".into(),
                    description: "The server's Allow header advertises TRACE. CodeTwin did not issue a TRACE request.".into(),
                    reproduction_summary: "Inspect the OPTIONS response Allow header.".into(),
                    impact: "TRACE is rarely needed by applications and unnecessarily expands the HTTP method surface.".into(),
                    remediation: "Disable TRACE unless there is a documented operational requirement.".into(),
                    references: Vec::new(),
                    evidence: vec![response_evidence("method inventory", "OPTIONS", &url, &response)],
                });
            }
        }
    }
    Ok(findings)
}

pub(crate) fn send_endpoint_baseline(
    requester: &ScopedRequester,
    endpoint: &EndpointObservation,
    url: &Url,
    parameter: Option<&str>,
) -> Result<ObservedResponse, RequestError> {
    if let Some(parameter) = parameter.filter(|value| !value.trim().is_empty()) {
        return send_payload(requester, endpoint, url, parameter, "");
    }

    let method = Method::from_bytes(endpoint.method.as_bytes())
        .map_err(|_| RequestError::Http("unsupported HTTP method".to_string()))?;
    requester.send(method, url, None, &[])
}

fn send_task_payload(
    requester: &ScopedRequester,
    task: &ProbeTask,
    base: &Url,
    payload: &str,
) -> Result<ObservedResponse, RequestError> {
    send_payload_with_seed(
        requester,
        &task.endpoint,
        base,
        &task.parameter,
        payload,
        &task.request_seed,
    )
}

fn send_payload(
    requester: &ScopedRequester,
    endpoint: &EndpointObservation,
    base: &Url,
    parameter: &str,
    payload: &str,
) -> Result<ObservedResponse, RequestError> {
    send_payload_with_seed(
        requester,
        endpoint,
        base,
        parameter,
        payload,
        &RequestSeedContext::default(),
    )
}

fn send_payload_with_seed(
    requester: &ScopedRequester,
    endpoint: &EndpointObservation,
    base: &Url,
    parameter: &str,
    payload: &str,
    request_seed: &RequestSeedContext,
) -> Result<ObservedResponse, RequestError> {
    validate_active_payload(payload)
        .map_err(|reason| RequestError::PayloadRejected(reason.to_string()))?;
    let location = proven_parameter_location(endpoint, parameter)?;

    if location == "cookie" {
        return Err(RequestError::Http(
            "cookie parameter active probes are intentionally disabled".to_string(),
        ));
    }
    if location == "body" {
        return Err(RequestError::Http(
            "ambiguous body parameter probes require proven JSON or form content-type evidence"
                .to_string(),
        ));
    }
    if location == "header" && !active_header_probe_allowed(parameter) {
        return Err(RequestError::Http(
            "sensitive or transport-controlled header probes are intentionally disabled".to_string(),
        ));
    }

    let method = Method::from_bytes(endpoint.method.as_bytes())
        .map_err(|_| RequestError::Http("unsupported HTTP method".to_string()))?;
    let mut url = if location == "path" && !payload.is_empty() {
        let template_base = endpoint
            .route_template
            .as_deref()
            .and_then(|value| Url::parse(value).ok())
            .unwrap_or_else(|| base.clone());
        replace_path_parameter(&template_base, parameter, payload)
            .ok_or_else(|| RequestError::Http("path parameter placeholder was not found".to_string()))?
    } else {
        base.clone()
    };

    if location == "query" {
        replace_query_parameter(&mut url, parameter, payload);
    }

    let body = contextual_request_body_with_seed(
        endpoint,
        parameter,
        location,
        payload,
        &request_seed.values,
    );
    match (body.as_ref(), location) {
        (Some((body, content_type)), "header") => requester.send_with_redaction_secrets(
            method,
            &url,
            Some(body.as_str()),
            &[("Content-Type", *content_type), (parameter, payload)],
            &request_seed.redaction_secrets,
        ),
        (None, "header") => requester.send_with_redaction_secrets(
            method,
            &url,
            None,
            &[(parameter, payload)],
            &request_seed.redaction_secrets,
        ),
        (Some((body, content_type)), _) => requester.send_with_redaction_secrets(
            method,
            &url,
            Some(body.as_str()),
            &[("Content-Type", *content_type)],
            &request_seed.redaction_secrets,
        ),
        (None, _) => requester.send_with_redaction_secrets(
            method,
            &url,
            None,
            &[],
            &request_seed.redaction_secrets,
        ),
    }
}

fn proven_parameter_location<'a>(
    endpoint: &'a EndpointObservation,
    parameter: &str,
) -> Result<&'a str, RequestError> {
    if let Some(location) = single_parameter_location(&endpoint.parameter_locations, parameter) {
        return Ok(location);
    }
    let count = endpoint
        .parameter_locations
        .get(parameter)
        .map(Vec::len)
        .unwrap_or(0);
    Err(RequestError::Http(if count > 1 {
        format!(
            "active probe requires an unambiguous parameter location; {parameter} has {count} proven locations"
        )
    } else {
        format!(
            "active probe requires proven location evidence for parameter {parameter}"
        )
    }))
}

fn replace_query_parameter(url: &mut Url, parameter: &str, payload: &str) {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| {
            if name == parameter {
                (name.into_owned(), payload.to_string())
            } else {
                (name.into_owned(), value.into_owned())
            }
        })
        .collect();
    url.set_query(None);
    let mut query = url.query_pairs_mut();
    let mut replaced = false;
    for (name, value) in pairs {
        if name == parameter {
            replaced = true;
        }
        query.append_pair(&name, &value);
    }
    if !replaced {
        query.append_pair(parameter, payload);
    }
}

fn contextual_request_body(
    endpoint: &EndpointObservation,
    target_parameter: &str,
    target_location: &str,
    payload: &str,
) -> Option<(String, &'static str)> {
    contextual_request_body_with_seed(
        endpoint,
        target_parameter,
        target_location,
        payload,
        &crate::RequestSeedValues::new(),
    )
}

fn contextual_request_body_with_seed(
    endpoint: &EndpointObservation,
    target_parameter: &str,
    target_location: &str,
    payload: &str,
    request_seed: &crate::RequestSeedValues,
) -> Option<(String, &'static str)> {
    if matches!(endpoint.method.as_str(), "GET" | "HEAD") {
        return None;
    }

    let json_parameters: Vec<&str> = endpoint
        .parameter_names
        .iter()
        .filter(|name| {
            parameter_has_location(&endpoint.parameter_locations, name, "json")
        })
        .map(String::as_str)
        .collect();
    let form_parameters: Vec<&str> = endpoint
        .parameter_names
        .iter()
        .filter(|name| {
            parameter_has_location(&endpoint.parameter_locations, name, "form")
        })
        .map(String::as_str)
        .collect();

    let content_type = endpoint.content_type.as_deref().unwrap_or("");
    let use_json = target_location == "json"
        || (target_location != "form"
            && (content_type.contains("application/json") || !json_parameters.is_empty()));
    if use_json && !json_parameters.is_empty() {
        let mut object = serde_json::Map::new();
        for name in json_parameters {
            let value = if target_location == "json" && name == target_parameter {
                if payload.is_empty() {
                    request_seed
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| serde_json::Value::String(String::new()))
                } else {
                    serde_json::Value::String(payload.to_string())
                }
            } else {
                request_seed
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| serde_json::Value::String("codetwin-test".to_string()))
            };
            object.insert(name.to_string(), value);
        }
        return Some((
            serde_json::Value::Object(object).to_string(),
            "application/json",
        ));
    }

    if !form_parameters.is_empty() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for name in form_parameters {
            let seeded = request_seed.get(name).and_then(seed_form_value);
            let value = if target_location == "form" && name == target_parameter {
                if payload.is_empty() {
                    seeded.as_deref().unwrap_or("")
                } else {
                    payload
                }
            } else {
                seeded.as_deref().unwrap_or("codetwin-test")
            };
            serializer.append_pair(name, value);
        }
        return Some((
            serializer.finish(),
            "application/x-www-form-urlencoded",
        ));
    }

    None
}

fn seed_form_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Null => Some(String::new()),
        _ => None,
    }
}

fn replace_path_parameter(base: &Url, parameter: &str, payload: &str) -> Option<Url> {
    let encoded: String = url::form_urlencoded::byte_serialize(payload.as_bytes()).collect();
    let raw = base.as_str();
    let placeholders = [
        format!("{{{parameter}}}"),
        format!("%7B{parameter}%7D"),
        format!("%7b{parameter}%7d"),
    ];
    for placeholder in placeholders {
        if raw.contains(&placeholder) {
            return Url::parse(&raw.replacen(&placeholder, &encoded, 1)).ok();
        }
    }
    None
}

fn contains_sql_error(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    [
        "sql syntax",
        "sqlstate",
        "sqlite error",
        "sqliteexception",
        "postgresql error",
        "pg::syntaxerror",
        "mysql_fetch",
        "mysqli_sql_exception",
        "ora-",
        "unclosed quotation mark",
        "syntax error at or near",
        "database query failed",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn similar_response(left: &ObservedResponse, right: &ObservedResponse) -> bool {
    if left.status != right.status || mime_type(left) != mime_type(right) {
        return false;
    }
    if body_hash(&left.body) == body_hash(&right.body) {
        return true;
    }
    normalized_body(&left.body) == normalized_body(&right.body)
}

fn materially_different(left: &ObservedResponse, right: &ObservedResponse) -> bool {
    if left.status != right.status || mime_type(left) != mime_type(right) {
        return true;
    }
    normalized_body(&left.body) != normalized_body(&right.body)
}

fn mime_type(response: &ObservedResponse) -> String {
    response
        .content_type
        .as_deref()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn normalized_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut output = String::with_capacity(text.len().min(65_536));
    let mut in_digits = false;
    let mut in_whitespace = false;
    for character in text.chars().take(65_536) {
        if character.is_ascii_digit() {
            if !in_digits {
                output.push('#');
            }
            in_digits = true;
            in_whitespace = false;
        } else if character.is_whitespace() {
            if !in_whitespace {
                output.push(' ');
            }
            in_digits = false;
            in_whitespace = true;
        } else {
            output.push(character);
            in_digits = false;
            in_whitespace = false;
        }
    }
    output
}

enum ReflectionContext {
    ScriptOrAttribute,
    HtmlMarkup,
    Text,
}

fn reflection_context(body: &str, marker: &str) -> ReflectionContext {
    let Some(index) = body.find(marker) else {
        return ReflectionContext::Text;
    };
    let marker_end = index + marker.len();
    let prefix_reversed: String = body[..index].chars().rev().take(180).collect();
    let prefix: String = prefix_reversed.chars().rev().collect();
    let suffix: String = body[marker_end..].chars().take(180).collect();
    let context = format!("{prefix}{marker}{suffix}").to_ascii_lowercase();
    let marker_lower = marker.to_ascii_lowercase();
    let before = context
        .split_once(&marker_lower)
        .map(|(before, _)| before)
        .unwrap_or("");
    let script_start = before.rfind("<script");
    let script_end = before.rfind("</script>");
    let inside_script = script_start.is_some()
        && script_end.map(|end| end < script_start.unwrap_or(0)).unwrap_or(true);
    if inside_script
        || before.ends_with(r#"=""#)
        || before.ends_with("='")
        || before.contains("onerror=")
        || before.contains("onclick=")
    {
        ReflectionContext::ScriptOrAttribute
    } else if context.contains("<codetwin-xss-") {
        ReflectionContext::HtmlMarkup
    } else {
        ReflectionContext::Text
    }
}

fn short_marker(endpoint: &str, parameter: &str) -> String {
    fingerprint(&[endpoint, parameter]).chars().take(12).collect()
}

fn looks_redirect_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["next", "url", "redirect", "redirect_uri", "return", "return_to", "callback"]
        .iter()
        .any(|value| lower == *value || lower.contains(value))
}

fn looks_path_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["file", "path", "template", "page", "download", "folder"]
        .iter()
        .any(|value| lower.contains(value))
}

fn looks_url_parameter(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["url", "uri", "endpoint", "webhook", "callback", "image", "avatar", "feed"]
        .iter()
        .any(|value| lower.contains(value))
}

fn looks_object_specific(endpoint: &EndpointObservation) -> bool {
    let Ok(url) = Url::parse(&endpoint.url) else { return false };
    if endpoint.parameter_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        ["id", "user", "account", "order", "document", "file", "record"]
            .iter()
            .any(|needle| lower.contains(needle))
    }) {
        return true;
    }
    url.path_segments()
        .into_iter()
        .flatten()
        .any(|segment| segment.len() >= 2 && segment.chars().all(|character| character.is_ascii_digit()))
}

fn method_probe_allowed(method: &str, allow_non_idempotent: bool) -> bool {
    matches!(method, "GET" | "HEAD")
        || (allow_non_idempotent && matches!(method, "POST" | "PUT" | "PATCH"))
}

fn active_header_probe_allowed(name: &str) -> bool {
    !matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
    )
}

pub(crate) fn baseline_key(method: &str, raw: &str) -> String {
    endpoint_request_key(method, raw)
}

fn normalized_key(raw: &str) -> String {
    Url::parse(raw)
        .map(|mut url| {
            url.set_fragment(None);
            url.to_string()
        })
        .unwrap_or_else(|_| raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::{baseline_key, contains_sql_error, materially_different, similar_response};
    use crate::ObservedResponse;

    fn response(status: u16, body: &str) -> ObservedResponse {
        ObservedResponse {
            status,
            headers: Vec::new(),
            content_type: Some("text/html".into()),
            location: None,
            body: body.as_bytes().to_vec(),
            elapsed_ms: 10,
            truncated: false,
            redaction_secrets: Vec::new(),
        }
    }

    #[test]
    fn active_worker_scope_errors_fail_the_scan() {
        use std::{
            collections::{BTreeMap, HashMap},
            sync::{
                atomic::AtomicBool,
                Arc,
            },
        };

        let config = crate::ScanConfig {
            scope: crate::ScopeConfig {
                target_url: "http://127.0.0.1:9/".into(),
                allowed_hostnames: vec!["127.0.0.1".into()],
                allowed_subdomains: Vec::new(),
                allowed_paths: vec!["/".into()],
                excluded_paths: Vec::new(),
                max_crawl_depth: 0,
                max_requests: 8,
                concurrency: 1,
                timeout_ms: 500,
                response_limit_bytes: 16_384,
                redirect_limit: 0,
                retry_limit: 0,
                active_testing: true,
                allow_non_idempotent_methods: false,
                allow_private_networks: true,
                enable_timing_probes: false,
                authorization_confirmed: true,
            },
            checks: crate::CheckConfig::default(),
        };
        let policy = crate::ScopePolicy::new(config.scope.clone()).expect("scope");
        let cancelled = Arc::new(AtomicBool::new(false));
        let requester = crate::ScopedRequester::new(
            policy.clone(),
            crate::AuthContext::default(),
            crate::RequestBudget::new(8),
            Arc::clone(&cancelled),
        );
        let endpoint = crate::EndpointObservation {
            url: "http://example.invalid:9/?q=a".into(),
            route_template: None,
            method: "GET".into(),
            depth: 0,
            source: "fixture".into(),
            parameter_names: vec!["q".into()],
            parameter_locations: BTreeMap::from([("q".into(), vec!["query".into()])]),
            response_header_names: Vec::new(),
            cookie_names: Vec::new(),
            content_type: None,
            status_code: None,
            redirect_to: None,
        };
        let endpoints = [endpoint];
        let baselines = HashMap::new();
        let request_seeds = HashMap::new();
        let mut ignored_progress = |_| {};

        let result = super::run_active_checks(
            super::ActiveCheckContext {
                policy: &policy,
                requester: &requester,
                secondary_auth: None,
                config: &config,
                endpoints: &endpoints,
                baselines: &baselines,
                request_seeds: &request_seeds,
                cancelled,
            },
            &mut ignored_progress,
        );

        assert!(
            matches!(result, Err(crate::ScanError::Scope(_))),
            "out-of-scope worker errors must fail the scan instead of being swallowed"
        );
    }

    #[test]
    fn baseline_keys_are_method_specific_and_fragment_stable() {
        assert_eq!(
            baseline_key("post", "https://example.test/users#details"),
            "POST https://example.test/users"
        );
        assert_ne!(
            baseline_key("GET", "https://example.test/users"),
            baseline_key("POST", "https://example.test/users")
        );
    }

    #[test]
    fn multiple_parameter_locations_are_not_guessed() {
        use std::collections::BTreeMap;

        let endpoint = crate::EndpointObservation {
            url: "https://example.test/users?id=1".to_string(),
            route_template: Some("https://example.test/users/{id}".to_string()),
            method: "GET".to_string(),
            depth: 0,
            source: "fixture".to_string(),
            parameter_names: vec!["id".to_string()],
            parameter_locations: BTreeMap::from([(
                "id".to_string(),
                vec!["path".to_string(), "query".to_string()],
            )]),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: None,
            status_code: None,
            redirect_to: None,
        };

        let error = super::proven_parameter_location(&endpoint, "id")
            .expect_err("ambiguous location must fail closed");
        assert!(error.to_string().contains("unambiguous parameter location"));
    }

    #[test]
    fn missing_parameter_location_is_not_guessed() {
        use std::collections::BTreeMap;

        let endpoint = crate::EndpointObservation {
            url: "https://example.test/users".to_string(),
            route_template: None,
            method: "POST".to_string(),
            depth: 0,
            source: "fixture".to_string(),
            parameter_names: vec!["email".to_string()],
            parameter_locations: BTreeMap::new(),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: None,
            status_code: None,
            redirect_to: None,
        };

        assert!(super::proven_parameter_location(&endpoint, "email").is_err());
    }

    #[test]
    fn ambiguous_body_location_does_not_build_a_probe_body() {
        use std::collections::BTreeMap;

        let endpoint = crate::EndpointObservation {
            url: "https://example.test/users".to_string(),
            route_template: None,
            method: "POST".to_string(),
            depth: 0,
            source: "source_route:laravel:routes/api.php:1".to_string(),
            parameter_names: vec!["email".to_string()],
            parameter_locations: BTreeMap::from([(
                "email".to_string(),
                vec!["body".to_string()],
            )]),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: None,
            status_code: None,
            redirect_to: None,
        };
        let body = super::contextual_request_body(&endpoint, "email", "body", "probe");
        assert!(body.is_none());
    }

    #[test]
    fn contextual_body_keeps_fields_in_declared_locations() {
        use std::collections::BTreeMap;

        let endpoint = crate::EndpointObservation {
            url: "http://localhost:3000/api/login/acme?next=home".into(),
            route_template: Some("http://localhost:3000/api/login/%7Btenant%7D?next=home".into()),
            method: "POST".into(),
            depth: 0,
            source: "source_route:express:src/auth.ts:10".into(),
            parameter_names: vec![
                "tenant".into(),
                "next".into(),
                "email".into(),
                "password".into(),
            ],
            parameter_locations: BTreeMap::from([
                ("tenant".into(), vec!["path".into()]),
                ("next".into(), vec!["query".into()]),
                ("email".into(), vec!["json".into()]),
                ("password".into(), vec!["json".into()]),
            ]),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: Some("application/json".into()),
            status_code: None,
            redirect_to: None,
        };

        let (body, content_type) =
            super::contextual_request_body(&endpoint, "email", "json", "probe")
                .expect("json body");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(content_type, "application/json");
        assert_eq!(value.get("email").and_then(|item| item.as_str()), Some("probe"));
        assert_eq!(
            value.get("password").and_then(|item| item.as_str()),
            Some("codetwin-test")
        );
        assert!(value.get("tenant").is_none());
        assert!(value.get("next").is_none());
    }

    #[test]
    fn runtime_json_seeds_preserve_simple_schema_types() {
        use std::collections::BTreeMap;

        let endpoint = crate::EndpointObservation {
            url: "http://localhost:3000/api/items".into(),
            route_template: None,
            method: "POST".into(),
            depth: 0,
            source: "openapi".into(),
            parameter_names: vec!["count".into(), "enabled".into(), "name".into()],
            parameter_locations: BTreeMap::from([
                ("count".into(), vec!["json".into()]),
                ("enabled".into(), vec!["json".into()]),
                ("name".into(), vec!["json".into()]),
            ]),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: Some("application/json".into()),
            status_code: None,
            redirect_to: None,
        };
        let seeds = crate::RequestSeedValues::from([
            ("count".into(), serde_json::json!(1)),
            ("enabled".into(), serde_json::json!(true)),
            ("name".into(), serde_json::json!("baseline-name")),
        ]);

        let (body, content_type) = super::contextual_request_body_with_seed(
            &endpoint,
            "name",
            "json",
            "",
            &seeds,
        )
        .expect("json body");
        assert_eq!(content_type, "application/json");
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(value["count"], serde_json::json!(1));
        assert_eq!(value["enabled"], serde_json::json!(true));
        assert_eq!(value["name"], serde_json::json!("baseline-name"));
    }

    #[test]
    fn runtime_form_seed_preserves_hidden_csrf_value() {
        use std::collections::BTreeMap;

        let endpoint = crate::EndpointObservation {
            url: "http://localhost:3000/update".into(),
            route_template: None,
            method: "POST".into(),
            depth: 0,
            source: "form".into(),
            parameter_names: vec!["csrf_token".into(), "display_name".into()],
            parameter_locations: BTreeMap::from([
                ("csrf_token".into(), vec!["form".into()]),
                ("display_name".into(), vec!["form".into()]),
            ]),
            response_header_names: vec![],
            cookie_names: vec![],
            content_type: Some("application/x-www-form-urlencoded".into()),
            status_code: None,
            redirect_to: None,
        };
        let seeds = crate::RequestSeedValues::from([(
            "csrf_token".into(),
            serde_json::json!("csrf-secret-123"),
        )]);

        let (body, content_type) = super::contextual_request_body_with_seed(
            &endpoint,
            "display_name",
            "form",
            "probe",
            &seeds,
        )
        .expect("form body");
        assert_eq!(content_type, "application/x-www-form-urlencoded");
        let pairs: std::collections::BTreeMap<_, _> =
            url::form_urlencoded::parse(body.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
        assert_eq!(pairs.get("csrf_token").map(String::as_str), Some("csrf-secret-123"));
        assert_eq!(pairs.get("display_name").map(String::as_str), Some("probe"));
    }

    #[test]
    fn boolean_differential_requires_material_difference() {
        let base = response(200, "search result id=123 count=45");
        let similar = response(200, "search   result id=987 count=12");
        let different = response(403, "denied");
        assert!(similar_response(&base, &similar));
        assert!(materially_different(&base, &different));
    }

    #[test]
    fn sql_error_detection_ignores_normal_content() {
        assert!(!contains_sql_error(b"normal application response"));
        assert!(contains_sql_error(b"SQLSTATE[42000] syntax error"));
    }
}
