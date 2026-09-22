use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use codetwin_core::{
    AuthorizedWebSecurityStore, Database, GuidedPlanItemInput, GuidedRetestInput,
    GuidedSecurityStore, GuidedSessionCreate, PreparationCompletion, ProjectIndexService,
    RepairApplicationService, VerifiedRepairService, WebEndpointInput, WebEvidenceInput,
    WebFindingInput, WebScanCreate,
};
use tempfile::tempdir;
use url::Url;
use web_security_testing::{
    apply_approved_execution_policy, prepare_guided_security, run_authorized_scan,
    run_targeted_retest, ApprovedExecutionPolicy, AuthContext, CheckConfig, OperationRisk,
    ScanConfig, ScanError, ScopeConfig, SecurityEnvironment, TargetedRetestRequest,
};

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    target: String,
    authorization: Option<String>,
    cookie: Option<String>,
}

struct LocalLab {
    base_url: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LocalLab {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind lab");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("address");
        let base_url = format!("http://127.0.0.1:{}", address.port());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle(stream, &thread_requests),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url,
            stop,
            requests,
            thread: Some(thread),
        }
    }

    fn config(&self, max_requests: usize) -> ScanConfig {
        let host = Url::parse(&self.base_url)
            .expect("lab url")
            .host_str()
            .expect("lab host")
            .to_string();
        ScanConfig {
            scope: ScopeConfig {
                target_url: format!("{}/", self.base_url),
                allowed_hostnames: vec![host],
                allowed_subdomains: vec![],
                allowed_paths: vec!["/".to_string()],
                excluded_paths: vec!["/excluded".to_string()],
                max_crawl_depth: 3,
                max_requests,
                max_requests_per_endpoint: 40,
                min_request_interval_ms: 0,
                concurrency: 2,
                timeout_ms: 2_000,
                response_limit_bytes: 128_000,
                redirect_limit: 3,
                retry_limit: 0,
                active_testing: true,
                allow_non_idempotent_methods: false,
                allow_private_networks: true,
                enable_timing_probes: false,
                authorization_confirmed: true,
            },
            checks: CheckConfig::default(),
        }
    }
}

impl Drop for LocalLab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(
            Url::parse(&self.base_url)
                .ok()
                .and_then(|url| url.socket_addrs(|| None).ok())
                .and_then(|mut values| values.pop())
                .unwrap_or_else(|| "127.0.0.1:9".parse().expect("fallback")),
        );
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn handle(mut stream: TcpStream, requests: &Arc<Mutex<Vec<RecordedRequest>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0u8; 16_384];
    let Ok(read) = stream.read(&mut buffer) else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..read]);
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let authorization = request_header(&request, "authorization");
    let cookie = request_header(&request, "cookie");
    if let Ok(mut history) = requests.lock() {
        history.push(RecordedRequest {
            method: method.to_string(),
            target: target.to_string(),
            authorization: authorization.clone(),
            cookie,
        });
    }

    let url = Url::parse(&format!("http://localhost{target}"))
        .unwrap_or_else(|_| Url::parse("http://localhost/").expect("fallback URL"));
    let path = url.path();
    let query: std::collections::HashMap<String, String> =
        url.query_pairs().map(|(key, value)| (key.into_owned(), value.into_owned())).collect();

    if method == "OPTIONS" {
        respond(
            &mut stream,
            "204 No Content",
            &[
                ("Access-Control-Allow-Origin", "https://example.invalid"),
                ("Access-Control-Allow-Credentials", "true"),
                ("Allow", "GET, OPTIONS, TRACE"),
            ],
            "",
        );
        return;
    }

    match path {
        "/" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/html; charset=utf-8")],
            r#"<html><body>
<a href="/search?q=hello&next=/home">search</a>
<a href="/safe?q=hello">safe</a>
<a href="/escape">escape</a>
<a href="/object?id=1">object</a>
<a href="/role-object?id=1">role object</a>
<a href="/openapi.json">api</a>
<a href="/static-sql?q=hello">static sql-looking text</a>
<a href="/escaped?q=hello">escaped reflection</a>
<a href="/redirect-safe?next=/home">safe redirect</a>
<a href="/generic500?q=hello">generic error</a>
<a href="/slow?q=hello">slow but normal</a>
<a href="/missing?q=hello">ordinary 404</a>
<form action="/update" method="post"><input name="display_name"></form>
</body></html>"#,
        ),
        "/search" => {
            let q = query.get("q").map(String::as_str).unwrap_or("");
            let next = query.get("next").map(String::as_str).unwrap_or("");
            if next.starts_with("https://example.invalid/codetwin-") {
                respond(&mut stream, "302 Found", &[("Location", next)], "");
            } else if q == "'" || q.contains("UNION SELECT") {
                respond(
                    &mut stream,
                    "500 Internal Server Error",
                    &[("Content-Type", "text/plain")],
                    "SQLSTATE[42000] syntax error near input",
                );
            } else if q.contains("' AND '1'='2'") {
                respond(
                    &mut stream,
                    "403 Forbidden",
                    &[("Content-Type", "text/html")],
                    "<html><body>no result</body></html>",
                );
            } else if q.contains("' OR '1'='1'") {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "text/html")],
                    "<html><body>normal-search-result</body></html>",
                );
            } else if q.contains("<codetwin-xss-") {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "text/html")],
                    &format!("<html><body><div>{q}</div></body></html>"),
                );
            } else if q.contains("{{7*7}}") {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "text/html")],
                    &format!("<html><body>{}</body></html>", q.replace("{{7*7}}", "49")),
                );
            } else {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "text/html")],
                    "<html><body>normal-search-result</body></html>",
                );
            }
        }
        "/safe" => {
            let q = query.get("q").map(String::as_str).unwrap_or("");
            let escaped = q.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            respond(
                &mut stream,
                "200 OK",
                &[
                    ("Content-Type", "text/html"),
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "no-referrer"),
                    ("Permissions-Policy", "camera=()"),
                ],
                &format!("<html><body>{escaped}</body></html>"),
            );
        }
        "/static-sql" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/html")],
            "<html><body>Example documentation: SQLSTATE[42000] syntax error text</body></html>",
        ),
        "/escaped" => {
            let q = query.get("q").map(String::as_str).unwrap_or("");
            let escaped = q
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#39;");
            respond(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/html")],
                &format!("<html><body><pre>{escaped}</pre></body></html>"),
            );
        }
        "/redirect-safe" => {
            let next = query.get("next").map(String::as_str).unwrap_or("/");
            let location = if next.starts_with('/') && !next.starts_with("//") {
                next
            } else {
                "/"
            };
            respond(&mut stream, "302 Found", &[("Location", location)], "");
        }
        "/generic500" => respond(
            &mut stream,
            "500 Internal Server Error",
            &[("Content-Type", "text/plain")],
            "Something went wrong. Reference ID 500.",
        ),
        "/slow" => {
            thread::sleep(Duration::from_millis(120));
            respond(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/html")],
                "<html><body>normal delayed response</body></html>",
            );
        }
        "/missing" => {
            let q = query.get("q").map(String::as_str).unwrap_or("unknown");
            respond(
                &mut stream,
                "404 Not Found",
                &[("Content-Type", "text/plain")],
                &format!("not found: {q}"),
            );
        }
        "/escape" => respond(
            &mut stream,
            "302 Found",
            &[("Location", "http://example.com/out-of-scope")],
            "",
        ),
        "/object" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "application/json")],
            r#"{"id":1,"name":"shared-test-object"}"#,
        ),
        "/role-object" => {
            let body = match authorization.as_deref() {
                Some("Bearer secondary-secret-token") => {
                    r#"{"id":1,"role":"secondary","visible":"limited"}"#
                }
                Some("Bearer primary-secret-token") => {
                    r#"{"id":1,"role":"primary","visible":"owner"}"#
                }
                _ => r#"{"id":1,"role":"anonymous","visible":"public"}"#,
            };
            respond(
                &mut stream,
                "200 OK",
                &[("Content-Type", "application/json")],
                body,
            );
        }
        "/openapi.json" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "application/json")],
            r#"{"openapi":"3.0.0","paths":{"/api/items":{"get":{"parameters":[{"name":"id","in":"query"}]}}}}"#,
        ),
        "/api/items" => {
            let id = query.get("id").map(String::as_str).unwrap_or("");
            if id.starts_with("CODETWIN_INVALID_") {
                respond(
                    &mut stream,
                    "500 Internal Server Error",
                    &[("Content-Type", "application/json")],
                    r#"{"error":"validation path crashed"}"#,
                );
            } else {
                respond(
                    &mut stream,
                    "200 OK",
                    &[("Content-Type", "application/json")],
                    r#"{"items":[]}"#,
                );
            }
        }
        "/update" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/plain")],
            "not executed by default",
        ),
        _ => respond(
            &mut stream,
            "404 Not Found",
            &[("Content-Type", "text/plain")],
            "not found",
        ),
    }
}

fn request_header(request: &str, name: &str) -> Option<String> {
    request.lines().skip(1).find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)], body: &str) {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.as_bytes().len()
    );
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[test]
fn authorized_local_lab_detects_representative_findings_without_scope_escape() {
    let lab = LocalLab::start();
    let cancelled = Arc::new(AtomicBool::new(false));
    let primary = AuthContext {
        cookie_header: Some("session=primary-cookie-secret".to_string()),
        bearer_token: Some("primary-secret-token".to_string()),
        ..AuthContext::default()
    };
    let secondary = AuthContext {
        cookie_header: Some("session=secondary-cookie-secret".to_string()),
        bearer_token: Some("secondary-secret-token".to_string()),
        ..AuthContext::default()
    };
    let outcome = run_authorized_scan(
        &lab.config(240),
        &primary,
        Some(&secondary),
        cancelled,
        |_| {},
    )
    .expect("authorized local scan");

    let categories: std::collections::HashSet<_> = outcome
        .findings
        .iter()
        .map(|finding| finding.category.as_str())
        .collect();
    assert!(categories.contains("sql_injection"));
    assert!(categories.contains("xss"));
    assert!(categories.contains("open_redirect"));
    assert!(categories.contains("csrf"));
    assert!(categories.contains("cors"));
    assert!(categories.contains("access_control"));
    assert!(categories.contains("api_input_validation"));
    assert!(!outcome.findings.iter().any(|finding| {
        finding.category == "access_control" && finding.endpoint.contains("/role-object")
    }));
    assert!(outcome
        .endpoints
        .iter()
        .any(|endpoint| endpoint.url.contains("/api/items")));
    assert!(outcome
        .endpoints
        .iter()
        .all(|endpoint| !endpoint.url.contains("example.com")));
    assert!(outcome.requests_performed <= 240);

    let safe_sql = outcome.findings.iter().filter(|finding| {
        finding.category == "sql_injection" && finding.endpoint.contains("/safe")
    });
    assert_eq!(safe_sql.count(), 0);

    let serialized = serde_json::to_string(&outcome.findings).expect("findings JSON");
    assert!(!serialized.contains("primary-secret-token"));
    assert!(!serialized.contains("secondary-secret-token"));
    assert!(!serialized.contains("primary-cookie-secret"));
    assert!(!serialized.contains("secondary-cookie-secret"));

    let history = lab.requests.lock().expect("requests");
    let role_requests: Vec<_> = history
        .iter()
        .filter(|request| request.target.starts_with("/role-object"))
        .collect();
    assert!(role_requests.iter().any(|request| {
        request.authorization.as_deref() == Some("Bearer primary-secret-token")
            && request.cookie.as_deref() == Some("session=primary-cookie-secret")
    }));
    assert!(role_requests.iter().any(|request| {
        request.authorization.as_deref() == Some("Bearer secondary-secret-token")
            && request.cookie.as_deref() == Some("session=secondary-cookie-secret")
    }));
    assert!(!role_requests.iter().any(|request| {
        request.authorization.as_deref() == Some("Bearer primary-secret-token")
            && request.cookie.as_deref() == Some("session=secondary-cookie-secret")
    }));
    assert!(!role_requests.iter().any(|request| {
        request.authorization.as_deref() == Some("Bearer secondary-secret-token")
            && request.cookie.as_deref() == Some("session=primary-cookie-secret")
    }));
    assert!(history.iter().all(|request| {
        request
            .authorization
            .as_deref()
            .is_none_or(|value| {
                value == "Bearer primary-secret-token" || value == "Bearer secondary-secret-token"
            })
    }));
    assert!(history.iter().all(|request| {
        request.cookie.as_deref().is_none_or(|value| {
            value == "session=primary-cookie-secret"
                || value == "session=secondary-cookie-secret"
        })
    }));
}


#[test]
fn guided_operator_maps_and_plans_before_active_execution() {
    let lab = LocalLab::start();
    let prepared = prepare_guided_security(
        &lab.config(120),
        &AuthContext::default(),
        None,
        SecurityEnvironment::Local,
        Arc::new(AtomicBool::new(false)),
    )
    .expect("guided preparation");

    assert!(prepared.application_map.endpoint_count >= 8);
    assert!(prepared.application_map.form_count >= 1);
    assert!(prepared.plan.selected_count > 0);
    assert!(prepared.plan.skipped_count > 0);
    assert!(prepared
        .plan
        .operations
        .iter()
        .any(|item| item.category == "sql_injection" && item.endpoint_url.contains("/search")));
    assert!(prepared
        .plan
        .operations
        .iter()
        .any(|item| item.category == "csrf" && item.endpoint_url.contains("/update")));
    assert!(prepared
        .plan
        .operations
        .iter()
        .filter(|item| item.method == "POST")
        .all(|item| !item.selected || item.category == "csrf"));
    assert!(prepared.mapping_requests <= 120);
}

#[test]
fn suspicious_but_safe_negative_fixtures_are_not_confirmed() {
    let lab = LocalLab::start();
    let outcome = run_authorized_scan(
        &lab.config(180),
        &AuthContext::default(),
        None,
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("negative fixture scan");

    let confirmed_on_safe_fixture: Vec<_> = outcome
        .findings
        .iter()
        .filter(|finding| {
            finding.confidence == "Confirmed"
                && (finding.endpoint.contains("/static-sql")
                    || finding.endpoint.contains("/escaped")
                    || finding.endpoint.contains("/redirect-safe")
                    || finding.endpoint.contains("/generic500")
                    || finding.endpoint.contains("/slow")
                    || finding.endpoint.contains("/missing")
                    || finding.endpoint.contains("/role-object")
                    || finding.endpoint.contains("/safe"))
        })
        .collect();
    assert!(
        confirmed_on_safe_fixture.is_empty(),
        "safe-looking fixtures must not become confirmed vulnerabilities: {confirmed_on_safe_fixture:?}"
    );

    assert!(!outcome.findings.iter().any(|finding| {
        finding.category == "xss" && finding.endpoint.contains("/escaped")
    }));
    assert!(!outcome.findings.iter().any(|finding| {
        finding.category == "open_redirect" && finding.endpoint.contains("/redirect-safe")
    }));
    assert!(!outcome.findings.iter().any(|finding| {
        finding.category == "sql_injection" && finding.endpoint.contains("/static-sql")
    }));
    assert!(!outcome.findings.iter().any(|finding| {
        finding.category == "api_input_validation" && finding.endpoint.contains("/generic500")
    }));
    assert!(!outcome.findings.iter().any(|finding| {
        finding.category == "access_control" && finding.endpoint.contains("/role-object")
    }));
    assert!(!outcome.findings.iter().any(|finding| {
        finding.confidence == "Confirmed" && finding.endpoint.contains("/missing")
    }));
}

#[test]
fn ordinary_slow_endpoint_does_not_become_timing_confirmation() {
    let lab = LocalLab::start();
    let mut config = lab.config(220);
    config.scope.enable_timing_probes = true;
    let outcome = run_authorized_scan(
        &config,
        &AuthContext::default(),
        None,
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("timing scan");
    assert!(!outcome.findings.iter().any(|finding| {
        finding.endpoint.contains("/slow")
            && finding.category == "sql_injection"
            && finding.title.to_ascii_lowercase().contains("timing")
    }));
}

#[test]
fn cancellation_prevents_requests() {
    let lab = LocalLab::start();
    let cancelled = Arc::new(AtomicBool::new(true));
    let result = run_authorized_scan(
        &lab.config(10),
        &AuthContext::default(),
        None,
        cancelled,
        |_| {},
    );
    assert!(matches!(result, Err(ScanError::Cancelled)));
    assert!(lab.requests.lock().expect("requests").is_empty());
}

#[test]
fn guided_developer_workflow_runs_end_to_end_on_local_fixtures() {
    let lab = LocalLab::start();
    let project = tempdir().expect("project tempdir");
    let source_dir = project.path().join("src");
    fs::create_dir_all(&source_dir).expect("source dir");
    let source_path = source_dir.join("search_controller.rs");
    let original_source = r#"pub fn search_controller(q: &str) -> String {
    format!("SELECT * FROM items WHERE name = '{q}'")
}
"#;
    fs::write(&source_path, original_source).expect("write source");

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index local project");

    let primary = AuthContext {
        cookie_header: Some("session=primary-cookie-secret".into()),
        bearer_token: Some("primary-secret-token".into()),
        custom_headers: Vec::new(),
    };
    let secondary = AuthContext {
        cookie_header: Some("session=secondary-cookie-secret".into()),
        bearer_token: Some("secondary-secret-token".into()),
        custom_headers: Vec::new(),
    };
    let config = lab.config(260);
    let config_json = serde_json::to_string(&config).expect("config json");

    let preparation = prepare_guided_security(
        &config,
        &primary,
        Some(&secondary),
        SecurityEnvironment::Local,
        Arc::new(AtomicBool::new(false)),
    )
    .expect("guided preparation");
    assert!(preparation.application_map.endpoint_count >= 10);
    assert!(preparation.plan.selected_count > 0);

    let plan_items: Vec<GuidedPlanItemInput> = preparation
        .plan
        .operations
        .iter()
        .map(|item| GuidedPlanItemInput {
            operation_key: item.operation_key.clone(),
            endpoint_url: item.endpoint_url.clone(),
            method: item.method.clone(),
            parameter_name: item.parameter_name.clone(),
            category: item.category.clone(),
            risk: match item.risk {
                OperationRisk::SAFE => "SAFE",
                OperationRisk::CAUTION => "CAUTION",
                OperationRisk::RESTRICTED => "RESTRICTED",
            }
            .to_string(),
            selected: item.selected,
            reason: item.reason.clone(),
            skip_reason: item.skip_reason.clone(),
        })
        .collect();

    let guided = GuidedSecurityStore::new(&database);
    let session = guided
        .create_session(&GuidedSessionCreate {
            website_id: None,
            project_id: Some(index.project_id.clone()),
            target_url: config.scope.target_url.clone(),
            environment: "local".into(),
            testing_depth: "deep".into(),
            auth_mode: "test_accounts_a_b".into(),
            authorization_confirmed: true,
            config_json: config_json.clone(),
        })
        .expect("guided session");
    let prepared = guided
        .complete_preparation(PreparationCompletion {
            session_id: &session.id,
            preflight_json: &serde_json::to_string(&preparation.preflight).expect("preflight"),
            application_map_json: &serde_json::to_string(&preparation.application_map).expect("map"),
            plan_json: &serde_json::to_string(&preparation.plan).expect("plan"),
            mapping_requests: preparation.mapping_requests,
            plan_items: &plan_items,
        })
        .expect("persist preparation");
    assert_eq!(prepared.status, "awaiting_approval");

    let approved = guided.approve_session(&session.id).expect("approve plan");
    assert_eq!(approved.status, "approved");
    guided
        .assert_execution_allowed(
            &session.id,
            &config.scope.target_url,
            &config_json,
        )
        .expect("approved config");

    let selected_categories = guided
        .selected_plan_categories(&session.id)
        .expect("selected categories");
    let execution_config = apply_approved_execution_policy(
        &config,
        &ApprovedExecutionPolicy {
            selected_categories,
            state_changing_selected: guided
                .has_selected_state_changing(&session.id)
                .expect("state-changing policy"),
        },
    );

    let web = AuthorizedWebSecurityStore::new(&database);
    let scan = web
        .create_scan(&WebScanCreate {
            website_id: None,
            project_id: Some(index.project_id.clone()),
            target_url: config.scope.target_url.clone(),
            authorization_confirmed: true,
            scope_json: serde_json::to_string(&config.scope).expect("scope json"),
            config_json: config_json.clone(),
            auth_metadata_json: serde_json::json!({
                "primary": primary.metadata(),
                "secondary": secondary.metadata(),
            })
            .to_string(),
        })
        .expect("scan record");
    guided.link_scan(&session.id, &scan.id).expect("link scan");

    let outcome = run_authorized_scan(
        &execution_config,
        &primary,
        Some(&secondary),
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("guided execution");

    for endpoint in &outcome.endpoints {
        web.record_endpoint(
            &scan.id,
            &WebEndpointInput {
                url: endpoint.url.clone(),
                method: endpoint.method.clone(),
                depth: endpoint.depth,
                source: endpoint.source.clone(),
                parameter_names: endpoint.parameter_names.clone(),
                parameter_locations: endpoint.parameter_locations.clone(),
                response_header_names: endpoint.response_header_names.clone(),
                cookie_names: endpoint.cookie_names.clone(),
                content_type: endpoint.content_type.clone(),
                status_code: endpoint.status_code,
                redirect_to: endpoint.redirect_to.clone(),
            },
        )
        .expect("persist endpoint");
    }

    let mut persisted = Vec::new();
    for finding in outcome.findings {
        let source = web
            .correlate_source(
                Some(&index.project_id),
                &finding.endpoint,
                finding.parameter.as_deref(),
            )
            .expect("source correlation");
        let record = web
            .record_finding(
                &scan.id,
                &WebFindingInput {
                    fingerprint: finding.stable_fingerprint(),
                    category: finding.category,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    target: finding.target,
                    endpoint_url: finding.endpoint,
                    method: finding.method,
                    parameter_name: finding.parameter,
                    title: finding.title,
                    description: finding.description,
                    reproduction_summary: finding.reproduction_summary,
                    impact: finding.impact,
                    remediation: finding.remediation,
                    references: finding.references,
                    source,
                },
            )
            .expect("persist finding");
        guided
            .set_finding_lifecycle(&record.id, Some(&session.id), "open")
            .expect("open lifecycle");
        guided
            .correlate_source_candidates(&record.id, 5)
            .expect("guided source candidates");
        for evidence in finding.evidence {
            web.record_evidence(
                &record.id,
                &WebEvidenceInput {
                    summary: evidence.summary,
                    request_metadata_json: evidence.request_metadata.to_string(),
                    response_metadata_json: evidence.response_metadata.to_string(),
                },
            )
            .expect("persist evidence");
        }
        persisted.push(record);
    }

    web.update_progress(
        &scan.id,
        "completed",
        "completed",
        outcome.endpoints.len(),
        outcome.requests_performed,
        persisted.len(),
    )
    .expect("complete scan");
    guided
        .update_from_scan(&session.id, "completed", "completed", None)
        .expect("complete guided session");

    let categories: std::collections::HashSet<_> =
        persisted.iter().map(|finding| finding.category.as_str()).collect();
    for expected in [
        "sql_injection",
        "xss",
        "csrf",
        "open_redirect",
        "access_control",
        "api_input_validation",
        "security_headers",
    ] {
        assert!(categories.contains(expected), "missing category {expected}");
    }

    let sql = persisted
        .iter()
        .find(|finding| finding.category == "sql_injection" && finding.endpoint_url.contains("/search"))
        .expect("SQL finding");
    let candidates = guided
        .list_source_candidates(&sql.id, 5)
        .expect("source candidates");
    assert!(!candidates.is_empty());
    assert!(candidates[0].relative_path.contains("search_controller"));

    let source_before_fix = fs::read_to_string(&source_path).expect("source before fix");
    let prepared_fix = guided.prepare_fix(&sql.id).expect("prepare fix");
    assert_eq!(prepared_fix.repair.status, "draft");
    assert_eq!(
        fs::read_to_string(&source_path).expect("source after prepare"),
        source_before_fix,
        "Prepare Fix must not modify source",
    );

    let candidate_file_id = prepared_fix
        .source_candidates
        .first()
        .expect("fix source candidate")
        .file_id
        .clone();
    let proposed = source_before_fix.replace(
        "format!(\"SELECT * FROM items WHERE name = '{q}'\")",
        "\"SELECT * FROM items WHERE name = ?\".to_string()",
    );
    assert_ne!(proposed, source_before_fix);

    let repair = VerifiedRepairService::new(&database);
    repair
        .add_file_replacement(&prepared_fix.repair.id, &candidate_file_id, &proposed)
        .expect("add reviewed replacement");
    repair
        .approve_plan(&prepared_fix.repair.id)
        .expect("explicit repair approval");

    let backups = tempdir().expect("backup tempdir");
    let application = RepairApplicationService::new(&database)
        .apply_plan(&prepared_fix.repair.id, backups.path())
        .expect("apply local repair");
    assert_eq!(application.status, "applied");
    guided
        .sync_repair_application_state(&prepared_fix.repair.id)
        .expect("sync applied repair");
    assert_eq!(
        guided
            .retest_candidate_finding_ids(&session.id, 20)
            .expect("retest candidates"),
        vec![sql.id.clone()],
    );

    let retest = run_targeted_retest(
        &config,
        &primary,
        Some(&secondary),
        &TargetedRetestRequest {
            endpoint_url: sql.endpoint_url.clone(),
            method: sql.method.clone(),
            parameter_name: sql.parameter_name.clone(),
            parameter_location: Some("query".into()),
            category: sql.category.clone(),
        },
        Arc::new(AtomicBool::new(false)),
    )
    .expect("targeted retest");
    assert!(retest.requests_performed <= 12);
    let still_vulnerable = retest
        .findings
        .iter()
        .any(|finding| finding.category == "sql_injection");
    assert!(still_vulnerable);

    guided
        .record_retest(GuidedRetestInput {
            finding_id: &sql.id,
            session_id: Some(&session.id),
            status: "still_vulnerable",
            original_confidence: &sql.confidence,
            observed_confidence: retest
                .findings
                .iter()
                .find(|finding| finding.category == "sql_injection")
                .map(|finding| finding.confidence.as_str()),
            requests_performed: retest.requests_performed,
            detail_json: r#"{"fixture":"local-guided-e2e"}"#,
        })
        .expect("record retest");

    let lifecycle: String = database
        .connection()
        .query_row(
            "SELECT state FROM guided_security_finding_lifecycle WHERE finding_id=?1",
            [&sql.id],
            |row| row.get(0),
        )
        .expect("final lifecycle");
    assert_eq!(lifecycle, "still_vulnerable");

    let original_history = web
        .finding_evidence(&sql.id, 50)
        .expect("original evidence");
    assert!(!original_history.is_empty());
    assert_eq!(
        web.get_scan(&scan.id)
            .expect("scan")
            .expect("scan exists")
            .status,
        "completed",
    );
}

#[test]
fn request_limit_is_hard_bounded() {
    let lab = LocalLab::start();
    let outcome = run_authorized_scan(
        &lab.config(3),
        &AuthContext::default(),
        None,
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("bounded scan");
    assert!(outcome.requests_performed <= 3);
    let history = lab.requests.lock().expect("requests");
    assert!(history.len() <= 3);
    assert!(history.iter().all(|request| !request.method.is_empty()));
}
