use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use url::Url;
use web_security_testing::{
    prepare_guided_security, run_authorized_scan, AuthContext, CheckConfig, ScanConfig, ScanError,
    ScopeConfig, SecurityEnvironment,
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
