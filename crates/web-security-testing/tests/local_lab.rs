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

struct LocalLab {
    base_url: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
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

fn handle(mut stream: TcpStream, requests: &Arc<Mutex<Vec<String>>>) {
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
    if let Ok(mut history) = requests.lock() {
        history.push(format!("{method} {target}"));
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
<a href="/openapi.json">api</a>
<a href="/static-sql?q=hello">static sql-looking text</a>
<a href="/escaped?q=hello">escaped reflection</a>
<a href="/redirect-safe?next=/home">safe redirect</a>
<a href="/generic500?q=hello">generic error</a>
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
        "/openapi.json" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "application/json")],
            r#"{"openapi":"3.0.0","paths":{"/api/items":{"get":{"parameters":[{"name":"id","in":"query"}]}}}}"#,
        ),
        "/api/items" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "application/json")],
            r#"{"items":[]}"#,
        ),
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
        bearer_token: Some("primary-secret-token".to_string()),
        ..AuthContext::default()
    };
    let secondary = AuthContext {
        bearer_token: Some("secondary-secret-token".to_string()),
        ..AuthContext::default()
    };
    let outcome = run_authorized_scan(
        &lab.config(120),
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
    assert!(outcome
        .endpoints
        .iter()
        .any(|endpoint| endpoint.url.contains("/api/items")));
    assert!(outcome
        .endpoints
        .iter()
        .all(|endpoint| !endpoint.url.contains("example.com")));
    assert!(outcome.requests_performed <= 120);

    let safe_sql = outcome.findings.iter().filter(|finding| {
        finding.category == "sql_injection" && finding.endpoint.contains("/safe")
    });
    assert_eq!(safe_sql.count(), 0);

    let serialized = serde_json::to_string(&outcome.findings).expect("findings JSON");
    assert!(!serialized.contains("primary-secret-token"));
    assert!(!serialized.contains("secondary-secret-token"));
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
    assert!(lab.requests.lock().expect("requests").len() <= 3);
}
