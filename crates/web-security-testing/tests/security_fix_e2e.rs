use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use codetwin_core::{
    AuthorizedWebSecurityStore, Database, FixEligibility, GuidedRetestInput, GuidedSecurityStore,
    PatchSafetyClass, ProjectIndexService, RepairApplicationService, SecurityFixService,
    ValidationResultInput,
    WebEndpointInput, WebEvidenceInput, WebFindingInput, WebFindingRecord, WebScanCreate,
};
use tempfile::tempdir;
use url::Url;
use web_security_testing::{
    run_authorized_scan, run_targeted_retest, AuthContext, CheckConfig, ScanConfig, ScanOutcome,
    ScopeConfig, TargetedRetestRequest,
};

struct SourceBackedLab {
    base_url: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SourceBackedLab {
    fn start(project_root: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind source-backed lab");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("lab address");
        let base_url = format!("http://127.0.0.1:{}", address.port());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_source_backed(stream, &project_root),
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
            thread: Some(thread),
        }
    }

    fn config(&self) -> ScanConfig {
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
                allowed_paths: vec!["/".into()],
                excluded_paths: vec![],
                max_crawl_depth: 3,
                max_requests: 260,
                concurrency: 2,
                timeout_ms: 2_000,
                response_limit_bytes: 128_000,
                redirect_limit: 2,
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

impl Drop for SourceBackedLab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(url) = Url::parse(&self.base_url) {
            if let Ok(mut addresses) = url.socket_addrs(|| None) {
                if let Some(address) = addresses.pop() {
                    let _ = TcpStream::connect(address);
                }
            }
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn handle_source_backed(mut stream: TcpStream, project_root: &Path) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = [0u8; 16_384];
    let Ok(read) = stream.read(&mut buffer) else {
        return;
    };
    if read == 0 {
        return;
    }
    let request = String::from_utf8_lossy(&buffer[..read]);
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let authorization = request_header(&request, "authorization");
    let url = Url::parse(&format!("http://localhost{target}"))
        .unwrap_or_else(|_| Url::parse("http://localhost/").expect("fallback url"));
    let query: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    if method == "OPTIONS" {
        respond(
            &mut stream,
            "204 No Content",
            &[("Allow", "GET, OPTIONS")],
            "",
        );
        return;
    }

    match url.path() {
        "/" => respond(
            &mut stream,
            "200 OK",
            &[("Content-Type", "text/html")],
            r#"<html><body>
<a href="/api/search?q=hello">search</a>
<a href="/api/render?q=hello">render</a>
<a href="/api/render-ambiguous?q=hello">ambiguous render</a>
<a href="/api/object?id=a">object</a>
</body></html>"#,
        ),
        "/api/search" => handle_search(&mut stream, project_root, &query),
        "/api/render" => handle_render(&mut stream, project_root, &query, false),
        "/api/render-ambiguous" => handle_render(&mut stream, project_root, &query, true),
        "/api/object" => handle_object(
            &mut stream,
            project_root,
            &query,
            authorization.as_deref(),
        ),
        _ => respond(
            &mut stream,
            "404 Not Found",
            &[("Content-Type", "text/plain")],
            "not found",
        ),
    }
}

fn handle_search(
    stream: &mut TcpStream,
    project_root: &Path,
    query: &std::collections::HashMap<String, String>,
) {
    let source = fs::read_to_string(project_root.join("src/api/search_controller.ts"))
        .unwrap_or_default();
    let parameterized =
        source.contains("WHERE name = ?") && source.contains("[q]");
    let q = query.get("q").map(String::as_str).unwrap_or("");

    if !parameterized {
        if q == "'" || q.contains("UNION SELECT") {
            respond(
                stream,
                "500 Internal Server Error",
                &[("Content-Type", "text/plain")],
                "SQLSTATE[42000] syntax error near input",
            );
            return;
        }
        if q.contains("' AND '1'='2'") {
            respond(
                stream,
                "403 Forbidden",
                &[("Content-Type", "application/json")],
                r#"{"items":[],"branch":"false-predicate"}"#,
            );
            return;
        }
        if q.contains("' OR '1'='1'") {
            respond(
                stream,
                "200 OK",
                &[("Content-Type", "application/json")],
                r#"{"items":[{"name":"apple"}],"query":"hello"}"#,
            );
            return;
        }
    }

    let body = match q {
        "hello" => r#"{"items":[{"name":"apple"}],"query":"hello"}"#.to_string(),
        "apple" => r#"{"items":[{"name":"apple"}],"query":"apple"}"#.to_string(),
        _ => format!(r#"{{"items":[],"query":"{}"}}"#, json_escape(q)),
    };
    respond(
        stream,
        "200 OK",
        &[("Content-Type", "application/json")],
        &body,
    );
}

fn handle_render(
    stream: &mut TcpStream,
    project_root: &Path,
    query: &std::collections::HashMap<String, String>,
    ambiguous: bool,
) {
    let file = if ambiguous {
        "src/api/render-ambiguous-controller.ts"
    } else {
        "src/api/render_controller.ts"
    };
    let source = fs::read_to_string(project_root.join(file)).unwrap_or_default();
    let q = query.get("q").map(String::as_str).unwrap_or("");

    if ambiguous {
        respond(
            stream,
            "200 OK",
            &[("Content-Type", "text/html")],
            &format!("<html><body><script>const data = \"{q}\";</script></body></html>"),
        );
        return;
    }

    if source.contains(".textContent = q") {
        respond(
            stream,
            "200 OK",
            &[("Content-Type", "text/html")],
            &format!("<html><body><div>{}</div></body></html>", html_escape(q)),
        );
    } else {
        respond(
            stream,
            "200 OK",
            &[("Content-Type", "text/html")],
            &format!("<html><body><div>{q}</div></body></html>"),
        );
    }
}

fn handle_object(
    stream: &mut TcpStream,
    project_root: &Path,
    query: &std::collections::HashMap<String, String>,
    authorization: Option<&str>,
) {
    let source = fs::read_to_string(project_root.join("src/api/object_controller.ts"))
        .unwrap_or_default();
    let ownership_enforced = source.contains("findOwned(id, user.id)");
    let id = query.get("id").map(String::as_str).unwrap_or("a");
    let user = match authorization {
        Some("Bearer user-a-token") => Some("user-a"),
        Some("Bearer user-b-token") => Some("user-b"),
        _ => None,
    };
    let owner = match id {
        "a" => "user-a",
        "b" => "user-b",
        _ => "nobody",
    };

    if ownership_enforced && user != Some(owner) {
        respond(
            stream,
            "403 Forbidden",
            &[("Content-Type", "application/json")],
            r#"{"error":"forbidden","policy":"owner-only"}"#,
        );
        return;
    }

    let body = format!(
        r#"{{"id":"{id}","owner":"{owner}","value":"synthetic-resource-{id}-for-local-security-fix-test"}}"#
    );
    respond(
        stream,
        "200 OK",
        &[("Content-Type", "application/json")],
        &body,
    );
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

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn primary_auth() -> AuthContext {
    AuthContext {
        bearer_token: Some("user-a-token".into()),
        ..AuthContext::default()
    }
}

fn secondary_auth() -> AuthContext {
    AuthContext {
        bearer_token: Some("user-b-token".into()),
        ..AuthContext::default()
    }
}

fn write_project(root: &Path) {
    let api = root.join("src/api");
    fs::create_dir_all(&api).expect("create api directory");
    let tick = char::from(96);
    let sql = format!(
        "export async function getSearch(q: string) {{\n  return db.query({tick}SELECT * FROM products WHERE name = '\\x24{{q}}'{tick});\n}}\n"
    )
    .replace("\\x24", "$");
    fs::write(api.join("search_controller.ts"), sql).expect("write sql source");
    fs::write(
        api.join("render_controller.ts"),
        "export function getRender(q: string) {\n  const output = document.createElement(\"div\");\n  output.innerHTML = q;\n  return output;\n}\n",
    )
    .expect("write xss source");
    let ambiguous = format!(
        "export function getRenderAmbiguous(q: string) {{\n  return {tick}<script>const data = \\\"{}{{q}}\\\";</script>{tick};\n}}\n",
        char::from(36),
    );
    fs::write(api.join("render-ambiguous-controller.ts"), ambiguous)
        .expect("write ambiguous xss source");
    fs::write(
        api.join("object_controller.ts"),
        "export async function getObject(id: string, user: User) {\n  return repository.find(id);\n}\n",
    )
    .expect("write idor source");
}

fn persist_outcome(
    database: &Database,
    project_id: &str,
    config: &ScanConfig,
    primary: &AuthContext,
    secondary: Option<&AuthContext>,
    outcome: ScanOutcome,
) -> Vec<WebFindingRecord> {
    let web = AuthorizedWebSecurityStore::new(database);
    let scan = web
        .create_scan(&WebScanCreate {
            website_id: None,
            project_id: Some(project_id.to_string()),
            target_url: config.scope.target_url.clone(),
            authorization_confirmed: true,
            scope_json: serde_json::to_string(&config.scope).expect("scope json"),
            config_json: serde_json::to_string(config).expect("config json"),
            auth_metadata_json: serde_json::json!({
                "primary": primary.metadata(),
                "secondary": secondary.map(AuthContext::metadata),
            })
            .to_string(),
        })
        .expect("create scan");

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

    let mut findings = Vec::new();
    for finding in outcome.findings {
        let source = web
            .correlate_source(
                Some(project_id),
                &finding.endpoint,
                finding.parameter.as_deref(),
            )
            .expect("correlate source");
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
        findings.push(record);
    }
    web.update_progress(
        &scan.id,
        "completed",
        "completed",
        outcome.endpoints.len(),
        outcome.requests_performed,
        findings.len(),
    )
    .expect("complete scan");
    findings
}

fn apply_generated_fix(
    database: &Database,
    project_root: &Path,
    finding: &WebFindingRecord,
) -> (String, String) {
    let service = SecurityFixService::new(database);
    let prepared = service
        .prepare_fix(&finding.id, false)
        .expect("prepare security fix");
    assert_eq!(prepared.eligibility.result, FixEligibility::AutoFixCandidate);
    assert!(prepared.root_causes[0].confidence >= 0.82);

    let review = service
        .generate_patch(&prepared.attempt.id)
        .expect("generate bounded patch");
    assert!(matches!(
        review.safety.classification,
        PatchSafetyClass::SafeToReview | PatchSafetyClass::Caution
    ));
    service
        .approve_attempt(
            &prepared.attempt.id,
            review.safety.classification == PatchSafetyClass::Caution,
        )
        .expect("approve exact patch");
    let repair_id = service
        .assert_application_allowed(&prepared.attempt.id)
        .expect("approved patch identity");

    let backups = tempdir().expect("backup root");
    let application = RepairApplicationService::new(database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply repair");
    assert_eq!(application.status, "applied");
    service
        .record_application(&prepared.attempt.id, &application.id)
        .expect("record application");
    GuidedSecurityStore::new(database)
        .sync_repair_application_state(&repair_id)
        .expect("sync guided lifecycle");
    ProjectIndexService::new(database)
        .index_project(project_root)
        .expect("re-index patched project");

    (prepared.attempt.id, application.id)
}

fn record_runtime_validation(database: &Database, attempt_id: &str, label: &str) {
    let service = SecurityFixService::new(database);
    service
        .add_validation_result(
            attempt_id,
            ValidationResultInput {
                command_label: label,
                runner_kind: "local_security_fix_fixture",
                targets: &[],
                status: "PASS",
                exit_code: Some(0),
                duration_ms: Some(1),
                classification: "NONE",
                stdout_summary: "local defensive behavior assertions passed",
                stderr_summary: "",
            },
        )
        .expect("persist validation");
    let completed = service
        .complete_validation(attempt_id)
        .expect("complete validation");
    assert_eq!(completed.status, "verification_pending");
}

fn targeted_retest_and_sync(
    database: &Database,
    config: &ScanConfig,
    finding: &WebFindingRecord,
    primary: &AuthContext,
    secondary: Option<&AuthContext>,
) {
    let retest = run_targeted_retest(
        config,
        primary,
        secondary,
        &TargetedRetestRequest {
            endpoint_url: finding.endpoint_url.clone(),
            method: finding.method.clone(),
            parameter_name: finding.parameter_name.clone(),
            parameter_location: finding.parameter_name.as_ref().map(|_| "query".into()),
            category: finding.category.clone(),
        },
        Arc::new(AtomicBool::new(false)),
    )
    .expect("targeted retest");
    assert!(retest.requests_performed > 0);
    assert!(
        retest.verification_completed,
        "targeted verification must have enough successful responses: {:?}",
        retest.failure_reason
    );
    let matching = retest
        .findings
        .iter()
        .filter(|observed| observed.category == finding.category)
        .collect::<Vec<_>>();
    let status = if matching.is_empty() {
        "retest_passed"
    } else {
        "still_vulnerable"
    };
    let observed_confidence = matching
        .iter()
        .map(|observed| observed.confidence.as_str())
        .max();
    GuidedSecurityStore::new(database)
        .record_retest(GuidedRetestInput {
            finding_id: &finding.id,
            session_id: None,
            status,
            original_confidence: &finding.confidence,
            observed_confidence,
            requests_performed: retest.requests_performed,
            detail_json: r#"{"fixture":"source-backed-local-security-fix-e2e"}"#,
        })
        .expect("persist targeted retest");
    let attempt = SecurityFixService::new(database)
        .sync_retest_result(&finding.id, status)
        .expect("sync fix retest")
        .expect("fix attempt");
    assert_eq!(status, "retest_passed", "targeted vulnerability still reproduced");
    assert_eq!(attempt.status, "fix_verified");
    assert_eq!(attempt.retest_state, "FIX_VERIFIED");
}

fn blocking_get(url: &str, auth: Option<&str>) -> (u16, String) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("http client");
    let mut request = client.get(url);
    if let Some(auth) = auth {
        request = request.header("Authorization", auth);
    }
    let response = request.send().expect("local request");
    let status = response.status().as_u16();
    let body = response.text().expect("response body");
    (status, body)
}

#[test]
fn sql_injection_fix_verify_changes_real_local_behavior() {
    let project = tempdir().expect("project");
    write_project(project.path());
    let lab = SourceBackedLab::start(project.path().to_path_buf());
    let config = lab.config();
    let primary = primary_auth();

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index project");

    let outcome = run_authorized_scan(
        &config,
        &primary,
        None,
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("initial scan");
    let findings = persist_outcome(
        &database,
        &index.project_id,
        &config,
        &primary,
        None,
        outcome,
    );
    let finding = findings
        .iter()
        .find(|item| {
            item.category == "sql_injection" && item.endpoint_url.contains("/api/search")
        })
        .expect("SQLi finding");

    let service = SecurityFixService::new(&database);
    let roots = service
        .analyze_root_causes(&finding.id)
        .expect("root causes");
    assert!(roots[0]
        .relative_path
        .ends_with("src/api/search_controller.ts"));
    let (attempt_id, _) = apply_generated_fix(&database, project.path(), finding);

    let (normal_status, normal_body) =
        blocking_get(&format!("{}/api/search?q=apple", lab.base_url), None);
    assert_eq!(normal_status, 200);
    assert!(normal_body.contains("\"name\":\"apple\""));
    let (probe_status, probe_body) =
        blocking_get(&format!("{}/api/search?q=%27", lab.base_url), None);
    assert_eq!(probe_status, 200);
    assert!(!probe_body.contains("SQLSTATE"));

    record_runtime_validation(&database, &attempt_id, "SQL search functional regression");
    targeted_retest_and_sync(&database, &config, finding, &primary, None);

    let source = fs::read_to_string(project.path().join("src/api/search_controller.ts"))
        .expect("patched source");
    assert!(source.contains("WHERE name = ?"));
    assert!(source.contains("[q]"));
}

#[test]
fn xss_fix_verify_preserves_text_and_ambiguous_context_is_not_auto_patched() {
    let project = tempdir().expect("project");
    write_project(project.path());
    let lab = SourceBackedLab::start(project.path().to_path_buf());
    let config = lab.config();
    let primary = primary_auth();

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index project");
    let outcome = run_authorized_scan(
        &config,
        &primary,
        None,
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("scan");
    let findings = persist_outcome(
        &database,
        &index.project_id,
        &config,
        &primary,
        None,
        outcome,
    );

    let xss = findings
        .iter()
        .find(|item| {
            item.category == "xss"
                && item.endpoint_url.contains("/api/render?q=")
                && !item.endpoint_url.contains("ambiguous")
        })
        .expect("plain HTML XSS finding");
    let (attempt_id, _) = apply_generated_fix(&database, project.path(), xss);

    let (text_status, text_body) =
        blocking_get(&format!("{}/api/render?q=hello", lab.base_url), None);
    assert_eq!(text_status, 200);
    assert!(text_body.contains("<div>hello</div>"));
    let (markup_status, markup_body) = blocking_get(
        &format!("{}/api/render?q=%3Cb%3Ehello%3C%2Fb%3E", lab.base_url),
        None,
    );
    assert_eq!(markup_status, 200);
    assert!(markup_body.contains("&lt;b&gt;hello&lt;/b&gt;"));
    assert!(!markup_body.contains("<b>hello</b>"));

    record_runtime_validation(&database, &attempt_id, "XSS text rendering regression");
    targeted_retest_and_sync(&database, &config, xss, &primary, None);

    let ambiguous = findings
        .iter()
        .find(|item| {
            item.category == "xss"
                && item.endpoint_url.contains("/api/render-ambiguous")
        })
        .expect("ambiguous XSS finding");
    let assessment = SecurityFixService::new(&database)
        .evaluate_eligibility(&ambiguous.id)
        .expect("ambiguous eligibility");
    assert!(matches!(
        assessment.result,
        FixEligibility::GuidedFixCandidate | FixEligibility::ManualRemediation
    ));
    let prepared = SecurityFixService::new(&database)
        .prepare_fix(&ambiguous.id, false)
        .expect("prepare ambiguous fix");
    assert!(
        SecurityFixService::new(&database)
            .generate_patch(&prepared.attempt.id)
            .is_err(),
        "ambiguous output context must not receive a speculative generated patch"
    );
}

#[test]
fn idor_guided_fix_verify_uses_two_local_identities_and_server_side_patch() {
    let project = tempdir().expect("project");
    write_project(project.path());
    let lab = SourceBackedLab::start(project.path().to_path_buf());
    let config = lab.config();
    let primary = primary_auth();
    let secondary = secondary_auth();

    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index project");
    let outcome = run_authorized_scan(
        &config,
        &primary,
        Some(&secondary),
        Arc::new(AtomicBool::new(false)),
        |_| {},
    )
    .expect("scan");
    let findings = persist_outcome(
        &database,
        &index.project_id,
        &config,
        &primary,
        Some(&secondary),
        outcome,
    );
    let finding = findings
        .iter()
        .find(|item| {
            item.category == "access_control" && item.endpoint_url.contains("/api/object")
        })
        .expect("authorization finding");
    assert_eq!(finding.confidence, "Potential");

    let service = SecurityFixService::new(&database);
    let prepared = service
        .prepare_fix(&finding.id, false)
        .expect("prepare authorization fix");
    assert_eq!(
        prepared.eligibility.result,
        FixEligibility::GuidedFixCandidate
    );
    assert!(prepared.root_causes[0]
        .relative_path
        .ends_with("src/api/object_controller.ts"));
    assert!(
        service.generate_patch(&prepared.attempt.id).is_err(),
        "authorization must not be auto-rewritten generically"
    );

    let file_id = prepared.root_causes[0].file_id.clone();
    let safe_patch =
        "export async function getObject(id: string, user: User) {\n  return repository.findOwned(id, user.id);\n}\n";
    let review = service
        .propose_replacement(&prepared.attempt.id, &file_id, safe_patch)
        .expect("review guided authorization patch");
    assert_ne!(review.safety.classification, PatchSafetyClass::Rejected);
    let caution = review.safety.classification == PatchSafetyClass::Caution;
    service
        .approve_attempt(&prepared.attempt.id, caution)
        .expect("approve guided patch");
    let repair_id = service
        .assert_application_allowed(&prepared.attempt.id)
        .expect("approved authorization patch");
    let backups = tempdir().expect("backup");
    let application = RepairApplicationService::new(&database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply authorization patch");
    assert_eq!(application.status, "applied");
    service
        .record_application(&prepared.attempt.id, &application.id)
        .expect("record application");
    GuidedSecurityStore::new(&database)
        .sync_repair_application_state(&repair_id)
        .expect("guided state");
    ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("re-index");

    let (a_own, _) = blocking_get(
        &format!("{}/api/object?id=a", lab.base_url),
        Some("Bearer user-a-token"),
    );
    let (b_own, _) = blocking_get(
        &format!("{}/api/object?id=b", lab.base_url),
        Some("Bearer user-b-token"),
    );
    let (a_cross, _) = blocking_get(
        &format!("{}/api/object?id=b", lab.base_url),
        Some("Bearer user-a-token"),
    );
    let (b_cross, _) = blocking_get(
        &format!("{}/api/object?id=a", lab.base_url),
        Some("Bearer user-b-token"),
    );
    assert_eq!(a_own, 200);
    assert_eq!(b_own, 200);
    assert_eq!(a_cross, 403);
    assert_eq!(b_cross, 403);

    record_runtime_validation(
        &database,
        &prepared.attempt.id,
        "Owner/cross-owner authorization regression",
    );
    targeted_retest_and_sync(
        &database,
        &config,
        finding,
        &primary,
        Some(&secondary),
    );
}

#[test]
fn unable_to_verify_never_becomes_fixed_when_local_target_is_down() {
    let project = tempdir().expect("project");
    write_project(project.path());
    let database = Database::open_in_memory().expect("database");
    let index = ProjectIndexService::new(&database)
        .index_project(project.path())
        .expect("index project");

    let web = AuthorizedWebSecurityStore::new(&database);
    let scan = web
        .create_scan(&WebScanCreate {
            website_id: None,
            project_id: Some(index.project_id.clone()),
            target_url: "http://127.0.0.1:9".into(),
            authorization_confirmed: true,
            scope_json: "{}".into(),
            config_json: "{}".into(),
            auth_metadata_json: "{}".into(),
        })
        .expect("scan");
    let finding = web
        .record_finding(
            &scan.id,
            &WebFindingInput {
                fingerprint: "unavailable-sqli".into(),
                category: "sql_injection".into(),
                severity: "high".into(),
                confidence: "Likely".into(),
                target: "http://127.0.0.1:9".into(),
                endpoint_url: "http://127.0.0.1:9/api/search?q=hello".into(),
                method: "GET".into(),
                parameter_name: Some("q".into()),
                title: "Local unavailable fixture".into(),
                description: "Persisted finding from an earlier local run.".into(),
                reproduction_summary: "Local only.".into(),
                impact: "Fixture only.".into(),
                remediation: "Parameterize SQL.".into(),
                references: vec![],
                source: None,
            },
        )
        .expect("finding");
    for summary in ["baseline", "quote probe"] {
        web.record_evidence(
            &finding.id,
            &WebEvidenceInput {
                summary: summary.into(),
                request_metadata_json: "{}".into(),
                response_metadata_json: "{}".into(),
            },
        )
        .expect("evidence");
    }

    let service = SecurityFixService::new(&database);
    let prepared = service
        .prepare_fix(&finding.id, false)
        .expect("prepare");
    service
        .generate_patch(&prepared.attempt.id)
        .expect("patch");
    service
        .approve_attempt(&prepared.attempt.id, false)
        .expect("approve");
    let repair_id = service
        .assert_application_allowed(&prepared.attempt.id)
        .expect("allowed");
    let backups = tempdir().expect("backup");
    let application = RepairApplicationService::new(&database)
        .apply_plan(&repair_id, backups.path())
        .expect("apply");
    service
        .record_application(&prepared.attempt.id, &application.id)
        .expect("record apply");
    record_runtime_validation(&database, &prepared.attempt.id, "local source validation");

    let unavailable_config = ScanConfig {
        scope: ScopeConfig {
            target_url: "http://127.0.0.1:9/".into(),
            allowed_hostnames: vec!["127.0.0.1".into()],
            allowed_subdomains: vec![],
            allowed_paths: vec!["/".into()],
            excluded_paths: vec![],
            max_crawl_depth: 0,
            max_requests: 12,
            concurrency: 1,
            timeout_ms: 150,
            response_limit_bytes: 16_384,
            redirect_limit: 0,
            retry_limit: 0,
            active_testing: true,
            allow_non_idempotent_methods: false,
            allow_private_networks: true,
            enable_timing_probes: false,
            authorization_confirmed: true,
        },
        checks: CheckConfig::default(),
    };
    let retest = run_targeted_retest(
        &unavailable_config,
        &AuthContext::default(),
        None,
        &TargetedRetestRequest {
            endpoint_url: finding.endpoint_url.clone(),
            method: finding.method.clone(),
            parameter_name: finding.parameter_name.clone(),
            parameter_location: Some("query".into()),
            category: finding.category.clone(),
        },
        Arc::new(AtomicBool::new(false)),
    )
    .expect("bounded unavailable retest");
    assert!(retest.requests_performed > 0);
    assert_eq!(retest.responses_observed, 0);
    assert!(!retest.verification_completed);
    assert!(retest.failure_reason.is_some());

    GuidedSecurityStore::new(&database)
        .record_retest(GuidedRetestInput {
            finding_id: &finding.id,
            session_id: None,
            status: "unable_to_verify",
            original_confidence: &finding.confidence,
            observed_confidence: None,
            requests_performed: retest.requests_performed,
            detail_json: &serde_json::json!({
                "reason": retest.failure_reason,
                "responses_observed": retest.responses_observed,
            }).to_string(),
        })
        .expect("persist unable retest");
    let attempt = service
        .sync_retest_result(&finding.id, "unable_to_verify")
        .expect("sync unable")
        .expect("attempt");
    assert_eq!(attempt.status, "unable_to_verify");
    assert_eq!(attempt.retest_state, "UNABLE_TO_VERIFY");
    assert_ne!(attempt.status, "fix_verified");
}
